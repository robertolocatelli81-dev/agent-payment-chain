"""Build the `canonical` member of an apc-0.3 bundle (SPEC 0.3, O1-O4) for a Base mainnet block. Read-only RPC.

  L1_RPC=... BASE_RPC=... python3 tools/canonical.py BUNDLE_V03.json > canonical.json

Finds, among the Base dispute games on Ethereum (AggregateVerifier, game type 621, base/contracts eaa7729), the game
whose range holds the bundle's block, takes the first intermediate output root at or after that block, and carries:
the L1 eth_call replies (all at one named L1 block) and the L2 headers from that root's block down to the block right
after the bundle's block. apc_verify recomputes everything on the L2 side; the L1 replies stay RPC answers.
"""
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_block as ab  # noqa: E402
from apc_block import keccak256  # noqa: E402

FACTORY = "0x43edb88c4b80fdd2adff2412a7bebf9df42cb40e"
REGISTRY = "0x909f6cf47ed12f010a796527f562bfc26c7f4e72"
GAME_TYPE = 621
GAME_CALLS = ("gameType()", "rootClaim()", "extraData()", "startingBlockNumber()", "status()")
REGISTRY_CALLS = ("isGameProper(address)", "isGameRespected(address)", "isGameClaimValid(address)")
HEADER_KEYS = ab.HEADER_BASE + ab.HEADER_OPT + ("hash",)
SCAN = 64                                # games looked at, from one index on, to meet one of type 621


def sel(sig):
    return "0x" + keccak256(sig.encode())[:4].hex()


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    err = None
    for attempt in range(6):            # free public endpoints answer 429 under load: wait and retry
        time.sleep(0.3)
        req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "apc-tools"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                d = json.loads(r.read())
            if "result" in d and d["result"] is not None:
                return d["result"]
            err = d.get("error")
        except (OSError, ValueError) as e:
            err = repr(e)
        time.sleep(5 * (attempt + 1))
    raise RuntimeError("%s %s: %s" % (method, params, err))


def build(doc, l1, l2):
    n = int(doc["inclusion"]["block_header"]["number"], 16)
    l1_block = rpc(l1, "eth_blockNumber", [])
    call = lambda to, data: rpc(l1, "eth_call", [{"to": to, "data": data}, l1_block])
    count = int(call(FACTORY, sel("gameCount()")), 16)
    lo, hi = 0, count - 1

    def game(i):
        r = call(FACTORY, sel("gameAtIndex(uint256)") + "%064x" % i)
        return int(r[2:66], 16), "0x" + r[-40:]

    def seq_from(i):
        """The first game of type 621 at index >= i (the factory also holds other types): (index, address, seq)."""
        for j in range(i, min(i + SCAN, count)):
            t, g = game(j)
            if t == GAME_TYPE:
                return j, g, int(call(g, sel("l2SequenceNumber()")), 16)
        return None

    while lo < hi:                       # first game of type 621 whose l2SequenceNumber >= n
        mid = (lo + hi) // 2
        f = seq_from(mid)
        if f is None:                    # no game of type 621 within SCAN of mid: they are the newest ones, so go up
            lo = min(mid + SCAN, hi)     # (2026-11-01: going down here never met one when the search started low)
        elif f[2] >= n:
            hi = mid
        else:
            lo = f[0] + 1
    f = seq_from(lo)
    if f is None:
        raise RuntimeError("no game of type %d at or after index %d" % (GAME_TYPE, lo))
    t, g = GAME_TYPE, f[1]
    replies = []
    for to, sig in [(g, s) for s in GAME_CALLS] + [(REGISTRY, s) for s in REGISTRY_CALLS]:
        data = sel(sig) + ("%064x" % int(g, 16) if "address" in sig else "")
        replies.append({"method": "eth_call", "params": [{"to": to, "data": data}, l1_block], "result": call(to, data)})
    start = int(replies[3]["result"], 16)
    ed = bytes.fromhex(replies[2]["result"][2:])
    roots_n = (int.from_bytes(ed[32:64], "big") - 52) // 32
    seq = int.from_bytes(ed[64:96], "big")
    k = (seq - start) // roots_n
    i = -(-(n - start) // k) - 1
    m = start + (i + 1) * k
    if not (t == GAME_TYPE and start < n <= seq):
        raise RuntimeError("game %s (type %d, blocks %d..%d) does not hold block %d" % (g, t, start + 1, seq, n))
    headers = []
    for b in range(m, n, -1):
        h = rpc(l2, "eth_getBlockByNumber", [hex(b), False])
        headers.append({key: h[key] for key in HEADER_KEYS if key in h})
    return {"l1_network": "eip155:1", "game": g, "root_index": i, "l1_replies": replies, "headers": headers}


def main(argv):
    l1, l2 = os.environ.get("L1_RPC"), os.environ.get("BASE_RPC")
    if len(argv) != 2 or not l1 or not l2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 64
    with open(argv[1]) as fh:
        doc = json.load(fh)
    print(json.dumps(build(doc, l1, l2), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
