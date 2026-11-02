"""Search Base for transactions whose calldata carries a WebAuthn assertion (the bytes `"type":"webauthn.get"`),
among the transactions that emitted a given event. Public JSON-RPC, read-only; batched requests.

  python3 tools/scan_webauthn.py OUT.json CONTRACT EVENT_SIGNATURE FROM_BLOCK N_BLOCKS [STEP]

  e.g. USDC AuthorizationUsed (every EIP-3009 execution):
    python3 tools/scan_webauthn.py out.json 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 \
        "AuthorizationUsed(address,bytes32)" 53090000 20000
  EntryPoint v0.6 UserOperationEvent (ERC-4337 operations):
    python3 tools/scan_webauthn.py out.json 0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789 \
        "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)" 53090000 200

Writes the counts (blocks, logs, distinct transactions read, hits) and, for every hit only, the raw
eth_getTransactionByHash reply and the logs of that transaction, so a hit can be re-derived offline. A transaction that
emitted the event executed (a reverted transaction emits no logs)."""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.load()      # SPEC 32.12 (f): x402-signature-vectors v1.4.0 run from the bytes hashed, never by name from a path
from lib.eip712 import keccak256  # noqa: E402

RPC = os.environ.get("BASE_RPC")          # checked where it is used, never at import
MARK = b'"type":"webauthn.get"'.hex()
_id = [0]


def batch(calls):
    """calls: [(method, params)]; returns the replies in order, as {"method", "params", "result"}."""
    body = []
    for m, p in calls:
        _id[0] += 1
        body.append({"jsonrpc": "2.0", "id": _id[0], "method": m, "params": p})
    if not RPC:
        sys.exit("BASE_RPC not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    req = urllib.request.Request(RPC, json.dumps(body).encode(),
                                 {"Content-Type": "application/json", "User-Agent": "apc-webauthn-scan/0"})
    for attempt in range(7):
        time.sleep(0.5 * 2 ** attempt)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                reply = json.load(r)
            break
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if attempt == 6 or (isinstance(e, urllib.error.HTTPError) and e.code not in (403, 429, 500, 502, 503)):
                raise
    if not isinstance(reply, list):
        raise SystemExit("RPC answered %r" % (reply,))
    by_id = {x.get("id"): x for x in reply}
    out = []
    for b in body:
        x = by_id.get(b["id"])
        if x is None or "error" in x:
            raise SystemExit("RPC error on %s %s: %s" % (b["method"], b["params"], x))
        out.append({"method": b["method"], "params": b["params"], "result": x["result"]})
    return out


def main(argv):
    if len(argv) < 6:
        raise SystemExit(__doc__)
    out, contract, event, lo, n = argv[1], argv[2].lower(), argv[3], int(argv[4]), int(argv[5])
    step = int(argv[6]) if len(argv) > 6 else 50
    topic = "0x" + keccak256(event.encode()).hex()
    if os.path.exists(out):
        raise SystemExit("%s exists" % out)
    seen, hits, nlogs, logs_by_tx = set(), [], 0, {}
    pending = []

    def flush():
        txs = batch([("eth_getTransactionByHash", [h]) for h in pending])
        for t in txs:
            if MARK in (t["result"] or {}).get("input", ""):
                hits.append({"tx": t, "logs": logs_by_tx[t["params"][0]]})
        pending.clear()

    for a in range(lo, lo + n, step):
        b = min(lo + n - 1, a + step - 1)
        g = batch([("eth_getLogs", [{"address": contract, "topics": [topic], "fromBlock": hex(a), "toBlock": hex(b)}])])[0]
        nlogs += len(g["result"])
        for lg in g["result"]:
            h = lg["transactionHash"]
            logs_by_tx.setdefault(h, []).append(lg)
            if h not in seen:
                seen.add(h)
                pending.append(h)
                if len(pending) >= 50:
                    flush()
        logs_by_tx = {h: logs_by_tx[h] for h in pending}     # a block lies in one step: earlier hits hold their lists
        print("blocks %d-%d logs %d tx %d hits %d" % (lo, b, nlogs, len(seen), len(hits)), flush=True)
    if pending:
        flush()
    summary = {"rpc": RPC, "contract": contract, "event": event, "topic0": topic, "from_block": lo, "n_blocks": n,
               "logs": nlogs, "distinct_tx": len(seen), "hits": len(hits), "marker": '"type":"webauthn.get"',
               "read": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(out, "x") as fh:
        json.dump({"summary": summary, "hits": hits}, fh, indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main(sys.argv)
