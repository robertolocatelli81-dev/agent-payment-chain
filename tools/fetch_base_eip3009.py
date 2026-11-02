"""Layer-2 oracle from real data: EIP-3009 authorizations that the USDC contract on Base mainnet EXECUTED.
The chain accepted each one, so its signature was valid for the token's EIP-712 domain at that block.

  python3 tools/fetch_base_eip3009.py OUT.json [N_BLOCKS] [MAX_TX]

Reads (public JSON-RPC, read-only): the token's name() and version() and the chain id; AuthorizationUsed logs over
the last N_BLOCKS blocks; each emitting transaction, kept only if it calls the token DIRECTLY with
transferWithAuthorization (v, r, s form or bytes-signature form). Writes every raw RPC reply it used, so the
result can be re-derived offline."""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/fetch_base_eip3009", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from lib.eip712 import keccak256  # noqa: E402

RPC = os.environ.get("BASE_RPC")          # checked where it is used, never at import
USDC = os.environ.get("APC_TOKEN", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913").lower()   # another EIP-3009 token: APC_TOKEN
SIG_VRS = "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
SIG_BYTES = "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)"
EVENT = "AuthorizationUsed(address,bytes32)"
_id = [0]


def rpc(method, params):
    _id[0] += 1
    body = json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": method, "params": params}).encode()
    if not RPC:
        sys.exit("BASE_RPC not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    req = urllib.request.Request(RPC, body, {"Content-Type": "application/json", "User-Agent": "eip3009-oracle/0"})
    for attempt in range(6):                      # the public endpoint rate-limits: pause, back off on 429
        time.sleep(1.0 * 2 ** attempt)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                reply = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429) or attempt == 5:
                raise
        except (urllib.error.URLError, TimeoutError):     # a read timeout of a public endpoint: try again
            if attempt == 5:
                raise
    if "error" in reply:
        raise SystemExit("RPC error on %s: %s" % (method, reply["error"]))
    return {"method": method, "params": params, "result": reply["result"]}


def abi_string(hexdata):
    b = bytes.fromhex(hexdata[2:])
    off = int.from_bytes(b[:32], "big")
    n = int.from_bytes(b[off:off + 32], "big")
    return b[off + 32:off + 32 + n].decode("utf-8")


def main(argv):
    out = argv[1]
    nblocks = int(argv[2]) if len(argv) > 2 else 200
    maxtx = int(argv[3]) if len(argv) > 3 else 200
    calls = []
    sel = {"0x" + keccak256(SIG_VRS.encode())[:4].hex(): "vrs", "0x" + keccak256(SIG_BYTES.encode())[:4].hex(): "bytes"}
    topic = "0x" + keccak256(EVENT.encode()).hex()
    chain = rpc("eth_chainId", [])
    calls.append(chain)
    head = rpc("eth_blockNumber", [])
    calls.append(head)
    name = rpc("eth_call", [{"to": USDC, "data": "0x" + keccak256(b"name()")[:4].hex()}, head["result"]])
    calls.append(name)
    try:
        ver = rpc("eth_call", [{"to": USDC, "data": "0x" + keccak256(b"version()")[:4].hex()}, head["result"]])
        calls.append(ver)
        token_version = abi_string(ver["result"])
    except SystemExit:          # no public version() (JPYC): the domain version is found from an execution later
        token_version = os.environ.get("APC_TOKEN_VERSION")
    hi = int(head["result"], 16)
    logs = []
    step = int(os.environ.get("APC_LOG_STEP", "10"))
    for lo in range(hi - nblocks + 1, hi + 1, step):
        g = rpc("eth_getLogs", [{"address": USDC, "topics": [topic], "fromBlock": hex(lo), "toBlock": hex(min(hi, lo + step - 1))}])
        calls.append(g)
        logs += g["result"]
    seen, kept = set(), []
    for lg in logs:
        h = lg["transactionHash"]
        if h in seen:
            continue
        seen.add(h)
        tx = rpc("eth_getTransactionByHash", [h])
        if (tx["result"]["to"] or "").lower() != USDC or tx["result"]["input"][:10] not in sel:
            continue
        calls.append(tx)
        # no receipt call (publicnode answers 403): a reverted transaction emits no logs, so the AuthorizationUsed
        # log this hash came from already shows the execution succeeded
        kept.append({"tx": h, "form": sel[tx["result"]["input"][:10]], "block": tx["result"]["blockNumber"],
                     "status": "0x1"})
        if len(kept) >= maxtx:
            break
    summary = {"rpc": RPC, "token": USDC, "chain_id": int(chain["result"], 16), "head_block": hi,
               "blocks_scanned": nblocks, "token_name": abi_string(name["result"]), "token_version": token_version,
               "authorization_used_logs": len(logs), "distinct_tx": len(seen), "direct_calls_kept": len(kept),
               "by_form": {f: sum(k["form"] == f for k in kept) for f in ("vrs", "bytes")}}
    with open(out, "x") as fh:
        json.dump({"summary": summary, "kept": kept, "calls": calls}, fh, indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main(sys.argv)
