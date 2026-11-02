"""Census of who settles EIP-3009 authorizations of a token: every transaction that made the token emit
AuthorizationUsed over a block range, with its sender, the contract it calls, the 4-byte selector and the ERC-8021
tag of its calldata tail (when the call is directly to the token). Read-only JSON-RPC; every raw reply is saved.

  python3 tools/census_eip3009.py OUT.json TOKEN FROM_BLOCK N_BLOCKS

The point: direct calls to the token are what apc 0.1 checks (C1); calls through another contract are counted here
so the share left out is measured, not assumed."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.fetch_base_eip3009 import rpc, keccak256, abi_string, SIG_VRS, SIG_BYTES, EVENT  # noqa: E402
from apc_verify import erc8021_schema2  # noqa: E402


def tail_of(inp, form):
    b = bytes.fromhex(inp[2:])
    if form == "vrs":
        return b[4 + 9 * 32:]
    off = int.from_bytes(b[4 + 6 * 32:4 + 7 * 32], "big")
    n = int.from_bytes(b[4 + off:4 + off + 32], "big")
    return b[4 + off + 32 + (n + 31) // 32 * 32:]


def main(argv):
    out, token, lo, n = argv[1], argv[2].lower(), int(argv[3]), int(argv[4])
    sel = {"0x" + keccak256(SIG_VRS.encode())[:4].hex(): "vrs", "0x" + keccak256(SIG_BYTES.encode())[:4].hex(): "bytes"}
    topic = "0x" + keccak256(EVENT.encode()).hex()
    calls = [rpc("eth_chainId", [])]
    last = hex(lo + n - 1)
    name = rpc("eth_call", [{"to": token, "data": "0x" + keccak256(b"name()")[:4].hex()}, last])
    calls.append(name)
    ver = rpc("eth_call", [{"to": token, "data": "0x" + keccak256(b"version()")[:4].hex()}, last])
    calls.append(ver)
    logs = []
    step = int(os.environ.get("APC_LOG_STEP", "10"))      # blocks per eth_getLogs (default 10, as on 2026-10-22)
    for a in range(lo, lo + n, step):
        g = rpc("eth_getLogs", [{"address": token, "topics": [topic], "fromBlock": hex(a), "toBlock": hex(min(lo + n - 1, a + step - 1))}])
        calls.append(g)
        logs += g["result"]
    per_tx = {}
    for lg in logs:
        per_tx.setdefault(lg["transactionHash"], 0)
        per_tx[lg["transactionHash"]] += 1
    rows = []
    for h, k in per_tx.items():
        t = rpc("eth_getTransactionByHash", [h])
        calls.append(t)
        tx = t["result"]
        to = (tx["to"] or "").lower()
        s = tx["input"][:10].lower()
        tag = None
        if to == token and s in sel:
            tail = tail_of(tx["input"], sel[s])
            tag = "none" if not tail else (erc8021_schema2(tail) or "unrecognized")
        rows.append({"tx": h, "from": tx["from"].lower(), "to": to, "selector": s, "authorizations": k,
                     "direct": to == token and s in sel, "erc8021_cbor": tag})
    summary = {"token": token, "chain_id": int(calls[0]["result"], 16), "from_block": lo, "n_blocks": n,
               "token_name": abi_string(name["result"]), "token_version": abi_string(ver["result"]),
               "logs": len(logs), "tx": len(rows), "direct": sum(r["direct"] for r in rows)}
    with open(out, "x") as fh:
        json.dump({"summary": summary, "rows": rows, "calls": calls}, fh, indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main(sys.argv)
