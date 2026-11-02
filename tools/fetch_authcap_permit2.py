"""Search for real auth-capture payments collected through the commerce-payments Permit2 collector (SPEC 0.16.1,
section 25.1): every PaymentAuthorized / PaymentCharged log of an escrow over a block range, kept when its tokenCollector
(the data word after PaymentInfo and amount) is the deployment's Permit2 collector. Read-only public JSON-RPC
(eth_getLogs); the full replies are too large to keep, so each window's reply is summarised by its log count, the count
per collector and the sha256 of its canonical JSON; the matching logs, their transactions and receipts are kept whole.

  python3 tools/fetch_authcap_permit2.py OUT.json ESCROW PERMIT2_COLLECTOR FROM_BLOCK TO_BLOCK [STEP] [MAX_TX]"""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/fetch_authcap_permit2", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from fetch_base_eip3009 import RPC, keccak256, rpc  # noqa: E402

PI = "(address,address,address,address,uint120,uint48,uint48,uint48,uint16,uint16,address,uint256)"
EVENTS = {"authorized": "PaymentAuthorized(bytes32,%s,uint256,address)" % PI,
          "charged": "PaymentCharged(bytes32,%s,uint256,address,uint256,address)" % PI}


def collector(lg):
    data = bytes.fromhex(lg["data"][2:])
    return "0x" + data[13 * 32 + 12:14 * 32].hex()      # PaymentInfo is 12 words, then amount, then tokenCollector


def main(argv):
    out, escrow, p2c, lo, hi = argv[1], argv[2].lower(), argv[3].lower(), int(argv[4]), int(argv[5])
    step = int(argv[6]) if len(argv) > 6 else 10000
    maxtx = int(argv[7]) if len(argv) > 7 else 20
    topics = ["0x" + keccak256(s.encode()).hex() for s in EVENTS.values()]
    windows, hits, calls = [], [], [rpc("eth_chainId", [])]
    b = lo
    while b <= hi:
        e = min(b + step - 1, hi)
        c = rpc("eth_getLogs", [{"address": escrow, "fromBlock": hex(b), "toBlock": hex(e), "topics": [topics]}])
        per = {}
        for lg in c["result"]:
            per[collector(lg)] = per.get(collector(lg), 0) + 1
            if collector(lg) == p2c:
                hits.append(lg)
        windows.append({"from": b, "to": e, "logs": len(c["result"]), "by_collector": per,
                        "sha256": hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()})
        b = e + 1
    seen = []
    for lg in hits:
        if lg["transactionHash"] not in seen and len(seen) < maxtx:
            seen.append(lg["transactionHash"])
            calls.append(rpc("eth_getTransactionByHash", [lg["transactionHash"]]))
            calls.append(rpc("eth_getTransactionReceipt", [lg["transactionHash"]]))
    total = {}
    for w in windows:
        for k, v in w["by_collector"].items():
            total[k] = total.get(k, 0) + v
    with open(out, "w") as fh:
        json.dump({"rpc": RPC, "escrow": escrow, "permit2_collector": p2c, "range": [lo, hi], "step": step,
                   "events": EVENTS, "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "logs": sum(w["logs"] for w in windows), "by_collector": total, "permit2_logs": hits,
                   "windows": windows, "calls": calls}, fh, indent=1)
    print(sum(w["logs"] for w in windows), "logs", total, len(hits), "through the Permit2 collector", len(seen), "transactions")


if __name__ == "__main__":
    main(sys.argv)
