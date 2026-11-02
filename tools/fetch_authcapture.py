"""Real auth-capture data (x402 scheme auth-capture, commerce-payments escrow on Base): PaymentAuthorized and
PaymentCharged logs of the escrow over a block range, and the emitting transactions (their input carries the
collectorData, the client's ERC-3009 signature). Read-only public JSON-RPC; every raw reply is saved.

  python3 tools/fetch_authcapture.py OUT.json ESCROW FROM_BLOCK TO_BLOCK [STEP] [MAX_TX]"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fetch_base_eip3009 import rpc, keccak256  # noqa: E402

PI = "(address,address,address,address,uint120,uint48,uint48,uint48,uint16,uint16,address,uint256)"
EVENTS = {"authorized": "PaymentAuthorized(bytes32,%s,uint256,address)" % PI,
          "charged": "PaymentCharged(bytes32,%s,uint256,address,uint256,address)" % PI}


def main(argv):
    out, escrow, lo, hi = argv[1], argv[2].lower(), int(argv[3]), int(argv[4])
    step = int(argv[5]) if len(argv) > 5 else 10000
    maxtx = int(argv[6]) if len(argv) > 6 else 40
    topics = {"0x" + keccak256(s.encode()).hex(): k for k, s in EVENTS.items()}
    calls, logs = [rpc("eth_chainId", [])], []
    b = lo
    while b <= hi:
        e = min(b + step - 1, hi)
        c = rpc("eth_getLogs", [{"address": escrow, "fromBlock": hex(b), "toBlock": hex(e), "topics": [list(topics)]}])
        calls.append(c)
        logs += c["result"]
        b = e + 1
        if len(logs) >= maxtx:
            break
    seen = []
    for lg in logs:
        if lg["transactionHash"] not in seen and len(seen) < maxtx:
            seen.append(lg["transactionHash"])
            calls.append(rpc("eth_getTransactionByHash", [lg["transactionHash"]]))
            calls.append(rpc("eth_getTransactionReceipt", [lg["transactionHash"]]))
    with open(out, "w") as fh:
        json.dump({"escrow": escrow, "range": [lo, hi], "events": EVENTS, "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "calls": calls}, fh, indent=1)
    print(len(logs), "logs", len(seen), "transactions")


if __name__ == "__main__":
    main(sys.argv)
