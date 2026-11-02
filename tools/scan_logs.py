"""All logs emitted by one contract over a block range, in steps the public RPC accepts; every raw reply saved.

  BASE_RPC=<url> python3 tools/scan_logs.py OUT.json ADDRESS FROM_BLOCK N_BLOCKS [STEP]

Used to find real x402 Permit2 settlements (logs of the x402ExactPermit2Proxy). A step the RPC refuses stops the scan
with the RPC's own message; nothing is skipped silently."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/scan_logs", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from tools.fetch_base_eip3009 import RPC, rpc  # noqa: E402


def main(argv):
    out, addr, lo, n = argv[1], argv[2].lower(), int(argv[3]), int(argv[4])
    step = int(argv[5]) if len(argv) > 5 else 100
    calls, logs = [], []
    for a in range(lo, lo + n, step):
        g = rpc("eth_getLogs", [{"address": addr, "fromBlock": hex(a), "toBlock": hex(min(lo + n - 1, a + step - 1))}])
        calls.append(g)
        logs += g["result"]
    summary = {"rpc": RPC, "address": addr, "from_block": lo, "n_blocks": n, "step": step, "logs": len(logs),
               "tx": len({lg["transactionHash"] for lg in logs})}
    with open(out, "x") as fh:
        json.dump({"summary": summary, "calls": calls}, fh, indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main(sys.argv)
