"""Measured search, offline over the saved RPC replies under oracle/: (1) logs with removed = true among every saved
log (unique by transaction hash and log index); (2) EIP-3009 executions of value zero: each AuthorizationUsed log
paired with the Transfer log the same token emitted in the same transaction (the next Transfer after it).

  python3 tools/count_removed_zero.py [ORACLE_DIR]"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/count_removed_zero", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from lib.eip712 import keccak256  # noqa: E402

USED = "0x" + keccak256(b"AuthorizationUsed(address,bytes32)").hex()
TRANSFER = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()


def logs_in(o, out):
    if isinstance(o, dict):
        if isinstance(o.get("topics"), list) and "logIndex" in o and "transactionHash" in o and "address" in o:
            out[(o["transactionHash"].lower(), o["logIndex"])] = o
        for v in o.values():
            logs_in(v, out)
    elif isinstance(o, list):
        for v in o:
            logs_in(v, out)


def main(argv):
    root = argv[1] if len(argv) > 1 else "oracle"
    logs = {}
    files = sorted(glob.glob(os.path.join(root, "**", "*.json"), recursive=True))
    for f in files:
        try:
            with open(f) as fh:
                logs_in(json.load(fh), logs)
        except (ValueError, UnicodeDecodeError):
            continue
    removed = sum(1 for lg in logs.values() if lg.get("removed") is True)
    by_tx = {}
    for (tx, li), lg in logs.items():
        by_tx.setdefault(tx, []).append(lg)
    used = paired = zero = 0
    for tx, lgs in by_tx.items():
        lgs.sort(key=lambda lg: int(lg["logIndex"], 16))
        for i, lg in enumerate(lgs):
            if lg["topics"] and lg["topics"][0].lower() == USED:
                used += 1
                nxt = [t for t in lgs[i + 1:] if t["topics"] and t["topics"][0].lower() == TRANSFER
                       and t["address"].lower() == lg["address"].lower()]
                if nxt:
                    paired += 1
                    zero += int(nxt[0]["data"], 16) == 0 if nxt[0]["data"] not in ("0x", "") else 1
    print(json.dumps({"files": len(files), "logs": len(logs), "removed_true": removed, "authorization_used": used,
                      "paired_with_transfer": paired, "zero_value": zero}))


if __name__ == "__main__":
    main(sys.argv)
