"""Fetch the token's Transfer logs for the blocks of a census file, so that each AuthorizationUsed(from, nonce) can be
paired with the Transfer(from, to, value) that Circle's EIP3009.sol emits right after it (_markAuthorizationAsUsed then
_transfer; FiatTokenV1._transfer emits Transfer). Read-only; raw replies saved.

  python3 tools/log_pairs.py CENSUS.json OUT.json"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.fetch_base_eip3009 import rpc, keccak256  # noqa: E402

TRANSFER = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()


def main(argv):
    doc = json.load(open(argv[1]))
    token = doc["summary"]["token"]
    blocks = sorted({lg["blockHash"] for c in doc["calls"] if c["method"] == "eth_getLogs" for lg in c["result"]})
    calls = []
    for bh in blocks:
        calls.append(rpc("eth_getLogs", [{"address": token, "topics": [TRANSFER], "blockHash": bh}]))
    with open(argv[2], "x") as fh:
        json.dump({"census": os.path.basename(argv[1]), "calls": calls}, fh, indent=1)
    print(len(blocks), "blocks", sum(len(c["result"]) for c in calls), "Transfer logs")


if __name__ == "__main__":
    main(sys.argv)
