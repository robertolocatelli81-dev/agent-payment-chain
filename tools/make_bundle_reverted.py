"""A real reverted EIP-3009 settlement on Base as an apc-0.3 bundle (SPEC Amendment 0.3.3).

REAL: the transaction and its status-0 receipt (oracle/reverted_53020172/scan_*.json, tools/scan_reverted.py), the block
and all its receipts (eth_getBlockByNumber / eth_getBlockReceipts), the inclusion built from them by tools/inclusion.py,
the authorization and signature decoded from the transaction input. RECONSTRUCTED: the x402 envelope (`accepted` with
payTo = to and amount = value, the USDC domain) and the settlement reply, which states success: the claim this bundle
tests (no facilitator reply for this transaction is known).

  python3 tools/make_bundle_reverted.py bundles/real_reverted/r001_status0_success_claim_reconstructed.json"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_bundle_reverted", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from tools.check_eip3009_oracle import decode  # noqa: E402

DATA = os.path.join(ROOT, "oracle", "reverted_53020172")
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"


def main(out):
    scan = json.load(open(os.path.join(DATA, "scan_53019382_1500.json")))
    tx, rc = scan["calls"][0]["result"], scan["calls"][1]["result"]
    assert rc["status"] == "0x0" and tx["input"][:10] == "0xe3ee160e" and rc["transactionHash"] == tx["hash"]
    msg, (v, r, s) = decode("vrs", tx["input"])
    inc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "inclusion.py"),
                          os.path.join(DATA, "eth_getBlockByNumber_53020172.json"),
                          os.path.join(DATA, "eth_getBlockReceipts_53020172.json"), tx["hash"]],
                         capture_output=True, text=True, check=True).stdout
    bundle = {
        "bundle_version": "apc-0.3",
        "payment_payload": {
            "x402Version": 2,
            "accepted": {"scheme": "exact", "network": "eip155:8453", "amount": str(msg["value"]), "asset": USDC,
                         "payTo": msg["to"], "maxTimeoutSeconds": 60, "extra": {"name": "USD Coin", "version": "2"}},
            "payload": {"signature": "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex(),
                        "authorization": {k: (str(x) if isinstance(x, int) else x) for k, x in msg.items()}}},
        "settlement": {"success": True, "transaction": tx["hash"], "network": "eip155:8453", "payer": msg["from"]},
        "chain_tx": {"network": "eip155:8453", "tx": tx},
        "inclusion": json.loads(inc),
    }
    with open(out, "w") as fh:
        json.dump(bundle, fh, indent=1)
    print("written", out)


if __name__ == "__main__":
    main(sys.argv[1])
