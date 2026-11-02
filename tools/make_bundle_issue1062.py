"""The real case of x402-foundation/x402#1062 (lpender, 2026-01-31) as an apc-0.1 bundle.

REAL: the transaction 0x8e01…e696 and its receipt as Base mainnet returns them (data_1062/, fetched 2026-10-24), the
authorization and the signature decoded from its input, and from the facilitator's settlement reply quoted in the
issue its errorReason "settle_exact_node_failure", network and transaction hash (the quote has no `success`: false is
supplied; its `errorMessage` is left out, not a SettlementResponse member of x402 v2 5.3.2). RECONSTRUCTED, as for
bundles/real: `accepted` (payTo = to, amount = value, the USDC domain) and the x402 envelope.

  python3 tools/make_bundle_issue1062.py bundles/real_issue1062/issue1062_envelope_reconstructed.json"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_bundle_issue1062", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from tools.check_eip3009_oracle import decode  # noqa: E402

DATA = os.path.join(ROOT, "oracle", "issue1062")
H = "0x8e01aace01ced4155b30d636b547727becdbb8a700f9b7f54ed02c4d629ae696"


def main(out):
    tx = json.load(open(os.path.join(DATA, "eth_getTransactionByHash.json")))["result"]
    rc = json.load(open(os.path.join(DATA, "eth_getTransactionReceipt.json")))["result"]
    assert tx["hash"] == H and rc["status"] == "0x1" and tx["input"][:10] == "0xe3ee160e"
    msg, (v, r, s) = decode("vrs", tx["input"])
    used = [lg for lg in rc["logs"] if lg["topics"][0] == "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"]
    assert len(used) == 1 and used[0]["topics"][2] == msg["nonce"]
    lg = dict(used[0])
    lg.setdefault("blockTimestamp", tx.get("blockTimestamp"))
    usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    bundle = {
        "bundle_version": "apc-0.1",
        "payment_payload": {
            "x402Version": 2,
            "accepted": {"scheme": "exact", "network": "eip155:8453", "amount": str(msg["value"]), "asset": usdc,
                         "payTo": msg["to"], "maxTimeoutSeconds": 60, "extra": {"name": "USD Coin", "version": "2"}},
            "payload": {"signature": "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex(),
                        "authorization": {k: (str(x) if isinstance(x, int) else x) for k, x in msg.items()}}},
        # the reply quoted in the issue: "Facilitator settle failed (500): {errorMessage, errorReason, network, transaction}"
        "settlement": {"success": False, "errorReason": "settle_exact_node_failure", "network": "eip155:8453",
                       "transaction": H},
        "chain_tx": {"network": "eip155:8453", "tx": tx, "log_authorization_used": lg},
    }
    with open(out, "w") as fh:
        json.dump(bundle, fh, indent=1)
    print("written", out, "value", msg["value"], "from", msg["from"], "to", msg["to"])


if __name__ == "__main__":
    main(sys.argv[1])
