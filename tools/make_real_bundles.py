"""Bundles from the real executions in an oracle file (fetch_base_eip3009.py). REAL: the authorization, the signature,
the transaction and its AuthorizationUsed log, as the RPC returned them. RECONSTRUCTED here, from those: the x402
envelope (`accepted` with payTo = to and amount = value, the settlement response). The reconstruction is stated in
each bundle's file name and in bundles/real/README.

  python3 tools/make_real_bundles.py ORACLE.json OUTDIR"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_real_bundles", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
from tools.check_eip3009_oracle import decode  # noqa: E402


def main(argv):
    doc = json.load(open(argv[1]))
    s = doc["summary"]
    if "rows" in doc:                       # census_eip3009.py output: the direct calls are the ones apc 0.1 checks
        sel = {"0xe3ee160e": "vrs", "0xcf092995": "bytes"}
        doc["kept"] = [{"tx": r["tx"], "form": sel[r["selector"]]} for r in doc["rows"] if r["direct"]]
    txs = {c["params"][0]: c["result"] for c in doc["calls"] if c["method"] == "eth_getTransactionByHash"}
    logs = {}
    for c in doc["calls"]:
        if c["method"] == "eth_getLogs":
            for lg in c["result"]:
                logs.setdefault(lg["transactionHash"], []).append(lg)
    n = 0
    for k in doc["kept"]:
        tx = txs[k["tx"]]
        msg, sig = decode(k["form"], tx["input"])
        if sig[0] == "contract":
            continue
        v, r, sv = sig
        signature = "0x" + r.to_bytes(32, "big").hex() + sv.to_bytes(32, "big").hex() + bytes([v]).hex()
        mine = [lg for lg in logs.get(k["tx"], []) if lg["topics"][2].lower() == msg["nonce"]]
        if len(mine) != 1:
            continue
        net = "eip155:%d" % s["chain_id"]
        acc = {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": s["token"],
               "payTo": msg["to"], "maxTimeoutSeconds": 60, "extra": {"name": s["token_name"], "version": s["token_version"]}}
        b = {"bundle_version": "apc-0.1",
             "payment_payload": {"x402Version": 2, "accepted": acc,
                                 "payload": {"signature": signature, "authorization": {
                                     "from": msg["from"], "to": msg["to"], "value": str(msg["value"]),
                                     "validAfter": str(msg["validAfter"]), "validBefore": str(msg["validBefore"]),
                                     "nonce": msg["nonce"]}}},
             "settlement": {"success": True, "transaction": k["tx"], "network": net, "payer": msg["from"]},
             "chain_tx": {"network": net, "tx": tx, "log_authorization_used": mine[0]}}
        n += 1
        with open(os.path.join(argv[2], "real_%03d_envelope_reconstructed.json" % n), "x") as fh:
            json.dump(b, fh, indent=1)
    print(n, "bundles")


if __name__ == "__main__":
    main(sys.argv)
