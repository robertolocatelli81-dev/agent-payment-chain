"""Bundles from real x402 Permit2 settlements on Base (transactions to the x402ExactPermit2Proxy, fetched by RPC with
their receipts). REAL: the permit, the witness, the signature, the transaction and its logs, as the RPC returned them.
RECONSTRUCTED here, from the calldata: the x402 envelope (`accepted` with asset = permitted.token, payTo = witness.to,
amount = permitted.amount, maxTimeoutSeconds 60, extra {assetTransferMethod: permit2}; spender = the proxy the
transaction calls; the settlement response). The reconstruction is stated in bundles/real_permit2/README.

  python3 tools/make_bundles_permit2.py TXS.json[.gz] OUTDIR [NAME ...]      (only the NAMEs if given; TXS: {"items": {hash: {"tx": reply, "receipt": reply}}})"""
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_bundles_permit2", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_verify  # noqa: E402,F401
import apc_permit2 as p2  # noqa: E402


def decode(inp):
    b = bytes.fromhex(inp[2:])
    base = 0 if b[:4] == p2.SEL_SETTLE else 5
    w = lambda i: int.from_bytes(b[4 + 32 * (base + i): 4 + 32 * (base + i + 1)], "big")  # noqa: E731
    a = lambda i: "0x%040x" % w(i)  # noqa: E731
    off = w(7)
    n = int.from_bytes(b[4 + off: 4 + off + 32], "big")
    return {"token": a(0), "amount": w(1), "nonce": w(2), "deadline": w(3), "from": a(4), "to": a(5),
            "validAfter": w(6)}, "0x" + b[4 + off + 32: 4 + off + 32 + n].hex()


def build(items):
    """[(name, bundle)] in block order, and the skipped transactions with the reason."""
    out, skipped = [], []
    for h in sorted(items, key=lambda h: (int(items[h]["tx"]["result"]["blockNumber"], 16), h)):
        tx, rc = items[h]["tx"]["result"], items[h]["receipt"]["result"]
        if tx["to"].lower() != p2.EXACT_PROXY or rc["status"] != "0x1":
            skipped.append((h, "not a direct successful call"))
            continue
        au, sig = decode(tx["input"])
        settled = [lg for lg in rc["logs"] if lg["address"].lower() == p2.EXACT_PROXY
                   and lg["topics"][0] in (p2.TOPIC_SETTLED, p2.TOPIC_SETTLED_PERMIT)]
        pad = "0x" + "0" * 24
        tr = [lg for lg in rc["logs"] if lg["address"].lower() == au["token"] and lg["topics"][0] == p2.TRANSFER_TOPIC
              and lg["topics"][1] == pad + au["from"][2:] and lg["topics"][2] == pad + au["to"][2:]]
        if len(settled) != 1 or len(tr) != 1:
            skipped.append((h, "settled %d, transfers %d" % (len(settled), len(tr))))
            continue
        net = "eip155:%d" % int(tx["chainId"], 16)
        acc = {"scheme": "exact", "network": net, "amount": str(au["amount"]), "asset": au["token"], "payTo": au["to"],
               "maxTimeoutSeconds": 60, "extra": {"assetTransferMethod": "permit2"}}
        b = {"bundle_version": "apc-0.10",
             "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {"signature": sig, "permit2Authorization": {
                 "permitted": {"token": au["token"], "amount": str(au["amount"])}, "from": au["from"],
                 "spender": p2.EXACT_PROXY, "nonce": str(au["nonce"]), "deadline": str(au["deadline"]),
                 "witness": {"to": au["to"], "validAfter": str(au["validAfter"])}}}},
             "settlement": {"success": True, "transaction": h, "network": net, "payer": au["from"]},
             "chain_tx": {"network": net, "tx": tx, "log_transfer": tr[0], "log_settled": settled[0]}}
        out.append(("p%03d_envelope_reconstructed.json" % (len(out) + 1), b))
    return out, skipped


def load(path):
    with (gzip.open(path, "rt") if path.endswith(".gz") else open(path)) as fh:
        return json.load(fh)["items"]


def main(argv):
    out, skipped = build(load(argv[1]))
    keep = set(argv[3:])
    for name, b in out:
        if keep and name not in keep:
            continue
        with open(os.path.join(argv[2], name), "x") as fh:
            json.dump(b, fh, indent=1)
    print(len(out), "bundles;", len(skipped), "skipped", skipped[:10])


if __name__ == "__main__":
    main(sys.argv)
