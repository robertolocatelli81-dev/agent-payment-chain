"""Bundles apc-0.16 from real XRPL mainnet Payments (tools/fetch_xrpl_ledgers.py output). The requirements are
RECONSTRUCTED from each transaction (payTo = Destination, asset and amount = Amount, destinationTag, issuer), as a
server that asked for exactly this payment would have written them; the invoiceId string behind an InvoiceID is not
on chain and is left out. The first Payment of each ledger also carries the ledger's whole transaction set
(inclusion). These are XRPL payments, not known to be x402 ones.

  python3 tools/make_bundles_xrp.py ORACLE.json OUTDIR"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_xrpl as xr  # noqa: E402


def build_one(t, L, ledger_index, provenance, first):
    """The apc-0.16 bundle of one transaction of ledger L (binary form), or None if it is not a Payment this tool
    bundles; `first` adds the ledger's whole transaction set (inclusion)."""
    tb = bytes.fromhex(t["tx_blob"])
    f, v = xr.decode(tb)
    if int.from_bytes(v["TransactionType"], "big") != xr.TX_TYPES["Payment"]:
        return None
    am = v["Amount"]
    if am[0] == "mpt":
        return None
    ex = {"areFeesSponsored": False}
    if "TicketSequence" in v:
        ex["assetTransferMethod"] = "ticketSequence"
    if "DestinationTag" in v:
        ex["destinationTag"] = int.from_bytes(v["DestinationTag"], "big")
    if am[0] == "xrp":
        asset, amount = "XRP", str(am[1])
    else:
        m, e = xr.iou_value(am[1])
        if m < 0:
            return None
        digits = str(m)
        if e >= 0:
            amount = digits + "0" * e
        else:
            digits = digits.rjust(-e + 1, "0")
            amount = (digits[:e] + "." + digits[e:]).rstrip("0").rstrip(".")
        cur = am[2]
        asset = cur[12:15].decode("ascii") if cur[:12] == bytes(12) and cur[15:] == bytes(5) else cur.hex().upper()
        ex["issuer"] = xr.classic_address(am[3])
    acc = {"scheme": "exact", "network": "xrpl:0", "asset": asset, "payTo": xr.classic_address(v["Destination"]),
           "amount": amount, "maxTimeoutSeconds": 600, "extra": ex}
    tid = xr.tx_id(tb)
    b = {"bundle_version": "apc-0.16",
         "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {"signedTxBlob": t["tx_blob"]}},
         "settlement": {"success": True, "transaction": tid, "network": "xrpl:0",
                        "payer": xr.classic_address(v["Account"])},
         "chain_tx": {"tx_blob": t["tx_blob"], "meta": t["meta"], "ledger_index": ledger_index},
         "provenance": provenance}
    if first:
        b["inclusion"] = {"ledger_data": L["ledger_data"],
                          "transactions": [{"tx_blob": x["tx_blob"], "meta": x["meta"]} for x in L["transactions"]]}
    return b


def main(argv):
    d = json.load(open(argv[1]))
    out = argv[2]
    os.makedirs(out, exist_ok=True)
    n = 0
    prov = {"chain_tx": {"source": "XRPL mainnet %s ledger (binary), tools/fetch_xrpl_ledgers.py" % d["server"],
                         "fetched": d["fetched"]},
            "settlement": {"source": "reconstructed from chain_tx, as the requirements (tools/make_bundles_xrp.py)",
                           "fetched": d["fetched"]}}
    for c in d["calls"]:
        if not c["params"].get("binary"):
            continue
        L = c["result"]["ledger"]
        first = True
        for t in L["transactions"]:
            b = build_one(t, L, c["params"]["ledger_index"], prov, first)
            if b is None:
                continue
            first = False
            with open(os.path.join(out, b["settlement"]["transaction"][:12].lower() + ".json"), "w") as fh:
                json.dump(b, fh, indent=1, sort_keys=True)
            n += 1
    print(n, "bundles")


if __name__ == "__main__":
    main(sys.argv)
