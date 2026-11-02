"""Build the apc-0.5 bundles of bundles/real_svm from real Solana data (SPEC 0.5, section 7).

  python3 tools/make_bundles_svm.py ROOT

Inputs (sources/solana_20261024, SHA256SUMS.txt there): getTransaction replies (encoding base64) of the transactions
signed by the fee payers x402scan@5732bb8 lists for 8 facilitators, and of one payment made for this work on mainnet.
The x402 payload is rebuilt: the confirmed transaction with the fee payer's signature set to 64 zero bytes (the
partially signed transaction of SVM step 4). accepted.asset, .amount and .payTo come from the first top-level
TransferChecked (payTo = the owner of its destination in the RPC's postTokenBalances), extra.feePayer from account 0,
maxTimeoutSeconds is set to 60 by this tool; the settlement reply names the confirmed transaction. A transaction whose
account 0 is not the listed fee payer, or with no top-level TransferChecked, is not an x402 exact payment and is listed
in the manifest as skipped, with the reason."""
import base64
import json
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_solana as sol  # noqa: E402

MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SRC = os.path.join(ROOT, "sources", "solana_20261024")
if not os.path.isfile(os.path.join(SRC, "solana_x402_20261024.json")):
    sys.exit("sources/solana_20261024: the saved RPC replies are not in the public tree (kept with the corpus); fetch them with tools/fetch_solana_feepayers.py, or rebuild the set: tools/rebuild_corpus.py --only real_svm")
OUT = os.path.join(ROOT, "bundles", "real_svm")
META = ("err", "fee", "preTokenBalances", "postTokenBalances", "innerInstructions", "loadedAddresses")


def bal(b):
    u = b["uiTokenAmount"]
    return {"accountIndex": b["accountIndex"], "mint": b["mint"], "owner": b["owner"], "programId": b["programId"],
            "uiTokenAmount": {"amount": u["amount"], "decimals": u["decimals"]}}


def bundle(r, fee_payer_listed, memo=None, accepted=None):
    raw = base64.b64decode(r["transaction"][0])
    tx = sol.parse_tx(raw)
    if fee_payer_listed is not None and tx["keys"][0] != fee_payer_listed:
        return None, "account 0 is not the listed fee payer"
    first = next((t for t in (sol.transfer_checked(tx, ix) for ix in tx["instructions"]) if t), None)
    if first is None:
        return None, "no top-level TransferChecked"
    m = r["meta"]
    owners = {b["accountIndex"]: b["owner"] for b in m["postTokenBalances"]}
    dest = tx["keys"].index(first["destination"])
    acc = accepted or {"scheme": "exact", "network": MAINNET, "amount": str(first["amount"]), "asset": first["mint"],
                       "payTo": owners[dest], "maxTimeoutSeconds": 60, "extra": {"feePayer": tx["keys"][0]}}
    if memo is not None:
        acc["extra"]["memo"] = memo
    n = raw[0]                                   # signature count (< 128: one shortvec byte)
    payload = raw[:1] + bytes(64) + raw[65:]     # the fee payer's slot is the first signature
    assert n == len(tx["signatures"]) and sol.parse_tx(payload)["message"] == tx["message"]
    meta = {k: m[k] for k in META}
    meta["preTokenBalances"] = [bal(b) for b in m["preTokenBalances"]]
    meta["postTokenBalances"] = [bal(b) for b in m["postTokenBalances"]]
    return {"bundle_version": "apc-0.5",
            "payment_payload": {"x402Version": 2, "accepted": acc,
                                "payload": {"transaction": base64.b64encode(payload).decode()}},
            "settlement": {"success": True, "transaction": sol.b58encode(tx["signatures"][0]), "network": MAINNET},
            "chain_tx": {"slot": r["slot"], "blockTime": r["blockTime"], "transaction": r["transaction"][0],
                         "meta": meta}}, None


def main():
    os.makedirs(OUT, exist_ok=True)
    d = json.load(open(os.path.join(SRC, "solana_x402_20261024.json")))
    man = {"source": "sources/solana_20261024 (SHA256SUMS.txt)", "rpc": d["rpc"], "fetched_utc": d["fetched_utc"],
           "bundles": [], "skipped": []}
    for k, t in enumerate(d["txs"]):
        b, why = bundle(t["raw"], t["fee_payer_listed"])
        name = "s%03d_%s.json" % (k, t["facilitator"])
        if b is None:
            man["skipped"].append({"signature": t["signature"], "facilitator": t["facilitator"], "reason": why})
            continue
        with open(os.path.join(OUT, name), "w") as fh:
            json.dump(b, fh, indent=1, sort_keys=True)
        man["bundles"].append({"file": name, "facilitator": t["facilitator"], "signature": t["signature"],
                               "kind": "reconstructed payload (fee payer signature zeroed)"})
    mp = json.load(open(os.path.join(SRC, "mainnet_payment_20261024.json")))
    sig = mp["transactions"]["payment"]
    ro = mp["roles"]
    acc = {"scheme": "exact", "network": MAINNET, "amount": str(mp["amount"]), "asset": ro["mint"], "payTo": ro["merchant"],
           "maxTimeoutSeconds": 60, "extra": {"feePayer": ro["payer"]}}
    b, why = bundle(mp["getTransaction"][sig], ro["payer"], mp["memo"], acc)
    assert b is not None, why
    with open(os.path.join(OUT, "m001_mainnet_payment_20261024.json"), "w") as fh:
        json.dump(b, fh, indent=1, sort_keys=True)
    man["bundles"].append({"file": "m001_mainnet_payment_20261024.json", "signature": sig,
                           "kind": "payment made for this work, 2026-10-24 (throwaway client, merchant and mint)"})
    with open(os.path.join(OUT, "MANIFEST.json"), "w") as fh:
        json.dump(man, fh, indent=1, sort_keys=True)
    print("bundles %d, skipped %d" % (len(man["bundles"]), len(man["skipped"])))


if __name__ == "__main__":
    main()
