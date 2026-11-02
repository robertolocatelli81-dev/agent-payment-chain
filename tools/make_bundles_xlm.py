"""apc-0.12 bundles (SPEC section 20) from oracle/stellar_20261026 (tools/fetch_stellar_x402org.py). REAL: the
operation and its authorization entries signed by the payer, the settled transaction as the RPC returned it, the
facilitator's signer list from its /supported. RECONSTRUCTED here: the x402 envelope (accepted from the transfer's
asset, recipient and amount; maxTimeoutSeconds 300, the x402 ResourceServer default, x402ResourceServer.ts 826) and
the client's payload transaction, which the facilitator does not publish: the real operation in a transaction whose
source is the all-zero account (not the client's real source, which no public record gives), fee and Soroban data
copied, sequence 0, no signatures (the client signs the authorization entries, not the transaction, XLM step 4).

  python3 tools/make_bundles_xlm.py ORACLE.json OUTDIR"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_stellar as xs  # noqa: E402

FETCHED = "2026-10-26T07:16:39Z"     # when tools/fetch_stellar_x402org.py wrote the oracle (file time, UTC)


def payload_tx(tx):
    zero = bytes(32)
    b = (2).to_bytes(4, "big") + (0).to_bytes(4, "big") + zero + tx["fee"].to_bytes(4, "big") + bytes(8) \
        + (0).to_bytes(4, "big") + (0).to_bytes(4, "big") + (1).to_bytes(4, "big") + tx["ops"][0]["body_raw"] \
        + tx["ext_raw"] + (0).to_bytes(4, "big")
    return base64.b64encode(b).decode("ascii")


def main(argv):
    doc = json.load(open(argv[1]))
    s = doc["summary"]
    sup = next(c for c in doc["calls"] if c.get("url") == s["facilitator"])
    n = 0
    for c in doc["calls"]:
        if c.get("method") != "getTransaction":
            continue
        r = c["result"]
        env = xs.envelope(r["envelopeXdr"])
        fn = env["tx"]["ops"][0]["fn"]
        acc = {"scheme": "exact", "network": s["network"], "amount": str(fn["args"][2][1]),
               "asset": xs.address_str(fn["contract"]), "payTo": xs.address_str(fn["args"][1][1]),
               "maxTimeoutSeconds": 300, "extra": {"areFeesSponsored": True}}
        b = {"bundle_version": "apc-0.12",
             "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {"transaction": payload_tx(env["tx"])}},
             "settlement": {"success": True, "transaction": r["txHash"], "network": s["network"],
                            "payer": xs.address_str(fn["args"][0][1])},
             "chain_tx": {"ledger": r["ledger"], "status": r["status"], "envelopeXdr": r["envelopeXdr"],
                          "resultXdr": r["resultXdr"], "contractEventsXdr": r["events"]["contractEventsXdr"]},
             "facilitator": {"signers": sup["result"]["signers"]["stellar:*"], "source": s["facilitator"],
                             "fetched": FETCHED}}
        n += 1
        with open(os.path.join(argv[2], "x%03d_envelope_reconstructed.json" % n), "x") as fh:
            json.dump(b, fh, indent=1)
    print(n, "bundles")


if __name__ == "__main__":
    main(sys.argv)
