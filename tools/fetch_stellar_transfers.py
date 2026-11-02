"""Real Soroban USDC transfers on Stellar pubnet in the x402 `exact` shape (SPEC section 20): read-only Stellar RPC
(getLatestLedger, getEvents for the USDC Stellar Asset Contract's "transfer" events, getTransaction). A transaction is
kept when its envelope has one invokeHostFunction `transfer` on USDC and an address-credential authorization entry of
the payer, and the transaction source is not the payer (a sponsored transfer: the facilitator pays the fee). Every
RPC reply is written so the selection can be re-derived offline. Like the EVM oracle, this shape is not proof that
the payment was x402.

  python3 tools/fetch_stellar_transfers.py OUT.json [LEDGERS_BACK] [MAX_TX]"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_stellar as xs  # noqa: E402

RPC = os.environ.get("STELLAR_RPC")          # checked where it is used, never at import
USDC = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"
TRANSFER = "AAAADwAAAAh0cmFuc2Zlcg=="           # SCVal symbol "transfer"
_id = [0]


def rpc(method, params):
    _id[0] += 1
    body = json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": method, "params": params}).encode()
    if not RPC:
        sys.exit("STELLAR_RPC not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    req = urllib.request.Request(RPC, body, {"Content-Type": "application/json", "User-Agent": "apc-oracle/0"})
    for attempt in range(5):
        time.sleep(0.5 * 2 ** attempt)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                reply = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 503) or attempt == 4:
                raise
    if "error" in reply:
        raise SystemExit("RPC error on %s: %s" % (method, reply["error"]))
    return {"method": method, "params": params, "result": reply["result"]}


def main(argv):
    out, back = argv[1], int(argv[2]) if len(argv) > 2 else 2000
    maxtx = int(argv[3]) if len(argv) > 3 else 20
    calls = []
    head = rpc("getLatestLedger", {})
    calls.append(head)
    start = head["result"]["sequence"] - back
    ev = rpc("getEvents", {"startLedger": start, "filters": [{"type": "contract", "contractIds": [USDC],
                                                               "topics": [[TRANSFER, "*", "*", "*"]]}],
                           "pagination": {"limit": 1000}})
    calls.append(ev)
    hashes = []
    for e in ev["result"]["events"]:
        if e["txHash"] not in hashes:
            hashes.append(e["txHash"])
    kept, seen = [], 0
    for h in hashes:
        t = rpc("getTransaction", {"hash": h})
        seen += 1
        if t["result"].get("status") != "SUCCESS":
            continue
        try:
            env = xs.envelope(t["result"]["envelopeXdr"])
        except xs.StellarRefusal:
            continue
        ops = env["tx"]["ops"]
        if len(ops) != 1 or ops[0]["fn"]["function"] != b"transfer" or \
                xs.address_str(ops[0]["fn"]["contract"]) != USDC or len(ops[0]["fn"]["args"]) != 3:
            continue
        frm = ops[0]["fn"]["args"][0]
        if frm[0] != "address" or frm[1][0] != "G":
            continue
        creds = [a["credentials"] for a in ops[0]["auth"] if a["credentials"]["type"] in (1, 2)]
        if not creds or env["tx"]["source"]["key"] == frm[1][1]:
            continue
        calls.append(t)
        kept.append({"hash": h, "ledger": t["result"]["ledger"],
                     "events": [e for e in ev["result"]["events"] if e["txHash"] == h]})
        if len(kept) >= maxtx:
            break
    summary = {"rpc": RPC, "asset": USDC, "network": "stellar:pubnet", "head_ledger": head["result"]["sequence"],
               "start_ledger": start, "transfer_events": len(ev["result"]["events"]), "distinct_tx": len(hashes),
               "transactions_read": seen, "kept": len(kept)}
    with open(out, "x") as fh:
        json.dump({"summary": summary, "kept": kept, "calls": calls}, fh, indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main(sys.argv)
