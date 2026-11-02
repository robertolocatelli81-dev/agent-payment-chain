"""Recent transactions of the Solana fee payers that the pinned x402scan list names (sources/solana_20261024/
solana_facilitators_x402scan_5732bb8.json): for each address, getSignaturesForAddress (the last LIMIT signatures),
then getTransaction (base64, maxSupportedTransactionVersion 0) of each. Read-only public JSON-RPC (SOLANA_RPC); the
output has the format of sources/solana_20261024/solana_x402_20261024.json ({"rpc", "fetched_utc", "txs"}), plus the
getSignaturesForAddress replies. A signature that appears for two fee payers is kept once, under the first.

  SOLANA_RPC=https://YOUR-SOLANA-ENDPOINT python3 -B tools/fetch_solana_feepayers.py OUT.json [LIMIT]"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

RPC = os.environ.get("SOLANA_RPC")          # checked where it is used, never at import
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIST = os.path.join(ROOT, "sources", "solana_20261024", "solana_facilitators_x402scan_5732bb8.json")


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(7):
        time.sleep(1.2 * 2 ** attempt)
        if not RPC:
            sys.exit("SOLANA_RPC not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
        req = urllib.request.Request(RPC, body, {"Content-Type": "application/json", "User-Agent": "apc-coverage/0"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                rep = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 502, 503) and attempt < 6:
                continue
            raise
        if "error" in rep:
            if attempt < 6:
                continue
            raise SystemExit("RPC error %s %s: %s" % (method, params[0], rep["error"]))
        return rep["result"]


def main(argv):
    out = argv[1]
    limit = int(argv[2]) if len(argv) > 2 else 20
    payers = json.load(open(LIST))
    sigs_replies, txs, seen = [], [], set()
    for fac, addr, _flag in payers:
        r = rpc("getSignaturesForAddress", [addr, {"limit": limit}])
        sigs_replies.append({"facilitator": fac, "address": addr, "result": r})
        for s in r:
            if s["signature"] in seen:
                continue
            seen.add(s["signature"])
            raw = rpc("getTransaction", [s["signature"], {"encoding": "base64", "maxSupportedTransactionVersion": 0}])
            txs.append({"facilitator": fac, "fee_payer_listed": addr, "signature": s["signature"], "slot": s["slot"],
                        "raw": raw})
        print(fac, addr, len(r), flush=True)
    with open(out, "x") as fh:
        json.dump({"rpc": RPC, "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "limit": limit,
                   "signatures": sigs_replies, "txs": txs}, fh)
    print(len(txs), "transactions")


if __name__ == "__main__":
    main(sys.argv)
