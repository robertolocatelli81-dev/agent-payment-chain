"""Collect REAL negatives on Solana: transactions signed (as fee payer) by the x402 facilitators that x402scan@5732bb8
lists (sources/solana_20261024/solana_facilitators_x402scan_5732bb8.json) which the chain executed and FAILED
(meta.err not null). Read-only public JSON-RPC.

  python3 tools/scan_negatives_svm.py OUT.json [PER_ADDRESS_SIGNATURES] [PER_ADDRESS_FAILED] [RPC]

For each listed fee payer: getSignaturesForAddress (newest first, up to PER_ADDRESS_SIGNATURES, default 1000), the
number with err, and getTransaction (encoding base64, maxSupportedTransactionVersion 0) of up to PER_ADDRESS_FAILED
(default 15) failed ones, newest first."""
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIST = os.path.join(ROOT, "sources", "solana_20261024", "solana_facilitators_x402scan_5732bb8.json")


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    err = None
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "curl/8"})
            d = json.load(urllib.request.urlopen(req, timeout=90))
            if "error" in d:
                raise RuntimeError(d["error"])
            return d["result"]
        except Exception as e:                          # noqa: BLE001 - public endpoint, retried
            err = e
            time.sleep(4 * (attempt + 1))
    raise err


def main(out, per_addr=1000, per_failed=15, url=None):
    url = url or os.environ.get("SOLANA_RPC") or sys.exit("SOLANA_RPC (or a URL argument) not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    rows, txs = [], []
    for name, addr, _flag in json.load(open(LIST)):
        sigs = rpc(url, "getSignaturesForAddress", [addr, {"limit": per_addr}])
        failed = [s for s in sigs if s.get("err") is not None]
        rows.append({"facilitator": name, "fee_payer": addr, "signatures": len(sigs), "failed": len(failed),
                     "oldest_blockTime": sigs[-1].get("blockTime") if sigs else None,
                     "newest_blockTime": sigs[0].get("blockTime") if sigs else None,
                     "err_kinds": sorted({json.dumps(s["err"], sort_keys=True) for s in failed})})
        for s in failed[:per_failed]:
            t = rpc(url, "getTransaction", [s["signature"], {"encoding": "base64", "maxSupportedTransactionVersion": 0,
                                                             "commitment": "finalized"}])
            txs.append({"facilitator": name, "fee_payer": addr, "signature": s["signature"], "result": t})
            time.sleep(0.3)
        print(name, addr, len(sigs), "failed", len(failed), flush=True)
        time.sleep(0.5)
    with open(out, "w") as fh:
        json.dump({"summary": {"rpc": url, "list": os.path.relpath(LIST, ROOT), "per_address": per_addr,
                               "per_failed": per_failed, "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                   "addresses": rows, "failed_transactions": txs}, fh, indent=1)
    print("done", sum(r["failed"] for r in rows), "failed of", sum(r["signatures"] for r in rows))


if __name__ == "__main__":
    a = sys.argv
    main(a[1], *(int(x) for x in a[2:4]), *a[4:5])
