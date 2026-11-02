"""Real XRPL data: validated mainnet ledgers with every transaction and its metadata in binary, plus the JSON header
the server reports (ledger_hash, transaction_hash). Read-only public JSON-RPC; the raw replies are saved.

  python3 tools/fetch_xrpl_ledgers.py OUT.json N [SERVER]"""
import json
import os
import sys
import time
import urllib.request


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "apc-xrpl-oracle/0"})
    time.sleep(1.0)
    with urllib.request.urlopen(req, timeout=60) as r:
        return {"method": method, "params": params, "result": json.load(r)["result"]}


def main(argv):
    out, n = argv[1], int(argv[2])
    url = argv[3] if len(argv) > 3 else (os.environ.get("XRPL_RPC") or sys.exit("XRPL_RPC (or a URL argument) not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool"))
    head = rpc(url, "ledger", {"ledger_index": "validated"})
    top = int(head["result"]["ledger_index"])
    calls = [head]
    for i in range(n):
        idx = top - 1 - 7 * i
        calls.append(rpc(url, "ledger", {"ledger_index": idx, "transactions": True, "expand": True, "binary": True}))
        calls.append(rpc(url, "ledger", {"ledger_index": idx}))
    with open(out, "w") as fh:
        json.dump({"server": url, "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "calls": calls}, fh)
    print(len(calls), "replies")


if __name__ == "__main__":
    main(sys.argv)
