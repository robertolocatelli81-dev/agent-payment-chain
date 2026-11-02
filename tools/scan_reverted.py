"""Find reverted EIP-3009 settlements on Base mainnet: receipts with status 0 sent to USDC whose input is
transferWithAuthorization (0xe3ee160e v,r,s form or 0xcf092995 bytes form). Read-only JSON-RPC.

  python3 scan_reverted.py FIRST_BLOCK COUNT OUT.json [RPC]"""
import json
import os
import sys
import time
import urllib.request

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
SEL = ("0xe3ee160e", "0xcf092995")


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "curl/8"})
            d = json.load(urllib.request.urlopen(req, timeout=60))
            if "error" in d:
                raise RuntimeError(d["error"])
            return d["result"]
        except Exception as e:                          # noqa: BLE001 - public endpoint, retried
            err = e
            time.sleep(2 * (attempt + 1))
    raise err


def main(first, count, out, url):
    found, calls, usdc_failed = [], [], 0
    for b in range(first, first + count):
        rs = rpc(url, "eth_getBlockReceipts", [hex(b)])
        for r in rs:
            if (r.get("to") or "").lower() == USDC and r["status"] == "0x0":
                usdc_failed += 1
                tx = rpc(url, "eth_getTransactionByHash", [r["transactionHash"]])
                if tx["input"][:10] in SEL:
                    found.append(r["transactionHash"])
                    calls.append({"method": "eth_getTransactionByHash", "params": [r["transactionHash"]], "result": tx})
                    calls.append({"method": "eth_getTransactionReceipt", "params": [r["transactionHash"]], "result": r})
        if (b - first) % 50 == 0:
            print(b, "found", len(found), "usdc failed", usdc_failed, flush=True)
    json.dump({"summary": {"rpc": url, "first_block": first, "count": count, "usdc_failed": usdc_failed,
                           "eip3009_reverted": len(found), "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
               "reverted": found, "calls": calls}, open(out, "w"), indent=1)
    print("done", len(found), "of", usdc_failed, "failed USDC calls")


if __name__ == "__main__":
    main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3],
         sys.argv[4] if len(sys.argv) > 4 else (os.environ.get("BASE_RPC") or sys.exit("BASE_RPC (or a URL argument) not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")))
