"""Collect REAL negatives: EIP-3009 calls (transferWithAuthorization / receiveWithAuthorization) that the chain itself
reverted (receipt status 0), with the chain's own reason. Read-only; public JSON-RPC, and for `index` mode the public
Routescan explorer API (Etherscan-compatible txlist; ROUTESCAN_API_KEY required, see routescan_key) used only to find
candidate hashes, every candidate re-read by RPC.

  python3 tools/scan_negatives_evm.py receipts CHAIN FIRST_BLOCK COUNT OUT.json
  python3 tools/scan_negatives_evm.py index CHAIN FIRST_BLOCK LAST_BLOCK OUT.json
  python3 tools/scan_negatives_evm.py hashes CHAIN OUT.json TX_HASH...   (candidates read from an index reply)
  python3 tools/scan_negatives_evm.py refetch CHAIN OUT.json     [ARCHIVE_RPC]   (full blocks; replays that failed at the RPC)

receipts: every block's eth_getBlockReceipts; a status-0 receipt sent to a watched token is read in full
(eth_getTransactionByHash) and kept when its selector is one of the four EIP-3009 call forms; status-0 receipts sent to
the other watched x402 contracts are kept as indirect candidates (counted, not decoded).
index: Routescan txlist of each watched token over the block range (split until a page holds fewer than 10000 rows),
rows with isError 1 and an EIP-3009 selector.
For each direct candidate the tool records, all from RPC: the transaction, its receipt, the block header and all the
block's receipts (gzip, for tools/inclusion.py), eth_call of the same call at the parent block and at the block,
authorizationState(from, nonce) at both, and the AuthorizationUsed logs of (from, nonce) in the 5000 blocks up to the block (the raw reply, an error included)."""
import gzip
import json
import os
import sys
import time
import urllib.request

SEL = {"0xe3ee160e": ("transfer", "vrs"), "0xcf092995": ("transfer", "bytes"),
       "0xef55bec6": ("receive", "vrs"), "0x88b7ab63": ("receive", "bytes")}
AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
CHAINS = {
    "base": {"chain_id": 8453, "rpc": os.environ.get("BASE_RPC"),
             "tokens": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": ("USD Coin", "2"),
                        "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42": ("EURC", "2")},
             "indirect": ["0x402085c248eea27d92e8b30b2c58ed07f9e20001",      # x402ExactPermit2Proxy
                          "0xe807a76385ec3d76d17ab955091c12329d0a1403"]},    # Central City
    "avax": {"chain_id": 43114, "rpc": os.environ.get("AVAX_RPC"),
             "tokens": {"0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": ("USD Coin", "2"),
                        "0xc891eb4cbdeff6e073e859e987815ed1505c2acd": ("Euro Coin", "2")}, "indirect": []},
    "eth": {"chain_id": 1, "rpc": os.environ.get("ETH_RPC"),
            "tokens": {"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USD Coin", "2"),
                       "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c": ("Euro Coin", "2")}, "indirect": []},
}
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/%d/etherscan/api"


def routescan_key():
    """The Routescan API is a keyed, subscription service (its terms and conditions): the index runs only with
    ROUTESCAN_API_KEY in the environment, else the tool stops here with the reason. Powered by Routescan.io APIs."""
    k = os.environ.get("ROUTESCAN_API_KEY")
    if not k:
        sys.exit("scan_negatives_evm: the Routescan index needs ROUTESCAN_API_KEY in the environment (api.routescan.io "
                 "is a keyed service under its own terms); not set, stopping. Powered by Routescan.io APIs")
    return k


def get(url, body=None):
    err = None
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "curl/8"})
            return json.load(urllib.request.urlopen(req, timeout=90))
        except Exception as e:                          # noqa: BLE001 - public endpoint, retried
            err = e
            time.sleep(3 * (attempt + 1))
    raise err


def rpc_raw(url, method, params):
    return get(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())


def rpc(url, method, params):
    d = rpc_raw(url, method, params)
    if "error" in d:
        raise RuntimeError("%s %s" % (method, d["error"]))
    return d["result"]


def evidence(c, tx, rc, outdir):
    url = c["rpc"]
    b = int(rc["blockNumber"], 16)
    call = {"from": tx["from"], "to": tx["to"], "data": tx["input"], "gas": tx["gas"], "value": tx.get("value", "0x0")}
    word = lambda i: tx["input"][10 + 64 * i: 10 + 64 * (i + 1)]          # noqa: E731
    frm, nonce = "0x" + word(0)[24:], "0x" + word(5)
    state = {"to": tx["to"], "data": "0xe94a0102" + word(0) + word(5)}
    blk = rpc(url, "eth_getBlockByNumber", [hex(b), True])
    rcs = rpc(url, "eth_getBlockReceipts", [hex(b)])
    os.makedirs(outdir, exist_ok=True)
    for name, obj in (("eth_getBlockByNumber_%d.json.gz" % b, blk), ("eth_getBlockReceipts_%d.json.gz" % b, rcs)):
        p = os.path.join(outdir, name)
        if not os.path.exists(p):
            with gzip.open(p, "wt") as fh:
                json.dump({"jsonrpc": "2.0", "id": 1, "result": obj}, fh)
    try:
        used = rpc_raw(url, "eth_getLogs", [{"address": tx["to"], "fromBlock": hex(max(0, b - 5000)), "toBlock": hex(b),
                                         "topics": [AUTH_USED, "0x" + "0" * 24 + frm[2:], nonce]}])
    except Exception as e:                              # noqa: BLE001 - kept as the reply: the endpoint refused it
        used = {"error": {"message": "%s: %s" % (type(e).__name__, e)}}
    return {"tx": tx, "receipt": rc, "block": b,
            "replay_parent": rpc_raw(url, "eth_call", [call, hex(b - 1)]),
            "replay_block": rpc_raw(url, "eth_call", [call, hex(b)]),
            "state_parent": rpc_raw(url, "eth_call", [state, hex(b - 1)]),
            "state_block": rpc_raw(url, "eth_call", [state, hex(b)]),
            "auth_used_logs": used, "block_files": ["eth_getBlockByNumber_%d.json.gz" % b,
                                                     "eth_getBlockReceipts_%d.json.gz" % b]}


def receipts(c, first, count, out):
    url, tokens, ind = c["rpc"], set(c["tokens"]), set(c["indirect"])
    direct, indirect, failed_token, failed_all = [], [], 0, 0
    for b in range(first, first + count):
        for r in rpc(url, "eth_getBlockReceipts", [hex(b)]):
            if r["status"] != "0x0":
                continue
            failed_all += 1
            to = (r.get("to") or "").lower()
            if to in tokens:
                failed_token += 1
                tx = rpc(url, "eth_getTransactionByHash", [r["transactionHash"]])
                if tx["input"][:10] in SEL:
                    direct.append(evidence(c, tx, r, os.path.dirname(os.path.abspath(out))))
            elif to in ind:
                indirect.append({"tx": rpc(url, "eth_getTransactionByHash", [r["transactionHash"]]), "receipt": r})
        if (b - first) % 100 == 0:
            print(b, "direct", len(direct), "indirect", len(indirect), "failed to token", failed_token, flush=True)
    return {"mode": "receipts", "first_block": first, "count": count, "failed_receipts": failed_all,
            "failed_to_token": failed_token}, direct, indirect


def txlist(c, token, lo, hi):
    q = "?module=account&action=txlist&address=%s&startblock=%d&endblock=%d&page=1&offset=10000&sort=asc"
    d = get(ROUTESCAN % c["chain_id"] + q % (token, lo, hi) + "&apikey=" + routescan_key())
    rows = d.get("result") or []
    if not isinstance(rows, list):
        raise RuntimeError(d)
    if len(rows) >= 10000 and hi > lo:
        mid = (lo + hi) // 2
        return txlist(c, token, lo, mid) + txlist(c, token, mid + 1, hi)
    return rows


def index(c, first, last, out):
    url, direct, rows_seen, err_rows = c["rpc"], [], 0, 0
    step = 20000 if c["chain_id"] != 1 else 500
    for token in c["tokens"]:
        for lo in range(first, last + 1, step):
            rows = txlist(c, token, lo, min(last, lo + step - 1))
            rows_seen += len(rows)
            for x in rows:
                if x["isError"] == "1" or x.get("txreceipt_status") == "0":
                    err_rows += 1
                    if x["input"][:10] in SEL:
                        rc = rpc(url, "eth_getTransactionReceipt", [x["hash"]])
                        if rc["status"] == "0x0":
                            tx = rpc(url, "eth_getTransactionByHash", [x["hash"]])
                            direct.append(evidence(c, tx, rc, os.path.dirname(os.path.abspath(out))))
            print(token, lo, "rows", rows_seen, "error rows", err_rows, "direct", len(direct), flush=True)
            time.sleep(0.6)                              # Routescan free tier: 2 requests per second
    return {"mode": "index", "first_block": first, "last_block": last, "index_rows": rows_seen,
            "index_error_rows": err_rows, "index": ROUTESCAN % c["chain_id"]}, direct, []


def is_revert(rep):
    e = rep.get("error")
    return e is None or e.get("code") == 3 or str(e.get("message", "")).startswith("execution reverted")


def refetch(c, path, url=None):
    """the full block (eth_getBlockByNumber with true, as tools/inclusion.py needs) for every candidate of PATH, and
    again the replies of a replay or state call that came back as an RPC failure, not as a result or a revert (from URL
    when given, an archive endpoint); PATH is rewritten with the new replies, the old ones kept under `rpc_failures`"""
    doc = json.load(open(path))
    url = url or c["rpc"]
    for x in doc["direct"]:
        b, tx = x["block"], x["tx"]
        blk = rpc(c["rpc"], "eth_getBlockByNumber", [hex(b), True])
        with gzip.open(os.path.join(os.path.dirname(os.path.abspath(path)), "eth_getBlockByNumber_%d.json.gz" % b), "wt") as fh:
            json.dump({"jsonrpc": "2.0", "id": 1, "result": blk}, fh)
        call = {"from": tx["from"], "to": tx["to"], "data": tx["input"], "gas": tx["gas"], "value": tx.get("value", "0x0")}
        word = lambda i: tx["input"][10 + 64 * i: 10 + 64 * (i + 1)]          # noqa: E731
        state = {"to": tx["to"], "data": "0xe94a0102" + word(0) + word(5)}
        for k, q, at in (("replay_parent", call, b - 1), ("replay_block", call, b), ("state_parent", state, b - 1),
                         ("state_block", state, b)):
            if not is_revert(x[k]):
                x.setdefault("rpc_failures", []).append({"key": k, "reply": x[k], "rpc": c["rpc"]})
                x[k] = rpc_raw(url, "eth_call", [q, hex(at)])
                x.setdefault("replays_from", {})[k] = url
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=1)
    print("refetched", len(doc["direct"]))


def main(argv):
    mode, chain = argv[1], argv[2]
    c = CHAINS[chain]
    if not c["rpc"]:
        sys.exit("BASE_RPC / AVAX_RPC / ETH_RPC (the one of this chain) not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    if mode == "refetch":
        return refetch(c, argv[3], argv[4] if len(argv) > 4 else None)
    if mode == "hashes":                 # candidates found by hand in an index reply: OUT.json HASH...
        direct = []
        for h in argv[4:]:
            rc = rpc(c["rpc"], "eth_getTransactionReceipt", [h])
            tx = rpc(c["rpc"], "eth_getTransactionByHash", [h])
            if rc["status"] == "0x0" and tx["input"][:10] in SEL:
                direct.append(evidence(c, tx, rc, os.path.dirname(os.path.abspath(argv[3]))))
        with open(argv[3], "w") as fh:
            json.dump({"summary": {"mode": "hashes", "chain": chain, "chain_id": c["chain_id"], "rpc": c["rpc"],
                                   "tokens": c["tokens"], "hashes": argv[4:], "direct_reverted": len(direct),
                                   "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                       "direct": direct, "indirect": []}, fh, indent=1)
        return print("done", len(direct))
    a, b, out = int(argv[3]), int(argv[4]), argv[5]
    summary, direct, indirect = (receipts if mode == "receipts" else index)(c, a, b, out)
    summary.update({"chain": chain, "chain_id": c["chain_id"], "rpc": c["rpc"], "tokens": c["tokens"],
                    "direct_reverted": len(direct), "indirect_reverted": len(indirect),
                    "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    with open(out, "w") as fh:
        json.dump({"summary": summary, "direct": direct, "indirect": indirect}, fh, indent=1)
    print("done", json.dumps(summary))


if __name__ == "__main__":
    main(sys.argv)
