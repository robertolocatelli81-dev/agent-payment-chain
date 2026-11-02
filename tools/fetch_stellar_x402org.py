"""Real x402 `exact` settlements on Stellar testnet by the x402.org facilitator (SPEC section 20). Read only: the
facilitator's own GET /supported (its Stellar signers), Horizon testnet (the signers' transactions) and Stellar RPC
testnet (getTransaction: envelope, result, events). Kept: a successful transaction with one invokeHostFunction
`transfer` and an address-credential authorization entry of the payer. Every reply is written.

  python3 tools/fetch_stellar_x402org.py OUT.json [PER_SIGNER] [MAX_TX]"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_stellar as xs  # noqa: E402

SUPPORTED = os.environ.get("X402_SUPPORTED_URL")    # checked where it is used, never at import
HORIZON = os.environ.get("STELLAR_HORIZON")          # both checked where they are used, never at import
RPC = os.environ.get("STELLAR_RPC")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "apc-oracle/0", "Accept": "application/json"})
    for attempt in range(5):
        time.sleep(0.5 * 2 ** attempt)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 503) or attempt == 4:
                raise


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    if not RPC:
        sys.exit("STELLAR_RPC not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    req = urllib.request.Request(RPC, body, {"Content-Type": "application/json", "User-Agent": "apc-oracle/0"})
    time.sleep(0.5)
    with urllib.request.urlopen(req, timeout=30) as r:
        reply = json.load(r)
    if "error" in reply:
        raise SystemExit("RPC error on %s: %s" % (method, reply["error"]))
    return {"method": method, "params": params, "result": reply["result"]}


def main(argv):
    out = argv[1]
    per = int(argv[2]) if len(argv) > 2 else 50
    maxtx = int(argv[3]) if len(argv) > 3 else 20
    if not SUPPORTED:
        sys.exit("X402_SUPPORTED_URL not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    sup = get(SUPPORTED)
    signers = sup["signers"]["stellar:*"]
    calls = [{"url": SUPPORTED, "result": sup}]
    hashes = []
    if not HORIZON:
        sys.exit("STELLAR_HORIZON not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool")
    for a in signers:
        u = "%s/accounts/%s/transactions?order=desc&limit=%d" % (HORIZON, a, per)
        h = get(u)
        calls.append({"url": u, "result": h})
        for rec in h["_embedded"]["records"]:
            if rec["successful"] and rec["hash"] not in hashes:
                hashes.append(rec["hash"])
    kept = []
    for h in hashes:
        t = rpc("getTransaction", {"hash": h})
        if t["result"].get("status") != "SUCCESS":
            continue
        try:
            env = xs.envelope(t["result"]["envelopeXdr"])
        except xs.StellarRefusal:
            continue
        ops = env["tx"]["ops"]
        if len(ops) != 1 or ops[0]["fn"]["function"] != b"transfer" or len(ops[0]["fn"]["args"]) != 3 or \
                not any(a["credentials"]["type"] in (1, 2) for a in ops[0]["auth"]):
            continue
        calls.append(t)
        kept.append({"hash": h, "ledger": t["result"]["ledger"]})
        if len(kept) >= maxtx:
            break
    summary = {"network": "stellar:testnet", "facilitator": SUPPORTED, "signers": signers, "horizon": HORIZON,
               "rpc": RPC, "candidate_tx": len(hashes), "kept": len(kept)}
    with open(out, "x") as fh:
        json.dump({"summary": summary, "kept": kept, "calls": calls}, fh, indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main(sys.argv)
