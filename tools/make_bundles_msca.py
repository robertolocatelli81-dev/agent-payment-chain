"""Real bundles of SPEC 0.21 (section 32): the direct USDC calls of the census windows whose payer's code is in
apc_msca.WALLETS (2026-11-01: 28 payments of one Circle_SingleOwnerMSCA 1.0.0 payer), each in two forms — an apc-0.2
bundle with `payer_state.rpc` and an apc-0.3 bundle with `inclusion` and `payer_state.proof`.

  BASE_RPC=https://... python3 -B tools/make_bundles_msca.py fetch RAW_DIR          read-only JSON-RPC; every raw reply
                                                                                    saved gzip-compressed in RAW_DIR
                                                                                    with RAW_DIR/SHA256SUMS (resumable)
  python3 -B tools/make_bundles_msca.py build RAW_DIR OUT_DIR                        offline: the bundles + MANIFEST.json
  python3 -B tools/make_bundles_msca.py replies RAW_DIR OUT.json                     offline: the rpc-form replies in the
                                                                                    format tools/coverage_census.py reads

Selection (offline, from the saved census replies): oracle/census_base_*.json, AuthorizationUsed logs whose transaction
calls the token directly, payer code (oracle/coverage_20261022/payer_wallet_replies.json and
oracle/coverage_20261026/payer_wallets_base_20261022_windows.json) with keccak256 in apc_msca.WALLETS. Per payment the
fetch reads: eth_getBlockByNumber(N, true) and eth_getBlockReceipts(N) (for inclusion), eth_getBlockByNumber(N-1, false),
eth_getProof of the payer with its two slots, of the implementation and of the owner at N-1 and at N, and for the rpc
form eth_getCode of the payer, the implementation and the owner and eth_getStorageAt of the two slots at N. The
implementation and owner addresses are read from the slot words of the proof at N (and must equal the list's).
"""
import glob
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_msca  # noqa: E402
import apc_verify as av  # noqa: E402
import inclusion  # noqa: E402
from apc_verify import keccak256  # noqa: E402

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
WALLET_FILES = ("oracle/coverage_20261022/payer_wallet_replies.json",
                "oracle/coverage_20261026/payer_wallets_base_20261022_windows.json")
HEADER_KEYS = inclusion.HEADER_KEYS


def _walk(x):
    if isinstance(x, dict):
        if "method" in x and "params" in x and "result" in x:
            yield x
        else:
            for v in x.values():
                yield from _walk(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            yield from _walk(v)


def saved_replies():
    out = {}
    for p in WALLET_FILES:
        d = json.load(open(os.path.join(ROOT, p)))
        items = d.get("replies") if isinstance(d, dict) and "replies" in d else d
        if isinstance(items, dict):
            items = list(items.items())
        for it in items:
            for rep in _walk(it):
                out[json.dumps([rep["method"], rep["params"]], sort_keys=True).lower()] = rep
    return out


def select():
    """The payments: [{window, tx, log, transfer, block}] sorted by block, from the saved census replies."""
    rep = saved_replies()
    rows = []
    for cf in sorted(glob.glob(os.path.join(ROOT, "oracle", "census_base_*.json"))):
        c = json.load(open(cf))
        label = os.path.basename(cf)[len("census_base_"):-len(".json")]
        t = json.load(open(os.path.join(ROOT, "oracle", "transfers_base_%s.json" % label)))
        txs = {x["params"][0]: x["result"] for x in c["calls"] if x["method"] == "eth_getTransactionByHash"}
        tr = {(lg["transactionHash"], int(lg["logIndex"], 16)): lg for x in t["calls"] for lg in x["result"]}
        for lg in [lg for x in c["calls"] if x["method"] == "eth_getLogs" for lg in x["result"]]:
            tx = txs[lg["transactionHash"]]
            if (tx.get("to") or "").lower() != USDC:
                continue
            frm = "0x" + lg["topics"][1][-40:]
            code = rep.get(json.dumps(["eth_getCode", [frm, lg["blockNumber"]]], sort_keys=True).lower())
            if code is None or code["result"] == "0x" or code["result"].startswith("0xef0100"):
                continue
            if keccak256(bytes.fromhex(code["result"][2:])).hex() not in apc_msca.WALLETS:
                continue
            rows.append({"window": label, "tx": tx, "log": lg, "transfer": tr.get((lg["transactionHash"], int(lg["logIndex"], 16) + 1)),
                         "payer": frm, "block": int(lg["blockNumber"], 16), "census": c["summary"]})
    return sorted(rows, key=lambda r: (r["block"], r["tx"]["hash"]))


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    err = None
    for attempt in range(5):
        req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "apc-tools"})
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                raw = r.read()
            d = json.loads(raw)
            if "result" in d and d["result"] is not None:
                return raw
            err = d.get("error")
        except (OSError, ValueError) as e:
            err = repr(e)
        time.sleep(4 * (attempt + 1))
    raise RuntimeError("rpc %s %s: %s" % (method, params[:1], err))


def _path(raw_dir, name):
    return os.path.join(raw_dir, name + ".json.gz")


def _read(raw_dir, name):
    with gzip.open(_path(raw_dir, name)) as fh:
        return json.loads(fh.read())["result"]


def _save(raw_dir, name, raw):
    p = _path(raw_dir, name)
    with open(p + ".tmp", "wb") as f0, gzip.GzipFile(filename="", fileobj=f0, mode="wb", mtime=0) as fh:
        fh.write(raw)
    os.replace(p + ".tmp", p)
    with open(os.path.join(raw_dir, "SHA256SUMS"), "a") as fh:
        fh.write("%s  %s\n" % (hashlib.sha256(open(p, "rb").read()).hexdigest(), os.path.basename(p)))


def fetch_one(url, raw_dir, name, method, params):
    if os.path.exists(_path(raw_dir, name)):
        return _read(raw_dir, name)
    _save(raw_dir, name, rpc(url, method, params))
    return _read(raw_dir, name)


def fetch(url, raw_dir):
    os.makedirs(raw_dir, exist_ok=True)
    rows = select()
    print(len(rows), "payments", flush=True)
    for r in rows:
        n, payer, hn = r["block"], r["payer"], hex(r["block"])
        pin = apc_msca.WALLETS[keccak256(bytes.fromhex(
            saved_replies()[json.dumps(["eth_getCode", [payer, hn]], sort_keys=True).lower()]["result"][2:])).hex()]
        fetch_one(url, raw_dir, "%d_block" % n, "eth_getBlockByNumber", [hn, True])
        fetch_one(url, raw_dir, "%d_receipts" % n, "eth_getBlockReceipts", [hn])
        fetch_one(url, raw_dir, "%d_header" % (n - 1), "eth_getBlockByNumber", [hex(n - 1), False])
        slots = ["0x%064x" % apc_msca.ERC1967_SLOT, "0x%064x" % pin[2]]
        for b in (n - 1, n):
            p = fetch_one(url, raw_dir, "%d_proof_%s" % (b, payer), "eth_getProof", [payer, slots, hex(b)])
            impl = "0x" + p["storageProof"][0]["value"][2:].rjust(40, "0")[-40:]
            owner = "0x%040x" % (int(p["storageProof"][1]["value"], 16) >> 16)
            if impl != pin[0]:
                raise RuntimeError("block %d: implementation %s is not the listed one" % (b, impl))
            fetch_one(url, raw_dir, "%d_proof_%s" % (b, impl), "eth_getProof", [impl, [], hex(b)])
            fetch_one(url, raw_dir, "%d_proof_%s" % (b, owner), "eth_getProof", [owner, [], hex(b)])
        fetch_one(url, raw_dir, "%d_code_%s" % (n, payer), "eth_getCode", [payer, hn])
        fetch_one(url, raw_dir, "%d_slot_%s_%s" % (n, payer, slots[0][:10]), "eth_getStorageAt", [payer, slots[0], hn])
        fetch_one(url, raw_dir, "%d_slot_%s_%s" % (n, payer, slots[1][:10]), "eth_getStorageAt", [payer, slots[1], hn])
        fetch_one(url, raw_dir, "%d_code_%s" % (n, impl), "eth_getCode", [impl, hn])
        fetch_one(url, raw_dir, "%d_code_%s" % (n, owner), "eth_getCode", [owner, hn])
        print("block", n, "done", flush=True)


def _rpc_reply(raw_dir, name, method, params):
    return {"method": method, "params": params, "result": _read(raw_dir, name)}


def rpc_form(raw_dir, r):
    n, payer, hn = r["block"], r["payer"], hex(r["block"])
    code = _rpc_reply(raw_dir, "%d_code_%s" % (n, payer), "eth_getCode", [payer, hn])
    pin = apc_msca.WALLETS[keccak256(bytes.fromhex(code["result"][2:])).hex()]
    slots = ["0x%064x" % apc_msca.ERC1967_SLOT, "0x%064x" % pin[2]]
    impl_w = _rpc_reply(raw_dir, "%d_slot_%s_%s" % (n, payer, slots[0][:10]), "eth_getStorageAt", [payer, slots[0], hn])
    own_w = _rpc_reply(raw_dir, "%d_slot_%s_%s" % (n, payer, slots[1][:10]), "eth_getStorageAt", [payer, slots[1], hn])
    impl = "0x" + impl_w["result"][-40:]
    owner = "0x%040x" % (int(own_w["result"], 16) >> 16)
    return {"code": code, "wallet": {
        "implementation": impl_w, "owner": own_w,
        "implementation_code": _rpc_reply(raw_dir, "%d_code_%s" % (n, impl), "eth_getCode", [impl, hn]),
        "owner_code": _rpc_reply(raw_dir, "%d_code_%s" % (n, owner), "eth_getCode", [owner, hn])}}


def proof_form(raw_dir, r):
    n, payer = r["block"], r["payer"]
    code = _read(raw_dir, "%d_code_%s" % (n, payer))
    pin = apc_msca.WALLETS[keccak256(bytes.fromhex(code[2:])).hex()]
    ph = _read(raw_dir, "%d_header" % (n - 1))
    ends = {}
    for end, b in (("at_parent", n - 1), ("at_block", n)):
        p = _read(raw_dir, "%d_proof_%s" % (b, payer))
        owner = "0x%040x" % (int(p["storageProof"][1]["value"], 16) >> 16)
        ends[end] = {"payer": {"accountProof": p["accountProof"],
                               "storageProof": [p["storageProof"][0]["proof"], p["storageProof"][1]["proof"]]},
                     "implementation": {"accountProof": _read(raw_dir, "%d_proof_%s" % (b, pin[0]))["accountProof"]},
                     "owner": {"accountProof": _read(raw_dir, "%d_proof_%s" % (b, owner))["accountProof"]}}
    return {"code": code, "parent_header": {k: ph[k] for k in HEADER_KEYS if k in ph},
            "at_parent": ends["at_parent"], "at_block": ends["at_block"]}


def payload(r):
    """The x402 envelope reconstructed from the direct call (as tools/make_bundles_v02.py), signature r||s||v."""
    tx, lg, lt, s = r["tx"], r["log"], r["transfer"], r["census"]
    b = bytes.fromhex(tx["input"][2:])
    w = lambda i: b[4 + 32 * i: 4 + 32 * (i + 1)]      # noqa: E731
    if tx["input"][:10].lower() != "0xe3ee160e":
        raise RuntimeError("%s: not the (v,r,s) form" % tx["hash"])
    msg = {"from": "0x" + w(0)[12:].hex(), "to": "0x" + w(1)[12:].hex(), "value": int.from_bytes(w(2), "big"),
           "validAfter": int.from_bytes(w(3), "big"), "validBefore": int.from_bytes(w(4), "big"), "nonce": "0x" + w(5).hex()}
    sig = w(7) + w(8) + bytes([int.from_bytes(w(6), "big")])
    if msg["from"] != r["payer"] or msg["nonce"] != lg["topics"][2].lower():
        raise RuntimeError("%s: calldata does not match the log" % tx["hash"])
    net = "eip155:%d" % s["chain_id"]
    acc = {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": s["token"], "payTo": msg["to"],
           "maxTimeoutSeconds": 60, "extra": {"name": s["token_name"], "version": s["token_version"]}}
    return {"payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
                "signature": "0x" + sig.hex(),
                "authorization": {"from": msg["from"], "to": msg["to"], "value": str(msg["value"]),
                                  "validAfter": str(msg["validAfter"]), "validBefore": str(msg["validBefore"]),
                                  "nonce": msg["nonce"]}}},
            "settlement": {"success": True, "transaction": tx["hash"], "network": net, "payer": msg["from"]},
            "chain_tx": {"network": net, "tx": tx, "log_authorization_used": lg, "log_transfer": lt}}


def build(raw_dir, out):
    os.makedirs(out, exist_ok=True)
    manifest = []
    for i, r in enumerate(select(), 1):
        base = payload(r)
        n = r["block"]
        two = {"rpc": dict(base, bundle_version="apc-0.2", payer_state={"rpc": rpc_form(raw_dir, r)}),
               "proof": dict(base, bundle_version="apc-0.3", payer_state={"proof": proof_form(raw_dir, r)},
                             inclusion=inclusion.build(_read(raw_dir, "%d_block" % n), _read(raw_dir, "%d_receipts" % n),
                                                       r["tx"]["hash"]))}
        for form, doc in two.items():
            name = "m%03d_%s_%s_envelope_reconstructed.json" % (i, form, r["tx"]["hash"][2:10])
            with open(os.path.join(out, name), "x") as fh:
                json.dump(doc, fh, indent=1, sort_keys=True)
            rep = av.verify_bundle(json.loads(json.dumps(doc)))
            manifest.append({"file": name, "tx": r["tx"]["hash"], "block": n, "window": r["window"], "form": form,
                             "payer": r["payer"], "sender": r["tx"]["from"].lower(), "verdict": rep["verdict"],
                             "L2.sig": rep["checks"]["L2.sig"], "payer_state": rep.get("payer_state"),
                             "block_bound": rep.get("block_bound"), "evidence_level": rep["evidence_level"]})
    with open(os.path.join(out, "MANIFEST.json"), "x") as fh:
        json.dump({"made": manifest, "real": "Base USDC EIP-3009 (v,r,s) executions of a Circle_SingleOwnerMSCA 1.0.0 payer "
                   "(the 28 `code_not_known` payments of oracle/coverage_20261022); tx, logs, header, proofs and state "
                   "replies are RPC data (base.drpc.org, 2026-11-01, raw in oracle/msca_20261101); the x402 envelope "
                   "(accepted, settlement) is RECONSTRUCTED from the calldata and the logs", "spec": "SPEC section 32"},
                  fh, indent=1)
    print(len(manifest), "bundles;", json.dumps(sorted({(m["form"], m["verdict"], m["L2.sig"]) for m in manifest})))


def replies(raw_dir, out):
    reps = []
    for r in select():
        f = rpc_form(raw_dir, r)
        reps.append(f["code"])
        reps.extend(f["wallet"].values())
    with open(out, "w") as fh:
        json.dump({"source": "tools/make_bundles_msca.py replies (oracle/msca_20261101 raw replies, base.drpc.org, 2026-11-01)",
                   "replies": reps}, fh, indent=1, sort_keys=True)
    print(len(reps), "replies")


def main(argv):
    if len(argv) >= 3 and argv[1] == "fetch":
        fetch(os.environ["BASE_RPC"], argv[2])
    elif len(argv) == 4 and argv[1] == "build":
        build(argv[2], argv[3])
    elif len(argv) == 4 and argv[1] == "replies":
        replies(argv[2], argv[3])
    else:
        print(__doc__)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
