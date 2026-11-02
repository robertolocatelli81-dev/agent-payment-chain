"""Bundles and a census of REAL negatives (oracle/negatives_20261026): payments the chain itself refused.

  python3 tools/make_bundles_negatives.py            writes bundles/real_negatives_20261026 and
                                                     oracle/negatives_20261026/NEGATIVES.json

EVM (*_receipts_*, *_index_*, *_hashes_* of tools/scan_negatives_evm.py): every transferWithAuthorization
call with a status-0 receipt. REAL: transaction, receipt, block, all its receipts, the inclusion proofs built from them
by tools/inclusion.py, the authorization and signature decoded from the input, and the chain's reason (eth_call of
the same call at the parent block; at the block itself when the parent replay succeeds). RECONSTRUCTED: the x402
envelope (`accepted` with payTo = to, amount = value, the token's domain name/version) and a settlement reply that
says success: true, the claim under test (no facilitator reply is known for these transactions).
receiveWithAuthorization calls are counted, not bundled (x402 `exact` names transferWithAuthorization).
Solana (svm_facilitators_failed.json of tools/scan_negatives_svm.py): failed transactions whose fee payer is the
listed facilitator and which carry a top-level TransferChecked; bundle as tools/make_bundles_svm.py (fee payer
signature zeroed, settlement success: true). The reason is meta.err and the failing program's log line.
XRPL (xrpl_ledgers_120.json.gz, gzip of the output of tools/fetch_xrpl_ledgers.py): Payments whose TransactionResult is not tesSUCCESS,
bundled by tools/make_bundles_xrp.py; the result code is the reason.
"""
import glob
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tools.check_eip3009_oracle import decode  # noqa: E402
from tools.scan_negatives_evm import CHAINS, SEL, is_revert  # noqa: E402

DATA = os.path.join(ROOT, "oracle", "negatives_20261026")
OUT = os.path.join(ROOT, "bundles", "real_negatives_20261026")


def evm_reason(x):
    def msg(rep):
        e = rep.get("error")
        if e is not None and not is_revert(rep):
            return "RPC failure, no replay: %s" % e.get("message")
        return None if e is None else (e.get("message") or "").replace("execution reverted: ", "") or "revert, no message"
    rp, rb = msg(x["replay_parent"]), msg(x["replay_block"])
    gas_all = int(x["receipt"]["gasUsed"], 16) >= int(x["tx"]["gas"], 16)
    used = x["auth_used_logs"].get("result")
    if rp is not None:
        reason, where = rp, "parent"
    elif rb is not None:
        reason, where = rb, "block"
    else:
        reason, where = "out of gas" if gas_all else "replay succeeds at parent and block", "none"
    return {"reason": reason, "replay": where, "gas_used_all": gas_all,
            "authorization_used_by": sorted({lg["transactionHash"] for lg in used}) if isinstance(used, list) else
            "eth_getLogs error: %s" % x["auth_used_logs"].get("error")}


def evm_bundle(c, x, tmp):
    tx = x["tx"]
    name, version = c["tokens"][tx["to"].lower()]
    kind, form = SEL[tx["input"][:10]]
    msg, sig = decode(form, tx["input"])
    if kind != "transfer" or sig[0] == "contract":
        return None, "receiveWithAuthorization" if kind != "transfer" else "contract signature (%d bytes)" % sig[1]
    v, r, s = sig
    paths = []
    for f in x["block_files"]:
        p = os.path.join(tmp, f[:-3])
        with gzip.open(os.path.join(DATA, f), "rt") as fh, open(p, "w") as o:
            o.write(fh.read())
        paths.append(p)
    inc = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "tools", "inclusion.py"), paths[0], paths[1], tx["hash"]],
                         capture_output=True, text=True)
    net = "eip155:%d" % c["chain_id"]
    b = {
        "bundle_version": "apc-0.3",
        "payment_payload": {
            "x402Version": 2,
            "accepted": {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": tx["to"].lower(),
                         "payTo": msg["to"], "maxTimeoutSeconds": 60, "extra": {"name": name, "version": version}},
            "payload": {"signature": "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex(),
                        "authorization": {k: (str(y) if isinstance(y, int) else y) for k, y in msg.items()}}},
        "settlement": {"success": True, "transaction": tx["hash"], "network": net, "payer": msg["from"]},
        "chain_tx": {"network": net, "tx": tx},
    }
    if inc.returncode != 0:
        # no inclusion: the bundle carries the transaction alone (apc-0.1), as a facilitator that hands over only the
        # transaction would; the receipt's status 0 is then not in the bundle
        b["bundle_version"] = "apc-0.1"
        return b, "inclusion not built (%s): transaction only" % (inc.stderr.strip().splitlines() or ["?"])[-1]
    b["inclusion"] = json.loads(inc.stdout)
    return b, None


def svm_module():
    argv, sys.argv = sys.argv, [sys.argv[0], ROOT]          # make_bundles_svm reads ROOT from argv at import
    try:
        import tools.make_bundles_svm as m
    finally:
        sys.argv = argv
    return m


def svm_reason(meta):
    fail = [ln for ln in meta.get("logMessages") or [] if " failed: " in ln or ln.startswith("Program log: Error")
            or "insufficient lamports" in ln]
    return {"err": meta["err"], "log": fail}


def xrpl_negatives(tmp):
    import apc_xrpl as xr
    src = os.path.join(DATA, "xrpl_ledgers_120.json.gz")
    if not os.path.exists(src):
        return [], 0, 0
    out = os.path.join(tmp, "xrp")
    od = json.load(gzip.open(src, "rt"))  # the public server answered tooBusy / slowDown to part of the calls: those
    od["calls"] = [c for c in od["calls"] if "ledger" in c["result"]]     # replies carry no ledger and are left out
    src = os.path.join(tmp, "xrpl_answered.json")
    with open(src, "w") as fh:
        json.dump(od, fh)
    subprocess.run([sys.executable, "-B", os.path.join(ROOT, "tools", "make_bundles_xrp.py"), src, out], check=True,
                   capture_output=True)
    rows, payments = [], 0
    for p in sorted(glob.glob(os.path.join(out, "*.json"))):
        payments += 1
        d = json.load(open(p))
        _f, mv = xr.decode(bytes.fromhex(d["chain_tx"]["meta"]))
        code = int.from_bytes(mv["TransactionResult"], "big") if isinstance(mv["TransactionResult"], bytes) else mv["TransactionResult"]
        name = xr.RESULTS.get(code, code)
        if name != "tesSUCCESS":
            rows.append((os.path.basename(p), d, name))
    return rows, payments, sum(1 for c in od["calls"] if c["params"].get("binary"))


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    census = {"evm": [], "svm": [], "xrpl": [], "skipped": []}
    with tempfile.TemporaryDirectory() as tmp:
        seen = set()
        for f in sorted(glob.glob(os.path.join(DATA, "*_receipts_*.json")) + glob.glob(os.path.join(DATA, "*_index_*.json")) + glob.glob(os.path.join(DATA, "*_hashes_*.json"))):
            doc = json.load(open(f))
            c = CHAINS[doc["summary"]["chain"]]
            for x in doc["direct"]:
                h = x["tx"]["hash"]
                if h in seen:
                    continue
                seen.add(h)
                row = {"network": "eip155:%d" % c["chain_id"], "tx": h, "block": x["block"], "source": os.path.basename(f),
                       "selector": x["tx"]["input"][:10], **evm_reason(x)}
                b, why = evm_bundle(c, x, tmp)
                if why is not None:
                    row["note"] = why
                if b is None:
                    row["bundle"] = None
                    row["not_bundled"] = why
                else:
                    name = "evm_%s_%d_%s.json" % (doc["summary"]["chain"], x["block"], h[2:14])
                    with open(os.path.join(OUT, name), "w") as fh:
                        json.dump(b, fh, indent=1, sort_keys=True)
                    row["bundle"] = name
                census["evm"].append(row)
        p = os.path.join(DATA, "svm_facilitators_failed.json")
        if os.path.exists(p):
            m = svm_module()
            doc = json.load(open(p))
            census["svm_addresses"] = doc["addresses"]
            for t in doc["failed_transactions"]:
                r = t["result"]
                row = {"network": "solana", "facilitator": t["facilitator"], "signature": t["signature"],
                       **svm_reason(r["meta"])}
                try:
                    b, why = m.bundle(r, t["fee_payer"])
                except KeyError:            # the destination has no token balance entry: payTo is not on chain
                    b, why = None, "destination token account absent from postTokenBalances (payTo unknown)"
                if b is None:
                    row["bundle"], row["not_bundled"] = None, why
                else:
                    name = "svm_%s_%s.json" % (t["facilitator"], t["signature"][:12])
                    with open(os.path.join(OUT, name), "w") as fh:
                        json.dump(b, fh, indent=1, sort_keys=True)
                    row["bundle"] = name
                census["svm"].append(row)
        rows, payments, ledgers = xrpl_negatives(tmp)
        census["xrpl_payments"], census["xrpl_ledgers"] = payments, ledgers
        for name, d, code in rows:
            with open(os.path.join(OUT, "xrpl_" + name), "w") as fh:
                json.dump(d, fh, indent=1, sort_keys=True)
            census["xrpl"].append({"network": "xrpl:0", "tx": d["settlement"]["transaction"], "reason": code,
                                   "bundle": "xrpl_" + name})
    with open(os.path.join(DATA, "NEGATIVES.json"), "w") as fh:
        json.dump(census, fh, indent=1, sort_keys=True)
    n = sum(1 for k in ("evm", "svm", "xrpl") for r in census[k] if r.get("bundle"))
    print("negatives evm %d svm %d xrpl %d, bundles %d" % (len(census["evm"]), len(census["svm"]), len(census["xrpl"]), n))
    print(hashlib.sha256(open(os.path.join(DATA, "NEGATIVES.json"), "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
