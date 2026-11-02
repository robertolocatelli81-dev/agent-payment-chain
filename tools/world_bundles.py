"""Bundles from the real EIP-3009 executions of oracle/world_20261026 (other chains and other stablecoins), verified by
apc_verify. REAL: authorization, signature, transaction and AuthorizationUsed log as the RPC returned them;
RECONSTRUCTED: the x402 envelope (as tools/make_real_bundles.py). When the token has no public version() (JPYC),
the EIP-712 domain version is found by recovery: the version under which every executed signature recovers its
`from` (the token accepted each one on chain, so the right domain must recover all of them); none or several is
reported, not guessed.

  APC_SIGLIB=... python3 tools/world_bundles.py ORACLE_DIR OUT_DIR"""
import glob
import gzip
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_verify as av  # noqa: E402

CANDIDATES = ("1", "2", "3")


def _read(oracle):
    with (gzip.open(oracle, "rt") if oracle.endswith(".gz") else open(oracle)) as fh:
        return json.load(fh)


def build(oracle, version, out):
    doc = _read(oracle)
    doc["summary"]["token_version"] = version
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(doc, fh)
    try:
        subprocess.run([sys.executable, "-B", os.path.join(ROOT, "tools", "make_real_bundles.py"), fh.name, out],
                       check=True, capture_output=True)
    finally:
        os.unlink(fh.name)
    return sorted(glob.glob(os.path.join(out, "*.json")))


def main(argv):
    src, dst = argv[1], argv[2]
    manifest = []
    for oracle in sorted(glob.glob(os.path.join(src, "*.json")) + glob.glob(os.path.join(src, "*.json.gz"))):
        s = _read(oracle)["summary"]
        name = os.path.basename(oracle).split(".json")[0]
        row = {"name": name, "chain_id": s["chain_id"], "token": s["token"], "token_name": s["token_name"],
               "token_version_rpc": s["token_version"], "logs": s["authorization_used_logs"],
               "direct_calls": s["direct_calls_kept"]}
        if not s["direct_calls_kept"]:
            manifest.append(dict(row, result="no direct transferWithAuthorization call in the scanned blocks"))
            continue
        tried = [s["token_version"]] if s["token_version"] else list(CANDIDATES)
        good = []
        for v in tried:
            with tempfile.TemporaryDirectory() as tmp:
                paths = build(oracle, v, tmp)
                reps = [av.verify_bundle(av.strict_json(open(p).read())) for p in paths]
                if reps and all(r["checks"]["L2.sig"] == "verified" for r in reps):
                    good.append((v, paths, reps, [open(p).read() for p in paths]))
        if len(good) != 1:
            manifest.append(dict(row, result="domain version not found by recovery: %d candidates hold" % len(good)))
            continue
        v, paths, reps, texts = good[0]
        out = os.path.join(dst, name)
        os.makedirs(out, exist_ok=True)
        for p, t in zip(paths, texts):
            with open(os.path.join(out, os.path.basename(p)), "w") as fh:
                fh.write(t)
        verdicts = {}
        for r in reps:
            verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
        manifest.append(dict(row, domain_version=v, version_source="rpc version()" if s["token_version"] else
                             "recovery over every executed signature", bundles=len(paths), verdicts=verdicts,
                             L2_sig_verified=sum(r["checks"]["L2.sig"] == "verified" for r in reps),
                             C1_C2_verified=sum(r["checks"]["C1"] == r["checks"]["C2"] == "verified" for r in reps)))
    with open(os.path.join(dst, "MANIFEST.json"), "w") as fh:
        json.dump({"source": os.path.relpath(src, ROOT), "made_by": "tools/world_bundles.py", "rows": manifest}, fh,
                  indent=1)
    for m in manifest:
        print(json.dumps(m))


if __name__ == "__main__":
    main(sys.argv)
