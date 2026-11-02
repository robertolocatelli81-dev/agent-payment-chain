"""Frozen regression corpus: apc_verify on every real bundle of bundles/, compared with regress/VERDICTS.json.

  python3 tools/regress.py check [--sample]     exit 0 = every change justified in regress/CHANGES.md, 1 = not, 3 = refused
  python3 tools/regress.py write                refreeze VERDICTS.json and MANIFEST (only when `check` passes)

Each bundle runs through apc_verify.main exactly as `python3 apc_verify.py BUNDLE` (stdout captured), with the options
DIRS gives for its directory. VERDICTS.json is canonical JSON (sorted keys, no spaces, one bundle per line): for each
bundle its path, the sha256 of its bytes, bundle_version, the options, the exit code, the verdict, the map check ->
outcome and the verifier string. A difference is (path, field, old, new) with field one of: verdict, check:<name>,
sha256, bundle_version, exit, verifier, added, removed. A difference passes only when regress/CHANGES.md holds the row
| path | field | old | new | SPEC section | reason | with the same four values and a section written "§N" or "§N.M".
The verifier string alone may change without a row when its version is the one SPEC.md's first line names (a release
changes every bundle's string); any other field needs its row. CHANGES.md is closed: a table row that does not parse
is a refusal (exit 3), and so is a row that justifies nothing in the run that reads it (a stale row).

--sample: per (directory, frozen verdict) the 2 bundles with the smallest sha256, plus every bundle the frozen file
does not know; deterministic (41 of 1034 bundles, 12 s, on 2026-10-26). The full run is the job of the final round
(its measured time in regress/MANIFEST).
"""
import contextlib
import hashlib
import io
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REG = os.path.join(ROOT, "regress")
sys.path.insert(0, ROOT)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/regress", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
L1CP = "0x9140c56ce20a77dca7d648364bca6470be6a7f88297e652a20f7e46e4a14f3a6"   # bundles/real_v04_l1state/MANIFEST.json
# directory -> (what is real, where it is said, options). Every bundle of bundles/ is real chain data; the x402
# envelope around it is reconstructed (no facilitator's own PaymentPayload was seen), as each README says.
DIRS = {
    "bundles/authcap_real_20261026": ("Base commerce-payments v1.0 authorizations; payload rebuilt from the authorize call", "SPEC §25", []),
    "bundles/authcap_real_v11_20261026": ("Base commerce-payments v1.1 authorizations; payload rebuilt", "SPEC §25", []),
    "bundles/real": ("Base USDC EIP-3009 executions, head 52929129; envelope reconstructed", "bundles/real/README", []),
    "bundles/real_msca_20261101": ("Base USDC (v,r,s) executions of a Circle_SingleOwnerMSCA 1.0.0 payer, the 28 code_not_known payments of the 2026-10-22 census, each as apc-0.2 with payer_state.rpc, apc-0.3 with inclusion and payer_state.proof, and the same anchored (canonical and l1_state at L1 block 26321847, one checkpoint; SPEC 32.10); envelope reconstructed", "bundles/real_msca_20261101/MANIFEST.json and ANCHORED.json, SPEC §32 and §32.10",
                                   ["--l1-checkpoint", "0x6e4d8bb54a650a38a950ccc2530a30314149ca5f316bc9f811f7834c10ce5895"]),
    "bundles/real_giskard_issue1": ("Base tx of agent-payment-chain issue 1 (giskard09), anchored (canonical and l1_state at L1 block 26329354, one checkpoint; SPEC 33.13); envelope and reply reconstructed", "bundles/real_giskard_issue1/README",
                                    ["--l1-checkpoint", "0x7717e1e2a07cd03552c896eaa5a325cc8379d9b607f10a9a3ce75976a4662c5c"]),
    "bundles/real_issue1062": ("Base tx of x402 issue 1062; reply from the issue, envelope reconstructed", "bundles/real_issue1062/README", []),
    "bundles/real_negatives_20261026": ("chain-reverted EIP-3009 calls and failed Solana settlements; envelope and reply reconstructed", "oracle/negatives_20261026/README", []),
    "bundles/real_permit2": ("Base x402ExactPermit2Proxy settlements; envelope reconstructed", "bundles/real_permit2/README", []),
    "bundles/real_reverted": ("Base reverted EIP-3009 settlement, block 53020172; reply reconstructed", "bundles/real_reverted/README", []),
    "bundles/real_svm": ("Solana facilitator settlements; payload rebuilt (fee payer signature zeroed); m001 our own payment", "bundles/real_svm/MANIFEST.json", []),
    "bundles/real_svm_mandate": ("our Solana mainnet payment of 2026-10-31 bound to an AP2 mandate pack (Memo = SHA-256 of the chain); needs APC_AP2EV", "SPEC §31.9", []),
    "bundles/real_v02": ("Base USDC EIP-3009 executions, window 52942756; envelope reconstructed", "bundles/real_v02/README", []),
    "bundles/real_v02_misc": ("Base ERC-8021 Schema 0 execution; envelope reconstructed", "bundles/real_v02_misc/README", []),
    "bundles/real_v02_passkey": ("Base block 53093490: a Coinbase Smart Wallet passkey payer and one EOA payer; envelope reconstructed", "bundles/real_v02_passkey/README", []),
    "bundles/real_v02_wallet": ("Base Coinbase Smart Wallet payers; envelope reconstructed", "bundles/real_v02_wallet/README", []),
    "bundles/real_v03": ("Base executions with inclusion proofs; envelope reconstructed", "bundles/real_v03/MANIFEST.json", []),
    "bundles/real_v03_canonical": ("real_v03 with the canonical member (L1 replies)", "bundles/real_v03_canonical/SHA256SUMS", []),
    "bundles/real_v04_l1state": ("real_v03_canonical with L1 state proofs", "bundles/real_v04_l1state/MANIFEST.json", ["--l1-checkpoint", L1CP]),
    "bundles/real_world_20261026": ("EIP-3009 executions on 10 EVM networks; envelope reconstructed", "bundles/real_world_20261026/MANIFEST.json", []),
    "bundles/xlm_real_20261026": ("Stellar TESTNET settlements of the x402.org facilitator; payload rebuilt", "SPEC §20", []),
    "bundles/xrp_real_20261026": ("XRP Ledger mainnet Payments, 12 ledgers; requirements rebuilt from each payment", "SPEC §26", []),
}
ROW = re.compile(r"^\| (bundles/[A-Za-z0-9_./-]+\.json) \| (verdict|check:[A-Za-z0-9_.-]+|sha256|bundle_version|exit|verifier|added|removed) "
                 r"\| ([^|]+?) \| ([^|]+?) \| (§\d+(?:\.\d+)?) \| ([^|\s][^|]*?) \|$")


class Refused(Exception):
    pass


def directory(rel):
    d = os.path.dirname(rel)
    while d and d not in DIRS:
        d = os.path.dirname(d)
    if not d:
        raise Refused("bundle outside every listed directory: %s" % rel)
    return d


def corpus():
    out = []
    if not os.path.isdir(os.path.join(ROOT, "bundles")):
        raise Refused("bundles/ is not here: the real corpus is not distributed (SPEC section 33); rebuild it with "
                      "python3 tools/rebuild_corpus.py --rpc <network>=<your endpoint>")
    for base, _dirs, files in os.walk(os.path.join(ROOT, "bundles")):
        for f in files:
            if f.endswith(".json") and f not in ("MANIFEST.json", "ANCHORED.json"):     # the manifests of a directory
                rel = os.path.relpath(os.path.join(base, f), ROOT)
                directory(rel)
                out.append(rel)
    if not out:
        raise Refused("bundles/ holds no bundle: the real corpus is not distributed (SPEC section 33); rebuild it with "
                      "python3 tools/rebuild_corpus.py --rpc <network>=<your endpoint>")
    return sorted(out)


def run_one(rel):
    import apc_verify
    with open(os.path.join(ROOT, rel), "rb") as fh:
        data = fh.read()
    opts = DIRS[directory(rel)][2]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = apc_verify.main(["apc_verify.py"] + opts + [os.path.join(ROOT, rel)])
    rep = json.loads(buf.getvalue())
    try:
        ver = json.loads(data).get("bundle_version")
    except ValueError:
        ver = None
    return {"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "bundle_version": ver, "options": opts,
            "exit": code, "verdict": rep["verdict"], "checks": rep.get("checks", {}), "verifier": rep["verifier"]}


def load_frozen():
    p = os.path.join(REG, "VERDICTS.json")
    doc = json.load(open(p))
    return {r["path"]: r for r in doc["bundles"]}


def spec_version():
    m = re.search(r"apc_verify (\d+\.\d+(?:\.\d+)?)", open(os.path.join(ROOT, "apc_verify.py")).read())
    return "apc_verify " + m.group(1)


def diffs(frozen, now):
    out = []
    for p in sorted(set(frozen) | set(now)):
        a, b = frozen.get(p), now.get(p)
        if a is None:
            out.append((p, "added", "-", b["verdict"]))
            continue
        if b is None:
            out.append((p, "removed", a["verdict"], "-"))
            continue
        for k in ("sha256", "bundle_version", "exit", "verdict"):
            if a[k] != b[k]:
                out.append((p, k, str(a[k]), str(b[k])))
        if a["verifier"] != b["verifier"] and b["verifier"] != spec_version():
            out.append((p, "verifier", a["verifier"], b["verifier"]))
        for c in sorted(set(a["checks"]) | set(b["checks"])):
            x, y = a["checks"].get(c, "-"), b["checks"].get(c, "-")
            if x != y:
                out.append((p, "check:" + c, x, y))
    return out


def read_changes(path=None):
    path = path or os.path.join(REG, "CHANGES.md")
    rows = set()
    for n, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        if not line.startswith("|"):
            continue
        if line.startswith("| path |") or re.match(r"^\|[-| ]+\|$", line):
            continue
        m = ROW.match(line)
        if not m:
            raise Refused("CHANGES.md line %d is not a change row: %r" % (n, line))
        rows.add(m.group(1, 2, 3, 4))
    return rows


def check(sample=False, frozen=None, changes=None, log=print):
    frozen = load_frozen() if frozen is None else frozen
    changes = read_changes() if changes is None else changes
    paths = corpus()
    if sample:
        # the sample is drawn from the FROZEN corpus (a bundle missing here is then a `removed` difference), plus any
        # bundle that is here and not frozen: an empty or partial bundles/ cannot pass on what it lacks
        pick, groups = set(p for p in paths if p not in frozen), {}
        for p, r in frozen.items():
            groups.setdefault((directory(p), r["verdict"]), []).append((r["sha256"], p))
        for g in groups.values():
            pick.update(p for _s, p in sorted(g)[:2])
        frozen = {p: frozen[p] for p in pick if p in frozen}
        paths = sorted(p for p in pick if os.path.exists(os.path.join(ROOT, p)))
    t = time.time()
    now = {p: run_one(p) for p in paths}
    d = diffs(frozen, now)
    bad = [x for x in d if x not in changes]
    if not sample:
        stale = sorted(changes - set(d))
        if stale:
            raise Refused("CHANGES.md rows that justify nothing in this run: %s" % stale)
    log("bundles %d, differences %d, unjustified %d, %.1f s" % (len(now), len(d), len(bad), time.time() - t))
    for x in bad:
        log("UNJUSTIFIED %s %s: %s -> %s" % x)
    return now, d, bad


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write(now, seconds):
    rows = [now[p] for p in sorted(now)]
    text = '{"bundles":[\n' + ",\n".join(canon(r) for r in rows) + '\n],"verifier":' + canon(spec_version()) + "}\n"
    with open(os.path.join(REG, "VERDICTS.json"), "w") as fh:
        fh.write(text)
    per = {}
    for r in rows:
        d = per.setdefault(directory(r["path"]), {"bundles": 0, "verdicts": {}, "files_sha256": hashlib.sha256()})
        d["bundles"] += 1
        d["verdicts"][r["verdict"]] = d["verdicts"].get(r["verdict"], 0) + 1
        d["files_sha256"].update((r["path"] + " " + r["sha256"] + "\n").encode())
    lines = ["regress/MANIFEST - frozen regression corpus (tools/regress.py write)",
             "verifier: " + spec_version(),
             "VERDICTS.json sha256: " + hashlib.sha256(text.encode()).hexdigest(),
             "bundles: %d; full run %.0f s on this machine (nice 19, one process)" % (len(rows), seconds),
             "per directory: bundles, verdicts, sha256 over its sorted 'path sha256' lines, what is real, where said, options"]
    for k in sorted(per):
        v = per[k]
        lines.append("%s | %d | %s | %s | %s | %s | %s" % (k, v["bundles"], canon(v["verdicts"]), v["files_sha256"].hexdigest(),
                                                          DIRS[k][0], DIRS[k][1], " ".join(DIRS[k][2]) or "-"))
    with open(os.path.join(REG, "MANIFEST"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv):
    if len(argv) < 2 or argv[1] not in ("check", "write") or argv[2:] not in ([], ["--sample"]) or \
            (argv[1] == "write" and argv[2:]):
        print(__doc__)
        return 64
    try:
        if argv[1] == "check":
            return 1 if check(sample=argv[2:] == ["--sample"])[2] else 0
        frozen = load_frozen() if os.path.exists(os.path.join(REG, "VERDICTS.json")) else None
        t = time.time()
        if frozen is None:
            now = {p: run_one(p) for p in corpus()}
        else:
            now, _d, bad = check(frozen=frozen)
            if bad:
                print("refused: unjustified differences, add their rows to regress/CHANGES.md")
                return 1
        write(now, time.time() - t)
        print("written", len(now))
        return 0
    except Refused as e:
        print("refused:", e)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
