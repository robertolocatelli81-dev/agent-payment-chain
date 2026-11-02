"""Which existing mutants of tools/mutants03.py do the real negatives kill? For each mutant whose name starts with one of
PREFIX: apply it to a copy of ROOT (without .git and oracle), run apc on every bundle of bundles/real_negatives_20261026
(as built, and with the settlement reply saying failure), print how many become chain_verified. Control first.

  python3 tools/negatives_vs_mutants.py ROOT PREFIX..."""
import importlib.util, os, shutil, subprocess, sys, tempfile
root = sys.argv[1]; names = sys.argv[2:]
spec = importlib.util.spec_from_file_location("m3", os.path.join(root, "tools", "mutants03.py"))
m = importlib.util.module_from_spec(spec); argv = sys.argv; sys.argv = ["x"]; spec.loader.exec_module(m); sys.argv = argv
CODE = r'''
import json, glob, sys, copy
sys.path.insert(0, ".")
import apc_verify as av
n = v = v2 = 0
for p in sorted(glob.glob("bundles/real_negatives_20261026/*.json")):
    d = av.strict_json(open(p).read())
    for k, doc in enumerate((d, dict(d, settlement=dict(d["settlement"], success=False)))):
        try: r = av.verify_bundle(copy.deepcopy(doc), None, None, None, False)["verdict"]
        except av.Refusal: r = "refused"
        if r == "chain_verified":
            if k == 0: v += 1
            else: v2 += 1
    n += 1
print(json.dumps({"bundles": n, "verified_as_built": v, "verified_failure_reply": v2}))
'''
tmp = tempfile.mkdtemp(prefix="negmut_", dir=os.environ.get("APC_SCRATCH"))
w = os.path.join(tmp, "w")
shutil.copytree(root, w, ignore=shutil.ignore_patterns(".git", "__pycache__", "oracle"))
def run():
    r = subprocess.run([sys.executable, "-B", "-c", CODE], cwd=w, capture_output=True, text=True)
    return r.stdout.strip() or r.stderr[-300:]
print("control", run(), flush=True)
for f, name, old, new in m.M:
    if not any(name.startswith(x) for x in names):
        continue
    p = os.path.join(w, f); src = open(p).read()
    if src.count(old) != 1:
        print(name, "STALE"); continue
    open(p, "w").write(src.replace(old, new))
    try:
        print("%-45s %s" % (name, run()), flush=True)
    finally:
        open(p, "w").write(src)
shutil.rmtree(tmp)
