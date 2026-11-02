"""tools/mutants03.py, R02 equivalence (python3 tools/equiv_r02.py ROOT [--list]): base vs EQ (R02) vs PC (R02 + R10:
both type checks gone) on the real EVM bundles with `removed` varied. --list prints the bundles it reads and stops."""
import sys, os, json, copy, types
SRC = sys.argv[1]
sys.path.insert(0, SRC)
import apc_verify as av
src = open(os.path.join(SRC, "apc_verify.py")).read()
R02 = ('    if not isinstance(lg["removed"], bool):\n        raise Refusal', '    if False:\n        raise Refusal')
R10 = ('            raise Refusal("chain_tx.%s.removed: not a boolean" % name)\n    acc, au', '            pass\n    acc, au')
def mk(repls, name):
    s = src
    for a, b in repls:
        assert s.count(a) == 1, (name, a); s = s.replace(a, b)
    m = types.ModuleType(name); m.__file__ = os.path.join(SRC, "apc_verify.py"); sys.modules[name] = m; exec(compile(s, name, "exec"), m.__dict__); return m
EQ, PC = mk([R02], "eq"), mk([R02, R10], "pc")
# SPEC 29.6, 29.8: the real EVM bundles by the closed table of bundle versions (tests/test_apc03.real_bundles); until
# 2026-10-27 the glob bundles/*/*.json, every directory (real or not) of every chain
sys.path.insert(0, os.path.join(SRC, "tests"))
from test_apc03 import real_bundles  # noqa: E402
files = real_bundles("evm")
base, chosen = [], []
for p in files:
    with open(p) as fh:
        d = json.load(fh)
    if isinstance(d.get("chain_tx"), dict):
        base.append(d)
        chosen.append(p)
if "--list" in sys.argv[2:]:
    print("\n".join(os.path.relpath(p, SRC) for p in chosen))
    sys.exit(0)
VALS = ["ABSENT", True, False, 0, 1, "true", "false", None, [], {}, 1.0]
def out(m, d):
    try:
        r = m.verify_bundle(copy.deepcopy(d))
        return ("R", r["verdict"], tuple(r["failed"]), tuple(r["not_evaluated"]), json.dumps(r["checks"], sort_keys=True))
    except (m.Refusal, av.Refusal) as e:
        return ("REFUSAL", str(e))
    except Exception as e:
        return ("CRASH", type(e).__name__)
n = deq = dpc = 0
for d in base:
    for name in ("log_authorization_used", "log_transfer", "log_forward"):
        if not isinstance(d["chain_tx"].get(name), dict):
            continue
        for v in VALS:
            x = copy.deepcopy(d)
            if v == "ABSENT":
                x["chain_tx"][name].pop("removed", None)
            else:
                x["chain_tx"][name]["removed"] = v
            b, e, c = out(av, x), out(EQ, x), out(PC, x)
            n += 1; deq += b != e; dpc += b != c
print("bundles", len(base), "cases", n, "EQ differs", deq, "PC differs", dpc)
