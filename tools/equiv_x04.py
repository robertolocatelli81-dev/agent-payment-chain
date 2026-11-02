"""tools/mutants03.py X04 equivalence (python3 tools/equiv_x04.py ROOT [--list]): base vs EQ (X04: C1 not required in _executed)
vs PC (X04 + X03: neither C1 nor C2 required) on real bundles with a failed settlement reply and C1/C2 broken in
several ways. --list prints the bundles it reads and stops."""
import copy, json, os, sys, types
SRC = sys.argv[1]
sys.path.insert(0, SRC)
import apc_verify as av
sys.path.insert(0, os.path.join(SRC, "tests"))
from test_apc03 import real_bundles  # noqa: E402
src = open(os.path.join(SRC, "apc_verify.py")).read()
X04 = ('    return c1 == "verified" and c2 == "verified" and', '    return c2 == "verified" and')
X03X04 = ('    return c1 == "verified" and c2 == "verified" and', '    return True and')
def mk(repls, name):
    s = src
    for a, b in repls:
        assert s.count(a) == 1, (name, a); s = s.replace(a, b)
    m = types.ModuleType(name); m.__file__ = os.path.join(SRC, "apc_verify.py"); sys.modules[name] = m; exec(compile(s, name, "exec"), m.__dict__); return m
EQ, PC = mk([X04], "eq"), mk([X03X04], "pc")
def load(p):
    with open(p, "rb") as fh:
        return av.strict_json(fh.read().decode("utf-8"))
def out(m, d):
    try:
        r = m.verify_bundle(copy.deepcopy(d))
        return ("R", r["verdict"], tuple(r["failed"]), json.dumps(r["checks"], sort_keys=True), tuple(r["notes"]))
    except (m.Refusal, av.Refusal) as e:
        return ("REFUSAL", str(e))
    except Exception as e:
        return ("CRASH", type(e).__name__)
def edits(d):
    yield "none", lambda e: None
    yield "value", lambda e: e["payment_payload"]["payload"]["authorization"].__setitem__("value", str(int(e["payment_payload"]["payload"]["authorization"]["value"]) + 1))
    yield "network", lambda e: e["chain_tx"].__setitem__("network", "eip155:1")
    yield "tx_to", lambda e: e["chain_tx"]["tx"].__setitem__("to", "0x" + "11" * 20)
    yield "log_nonce", lambda e: e["chain_tx"]["log_authorization_used"]["topics"].__setitem__(2, "0x" + "00" * 32)
    yield "sig", lambda e: e["payment_payload"]["payload"].__setitem__("signature", e["payment_payload"]["payload"]["signature"][:-4] + "1b1b"[: 4] if not e["payment_payload"]["payload"]["signature"].endswith("1b") else e["payment_payload"]["payload"]["signature"][:-2] + "1c")
# SPEC 29.6: the real EVM bundles by the closed table of bundle versions (tests/test_apc03.real_bundles), never the glob
# bundles/real*/*.json (until 2026-10-27 it also took the 562 Solana and XRPL bundles with settlement and chain_tx)
BASE = [(p, d) for p, d in ((p, load(p)) for p in real_bundles("evm")) if "settlement" in d and "chain_tx" in d]
if "--list" in sys.argv[2:]:
    print("\n".join(os.path.relpath(p, SRC) for p, _ in BASE))
    sys.exit(0)
n = deq = dpc = crashes = 0
for p, d in BASE:
    for name, ed in edits(d):
        e = copy.deepcopy(d)
        e["settlement"] = {"success": False, "errorReason": "x", "network": d["settlement"]["network"],
                           "transaction": d["settlement"]["transaction"]}
        try:
            ed(e)
        except Exception:
            continue
        b, q, c = out(av, e), out(EQ, e), out(PC, e)
        n += 1; deq += b != q; dpc += b != c; crashes += "CRASH" in (b[0], q[0], c[0])
print("cases", n, "EQ differs", deq, "PC differs", dpc, "crashes", crashes)
