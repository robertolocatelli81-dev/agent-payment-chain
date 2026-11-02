"""Equivalence checks of the two mutants left out of tools/mutants.py (c3) and tools/mutants03.py (o3).

  python3 tools/equiv_mutants.py ROOT c3 450 [--list]      python3 tools/equiv_mutants.py ROOT o3 300

(--list, c3 only: prints the bundles it reads and stops.)

which = c3 | o3. Compares (verdict, failed, not_evaluated, block_bound, canonical,
checks) between the unmutated verifier, the claimed-equivalent mutant (EQ) and a known non-equivalent mutant (PC)."""
import sys, os, glob, json, copy, random, types
SRC, which, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
sys.path.insert(0, SRC)
import apc_verify as av
src = open(os.path.join(SRC, "apc_verify.py")).read()
def mk(repls, name):
    s = src
    for a, b in repls:
        assert s.count(a) == 1, (name, a); s = s.replace(a, b)
    m = types.ModuleType(name); m.__file__ = os.path.join(SRC, "apc_verify.py"); sys.modules[name] = m; exec(compile(s, name, "exec"), m.__dict__); return m
if which == "c3":
    EQ = mk([('        core = core and res.get("C3") == "verified"', '        pass')], "eq")
    PC = mk([('        core = core and res.get("C3") == "verified"', '        pass'),
             ('c3 = ("not_evaluated:indirect_call_needs_log_transfer" if indirect else', 'c3 = ("not_evaluated:absent:no_log_transfer" if indirect else')], "pc")
    # SPEC 29.6: the real EVM bundles by the closed table of bundle versions (tests/test_apc03.real_bundles), in the
    # directories bundles/real_v02* and bundles/real_v03* as before, sorted (glob order is the file system's)
    sys.path.insert(0, os.path.join(SRC, "tests"))
    from test_apc03 import real_bundles
    files = [p for p in real_bundles("evm") if os.path.basename(os.path.dirname(p)).startswith(("real_v02", "real_v03"))]
    docs, chosen = [], []
    for p in files:
        d = json.load(open(p))
        if isinstance(d, dict) and "chain_tx" in d and d["chain_tx"]["tx"]["to"].lower() != d["payment_payload"]["accepted"]["asset"].lower():
            docs.append(d)
            chosen.append(p)
else:
    EQ = mk([('root = keccak256(bytes(32) + bytes.fromhex(top["stateRoot"][2:]) + bytes.fromhex(top["withdrawalsRoot"][2:])\n                         + bytes.fromhex(chain[0][1][2:]))',
              'root = keccak256(bytes(32) + bytes.fromhex(top["stateRoot"][2:]) + bytes.fromhex(top["withdrawalsRoot"][2:])\n                         + bytes.fromhex(str(top["hash"])[2:]))')], "eq")
    PC = mk([('root = keccak256(bytes(32) + bytes.fromhex(top["stateRoot"][2:]) + bytes.fromhex(top["withdrawalsRoot"][2:])\n                         + bytes.fromhex(chain[0][1][2:]))',
              'root = keccak256(bytes(32) + bytes.fromhex(top["stateRoot"][2:]) + bytes.fromhex(top["withdrawalsRoot"][2:])\n                         + bytes.fromhex(str(top["hash"])[2:]))'),
             ('o2 += ["failed:header_hash_mismatch" for h, hh, _ in chain if hh != str(h.get("hash", "")).lower()]',
              'o2 += ["failed:header_hash_mismatch" for h, hh, _ in chain[1:] if hh != str(h.get("hash", "")).lower()]')], "pc")
    docs = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(SRC, "bundles/real_v03_canonical/v*.json")))]
if which == "c3" and "--list" in sys.argv[4:]:
    print("\n".join(os.path.relpath(p, SRC) for p in chosen))
    sys.exit(0)
print("base files", len(docs))
def out(m, d):
    try:
        r = m.verify_bundle(copy.deepcopy(d))
        return (r["verdict"], tuple(r["failed"]), tuple(r["not_evaluated"]), r.get("block_bound"), r.get("canonical"), json.dumps(r["checks"], sort_keys=True))
    except (m.Refusal, av.Refusal) as e:
        return ("refused", str(e))
    except Exception as e:
        return ("crash", type(e).__name__)
rnd = random.Random(20261023)
def alter(d):
    d = copy.deepcopy(d)
    if which == "c3":
        ct = d["chain_tx"]; op = rnd.randrange(8)
        if op == 0: ct.pop("log_transfer", None)
        elif op == 1 and "log_transfer" in ct: ct["log_transfer"]["logIndex"] = hex(int(ct["log_transfer"]["logIndex"], 16) + rnd.choice((1, 2, -1)))
        elif op == 2 and "log_transfer" in ct: t = ct["log_transfer"]["topics"]; t[rnd.randrange(3)] = "0x" + "%064x" % rnd.randrange(1 << 64)
        elif op == 3 and "log_transfer" in ct: ct["log_transfer"]["data"] = "0x" + "%064x" % rnd.randrange(1 << 64)
        elif op == 4 and "log_transfer" in ct: ct["log_transfer"]["address"] = "0x" + "%040x" % rnd.randrange(1 << 64)
        elif op == 5: ct["log_authorization_used"]["logIndex"] = hex(rnd.randrange(1, 500))
        elif op == 6 and "log_transfer" in ct: ct["log_transfer"]["transactionHash"] = "0x" + "%064x" % rnd.randrange(1 << 64)
        elif op == 7: ct.pop("log_forward", None); ct.pop("log_transfer", None); d.pop("inclusion", None); d.pop("canonical", None)
    else:
        hs = d["canonical"]["headers"]; op = rnd.randrange(5)
        tgt = hs[0] if hs and rnd.random() < .7 else (rnd.choice(hs) if hs else d["inclusion"]["block_header"])
        h = tgt["hash"]
        if op == 0: tgt["hash"] = "0x" + h[2:].upper()
        elif op == 1: i = rnd.randrange(2, len(h)); tgt["hash"] = h[:i] + ("1" if h[i] != "1" else "2") + h[i + 1:]
        elif op == 2: tgt["hash"] = h + "00"
        elif op == 3: tgt["hash"] = " " + h
        elif op == 4: tgt["stateRoot"] = tgt["stateRoot"][:5] + ("1" if tgt["stateRoot"][5] != "1" else "2") + tgt["stateRoot"][6:]
    return d
vec_diff = sum(out(av, d) != out(EQ, d) for d in docs)
print("vectors: EQ differs on", vec_diff, "of", len(docs))
eqd = pcd = 0; crashes = 0
for i in range(N):
    d = alter(rnd.choice(docs))
    a, b = out(av, d), out(EQ, d)
    eqd += a != b; crashes += a[0] == "crash"
    if i < N // 3 or which == "o3":
        pcd += a != out(PC, d)
print("generated", N, "EQ differences", eqd, "PC differences", pcd, "(PC on", N // 3 if which == "c3" else N, "cases)", "crashes", crashes)
