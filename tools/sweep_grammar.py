import copy, glob, json, sys, os
sys.path.insert(0, os.getcwd())
import apc_verify as av
def paths(x, p=()):
    yield p, x
    if isinstance(x, dict):
        for k, v in x.items(): yield from paths(v, p + (k,))
    elif isinstance(x, list):
        for i, v in enumerate(x): yield from paths(v, p + (i,))
def setp(d, p, v):
    for k in p[:-1]: d = d[k]
    d[p[-1]] = v
def run(d):
    try: return av.verify_bundle(d)
    except av.Refusal as e: return {"verdict": "refused", "reason": str(e)}
files = sys.argv[1:]
crash, unk, swaps = [], [], []
for f in files:
    doc = json.load(open(f)); base = run(doc)
    for p, v in list(paths(doc)):
        if isinstance(v, dict):
            d = copy.deepcopy(doc); t = d
            for k in p: t = t[k]
            t["zz_unknown"] = 1
            r = run(d)
            if r["verdict"] != "refused": unk.append((f[-40:], p, r["verdict"]))
        if p:
            for alt in (None, True, 7, "x", [], {}):
                if type(alt) is type(v): continue
                d = copy.deepcopy(doc); setp(d, p, alt)
                try: r = run(d)
                except Exception as e: crash.append((f[-40:], p, repr(alt), repr(e)[:80])); continue
                if r["verdict"] == base["verdict"] and r.get("canonical") == base.get("canonical") and r.get("checks") == base.get("checks"):
                    swaps.append((f[-40:], p, repr(alt)))
print("base", base["verdict"], base.get("canonical"))
print("CRASH", len(crash)); [print(c) for c in crash[:15]]
print("UNKNOWN KEY ACCEPTED", len(unk)); [print(c) for c in unk[:15]]
print("TYPE SWAP UNNOTICED", len(swaps)); [print(x) for x in sorted({c[1] for c in swaps})]
