"""SPEC 0.8 structural fuzz (python3 tools/fuzz_exchange.py ROOT SEED N): the x402 http.md example bundle of
tests/test_http.py, half of the cases with the RFC 9421 B.2.4 response signature added, then 1 to 3 random edits of
the exchange (values replaced, members deleted or added, list entries inserted, characters changed); each case is
verified without and with the RFC test keys. Every outcome must be a report or a refusal: any other exception is
printed as CRASH and counted in "bad"."""
import sys, random, copy, json, collections, base64
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[1] + "/tests")
import apc_verify as av, test_http as T
rng = random.Random(int(sys.argv[2]))
VALS = [None, True, 0, -1, 1.5, 1e400 if False else 2**64, "", "x", "\ud800" if False else "é", [], {}, [[]], [["A", "b"]], "AAAA", "A=="]
def walk(o, path=()):
    yield path, o
    if isinstance(o, dict):
        for k, v in o.items(): yield from walk(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o): yield from walk(v, path + (i,))
out = collections.Counter(); bad = 0
for n in range(int(sys.argv[3])):
    d = T.md_bundle()
    if rng.random() < .5:
        d["exchange"]["response"]["fields"] += [["Signature-Input", T.TEST_RESPONSE["fields"][4][1]], ["Signature", T.TEST_RESPONSE["fields"][5][1]]]
    for _ in range(rng.randint(1, 3)):
        nodes = list(walk(d["exchange"]))
        path, node = rng.choice(nodes)
        parent = d["exchange"]
        for k in path[:-1]: parent = parent[k]
        op = rng.random()
        if not path: continue
        if op < .35: parent[path[-1]] = copy.deepcopy(rng.choice(VALS))
        elif op < .5 and isinstance(parent, dict): del parent[path[-1]]
        elif op < .6 and isinstance(parent, list): parent.insert(path[-1], copy.deepcopy(rng.choice(VALS)))
        elif op < .75 and isinstance(node, str) and node: 
            i = rng.randrange(len(node)); parent[path[-1]] = node[:i] + rng.choice("aZ09+/=: ,;\"()\t\x01è") + node[i + 1:]
        elif isinstance(parent, dict): parent["k%d" % rng.randrange(9)] = copy.deepcopy(rng.choice(VALS))
    for keys in (None, T.KEYS):
        try:
            r = av.verify_bundle(json.loads(json.dumps(d)), None, keys)
            out[r["verdict"]] += 1
            json.dumps(r)
        except av.Refusal:
            out["refused"] += 1
        except Exception as e:
            bad += 1; print("CRASH", type(e).__name__, e, json.dumps(d["exchange"])[:300])
print("bad", bad, dict(out))
