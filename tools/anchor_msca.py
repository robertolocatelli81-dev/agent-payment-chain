"""Anchor the proof-form bundles of bundles/real_msca_20261101 (SPEC 32.10): add `canonical` (section 6, O1-O4: the Base
dispute game whose range holds the payment's block, the L2 headers from the root's block down to the block after the
payment's) and `canonical.l1_state` (Amendment 0.4: the L1 header, account and storage proofs and game code from which
the eight L1 replies are recomputed), all at ONE L1 block, so that one checkpoint — that L1 header's hash — anchors
every bundle built here. Read-only JSON-RPC, at most one request per second, no key.

  L1_RPC=https://... BASE_RPC=https://... python3 -B tools/anchor_msca.py fetch RAW_DIR      resumable; raw replies in RAW_DIR
  python3 -B tools/anchor_msca.py build RAW_DIR BUNDLE_DIR                                   offline: m0NN_anchored_*.json + ANCHORED.json

A payment is anchored only when the first intermediate output root at or after its block is at most 64 blocks away
(SPEC section 6: `canonical.headers` holds at most 64 headers); otherwise ANCHORED.json records why, and no bundle is
written for it. The game must hold the block (startingBlockNumber < block <= l2SequenceNumber); its status, proper,
respected and claim-valid words are what the L1 block says: a game not yet valid gives O4 pending, not verified.
"""
import glob
import json
import os
import sys
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "sources", "l1proof_20261024"))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/anchor_msca", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_verify as av  # noqa: E402
import canonical as C  # noqa: E402
import fetch_l1proof as FL  # noqa: E402
import make_bundles_l1state as ML  # noqa: E402
import make_bundles_msca as mb  # noqa: E402

BUNDLES = os.path.join(ROOT, "bundles", "real_msca_20261101")
MAX_HEADERS = 64
_last = [0.0]


_raw_rpc = mb.rpc


def raw_rpc(url, method, params):
    """make_bundles_msca.rpc (the whole reply, bytes, retried) at one request per second at most, whatever the caller."""
    wait = _last[0] + 1.0 - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last[0] = time.monotonic()
    return _raw_rpc(url, method, params)


def rpc(url, method, params):
    return json.loads(raw_rpc(url, method, params))["result"]


mb.rpc = raw_rpc          # make_bundles_msca.fetch_one (the L2 headers) goes through the same throttle
C.rpc = rpc
FL.rpc = rpc


def where(url):
    """scheme://host[:port] of an endpoint: what meta.json and ANCHORED.json record. A path, query or user part can
    hold a key (review 2, 2026-11-01): it is never written."""
    u = urllib.parse.urlsplit(url)
    return "%s://%s%s" % (u.scheme, u.hostname or "?", ":%d" % u.port if u.port else "")


def proof_bundles():
    return sorted(glob.glob(os.path.join(BUNDLES, "m*_proof_*.json")))


def _jload(p, default):
    return json.load(open(p)) if os.path.exists(p) else default


def _jsave(p, d):
    with open(p + ".tmp", "w") as fh:
        json.dump(d, fh, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)


class Games:
    """The factory's games of type 621 read once each (cached in RAW_DIR/games.json) and the first one whose
    l2SequenceNumber >= a block, by binary search on the index (the sequence numbers grow with the index)."""
    def __init__(self, raw, l1, l1_block):
        self.raw, self.l1, self.l1_block = raw, l1, l1_block
        self.p = os.path.join(raw, "games.json")
        self.d = _jload(self.p, {"count": None, "at": {}})
        self.call = lambda to, data: rpc(l1, "eth_call", [{"to": to, "data": data}, l1_block])
        if self.d["count"] is None:
            self.d["count"] = int(self.call(C.FACTORY, C.sel("gameCount()")), 16)
            _jsave(self.p, self.d)

    def at(self, i):
        k = str(i)
        if k not in self.d["at"]:
            r = self.call(C.FACTORY, C.sel("gameAtIndex(uint256)") + "%064x" % i)
            t, g = int(r[2:66], 16), "0x" + r[-40:]
            seq = int(self.call(g, C.sel("l2SequenceNumber()")), 16) if t == C.GAME_TYPE else None
            self.d["at"][k] = {"type": t, "game": g, "seq": seq}
            _jsave(self.p, self.d)
        return self.d["at"][k]

    def seq_from(self, i):
        for j in range(i, min(i + C.SCAN, self.d["count"])):
            e = self.at(j)
            if e["type"] == C.GAME_TYPE:
                return j, e["game"], e["seq"]
        return None

    def covering(self, n):
        lo, hi = 0, self.d["count"] - 1
        while lo < hi:
            mid = (lo + hi) // 2
            f = self.seq_from(mid)
            if f is None:                 # no game of type 621 within SCAN of mid: they are the newest, so go up
                lo = min(mid + C.SCAN, hi)
            elif f[2] >= n:
                hi = mid
            else:
                lo = f[0] + 1
        f = self.seq_from(lo)
        if f is None:
            raise RuntimeError("no game of type %d at or after index %d" % (C.GAME_TYPE, lo))
        return f


def game_facts(games, g):
    """start, l2SequenceNumber, roots count, status, isGameClaimValid of game g at the L1 block (cached)."""
    k = os.path.join(games.raw, "game_%s.json" % g[2:10])
    d = _jload(k, None)
    if d is None:
        start = int(games.call(g, C.sel("startingBlockNumber()")), 16)
        ed = bytes.fromhex(games.call(g, C.sel("extraData()"))[2:])
        d = {"game": g, "start": start, "seq": int.from_bytes(ed[64:96], "big"),
             "roots": (int.from_bytes(ed[32:64], "big") - 52) // 32,
             "status": int(games.call(g, C.sel("status()")), 16),
             "valid": int(games.call(C.REGISTRY, C.sel("isGameClaimValid(address)") + "%064x" % int(g, 16)), 16)}
        _jsave(k, d)
    return d


def place(f, n):
    """root_index and the root's block for block n in game facts f (as tools/canonical.py)."""
    k = (f["seq"] - f["start"]) // f["roots"]
    i = -(-(n - f["start"]) // k) - 1
    return i, f["start"] + (i + 1) * k, k


def fetch(raw, l1, l2):
    os.makedirs(raw, exist_ok=True)
    meta_p = os.path.join(raw, "meta.json")
    meta = _jload(meta_p, None)
    if meta is None:
        meta = {"l1_rpc": where(l1), "l2_rpc": where(l2), "l1_block": hex(int(rpc(l1, "eth_blockNumber", []), 16) - 3),
                "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _jsave(meta_p, meta)
    games = Games(raw, l1, meta["l1_block"])
    plan_p = os.path.join(raw, "plan.json")
    plan = _jload(plan_p, {})
    for p in proof_bundles():
        name = os.path.basename(p)
        if name in plan:
            continue
        doc = json.load(open(p))
        n = int(doc["inclusion"]["block_header"]["number"], 16)
        j, g, seq = games.covering(n)
        f = game_facts(games, g)
        i, m, k = place(f, n)
        e = {"block": n, "game": g, "game_index": j, "root_index": i, "root_block": m, "headers": m - n, "k": k,
             "status": f["status"], "valid": f["valid"], "in_range": f["start"] < n <= f["seq"]}
        e["anchorable"] = e["in_range"] and e["headers"] <= MAX_HEADERS
        if not e["in_range"]:
            e["why_not"] = "game %s holds blocks %d..%d, not %d" % (g, f["start"] + 1, f["seq"], n)
        elif e["headers"] > MAX_HEADERS:
            e["why_not"] = "the first root at or after the block is %d blocks away (block %d); canonical.headers holds " \
                           "at most %d headers (SPEC section 6)" % (m - n, m, MAX_HEADERS)
        plan[name] = e
        _jsave(plan_p, plan)
        print(name, json.dumps(e), flush=True)
    for name, e in plan.items():
        if not e["anchorable"]:
            continue
        for b in range(e["root_block"], e["block"], -1):             # the L2 headers m .. n+1 (as tools/canonical.py)
            mb.fetch_one(l2, raw, "hdr_%d" % b, "eth_getBlockByNumber", [hex(b), False])
        out = os.path.join(raw, "l1proof_%s.json" % e["game"][2:10])
        if not os.path.exists(out):
            sys.argv = ["fetch_l1proof.py", e["game"], out, l1, meta["l1_block"]]
            FL.main()
    print("plan:", sum(e["anchorable"] for e in plan.values()), "anchorable of", len(plan))


def build(raw, out_dir):
    meta = _jload(os.path.join(raw, "meta.json"), None)
    plan = _jload(os.path.join(raw, "plan.json"), None)
    if meta is None or plan is None:
        raise SystemExit("fetch first")
    made, checkpoints = [], set()
    for p in proof_bundles():
        name = os.path.basename(p)
        e = dict(plan[name])
        rec = {"from": name, "block": e["block"], "game": e["game"], "root_index": e["root_index"],
               "root_block": e["root_block"], "headers": e["headers"], "l1_block": int(meta["l1_block"], 16)}
        if not e["anchorable"]:
            rec.update(anchored=False, why_not=e["why_not"])
            made.append(rec)
            continue
        doc = json.load(open(p))
        d = json.load(open(os.path.join(raw, "l1proof_%s.json" % e["game"][2:10])))
        headers = [{k: h[k] for k in C.HEADER_KEYS if k in h}
                   for h in (mb._read(raw, "hdr_%d" % b) for b in range(e["root_block"], e["block"], -1))]
        doc["canonical"] = {
            "l1_network": "eip155:1", "game": e["game"], "root_index": e["root_index"], "headers": headers,
            "l1_replies": [{"method": "eth_call", "params": [{"to": c["to"], "data": c["data"]}, d["block"]],
                            "result": c["result"]} for c in d["calls"]],
            "l1_state": ML.l1_state(d)}
        cp = d["header"]["hash"]
        checkpoints.add(cp)
        new = name.replace("_proof_", "_anchored_")
        with open(os.path.join(out_dir, new), "w") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
        rep = av.verify_bundle(json.loads(json.dumps(doc)), l1_checkpoint=cp)
        rec.update(anchored=True, file=new, checkpoint=cp, verdict=rep["verdict"], **{"L2.sig": rep["checks"]["L2.sig"]},
                   evidence_level=rep["evidence_level"], canonical=rep.get("canonical"), l1_state=rep.get("l1_state"),
                   O4=rep["checks"].get("O4"))
        made.append(rec)
    _jsave(os.path.join(out_dir, "ANCHORED.json"), {
        "made": made, "checkpoints": sorted(checkpoints), "l1_block": meta["l1_block"], "l1_rpc": meta["l1_rpc"],
        "l2_rpc": meta["l2_rpc"], "fetched_utc": meta["fetched_utc"], "spec": "SPEC 32.10, section 6, Amendment 0.4",
        "real": "the proof-form bundles of this directory with canonical (the Base dispute game holding the block, its L1 "
                "replies at one L1 block, the L2 headers from the root's block) and l1_state (the L1 header, the proofs "
                "and the game code from which the replies are recomputed); the checkpoint is that L1 header's hash"})
    print(json.dumps(sorted({(r["anchored"], r.get("verdict"), r.get("L2.sig"), r.get("evidence_level"))
                             for r in made}, key=str)), "checkpoints", sorted(checkpoints))


def main(argv):
    if len(argv) == 3 and argv[1] == "fetch" and os.environ.get("L1_RPC") and os.environ.get("BASE_RPC"):
        fetch(argv[2], os.environ["L1_RPC"], os.environ["BASE_RPC"])
    elif len(argv) == 4 and argv[1] == "build":
        build(argv[2], argv[3])
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
