"""Build bundles/real_v04_l1state (SPEC 0.4): the payments of bundles/real_v03_canonical whose game has L1 proofs in
sources/l1proof_20261024, with canonical.l1_replies replaced by the eth_call replies fetched at the proofs' L1 block and
canonical.l1_state added (the L1 header of that block, the account and storage proofs of eth_getProof, the game's
code). The checkpoint a reader passes is that header's hash.

  python3 tools/make_bundles_l1state.py ROOT"""
import glob
import json
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_block  # noqa: E402
import apc_l1proof  # noqa: E402

SRC = os.path.join(ROOT, "sources", "l1proof_20261024")
if not os.path.isfile(os.path.join(SRC, "l1proof_g7a3a.json")):
    sys.exit("sources/l1proof_20261024: the saved RPC replies are not in the public tree (kept with the corpus); fetch them with sources/l1proof_20261024/fetch_l1proof.py, or rebuild the set: tools/rebuild_corpus.py --only real_v04_l1state")
OUT = os.path.join(ROOT, "bundles", "real_v04_l1state")


def l1_state(d):
    """Only the proofs the eight replies read (apc_l1proof.replies records them): the verifier refuses an unread one."""
    hdr = {k: v for k, v in d["header"].items() if k in apc_block.HEADER_BASE + apc_block.HEADER_OPT + ("hash",)}
    h = lambda x: bytes.fromhex(x[2:])                                         # noqa: E731
    accs = {h(p["address"]): ([h(n) for n in p["accountProof"]],
                              {int(sp["key"], 16): [h(n) for n in sp["proof"]] for sp in p["storageProof"]})
            for p in d["proofs"].values()}
    used = set()
    apc_l1proof.replies(d["header"], accs, h(d["codes"]["game"]), h(d["game"]), used)
    accounts = [{"address": p["address"], "accountProof": p["accountProof"],
                 "storageProof": [{"key": sp["key"], "proof": sp["proof"]} for sp in p["storageProof"]
                                  if (h(p["address"]), int(sp["key"], 16)) in used]}
                for _, p in sorted(d["proofs"].items()) if (h(p["address"]), None) in used]
    return {"headers": [hdr], "accounts": accounts, "game_code": d["codes"]["game"]}


def main():
    os.makedirs(OUT, exist_ok=True)
    proofs = {}
    for p in sorted(glob.glob(os.path.join(SRC, "l1proof_*.json"))):
        d = json.load(open(p))
        proofs[d["game"].lower()] = (os.path.basename(p), d)
    man = {"source": "sources/l1proof_20261024 (SHA256SUMS.txt)", "bundles": []}
    for p in sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v03_canonical", "v*.json"))):
        doc = json.load(open(p))
        game = doc["canonical"]["game"].lower()
        if game not in proofs:
            continue
        name, d = proofs[game]
        doc["canonical"]["l1_replies"] = [{"method": "eth_call", "params": [{"to": c["to"], "data": c["data"]}, d["block"]],
                                           "result": c["result"]} for c in d["calls"]]
        doc["canonical"]["l1_state"] = l1_state(d)
        out = os.path.basename(p).replace("_envelope_reconstructed", "_l1state")
        with open(os.path.join(OUT, out), "w") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
        man["bundles"].append({"file": out, "from": "bundles/real_v03_canonical/" + os.path.basename(p), "proofs": name,
                               "l1_block": int(d["block"], 16), "checkpoint": d["header"]["hash"]})
    with open(os.path.join(OUT, "MANIFEST.json"), "w") as fh:
        json.dump(man, fh, indent=1, sort_keys=True)
    print("bundles %d" % len(man["bundles"]))


if __name__ == "__main__":
    main()
