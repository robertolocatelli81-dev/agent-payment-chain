"""SPEC 0.4 (section 6): canonical.l1_state, the eight L1 replies recomputed from eth_getProof proofs under an L1 header
chain that starts at the reader's checkpoint. Real data: bundles/real_v04_l1state (8 payments, game 0x7a3a…, proofs at
L1 block 26259631) and the proofs of a second game still in progress (0x8710…, L1 block 26259645), in
sources/l1proof_20261024."""
import copy
import glob
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03_canonical", "real_v04_l1state", files=("sources/l1proof_20261024/l1proof_g7a3a.json", "sources/l1proof_20261024/l1proof_g8710.json"))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_l1proof as lp  # noqa: E402
import apc_verify as av  # noqa: E402

DIR = os.path.join(ROOT, "bundles", "real_v04_l1state")
FILES = sorted(p for p in glob.glob(os.path.join(DIR, "*.json")) if "MANIFEST" not in p)
SRC = os.path.join(ROOT, "sources", "l1proof_20261024")


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


MAN = {b["file"]: b for b in load(os.path.join(DIR, "MANIFEST.json"))["bundles"]}


def run(d, cp):
    try:
        return av.verify_bundle(d, cp)
    except av.Refusal:
        return {"verdict": "refused"}


def cp_of(p):
    return MAN[os.path.basename(p)]["checkpoint"]


def flip(hx, i):
    b = bytearray(bytes.fromhex(hx[2:]))
    b[i % len(b)] ^= 1
    return "0x" + b.hex()


def acc_of(d, addr):
    return next(a for a in d["canonical"]["l1_state"]["accounts"] if a["address"].lower() == addr)


class Real(unittest.TestCase):
    def test_all_proven(self):
        self.assertEqual(len(FILES), 8)
        for p in FILES:
            d = load(p)
            r = run(d, cp_of(p))
            self.assertEqual((r["verdict"], r["checks"]["L1"], r["l1_state"], r["canonical"]),
                             ("chain_verified", "verified", "proven", "final"), p)
            self.assertTrue(any("recomputed from account and storage proofs" in n for n in r["notes"]), p)
            r = run(d, None)
            self.assertEqual((r["verdict"], r["checks"]["L1"], r["l1_state"]),
                             ("chain_verified", "not_evaluated:absent:no_l1_checkpoint", "not_shown"), p)

    def test_second_game_in_progress(self):
        """the game 0x8710… (no payment of ours in it): its eight replies recomputed from its proofs equal eth_call"""
        d = load(os.path.join(SRC, "l1proof_g8710.json"))
        st = json.loads(json.dumps(d))
        accs = {bytes.fromhex(p["address"][2:]): ([bytes.fromhex(n[2:]) for n in p["accountProof"]],
                                                   {int(s["key"], 16): [bytes.fromhex(n[2:]) for n in s["proof"]]
                                                    for s in p["storageProof"]}) for p in st["proofs"].values()}
        got = lp.replies(d["header"], accs, bytes.fromhex(d["codes"]["game"][2:]), bytes.fromhex(d["game"][2:]))
        self.assertEqual([g.hex() for g in got], [c["result"][2:] for c in d["calls"]])
        self.assertEqual(int(d["calls"][7]["result"], 16), 0)                 # not a valid claim yet
        self.assertEqual(int(d["calls"][4]["result"], 16), 0)                 # IN_PROGRESS

    def test_v03_bundles_unchanged(self):
        """the 0.3 canonical bundles carry no l1_state: L1 absent, verdicts as before"""
        for p in sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v03_canonical", "v*.json")))[:4]:
            r = run(load(p), "0x" + "11" * 32)
            self.assertEqual((r["checks"]["L1"], r["l1_state"]), ("not_evaluated:absent:no_l1_state", "not_shown"), p)


class Broken(unittest.TestCase):
    def setUp(self):
        self.p = FILES[0]
        self.d0, self.cp = load(self.p), cp_of(self.p)

    def l1(self, d):
        return run(d, self.cp)["checks"]["L1"]

    def test_wrong_checkpoint(self):
        self.assertEqual(self.l1(self.d0), "verified")
        r = run(self.d0, flip(self.cp, 5))
        self.assertEqual((r["checks"]["L1"], r["l1_state"], r["verdict"]),
                         ("failed:l1_state:header_chain_broken", "failed", "chain_failed"))

    def test_header_fields(self):
        d = copy.deepcopy(self.d0)
        h = d["canonical"]["l1_state"]["headers"][0]
        h["stateRoot"] = flip(h["stateRoot"], 3)
        self.assertEqual(self.l1(d), "failed:l1_header_hash_mismatch")
        h["hash"] = "0x" + av.apc_block.header_hash(h)[2:]
        self.assertEqual(self.l1(d), "failed:l1_state:header_chain_broken")   # the checkpoint no longer matches

    def test_every_proof_node(self):
        """each account proof and each storage proof, one node changed: never verified"""
        n = 0
        for i, a in enumerate(self.d0["canonical"]["l1_state"]["accounts"]):
            for where in ["accountProof"] + [("storageProof", j) for j in range(len(a["storageProof"]))]:
                for k in (0, -1):
                    d = copy.deepcopy(self.d0)
                    aa = d["canonical"]["l1_state"]["accounts"][i]
                    nodes = aa["accountProof"] if where == "accountProof" else aa["storageProof"][where[1]]["proof"]
                    if not nodes:
                        continue
                    nodes[k] = flip(nodes[k], 9)
                    got = self.l1(d)
                    self.assertTrue(got.startswith("failed:l1_state:"), (i, where, k, got))
                    n += 1
        self.assertGreater(n, 40)

    def test_missing_proofs(self):
        d = copy.deepcopy(self.d0)
        st = d["canonical"]["l1_state"]
        asr = acc_of(d, "0x909f6cf47ed12f010a796527f562bfc26c7f4e72")
        asr["storageProof"] = asr["storageProof"][1:]
        self.assertEqual(self.l1(d), "failed:l1_state:storage_proof_missing")
        d = copy.deepcopy(self.d0)
        st = d["canonical"]["l1_state"]
        st["accounts"] = [a for a in st["accounts"] if a["address"].lower() != "0x43edb88c4b80fdd2adff2412a7bebf9df42cb40e"]
        self.assertEqual(self.l1(d), "failed:l1_state:account_proof_missing_0x43edb88c4b80fdd2adff2412a7bebf9df42cb40e")

    def test_game_code(self):
        d = copy.deepcopy(self.d0)
        d["canonical"]["l1_state"]["game_code"] = flip(d["canonical"]["l1_state"]["game_code"], 200)
        self.assertEqual(self.l1(d), "failed:l1_state:code_not_code_hash")

    def test_each_reply_against_the_proof(self):
        names = ["gameType", "rootClaim", "extraData", "startingBlockNumber", "status", "isGameProper",
                 "isGameRespected", "isGameClaimValid"]
        for i, name in enumerate(names):
            d = copy.deepcopy(self.d0)
            r = d["canonical"]["l1_replies"][i]
            b = bytearray(bytes.fromhex(r["result"][2:]))
            b[31 if i != 2 else 70] ^= 1
            r["result"] = "0x" + b.hex()
            got = run(d, self.cp)
            if got["verdict"] == "refused":          # a reply outside its own grammar (a status above 2, ...)
                continue
            self.assertEqual(got["checks"]["L1"], "failed:l1_reply_not_proven:" + name, name)

    def test_replies_at_another_block(self):
        d = copy.deepcopy(self.d0)
        for r in d["canonical"]["l1_replies"]:
            r["params"][1] = hex(int(r["params"][1], 16) + 1)
        self.assertEqual(self.l1(d), "failed:l1_last_header_not_the_replies_block")

    def test_unpinned_implementation(self):
        saved = dict(lp.PINS["asr_impl"])
        lp.PINS["asr_impl"].clear()
        try:
            self.assertEqual(self.l1(copy.deepcopy(self.d0)), "not_evaluated:l1_asr_impl_not_pinned")
            r = run(self.d0, self.cp)
            self.assertEqual((r["verdict"], r["l1_state"]), ("chain_incomplete", "not_shown"))
        finally:
            lp.PINS["asr_impl"].update(saved)
        saved = set(lp.PROXY_CODEHASH)
        lp.PROXY_CODEHASH.clear()
        try:
            self.assertEqual(self.l1(copy.deepcopy(self.d0)), "not_evaluated:l1_asr_impl_proxy_code_not_pinned")
        finally:
            lp.PROXY_CODEHASH.update(saved)
        saved = dict(lp.PINS["game_impl"])
        lp.PINS["game_impl"].clear()
        try:
            self.assertEqual(self.l1(copy.deepcopy(self.d0)), "not_evaluated:l1_game_impl_not_pinned")
        finally:
            lp.PINS["game_impl"].update(saved)

    def test_pinned_values_matter(self):
        """a pinned value read wrongly changes a reply: the comparison catches it (roots, finality delay)"""
        k = next(iter(lp.PINS["game_impl"]))
        for key, val, want in (("roots", 19, "failed:"),):
            saved = {h: dict(v) for h, v in lp.PINS["game_impl"].items()}
            for v in lp.PINS["game_impl"].values():
                v[key] = val
            try:
                self.assertTrue(self.l1(copy.deepcopy(self.d0)).startswith(want))   # another slot is read: a proof
            finally:                                                              # is missing, or a reply differs
                lp.PINS["game_impl"].clear()
                lp.PINS["game_impl"].update(saved)
        self.assertIn(k, lp.PINS["game_impl"])
        saved = {h: dict(v) for h, v in lp.PINS["asr_impl"].items()}
        for v in lp.PINS["asr_impl"].values():
            v["finality_delay"] = 10 ** 10
        try:
            self.assertEqual(self.l1(copy.deepcopy(self.d0)), "failed:l1_reply_not_proven:isGameClaimValid")
        finally:
            lp.PINS["asr_impl"].clear()
            lp.PINS["asr_impl"].update(saved)


class Logic(unittest.TestCase):
    """the conditions the real game does not meet (blacklisted, retired, paused, not registered, ...): the value read from
    one slot is replaced, every other value still comes from the real proofs; each changes a reply or fails the proof"""
    def setUp(self):
        self.d0, self.cp = load(FILES[0]), cp_of(FILES[0])
        self.game = bytes.fromhex(self.d0["canonical"]["game"][2:].lower())
        self.ts = int(self.d0["canonical"]["l1_state"]["headers"][0]["timestamp"], 16)

    def game_root(self):
        st = self.d0["canonical"]["l1_state"]
        a = acc_of(self.d0, self.d0["canonical"]["game"].lower())
        return lp.account(bytes.fromhex(st["headers"][0]["stateRoot"][2:]), self.game,
                          [bytes.fromhex(n[2:]) for n in a["accountProof"]])[2]

    def with_slot(self, slot, fn, root=None):
        """root: only in that account's storage (slot numbers repeat across contracts)"""
        real = lp.storage

        def fake(r, s, proof):
            v = real(r, s, proof)
            return fn(v) if s == slot and (root is None or r == root) else v
        with mock.patch.object(lp, "storage", fake):
            return run(copy.deepcopy(self.d0), self.cp)["checks"]["L1"]

    def test_blacklisted(self):
        self.assertEqual(self.with_slot(lp.mapping_slot(bytes(12) + self.game, 5), lambda v: 1),
                         "failed:l1_reply_not_proven:isGameProper")

    def test_retired(self):
        self.assertEqual(self.with_slot(6, lambda v: v | (2 ** 63 << 32)), "failed:l1_reply_not_proven:isGameProper")

    def test_paused(self):
        for ident in (bytes(20), None):
            if ident is None:              # the portal: SystemConfig's portal slot names it
                real = lp.storage
                seen = {}

                def spy(root, s, proof):
                    v = real(root, s, proof)
                    seen[s] = v
                    return v
                with mock.patch.object(lp, "storage", spy):
                    run(copy.deepcopy(self.d0), self.cp)
                ident = lp._addr_of(seen[lp.PORTAL_SLOT])
            self.assertEqual(self.with_slot(lp.mapping_slot(bytes(12) + ident, 0), lambda v: self.ts),
                             "failed:l1_reply_not_proven:isGameProper", ident.hex())
            # a pause that expired (t + 7 884 000 <= timestamp) does not count
            self.assertEqual(self.with_slot(lp.mapping_slot(bytes(12) + ident, 0), lambda v: self.ts - 7_884_000),
                             "verified", ident.hex())

    def test_not_registered(self):
        real = lp.storage
        reads = []

        def spy(root, s, proof):
            reads.append(s)
            return real(root, s, proof)
        with mock.patch.object(lp, "storage", spy):
            run(copy.deepcopy(self.d0), self.cp)
        big = [s for s in reads if s > 2 ** 200 and s not in (lp.IMPL_SLOT, lp.PORTAL_SLOT,
                                                               lp.mapping_slot(bytes(12) + self.game, 5))]
        hits = [s for s in big if self.with_slot(s, lambda v: 0) == "failed:l1_reply_not_proven:isGameProper"]
        self.assertGreaterEqual(len(hits), 1)          # the factory's slot-103 entry, set to zero

    def test_resolved_after_the_block(self):
        self.assertEqual(self.with_slot(0, lambda v: (v & ~((2 ** 64 - 1) << 64)) | ((self.ts + 1) << 64),
                                        self.game_root()),
                         "failed:l1_state:game_resolved_after_block")

    def test_status_read(self):
        got = self.with_slot(0, lambda v: (v & ~(0xff << 128)) | (1 << 128), self.game_root())
        self.assertEqual(got, "failed:l1_reply_not_proven:status")

    def test_not_respected(self):
        """respected 0 in the game's slot 0: isGameRespected and isGameClaimValid recomputed 0; the carried replies say
        the same, so L1 holds (and validity did read respected)"""
        d = copy.deepcopy(self.d0)
        for i in (6, 7):
            d["canonical"]["l1_replies"][i]["result"] = "0x" + "00" * 32
        real = lp.storage
        root = self.game_root()

        def fake(r, s, proof):
            v = real(r, s, proof)
            return v & ~(0xff << 144) if s == 0 and r == root else v
        with mock.patch.object(lp, "storage", fake):
            got = run(d, self.cp)
        self.assertEqual(got["checks"]["L1"], "verified")
        self.assertEqual(got["checks"]["O4"], "not_evaluated:game_not_proper_or_not_respected")

    def test_another_factory(self):
        self.assertEqual(self.with_slot(1, lambda v: v ^ 1), "failed:l1_state:asr_factory_not_the_pinned_factory")

    def test_clone_layout(self):
        real = lp.code
        for cut in (lambda c: c[:-1], lambda c: c[:-2] + (len(c) + 7).to_bytes(2, "big"),
                    lambda c: b"\x00" + c[1:]):
            with mock.patch.object(lp, "code", lambda h, c: cut(real(h, c))):
                got = run(copy.deepcopy(self.d0), self.cp)["checks"]["L1"]
            self.assertTrue(got.startswith("failed:l1_state:game_"), got)


class OtherNetwork(unittest.TestCase):
    def test_l1_state_outside_base_mainnet(self):
        d = load(FILES[0])
        d["payment_payload"]["accepted"]["network"] = "eip155:84532"
        r = run(d, cp_of(FILES[0]))
        self.assertEqual(r["checks"]["L1"], "not_evaluated:canonical_rules_only_for_base_mainnet")
        self.assertEqual(r["l1_state"], "not_shown")


class Grammar(unittest.TestCase):
    def test_closed_and_typed(self):
        d0, cp = load(FILES[0]), cp_of(FILES[0])
        st = ["canonical", "l1_state"]
        cases = [(st, "zz", 1), (st + ["accounts", 0], "zz", 1), (st + ["accounts", 0, "storageProof", 0], "zz", 1),
                 (st + ["accounts", 0, "storageProof", 0], "value", "0x1"), (st + ["headers", 0], "zz", "0x1")]
        for path, k, v in cases:
            d = copy.deepcopy(d0)
            o = d
            for x in path:
                o = o[x]
            o[k] = v
            self.assertEqual(run(d, cp)["verdict"], "refused", (path, k))
        for path, bad in ((st + ["headers"], []), (st + ["headers"], {}), (st + ["accounts"], []),
                          (st + ["accounts", 0, "address"], "0x12"), (st + ["accounts", 0, "accountProof"], []),
                          (st + ["accounts", 0, "accountProof"], ["0x"]), (st + ["accounts", 0, "accountProof"], ["zz"]),
                          (st + ["accounts", 0, "storageProof"], {}), (st + ["game_code"], "0x1"),
                          (st + ["game_code"], 5)):
            d = copy.deepcopy(d0)
            o = d
            for x in path[:-1]:
                o = o[x]
            o[path[-1]] = bad
            self.assertEqual(run(d, cp)["verdict"], "refused", (path, bad))

    def test_unread_proof_refused(self):
        d0, cp = load(FILES[0]), cp_of(FILES[0])
        d = copy.deepcopy(d0)
        g = acc_of(d, d["canonical"]["game"].lower())
        g["storageProof"].append({"key": "0x" + "00" * 31 + "01", "proof": g["storageProof"][0]["proof"]})
        self.assertEqual(run(d, cp)["verdict"], "refused")
        d = copy.deepcopy(d0)
        extra = copy.deepcopy(d["canonical"]["l1_state"]["accounts"][0])
        extra["address"] = "0x" + "12" * 20
        d["canonical"]["l1_state"]["accounts"].append(extra)
        self.assertEqual(run(d, cp)["verdict"], "refused")

    def test_duplicates(self):
        d0, cp = load(FILES[0]), cp_of(FILES[0])
        d = copy.deepcopy(d0)
        accs = d["canonical"]["l1_state"]["accounts"]
        accs.append(copy.deepcopy(accs[0]))
        self.assertEqual(run(d, cp)["verdict"], "refused")
        d = copy.deepcopy(d0)
        a = next(a for a in d["canonical"]["l1_state"]["accounts"] if a["storageProof"])
        a["storageProof"].append(copy.deepcopy(a["storageProof"][0]))
        self.assertEqual(run(d, cp)["verdict"], "refused")

    def test_cli_checkpoint(self):
        import subprocess
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        cmd = [sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), FILES[0]]
        r = subprocess.run(cmd + ["--l1-checkpoint", cp_of(FILES[0])], capture_output=True, text=True, env=env)
        self.assertEqual((r.returncode, json.loads(r.stdout)["l1_state"]), (0, "proven"), r.stderr)
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        self.assertEqual((r.returncode, json.loads(r.stdout)["l1_state"]), (0, "not_shown"))
        for bad in (["--l1-checkpoint"], ["--l1-checkpoint", "0x12"], ["--l1-checkpoint", "zz" * 33]):
            r = subprocess.run(cmd + bad, capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 64, bad)


if __name__ == "__main__":
    unittest.main()
