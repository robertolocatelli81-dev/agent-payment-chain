"""SPEC 32.10 (Amendment 0.21.1, 2026-11-01): a `verified (ERC-1271 …)` read from `payer_state` is admitted only when the
block whose state decides it is anchored — the predicate of finality_proven (SPEC 30.1: B1-B4, O1-O4 and L1 verified,
l1_state proven from the reader's --l1-checkpoint); otherwise `not_evaluated:payer_state_block_not_anchored`.

The anchored case cannot come from real data with a synthetic state (the output root of O3 covers the block hash, so a
block whose state tries are built here cannot sit under a real game), and no real Circle_SingleOwnerMSCA payment sits
within 64 blocks of a resolved game: the positive control builds the L1 side itself — a made-up L1 header (its hash is
the checkpoint THIS reader trusts), the game clone with its immutable args, the registry, factory, system and superchain
config accounts with their storage, all proven under that header (apc_block.trie_root / trie_proof). What that shows:
with the reader's checkpoint vouching for the L1 state, the rule ends in `verified`; with the same bundle and no
checkpoint, another checkpoint, a game in progress or a challenger win, it does not. What it also shows (a limit, SPEC
30.2): a reader who trusts a forger's checkpoint is shown whatever that L1 says.

Everything goes through apc_verify.verify_bundle; on a verifier without 32.10 each behaviour test fails with an
AssertionError (positive control of the file: measured on 19b0ecd with the review patch of 2026-11-01)."""
import copy
import glob
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import apc_block as ab  # noqa: E402
import apc_l1proof as lp  # noqa: E402
import apc_verify as av  # noqa: E402
from apc_verify import keccak256  # noqa: E402
import test_msca as tm  # noqa: E402
import test_review_msca as tr  # noqa: E402

MSCA = tm.MSCA
NE = "not_evaluated:payer_state_block_not_anchored"
V04 = os.path.join(ROOT, "bundles", "real_v04_l1state", "v001_b001_indirect_l1state.json")
L1CP = "0x9140c56ce20a77dca7d648364bca6470be6a7f88297e652a20f7e46e4a14f3a6"   # tools/regress.py L1CP
CANON = os.path.join(ROOT, "bundles", "real_v03_canonical", "v001_b001_indirect_envelope_reconstructed.json")
EMPTY_TRIE = keccak256(ab.rlp(b""))
# the helper under test, taken so that on a verifier without it the tests below fail with an AssertionError
anchored = getattr(av, "block_anchored", lambda res: None)


def hx(b):
    return "0x" + b.hex()


def fh(s):
    return bytes.fromhex(s[2:])


def run(d, cp=None):
    try:
        r = av.verify_bundle(copy.deepcopy(d), l1_checkpoint=cp)
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e), "checks": {}, "notes": []}
    return r


def l2(d, cp=None):
    r = run(d, cp)
    return r["checks"].get("L2.sig", r.get("verdict"))


def account_rlp(storage_root, code_hash, nonce=b"\x01"):
    return ab.rlp([nonce, b"", storage_root, code_hash])


def storage_trie(words):
    """{slot int: word int} -> (root, {slot: proof nodes}); every word is non-zero so every proof is a presence proof."""
    pairs = sorted((keccak256(s.to_bytes(32, "big")), ab.rlp(ab._int_bytes(w))) for s, w in words.items())
    root = ab.trie_root(pairs)
    return root, {s: [hx(x) for x in ab.trie_proof(pairs, keccak256(s.to_bytes(32, "big")))] for s in words}


def anchor(d, status=2, respected=1):
    """Adds to the apc-0.3 bundle d a `canonical` member whose game has our block as its last root (20 roots, root_index
    19, start = N - 20) and an `l1_state` proven under a made-up L1 header. Returns (bundle, the checkpoint = that L1
    header's hash). status: GameStatus (0 in progress, 1 challenger wins, 2 defender wins); respected: 0 or 1."""
    d = copy.deepcopy(d)
    hdr = d["inclusion"]["block_header"]
    n = int(hdr["number"], 16)
    start, seq = n - 20, n
    out_root = keccak256(bytes(32) + fh(hdr["stateRoot"]) + fh(hdr["withdrawalsRoot"]) + fh(hdr["hash"]))
    roots = [keccak256(b"intermediate root %d" % j) for j in range(19)] + [out_root]
    extra = seq.to_bytes(32, "big") + b"\x11" * 20 + b"".join(roots)          # l2SequenceNumber, parent, 20 roots
    args = b"\x22" * 20 + out_root + b"\x33" * 32 + extra                      # creator, rootClaim, l1Head, extraData
    argc = len(args) + 2
    A = {k: bytes([v]) * 20 for k, v in (("game", 0x0a), ("game_impl", 0x0b), ("asr_impl", 0x0c), ("dgf_impl", 0x0d),
                                            ("sysconf", 0x0e), ("sysconf_impl", 0x0f), ("supc", 0x10),
                                            ("supc_impl", 0x12), ("portal", 0x13))}
    A["asr"], A["dgf"] = lp.ASR, lp.DGF
    game_code = lp.CLONE_PRE + argc.to_bytes(2, "big") + lp.CLONE_MID + A["game_impl"] + lp.CLONE_SUF + args \
        + argc.to_bytes(2, "big")
    pin = lambda kind: bytes.fromhex(sorted(lp.PINS[kind])[0])
    proxy = bytes.fromhex(sorted(lp.PROXY_CODEHASH)[0])
    l1h = tm.load(V04)["canonical"]["l1_state"]["headers"][0]
    ts = int(l1h["timestamp"], 16)
    enc = (621).to_bytes(32, "big") + out_root + (96).to_bytes(32, "big") + len(extra).to_bytes(32, "big") + extra \
        + b"\0" * (-len(extra) % 32)
    I = lambda b: int.from_bytes(b, "big")
    words = {
        "game": {0: 1 | ((ts - 1) << 64) | (status << 128) | (respected << 144), 2: start},
        "asr": {lp.IMPL_SLOT: I(A["asr_impl"]), 0: I(A["sysconf"]) << 16, 1: I(lp.DGF), 6: 1,
                lp.mapping_slot(bytes(12) + A["game"], 5): 1 << 8},
        "dgf": {lp.IMPL_SLOT: I(A["dgf_impl"]), lp.mapping_slot(keccak256(enc), 103): I(A["game"])},
        "sysconf": {lp.IMPL_SLOT: I(A["sysconf_impl"]), 108: I(A["supc"]), lp.PORTAL_SLOT: I(A["portal"])},
        "supc": {lp.IMPL_SLOT: I(A["supc_impl"]), lp.mapping_slot(bytes(32), 0): 1,
                 lp.mapping_slot(bytes(12) + A["portal"], 0): 1},
    }
    codes = {"game": keccak256(game_code), "game_impl": pin("game_impl"), "asr": proxy, "asr_impl": pin("asr_impl"),
             "dgf": proxy, "dgf_impl": pin("dgf_impl"), "sysconf": proxy, "sysconf_impl": pin("sysconf_impl"),
             "supc": proxy, "supc_impl": pin("supc_impl")}
    accs, sproofs = {}, {}
    for k, ch in codes.items():
        if k in words:
            root, sproofs[k] = storage_trie(words[k])
        else:
            root, sproofs[k] = EMPTY_TRIE, {}
        accs[k] = account_rlp(root, ch)
    pairs = sorted((keccak256(A[k]), v) for k, v in accs.items())
    l1h["stateRoot"] = hx(ab.trie_root(pairs))
    l1h["hash"] = ab.header_hash(l1h)
    l1_state = {"headers": [l1h], "game_code": hx(game_code), "accounts": [
        {"address": hx(A[k]), "accountProof": [hx(x) for x in ab.trie_proof(pairs, keccak256(A[k]))],
         "storageProof": [{"key": "0x%064x" % s, "proof": p} for s, p in sproofs[k].items()]} for k in codes]}
    nodes = {A[k]: ([fh(x) for x in a["accountProof"]], {int(sp["key"], 16): [fh(x) for x in sp["proof"]]
                                                        for sp in a["storageProof"]})
             for k, a in zip(codes, l1_state["accounts"])}
    results = lp.replies(l1h, nodes, game_code, A["game"])
    game = hx(A["game"])
    calls = [(game, av._SEL(s)) for s in av.CANON_GAME_CALLS] \
        + [(av.BASE_REGISTRY, av._SEL(s) + "%064x" % int(game, 16)) for s in av.CANON_REGISTRY_CALLS]
    d["canonical"] = {"l1_network": "eip155:1", "game": game, "root_index": 19, "headers": [], "l1_state": l1_state,
                      "l1_replies": [{"method": "eth_call", "params": [{"to": to, "data": data}, l1h["number"]],
                                      "result": hx(r)} for (to, data), r in zip(calls, results)]}
    return d, l1h["hash"]


def synthetic(owner_code_parent=False, owner_code_block=False, owner=tm.OWNER):
    """A real proof bundle (bundles/real_msca_20261101, m001) whose two state tries are built here, as
    tests/test_msca.py ProofForm.synthetic, with the owner's code chosen end by end."""
    d = tm.load(tm.PROOF[0])
    pr, inc = d["payer_state"]["proof"], d["inclusion"]
    payer = fh(d["payment_payload"]["payload"]["authorization"]["from"])
    code = fh(pr["code"])
    word = (int(owner, 16) << 16) | 1
    roots = {}
    for end, oc in (("at_parent", owner_code_parent), ("at_block", owner_code_block)):
        spairs = sorted([(keccak256(tm.SLOT1967.to_bytes(32, "big")), ab.rlp(ab._int_bytes(int(tm.IMPL, 16)))),
                         (keccak256(tm.OWNER_SLOT.to_bytes(32, "big")), ab.rlp(ab._int_bytes(word)))])
        oaddr = fh(owner)
        pairs = sorted([(keccak256(payer), ab.rlp([b"\x01", b"", ab.trie_root(spairs), keccak256(code)])),
                        (keccak256(fh(tm.IMPL)), ab.rlp([b"\x01", b"", EMPTY_TRIE, bytes.fromhex(tm.IMPL_HASH)])),
                        (keccak256(oaddr), ab.rlp([b"", b"", EMPTY_TRIE, keccak256(b"\x60" if oc else b"")]))])
        roots[end] = ab.trie_root(pairs)
        P = lambda prs, k: [hx(x) for x in ab.trie_proof(prs, k)]
        pr[end] = {"payer": {"accountProof": P(pairs, keccak256(payer)),
                             "storageProof": [P(spairs, keccak256(tm.SLOT1967.to_bytes(32, "big"))),
                                              P(spairs, keccak256(tm.OWNER_SLOT.to_bytes(32, "big")))]},
                   "implementation": {"accountProof": P(pairs, keccak256(fh(tm.IMPL)))},
                   "owner": {"accountProof": P(pairs, keccak256(oaddr))}}
    pr["parent_header"]["stateRoot"] = hx(roots["at_parent"])
    pr["parent_header"]["hash"] = ab.header_hash(pr["parent_header"])
    inc["block_header"]["stateRoot"] = hx(roots["at_block"])
    inc["block_header"]["parentHash"] = pr["parent_header"]["hash"]
    inc["block_header"]["hash"] = ab.header_hash(inc["block_header"])
    for o in (d["chain_tx"]["tx"], d["chain_tx"]["log_authorization_used"], d["chain_tx"]["log_transfer"]):
        o["blockHash"] = inc["block_header"]["hash"]
    return d


class Anchored(unittest.TestCase):
    """The positive half of 32.10: the same real signature under the same synthetic state, anchored and not."""
    def test_anchored_block_verified(self):
        d, cp = anchor(synthetic())
        r = run(d, cp)
        self.assertEqual((r["verdict"], r["checks"].get("L2.sig"), r["checks"].get("K3"), r.get("payer_state"),
                          r.get("evidence_level"), r.get("canonical"), r.get("l1_state")),
                         ("chain_verified", MSCA, "verified (by L2.sig)", "proven_at_parent_and_block", "finality_proven",
                          "final", "proven"))
        self.assertIs(anchored(r["checks"]), True)

    def test_same_bundle_not_anchored(self):
        d, cp = anchor(synthetic())
        prog, cp_prog = anchor(synthetic(), status=0)                  # each L1 state has its own header, so its own checkpoint
        cases = {"no checkpoint": (d, None),
                 "another checkpoint": (d, "0x" + "ab" * 32),
                 "game in progress": (prog, cp_prog),
                 "challenger wins": anchor(synthetic(), status=1),
                 "game not respected": anchor(synthetic(), respected=0),
                 "no canonical": (synthetic(), cp)}
        for name, (b, c) in cases.items():
            r = run(b, c)
            self.assertEqual((r["checks"].get("L2.sig"), r["checks"].get("K3")), (NE, "not_evaluated:by_L2.sig"), name)
            self.assertIs(anchored(r["checks"]), False, name)
            self.assertNotEqual(r["evidence_level"], "finality_proven", name)
            self.assertTrue(any("SPEC 32.10" in x for x in r["notes"]), name)
        # the same checkpoint on the bundle whose game is in progress: O4 pending, canonical proposed, not final
        r = run(prog, cp_prog)
        self.assertEqual((r["checks"].get("O4"), r.get("canonical"), r.get("l1_state")),
                         ("pending:game_not_final", "proposed", "proven"))

    def test_anchoring_does_not_lift_a_failed_recovery(self):
        d, cp = anchor(synthetic())
        tm.set_sig(d, tm.hexflip(tm.sig(d), 5))
        self.assertTrue(l2(d, cp).startswith("failed:msca_signature_"), l2(d, cp))
        d, cp = anchor(synthetic(owner="0x" + "99" * 20))              # another owner in the anchored state
        self.assertTrue(l2(d, cp).startswith("failed:msca_signature_recovers_"))

    def test_reverted_in_an_anchored_block_stays_failed(self):
        """B3 failed is not anchored (the receipt is the chain's but says reverted): the recovery of section 3 stands."""
        d, cp = anchor(tr.forge(mode="reverted"))
        r = run(d, cp)
        self.assertTrue(r.get("reverted"))
        self.assertEqual((r["checks"].get("O4"), r["checks"].get("L1")), ("verified", "verified"))
        self.assertTrue(r["checks"].get("L2.sig", "").startswith("failed:recovers_"), r["checks"].get("L2.sig"))

    def test_limit_a_forger_with_his_own_checkpoint(self):
        """SPEC 30.2: finality_proven rests on the L1 block hash the reader trusts. A made-up block, state and L1 under a
        checkpoint the forger hands the reader gives verified: the rule moves the trust to the checkpoint, no further."""
        d, cp = anchor(tr.forge(new_to=tr.A, new_value=10 ** 12))
        r = run(d, cp)
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"], r["evidence_level"]), ("chain_verified", MSCA, "finality_proven"))
        self.assertEqual(l2(d, None), NE)                              # the same bundle, no checkpoint: not anchored
        self.assertEqual(l2(d, L1CP), NE)                              # the real Ethereum checkpoint of the corpus


class NotAnchored(unittest.TestCase):
    """The negative half of 32.10 on the real bundles and the made-up block of the review."""
    def test_real_bundles(self):
        for p in tm.RPC:
            r = run(tm.load(p))
            self.assertEqual((r.get("verdict"), r["checks"].get("L2.sig"), r["checks"].get("K3"), r.get("payer_state"),
                              r.get("evidence_level")),
                             ("chain_incomplete", NE, "not_evaluated:by_L2.sig", "declared_rpc", "none"), p)
        for p in tm.PROOF:
            r = run(tm.load(p))
            self.assertEqual((r.get("verdict"), r["checks"].get("L2.sig"), r.get("payer_state"), r.get("block_bound"),
                              r.get("evidence_level"), r.get("canonical")),
                             ("chain_incomplete", NE, "proven_at_parent_and_block", True, "none", "not_shown"), p)

    def test_made_up_block_of_the_review(self):
        """Independent review R3 (2026-11-01): headers, state tries and transaction invented, owner = the forger's key, payTo and
        value changed: chain_verified, inclusion_proof on 19b0ecd. Now not anchored."""
        r = run(tr.forge(new_to=tr.A, new_value=10 ** 12))
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"], r["evidence_level"], r["block_bound"]),
                         ("chain_incomplete", NE, "none", True))

    def test_declared_rpc_without_chain_tx_is_failed(self):
        """32.3 (review): a declared member does not lift a failed recovery without the conditions of 32.2."""
        d = tm.load(tm.RPC[0])
        for k in ("chain_tx", "settlement"):
            d.pop(k)
        self.assertTrue(l2(d).startswith("failed:recovers_"), l2(d))

    def test_empty_code_does_not_need_anchoring(self):
        """A `verified` of section 3 (the state says no code, the recovery gives `from`) is not read from the state."""
        d = tr.eoa_v02()
        au = d["payment_payload"]["payload"]["authorization"]
        d["payer_state"] = {"rpc": {"code": {"method": "eth_getCode", "params": [au["from"], d["chain_tx"]["tx"]["blockNumber"]],
                                             "result": "0x"}}}
        r = run(d)
        self.assertEqual((r["checks"]["L2.sig"], r["payer_state"], r["verdict"]), ("verified", "declared_rpc", "chain_verified"))


class Predicate(unittest.TestCase):
    """block_anchored is the predicate of finality_proven (SPEC 30.1), read on the corpus."""
    def test_matches_finality_proven(self):
        r = run(tm.load(V04), L1CP)
        self.assertEqual((r["evidence_level"], anchored(r["checks"])), ("finality_proven", True))
        r = run(tm.load(V04))
        self.assertEqual((r["checks"]["L1"], anchored(r["checks"])), ("not_evaluated:absent:no_l1_checkpoint", False))
        r = run(tm.load(CANON))                                   # declared L1 replies: canonical final, not proven
        self.assertEqual((r.get("canonical"), r.get("l1_state"), anchored(r["checks"])), ("final", "not_shown", False))
        for p in tm.PROOF + tm.RPC:
            self.assertIs(anchored(run(tm.load(p))["checks"]), False, p)

    def test_each_check_counts(self):
        res = {k: "verified" for k in ("B1", "B2", "B3", "B4", "O1", "O2", "O3", "O4", "L1")}
        self.assertIs(anchored(res), True)
        for k in list(res):
            for bad in ("failed:x", "pending:game_not_final", "not_evaluated:absent:no_l1_checkpoint", None):
                m = dict(res)
                if bad is None:
                    del m[k]
                else:
                    m[k] = bad
                self.assertIs(anchored(m), False, (k, bad))


class OwnerCodeAtEitherEnd(unittest.TestCase):
    """32.6 (0.21.1, N04 of the review): the owner HAS code when its codeHash is not keccak256("") at either end."""
    def test_code_at_one_end(self):
        other = "0x" + "88" * 20
        for ends in ((True, False), (False, True), (True, True)):
            # the state names another owner, with code: the real signature (C1 verified, executed) is not its; OZ 22-27
            # would ask that owner's ERC-1271
            self.assertEqual(l2(synthetic(*ends, owner=other)), "not_evaluated:msca_owner_has_code", ends)
            d, cp = anchor(synthetic(*ends))                               # the owner's own signature, anchored: OZ 22-27
            self.assertEqual(l2(d, cp), MSCA, ends)
        self.assertTrue(l2(synthetic(False, False, owner=other)).startswith("failed:msca_signature_recovers_"))
        # an altered signature is not the one the transaction carries (C1 failed, not executed): with the state not
        # anchored, nothing lifts the failed recovery of section 3 (32.3, review), whatever the owner's code says
        d = synthetic(True, True)
        tm.set_sig(d, tm.hexflip(tm.sig(d), 5))
        self.assertTrue(l2(d).startswith("failed:recovers_"), l2(d))


    def test_every_unusable_signature_with_owner_code_is_not_evaluated(self):
        # review 2 (2026-11-01): OZ 22-27 ask the owner's ERC-1271 whenever tryRecover does not give the owner: a length
        # other than 65, a high s or a bad v, an r with no curve point. Anchored, so that the clause of 32.3 does not
        # act and the outcome is the rule's own
        from lib.secp256k1 import recover_public_key
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        s0 = tm.sig(synthetic(True, True))
        twin = s0[:66] + "%064x" % (n - int(s0[66:130], 16)) + ("1c" if s0[130:] == "1b" else "1b")
        r = next(r for r in range(1, 200) if self._no_point(recover_public_key, r))
        nopoint = "0x%064x" % r + s0[66:]
        for sg, why in ((s0 + "00", "66 bytes"), (twin, "high s"), (s0[:130] + "1d", "v 29"), (nopoint, "r with no point")):
            d = synthetic(True, True)
            tm.set_sig(d, sg)
            d, cp = anchor(d)
            self.assertEqual(l2(d, cp), "not_evaluated:msca_owner_has_code", why)
            d = synthetic(False, False)                                    # control: the owner without code
            tm.set_sig(d, sg)
            d, cp = anchor(d)
            self.assertTrue(l2(d, cp).startswith("failed:msca_"), (why, l2(d, cp)))

    @staticmethod
    def _no_point(rec, r):
        try:
            rec(b"\x11" * 32, r, 1, 0)
            return False
        except ValueError:
            return True

ANCHORED = os.path.join(ROOT, "bundles", "real_msca_20261101", "ANCHORED.json")


def anchored_real():
    """(bundle, checkpoint, record) for each anchored real bundle of tools/anchor_msca.py (ANCHORED.json)."""
    man = tm.load(ANCHORED)
    return [(tm.load(os.path.join(os.path.dirname(ANCHORED), r["file"])), r["checkpoint"], r)
            for r in man["made"] if r["anchored"]]


class RealAnchored(unittest.TestCase):
    """32.10 on real data: the proof-form bundles anchored by tools/anchor_msca.py — canonical (the Base dispute game
    holding the block, its L1 replies at one L1 block, the L2 headers from the root's block) and l1_state (the L1 header,
    proofs and game code) — under the one checkpoint ANCHORED.json names."""
    def test_every_payment_anchored_and_verified(self):
        man = tm.load(ANCHORED)
        self.assertEqual(len(man["made"]), 28)
        self.assertEqual([r["from"] for r in man["made"] if not r["anchored"]], [])      # none left out: say why if so
        self.assertEqual(len(man["checkpoints"]), 1)
        for d, cp, r in anchored_real():
            res = run(d, cp)
            self.assertEqual((res["verdict"], res["checks"].get("L2.sig"), res["checks"].get("K3"), res.get("payer_state"),
                              res.get("evidence_level"), res.get("canonical"), res.get("l1_state"), res.get("block_bound")),
                             ("chain_verified", MSCA, "verified (by L2.sig)", "proven_at_parent_and_block", "finality_proven",
                              "final", "proven", True), r["file"])
            self.assertIs(anchored(res["checks"]), True)
            self.assertEqual((r["verdict"], r["L2.sig"], r["evidence_level"]), ("chain_verified", MSCA, "finality_proven"))
            self.assertLessEqual(len(d["canonical"]["headers"]), 64)

    def test_same_bundles_without_the_checkpoint(self):
        for d, cp, r in anchored_real():
            res = run(d)
            self.assertEqual((res["verdict"], res["checks"].get("L2.sig"), res.get("canonical"), res.get("l1_state"),
                              res.get("evidence_level")),
                             ("chain_incomplete", NE, "final", "not_shown", "none"), r["file"])
            self.assertEqual(l2(d, L1CP), NE, r["file"])                           # a real L1 header, not this one

    def test_altered_anchoring_is_not_verified(self):
        d, cp, r = anchored_real()[0]
        can = d["canonical"]

        def alt(fn):
            b = copy.deepcopy(d)
            fn(b["canonical"])
            res = run(b, cp)
            return res["checks"].get("L2.sig", res["verdict"]), res["checks"].get("L1"), res["checks"].get("O2"), res["checks"].get("O3")
        cases = {
            "a header of the L2 chain altered": lambda c: c["headers"].__setitem__(0, dict(c["headers"][0], stateRoot=tm.hexflip(c["headers"][0]["stateRoot"], 3))),
            "root_index + 1": lambda c: c.__setitem__("root_index", c["root_index"] + 1),
            "status reply says in progress": lambda c: c["l1_replies"][4].__setitem__("result", "0x" + "00" * 32),
            "claim-valid reply says not valid, the proofs say valid": lambda c: c["l1_replies"][7].__setitem__("result", "0x" + "00" * 32),
            "a node of an L1 account proof altered": lambda c: c["l1_state"]["accounts"][0]["accountProof"].__setitem__(0, tm.hexflip(c["l1_state"]["accounts"][0]["accountProof"][0], 7)),
            "the L1 header's stateRoot altered": lambda c: c["l1_state"]["headers"][0].__setitem__("stateRoot", tm.hexflip(c["l1_state"]["headers"][0]["stateRoot"], 3)),
            "replies at another L1 block": lambda c: [x["params"].__setitem__(1, hex(int(x["params"][1], 16) - 1)) for x in c["l1_replies"]],
        }
        for name, fn in cases.items():
            got = alt(fn)
            self.assertNotEqual(got[0], MSCA, (name, got))
            self.assertTrue(got[0].startswith("not_evaluated:") or got[0] in ("refused",), (name, got))
        # and the unaltered one, as the control of these alterations
        self.assertEqual(l2(d, cp), MSCA)
        # the checkpoint of this very L1 header is the only one that anchors: its hash altered in one digit does not
        self.assertEqual(l2(d, tm.hexflip(cp, 10)), NE)
        self.assertTrue(can["headers"] == [] or int(can["headers"][-1]["number"], 16) == int(d["inclusion"]["block_header"]["number"], 16) + 1)


class DeclaredBesideAnchored(unittest.TestCase):
    """SPEC 32.10 (review 2, 2026-11-01): anchored = the block is anchored AND the state is read from it (proof form). A
    declared rpc state put beside a real anchored inclusion gave `verified`, finality_proven on 2ffb35a; and with the
    reader's checkpoint a forged 65-byte signature beside a declared unknown code left `failed` (it stayed failed without
    the checkpoint: more trust gave a weaker outcome)."""
    def _pair(self):
        d, cp, r = anchored_real()[0]
        rpc = tm.load(os.path.join(os.path.dirname(ANCHORED), r["file"].replace("_anchored_", "_rpc_")))
        return d, cp, rpc["payer_state"]

    def test_rpc_state_beside_an_anchored_block_is_not_verified(self):
        d, cp, ps = self._pair()
        self.assertEqual(l2(d, cp), MSCA)                                   # control: the proof form, anchored
        b = copy.deepcopy(d)
        b["payer_state"] = copy.deepcopy(ps)
        res = run(b, cp)
        self.assertEqual((res["verdict"], res["checks"].get("L2.sig"), res.get("payer_state"), res.get("evidence_level")),
                         ("chain_incomplete", NE, "declared_rpc", "none"))
        self.assertIs(anchored(res["checks"]), True)                        # the block IS anchored; the state is not read from it

    def test_forged_signature_beside_declared_code_stays_failed_with_the_checkpoint(self):
        d, cp, ps = self._pair()
        b = copy.deepcopy(d)
        sig = b["payment_payload"]["payload"]["signature"]
        b["payment_payload"]["payload"]["signature"] = tm.hexflip(sig, 70)
        b["payer_state"] = {"rpc": {"code": dict(ps["rpc"]["code"], result="0x6001")}}
        for c in (None, cp):
            self.assertTrue(l2(b, c).startswith("failed:recovers_"), (c, l2(b, c)))


if __name__ == "__main__":
    unittest.main()
