"""Tests for SPEC 0.3: block inclusion (apc_block, B1-B4, E1), ERC-6492 recognition, K6 zero amount, and the set checks
of apc_batch (D1, D2). Positive cases are real Base blocks and payments (bundles/real_v03, oracle/blocks_v03); every
negative case is a named alteration of a real one.

  python3 -m unittest tests.test_apc03
"""
import copy
import glob
import gzip
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*", oracle=("blocks_v03",))   # the Canonical classes name the local_only set themselves   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_batch  # noqa: E402
import apc_block as ab  # noqa: E402
import apc_verify as av  # noqa: E402
import inclusion  # noqa: E402

REAL03 = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v03", "v*.json")))
BLOCKS = os.path.join(ROOT, "oracle", "blocks_v03")
CENTRAL = os.path.join(ROOT, "bundles", "real_v03", "v016_b007_indirect_envelope_reconstructed.json")


def load(p):
    with open(p, "rb") as fh:
        return av.strict_json(fh.read().decode("utf-8"))


def run(doc):
    try:
        return av.verify_bundle(doc)
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e), "checks": {}}


# bundles/real*/*.json by bundle_version, a closed table: a bundle of a version not listed is an error of real_bundles,
# so a new version (or a new directory of another chain) is a decision of the tests, never a silent member of the glob
# (26/10: bundles/real_negatives_20261026 brought apc-0.5 and apc-0.16 bundles into the EVM tests' glob).
REAL_KINDS = {"apc-0.1": "evm", "apc-0.2": "evm", "apc-0.3": "evm", "apc-0.10": "evm", "apc-0.5": "solana",
              "apc-0.16": "xrpl"}


def real_bundles(kind):
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, "bundles", "real*", "*.json"))):
        if os.path.basename(p) in ("MANIFEST.json", "ANCHORED.json"):      # the manifests of a directory, not bundles
            continue
        with open(p, "rb") as fh:
            ver = json.loads(fh.read()).get("bundle_version")
        if ver not in REAL_KINDS:
            raise AssertionError("%s: bundle_version %r is not in REAL_KINDS (tests/test_apc03.py)" % (p, ver))
        if REAL_KINDS[ver] == kind:
            out.append(p)
    return out


def raw_block(number):
    out = []
    for name in ("block", "receipts"):
        with gzip.open(os.path.join(BLOCKS, "%d_%s.json.gz" % (number, name))) as fh:
            out.append(json.loads(fh.read())["result"])
    return out


def flip(h, pos):
    """Change one hex digit of a 0x string at position pos (counted after 0x)."""
    i = 2 + pos
    return h[:i] + ("1" if h[i] != "1" else "2") + h[i + 1:]


class RealInclusion(unittest.TestCase):
    def test_all_real_v03_bundles_are_block_bound(self):
        self.assertEqual(len(REAL03), 19)
        for p in REAL03:
            r = run(load(p))
            self.assertEqual((r["verdict"], r.get("block_bound")), ("chain_verified", True), p)
            for k in ("B1", "B2", "B3", "B4", "K6"):
                self.assertEqual(r["checks"][k], "verified", (p, k))

    def test_real_blocks_recompute_from_raw_replies(self):
        n = 0
        for p in REAL03:
            d = load(p)
            blk, rcs = raw_block(int(d["chain_tx"]["tx"]["blockNumber"], 16))
            r = ab.check_block({k: v for k, v in blk.items()}, rcs)
            self.assertEqual(r["verdict"], "block_bound", p)
            self.assertEqual(inclusion.build(blk, rcs, d["chain_tx"]["tx"]["hash"]), d["inclusion"], p)
            n += 1
        self.assertEqual(n, 19)

    def test_E1_lists_the_other_transfers_out_of_the_payer(self):
        r = run(load(CENTRAL))
        e1 = [n for n in r["notes"] if n.startswith("E1:")]
        self.assertEqual(len(e1), 1)
        self.assertIn("moves 5 other Transfer(s)", e1[0])
        self.assertEqual(r["verdict"], "chain_verified")      # E1 reports, it does not decide
        single = run(load(REAL03[1]))
        self.assertEqual([n for n in single["notes"] if n.startswith("E1:")], [])

    def test_E1_without_log_transfer_lists_the_payment_too(self):
        """Without log_transfer the log after AuthorizationUsed is not known to be the payment's: it is listed."""
        for p, n in ((CENTRAL, 6), (REAL03[1], 1)):
            d = load(p)
            value = int(d["payment_payload"]["payload"]["authorization"]["value"])
            del d["chain_tx"]["log_transfer"]
            e1 = [x for x in run(d)["notes"] if x.startswith("E1:")]
            self.assertEqual(len(e1), 1, p)
            self.assertIn("moves %d Transfer(s), the payment's own among them" % n, e1[0])
            self.assertIn("value %d" % value, e1[0])


class InclusionMutations(unittest.TestCase):
    """Each alteration of a real bundle's inclusion must fail the named check (or be refused)."""

    def setUp(self):
        self.docs = [load(p) for p in (REAL03[0], REAL03[1], CENTRAL, REAL03[16])]

    def each(self, mutate, check, prefix):
        for d0 in self.docs:
            d = copy.deepcopy(d0)
            mutate(d)
            r = run(d)
            got = r["checks"].get(check, r.get("reason", ""))
            self.assertTrue(got.startswith(prefix), (check, got))
            self.assertFalse(r.get("block_bound"), check)
            self.assertNotEqual(r["verdict"], "chain_verified", check)

    def test_header_field_changed(self):
        for f in ("parentHash", "stateRoot", "timestamp", "extraData", "requestsHash", "gasUsed"):
            def m(d, f=f):
                h = d["inclusion"]["block_header"]
                h[f] = hex(int(h[f], 16) + 1) if f in ("timestamp", "gasUsed") else flip(h[f], 3)
            self.each(m, "B1", "failed:header_hash_mismatch")

    def test_header_hash_claimed_for_another_block(self):
        def m(d):
            d["inclusion"]["block_header"]["hash"] = flip(d["inclusion"]["block_header"]["hash"], 5)
        self.each(m, "B1", "failed:header_hash_mismatch")

    def test_transaction_index_moved(self):
        def m(d):
            d["inclusion"]["transaction_index"] = hex(int(d["inclusion"]["transaction_index"], 16) + 1)
        self.each(m, "B1", "failed:transaction_index_not_tx")

    def test_tx_proof_node_byte(self):
        for i in (0, -1):
            def m(d, i=i):
                pr = d["inclusion"]["tx_proof"]
                pr[i] = flip(pr[i], len(pr[i]) - 3)
            self.each(m, "B2", "failed:tx_proof:")

    def test_receipt_proof_node_byte(self):
        for i in (0, -1):
            def m(d, i=i):
                pr = d["inclusion"]["receipt_proof"]
                pr[i] = flip(pr[i], len(pr[i]) - 3)
            self.each(m, "B3", "failed:receipt_proof:")

    def test_proofs_swapped(self):
        def m(d):
            inc = d["inclusion"]
            inc["tx_proof"], inc["receipt_proof"] = inc["receipt_proof"], inc["tx_proof"]
        for d0 in self.docs:
            d = copy.deepcopy(d0)
            m(d)
            r = run(d)
            self.assertFalse(r["checks"]["B2"] == "verified" and r["checks"]["B3"] == "verified")
            self.assertFalse(r["block_bound"])

    def test_proof_with_node_dropped_or_added(self):
        def drop(d):
            d["inclusion"]["receipt_proof"] = d["inclusion"]["receipt_proof"][:-1]
        def add(d):
            d["inclusion"]["receipt_proof"].append(d["inclusion"]["receipt_proof"][-1])
        self.each(drop, "B3", "failed:receipt_proof:")
        self.each(add, "B3", "failed:receipt_proof:")

    def test_inclusion_of_another_payment(self):
        other = load(REAL03[5])["inclusion"]
        def m(d):
            d["inclusion"] = copy.deepcopy(other)
        self.each(m, "B1", "failed:")

    def test_log_moved_to_another_block(self):
        def m(d):
            d["chain_tx"]["log_authorization_used"]["blockHash"] = flip(d["chain_tx"]["log_authorization_used"]["blockHash"], 4)
        for d0 in self.docs:
            d = copy.deepcopy(d0)
            m(d)
            r = run(d)
            self.assertNotEqual(r["verdict"], "chain_verified")
            self.assertFalse(r["block_bound"])

    def test_receipt_logs_must_hold_the_bundle_logs(self):
        """A log the receipt does not hold: the bundle's AuthorizationUsed data changed (C2 does not read data)."""
        def m(d):
            d["chain_tx"]["log_authorization_used"]["data"] = "0x00"
        self.each(m, "B3", "failed:authorization_log_not_in_receipt")

    def test_unknown_members_refused(self):
        for where in ("inclusion", "header"):
            def m(d, where=where):
                (d["inclusion"] if where == "inclusion" else d["inclusion"]["block_header"])["extra"] = "0x"
            for d0 in self.docs:
                d = copy.deepcopy(d0)
                m(d)
                self.assertEqual(run(d)["verdict"], "refused", where)

    def test_inclusion_not_read_before_03(self):
        d = load(REAL03[0])
        d["bundle_version"] = "apc-0.2"
        self.assertEqual(run(d)["verdict"], "refused")

    def test_absent_inclusion_is_listed_not_bound(self):
        d = load(REAL03[0])
        del d["inclusion"]
        r = run(d)
        self.assertEqual(r["checks"]["B1"], "not_evaluated:absent:no_inclusion")
        self.assertIn("B1", r["absent"])
        self.assertFalse(r["block_bound"])

    def test_B4_window_against_the_block_time(self):
        d = load(REAL03[1])
        pp = av.parse_payload(d["payment_payload"])
        ts = int(d["inclusion"]["block_header"]["timestamp"], 16)
        for va, vb, want in ((ts - 1, ts + 1, "verified"), (ts, ts + 9, "failed"), (ts - 9, ts, "failed"),
                             (ts + 1, ts + 9, "failed")):
            au = dict(pp["auth"], validAfter=va, validBefore=vb)
            got = av.check_inclusion(d["inclusion"], d["chain_tx"], au)[0]["B4"]
            self.assertTrue(got.startswith(want), (va - ts, vb - ts, got))


class GenerativeInclusion(unittest.TestCase):
    """Random byte and shape changes in the inclusion member: never a crash, never block_bound."""

    def test_random_alterations(self):
        rnd = random.Random(20261022)
        base = load(REAL03[2])
        n = 0
        for _ in range(300):
            d = copy.deepcopy(base)
            inc = d["inclusion"]
            choice = rnd.randrange(6)
            if choice == 0:
                k = rnd.choice(("tx_proof", "receipt_proof"))
                j = rnd.randrange(len(inc[k]))
                inc[k][j] = flip(inc[k][j], rnd.randrange(len(inc[k][j]) - 2))
            elif choice == 1:
                f = rnd.choice(sorted(inc["block_header"]))
                v = inc["block_header"][f]
                inc["block_header"][f] = flip(v, rnd.randrange(len(v) - 2)) if len(v) > 3 else "0x1"
            elif choice == 2:
                k = rnd.choice(("tx_proof", "receipt_proof", "transaction_index", "block_header"))
                inc[k] = rnd.choice((None, 7, "", [], {}, ["0x"], ["zz"], "0x00", [inc["tx_proof"][0]] * 65))
            elif choice == 3:
                k = rnd.choice(("tx_proof", "receipt_proof"))
                j = rnd.randrange(len(inc[k]))
                inc[k][j] = inc[k][j][:rnd.randrange(2, len(inc[k][j]))]
                if len(inc[k][j]) % 2:
                    inc[k][j] += "0"
            elif choice == 4:
                del inc[rnd.choice(sorted(inc))]
            else:
                k = rnd.choice(("tx_proof", "receipt_proof"))
                rnd.shuffle(inc[k])
                if len(inc[k]) == 1:
                    inc[k] = inc[k] * 2
            if d == base:
                continue            # the draw changed nothing (e.g. a shuffle that kept the order): not a mutant
            n += 1
            r = run(d)
            self.assertFalse(r.get("block_bound"), (choice, r.get("checks")))
        self.assertGreater(n, 250)


class Erc6492AndZero(unittest.TestCase):
    def test_6492_suffix_is_recognized_first(self):
        """Constructed: a real 65-byte signature wrapped as ERC-6492 says (no real 6492 x402 payment is in our set)."""
        d = load(REAL03[1])
        pl = d["payment_payload"]["payload"]
        word = lambda n: "%064x" % n
        inner = pl["signature"][2:]
        enc = (word(0x60) + "00" * 12 + "ab" * 20 + word(0x80) + word(0xA0) + word(0) + word(len(inner) // 2) + inner
               + "00" * ((32 - len(inner) // 2 % 32) % 32))
        pl["signature"] = "0x" + enc + "6492" * 16
        r = run(d)
        self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:erc6492_counterfactual_signature")
        self.assertNotEqual(r["verdict"], "chain_verified")
        self.assertTrue(any("ERC-6492" in n for n in r["notes"]))

    def test_6492_magic_only_at_the_end(self):
        d = load(REAL03[1])
        pl = d["payment_payload"]["payload"]
        pl["signature"] = "0x" + "6492" * 16 + pl["signature"][2:]
        self.assertNotEqual(run(d)["checks"].get("L2.sig"), "not_evaluated:erc6492_counterfactual_signature")

    def test_zero_amount(self):
        d = load(REAL03[1])
        d["payment_payload"]["payload"]["authorization"]["value"] = "0"
        d["payment_payload"]["accepted"]["amount"] = "0"
        r = run(d)
        self.assertEqual(r["checks"]["K6"], "failed:zero_amount")
        self.assertEqual(r["verdict"], "chain_failed")


class SetChecks(unittest.TestCase):
    def docs(self):
        return [(os.path.basename(p), load(p)) for p in REAL03]

    def test_real_set_is_consistent(self):
        """Real fact found by D2: v015 (census window) and v018 (wallet set) are the same Base payment."""
        r = apc_batch.check_set(self.docs())
        self.assertEqual((r["verdict"], r["D1"], r["refused"]), ("set_consistent", "verified", []))
        self.assertEqual(r["authorizations"], 18)
        self.assertEqual([x["bundles"] for x in r["D2"]],
                         [["v015_b005_indirect_envelope_reconstructed.json", "v018_w_proxy_indirect.json"]])

    def test_same_payment_shown_for_two_resources(self):
        docs = self.docs()
        a = copy.deepcopy(docs[3][1])
        b = copy.deepcopy(docs[3][1])
        for doc, url in ((a, "https://api.example/one"), (b, "https://api.example/two")):
            doc["payment_payload"]["resource"] = {"url": url}
        r = apc_batch.check_set(docs[:3] + [("a", a), ("b", b)])
        self.assertEqual(r["verdict"], "set_failed")
        self.assertEqual(r["D1"][0]["bundles"], ["a", "b"])

    def test_same_payment_two_acceptance_receipts(self):
        docs = self.docs()
        a, b = copy.deepcopy(docs[4][1]), copy.deepcopy(docs[4][1])
        a["acceptance"] = {"receipt": {"id": "r1"}}
        b["acceptance"] = {"receipt": {"id": "r2"}}
        r = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual((r["verdict"], r["refused"]), ("set_failed", []))
        self.assertEqual(r["D1"][0]["check"], "failed:same_payment_for_two_deliveries")

    def test_exact_duplicate_is_D2_not_D1(self):
        docs = self.docs()
        r = apc_batch.check_set(docs + [("dup", copy.deepcopy(docs[0][1]))])
        self.assertEqual(r["verdict"], "set_consistent")
        self.assertEqual(sorted(len(x["bundles"]) for x in r["D2"]), [2, 2])

    def test_one_authorization_two_settlement_transactions(self):
        """SPEC D3: (from, nonce) executes once, so two transactions for it in one set cannot both be true"""
        a = copy.deepcopy(self.docs()[0][1])
        b = copy.deepcopy(a)
        for k in ("chain_tx", "inclusion", "canonical"):
            b.pop(k, None)
        b["settlement"]["transaction"] = "0x" + "ab" * 32
        self.assertEqual((run(a)["verdict"], run(b)["verdict"]), ("chain_verified", "chain_verified"))   # each alone
        r = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual((r["verdict"], r["D3"][0]["check"]), ("set_failed", "failed:same_authorization_two_settlements"))
        b["settlement"]["transaction"] = a["settlement"]["transaction"].upper().replace("0X", "0x")
        self.assertEqual(apc_batch.check_set([("a", a), ("b", b)])["verdict"], "set_consistent")

    def test_refused_bundle_is_listed(self):
        r = apc_batch.check_set([("x", {"bundle_version": "apc-0.3"})])
        self.assertEqual(len(r["refused"]), 1)


CANON = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v03_canonical", "v*.json")))
# measured 2026-10-23 05:05 CEST from the L1 replies the bundles carry (all at the L1 block named in each bundle):
# 14 games resolved and valid, 5 (the two most recent census windows) proper and respected but not yet final
CANON_EXPECTED = {"final": 14, "proposed": 5}


@real_corpus.unless("real_v03_canonical")
class Canonical(unittest.TestCase):
    """SPEC 0.3 O1-O4 on real Base payments whose block was linked to a Base dispute game on Ethereum."""

    def test_real_bundles_are_final_or_proposed(self):
        self.assertEqual(len(CANON), 19)
        seen = {}
        for p in CANON:
            r = run(load(p))
            self.assertEqual(r["verdict"], "chain_verified", p)
            self.assertIn(r["canonical"], ("final", "proposed"), (p, r["checks"]))
            for k in ("O1", "O2", "O3"):
                self.assertEqual(r["checks"][k], "verified", (p, k))
            seen[r["canonical"]] = seen.get(r["canonical"], 0) + 1
        self.assertEqual(seen, CANON_EXPECTED)

    def mutate(self, fn):
        d = load(CANON[0])
        fn(d)
        return run(d)

    def reply(self, d, i, value):
        d["canonical"]["l1_replies"][i]["result"] = value

    def test_each_header_changed_breaks_the_chain(self):
        n = len(load(CANON[0])["canonical"]["headers"])
        self.assertGreater(n, 0)
        for j in range(n):
            def m(d, j=j):
                d["canonical"]["headers"][j]["stateRoot"] = flip(d["canonical"]["headers"][j]["stateRoot"], 7)
            r = self.mutate(m)
            self.assertEqual(r["checks"]["O2"], "failed:header_hash_mismatch", j)
            self.assertEqual(r["canonical"], "failed")

    def test_header_dropped(self):
        for j in (0, -1):
            def m(d, j=j):
                del d["canonical"]["headers"][j]
            r = self.mutate(m)
            self.assertTrue(r["checks"]["O2"].startswith("failed:"), r["checks"]["O2"])

    def test_root_index_moved(self):
        r = self.mutate(lambda d: d["canonical"].__setitem__("root_index", d["canonical"]["root_index"] + 1))
        self.assertEqual(r["checks"]["O2"], "failed:first_header_not_the_root_block")

    def test_used_intermediate_root_changed(self):
        def m(d):
            c = d["canonical"]
            ed = c["l1_replies"][2]["result"]
            pos = 2 + 2 * (116 + 32 * c["root_index"]) + 10
            c["l1_replies"][2]["result"] = ed[:pos] + ("1" if ed[pos] != "1" else "2") + ed[pos + 1:]
        r = self.mutate(m)
        self.assertEqual(r["checks"]["O3"], "failed:output_root_not_the_game_root")

    def test_root_claim_not_last_root(self):
        r = self.mutate(lambda d: self.reply(d, 1, flip(d["canonical"]["l1_replies"][1]["result"], 9)))
        self.assertEqual(r["checks"]["O1"], "failed:last_intermediate_root_not_root_claim")

    def test_other_game_type(self):
        r = self.mutate(lambda d: self.reply(d, 0, "0x" + "%064x" % 1))
        self.assertEqual(r["checks"]["O1"], "failed:game_type_not_621")

    def test_game_states(self):
        w = lambda n: "0x" + "%064x" % n
        # the base bundle is final (isGameClaimValid 1): a case that turns a precondition off turns that reply off too,
        # since isGameClaimValid implies proper, respected and DEFENDER_WINS (AnchorStateRegistry.sol 307-329)
        cases = [({4: w(1), 7: w(0)}, "failed:game_challenger_wins", "failed"),
                 ({5: w(0), 7: w(0)}, "not_evaluated:game_not_proper_or_not_respected", "not_shown"),
                 ({6: w(0), 7: w(0)}, "not_evaluated:game_not_proper_or_not_respected", "not_shown"),
                 ({4: w(2), 7: w(0)}, "pending:game_not_final", "proposed"),
                 ({4: w(0), 7: w(0)}, "pending:game_not_final", "proposed"),
                 ({4: w(2), 5: w(1), 6: w(1), 7: w(1)}, "verified", "final")]
        for changes, o4, level in cases:
            def m(d, changes=changes):
                for i, v in changes.items():
                    self.reply(d, i, v)
            r = self.mutate(m)
            self.assertEqual((r["checks"]["O4"], r["canonical"]), (o4, level), changes)
            self.assertEqual(r["verdict"], {"failed": "chain_failed", "not_shown": "chain_incomplete"}.get(level, "chain_verified"))

    def test_reply_grammar_refused(self):
        w1 = "0x" + "%064x" % 1
        cases = [lambda d: d["canonical"]["l1_replies"][0]["params"][0].__setitem__("to", "0x" + "11" * 20),
                 lambda d: d["canonical"]["l1_replies"][7]["params"][0].__setitem__("data", d["canonical"]["l1_replies"][7]["params"][0]["data"][:-1] + "0"),
                 lambda d: d["canonical"]["l1_replies"][3]["params"].__setitem__(1, "0x1"),
                 lambda d: d["canonical"]["l1_replies"].pop(),
                 lambda d: d["canonical"]["l1_replies"].append(d["canonical"]["l1_replies"][0]),
                 lambda d: d["canonical"].__setitem__("extra", 1),
                 lambda d: d["canonical"]["l1_replies"][0].__setitem__("extra", 1),
                 lambda d: d["canonical"].__setitem__("l1_network", "eip155:8453"),
                 lambda d: self.reply(d, 4, "0x02"),
                 lambda d: self.reply(d, 5, "0x" + "%064x" % 2),
                 lambda d: self.reply(d, 2, "0x1234"),
                 lambda d: d["canonical"]["headers"].__setitem__(0, dict(d["canonical"]["headers"][0], foo="0x")),
                 lambda d: d["canonical"].__setitem__("root_index", "1"),
                 lambda d: d.pop("inclusion"),
                 lambda d: self.reply(d, 6, w1[:-1] + "3")]
        for i, fn in enumerate(cases):
            r = self.mutate(fn)
            self.assertEqual(r["verdict"], "refused", (i, r.get("checks")))

    def test_absent_canonical_is_listed(self):
        r = run(load(REAL03[0]))
        self.assertEqual(r["checks"]["O1"], "not_evaluated:absent:no_canonical")
        self.assertEqual(r["canonical"], "not_shown")
        self.assertEqual(r["verdict"], "chain_verified")

    def test_canonical_of_another_payment(self):
        other = load(CANON[-1])["canonical"]
        d = load(CANON[0])
        if other["game"] == d["canonical"]["game"] and other["root_index"] == d["canonical"]["root_index"]:
            self.skipTest("same root")
        d["canonical"] = other
        r = run(d)
        self.assertEqual(r["canonical"], "failed")



def forge_receipt(d, edit):
    """A consistent forgery: edit the bundle's receipt in the real block, rebuild the receipts trie, put the new root in
    the header, recompute the header hash and point the bundle's tx and logs at it. Only B3 can see it."""
    blk, rcs = raw_block(int(d["chain_tx"]["tx"]["blockNumber"], 16))
    idx = int(d["inclusion"]["transaction_index"], 16)
    edit(rcs[idx])
    keys = [ab.rlp(ab._int_bytes(i)) for i in range(len(rcs))]
    pairs = list(zip(keys, [ab.encode_receipt(r, i) for i, r in enumerate(rcs)]))
    hdr = d["inclusion"]["block_header"]
    hdr["receiptsRoot"] = "0x" + ab.trie_root(pairs).hex()
    hdr["hash"] = ab.header_hash(hdr)
    d["inclusion"]["receipt_proof"] = ["0x" + x.hex() for x in ab.trie_proof(pairs, keys[idx])]
    for k in ("tx", "log_authorization_used", "log_transfer"):
        d["chain_tx"][k]["blockHash"] = hdr["hash"]
    return d


class ConsistentForgeries(unittest.TestCase):
    """Alterations rebuilt so that every hash and root agrees: the named check is the one that must catch them."""

    def forged(self, edit):
        d = forge_receipt(load(REAL03[1]), edit)
        r = run(d)
        for k in ("B1", "B2", "B4"):
            self.assertEqual(r["checks"][k], "verified", k)      # the forgery is consistent: only B3 is left
        self.assertFalse(r["block_bound"])
        return r["checks"]["B3"]

    def au_log(self, rc, d):
        lg = d["chain_tx"]["log_authorization_used"]
        return next(x for x in rc["logs"] if x["logIndex"] == lg["logIndex"])

    def test_control_unedited_forgery_is_bound(self):
        d = forge_receipt(load(REAL03[1]), lambda rc: None)
        self.assertEqual(run(d)["block_bound"], True)

    def test_failed_receipt(self):
        def edit(rc):
            rc["status"] = "0x0"
        self.assertEqual(self.forged(edit), "failed:receipt_status_not_success")

    def test_authorization_log_twice(self):
        d = load(REAL03[1])
        def edit(rc):
            rc["logs"].append(copy.deepcopy(self.au_log(rc, d)))
        self.assertEqual(self.forged(edit), "failed:authorization_log_not_in_receipt")

    def test_log_between_authorization_and_transfer(self):
        d = load(REAL03[1])
        def edit(rc):
            p = rc["logs"].index(self.au_log(rc, d))
            rc["logs"].insert(p + 1, {"address": "0x" + "00" * 20, "topics": [], "data": "0x"})
        self.assertEqual(self.forged(edit), "failed:transfer_log_not_next_in_receipt")


class SmallerRules(unittest.TestCase):
    def test_tx_in_another_block(self):
        d = load(REAL03[1])
        d["chain_tx"]["tx"]["blockHash"] = flip(d["chain_tx"]["tx"]["blockHash"], 4)
        r = run(d)
        self.assertEqual(r["checks"]["B1"], "failed:tx_block_not_header")
        self.assertFalse(r["block_bound"])

    def test_proven_tx_is_not_the_bundle_tx(self):
        d = load(REAL03[1])
        d["chain_tx"]["tx"]["hash"] = flip(d["chain_tx"]["tx"]["hash"], 4)
        self.assertEqual(av.check_inclusion(d["inclusion"], d["chain_tx"],
                                            av.parse_payload(d["payment_payload"])["auth"])[0]["B2"],
                         "failed:proven_tx_is_another_tx")

    def test_block_bound_needs_B4(self):
        d = load(REAL03[1])
        ts = int(d["inclusion"]["block_header"]["timestamp"], 16)
        d["payment_payload"]["payload"]["authorization"]["validBefore"] = str(ts)
        r = run(d)
        self.assertTrue(r["checks"]["B4"].startswith("failed:"), r["checks"]["B4"])
        self.assertEqual([r["checks"][k] for k in ("B1", "B2", "B3")], ["verified"] * 3)
        self.assertFalse(r["block_bound"])

    def test_header_fields_must_be_a_fork_prefix(self):
        d = load(REAL03[1])
        del d["inclusion"]["block_header"]["withdrawalsRoot"]
        r = run(d)
        self.assertEqual(r["verdict"], "refused")
        self.assertIn("header_fields_not_a_fork_prefix", r["reason"])

    def test_rlp_trailing_bytes(self):
        good = ab.rlp([b"a", b"bc"])
        self.assertEqual(ab.rlp_decode(good), [b"a", b"bc"])
        with self.assertRaises(ab.BlockRefusal):
            ab.rlp_decode(good + b"\x00")

    def test_extension_path_must_match_the_key(self):
        """Two keys sharing the nibbles 1,2,3 make an extension node at the root (Yellow Paper, appendix D)."""
        pairs = [(b"\x12\x34", b"left"), (b"\x12\x35", b"right")]
        root = ab.trie_root(pairs)
        proof = ab.trie_proof(pairs, b"\x12\x34")
        self.assertEqual(ab.verify_proof(root, b"\x12\x34", proof), b"left")
        for other in (b"\x56\x34", b"\x13\x34"):
            with self.assertRaises(ab.BlockRefusal):
                ab.verify_proof(root, other, proof)


@real_corpus.unless("real_v03_canonical")
class CanonicalRules(unittest.TestCase):
    """Canonical members moved between real bundles: the first O2 rule that sees it is named."""

    def by_name(self, prefix):
        return load(next(p for p in CANON if os.path.basename(p).startswith(prefix)))

    def test_call_case_is_ignored_and_its_members_closed(self):
        base = self.by_name("v001")
        want = run(base)
        for i in (0, 5):                             # a game call and a registry call
            d = copy.deepcopy(base)
            call = d["canonical"]["l1_replies"][i]["params"][0]
            call["to"], call["data"] = "0x" + call["to"][2:].upper(), call["data"].upper().replace("0X", "0x")
            r = run(d)
            self.assertEqual((r["verdict"], r.get("canonical")), (want["verdict"], want["canonical"]), i)
            for bad in ({"to": call["to"]}, dict(call, gas="0x1"), dict(call, to=1), {"to": call["to"], "date": call["data"]},
                        dict(call, to="0X" + call["to"][2:]), dict(call, data=call["data"] + " "),
                        dict(call, data="0X" + call["data"][2:])):
                d["canonical"]["l1_replies"][i]["params"][0] = bad
                self.assertEqual(run(d)["verdict"], "refused", (i, bad))

    def test_root_of_a_later_window(self):
        d = self.by_name("v001")                    # block 51646816, root index 8 of game 0x7a3a...
        d["canonical"] = self.by_name("v008")["canonical"]     # same game, root index 11
        r = run(d)
        self.assertEqual(r["checks"]["O2"], "failed:not_the_first_root_at_or_after_the_block")
        self.assertEqual(r["canonical"], "failed")

    def test_game_that_does_not_hold_the_block(self):
        d = self.by_name("v001")
        d["canonical"] = self.by_name("v009")["canonical"]     # game 0x5d99..., blocks 52035361..
        r = run(d)
        self.assertEqual(r["checks"]["O2"], "failed:block_not_in_game_range")

    def test_header_relinked_with_its_hash_recomputed(self):
        d = self.by_name("v001")
        top = d["canonical"]["headers"][0]
        top["parentHash"] = flip(top["parentHash"], 4)
        top["hash"] = ab.header_hash(top)
        r = run(d)
        self.assertEqual(r["checks"]["O2"], "failed:header_chain_broken")

    def test_bundle_header_hash_field_is_read_by_O2(self):
        d = self.by_name("v001")
        h = d["inclusion"]["block_header"]
        h["hash"] = flip(h["hash"], 4)
        r = run(d)
        self.assertEqual(r["checks"]["O2"], "failed:header_hash_mismatch")

    def test_final_needs_block_bound(self):
        d = self.by_name("v001")
        self.assertEqual(run(d)["canonical"], "final")
        d["chain_tx"]["tx"]["blockHash"] = flip(d["chain_tx"]["tx"]["blockHash"], 4)
        r = run(d)
        self.assertEqual([r["checks"][k] for k in ("O1", "O2", "O3", "O4")], ["verified"] * 4)
        self.assertNotIn(r["canonical"], ("final", "proposed"))

    def test_proposed_needs_O3(self):
        d = self.by_name("v014")
        self.assertEqual(run(d)["canonical"], "proposed")
        c = d["canonical"]
        ed = c["l1_replies"][2]["result"]
        pos = 2 + 2 * (116 + 32 * c["root_index"]) + 10
        c["l1_replies"][2]["result"] = ed[:pos] + ("1" if ed[pos] != "1" else "2") + ed[pos + 1:]
        r = run(d)
        self.assertEqual(r["checks"]["O3"], "failed:output_root_not_the_game_root")
        self.assertEqual(r["canonical"], "failed")


@real_corpus.unless("real_v03_canonical")
class ReviewGrammar(unittest.TestCase):
    """Inputs outside the 0.3 grammar are refused with a reason (exit 3), never a traceback (exit 1 = chain_failed)
    and never read as if they were canonical."""

    def base(self):
        return load(CANON[1])

    def refused(self, fn, what):
        d = self.base()
        fn(d)
        r = run(d)              # a traceback here is an error of the test, as it is a wrong exit code of the CLI
        self.assertEqual(r["verdict"], "refused", (what, r.get("checks")))
        return r["reason"]

    def test_quantities_are_json_rpc_quantities(self):
        H = lambda d: d["inclusion"]["block_header"]
        fw = lambda s: "".join(chr(ord(c) + 0xFEE0) if c.isdigit() else c for c in s)
        cases = {"negative number": lambda d: H(d).__setitem__("number", "0x-1"),
                 "plus sign": lambda d: H(d).__setitem__("gasUsed", "0x+" + H(d)["gasUsed"][2:]),
                 "underscore": lambda d: H(d).__setitem__("gasUsed", H(d)["gasUsed"][:4] + "_" + H(d)["gasUsed"][4:]),
                 "trailing space": lambda d: H(d).__setitem__("gasUsed", H(d)["gasUsed"] + " "),
                 "upper case": lambda d: H(d).__setitem__("gasUsed", "0x" + H(d)["gasUsed"][2:].upper()),
                 "negative index": lambda d: d["inclusion"].__setitem__("transaction_index", "0x-1"),
                 "fullwidth digits": lambda d: d["inclusion"].__setitem__(
                     "transaction_index", "0x" + fw(d["inclusion"]["transaction_index"][2:]) + "１"),
                 "canonical header negative": lambda d: d["canonical"]["headers"][0].__setitem__("number", "0x-1"),
                 "257 bits": lambda d: d["inclusion"]["block_header"].__setitem__("difficulty", "0x1" + "0" * 64),
                 "leading zero": lambda d: d["inclusion"]["block_header"].__setitem__(
                     "gasUsed", "0x0" + d["inclusion"]["block_header"]["gasUsed"][2:])}
        for what, fn in cases.items():
            self.assertIn("not_quantity", self.refused(fn, what), what)

    def test_hex_data_has_no_spaces(self):
        sp = lambda v: v[:10] + "  " + v[10:]
        cases = {"header stateRoot": lambda d: d["inclusion"]["block_header"].__setitem__(
                     "stateRoot", sp(d["inclusion"]["block_header"]["stateRoot"])),
                 "tx_proof node": lambda d: d["inclusion"]["tx_proof"].__setitem__(0, sp(d["inclusion"]["tx_proof"][0])),
                 "canonical header": lambda d: d["canonical"]["headers"][0].__setitem__(
                     "stateRoot", sp(d["canonical"]["headers"][0]["stateRoot"]))}
        for what, fn in cases.items():
            self.assertIn("not_hex_bytes", self.refused(fn, what), what)

    def test_tx_and_log_checked_when_C1_returns_early(self):
        def other_net(d, tx):
            d["chain_tx"]["network"] = "eip155:1"
            d["chain_tx"]["tx"] = tx(d["chain_tx"]["tx"])
        cases = {"tx not an object": lambda d: other_net(d, lambda t: 5),
                 "tx without hash": lambda d: other_net(d, lambda t: {k: v for k, v in t.items() if k != "hash"}),
                 "log not an object": lambda d: (d["chain_tx"]["tx"].__setitem__("input", "0x12345678"),
                                                 d["chain_tx"].__setitem__("log_authorization_used", "x"))}
        for what, fn in cases.items():
            self.assertIn("inclusion: chain_tx", self.refused(fn, what), what)

    def test_headers_are_closed_objects(self):
        cases = {"canonical header size": lambda d: d["canonical"]["headers"][0].__setitem__("size", {"x": [1]}),
                 "canonical header transactions": lambda d: d["canonical"]["headers"][0].__setitem__("transactions", 5),
                 "canonical header without hash": lambda d: d["canonical"]["headers"][0].pop("hash"),
                 "inclusion header hash not a string": lambda d: d["inclusion"]["block_header"].__setitem__("hash", 5),
                 "inclusion header without hash": lambda d: d["inclusion"]["block_header"].pop("hash")}
        for what, fn in cases.items():
            self.refused(fn, what)

    def test_canonical_values(self):
        w = lambda n: "0x" + "%064x" % n
        def reply(i, v):
            return lambda d: d["canonical"]["l1_replies"][i].__setitem__("result", v)
        cases = {"negative root_index": lambda d: d["canonical"].__setitem__("root_index", -1),
                 "status 3": reply(4, w(3)),
                 "status 3, claim not valid": lambda d: (reply(4, w(3))(d), reply(7, w(0))(d)),
                 "L1 block named by a tag": lambda d: [r["params"].__setitem__(1, "latest") for r in d["canonical"]["l1_replies"]],
                 "inclusion without chain_tx": lambda d: [d.pop(k, None) for k in ("chain_tx", "canonical")],
                 "status 7, claim valid": reply(4, w(7)),
                 "claim valid while in progress": reply(4, w(0)),
                 "claim valid while not proper": reply(5, w(0))}
        for what, fn in cases.items():
            self.refused(fn, what)

    def test_canonical_grammar_on_another_network(self):
        d = self.base()
        hdr = d["inclusion"]["block_header"]
        ok = av.check_canonical(copy.deepcopy(d["canonical"]), hdr, "eip155:84532")[0]
        self.assertEqual(set(ok.values()), {"not_evaluated:canonical_rules_only_for_base_mainnet"})
        for key, bad in (("root_index", "garbage"), ("l1_replies", 5), ("headers", "x"), ("game", 7), ("l1_network", None),
                         ("headers", [{"foo": 1}]), ("l1_network", "eip155:01")):
            can = copy.deepcopy(d["canonical"])
            can[key] = bad
            with self.assertRaises(av.Refusal, msg=key):
                av.check_canonical(can, hdr, "eip155:84532")

    def test_note_names_what_the_L1_replies_need(self):
        r = run(self.base())
        note = next(n for n in r["notes"] if n.startswith("canonical:"))
        self.assertIn("archive node", note)
        self.assertNotIn("any Ethereum node", note)

    def test_E1_with_receipt_items_of_the_wrong_shape(self):
        """A consistent forgery (own block, trie, root, header hash) whose receipt carries a Transfer-like log with a
        list where a topic or the data is: E1 skips it, no traceback."""
        for where in ("topic", "data"):
            d = load(REAL03[1])
            n = int(d["chain_tx"]["tx"]["blockNumber"], 16)
            _, rcs = raw_block(n)
            idx = int(d["inclusion"]["transaction_index"], 16)
            enc = [ab.encode_receipt(rc, i) for i, rc in enumerate(rcs)]
            t = enc[idx][:1] if enc[idx][0] < 0x80 else b""
            body = ab.rlp_decode(enc[idx][len(t):])
            asset = bytes.fromhex(d["chain_tx"]["log_authorization_used"]["address"][2:])
            payer = bytes(12) + bytes.fromhex(av.parse_payload(d["payment_payload"])["auth"]["from"][2:])
            tr = bytes.fromhex(av.TRANSFER_TOPIC[2:])
            body[3].append([asset, [tr, payer, [b"\x01"]], b"\x01"] if where == "topic"
                           else [asset, [tr, payer, bytes(32)], [b"\x01"]])
            enc[idx] = t + ab.rlp(body)
            keys = [ab.rlp(ab._int_bytes(i)) for i in range(len(rcs))]
            pairs = list(zip(keys, enc))
            hdr = d["inclusion"]["block_header"]
            hdr["receiptsRoot"] = "0x" + ab.trie_root(pairs).hex()
            hdr["hash"] = ab.header_hash(hdr)
            d["inclusion"]["receipt_proof"] = ["0x" + x.hex() for x in ab.trie_proof(pairs, keys[idx])]
            for k in ("tx", "log_authorization_used", "log_transfer"):
                if k in d["chain_tx"]:
                    d["chain_tx"][k]["blockHash"] = hdr["hash"]
            r = run(d)
            self.assertEqual(r["checks"]["B3"], "verified", where)
            self.assertFalse([x for x in r["notes"] if x.startswith("E1:")], where)



def forge_raw(d, edit):
    """Like forge_receipt, on the encoded receipts: edit(enc, idx) changes the list of encoded receipts in place."""
    _, rcs = raw_block(int(d["chain_tx"]["tx"]["blockNumber"], 16))
    idx = int(d["inclusion"]["transaction_index"], 16)
    enc = [ab.encode_receipt(rc, i) for i, rc in enumerate(rcs)]
    edit(enc, idx)
    keys = [ab.rlp(ab._int_bytes(i)) for i in range(len(rcs))]
    pairs = list(zip(keys, enc))
    hdr = d["inclusion"]["block_header"]
    hdr["receiptsRoot"] = "0x" + ab.trie_root(pairs).hex()
    hdr["hash"] = ab.header_hash(hdr)
    d["inclusion"]["receipt_proof"] = ["0x" + x.hex() for x in ab.trie_proof(pairs, keys[idx])]
    for k in ("tx", "log_authorization_used", "log_transfer"):
        if k in d["chain_tx"]:
            d["chain_tx"][k]["blockHash"] = hdr["hash"]
    return d


@real_corpus.unless("real_v03_canonical")
class ReviewCoverage(unittest.TestCase):
    """Rules of the 0.3 code that no other test reached (each one found alive as a mutant)."""

    def b3(self, edit):
        r = run(forge_raw(load(REAL03[1]), edit))
        return r["checks"]["B3"]

    @staticmethod
    def body(enc, idx):
        t = enc[idx][:1] if enc[idx][0] < 0x80 else b""
        return t, ab.rlp_decode(enc[idx][len(t):])

    def test_legacy_receipt_encoding_is_read(self):
        def edit(enc, idx):
            t, body = self.body(enc, idx)
            enc[idx] = ab.rlp(body)                 # the same receipt without its EIP-2718 type byte
        self.assertEqual(self.b3(edit), "verified")

    def test_empty_and_misshapen_receipts(self):
        def empty(enc, idx):
            enc[idx] = b""
        def short(enc, idx):
            t, body = self.body(enc, idx)
            enc[idx] = t + ab.rlp(body[:3])
        def logs_not_list(enc, idx):
            t, body = self.body(enc, idx)
            enc[idx] = t + ab.rlp(body[:3] + [b"\x01"])
        self.assertTrue(self.b3(empty).startswith("failed:"), "empty")
        self.assertEqual(self.b3(short), "failed:receipt_shape")
        self.assertEqual(self.b3(logs_not_list), "failed:receipt_shape")

    def test_authorization_log_last_in_receipt(self):
        d = load(REAL03[1])
        lg = d["chain_tx"]["log_authorization_used"]
        target = [bytes.fromhex(lg["address"][2:]), [bytes.fromhex(t[2:]) for t in lg["topics"]], bytes.fromhex(lg["data"][2:])]
        def edit(enc, idx):
            t, body = self.body(enc, idx)
            body[3] = [x for x in body[3] if x != target] + [target]
            enc[idx] = t + ab.rlp(body)
        self.assertEqual(self.b3(edit), "failed:transfer_log_not_next_in_receipt")

    def test_extradata_abi_layout(self):
        def ed(fn):
            def m(d):
                r = d["canonical"]["l1_replies"][2]
                b = bytearray(bytes.fromhex(r["result"][2:]))
                fn(b)
                r["result"] = "0x" + bytes(b).hex()
            return m
        def offset(b):
            b[31] = 0x40
        def padding(b):
            b[-1] = 1                       # the zero bytes after the 52 + 32 * 20 bytes of extraData
        cases = {"offset": ed(offset), "padding": ed(padding)}
        for what, fn in cases.items():
            d = load(CANON[1])
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused", what)

    def test_proof_shapes(self):
        """A value held in a branch (one key the prefix of another), and proofs longer than 64 nodes."""
        pairs = [(b"\x12", b"a" * 40), (b"\x12\x34", b"b" * 40)]
        root = ab.trie_root(pairs)
        proof = ab.trie_proof(pairs, b"\x12")
        self.assertEqual(ab.verify_proof(root, b"\x12", proof), b"a" * 40)
        with self.assertRaises(ab.BlockRefusal):
            ab.verify_proof(root, b"\x12", proof + [proof[-1]])
        with self.assertRaises(ab.BlockRefusal):
            ab.verify_proof(root, b"\x12", proof * 33)
        d = load(CANON[1])
        d["canonical"]["headers"] = d["canonical"]["headers"][:1] * 65
        self.assertEqual(run(d)["verdict"], "refused")
        d = load(CANON[1])
        d["inclusion"]["tx_proof"] = d["inclusion"]["tx_proof"][:1] * 65
        self.assertEqual(run(d)["verdict"], "refused")

    def test_proof_depth_and_empty_extension(self):
        """66 keys of 33 bytes that leave the target key one nibble apart each: its honest proof has more than 64
        nodes and is refused by the bound. An extension with an empty path (no canonical trie has one) is refused."""
        nib = lambda ns: bytes(ns[i] << 4 | ns[i + 1] for i in range(0, len(ns), 2))
        target = bytes(33)
        pairs = [(target, b"t" * 40)] + [(nib([0] * j + [1] + [0] * (65 - j)), b"v" * 40) for j in range(66)]
        root = ab.trie_root(pairs)
        proof = ab.trie_proof(pairs, target)
        self.assertGreater(len(proof), 64)
        with self.assertRaises(ab.BlockRefusal):
            ab.verify_proof(root, target, proof)
        leaf = ab.rlp([ab._hp(ab._nibbles(b"\x12"), True), b"x" * 40])
        ext = ab.rlp([b"\x00", ab.keccak256(leaf)])            # hex-prefix of an empty path, extension flag
        with self.assertRaises(ab.BlockRefusal):
            ab.verify_proof(ab.keccak256(ext), b"\x12", [ext, leaf])
        self.assertEqual(ab.verify_proof(ab.keccak256(leaf), b"\x12", [leaf]), b"x" * 40)   # the leaf alone: control

    def test_O3_needs_withdrawalsRoot(self):
        """The root's header without the Isthmus field (and the later ones, so the fork prefix holds), its hash
        recomputed: O1-O2 still pass, O3 cannot compute the output root and canonicality is not shown."""
        d = load(CANON[1])
        top = d["canonical"]["headers"][0]
        for k in ("withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"):
            top.pop(k, None)
        top["hash"] = ab.header_hash(top)
        r = run(d)
        self.assertEqual([r["checks"][k] for k in ("O1", "O2")], ["verified"] * 2)
        self.assertEqual(r["checks"]["O3"], "not_evaluated:header_without_withdrawalsRoot")
        self.assertEqual((r["canonical"], r["verdict"]), ("not_shown", "chain_incomplete"))

    def test_E1_lists_only_the_asset_out_of_the_payer(self):
        d = load(REAL03[1])
        asset = bytes.fromhex(d["chain_tx"]["log_authorization_used"]["address"][2:])
        payer = bytes(12) + bytes.fromhex(av.parse_payload(d["payment_payload"])["auth"]["from"][2:])
        tr, other = bytes.fromhex(av.TRANSFER_TOPIC[2:]), bytes(12) + b"\x77" * 20
        def edit(enc, idx):
            t, body = self.body(enc, idx)
            body[3] += [[b"\x66" * 20, [tr, payer, other], bytes(31) + b"\x05"],      # another token
                        [asset, [tr, other, payer], bytes(31) + b"\x06"]]            # into the payer, not out
            enc[idx] = t + ab.rlp(body)
        r = run(forge_raw(d, edit))
        self.assertEqual(r["checks"]["B3"], "verified")
        self.assertEqual([x for x in r["notes"] if x.startswith("E1:")], [])
        def edit2(enc, idx):
            t, body = self.body(enc, idx)
            body[3] += [[asset, [tr, payer, other], bytes(31) + b"\x07"]]
            enc[idx] = t + ab.rlp(body)
        r = run(forge_raw(load(REAL03[1]), edit2))
        self.assertEqual(len([x for x in r["notes"] if x.startswith("E1:")]), 1)        # positive control

    def test_range_must_divide_by_the_root_count(self):
        d = load(CANON[1])
        r = d["canonical"]["l1_replies"][3]
        r["result"] = "0x" + "%064x" % (int(r["result"], 16) + 1)
        self.assertEqual(run(d)["checks"]["O1"], "failed:game_range_not_divisible")


@real_corpus.unless("real_v03_canonical")
class Review031(unittest.TestCase):
    """Found on 2026-10-23 by the review of 0.3.1 (each test fails on the code before its fix)."""

    def test_unpaired_surrogate_refused_not_a_traceback(self):
        for p in (CENTRAL, REAL03[16], REAL03[17]):                 # an EOA payer and the two wallet payers
            with open(p, "rb") as fh:
                text = fh.read().decode("utf-8")
            name = json.loads(text)["payment_payload"]["accepted"]["extra"]["name"]
            bad = text.replace(json.dumps(name), json.dumps(name)[:-1] + '\\ud800"', 1)
            self.assertNotEqual(bad, text)
            with self.assertRaises(av.Refusal):
                av.strict_json(bad)
            d = json.loads(bad)                                     # a caller that parsed it otherwise
            self.assertEqual(run(d)["verdict"], "refused", p)
        with self.assertRaises(av.Refusal):
            av.strict_json('{"a": 1e400}')
        d = load(CENTRAL)
        d["payment_payload"]["accepted"]["extra"]["n"] = float("inf")              # parsed by another parser
        self.assertEqual(run(d)["verdict"], "refused")

    def test_k4_is_json_equality(self):
        d = load(CENTRAL)
        acc = d["payment_payload"]["accepted"]
        acc["extra"]["flag"] = True
        offered = copy.deepcopy(acc)
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "https://x.example/"}, "accepts": [offered]}
        self.assertEqual(run(d)["checks"]["K4"], "verified")                            # control
        offered["extra"]["flag"] = 1
        self.assertEqual(run(d)["checks"]["K4"], "failed:accepted_not_offered")       # true is not 1

    def test_k4_deep_value_no_traceback(self):
        d = load(CENTRAL)
        acc = d["payment_payload"]["accepted"]
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "https://x.example/"}, "accepts": [acc]}
        # SPEC 29.1 (0.18): 64 levels at most. Deeper was read until 0.16.1 (900 here); now refused, still no traceback
        text = json.dumps(d).replace('"version": "2"', '"version": "2", "deep": %s' % ("[" * 59 + "]" * 59))
        self.assertIn('"deep"', text)
        self.assertEqual(run(av.strict_json(text))["checks"]["K4"], "verified")
        text = json.dumps(d).replace('"version": "2"', '"version": "2", "deep": %s' % ("[" * 900 + "]" * 900))
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.1"):
            av.strict_json(text)

    def test_quantities_at_most_256_bits(self):
        d = load(CANON[0])
        self.assertEqual((run(d)["verdict"], run(d)["canonical"]), ("chain_verified", "final"))        # control
        for r in d["canonical"]["l1_replies"]:
            r["params"][1] = "0x1" + "0" * 64                          # 2^256, the same at all eight
        self.assertEqual(run(d)["verdict"], "refused")
        d = load(CENTRAL)
        d["chain_tx"]["log_transfer"]["logIndex"] = "0x" + "f" * 65
        self.assertEqual(run(d)["verdict"], "refused")

    def test_inclusion_note_follows_canonical(self):
        r = run(load(CANON[0]))
        note = next(n for n in r["notes"] if n.startswith("inclusion:"))
        self.assertEqual((r["canonical"], "shown only by O1-O4" in note, "not decided" in note), ("final", True, False))
        r = run(load(CENTRAL))                                       # inclusion without canonical
        note = next(n for n in r["notes"] if n.startswith("inclusion:"))
        self.assertIn("not decided by this verifier", note)

    def test_b3_reads_the_logs_as_hex_of_their_size(self):
        base = load(CENTRAL)
        self.assertEqual(run(base)["verdict"], "chain_verified")
        for log, member, v in (("log_authorization_used", "data", "Zx"), ("log_authorization_used", "data", "  "),
                               ("log_authorization_used", "data", "0x 0"), ("log_transfer", "data", "0x" + "00" * 31 + " 1")):
            d = copy.deepcopy(base)
            d["chain_tx"][log][member] = v
            self.assertEqual(run(d)["verdict"], "refused", (log, v))
        # also when C1 stops and C2/C3 do not read the logs: B3 still compares them byte by byte
        stop = copy.deepcopy(base)
        stop["chain_tx"]["network"] = "eip155:1"
        self.assertEqual(run(stop)["verdict"], "chain_failed")                         # control
        lg = stop["chain_tx"]["log_authorization_used"]
        for member, v in (("address", " " + lg["address"]), ("address", "0X" + lg["address"][2:]),
                          ("topics", [lg["topics"][0], " " + lg["topics"][1], lg["topics"][2]])):
            d = copy.deepcopy(stop)
            d["chain_tx"]["log_authorization_used"][member] = v
            self.assertEqual(run(d)["verdict"], "refused", (member, v))


class CliFiles(unittest.TestCase):
    """0.3.1: a FIFO blocked the verifier and /dev/zero ended in a MemoryError traceback with exit 1 (chain_failed)."""

    def cli(self, path):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        return subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), path], env=env,
                              capture_output=True, text=True, timeout=60)

    def test_not_a_regular_file(self):
        d = tempfile.mkdtemp()
        try:
            fifo = os.path.join(d, "fifo")
            os.mkfifo(fifo)
            for p in (fifo, "/dev/zero", d):
                r = self.cli(p)
                self.assertEqual((r.returncode, json.loads(r.stdout)["verdict"]), (3, "refused"), p)
                self.assertIn("not a regular file", json.loads(r.stdout)["reason"], p)
            self.assertEqual(self.cli(CENTRAL).returncode, 0)                    # control
        finally:
            shutil.rmtree(d)

    def test_size_cap(self):
        with open(CENTRAL, "rb") as fh:
            n = len(fh.read())
        keep = av.MAX_BUNDLE_BYTES
        try:
            av.MAX_BUNDLE_BYTES = n
            self.assertEqual(len(av.read_bundle_bytes(CENTRAL)), n)               # control: exactly at the cap
            av.MAX_BUNDLE_BYTES = n - 1
            with self.assertRaises(av.Refusal):
                av.read_bundle_bytes(CENTRAL)
        finally:
            av.MAX_BUNDLE_BYTES = keep


if __name__ == "__main__":
    unittest.main()
