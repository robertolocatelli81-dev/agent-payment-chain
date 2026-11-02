"""Tests for SPEC section 30 (0.19, revised by 0.19.1): the report members evidence_level and facilitator_reply, the
option --require-level, the closed table of bundle versions and the closed list of qualified outcomes. The oracles are
real bundles of bundles/ (their verdict, level and reply, and the report members the level reads) and real bundles
with artifacts taken out, whose level the table of SPEC 30.2 names.

  python3 -m unittest tests.test_evidence_level
"""
import ast
import contextlib
import copy
import glob
import inspect
import io
import json
import os
import random
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*", "real_v03_canonical", "real_v04_l1state", "xlm_real_20261026", oracle=("xrpl_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402

LEVELS = ["none", "signature", "settlement_record", "inclusion_proof", "finality_proven"]
REPLIES = ("verified", "failed", "absent", "not_evaluated")
CANON = "bundles/real_v03_canonical/v001_b001_indirect_envelope_reconstructed.json"
V04 = "bundles/real_v04_l1state/v001_b001_indirect_l1state.json"
L1CP = "0x9140c56ce20a77dca7d648364bca6470be6a7f88297e652a20f7e46e4a14f3a6"   # tools/regress.py L1CP
XRP_BOUND = "bundles/xrp_real_20261026/0357d4c313ea.json"
DECLARED_NOTE = "evidence_level inclusion_proof: canonical final rests on L1 replies the bundle carries, declared"
OUTSIDE_NOTE = "is not in the closed list of SPEC 30.4"


def load(rel):
    with open(os.path.join(ROOT, rel), "rb") as fh:
        return av.strict_json(fh.read().decode("utf-8"))


def run(doc, cp=None, drafts=False):
    try:
        return av.verify_bundle(copy.deepcopy(doc), l1_checkpoint=cp, drafts=drafts)
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e)}


def cli(doc, *opts):
    """apc_verify.main on doc written to a file, as `python3 apc_verify.py [opts] FILE`: (exit, report)."""
    d = tempfile.mkdtemp(prefix="apc_el_")
    try:
        p = os.path.join(d, "b.json")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = av.main(["apc_verify.py"] + list(opts) + [p])
        out = buf.getvalue()
        try:
            return code, json.loads(out)
        except ValueError:
            return code, out
    finally:
        shutil.rmtree(d)


def without(doc, *members):
    return {k: v for k, v in doc.items() if k not in members}


def payer_only(doc, cp=None):
    """The bundle without the facilitator's reply: settlement out, and provenance too when its grammar names
    settlement (G6, SPEC 29: a provenance naming a member the bundle does not carry is refused)."""
    d = without(doc, "settlement")
    if run(d, cp)["verdict"] == "refused" and "provenance" in d:
        d = without(d, "provenance")
    return d


def xrp_checkpoint(doc):
    """The ledger hash the server gave for the bundle's ledger (oracle/xrpl_20261026), the reader's trusted hash."""
    with open(os.path.join(ROOT, "oracle", "xrpl_20261026", "mainnet_ledgers.json")) as fh:
        d = json.load(fh)
    hashes = {c["params"]["ledger_index"]: c["result"]["ledger_hash"] for c in d["calls"]
              if "binary" not in c["params"] and isinstance(c["params"]["ledger_index"], int)}
    return "0x" + hashes[doc["chain_tx"]["ledger_index"]].lower()


def v1_form(rel):
    from test_v1 import as_v1
    return as_v1(os.path.join(ROOT, rel))[0]


# one real bundle of each (version, verdict, level, reply) the corpus holds (tools/regress.py runs, apc_verify 0.19.1)
CORPUS = [
    ("bundles/real/real_001_envelope_reconstructed.json", None, "chain_verified", "settlement_record", "verified"),
    ("bundles/real_world_20261026/base_eurc/real_001_envelope_reconstructed.json", None, "chain_incomplete", "signature",
     "verified"),
    ("bundles/real_issue1062/issue1062_envelope_reconstructed.json", None, "chain_failed", "none", "failed"),
    ("bundles/real_v02/b001_direct_envelope_reconstructed.json", None, "chain_verified", "settlement_record", "verified"),
    ("bundles/real_v02_wallet/w_proxy_indirect.json", None, "chain_verified", "settlement_record", "verified"),
    ("bundles/real_v03/v001_b001_indirect_envelope_reconstructed.json", None, "chain_verified", "inclusion_proof",
     "verified"),
    ("bundles/real_v03_canonical/v014_b002_direct_envelope_reconstructed.json", None, "chain_verified", "inclusion_proof",
     "verified"),
    (CANON, None, "chain_verified", "inclusion_proof", "verified"),
    (V04, L1CP, "chain_verified", "finality_proven", "verified"),
    # SPEC 32.10: a Circle_SingleOwnerMSCA payment anchored by tools/anchor_msca.py (canonical + l1_state, the checkpoint of
    # bundles/real_msca_20261101/ANCHORED.json); the same bundle without the checkpoint is chain_incomplete, none
    ("bundles/real_msca_20261101/m001_anchored_0119601b_envelope_reconstructed.json",
     "0x6e4d8bb54a650a38a950ccc2530a30314149ca5f316bc9f811f7834c10ce5895", "chain_verified", "finality_proven", "verified"),
    ("bundles/real_msca_20261101/m001_anchored_0119601b_envelope_reconstructed.json", None, "chain_incomplete", "none", "verified"),
    ("bundles/real_msca_20261101/m001_proof_0119601b_envelope_reconstructed.json", None, "chain_incomplete", "none", "verified"),
    ("bundles/real_msca_20261101/m001_rpc_0119601b_envelope_reconstructed.json", None, "chain_incomplete", "none", "verified"),
    ("bundles/real_negatives_20261026/evm_base_53101310_d6fa42f2020b.json", None, "chain_failed", "none", "failed"),
    ("bundles/real_permit2/p001_envelope_reconstructed.json", None, "chain_verified", "settlement_record", "verified"),
    ("bundles/real_permit2/p029_envelope_reconstructed_proof.json", None, "chain_verified", "inclusion_proof", "verified"),
    ("bundles/real_permit2/p029_envelope_reconstructed.json", None, "chain_incomplete", "none", "verified"),
    ("bundles/real_svm/m001_mainnet_payment_20261024.json", None, "chain_verified", "settlement_record", "verified"),
    ("bundles/real_negatives_20261026/svm_cascade_48awzw8rfzms.json", None, "chain_failed", "none", "failed"),
    ("bundles/xlm_real_20261026/x017_envelope_reconstructed.json", None, "chain_verified", "settlement_record", "verified"),
    ("bundles/xlm_real_20261026/x001_envelope_reconstructed.json", None, "chain_incomplete", "none", "verified"),
    ("bundles/authcap_real_20261026/18ddc9b4ad8a.json", None, "chain_verified", "settlement_record", "verified"),
    (XRP_BOUND, None, "chain_verified", "settlement_record", "verified"),
    ("bundles/real_negatives_20261026/xrpl_011af6d52e5d.json", None, "chain_failed", "none", "failed"),
]


class Corpus(unittest.TestCase):
    def test_real_bundles_at_their_level(self):
        for rel, cp, verdict, level, reply in CORPUS:
            r = run(load(rel), cp)
            self.assertEqual((r["verdict"], r.get("evidence_level"), r.get("facilitator_reply")), (verdict, level, reply),
                             rel)
            self.assertNotIn("evidence_required", r, rel)
            self.assertFalse([n for n in r["notes"] if OUTSIDE_NOTE in n], rel)
            self.assertEqual(any(DECLARED_NOTE in n for n in r["notes"]), rel == CANON, rel)

    def test_what_the_level_reads(self):
        # the members the two upper levels read, on the real bundles that reach them or stop below them
        r = run(load(CANON))
        self.assertEqual((r["block_bound"], r["canonical"], r["l1_state"]), (True, "final", "not_shown"))
        r = run(load(V04), L1CP)
        self.assertEqual((r["block_bound"], r["canonical"], r["l1_state"]), (True, "final", "proven"))
        r = run(load("bundles/real_v03_canonical/v014_b002_direct_envelope_reconstructed.json"))
        self.assertEqual((r["block_bound"], r["canonical"], r["checks"]["O4"]), (True, "proposed", "pending:game_not_final"))
        r = run(load("bundles/real_permit2/p029_envelope_reconstructed.json"))
        self.assertTrue(r["checks"]["L2.sig"].startswith("not_evaluated:"))
        r = run(load("bundles/xlm_real_20261026/x001_envelope_reconstructed.json"))
        self.assertEqual(r["checks"]["G2"], "not_evaluated:contract_account_check_auth")
        r = run(load("bundles/real_world_20261026/base_eurc/real_001_envelope_reconstructed.json"))
        self.assertEqual((r["checks"]["T1"], r["checks"]["T2"]), ("verified", "verified"))
        self.assertTrue(r["checks"]["C1"].startswith("not_evaluated:"), r["checks"]["C1"])

    def test_every_version(self):
        seen = {load(rel)["bundle_version"] for rel, *_ in CORPUS}
        self.assertEqual(seen | {"apc-0.13"}, set(av.EVIDENCE_RULES))

    def test_v1_form(self):
        r = run(v1_form(CANON))
        self.assertEqual((r["verdict"], r["evidence_level"], r["facilitator_reply"], r["x402_version"]),
                         ("chain_verified", "inclusion_proof", "verified", 1))
        r = run(v1_form(V04), L1CP)
        self.assertEqual((r["verdict"], r["evidence_level"], r["l1_state"]), ("chain_verified", "finality_proven", "proven"))

    def test_xrpl_block_bound_with_the_trusted_hash(self):
        d = load(XRP_BOUND)
        cp = xrp_checkpoint(d)
        r = run(d, cp)
        self.assertEqual((r["verdict"], r["block_bound"], r["evidence_level"]), ("chain_verified", True, "inclusion_proof"))
        r = run(d, "0x" + "00" * 32)
        self.assertEqual((r["verdict"], r["evidence_level"], r["facilitator_reply"]), ("chain_failed", "none", "verified"))

    def test_erc7710_is_none(self):
        from test_permit2 import built_7710
        r = run(built_7710())
        self.assertEqual((r["verdict"], r["evidence_level"]), ("chain_incomplete", "none"))
        self.assertIn(r["facilitator_reply"], REPLIES)


class Finality(unittest.TestCase):
    """SPEC 30.1 (b): finality_proven needs canonical final AND l1_state proven; declared L1 replies stay below."""
    def test_declared_and_proven(self):
        d = load(V04)
        r = run(d, L1CP)
        self.assertEqual((r["evidence_level"], r["l1_state"]), ("finality_proven", "proven"))
        self.assertFalse([n for n in r["notes"] if DECLARED_NOTE in n])
        # the same bundle without the reader's L1 hash: the L1 replies are only declared
        r = run(d)
        self.assertEqual((r["verdict"], r["canonical"], r["l1_state"], r["evidence_level"]),
                         ("chain_verified", "final", "not_shown", "inclusion_proof"))
        self.assertEqual([n for n in r["notes"] if DECLARED_NOTE in n],
                         [DECLARED_NOTE + " (l1_state not_shown); finality_proven needs l1_state proven (SPEC 30.1)"])
        # the proofs taken out: the same
        r = run(dict(d, canonical=without(d["canonical"], "l1_state")), L1CP)
        self.assertEqual((r["canonical"], r["l1_state"], r["evidence_level"]), ("final", "not_shown", "inclusion_proof"))
        # a wrong L1 hash: l1_state failed is chain_failed (Amendment 0.4)
        r = run(d, "0x" + "11" * 32)
        self.assertEqual((r["l1_state"], r["verdict"], r["evidence_level"]), ("failed", "chain_failed", "none"))

    def test_members_read(self):
        rep = run(load(V04), L1CP)
        for l1, can, want in (("proven", "final", "finality_proven"), ("not_shown", "final", "inclusion_proof"),
                              ("failed", "final", "inclusion_proof"), ("proven", "proposed", "inclusion_proof"),
                              (None, "final", "inclusion_proof"), ("Proven", "final", "inclusion_proof"),
                              (True, "final", "inclusion_proof")):
            o = copy.deepcopy(rep)
            o["canonical"] = can
            if l1 is None:
                del o["l1_state"]
            else:
                o["l1_state"] = l1
            level, _r, notes = av.evidence("apc-0.3", o)
            self.assertEqual(level, want, (l1, can))
            self.assertEqual(any(DECLARED_NOTE in n for n in notes), can == "final" and l1 != "proven", (l1, can))
        # only the JSON true of block_bound lifts the level (1, "true" do not)
        for bb in (1, "true", None):
            o = dict(copy.deepcopy(rep), block_bound=bb)
            self.assertEqual(av.evidence_level("apc-0.3", o), "settlement_record", bb)
        # a version whose row has no finality level never reads l1_state (apc-0.16: inclusion_proof is its top)
        out = {"verdict": "chain_verified", "block_bound": True, "canonical": "final", "l1_state": "proven",
               "checks": {k: "verified" for k in ("R3", "R4", "R5", "R6", "R10", "T1", "C1", "C2", "C3", "C4")}}
        self.assertEqual(av.evidence("apc-0.16", out), ("inclusion_proof", "verified", []))


# each step takes out the artifact of the level above: (members removed)
LADDER = [("canonical",), ("inclusion",), ("chain_tx", "provenance")]   # provenance names chain_tx
STEPS = {   # name -> (bundle, l1 checkpoint or None, the levels after 0, 1, 2, ... removals of LADDER present in it)
    "apc-0.3": (lambda: load(V04), L1CP, ["finality_proven", "inclusion_proof", "settlement_record", "signature"]),
    "apc-0.3 declared": (lambda: load(CANON), None, ["inclusion_proof", "inclusion_proof", "settlement_record",
                                                     "signature"]),
    "apc-0.13": (lambda: v1_form(V04), L1CP, ["finality_proven", "inclusion_proof", "settlement_record", "signature"]),
    "apc-0.1": (lambda: load("bundles/real/real_001_envelope_reconstructed.json"), None,
                ["settlement_record", "signature"]),
    "apc-0.2": (lambda: load("bundles/real_v02/b001_direct_envelope_reconstructed.json"), None,
                ["settlement_record", "signature"]),
    # p029 _rpc: payer_code read by RPC (the _proof form proves it from inclusion, so without inclusion it is none)
    "apc-0.10": (lambda: load("bundles/real_permit2/p029_envelope_reconstructed_rpc.json"), None,
                 ["inclusion_proof", "settlement_record", "signature"]),
    "apc-0.5": (lambda: load("bundles/real_svm/m001_mainnet_payment_20261024.json"), None,
                ["settlement_record", "signature"]),
    "apc-0.12": (lambda: load("bundles/xlm_real_20261026/x017_envelope_reconstructed.json"), None,
                 ["settlement_record", "signature"]),
    "apc-0.15": (lambda: load("bundles/authcap_real_20261026/18ddc9b4ad8a.json"), None,
                 ["settlement_record", "signature"]),
    "apc-0.16": (lambda: load(XRP_BOUND), "xrp", ["inclusion_proof", "settlement_record", "signature"]),
}


class Ladder(unittest.TestCase):
    def test_each_artifact_taken_out(self):
        covered = set()
        for name, (make, cp, want) in STEPS.items():
            d = make()
            if cp == "xrp":
                cp = xrp_checkpoint(d)
            got = [run(d, cp)["evidence_level"]]
            for m in LADDER:
                if m[0] in d:
                    d = without(d, *m)
                    r = run(d, cp)
                    self.assertIn(r["verdict"], ("chain_verified", "chain_incomplete"), (name, m, r.get("reason")))
                    got.append(r["evidence_level"])
            self.assertEqual(got, want, name)
            covered.update(got)
            # without chain data, and without the reply: still signature, and chain_verified (SPEC 5)
            r = run(payer_only(d, cp), cp)
            self.assertEqual((r["verdict"], r["evidence_level"], r["facilitator_reply"]),
                             ("chain_verified", "signature", "absent"), name)
        self.assertEqual(covered, set(LEVELS) - {"none"})

    def test_signature_artifact_taken_out(self):
        # a smart-wallet payer: its ERC-1271 signature needs payer_wallet (SPEC 3); without it, L2.sig not evaluated
        d = load("bundles/real_v02_wallet/w_proxy_indirect.json")
        self.assertTrue(run(d)["checks"]["L2.sig"].startswith("verified (ERC-1271"))
        r = run(without(d, "payer_wallet"))
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"], r["evidence_level"]),
                         ("chain_incomplete", "not_evaluated:contract_wallet_needs_payer_wallet", "none"))
        # Permit2 from a payer with code: payer_code (SPEC 12.5); without it, the 66-byte signature is not evaluated
        d = load("bundles/real_permit2/p029_envelope_reconstructed_rpc.json")
        self.assertEqual(run(d)["evidence_level"], "inclusion_proof")
        self.assertEqual(run(without(d, "payer_code"))["evidence_level"], "none")

    def test_indirect_call_without_its_log(self):
        # SPEC 5: an indirect call stands on C3; without log_transfer the settlement_record level is not reached
        d = load("bundles/real_v03/v001_b001_indirect_envelope_reconstructed.json")
        self.assertEqual(run(d)["checks"]["C1"], "not_applicable:indirect_call")
        ct = {k: v for k, v in d["chain_tx"].items() if k not in ("log_transfer", "log_forward")}
        r = run(dict(without(d, "inclusion"), chain_tx=ct))
        self.assertEqual((r["verdict"], r["checks"]["C3"], r["evidence_level"], r["facilitator_reply"]),
                         ("chain_incomplete", "not_evaluated:indirect_call_needs_log_transfer", "signature", "verified"))


class PayerOnly(unittest.TestCase):
    """SPEC 30.1 (a): the bundle of the payer alone (chain_tx, no settlement) reaches settlement_record; the
    facilitator's reply is apart, and taking it out changes no level and no check outside T1/T2 except the comparison
    with settlement.transaction that 30.2 names."""
    def test_every_version_without_settlement(self):
        for name, (make, cp, want) in STEPS.items():
            d = make()
            if cp == "xrp":
                cp = xrp_checkpoint(d)
            full, r = run(d, cp), run(payer_only(d, cp), cp)
            self.assertEqual((r["verdict"], r["evidence_level"], r["facilitator_reply"]),
                             (full["verdict"], want[0], "absent"), name)
            fac = av.EVIDENCE_RULES[d["bundle_version"]][1]
            self.assertEqual({k: x for k, x in r["checks"].items() if k not in fac},
                             {k: x for k, x in full["checks"].items() if k not in fac}, name)
            self.assertEqual({r["checks"][k] for k in fac}, {av.NO_SETTLEMENT}, name)

    def test_require_settlement_record_without_the_reply(self):
        d = payer_only(load("bundles/real_v02/b001_direct_envelope_reconstructed.json"))
        code, r = cli(d, "--require-level", "settlement_record")
        self.assertEqual((code, r["verdict"], r["facilitator_reply"], r["evidence_required"]),
                         (0, "chain_verified", "absent", {"level": "settlement_record", "met": True}))

    def test_the_reply_alone_is_signature(self):
        # the reply without chain data does not lift the level (0.19.0 named this facilitator_claim)
        d = without(load("bundles/real_v02/b001_direct_envelope_reconstructed.json"), "chain_tx")
        r = run(d)
        self.assertEqual((r["verdict"], r["evidence_level"], r["facilitator_reply"]), ("chain_verified", "signature",
                                                                                      "verified"))

    def test_reply_values(self):
        rep = run(load(CANON))
        for t1, t2, want in (("verified", "verified", "verified"), (av.NO_SETTLEMENT, av.NO_SETTLEMENT, "absent"),
                             ("failed:settlement_not_successful", "verified", "failed"),
                             ("verified", "failed:network_mismatch", "failed"),
                             ("not_evaluated:settlement_pending", "verified", "not_evaluated"),
                             ("not_evaluated:settlement_pending_executed_on_chain", "verified", "not_evaluated"),
                             (av.NO_SETTLEMENT, "verified", "not_evaluated"), (None, "verified", "not_evaluated"),
                             ("verified (by facilitator)", "verified", "not_evaluated"),
                             ("verifiedX", "verified", "not_evaluated"), (1, "verified", "not_evaluated"),
                             ("failed", "verified", "not_evaluated"), ("not_evaluated:absent:x", av.NO_SETTLEMENT,
                                                                       "not_evaluated")):
            o = copy.deepcopy(rep)
            for k, x in (("T1", t1), ("T2", t2)):
                if x is None:
                    del o["checks"][k]
                else:
                    o["checks"][k] = x
            level, reply, notes = av.evidence("apc-0.3", o)
            self.assertEqual(reply, want, (t1, t2))
            self.assertEqual(level, "inclusion_proof", (t1, t2))        # the level never reads the reply
            self.assertEqual(any(OUTSIDE_NOTE in n for n in notes), t1 == "verified (by facilitator)", (t1, t2))
        # whatever the verdict
        o = copy.deepcopy(rep)
        o["verdict"] = "chain_failed"
        self.assertEqual(av.evidence("apc-0.3", o)[:2], ("none", "verified"))


class Qualified(unittest.TestCase):
    """SPEC 30.4 (ii): the closed list of qualified outcomes, against what the source writes."""
    # every `verified (` form in the source of apc_*.py -> (versions, check) of the list, or None (outside the ladder)
    WRITTEN = {
        "verified (by L2.sig)": (("apc-0.1", "apc-0.2", "apc-0.3", "apc-0.13"), "K3"),
        "verified (ERC-1271 %s)": (("apc-0.2", "apc-0.3", "apc-0.13"), "L2.sig"),
        "verified (ERC-1271 %s, passkey)": (("apc-0.2", "apc-0.3", "apc-0.13"), "L2.sig"),
        "verified (v1: value %s exceeds maxAmountRequired %d)": (("apc-0.13",), "K2"),
        "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)": (("apc-0.10",), "L2.sig"),
        "verified (ERC-1271 EIP7702StatelessDeleGator by EIP-7702)": (("apc-0.10",), "L2.sig"),
        "verified (token; chainId by L2.sig)": (("apc-0.10",), "K3"),
        "verified (v1: the requirement is read from payment_required)": None,      # K4, no column
        "verified (signer %s)": None,                                               # CF4, draft profile
    }

    @staticmethod
    def written():
        out = set()
        for p in sorted(glob.glob(os.path.join(ROOT, "apc_*.py"))):
            with open(p, "rb") as fh:
                tree = ast.parse(fh.read().decode("utf-8"), p)
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("verified ("):
                    out.add(n.value)
        return out

    @staticmethod
    def expand(form):
        names = sorted(set(av.WALLET_IMPL.values()))
        if form == "verified (ERC-1271 %s)":                 # section 3 wallets and the SPEC 32.5 list (apc_msca)
            import apc_msca
            return [form % n for n in names] + [form % w[3] for w in apc_msca.WALLETS.values()]
        if "ERC-1271 %s" in form:
            return [form % n for n in names]
        if "%d" in form:
            return [form % ("2000", 1000)]
        return [form]

    def test_the_list_is_what_the_source_writes(self):
        # the word "verified (" is only a prefix in _Counter and the K3/Permit2 tests on L2.sig, never a whole outcome
        self.assertEqual(self.written() - {"verified ("}, set(self.WRITTEN))
        self.assertEqual(set(av.WALLET_IMPL.values()), {"CoinbaseSmartWallet"})
        self.assertEqual(set(av.EVIDENCE_QUALIFIED), set(av.EVIDENCE_RULES))
        listed = {(v, k, f) for v, by in av.EVIDENCE_QUALIFIED.items() for k, fs in by.items() for f in fs}
        hit = set()
        for form, where in self.WRITTEN.items():
            for x in self.expand(form):
                for ver, (sig, fac, _c, _b, _f) in av.EVIDENCE_RULES.items():
                    for k in sig + fac + ("C1", "C2", "C3", "C4"):
                        c = av._Counter(ver, {k: x})
                        want = where is not None and ver in where[0] and k == where[1]
                        self.assertEqual(c(k), want, (form, ver, k))
                        self.assertEqual(c.outside, [] if want else [(k, x)], (form, ver, k))
                        hit |= {(ver, k, f) for f in av.EVIDENCE_QUALIFIED[ver].get(k, ()) if re.fullmatch(f, x)}
        self.assertEqual(hit, listed)           # every pattern of the list matches a form the source writes

    def test_matched_whole(self):
        for x in ("verified (by L2.sig)X", "verified (by L2.sig) ", " verified (by L2.sig)", "verified (by L2.sig))",
                  "Verified (by L2.sig)", "verified (by L2Xsig)", "verified (v1: value 2 exceeds maxAmountRequired 1x)",
                  "verified (v1: value -2 exceeds maxAmountRequired 1)",
                  "verified (ERC-1271 CoinbaseSmartWallet)\n", "verified (ERC-1271 OtherWallet)"):
            for ver in ("apc-0.1", "apc-0.3", "apc-0.13", "apc-0.10"):
                for k in ("K3", "K2", "L2.sig"):
                    self.assertFalse(av._Counter(ver, {k: x})(k), (x, ver, k))
        self.assertTrue(av._Counter("apc-0.13", {"K2": "verified (v1: value 2000 exceeds maxAmountRequired 1000)"})("K2"))

    def test_outside_the_list_does_not_count_and_is_noted(self):
        rep = run(load(CANON))
        for k, x, want in (("L2.sig", "verified (declared by the facilitator)", "none"),
                           ("K3", "verified (token; chainId by L2.sig)", "none"),         # the apc-0.10 form, in 0.3
                           ("C2", "verified (rpc)", "signature"),
                           ("C3", "verified (by L2.sig)", "signature")):
            o = copy.deepcopy(rep)
            o["checks"][k] = x
            level, reply, notes = av.evidence("apc-0.3", o)
            self.assertEqual(level, want, k)
            self.assertEqual([n for n in notes if OUTSIDE_NOTE in n],
                             ["evidence_level: %s outcome %s is not in the closed list of SPEC 30.4 for apc-0.3: it "
                              "does not count" % (k, x)], k)
        # through verify_bundle: the note is in the report
        d = load(CANON)
        real = av._verify_bundle

        def forged(doc, *a):
            out = real(doc, *a)
            out["checks"]["L2.sig"] = "verified (declared)"
            return out
        with mock.patch.object(av, "_verify_bundle", forged):
            r = run(d)
        self.assertEqual(r["evidence_level"], "none")
        self.assertTrue(any("L2.sig outcome verified (declared) is not in the closed list" in n for n in r["notes"]))


# SPEC 30.2 written again from the SPEC text (not read from apc_verify): version -> the checks of signature, the
# facilitator checks, settlement_record (for EVM: C2, and C1 or an indirect C1 with C3), whether inclusion_proof and
# finality_proven apply
SPEC_TABLE = {
    "apc-0.1": (("L2.sig", "K1", "K2", "K3"), ("T1", "T2"), "evm", False, False),
    "apc-0.2": (("L2.sig", "K1", "K2", "K3"), ("T1", "T2"), "evm", False, False),
    "apc-0.3": (("L2.sig", "K1", "K2", "K3"), ("T1", "T2"), "evm", True, True),
    "apc-0.13": (("L2.sig", "K1", "K2", "K3"), ("T1", "T2"), "evm", True, True),
    "apc-0.10": (("L2.sig", "K1", "K2", "K3", "K7"), ("T1", "T2"), "evm", True, True),
    "apc-0.5": (("S1", "S2"), ("T1",), ("C1", "C2", "C3"), False, False),
    "apc-0.12": (("G1", "G2"), ("T1",), ("C1", "C2", "C3"), False, False),
    "apc-0.15": (("AC5", "AC6", "AC7"), ("T1",), ("C1", "C2", "C3", "C4"), False, False),
    "apc-0.16": (("R3", "R4", "R5", "R6", "R10"), ("T1",), ("C1", "C2", "C3", "C4"), True, False),
}
OTHER = ("K4", "K5", "K6", "F1", "F2", "S3", "S4", "S5", "G3", "G4", "AC1", "AC2", "AC3", "AC4", "AC8", "R7", "R8", "R9",
         "A1", "A2", "M1", "B1", "B2", "B3", "B4", "O1", "O2", "O3", "O4", "L1", "I1", "I2", "E1")


class Table(unittest.TestCase):
    def full(self, ver):
        sig, fac, chain, bb, can = SPEC_TABLE[ver]
        ck = {k: "verified" for k in sig + fac + ("C1", "C2", "C3", "C4") + OTHER}
        return {"verdict": "chain_verified", "checks": ck, "block_bound": True, "canonical": "final",
                "l1_state": "proven"}, ("finality_proven" if can else "inclusion_proof" if bb else "settlement_record")

    def test_every_cell(self):
        self.assertEqual(set(SPEC_TABLE), set(av.EVIDENCE_RULES))
        for ver, (sig, fac, chain, bb, can) in SPEC_TABLE.items():
            out, top = self.full(ver)
            self.assertEqual(av.evidence(ver, out), (top, "verified", []), ver)
            for bad in ("not_evaluated:x", "not_evaluated:absent:x", "pending:x", "not_applicable:x", "verifiedx",
                        "failed:x", None):
                for k, want in [(k, "none") for k in sig] + [(k, top) for k in fac] + \
                        [(k, "signature" if (chain == "evm" and k == "C2") or (chain != "evm" and k in chain)
                          else top) for k in ("C1", "C2", "C3", "C4")] + [(k, top) for k in OTHER]:
                    o = copy.deepcopy(out)
                    if bad is None:
                        del o["checks"][k]
                    else:
                        o["checks"][k] = bad
                    if chain == "evm" and k == "C1":
                        want = "signature"
                    level, reply, _n = av.evidence(ver, o)
                    self.assertEqual(level, want, (ver, k, bad))
                    self.assertEqual(reply, ("failed" if bad == "failed:x" else "not_evaluated") if k in fac else
                                     "verified", (ver, k, bad))
            if chain == "evm":         # an indirect call stands on C3 (SPEC 5); a direct call does not need it
                o = copy.deepcopy(out)
                o["checks"]["C1"] = "not_applicable:indirect_call"
                self.assertEqual(av.evidence_level(ver, o), top, ver)
                o["checks"]["C3"] = "not_evaluated:indirect_call_needs_log_transfer"
                self.assertEqual(av.evidence_level(ver, o), "signature", ver)
                o["checks"]["C1"] = "verified"
                self.assertEqual(av.evidence_level(ver, o), top, ver)
            for member, value, want in (("block_bound", False, "settlement_record"),
                                        ("canonical", "proposed", "inclusion_proof" if bb else "settlement_record"),
                                        ("l1_state", "not_shown", "inclusion_proof" if bb else "settlement_record")):
                o = dict(out, **{member: value})
                applies = bb if member == "block_bound" else can
                self.assertEqual(av.evidence_level(ver, o), want if applies else top, (ver, member))
            # the facilitator checks out: no level changes (SPEC 30.1 a)
            o = copy.deepcopy(out)
            for k in fac:
                o["checks"][k] = av.NO_SETTLEMENT
            self.assertEqual(av.evidence(ver, o)[:2], (top, "absent"), ver)
            # a level holds only when the levels below hold: inclusion and finality without the chain checks
            o = copy.deepcopy(out)
            o["checks"]["C2"] = "not_evaluated:absent:no_chain_tx"
            self.assertEqual(av.evidence_level(ver, o), "signature", ver)
            o["verdict"] = "chain_incomplete"
            self.assertEqual(av.evidence_level(ver, o), "signature", ver)
            o["verdict"] = "chain_failed"
            self.assertEqual(av.evidence(ver, o)[:2], ("none", "verified"), ver)


class RequireLevel(unittest.TestCase):
    def test_signature_only(self):
        d = {"bundle_version": "apc-0.3", "payment_payload": load(CANON)["payment_payload"]}
        code, r = cli(d)
        self.assertEqual((code, r["verdict"], r["evidence_level"], r["facilitator_reply"]),
                         (0, "chain_verified", "signature", "absent"))
        self.assertNotIn("evidence_required", r)
        code, r = cli(d, "--require-level", "settlement_record")
        self.assertEqual((code, r["verdict"], r["evidence_required"]),
                         (2, "chain_incomplete", {"level": "settlement_record", "met": False}))
        self.assertIn("below the required settlement_record", r["notes"][-1])
        self.assertEqual(r["checks"], run(d)["checks"])
        code, r = cli(d, "--require-level", "signature")
        self.assertEqual((code, r["verdict"], r["evidence_required"]),
                         (0, "chain_verified", {"level": "signature", "met": True}))

    def test_every_level_against_every_requirement(self):
        d = load(V04)
        series = [d, without(d, "canonical"), without(d, "canonical", "inclusion"),
                  without(d, "canonical", "inclusion", "chain_tx"),
                  without(d, "canonical", "inclusion", "chain_tx", "settlement")]
        seen = set()
        for b in series + [load(CANON)]:
            base = run(b, L1CP)
            seen.add(base["evidence_level"])
            for req in LEVELS[1:]:
                rep = av.require_level(copy.deepcopy(base), req)
                met = LEVELS.index(base["evidence_level"]) >= LEVELS.index(req)
                self.assertEqual(rep["evidence_required"], {"level": req, "met": met})
                self.assertEqual(rep["verdict"], "chain_verified" if met else "chain_incomplete")
                self.assertEqual(rep["checks"], base["checks"])
                self.assertEqual((rep["evidence_level"], rep["facilitator_reply"]),
                                 (base["evidence_level"], base["facilitator_reply"]))
        self.assertEqual(seen, set(LEVELS) - {"none"})
        code, r = cli(load(CANON), "--require-level", "finality_proven")
        self.assertEqual((code, r["verdict"], r["evidence_required"]["met"]), (2, "chain_incomplete", False))
        code, r = cli(load(V04), "--l1-checkpoint", L1CP, "--require-level", "finality_proven")
        self.assertEqual((code, r["verdict"], r["evidence_required"]["met"]), (0, "chain_verified", True))

    def test_other_verdicts_untouched(self):
        code, r = cli(load("bundles/real_issue1062/issue1062_envelope_reconstructed.json"), "--require-level",
                      "finality_proven")
        self.assertEqual((code, r["verdict"], r["evidence_level"], r["facilitator_reply"], r["evidence_required"]),
                         (1, "chain_failed", "none", "failed", {"level": "finality_proven", "met": False}))
        code, r = cli(load("bundles/xlm_real_20261026/x001_envelope_reconstructed.json"), "--require-level", "signature")
        self.assertEqual((code, r["verdict"], r["evidence_required"]),
                         (2, "chain_incomplete", {"level": "signature", "met": False}))
        code, r = cli(load("bundles/real_v02_wallet/w_proxy_indirect.json"), "--require-level", "settlement_record")
        self.assertEqual((code, r["verdict"], r["evidence_required"]),
                         (0, "chain_verified", {"level": "settlement_record", "met": True}))
        code, r = cli(dict(load(CANON), surplus=1), "--require-level", "signature")
        self.assertEqual((code, r["verdict"]), (3, "refused"))
        for m in ("evidence_level", "evidence_required", "facilitator_reply"):
            self.assertNotIn(m, r)

    def test_usage(self):
        d = load(CANON)
        for opts in (["--require-level", "none"], ["--require-level", "Finality_proven"], ["--require-level", ""],
                     ["--require-level", "settlement-record"], ["--require-level", "inclusion_proof "],
                     # the names of 0.19.0 (SPEC 30.3)
                     ["--require-level", "facilitator_claim"], ["--require-level", "rpc_data"],
                     ["--require-level", "block_bound"], ["--require-level", "canonical"],
                     # facilitator_reply is not a level
                     ["--require-level", "facilitator_reply"], ["--require-level", "verified"]):
            code, _out = cli(d, *opts)
            self.assertEqual(code, 64, opts)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(av.main(["apc_verify.py", "--require-level"]), 64)
        code, r = cli(d, "--require-level", "inclusion_proof", "--drafts")
        self.assertEqual((code, r["evidence_required"]["met"]), (0, True))


class Drafts(unittest.TestCase):
    def test_drafts_do_not_change_the_members(self):
        for rel, cp, _v, level, reply in CORPUS:
            r = run(load(rel), cp, drafts=True)
            self.assertEqual((r["evidence_level"], r["facilitator_reply"]), (level, reply), rel)


class ClosedTable(unittest.TestCase):
    def test_rows_are_the_versions_read(self):
        src = inspect.getsource(av._verify_bundle)
        read = set(re.findall(r'ver == "(apc-[0-9.]+)"', src)) | set(av.EVM_VERSIONS)
        m = re.search(r'not in \(("apc-[^)]*)\)', src)
        read |= set(re.findall(r'"(apc-[0-9.]+)"', m.group(1)))
        self.assertEqual(read, set(av.EVIDENCE_RULES))
        self.assertEqual(len(read), 9)
        self.assertEqual(av.EVIDENCE_LEVELS, tuple(LEVELS))
        self.assertEqual(av.FACILITATOR_REPLY, REPLIES)

    def test_a_version_without_a_row_is_an_error(self):
        for table in (av.EVIDENCE_RULES, av.EVIDENCE_QUALIFIED):
            with mock.patch.dict(table):
                del table["apc-0.2"]
                code, r = cli(load("bundles/real_v02/b001_direct_envelope_reconstructed.json"))
            self.assertEqual((code, r["verdict"]), (3, "error"))
            self.assertNotIn("evidence_level", r)
            self.assertNotIn("facilitator_reply", r)


class Generative(unittest.TestCase):
    """Take out artifacts of real bundles in random order: a level never rises while the verdict stays out of
    chain_failed (from a chain_failed bundle, taking out the failing artifact can raise both, SPEC 30.2); taking out
    settlement never changes the level and makes the reply absent."""
    START = [V04, CANON, "bundles/real_v03/v018_w_proxy_indirect.json", "bundles/real_v02_wallet/w_proxy_indirect.json",
             "bundles/real/real_001_envelope_reconstructed.json", "bundles/real_permit2/p029_envelope_reconstructed_proof.json",
             "bundles/real_permit2/p029_envelope_reconstructed_rpc.json", "bundles/real_svm/m001_mainnet_payment_20261024.json",
             "bundles/xlm_real_20261026/x017_envelope_reconstructed.json", "bundles/authcap_real_20261026/18ddc9b4ad8a.json",
             "bundles/real_issue1062/issue1062_envelope_reconstructed.json", XRP_BOUND]
    ROUNDS = 3

    @staticmethod
    def artifacts(d):
        out = [("top", k) for k in d if k not in ("bundle_version", "payment_payload")]
        if isinstance(d.get("chain_tx"), dict):
            out += [("chain_tx", k) for k in d["chain_tx"] if k.startswith("log_")]
        if isinstance(d.get("canonical"), dict) and "l1_state" in d["canonical"]:
            out.append(("canonical", "l1_state"))
        return out

    def test_monotone(self):
        rnd = random.Random(20261028)
        steps = refused = settle = 0
        for rel in self.START:
            base = load(rel)
            cp = xrp_checkpoint(base) if rel == XRP_BOUND else L1CP if rel == V04 else None
            for _ in range(self.ROUNDS):
                d, prev = copy.deepcopy(base), run(base, cp)
                arts = self.artifacts(d)
                rnd.shuffle(arts)
                for where, k in arts:
                    nd = copy.deepcopy(d)
                    if where == "top":
                        nd.pop(k, None)
                    elif isinstance(nd.get(where), dict):
                        nd[where].pop(k, None)
                    else:
                        continue
                    r = run(nd, cp)
                    if r["verdict"] == "refused":
                        refused += 1
                        continue
                    steps += 1
                    self.assertIn(r["facilitator_reply"], REPLIES)
                    if "chain_failed" not in (r["verdict"], prev["verdict"]):
                        self.assertLessEqual(LEVELS.index(r["evidence_level"]), LEVELS.index(prev["evidence_level"]),
                                             (rel, where, k, prev["evidence_level"], r["evidence_level"]))
                        if (where, k) == ("top", "settlement"):
                            settle += 1
                            self.assertEqual(r["evidence_level"], prev["evidence_level"], (rel, k))
                    if r["verdict"] == "chain_failed":
                        self.assertEqual(r["evidence_level"], "none")
                    if "settlement" not in nd:
                        self.assertEqual(r["facilitator_reply"], "absent", (rel, where, k))
                    d, prev = nd, r
        type(self).measured = (steps, refused, settle)
        self.assertGreaterEqual(steps, 100)         # 113 with this seed, 40 refused, 30 settlement (measured 2026-10-27)
        self.assertGreater(refused, 0)          # the grammar's own dependencies (canonical needs inclusion, ...)
        self.assertGreater(settle, 5)

    def test_failed_bundle_without_its_failing_artifact(self):
        # issue 1062: the reply says failed, the chain says executed (T1 failed): none; without the reply, the chain's
        # own record binds the payer's authorization: settlement_record
        d = load("bundles/real_issue1062/issue1062_envelope_reconstructed.json")
        self.assertEqual(run(d)["evidence_level"], "none")
        r = run(without(d, "settlement"))
        self.assertEqual((r["verdict"], r["evidence_level"], r["facilitator_reply"]),
                         ("chain_verified", "settlement_record", "absent"))


if __name__ == "__main__":
    unittest.main()
