"""SPEC Amendment 0.3.2: a settlement reply that says the payment failed, for an authorization chain_tx shows executed,
is reported as such (the payer was charged). Real case: x402 issue #1062 (bundles/real_issue1062); then every real
bundle of the corpus with its settlement reply turned into a failure."""
import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
from test_apc03 import load, real_bundles, run  # noqa: E402

ISSUE = os.path.join(ROOT, "bundles", "real_issue1062", "issue1062_envelope_reconstructed.json")
WITH_CHAIN = [p for p in real_bundles("evm") if "issue1062" not in p]    # EVM (Solana, XRPL: their own tests)
REASON = "failed:settlement_reported_failed_but_executed_on_chain"


def t1_note(r):
    return [n for n in r["notes"] if n.startswith("T1:")]


def failed_reply(d, tx=None):
    e = copy.deepcopy(d)
    e["settlement"] = {"success": False, "errorReason": "settle_exact_node_failure",
                       "network": d["settlement"]["network"], "transaction": tx or d["settlement"]["transaction"]}
    return e


class FailedButExecuted(unittest.TestCase):
    def test_issue_1062(self):
        r = run(load(ISSUE))
        self.assertEqual(r["checks"]["T1"], REASON)
        self.assertEqual((r["checks"]["C1"], r["checks"]["C2"], r["checks"]["L2.sig"]), ("verified",) * 3)
        self.assertEqual(r["verdict"], "chain_failed")
        self.assertEqual(len(t1_note(r)), 1)
        self.assertIn("the payer was charged", t1_note(r)[0])
        self.assertIn("it is the transaction the reply names", t1_note(r)[0])

    def test_corpus_failed_reply(self):
        n = 0
        for p in WITH_CHAIN:
            d = load(p)
            if "settlement" not in d or "chain_tx" not in d or run(d)["verdict"] != "chain_verified":
                continue
            n += 1
            r = run(failed_reply(d))
            self.assertEqual(r["checks"]["T1"], REASON, p)
            self.assertIn("it is the transaction the reply names", t1_note(r)[0], p)
            other = "0x" + ("ab" * 32)
            r = run(failed_reply(d, other))
            self.assertEqual(r["checks"]["T1"], REASON, p)
            self.assertIn("the reply names %s, another transaction executed it" % other, t1_note(r)[0], p)
        self.assertGreater(n, 100)

    def test_not_executed_stays_plain(self):
        """the chain does not show the authorization executed: nothing is claimed"""
        d = load(ISSUE)
        d["chain_tx"]["log_authorization_used"]["topics"][2] = "0x" + "00" * 32      # another nonce: C2 fails
        r = run(d)
        self.assertEqual(r["checks"]["T1"], "failed:settlement_not_successful")
        self.assertEqual(t1_note(r), [])
        d = load(ISSUE)
        del d["chain_tx"]
        r = run(d)
        self.assertEqual(r["checks"]["T1"], "failed:settlement_not_successful")
        self.assertEqual(t1_note(r), [])

    def test_indirect_needs_c3(self):
        """an indirect call stands on C2 and C3: with C3 failed nothing is claimed"""
        n = 0
        for p in WITH_CHAIN:
            d = load(p)
            if "settlement" not in d or run(d)["checks"].get("C1") != "not_applicable:indirect_call":
                continue
            if run(d)["checks"].get("C3") != "verified":
                continue
            e = failed_reply(d)
            lt = e["chain_tx"]["log_transfer"]
            lt["data"] = "0x" + "%064x" % (int(lt["data"], 16) + 1)                  # amount moved differs: C3 fails
            r = run(e)
            self.assertEqual(r["checks"]["C2"], "verified", p)
            self.assertTrue(r["checks"]["C3"].startswith("failed"), p)
            self.assertEqual(r["checks"]["T1"], "failed:settlement_not_successful", p)
            self.assertEqual(t1_note(r), [], p)
            r = run(failed_reply(d))                                                   # control: C3 verified
            self.assertEqual(r["checks"]["T1"], REASON, p)
            n += 1
        self.assertGreater(n, 10)

    def test_success_reply_unchanged(self):
        d = load(ISSUE)
        d["settlement"]["success"] = True
        del d["settlement"]["errorReason"]
        r = run(d)
        self.assertEqual(r["checks"]["T1"], "verified")
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertEqual(t1_note(r), [])


if __name__ == "__main__":
    unittest.main()
