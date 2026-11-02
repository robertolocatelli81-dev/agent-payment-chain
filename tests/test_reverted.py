"""SPEC Amendment 0.3.3 part 1: a reverted settlement can be carried (apc-0.3 with inclusion, no logs) and is reported as
reverted; a success reply next to it fails T1. Real case: bundles/real_reverted (Base block 53020172, status 0)."""
import copy
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("real_reverted", "real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
from test_apc03 import load, run  # noqa: E402

REV = os.path.join(ROOT, "bundles", "real_reverted", "r001_status0_success_claim_reconstructed.json")
V03 = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v03", "*.json")) if "MANIFEST" not in p)


def notes(r, prefix):
    return [n for n in r["notes"] if n.startswith(prefix)]


class Reverted(unittest.TestCase):
    def test_real_reverted_success_claim(self):
        r = run(load(REV))
        self.assertEqual(r["verdict"], "chain_failed")
        self.assertIs(r["reverted"], True)
        c = r["checks"]
        self.assertEqual((c["L2.sig"], c["C1"], c["B1"], c["B2"], c["B4"]), ("verified",) * 5)
        self.assertEqual(c["B3"], "failed:receipt_status_not_success")
        self.assertEqual(c["T1"], "failed:settlement_reported_success_but_reverted")
        self.assertEqual(c["C2"], "not_evaluated:no_log_authorization_used")
        self.assertEqual(len(notes(r, "B3: the transaction is in the block and REVERTED")), 1)
        self.assertEqual(len(notes(r, "T1: the settlement reply says success")), 1)

    def test_real_reverted_failure_reply(self):
        d = load(REV)
        d["settlement"]["success"] = False
        r = run(d)
        self.assertIs(r["reverted"], True)
        self.assertEqual(r["checks"]["T1"], "failed:settlement_not_successful")
        self.assertEqual(notes(r, "T1:"), [])

    def test_reply_naming_another_transaction(self):
        """the reply names another hash: C2 fails on the transaction alone, the transaction is still reported reverted,
        but the success claim is not attributed to it"""
        d = load(REV)
        d["settlement"]["transaction"] = "0x" + "ab" * 32
        r = run(d)
        self.assertEqual(r["checks"]["C2"], "failed:tx_hash_not_settlement_transaction")
        self.assertIs(r["reverted"], True)
        self.assertEqual(r["checks"]["T1"], "verified")
        self.assertEqual(notes(r, "T1: the settlement reply says success"), [])
        self.assertEqual(r["verdict"], "chain_failed")

    def test_logs_absent_without_inclusion_refused(self):
        d = load(REV)
        del d["inclusion"]
        self.assertEqual(run(d)["verdict"], "refused")

    def test_transfer_log_without_authorization_log_refused(self):
        d = load(REV)
        d["chain_tx"]["log_transfer"] = load(V03[0])["chain_tx"].get("log_transfer") or {"address": "0x" + "00" * 20}
        self.assertEqual(run(d)["verdict"], "refused")

    def test_status1_without_log_refused(self):
        """a successful execution emits AuthorizationUsed: its absence next to a status-1 receipt is refused"""
        n = 0
        for p in V03:
            d = load(p)
            if "inclusion" not in d or run(d)["verdict"] != "chain_verified":
                continue
            e = copy.deepcopy(d)
            for k in ("log_authorization_used", "log_transfer", "log_forward"):
                e["chain_tx"].pop(k, None)
            self.assertEqual(run(e)["verdict"], "refused", p)
            self.assertIs(run(d)["reverted"], False, p)
            n += 1
        self.assertGreater(n, 10)

    def test_tampered_tx_not_reported_reverted(self):
        """reverted is said only when B1 and B2 bind the transaction to the block"""
        d = load(REV)
        d["chain_tx"]["tx"]["nonce"] = hex(int(d["chain_tx"]["tx"]["nonce"], 16) + 1)
        r = run(d)
        self.assertIs(r["reverted"], False)
        self.assertEqual(notes(r, "B3: the transaction is in the block and REVERTED"), [])
        self.assertEqual(r["checks"]["C2"], "failed:tx_hash_not_its_rlp")     # the first reason, on the tx-only path

    def test_each_binding_check_needed(self):
        """one edit per case leaves the recomputed hash intact and fails exactly one of B1, B2, C1: no 'reverted'"""
        def bump_number(e):
            tx = e["chain_tx"]["tx"]
            tx["blockNumber"] = hex(int(tx["blockNumber"], 16) + 1)

        def bad_tx_proof(e):
            n = e["inclusion"]["tx_proof"]
            n[-1] = n[-1][:-2] + ("01" if n[-1].endswith("00") else "00")

        def other_value(e):
            a = e["payment_payload"]["payload"]["authorization"]
            a["value"] = str(int(a["value"]) + 1)

        for edit, failing in ((bump_number, "B1"), (bad_tx_proof, "B2"), (other_value, "C1")):
            d = load(REV)
            edit(d)
            r = run(d)
            c = r["checks"]
            self.assertEqual(c["B3"], "failed:receipt_status_not_success", failing)
            self.assertEqual([k for k in ("B1", "B2", "C1") if c[k] != "verified"], [failing])
            self.assertIs(r["reverted"], False, failing)
            self.assertEqual(notes(r, "B3: the transaction is in the block and REVERTED"), [], failing)


if __name__ == "__main__":
    unittest.main()
