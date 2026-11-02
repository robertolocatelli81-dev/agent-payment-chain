"""SPEC Amendment 0.3.3 part 2: payer equal to payee is reported (not decisive). Real case: v004 (0x2126…ae31 pays
itself 10000 via Multicall3)."""
import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*", "real_v03_canonical")   # the real corpus is not distributed (SPEC 33): skip with the reason
from test_apc03 import REAL_KINDS, load, real_bundles, run  # noqa: E402

SELF = [os.path.join(ROOT, "bundles", d, "v004_b103_indirect_envelope_reconstructed.json")
        for d in ("real_v03", "real_v03_canonical")]


class SelfPayment(unittest.TestCase):
    def test_real_self_payment_reported(self):
        for p in SELF:
            r = run(load(p))
            self.assertIs(r["payer_is_payee"], True, p)
            self.assertEqual(r["verdict"], "chain_verified", p)          # reported, not decisive
            self.assertEqual(sum("the payer is the payee" in n for n in r["notes"]), 1, p)

    def test_corpus_only_v004(self):
        hits = []
        # the bundles of bundles/real*/ (784 of the 1036 of the frozen corpus, SPEC 29.8), by the closed table of bundle
        # versions (SPEC 29.6), never the glob real*; the other 252 have no self-payment either (independent review 27/10, measured)
        for p in sorted(sum((real_bundles(k) for k in sorted(set(REAL_KINDS.values()))), [])):
            r = run(load(p))
            if r.get("payer_is_payee"):
                hits.append(os.path.basename(p))
            else:
                self.assertFalse(any("the payer is the payee" in n for n in r.get("notes", [])), p)
        # v004 in real_v03 and real_v03_canonical, and its SPEC 0.4 copy in real_v04_l1state: one real payment
        self.assertEqual(sorted(hits), ["v004_b103_indirect_envelope_reconstructed.json"] * 2
                         + ["v004_b103_indirect_l1state.json"])

    def test_case_of_address_ignored(self):
        """addresses compare as 20-byte values: mixed-case payTo of the same address is still the payer"""
        d = load(SELF[0])
        d["payment_payload"]["accepted"]["payTo"] = d["payment_payload"]["accepted"]["payTo"].upper().replace("0X", "0x")
        self.assertIs(run(d).get("payer_is_payee"), True)


if __name__ == "__main__":
    unittest.main()
