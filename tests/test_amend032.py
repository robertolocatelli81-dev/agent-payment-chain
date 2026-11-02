"""SPEC Amendment 0.3.2, third and fourth parts, on real bundles: "0X" (not JSON-RPC hex) in payer_wallet params is
refused; K6 (zero value) applies to every bundle version."""
import copy
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v02_wallet", "real", "real_v02", "real_v03_canonical")   # the real corpus is not distributed (SPEC 33): skip with the reason
from test_apc03 import load, run  # noqa: E402

WALLETS = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v02_wallet", "w_*.json")))
FIRST = {v: sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", d, "*.json")) if "MANIFEST" not in p)[0]
         for v, d in (("apc-0.1", "real"), ("apc-0.2", "real_v02"), ("apc-0.3", "real_v03"))}


class UpperX(unittest.TestCase):
    def test_wallet_control(self):
        self.assertEqual(len(WALLETS), 2)
        for p in WALLETS:
            self.assertTrue(run(load(p))["checks"]["L2.sig"].startswith("verified"), p)

    def test_upper_x_refused(self):
        edits = [lambda w: w["code"]["params"].__setitem__(0, "0X" + w["code"]["params"][0][2:]),
                 lambda w: w["implementation"]["params"].__setitem__(1, "0X" + w["implementation"]["params"][1][2:]),
                 lambda w: w["owner"]["params"][0].__setitem__("to", "0X" + w["owner"]["params"][0]["to"][2:]),
                 lambda w: w["owner"]["params"][0].__setitem__("data", "0X" + w["owner"]["params"][0]["data"][2:])]
        for p in WALLETS:
            for i, e in enumerate(edits):
                d = load(p)
                e(d["payer_wallet"])
                self.assertEqual(run(d)["verdict"], "refused", (p, i))

    def test_member_not_a_string_refused(self):
        d = load(WALLETS[0])
        d["payer_wallet"]["owner"]["params"][0]["to"] = int(d["payer_wallet"]["owner"]["params"][0]["to"], 16)
        self.assertEqual(run(d)["verdict"], "refused")

    def test_mixed_case_digits_still_match(self):
        """case of the hex digits stays free (checksummed addresses)"""
        for p in WALLETS:
            d = load(p)
            d["payer_wallet"]["code"]["params"][0] = "0x" + d["payer_wallet"]["code"]["params"][0][2:].upper()
            self.assertTrue(run(d)["checks"]["L2.sig"].startswith("verified"), p)


class ZeroValueEveryVersion(unittest.TestCase):
    def test_k6_on_every_version(self):
        for ver, p in FIRST.items():
            d = load(p)
            self.assertEqual(d["bundle_version"], ver)
            self.assertEqual(run(d)["checks"].get("K6"), "verified", p)
            e = copy.deepcopy(d)
            e["payment_payload"]["payload"]["authorization"]["value"] = "0"
            e["payment_payload"]["accepted"]["amount"] = "0"
            r = run(e)
            self.assertEqual(r["checks"].get("K6"), "failed:zero_amount", p)
            self.assertNotIn(r["verdict"], ("chain_verified",), p)


if __name__ == "__main__":
    unittest.main()
