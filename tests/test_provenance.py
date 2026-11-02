"""SPEC 0.6 G6: the declared provenance member (apc-0.3 and apc-0.5): echoed in the report with a note, closed grammar,
no verdict changed."""
import copy
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm", "real_v02", "real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402

V03 = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v03", "*.json")) if "MANIFEST" not in p)[0]
SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")
V02 = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v02", "*.json")) if "MANIFEST" not in p)[0]
PV = {"chain_tx": {"source": "https://mainnet.base.org", "fetched": "2026-10-22T10:00:00Z"},
      "settlement": {"source": "facilitator reply", "fetched": "2026-10-22T09:59:58Z"}}


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(d)
    except av.Refusal:
        return {"verdict": "refused"}


class Provenance(unittest.TestCase):
    def test_echoed_not_decisive(self):
        for p in (V03, SVM):
            d0 = load(p)
            r0 = run(d0)
            self.assertIsNone(r0["provenance"], p)
            d = copy.deepcopy(d0)
            d["provenance"] = copy.deepcopy(PV)
            r = run(d)
            self.assertEqual(r["provenance"], PV, p)
            self.assertEqual((r["verdict"], r["checks"]), (r0["verdict"], r0["checks"]), p)
            self.assertEqual(len([n for n in r["notes"] if n.startswith("provenance (declared")]), 1, p)
            d["provenance"] = {"chain_tx": PV["chain_tx"]}
            self.assertEqual(run(d)["provenance"], {"chain_tx": PV["chain_tx"]}, p)

    def test_grammar(self):
        for p in (V03, SVM):
            for bad in ({}, [], {"zz": PV["chain_tx"]}, {"chain_tx": {"source": "x"}},
                        {"chain_tx": dict(PV["chain_tx"], zz=1)}, {"chain_tx": dict(PV["chain_tx"], source="")},
                        {"chain_tx": dict(PV["chain_tx"], source="x" * 257)},
                        {"chain_tx": dict(PV["chain_tx"], fetched="2026-10-22 10:00:00")},
                        {"chain_tx": dict(PV["chain_tx"], fetched=5)}):
                d = load(p)
                d["provenance"] = bad
                self.assertEqual(run(d)["verdict"], "refused", (p, bad))
            d = load(p)
            d["provenance"] = {"chain_tx": dict(PV["chain_tx"], source="x" * 256)}
            self.assertNotEqual(run(d)["verdict"], "refused")
        d = load(SVM)
        del d["settlement"]
        d["provenance"] = copy.deepcopy(PV)                     # names a member the bundle does not carry
        self.assertEqual(run(d)["verdict"], "refused")

    def test_only_in_apc_03_and_05(self):
        d = load(V02)
        d["provenance"] = {"chain_tx": PV["chain_tx"]}
        self.assertEqual(run(d)["verdict"], "refused")


if __name__ == "__main__":
    unittest.main()
