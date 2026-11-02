"""A log that the RPC reply itself marks "removed": true (Ethereum JSON-RPC: the log was dropped by a chain
reorganization) is not evidence of a payment. Found on 2026-10-23 by tools/sweep_grammar.py: the member was unread
and such a bundle was chain_verified."""
import copy
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*", "real_v03_canonical")   # the real corpus is not distributed (SPEC 33): skip with the reason
from test_apc03 import load, real_bundles, run  # noqa: E402

FILES = {"v01": sorted(glob.glob(os.path.join(ROOT, "bundles", "real", "real_*.json")))[0],
         "v02": sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02", "b*indirect*.json")))[0],
         "v03": sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v03_canonical", "v*indirect*.json")))[0]}


class RemovedLog(unittest.TestCase):
    def test_removed_true_fails(self):
        for tag, f in FILES.items():
            base = load(f)
            self.assertEqual(run(base)["verdict"], "chain_verified", f)       # control
            for log, check in (("log_authorization_used", "C2"), ("log_transfer", "C3"))[:1 if tag == "v01" else 2]:
                d = copy.deepcopy(base)
                d["chain_tx"][log]["removed"] = True
                r = run(d)
                self.assertEqual(r["verdict"], "chain_failed", (tag, log))
                self.assertEqual(r["checks"][check], "failed:%s_removed" % log, (tag, log))
                d["chain_tx"][log]["removed"] = False
                self.assertEqual(run(d)["verdict"], "chain_verified", (tag, log))

    def test_removed_not_a_bool_refused(self):
        d = load(FILES["v03"])
        d["chain_tx"]["log_authorization_used"]["removed"] = "false"
        self.assertEqual(run(d)["verdict"], "refused")

    def test_removed_not_a_bool_refused_when_C1_stops(self):
        """refused in every branch, also when C1 stops before C2 and C3 read the logs"""
        for tag, f in FILES.items():
            d = load(f)
            d["chain_tx"]["network"] = "eip155:1"                 # C1 stops: chain_tx_network_mismatch
            self.assertEqual(run(d)["verdict"], "chain_failed", tag)          # control
            for log in ("log_authorization_used", "log_transfer")[:1 if tag == "v01" else 2]:
                e = copy.deepcopy(d)
                e["chain_tx"][log]["removed"] = 0
                self.assertEqual(run(e)["verdict"], "refused", (tag, log))

    def test_forward_removed_fails_f1(self):
        f = next(p for p in real_bundles("evm")            # SPEC 29.6: the closed table, not the glob real_v0*
                 if os.path.basename(os.path.dirname(p)).startswith("real_v0") and "log_forward" in load(p).get("chain_tx", {}))
        d = load(f)
        d["chain_tx"]["log_forward"]["removed"] = True
        self.assertEqual(run(d)["checks"]["F1"], "failed:log_forward_removed")


if __name__ == "__main__":
    unittest.main()
