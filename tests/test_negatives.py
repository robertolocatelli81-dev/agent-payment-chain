"""Real negatives (oracle/negatives_20261026, bundles/real_negatives_20261026; tools/make_bundles_negatives.py): payments
the chain refused (EVM receipt status 0, Solana meta.err, XRPL tec*). None may be chain_verified: as built (the
reconstructed reply says success), with the reply saying failure, and (apc-0.3) without the inclusion proofs.
Positive control first: the same harness gives chain_verified on real executed payments of each family, so the
assertion `!= chain_verified` can fail."""
import copy
import glob
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_negatives_20261026", "real_svm", "real_v03", "real_world_20261026", "xrp_real_20261026", oracle=("negatives_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402

DATA = os.path.join(ROOT, "oracle", "negatives_20261026")
DIR = os.path.join(ROOT, "bundles", "real_negatives_20261026")
CENSUS = json.load(open(os.path.join(DATA, "NEGATIVES.json")))
POSITIVE = ["bundles/real_v03/v001_b001_indirect_envelope_reconstructed.json", "bundles/real_svm/s004_coinbase.json",
            "bundles/xrp_real_20261026/0357d4c313ea.json",
            "bundles/real_world_20261026/avax_usdc/real_001_envelope_reconstructed.json"]


def verdict(doc):
    try:
        return av.verify_bundle(copy.deepcopy(doc), None, None, None, False)["verdict"]
    except av.Unsupported:
        return "unsupported"
    except av.Refusal:
        return "refused"


def load(name):
    return av.strict_json(open(os.path.join(DIR, name), encoding="utf-8").read())


def rows():
    return [r for k in ("evm", "svm", "xrpl") for r in CENSUS[k]]


class Negatives(unittest.TestCase):
    def test_positive_control(self):
        for p in POSITIVE:
            self.assertEqual(verdict(av.strict_json(open(os.path.join(ROOT, p)).read())), "chain_verified", p)

    def test_listed_equals_directory(self):
        listed = sorted(r["bundle"] for r in rows() if r.get("bundle"))
        self.assertEqual(listed, sorted(os.path.basename(p) for p in glob.glob(os.path.join(DIR, "*.json"))))
        self.assertEqual(len(listed), len(set(listed)))

    def test_census_in_sha256sums(self):
        sums = {}
        for line in open(os.path.join(DATA, "SHA256SUMS")).read().splitlines():
            h, name = line.split("  ", 1)
            sums[name] = h
        for name, h in sums.items():
            self.assertEqual(hashlib.sha256(open(os.path.join(DATA, name), "rb").read()).hexdigest(), h, name)
        self.assertIn("NEGATIVES.json", sums)

    def test_none_verified_as_built(self):
        n = 0
        for r in rows():
            if r.get("bundle"):
                self.assertNotEqual(verdict(load(r["bundle"])), "chain_verified", r["bundle"])
                n += 1
        self.assertGreater(n, 0)

    def test_none_verified_with_failure_reply(self):
        for r in rows():
            if r.get("bundle"):
                d = load(r["bundle"])
                d["settlement"]["success"] = False
                self.assertNotEqual(verdict(d), "chain_verified", r["bundle"])

    def test_without_inclusion_refused(self):
        """a reverted EVM transaction without its proven receipt: the bundle cannot state the revert, and has no log"""
        n = 0
        for r in CENSUS["evm"]:
            if r.get("bundle"):
                d = load(r["bundle"])
                d.pop("inclusion", None)
                self.assertEqual(verdict(d), "refused", r["bundle"])
                d["bundle_version"] = "apc-0.1"
                self.assertEqual(verdict(d), "refused", r["bundle"])
                n += 1
        self.assertGreater(n, 0)

    def test_census_recomputed_from_the_replies(self):
        """every EVM and Solana row's reason, recomputed from the saved RPC replies, is the census row's"""
        from tools.make_bundles_negatives import evm_reason, svm_reason
        evm = {r["tx"]: r for r in CENSUS["evm"]}
        n = 0
        for f in sorted(glob.glob(os.path.join(DATA, "*_receipts_*.json")) + glob.glob(os.path.join(DATA, "*_index_*.json"))):
            for x in json.load(open(f))["direct"]:
                row = evm[x["tx"]["hash"]]
                self.assertEqual({k: row[k] for k in evm_reason(x)}, evm_reason(x), x["tx"]["hash"])
                n += 1
        self.assertEqual(n, len(evm))
        svm = json.load(open(os.path.join(DATA, "svm_facilitators_failed.json")))["failed_transactions"]
        self.assertEqual([svm_reason(t["result"]["meta"]) for t in svm],
                         [{"err": r["err"], "log": r["log"]} for r in CENSUS["svm"]])
        self.assertEqual(sum(a["failed"] for a in CENSUS["svm_addresses"]), len(svm))

    def test_reason_classifier(self):
        """a replay the RPC did not run is no reason; a revert is; a success at both blocks is named"""
        from tools.make_bundles_negatives import evm_reason
        x = {"replay_parent": {"error": {"code": -32000, "message": "request timed out"}},
             "replay_block": {"result": "0x"}, "receipt": {"gasUsed": "0x10"}, "tx": {"gas": "0x20"},
             "auth_used_logs": {"result": []}}
        self.assertEqual(evm_reason(x)["reason"], "RPC failure, no replay: request timed out")
        x["replay_parent"] = {"error": {"code": 3, "message": "execution reverted: FiatTokenV2: authorization is expired"}}
        self.assertEqual((evm_reason(x)["reason"], evm_reason(x)["replay"]), ("FiatTokenV2: authorization is expired", "parent"))
        x["replay_parent"] = {"result": "0x"}
        self.assertEqual((evm_reason(x)["reason"], evm_reason(x)["replay"]), ("replay succeeds at parent and block", "none"))
        x["receipt"]["gasUsed"] = "0x20"
        self.assertEqual(evm_reason(x)["reason"], "out of gas")
        x["replay_block"] = {"error": {"message": "execution reverted: ERC20: transfer amount exceeds balance"}}
        self.assertEqual((evm_reason(x)["reason"], evm_reason(x)["replay"]), ("ERC20: transfer amount exceeds balance", "block"))

    def test_evm_reason_from_the_chain(self):
        """every EVM row's reason is the revert message of an eth_call replay or names why there is none"""
        for r in CENSUS["evm"]:
            self.assertIn(r["replay"], ("parent", "block", "none"), r["tx"])
            if r["replay"] == "none":
                self.assertIn(r["reason"], ("out of gas", "replay succeeds at parent and block"))


if __name__ == "__main__":
    unittest.main()
