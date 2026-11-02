"""tools/coverage_census.py on real saved data (oracle/census_base_52942756_50.json and its Transfer logs; the
manifest of the 2026-10-22 run, oracle/coverage_20261022/MANIFEST_w52942756_50.json, is the reference).

Positive controls: switching one rule off must move a real authorization to another class (an EntryPoint route
entry, the log-guided extraction); the census must agree with the 2026-10-22 builder on the same transactions."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from tests import real_corpus  # noqa: E402
real_corpus.need(oracle=("coverage_20261022", "coverage_20261026", "census_base_52942756_50.json", "transfers_base_52942756_50.json", "census_base_52338016_100.json", "transfers_base_52338016_100.json",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import coverage_census as cc  # noqa: E402

EP6 = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
ANTSEED = "0x34a44542e76f9b4cff3a31902edf14abf2c3b3dd"
TX_EP6 = "0x99ecf762044507a9efcec0a010ce73205710e8d05ef453deab7536541f20d830"
TX_ANTSEED = "0xd78c6d03bf1e18f0e39875cc3b93348001c38dc68a24e2cd52937210a161d72b"
TX_DIRECT = "0xe64cd5592f8badf7d340a93fd4a376bfe4feb70f69db6e9f5249c78a417f78af"         # coinbase, direct
TX_GUIDED = "0x02f0818941463be89acbf649c94a54acf32f95bd5f015b094eb46d2e32ba6b23"         # log_guided, 1 log
TX_INNER = "0x0f820adb947eb2450b60247b440101bba18c8b7f38c95ff415c43173d6171049"          # indirect, calldata
ONLY = {TX_EP6, TX_ANTSEED, TX_DIRECT, TX_GUIDED, TX_INNER}
ENTRY = {"kind": "evm_eip3009", "network": "eip155:8453", "asset": "USDC", "label": "w52942756_50",
         "files": {"census": "oracle/census_base_52942756_50.json", "transfers": "oracle/transfers_base_52942756_50.json",
                   "wallets": ["oracle/coverage_20261022/payer_wallet_replies.json"]}}
CAMPAIGN = {"campaign": "test", "entries": [ENTRY]}


def recs(disable=()):
    out, _, _ = cc.classify_eip3009(ENTRY, cc.facilitators(), cc.load_routes(), disable, ONLY)
    return {r["tx"]: r for r in out}


class Census(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = recs()

    def test_agrees_with_the_20261022_builder(self):
        man = json.load(open(os.path.join(ROOT, "oracle", "coverage_20261022", "MANIFEST_w52942756_50.json")))
        built = {b["tx"]: b for b in man["bundles"] if b["tx"] in ONLY}
        self.assertEqual({h for h, r in self.base.items() if r["built"]}, set(built))
        for h, b in built.items():
            self.assertEqual(self.base[h]["extraction"], b["extraction"], h)
            self.assertEqual(self.base[h]["facilitator"], b["facilitator"], h)
            self.assertEqual(self.base[h]["verdict"], "chain_verified", h)
        skipped = {h: r for h, r in self.base.items() if not r["built"]}
        self.assertEqual({r["target"] for r in skipped.values()}, {EP6, ANTSEED})
        self.assertEqual({r["reason"] for r in skipped.values()}, {"indirect_not_extracted"})

    def test_route_classes(self):
        self.assertEqual(self.base[TX_EP6]["route"], "erc4337_entrypoint_v0_6")
        self.assertEqual(self.base[TX_ANTSEED]["route"], "antseed_deposit_relay")
        self.assertEqual(self.base[TX_EP6]["selector"], "0x1fad948c")      # handleOps v0.6

    def test_positive_control_route_rule_removed(self):
        r = recs(disable=("route:" + EP6,))
        self.assertEqual(r[TX_EP6]["route"], "other_contract")
        self.assertEqual(r[TX_ANTSEED]["route"], "antseed_deposit_relay")

    def test_positive_control_log_guided_removed(self):
        r = recs(disable=("log_guided",))
        self.assertTrue(self.base[TX_GUIDED]["built"])
        self.assertFalse(r[TX_GUIDED]["built"])
        self.assertEqual(r[TX_GUIDED]["reason"], "indirect_not_extracted")
        self.assertTrue(r[TX_DIRECT]["built"] and r[TX_INNER]["built"])

    def test_builder_code_read(self):
        self.assertEqual(self.base[TX_DIRECT]["builder_w"], "cdp_facil1")
        self.assertIsNone(self.base[TX_GUIDED]["builder_w"])

    def test_summary_and_canonical(self):
        res = cc.run(CAMPAIGN, only=ONLY)
        g = res["groups"]["eip155:8453 USDC evm_eip3009"]
        self.assertEqual((g["observed"], g["built"], g["verdicts"]), (5, 3, {"chain_verified": 3}))
        self.assertEqual(sum(x["count"] for x in g["excluded"].values()), 2)
        text = cc.canonical(res)
        self.assertEqual(text, cc.canonical(json.loads(text)))
        self.assertTrue(text.endswith("}\n") and ", " not in text.split('"routes"')[0])


class Wallet(unittest.TestCase):
    """A direct call paid from a Coinbase Smart Wallet (ERC-1271, the 2026-10-22 log_guided_wallet bundle b243)."""
    TX = "0x4fc43667e88a8c8af996e295071a6d0fb32c440f4a3f1b7f6afedd0b96ef9d72"
    E = {"kind": "evm_eip3009", "network": "eip155:8453", "asset": "USDC", "label": "w52338016_100",
         "files": {"census": "oracle/census_base_52338016_100.json",
                   "transfers": "oracle/transfers_base_52338016_100.json",
                   "wallets": ["oracle/coverage_20261022/payer_wallet_replies.json"]}}

    def run_one(self, entry, disable=()):
        out, _, wal = cc.classify_eip3009(entry, cc.facilitators(), cc.load_routes(), disable, {self.TX})
        return out[0], wal

    def test_built_from_the_saved_wallet_replies(self):
        r, _ = self.run_one(self.E)
        self.assertEqual((r["built"], r["extraction"], r["verdict"]), (True, "log_guided_wallet", "chain_verified"))

    def test_positive_control_wallet_rule_removed(self):
        r, _ = self.run_one(self.E, ("wallet_1271",))
        self.assertEqual((r["built"], r["reason"], r["payer"]),
                         (False, "direct_not_decoded", "CoinbaseSmartWallet_no_signature_verified"))

    def test_positive_control_replies_missing(self):
        r, wal = self.run_one(dict(self.E, files={k: v for k, v in self.E["files"].items() if k != "wallets"}))
        self.assertEqual((r["built"], r["payer"]), (False, "not_read"))
        self.assertEqual(len(wal.not_read), 1)


class Grammar(unittest.TestCase):
    def test_campaign_closed(self):
        for bad in ({"campaign": "x"}, {"campaign": "x", "entries": [], "more": 1},
                    {"campaign": "x", "entries": [dict(ENTRY, extra=1)]},
                    {"campaign": "x", "entries": [dict(ENTRY, kind="evm_other")]},
                    {"campaign": "x", "entries": [dict(ENTRY, files={"census": "a"})]},
                    {"campaign": "x", "entries": [dict(ENTRY, files=dict(ENTRY["files"], logs="a"))]}):
            with self.assertRaises(ValueError):
                cc.check_campaign(bad)
        cc.check_campaign(CAMPAIGN)

    def test_wilson(self):
        self.assertIsNone(cc.wilson(0, 0))
        lo, hi = cc.wilson(50, 100)
        self.assertAlmostEqual(lo, 0.403832, places=5)
        self.assertAlmostEqual(hi, 0.596168, places=5)
        self.assertEqual(cc.wilson(10, 10)[1], 1.0)

    def test_facilitator_lists_match_the_builder(self):
        """Base addresses of the per-network parser = make_bundles_v02.facilitator_map minus nothing it has."""
        fac = cc.facilitators()
        old = cc.mb.facilitator_map(os.path.join(ROOT, "sources", "x402scan_5732bb8"))
        base, anyn = fac["eip155:8453"], fac["*"]
        self.assertEqual(set(old), set(a for a in anyn if a.startswith("0x")))
        for a in base:
            self.assertEqual(base[a], old[a], a)
        self.assertGreater(len(base), 10)


if __name__ == "__main__":
    unittest.main()
