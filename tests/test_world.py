"""Amendment 0.11.5: stablecoins measured for the world. Real data: bundles/real_world_20261026 (90 real EIP-3009
executions on Ethereum, Arbitrum, Avalanche, Optimism, Monad, Celo, Base EURC, Polygon JPYC, rebuilt by tools/world_bundles.py
from oracle/world_20261026); the high-s probes of oracle/world_20261026/probe_*.txt. Positive control: apc_verify 0.8.0
(5cbe7c7) does not know the new tokens' high-s rule."""
import copy
import glob
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_world_20261026", oracle=("world_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_assets  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
WORLD = os.path.join(ROOT, "bundles", "real_world_20261026")
with open(os.path.join(WORLD, "MANIFEST.json")) as _fh:
    MANIFEST = json.load(_fh)["rows"]
PATHS = sorted(glob.glob(os.path.join(WORLD, "*", "*.json")))


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def high_s(d):
    d = copy.deepcopy(d)
    sig = bytes.fromhex(d["payment_payload"]["payload"]["signature"][2:])
    s = av.SECP_N - int.from_bytes(sig[32:64], "big")
    d["payment_payload"]["payload"]["signature"] = "0x" + (sig[:32] + s.to_bytes(32, "big")
                                                            + bytes([27 + ((sig[64] - 27) ^ 1)])).hex()
    d.pop("chain_tx")          # a transaction carries the low-s signature, so C1 would differ: the payload alone
    return d


class RealWorld(unittest.TestCase):
    def test_every_real_bundle(self):
        self.assertEqual(len(PATHS), 90)
        verdicts = {}
        for p in PATHS:
            r = av.verify_bundle(load(p))
            self.assertEqual(r["checks"]["L2.sig"], "verified", p)
            verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
            acc = load(p)["payment_payload"]["accepted"]
            a = apc_assets.ASSETS[(acc["network"], acc["asset"].lower())]
            self.assertEqual((r["asset"]["symbol"], r["asset"]["decimals"]), a[:2], p)
        self.assertEqual(verdicts, {"chain_verified": 89, "chain_incomplete": 1})
        rows = {m["name"]: m for m in MANIFEST if "bundles" in m}
        self.assertEqual(sum(m["bundles"] for m in rows.values()), 90)
        self.assertEqual({k: rows[k]["domain_version"] for k in ("polygon_jpyc_e7c3", "celo_usdt", "celo_usat")},
                         {"polygon_jpyc_e7c3": "1", "celo_usdt": "1", "celo_usat": "1"})

    def test_domain_version_by_recovery_discriminates(self):
        for name in ("polygon_jpyc_e7c3", "celo_usdt", "celo_usat"):
            p = sorted(glob.glob(os.path.join(WORLD, name, "*.json")))[0]
            d = load(p)
            d["payment_payload"]["accepted"]["extra"]["version"] = "2"
            r = av.verify_bundle(d)
            self.assertTrue(r["checks"]["L2.sig"].startswith("failed:recovers_"), name)

    def test_high_s_refused_on_every_measured_token(self):
        seen = set()
        for p in PATHS:
            d = load(p)
            acc = d["payment_payload"]["accepted"]
            key = (acc["network"], acc["asset"].lower())
            if key in seen:
                continue
            seen.add(key)
            self.assertEqual(av.verify_bundle(high_s(d))["checks"]["L2.sig"], "failed:high_s_refused_by_token", p)
            name = os.path.basename(os.path.dirname(p)).replace("_e7c3", "")
            with open(os.path.join(ROOT, "oracle", "world_20261026", "probe_%s.txt" % name)) as fh:
                probe = fh.read()
            self.assertIn("low-s  {'jsonrpc': '2.0'", probe)
            self.assertNotIn("'error'", probe.split("low-s ")[1].split("\n")[0])
            self.assertIn("invalid signature 's' value", probe.split("high-s")[1].split("\n")[0])
        self.assertEqual(len(seen), 10)

    def test_amount_in_units(self):
        self.assertEqual(apc_assets.info("eip155:137", "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29", 10 ** 18)["amount"], "1")
        self.assertEqual(apc_assets.info("eip155:137", "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29", 5)["amount"],
                         "0.000000000000000005")
        self.assertEqual(apc_assets.info("eip155:1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 2000)["amount"], "0.002")
        self.assertEqual(apc_assets.info("eip155:1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 2 ** 256 - 1)["amount"],
                         "%d.%06d" % divmod(2 ** 256 - 1, 10 ** 6))
        self.assertIsNone(apc_assets.info("eip155:1", "0x" + "11" * 20, 1))

    def test_positive_control_old(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            p = os.path.join(tmp, "b.json")
            with open(p, "w") as fh:
                json.dump(high_s(load(sorted(glob.glob(os.path.join(WORLD, "polygon_jpyc_e7c3", "*.json")))[0])), fh)
            rep = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), p],
                                            capture_output=True, text=True).stdout)
            self.assertEqual((rep["verifier"], rep["checks"]["L2.sig"]),
                             ("apc_verify 0.8.0", "not_evaluated:high_s_token_rule_not_measured"))


if __name__ == "__main__":
    unittest.main()
