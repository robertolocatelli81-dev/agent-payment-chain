"""SPEC 0.6 (section 8): the report tools of apc_report.py on real bundles: Ed25519 signature over the canonical report
(RFC 8032 test vectors first), SARIF 2.1.0, the policy checks P1-P5, the RFC 6962 Merkle root (its published vector)."""
import copy
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm", "real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_report as rp  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402

V03 = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v03", "*.json")) if "MANIFEST" not in p)
SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")
SEED = hashlib.sha256(b"apc report test seed").digest()          # a test key, not anyone's


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def env():
    e = dict(os.environ)
    e.pop("PYTHONPATH", None)
    return e


class Ed25519(unittest.TestCase):
    def test_rfc8032_vectors(self):
        """RFC 8032 7.1 TEST 1, 2 and 3: public key, signature, verification"""
        for sd, pk, m, sig in (
                ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                 "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                 "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f05"
                 "95bbe24655141438e7a100b"),
                ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                 "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                 "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb43"
                 "02aeeb00d291612bb0c00"),
                ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                 "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                 "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e97"
                 "16ed28dc027beceea1ec40a")):
            self.assertEqual(sol.ed25519_public(bytes.fromhex(sd)).hex(), pk)
            self.assertEqual(sol.ed25519_sign(bytes.fromhex(sd), bytes.fromhex(m)).hex(), sig)
            self.assertTrue(sol.ed25519_verify(bytes.fromhex(pk), bytes.fromhex(m), bytes.fromhex(sig)))
        for bad in (b"", bytes(31), "00" * 32):
            with self.assertRaises(ValueError):
                sol.ed25519_public(bad)


class Signed(unittest.TestCase):
    def reports(self):
        return [av.verify_bundle(load(p)) for p in V03[:5]] + [av.verify_bundle(load(SVM))]

    def test_sign_verify_real_reports(self):
        pub = sol.ed25519_public(SEED).hex()
        for rep in self.reports():
            s = rp.sign(rep, SEED)
            self.assertEqual(rp.verify(s), "verified")
            self.assertEqual(rp.verify(s, pub), "verified")
            self.assertEqual(rp.verify(s, pub.upper()), "verified")
            self.assertEqual(rp.verify(s, "00" * 32), "failed:signed_by_another_key")

    def test_any_change_breaks_it(self):
        s0 = rp.sign(self.reports()[0], SEED)
        for change in (lambda s: s["report"].__setitem__("verdict", "chain_failed"),
                       lambda s: s["report"]["checks"].__setitem__("K1", "failed:x"),
                       lambda s: s["report"]["notes"].append("x"),
                       lambda s: s["report"].__setitem__("extra", 1),
                       lambda s: s.__setitem__("signature", s["signature"][:-2] + ("00" if s["signature"][-2:] != "00"
                                                                                   else "01"))):
            s = copy.deepcopy(s0)
            change(s)
            self.assertEqual(rp.verify(s), "failed:signature_invalid")
        s = copy.deepcopy(s0)
        other = sol.ed25519_public(hashlib.sha256(b"other").digest()).hex()
        s["public_key"] = other
        self.assertEqual(rp.verify(s), "failed:key_id_not_the_key")
        s["key_id"] = hashlib.sha256(bytes.fromhex(other)).hexdigest()[:16]
        self.assertEqual(rp.verify(s), "failed:signature_invalid")

    def test_domain_separation(self):
        """the signature covers 'apc-report-v1\\n' + the canonical report, not the bare report bytes"""
        rep = self.reports()[0]
        s = rp.sign(rep, SEED)
        bare = sol.ed25519_sign(SEED, rp.canonical(rep)).hex()
        self.assertNotEqual(bare, s["signature"])
        s["signature"] = bare
        self.assertEqual(rp.verify(s), "failed:signature_invalid")

    def test_grammar(self):
        s0 = rp.sign(self.reports()[0], SEED)
        for k, v in (("apc_signed_report", 2), ("apc_signed_report", True), ("apc_signed_report", 1.0),
                     ("public_key", s0["public_key"].upper()), ("public_key", "00"), ("signature", "00"),
                     ("signature", s0["signature"].upper()), ("zz", 1)):
            s = copy.deepcopy(s0)
            s[k] = v
            with self.assertRaises(rp.Bad, msg=(k, v)):
                rp.verify(s)
        s = copy.deepcopy(s0)
        del s["key_id"]
        with self.assertRaises(rp.Bad):
            rp.verify(s)

    def test_canonical(self):
        self.assertEqual(rp.canonical({"b": 1, "a": [True, None, "é\n"]}), '{"a":[true,null,"é\\n"],"b":1}'.encode())
        for bad in ({"a": 1.5}, {"é": 1}, {"a": 2 ** 53}, {"a": b"x"}, {1: 2}):
            with self.assertRaises(rp.Bad, msg=bad):
                rp.canonical(bad)
        self.assertEqual(rp.canonical({"a": 2 ** 53 - 1}), b'{"a":9007199254740991}')

    def test_cli_sign_verify(self):
        with tempfile.TemporaryDirectory() as t:
            seed, rep, sig = (os.path.join(t, x) for x in ("seed", "rep.json", "signed.json"))
            with open(seed, "w") as fh:
                fh.write(SEED.hex() + "\n")
            with open(rep, "w") as fh:
                json.dump(self.reports()[0], fh)
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_report.py"), "sign", seed, rep],
                               capture_output=True, text=True, env=env())
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(SEED.hex(), r.stdout)                   # the seed is never printed
            with open(sig, "w") as fh:
                fh.write(r.stdout)
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_report.py"), "verify", sig],
                               capture_output=True, text=True, env=env())
            self.assertEqual((r.returncode, json.loads(r.stdout)), (0, {"signature": "verified"}))
            d = json.load(open(sig))
            d["report"]["verdict"] = "x"
            with open(sig, "w") as fh:
                json.dump(d, fh)
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_report.py"), "verify", sig],
                               capture_output=True, text=True, env=env())
            self.assertEqual(r.returncode, 1)
            with open(seed, "w") as fh:
                fh.write("zz\n")
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_report.py"), "sign", seed, rep],
                               capture_output=True, text=True, env=env())
            self.assertEqual(r.returncode, 3)


class Sarif(unittest.TestCase):
    def test_results(self):
        items = [(p, av.verify_bundle(load(p))) for p in V03[:6]]
        bad = load(V03[0])
        bad["payment_payload"]["accepted"]["amount"] = str(int(bad["payment_payload"]["accepted"]["amount"]) + 1)
        items.append(("bad.json", av.verify_bundle(bad)))
        pend = load(V03[0])                                  # x402 v2 9: settlement_pending, a check not evaluated
        pend["settlement"]["success"] = False
        pend["settlement"]["errorReason"] = "settlement_pending"
        items.append(("pending.json", av.verify_bundle(pend)))
        self.assertTrue(items[-1][1]["not_evaluated"])
        items.append(("refused.json", {"verdict": "refused", "reason": "x"}))
        log = rp.sarif(items)
        self.assertEqual(log["version"], "2.1.0")
        res = log["runs"][0]["results"]
        want = sum(len(r["failed"]) + len(r["not_evaluated"]) for _, r in items[:-1]) + 1
        self.assertEqual(len(res), want)
        k2 = [x for x in res if x["ruleId"] == "K2"]
        self.assertEqual([(x["level"], x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]) for x in k2],
                         [("error", "bad.json")])
        self.assertEqual([x["ruleId"] for x in res if x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                          == "refused.json"], ["bundle"])
        ids = [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(ids, sorted(set(x["ruleId"] for x in res)))
        warn = [x for x in res if x["level"] == "warning"]
        self.assertEqual(len(warn), sum(len(r["not_evaluated"]) for _, r in items[:-1]))
        self.assertGreater(len(warn), 0)
        self.assertTrue(all(x["ruleId"] in dict(items)[x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]]
                            ["not_evaluated"] for x in warn))


class Policy(unittest.TestCase):
    def setUp(self):
        self.doc = load(V03[0])
        self.rep = av.verify_bundle(self.doc)
        self.acc = self.doc["payment_payload"]["accepted"]

    def pol(self, **kw):
        return rp.apply_policy(rp.parse_policy(dict({"apc_policy": 1}, **kw)), self.doc, self.rep)

    def test_rules(self):
        a = self.acc
        r = self.pol(networks=[a["network"]], assets=[a["asset"].upper().replace("0X", "0x")], pay_to=[a["payTo"]],
                     max_amount={a["asset"]: a["amount"]})
        self.assertEqual([r["policy"][k] for k in ("P1", "P2", "P3", "P4")], ["verified"] * 4)
        self.assertEqual(r["policy_verdict"], "policy_met")
        self.assertEqual(r["verdict"], self.rep["verdict"])
        self.assertEqual(self.pol(networks=["eip155:1"])["policy"]["P1"], "failed:network_not_allowed")
        self.assertEqual(self.pol(assets=["0x" + "11" * 20])["policy"]["P2"], "failed:asset_not_allowed")
        self.assertEqual(self.pol(max_amount={a["asset"]: str(int(a["amount"]) - 1)})["policy"]["P3"],
                         "failed:amount_above_cap")
        self.assertEqual(self.pol(max_amount={"0x" + "11" * 20: "5"})["policy"]["P3"], "failed:asset_without_a_cap")
        self.assertEqual(self.pol(pay_to=["0x" + "11" * 20])["policy"]["P4"], "failed:recipient_not_allowed")
        r = self.pol(pay_to=["0x" + "11" * 20])
        self.assertEqual(r["policy_verdict"], "policy_failed")
        self.assertEqual(self.pol()["policy"], {k: "not_evaluated:absent:no_rule" for k in ("P1", "P2", "P3", "P4", "P5")})

    def test_hosts(self):
        url = (self.doc["payment_payload"].get("resource") or {}).get("url")
        if url is None:
            self.assertEqual(self.pol(hosts=["example.org"])["policy"]["P5"], "failed:no_resource_url")
            self.doc["payment_payload"]["resource"] = {"url": "https://Pay.Example.org/x"}
        self.doc["payment_payload"]["resource"] = {"url": "https://Pay.Example.org/x"}
        self.assertEqual(self.pol(hosts=["pay.example.org"])["policy"]["P5"], "verified")
        self.assertEqual(self.pol(hosts=["PAY.EXAMPLE.ORG"])["policy"]["P5"], "verified")
        self.assertEqual(self.pol(hosts=["example.org"])["policy"]["P5"], "failed:host_not_allowed")
        del self.doc["payment_payload"]["resource"]
        self.assertEqual(self.pol(hosts=["example.org"])["policy"]["P5"], "failed:no_resource_url")

    def test_solana_case_exact(self):
        doc = load(SVM)
        rep = av.verify_bundle(doc)
        a = doc["payment_payload"]["accepted"]
        r = rp.apply_policy(rp.parse_policy({"apc_policy": 1, "assets": [a["asset"]], "pay_to": [a["payTo"].lower()]}),
                            doc, rep)
        self.assertEqual((r["policy"]["P2"], r["policy"]["P4"]), ("verified", "failed:recipient_not_allowed"))

    def test_grammar(self):
        for bad in ({}, {"apc_policy": 2}, {"apc_policy": True}, {"apc_policy": 1.0}, {"apc_policy": 1, "zz": 1},
                    {"apc_policy": 1, "networks": []}, {"apc_policy": 1, "networks": ["a", "a"]},
                    {"apc_policy": 1, "assets": "x"}, {"apc_policy": 1, "max_amount": {}},
                    {"apc_policy": 1, "max_amount": {"a": "01"}}, {"apc_policy": 1, "max_amount": {"a": 5}},
                    {"apc_policy": 1, "hosts": [""]}, []):
            with self.assertRaises(rp.Bad, msg=bad):
                rp.parse_policy(bad)


class Merkle(unittest.TestCase):
    def test_rfc6962_vector(self):
        """certificate-transparency's reference tree test vectors: the roots of the first 1..8 leaves"""
        leaves = [bytes.fromhex(x) for x in ("", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                                             "606162636465666768696a6b6c6d6e6f")]
        roots = ("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                 "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
                 "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
                 "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                 "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
                 "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
                 "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
                 "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")
        for n, want in enumerate(roots, 1):                    # every prefix: the split at the largest power of two
            self.assertEqual(rp.merkle_root(leaves[:n]).hex(), want, n)
        self.assertEqual(rp.merkle_root(leaves[:1]).hex(), hashlib.sha256(b"\0").hexdigest())
        self.assertEqual(rp.merkle_root([]).hex(), hashlib.sha256(b"").hexdigest())
        for n in range(2, 9):                    # order matters, every leaf counts
            self.assertNotEqual(rp.merkle_root(leaves[:n]), rp.merkle_root(leaves[:n][::-1]))
            self.assertNotEqual(rp.merkle_root(leaves[:n]), rp.merkle_root(leaves[:n - 1]))

    def test_cli_on_reports(self):
        with tempfile.TemporaryDirectory() as t:
            paths = []
            for i, p in enumerate(V03[:3]):
                q = os.path.join(t, "r%d.json" % i)
                with open(q, "w") as fh:
                    json.dump(av.verify_bundle(load(p)), fh)
                paths.append(q)
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_report.py"), "merkle"] + paths,
                               capture_output=True, text=True, env=env())
            out = json.loads(r.stdout)
            leaves = [rp.canonical(load(q)) for q in paths]
            self.assertEqual(out["root"], rp.merkle_root(leaves).hex())
            self.assertEqual(out["leaves"], [hashlib.sha256(b"\0" + x).hexdigest() for x in leaves])


if __name__ == "__main__":
    unittest.main()
