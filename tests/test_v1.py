"""SPEC 0.13 (section 21): x402 version 1, bundle apc-0.13. Oracles: the JSON examples of x402 4241d56
specs/x402-specification-v1.md 5.1.1, 5.2.1, 5.3.1 (the example signature is a real EIP-712 signature by its `from`
under the Base Sepolia USDC domain); the real bundles of bundles/real_v03 written as their v1 form. Positive control:
apc_verify 0.8.0 (5cbe7c7) refuses apc-0.13."""
import copy
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_batch  # noqa: E402
import apc_v1  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
with open(os.path.join(ROOT, "sources", "x402_schemes_20261026", "x402-specification-v1.md")) as _fh:
    BLOCKS = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", _fh.read(), re.S)[:3]]
REQ, PAY, SET = BLOCKS[0], BLOCKS[1], BLOCKS[2]
NAME = {v: k for k, v in apc_v1.V1_EVM.items()}


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Unsupported:
        return {"verdict": "unsupported", "checks": {}}
    except av.Refusal as e:
        return {"verdict": "refused", "checks": {}, "reason": str(e)}


def spec_bundle():
    return {"bundle_version": "apc-0.13", "payment_payload": copy.deepcopy(PAY), "payment_required": copy.deepcopy(REQ),
            "settlement": copy.deepcopy(SET)}


def as_v1(p):
    """A real apc-0.3 bundle written in its x402 v1 form (the objects only; chain data unchanged)."""
    with open(p) as fh:
        d = av.strict_json(fh.read())
    acc = d["payment_payload"]["accepted"]
    net = NAME[int(acc["network"].split(":")[1])]
    req = {"scheme": "exact", "network": net, "maxAmountRequired": acc["amount"], "asset": acc["asset"],
           "payTo": acc["payTo"], "resource": "https://api.example.com/r", "description": "", "mimeType": "application/json",
           "maxTimeoutSeconds": acc["maxTimeoutSeconds"], "extra": acc["extra"]}
    out = {"bundle_version": "apc-0.13",
           "payment_payload": {"x402Version": 1, "scheme": "exact", "network": net, "payload": d["payment_payload"]["payload"]},
           "payment_required": {"x402Version": 1, "error": "X-PAYMENT header is required", "accepts": [req]}}
    st = d["settlement"]
    out["settlement"] = {"success": st["success"], "transaction": st["transaction"], "network": net,
                         "payer": st.get("payer", d["payment_payload"]["payload"]["authorization"]["from"])}
    for k in ("chain_tx", "inclusion", "canonical", "payer_wallet"):
        if k in d:
            out[k] = d[k]
    return out, d


class Spec(unittest.TestCase):
    def test_examples(self):
        self.assertEqual((REQ["x402Version"], PAY["x402Version"], SET["network"]), (1, 1, "base-sepolia"))
        r = run(spec_bundle())
        self.assertEqual(r["checks"]["L2.sig"], "verified")
        self.assertEqual((r["verdict"], r["x402_version"]), ("chain_verified", 1))

    def test_amount_rule(self):
        d = spec_bundle()
        d["payment_required"]["accepts"][0]["maxAmountRequired"] = "9999"           # the value exceeds it: v1 accepts
        r = run(d)
        self.assertTrue(r["checks"]["K2"].startswith("verified (v1: value 10000 exceeds"))
        self.assertEqual(r["verdict"], "chain_verified")
        d["payment_required"]["accepts"][0]["maxAmountRequired"] = "10001"
        self.assertTrue(run(d)["checks"]["K2"].startswith("failed"))

    def test_refusals(self):
        for mut, want in ((lambda d: d["payment_payload"].__setitem__("network", "ethereum"), "unsupported"),
                          (lambda d: d["payment_payload"].__setitem__("network", "base"), "refused"),
                          (lambda d: d["payment_required"]["accepts"].append(copy.deepcopy(d["payment_required"]["accepts"][0])),
                           "refused"),
                          (lambda d: d["payment_payload"].__setitem__("accepted", {}), "refused"),
                          (lambda d: d["payment_required"].pop("error"), "refused"),
                          (lambda d: d["settlement"].pop("payer"), "refused"),
                          (lambda d: d["payment_required"]["accepts"][0].pop("description"), "refused"),
                          (lambda d: d.__setitem__("exchange", {}), "refused")):
            d = spec_bundle()
            mut(d)
            self.assertEqual(run(d)["verdict"], want)
        d = spec_bundle()                                   # two requirements on one network, told apart by payTo
        other = copy.deepcopy(d["payment_required"]["accepts"][0])
        other["payTo"] = "0x" + "11" * 20
        d["payment_required"]["accepts"].insert(0, other)
        self.assertEqual(run(d)["verdict"], "chain_verified")


class Real(unittest.TestCase):
    def test_real_bundles_in_v1_form(self):
        paths = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v03", "*.json")) if "MANIFEST" not in p)
        n = 0
        for p in paths:
            v1, v2 = as_v1(p)
            r1, r2 = run(v1), run(v2)
            self.assertEqual(r1["verdict"], r2["verdict"], p)
            for k in ("L2.sig", "K1", "K3", "C1", "C2", "B1", "B2", "B3", "B4", "O1", "O4"):
                if k in r2["checks"]:
                    self.assertEqual(r1["checks"][k], r2["checks"][k], (p, k))
            n += 1
        self.assertEqual(n, len(paths))
        self.assertGreater(n, 15)

    def test_set_checks(self):
        p = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v03", "*.json")) if "MANIFEST" not in p)[1]
        a, _ = as_v1(p)
        b = copy.deepcopy(a)
        b["payment_required"]["accepts"][0]["resource"] = "https://api.example.com/other"
        rep = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual(rep["D1"][0]["check"], "failed:same_payment_for_two_deliveries")

    def test_policy_and_drafts(self):
        import apc_report as rp
        d = spec_bundle()
        rep = av.verify_bundle(copy.deepcopy(d), drafts=True)
        self.assertEqual(rep["drafts"]["x402-pr3910@2e9e6aa"]["checks"], {"DS1": "verified"})
        out = rp.apply_policy(rp.parse_policy({"apc_policy": 1, "networks": ["eip155:84532"],
                                               "hosts": ["api.example.com"]}), d, rep)
        self.assertEqual((out["policy"]["P1"], out["policy"]["P5"]), ("verified", "verified"))

    def test_positive_control_old(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            pth = os.path.join(tmp, "b.json")
            with open(pth, "w") as fh:
                json.dump(spec_bundle(), fh)
            rep = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), pth],
                                            capture_output=True, text=True).stdout)
            self.assertEqual((rep["verifier"], rep["verdict"]), ("apc_verify 0.8.0", "refused"))


if __name__ == "__main__":
    unittest.main()
