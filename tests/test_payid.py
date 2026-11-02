"""Amendment 0.11.2: the x402 payment-identifier extension (PI1 alone, D4 across a set). Real bundles of the corpus:
real_001 and real_002 are two real executed authorizations to one payTo for one amount (Base USDC, 10000), the shape
of a retried request paid twice; the ids are added (the extension is unsigned envelope data). Positive control:
apc_verify / apc_batch 0.8.0 (5cbe7c7) do not read the extension."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_batch  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
R1 = os.path.join(ROOT, "bundles", "real", "real_001_envelope_reconstructed.json")
R2 = os.path.join(ROOT, "bundles", "real", "real_002_envelope_reconstructed.json")
OTHER = os.path.join(ROOT, "bundles", "real", "real_003_envelope_reconstructed.json")     # another payTo and amount
ID = "pay_7d5d747be160e280504c099d984bcfe0"         # the example id of x402 payment_identifier.md


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def with_id(d, pid=ID, required=None, url="https://api.example.com/premium-data"):
    d = copy.deepcopy(d)
    d["payment_payload"]["resource"] = {"url": url}
    if pid is not None:
        d["payment_payload"].setdefault("extensions", {})["payment-identifier"] = {
            "info": {"required": False, "id": pid}}
    if required is not None:
        d["payment_required"] = {"x402Version": 2, "resource": {"url": url},
                                 "accepts": [copy.deepcopy(d["payment_payload"]["accepted"])],
                                 "extensions": {"payment-identifier": {"info": {"required": required}}}}
    return d


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Refusal as e:
        return {"verdict": "refused", "checks": {}, "reason": str(e)}


class Single(unittest.TestCase):
    def test_pi1(self):
        base = load(R1)
        self.assertNotIn("PI1", run(base)["checks"])
        self.assertEqual(run(with_id(base))["checks"]["PI1"], "verified")
        self.assertEqual(run(with_id(base))["verdict"], "chain_verified")
        for bad in ("short", "x" * 129, "pay_7d5d747be160e2805!", "pay_7d5d747be160e28é", "pay 7d5d747be160e2805"):
            r = run(with_id(base, bad))
            self.assertEqual((r["checks"]["PI1"], r["verdict"]), ("failed:payment_identifier_malformed", "chain_failed"), bad)
        r = run(with_id(base, None, required=True))
        self.assertEqual(r["checks"]["PI1"], "failed:payment_identifier_required_but_absent")
        self.assertEqual(run(with_id(base, None, required=False))["checks"]["PI1"],
                         "not_evaluated:absent:no_payment_identifier")
        self.assertEqual(run(with_id(base, ID, required=True))["checks"]["PI1"], "verified")

    def test_closed(self):
        base = with_id(load(R1))
        ext = lambda d: d["payment_payload"]["extensions"]["payment-identifier"]      # noqa: E731
        for mut in (lambda e: e.__setitem__("x", 1), lambda e: e["info"].__setitem__("x", 1),
                    lambda e: e["info"].__setitem__("required", "false"), lambda e: e["info"].__setitem__("id", 5),
                    lambda e: e.__setitem__("schema", []), lambda e: e.pop("info"), lambda e: e["info"].pop("required")):
            d = copy.deepcopy(base)
            mut(ext(d))
            self.assertEqual(run(d)["verdict"], "refused")


class Set(unittest.TestCase):
    def test_d4(self):
        a, b, o = load(R1), load(R2), load(OTHER)
        rep = apc_batch.check_set([("a", with_id(a)), ("b", with_id(b))])
        self.assertEqual(rep["D4"][0]["check"], "failed:payment_identifier_two_settled_payments")
        self.assertEqual(len(rep["D4"][0]["transactions"]), 2)
        self.assertEqual(rep["verdict"], "set_failed")
        # same id, another resource of the same merchant: another fingerprint
        rep = apc_batch.check_set([("a", with_id(a)), ("b", with_id(b, url="https://api.example.com/other"))])
        self.assertEqual(rep["D4"][0]["check"], "failed:payment_identifier_reused")
        # the same bundle twice: one authorization, a duplicate (D2), not D4
        rep = apc_batch.check_set([("a", with_id(a)), ("a2", with_id(a))])
        self.assertEqual((rep["D4"], rep["verdict"]), ("verified", "set_consistent"))
        # another merchant may use the same id (PI: scope the key)
        rep = apc_batch.check_set([("a", with_id(a)), ("o", with_id(o))])
        self.assertEqual((rep["D4"], rep["verdict"]), ("verified", "set_consistent"))
        # different ids: nothing to compare
        rep = apc_batch.check_set([("a", with_id(a)), ("b", with_id(b, ID + "x"))])
        self.assertEqual(rep["D4"], "verified")

    def test_positive_control_old(self):
        a, b = load(R1), load(R2)
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            paths = []
            for n, d in (("a", with_id(a)), ("b", with_id(b))):
                paths.append(os.path.join(tmp, n + ".json"))
                with open(paths[-1], "w") as fh:
                    json.dump(d, fh)
            out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_batch.py")] + paths,
                                 capture_output=True, text=True, cwd=tmp)
            self.assertEqual(json.loads(out.stdout)["verdict"], "set_consistent")
            bad = os.path.join(tmp, "m.json")
            with open(bad, "w") as fh:
                json.dump(with_id(a, "short"), fh)
            rep = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), bad],
                                            capture_output=True, text=True).stdout)
            self.assertEqual((rep["verifier"], rep["verdict"]), ("apc_verify 0.8.0", "chain_verified"))


if __name__ == "__main__":
    unittest.main()
