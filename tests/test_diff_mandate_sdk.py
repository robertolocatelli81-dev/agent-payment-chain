"""SPEC 33.14: the report of tools/diff_mandate_sdk.py counts every generated pair once. `compared` is the number of pairs
both sides decided (agree + disagree + the two declared divergences); `apc_not_evaluated` and `sdk_error` are outside it,
and the six sum to `n`. Until 2026-11-02 the tool printed no `compared`, and SPEC 31.8 called the agreements "pairs"
("0 disagreements on 13 712 pairs": 13 712 was `agree`; 13 736 were compared).

The AP2 SDK is not a dependency of this repository: the tool is run here against a stand-in SDK written by the test
(`check_payment_constraints` says "no violation" for every pair and raises on some), with the pack at APC_AP2EV
(skipped with the reason when it is not usable, as the other tests of the pack). The stand-in makes every one of the
six outcomes non-zero, so a sum that leaves one out is seen. Positive control (2026-11-02): with `compared` written as
`agree` alone the first test fails on every seed; with the tool of 3095ea5 (no `compared`) it fails with a KeyError.
Needs ap2-evidence-pack v1.7.1 and the signature library (APC_SIGLIB), as the other tests."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.test_amend0212 import PACK, env, needs_pack  # noqa: E402

STANDIN = {
    "ap2/__init__.py": "",
    "ap2/sdk/__init__.py": "",
    "ap2/sdk/generated/__init__.py": "",
    "ap2/sdk/generated/open_payment_mandate.py": "class OpenPaymentMandate:\n"
                                                 "    @staticmethod\n"
                                                 "    def model_validate(d):\n        return d\n",
    "ap2/sdk/generated/payment_mandate.py": "class PaymentMandate:\n"
                                            "    @staticmethod\n"
                                            "    def model_validate(d):\n        return d\n",
    # no violation for every pair; the SDK's own failure on one amount in eleven
    "ap2/sdk/constraints.py": "class MandateContext:\n    pass\n\n\n"
                              "def check_payment_constraints(o, c, open_checkout_hash=None, mandate_context=None):\n"
                              "    if c['payment_amount']['amount'] % 11 == 0:\n"
                              "        raise ValueError('stand-in failure')\n"
                              "    return []\n",
}
COUNTS = ("agree", "disagree", "declared_divergence_preset_payee", "declared_divergence_preset_pisp_risk_data",
          "apc_not_evaluated", "sdk_error")


def run_tool(sdk, n, seed, presets):
    code = ("import sys, tools.diff_mandate_sdk as m\nsys.exit(m.main(%d, %d, %s))" % (n, seed, presets))
    e = env(AP2_SDK_PATH=sdk, APC_AP2EV=PACK)
    return subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, env=e, cwd=ROOT, stdin=subprocess.DEVNULL)


class ComparedCountsEveryPairOnce(unittest.TestCase):

    def write_standin(self, tmp):
        for rel, text in STANDIN.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return tmp

    @needs_pack
    def test_compared_is_the_sum_of_the_decided_and_the_five_sum_to_n(self):
        with tempfile.TemporaryDirectory() as tmp:
            sdk = self.write_standin(tmp)
            for seed in (20261031, 7, 99):
                with self.subTest(seed=seed):
                    r = run_tool(sdk, 600, seed, True)
                    err = r.stderr.decode("utf-8")
                    self.assertNotIn("Traceback", err)
                    rep = json.loads(r.stdout.decode("utf-8"))
                    self.assertEqual(rep["n"], 600)
                    for k in COUNTS:
                        self.assertGreater(rep[k], 0, (k, {c: rep[c] for c in COUNTS}))   # every class present
                    self.assertEqual(rep["compared"], rep["agree"] + rep["disagree"] + rep["declared_divergence_preset_payee"]
                                     + rep["declared_divergence_preset_pisp_risk_data"])
                    self.assertEqual(rep["compared"] + rep["apc_not_evaluated"] + rep["sdk_error"], rep["n"])
                    self.assertNotEqual(rep["compared"], rep["agree"])     # the two numbers SPEC 31.8 confused differ here
                    self.assertEqual(r.returncode, 1, "a disagreement is exit 1")    # the stand-in disagrees with apc

    @needs_pack
    def test_without_presets_the_pisp_risk_data_class_is_zero_and_the_sum_holds(self):
        with tempfile.TemporaryDirectory() as tmp:
            sdk = self.write_standin(tmp)
            r = run_tool(sdk, 600, 20261031, False)
            rep = json.loads(r.stdout.decode("utf-8"))
            self.assertEqual(rep["declared_divergence_preset_pisp_risk_data"], 0)
            self.assertEqual(rep["compared"] + rep["apc_not_evaluated"] + rep["sdk_error"], 600)
            self.assertEqual(rep["compared"], rep["agree"] + rep["disagree"] + rep["declared_divergence_preset_payee"])


if __name__ == "__main__":
    unittest.main()
