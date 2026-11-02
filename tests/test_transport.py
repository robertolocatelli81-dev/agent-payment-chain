"""Amendment 0.11.3: the x402 payment over MCP and A2A (XM1-XM4, XA1-XA4). Oracle: the JSON examples of x402 4241d56
transports-v2/mcp.md and a2a.md (sources/x402_transports_20261026), with the real payment and settlement of a bundle
of the corpus put where the examples carry theirs. Positive control: apc_verify 0.8.0 (5cbe7c7) refuses the members."""
import copy
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
real_corpus.need("real_svm", "real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
SRC = os.path.join(ROOT, "sources", "x402_transports_20261026")
V03 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")
SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def examples(name):
    with open(os.path.join(SRC, name)) as fh:
        return [json.loads(b) for b in re.findall(r"```json\n(.*?)```", fh.read(), re.S)]


MCP, A2A = examples("mcp.md"), examples("a2a.md")


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Refusal as e:
        return {"verdict": "refused", "checks": {}, "reason": str(e)}


def mcp_bundle(p=V03, success=True):
    d = load(p)
    rq = copy.deepcopy(MCP[1])
    rq["params"]["_meta"]["x402/payment"] = copy.deepcopy(d["payment_payload"])
    if success:
        rs = copy.deepcopy(MCP[2])
        rs["result"]["_meta"]["x402/payment-response"] = copy.deepcopy(d["settlement"])
    else:
        d["settlement"]["success"] = False
        rs = copy.deepcopy(MCP[0])                     # isError with the PaymentRequired in both forms
    d["exchange_mcp"] = {"request": rq, "response": rs}
    return d


def a2a_bundle(p=V03, success=True):
    d = load(p)
    rq = copy.deepcopy(A2A[1])
    rq["params"]["message"]["metadata"]["x402.payment.payload"] = copy.deepcopy(d["payment_payload"])
    if success:
        rs = copy.deepcopy(A2A[2])
    else:
        d["settlement"]["success"] = False
        rs = copy.deepcopy(A2A[3])
    rs["result"]["status"]["message"]["metadata"]["x402.payment.receipts"] = [copy.deepcopy(d["settlement"])]
    d["exchange_a2a"] = {"request": rq, "response": rs}
    return d


class SpecExamples(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual([e.get("method") for e in MCP[:4]], [None, "tools/call", None, None])
        self.assertEqual(A2A[1]["method"], "message/send")
        sc, txt = MCP[0]["result"]["structuredContent"], MCP[0]["result"]["content"][0]["text"]
        self.assertEqual(json.loads(txt), sc)                       # the Payment Required example holds
        with self.assertRaises(ValueError):                          # the Settlement Failure one abbreviates
            json.loads(MCP[3]["result"]["content"][0]["text"])


class Mcp(unittest.TestCase):
    def test_verified_on_both_networks(self):
        for p in (V03, SVM):
            r = run(mcp_bundle(p))
            self.assertEqual([r["checks"][k] for k in ("XM1", "XM2", "XM3", "XM4")], ["verified"] * 4, p)
            self.assertEqual(r["verdict"], run(load(p))["verdict"], p)
            self.assertEqual(r["exchange_mcp"]["tool"], "financial_analysis")
        r = run(mcp_bundle(V03, success=False))
        self.assertEqual((r["checks"]["XM3"], r["checks"]["XM4"]), ("not_evaluated:absent:no_payment_response", "verified"))

    def test_failures(self):
        cases = []
        d = mcp_bundle()
        d["exchange_mcp"]["request"]["method"] = "tools/list"
        cases.append((d, "XM1", "failed:mcp_request_not_tools_call"))
        d = mcp_bundle()
        d["exchange_mcp"]["request"]["params"]["_meta"]["x402/payment"]["accepted"]["amount"] = "1"
        cases.append((d, "XM1", "failed:mcp_request_carries_another_payment"))
        d = mcp_bundle()
        del d["exchange_mcp"]["request"]["params"]["_meta"]["x402/payment"]
        cases.append((d, "XM1", "failed:mcp_request_without_payment"))
        d = mcp_bundle()
        d["exchange_mcp"]["response"]["id"] = "1"
        cases.append((d, "XM2", "failed:mcp_response_id_mismatch"))
        d = mcp_bundle()
        d["exchange_mcp"]["response"]["result"]["_meta"]["x402/payment-response"]["transaction"] = "0x" + "ab" * 32
        cases.append((d, "XM3", "failed:mcp_response_carries_another_settlement"))
        d = mcp_bundle()
        del d["exchange_mcp"]["response"]["result"]["_meta"]["x402/payment-response"]
        cases.append((d, "XM3", "failed:mcp_response_without_payment_response"))
        d = mcp_bundle()
        d["exchange_mcp"]["response"]["result"]["isError"] = True
        cases.append((d, "XM4", "failed:mcp_status_contradicts_settlement"))
        d = mcp_bundle(success=False)
        d["exchange_mcp"]["response"]["result"]["content"][0]["text"] = MCP[3]["result"]["content"][0]["text"]
        cases.append((d, "XM4", "failed:mcp_payment_required_text_differs"))
        d = mcp_bundle(success=False)
        del d["exchange_mcp"]["response"]["result"]["structuredContent"]
        cases.append((d, "XM4", "failed:mcp_payment_required_not_in_both_forms"))
        for d, k, want in cases:
            r = run(d)
            self.assertEqual((r["checks"].get(k), r["verdict"]), (want, "chain_failed"), want)

    def test_closed(self):
        for mut in (lambda e: e.__setitem__("x", 1), lambda e: e["request"].__setitem__("x", 1),
                    lambda e: e["request"].__setitem__("jsonrpc", "1.0"), lambda e: e["request"].__setitem__("id", None),
                    lambda e: e["request"].__setitem__("id", True), lambda e: e["request"].__setitem__("params", []),
                    lambda e: e["response"].__setitem__("error", {}), lambda e: e["response"].pop("result"),
                    lambda e: e["response"]["result"].__setitem__("isError", "no"),
                    lambda e: e["request"]["params"].__setitem__("_meta", [])):
            d = mcp_bundle()
            mut(d["exchange_mcp"])
            self.assertEqual(run(d)["verdict"], "refused")
        d = mcp_bundle()
        d["bundle_version"] = "apc-0.2"
        self.assertEqual(run(d)["verdict"], "refused")


class A2a(unittest.TestCase):
    def test_verified(self):
        for p in (V03, SVM):
            r = run(a2a_bundle(p))
            self.assertEqual([r["checks"][k] for k in ("XA1", "XA2", "XA3", "XA4")], ["verified"] * 4, p)
        r = run(a2a_bundle(V03, success=False))
        self.assertEqual([r["checks"][k] for k in ("XA3", "XA4")], ["verified", "verified"])

    def test_failures(self):
        cases = []
        d = a2a_bundle()
        d["exchange_a2a"]["request"]["params"]["message"]["metadata"]["x402.payment.status"] = "payment-verified"
        cases.append((d, "XA1", "failed:a2a_request_status_not_payment_submitted"))
        d = a2a_bundle()
        del d["exchange_a2a"]["request"]["params"]["message"]["taskId"]
        cases.append((d, "XA1", "failed:a2a_request_without_task_id"))
        d = a2a_bundle()
        d["exchange_a2a"]["request"]["params"]["message"]["metadata"]["x402.payment.payload"]["payload"]["signature"] = "0x00"
        cases.append((d, "XA1", "failed:a2a_request_carries_another_payment"))
        d = a2a_bundle()
        d["exchange_a2a"]["response"]["result"]["id"] = "task-999"
        cases.append((d, "XA2", "failed:a2a_task_id_mismatch"))
        d = a2a_bundle()
        d["exchange_a2a"]["response"]["result"]["status"]["message"]["metadata"]["x402.payment.receipts"][0]["payer"] = "0x" + "11" * 20
        cases.append((d, "XA3", "failed:a2a_receipts_without_the_settlement"))
        d = a2a_bundle()
        d["exchange_a2a"]["response"]["result"]["status"]["state"] = "failed"
        cases.append((d, "XA4", "failed:a2a_status_contradicts_settlement"))
        d = a2a_bundle(success=False)
        d["exchange_a2a"]["response"]["result"]["status"]["message"]["metadata"]["x402.payment.status"] = "payment-completed"
        cases.append((d, "XA4", "failed:a2a_status_contradicts_settlement"))
        for d, k, want in cases:
            r = run(d)
            self.assertEqual((r["checks"].get(k), r["verdict"]), (want, "chain_failed"), want)
        d = a2a_bundle()
        d["exchange_a2a"]["request"]["params"]["message"]["metadata"]["x402.payment.status"] = "paid"
        self.assertEqual(run(d)["verdict"], "refused")


class PositiveControl(unittest.TestCase):
    def test_old_verifier_refuses_the_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            for d in (mcp_bundle(), a2a_bundle()):
                p = os.path.join(tmp, "b.json")
                with open(p, "w") as fh:
                    json.dump(d, fh)
                rep = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), p],
                                                capture_output=True, text=True).stdout)
                self.assertEqual((rep["verifier"], rep["verdict"]), ("apc_verify 0.8.0", "refused"))


if __name__ == "__main__":
    unittest.main()
