"""Review of apc_verify 0.7.0 (independent review, 2026-10-25): inputs that crashed instead of being refused, settlement members
read by nothing, the u16 short_vec and the 1232-byte transaction, and rules of 0.4-0.7 that no test held (each test
here kills a mutant that the suite let live)."""
import copy
import glob
import hashlib
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm", "real_v02", "real_v04_l1state")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_report as rp  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402

SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")
EVM = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02", "b*.json")))
BIG = "1" * 5000                                  # above int()'s 4300-digit limit
CASES = os.environ.get("APC_PULSE_CASES")
PULSE_SHA256 = "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"


def svm():
    with open(SVM) as fh:
        return json.load(fh)


def run(d, cp=None):
    return av.verify_bundle(copy.deepcopy(d), cp)


class BigIntegers(unittest.TestCase):
    def test_svm_u64_fields_refused_not_crashed(self):
        for path in (("payment_payload", "accepted", "amount"),
                     ("payment_payload", "accepted", "extra", "lastValidBlockHeight")):
            d = svm()
            o = d
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = BIG
            with self.assertRaises(av.Refusal):
                run(d)
        d = svm()
        d["chain_tx"]["meta"]["postTokenBalances"][0]["uiTokenAmount"]["amount"] = BIG
        with self.assertRaises(av.Refusal):
            run(d)
        d = svm()
        d["payment_payload"]["accepted"]["amount"] = "1" + "0" * 20      # 21 digits, above u64
        with self.assertRaises(av.Refusal):
            run(d)

    def test_policy_cap_digits(self):
        with self.assertRaises(rp.Bad):
            rp.parse_policy({"apc_policy": 1, "max_amount": {"x": BIG}})
        rp.parse_policy({"apc_policy": 1, "max_amount": {"x": "9" * 78}})


class Settlement(unittest.TestCase):
    def setUp(self):
        self.d = svm()
        self.rep = run(self.d)
        self.assertEqual(self.rep["verdict"], "chain_verified")

    def t1(self, **kv):
        d = copy.deepcopy(self.d)
        d["settlement"].update(kv)
        return run(d)["checks"]["T1"]

    def test_payer(self):
        self.assertEqual(self.t1(payer=self.rep["fee_payer"]), "verified")
        self.assertEqual(self.t1(payer=self.rep["payer"]), "verified")
        self.assertEqual(self.t1(payer="11111111111111111111111111111111"), "failed:settlement_payer_mismatch")
        for bad in (12345, "", "0x" + "11" * 20):
            with self.assertRaises(av.Refusal):
                self.t1(payer=bad)

    def test_amount(self):
        amt = self.d["payment_payload"]["accepted"]["amount"]
        self.assertEqual(self.t1(amount=amt), "verified")
        self.assertEqual(self.t1(amount=str(int(amt) + 1)), "failed:settlement_amount_mismatch")
        for bad in ([1], 1, "01"):
            with self.assertRaises(av.Refusal):
                self.t1(amount=bad)

    def test_types(self):
        with self.assertRaises(av.Refusal):
            self.t1(extensions="x")
        with self.assertRaises(av.Refusal):
            self.t1(errorReason=7)
        self.assertEqual(self.t1(extensions={}), "verified")


class PaymentRequired(unittest.TestCase):
    def test_version_and_error(self):
        d = svm()
        acc = d["payment_payload"]["accepted"]
        pr = {"x402Version": 2, "resource": {"url": "https://x"}, "accepts": [acc]}
        d["payment_required"] = pr
        self.assertEqual(run(d)["checks"]["K4"], "verified")
        for k, v in (("x402Version", "junk"), ("x402Version", 1), ("error", 99)):
            e = copy.deepcopy(d)
            e["payment_required"][k] = v
            with self.assertRaises(av.Unsupported if v == 1 else av.Refusal) as cm:
                run(e)
            self.assertEqual(type(cm.exception) is av.Unsupported, v == 1, (k, v))

    def test_evm_version(self):
        """the EVM branch (0.7.1, apc_verify.py): payment_required.x402Version other than 2 is unsupported, as in
        payment_payload; the SVM test above does not reach this line"""
        with open(EVM[0]) as fh:
            d = json.load(fh)
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "u"},
                                 "accepts": [d["payment_payload"]["accepted"]]}
        self.assertEqual(run(d)["checks"]["K4"], "verified")
        for v, want in ((1, av.Unsupported), (3, av.Unsupported), ("2", av.Refusal)):
            e = copy.deepcopy(d)
            e["payment_required"]["x402Version"] = v
            with self.assertRaises(want) as cm:
                run(e)
            self.assertEqual(type(cm.exception) is av.Unsupported, want is av.Unsupported, v)
        acc = d["payment_payload"]["accepted"]
        e = copy.deepcopy(d)
        e["payment_required"]["error"] = "payment required"
        self.assertEqual(run(e)["checks"]["K4"], "verified")                 # a string error is allowed
        for k, v in (("error", 99), ("error", ["x"]), ("accepts", []), ("accepts", acc), ("accepts", [5, acc]),
                     ("resource", 5), ("resource", {"url": "u", "zz": 1})):
            e = copy.deepcopy(d)
            e["payment_required"][k] = v
            with self.assertRaises(av.Refusal) as cm:
                run(e)
            self.assertIsNot(type(cm.exception), av.Unsupported, (k, v))


class WireFormat(unittest.TestCase):
    def test_shortvec(self):
        self.assertEqual(sol._shortvec(bytes([0xff, 0xff, 0x03]), 0), (0xFFFF, 3))
        for b in ([0x80, 0x80, 0x04], [0xff, 0xff, 0x7f], [0x80, 0x00], [0x80, 0x80, 0x00]):
            with self.assertRaises(sol.SolRefusal):
                sol._shortvec(bytes(b), 0)

    def test_transaction_size(self):
        k, k2 = bytes(range(32)), bytes(range(1, 33))
        n = 2000
        msg = (bytes([1, 0, 1, 2]) + k + k2 + bytes(32) + bytes([1, 1, 0])
               + bytes([0x80 | (n & 0x7f), n >> 7]) + bytes(n))
        with self.assertRaises(sol.SolRefusal):
            sol.parse_tx(bytes([1]) + bytes(64) + msg)

    def test_ed25519_s_not_reduced(self):
        """RFC 8032 5.1.7: S >= L is rejected (else S + L is a second valid signature: malleable)"""
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701"
                            "cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(sol.ed25519_verify(pk, b"", sig))
        s2 = (int.from_bytes(sig[32:], "little") + sol.L).to_bytes(32, "little")
        self.assertFalse(sol.ed25519_verify(pk, b"", sig[:32] + s2))


class SvmGrammar(unittest.TestCase):
    def refused(self, f):
        d = svm()
        f(d)
        with self.assertRaises(av.Refusal):
            run(d)

    def test_payload_extensions(self):
        self.refused(lambda d: d["payment_payload"].__setitem__("extensions", "x"))

    def test_balances(self):
        self.refused(lambda d: d["chain_tx"]["meta"]["postTokenBalances"][0].__setitem__("accountIndex", 255))
        self.refused(lambda d: d["chain_tx"]["meta"]["preTokenBalances"].append(
            copy.deepcopy(d["chain_tx"]["meta"]["preTokenBalances"][0])))

    def test_inner_index(self):
        def f(d):
            d["chain_tx"]["meta"]["innerInstructions"] = [
                {"index": 0, "instructions": [{"programIdIndex": 200, "accounts": [], "data": ""}]}]
        self.refused(f)

    def test_c3_without_pre_balance(self):
        """an account absent from preTokenBalances held 0 (created by the transaction)"""
        d = svm()
        rep = run(d)
        meta = d["chain_tx"]["meta"]
        post = {b["accountIndex"]: int(b["uiTokenAmount"]["amount"]) for b in meta["postTokenBalances"]}
        pre = {b["accountIndex"]: int(b["uiTokenAmount"]["amount"]) for b in meta["preTokenBalances"]}
        amt = int(d["payment_payload"]["accepted"]["amount"])
        dest = [i for i in post if post[i] - pre.get(i, 0) >= amt and i in pre]
        self.assertTrue(dest and rep["checks"]["C3"] == "verified")
        i = dest[0]
        meta["preTokenBalances"] = [b for b in meta["preTokenBalances"] if b["accountIndex"] != i]
        self.assertEqual(run(d)["checks"]["C3"], "verified")


class L1Grammar(unittest.TestCase):
    def setUp(self):
        d = os.path.join(ROOT, "bundles", "real_v04_l1state")
        with open(os.path.join(d, "MANIFEST.json")) as fh:
            b = json.load(fh)["bundles"][0]
        with open(os.path.join(d, b["file"])) as fh:
            self.d = json.load(fh)

    def refused(self, f):
        d = copy.deepcopy(self.d)
        f(d["canonical"]["l1_state"])
        with self.assertRaises(av.Refusal):
            av.verify_bundle(d)

    def test_bounds(self):
        self.refused(lambda s: s.__setitem__("headers", s["headers"] * 8193))
        # distinct addresses and slots, so that only the bound refuses (not the second-proof rule)
        self.refused(lambda s: s.__setitem__("accounts", [dict(s["accounts"][0], address="0x%040x" % (i + 1),
                                                               storageProof=[]) for i in range(33)]))
        self.refused(lambda s: s["accounts"][0].__setitem__("storageProof", [
            {"key": "0x%064x" % (i + 1), "proof": []} for i in range(65)]))
        self.refused(lambda s: s["accounts"][0]["storageProof"][0].__setitem__("key", "0x12"))

    def test_unread_proof_without_checkpoint_is_not_refused(self):
        """SPEC 0.4 as corrected: the read set is known only with a checkpoint"""
        d = copy.deepcopy(self.d)
        a = d["canonical"]["l1_state"]["accounts"][0]
        a["storageProof"].append({"key": "0x" + "ab" * 32, "proof": a["storageProof"][0]["proof"]})
        self.assertEqual(av.verify_bundle(copy.deepcopy(d))["checks"]["L1"], "not_evaluated:absent:no_l1_checkpoint")


class ReportTools(unittest.TestCase):
    def test_unparsable_resource_url(self):
        d = svm()
        d["payment_payload"]["resource"] = {"url": "http://[bad"}
        out = rp.apply_policy(rp.parse_policy({"apc_policy": 1, "hosts": ["example.com"]}), d, run(d))
        self.assertEqual(out["policy"]["P5"], "failed:resource_url_not_parsable")

    def test_sarif_unsupported_is_a_bundle_error(self):
        log = rp.sarif([("b.json", {"verdict": "unsupported", "reason": "r"})])
        self.assertEqual([r["ruleId"] for r in log["runs"][0]["results"]], ["bundle"])


class McpSurvives(unittest.TestCase):
    def test_internal_error_is_a_reply(self):
        import apc_mcp
        from unittest import mock
        msg = {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "verify_bundle",
                                                                          "arguments": {"bundle_json": "{}"}}}
        with mock.patch.object(apc_mcp, "call", side_effect=RuntimeError("x")):
            self.assertEqual(apc_mcp.handle(msg)["error"]["code"], -32603)

    def test_bad_inputs_do_not_end_the_server(self):
        big = svm()
        big["payment_payload"]["accepted"]["amount"] = BIG
        url = svm()
        url["payment_payload"]["resource"] = {"url": "http://[bad"}

        def call(name, args):
            return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": args}})
        bad = [call("verify_bundle", {"bundle_json": json.dumps(big)}),
               json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": []}}),
               "[" * 100000 + "]" * 100000,
               call("apply_policy", {"policy_json": json.dumps({"apc_policy": 1, "hosts": ["example.com"]}),
                                     "bundle_json": json.dumps(url)})]
        ping = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"})
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        for line in bad:
            p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_mcp.py")], input=line + "\n" + ping + "\n",
                               capture_output=True, text=True, env=env, timeout=600)
            outs = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
            self.assertEqual(p.returncode, 0, p.stderr[-300:])
            self.assertEqual(len(outs), 2)
            self.assertEqual(outs[1], {"jsonrpc": "2.0", "id": 99, "result": {}})


@unittest.skipUnless(CASES, "APC_PULSE_CASES not set")
class Ap2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import apc_ap2
        cls.a2 = apc_ap2
        with open(CASES, "rb") as fh:
            raw = fh.read()
        assert hashlib.sha256(raw).hexdigest() == PULSE_SHA256
        cls.good = [c for c in json.loads(raw)["cases"] if c["expected"]["consistent"]][0]

    def test_big_decimals_decided_not_crashed(self):
        c = copy.deepcopy(self.good)
        c["x402"]["payload"]["payload"]["authorization"]["validAfter"] = BIG
        r = self.a2.verify_case(c)
        self.assertFalse(r["consistent"])
        self.assertIn("EIP3009_VALID_AFTER_IN_FUTURE", r["failureCodes"])
        c = copy.deepcopy(self.good)
        c["x402"]["payload"]["payload"]["authorization"]["value"] = BIG
        self.assertIn("EIP3009_SIGNATURE_INVALID", self.a2.verify_case(c)["failureCodes"])
        c = copy.deepcopy(self.good)
        c["x402"]["requirements"]["network"] = "eip155:" + BIG
        self.assertEqual(self.a2.verify_case(c)["failureCodes"], ["INPUT_SCHEMA_INVALID"])

    def test_fraction_digits_same_on_every_python(self):
        """fromisoformat took only 3 or 6 fraction digits before Python 3.11"""
        a = self.a2._iso("2026-01-01T00:00:00.1Z")
        self.assertEqual(a, self.a2._iso("2026-01-01T00:00:00.100000+00:00"))
        self.assertEqual(self.a2._iso("2026-01-01T00:00:00.1234567Z"), self.a2._iso("2026-01-01T00:00:00.123Z"))
        c = copy.deepcopy(self.good)
        ed = c["ap2"]["closedMandate"]["execution_date"]
        c["ap2"]["closedMandate"]["execution_date"] = ed[:19] + ".1Z"
        self.assertNotIn("INPUT_SCHEMA_INVALID", self.a2.verify_case(c)["failureCodes"])


if __name__ == "__main__":
    unittest.main()
