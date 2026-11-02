"""Second review of apc_verify 0.7.1 (independent review, 2026-10-26): inputs that still crashed instead of being refused (a line
that is not UTF-8 on the MCP server; a mandate case with caseVersion or frequency not a string, or an unparsable URL),
and the profile's date-time (zod 4.4.3 z.string().datetime({ offset: true }) read by Date.parse), whose expected values
below were printed by node 22.23.2 (Date.parse), not by this code."""
import copy
import hashlib
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_ap2 as a2  # noqa: E402
import apc_verify as av  # noqa: E402

CASES = os.environ.get("APC_PULSE_CASES")
PULSE_SHA256 = "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"


class McpNotUtf8(unittest.TestCase):
    def test_not_utf8_line_is_a_parse_error(self):
        env = dict(os.environ, PYTHONIOENCODING="utf-8:strict")        # a strict UTF-8 stdin, as en_US.UTF-8 gives
        env.pop("PYTHONPATH", None)
        data = b'{"jsonrpc":"2.0","id":1,"method":"ping\xff"}\n\xc3\n{"jsonrpc":"2.0","id":99,"method":"ping"}\n'
        p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_mcp.py")], input=data, capture_output=True,
                           env=env, timeout=120)
        outs = [json.loads(x) for x in p.stdout.decode().splitlines() if x.strip()]
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertEqual([o.get("error", {}).get("code") for o in outs[:2]], [-32700, -32700])
        self.assertEqual(outs[2], {"jsonrpc": "2.0", "id": 99, "result": {}})


class DateTime(unittest.TestCase):
    def test_profile_grammar(self):
        for s in ("2026-01-01T00:00Z", "0000-01-01T00:00:00Z", "2024-02-29T23:59:59.9-23:59", "2000-02-29T00:00Z",
                  "2026-07-21T00:00+05:30"):
            a2._datetime(s, "p")                                    # zod accepts each
        for s in ("2026-01-01T24:00:00Z", "2026-01-01T24:00Z", "1900-02-29T00:00:00Z", "2026-01-01T00:00:60Z",
                  "2026-01-01T00:60Z", "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+0530", "2026-01-01T00:00:00",
                  "2026-01-01t00:00:00Z", "2026-01-01T00:00:00z", "２026-01-01T00:00:00Z", "2026-01-01T00:00:00.Z"):
            with self.assertRaises(a2.SchemaError, msg=s):          # zod refuses each
                a2._datetime(s, "p")

    def test_read_as_date_parse(self):
        for s, want in (("2026-01-01T00:00:00.1239Z", 1767225600123), ("2026-01-01T00:00:00.1231Z", 1767225600123),
                        ("0000-01-01T00:00:00Z", -62167219200000), ("2026-01-01T00:00Z", 1767225600000),
                        ("2026-07-21T00:00+05:30", 1784572200000), ("2024-02-29T23:59:59.9-23:59", 1709337539900),
                        ("1969-12-31T23:59:59.999Z", -1)):
            self.assertEqual(a2._ts(s), want, s)


class Bounds(unittest.TestCase):
    def test_policy_cap_79_digits_refused(self):
        import apc_report as rp
        rp.parse_policy({"apc_policy": 1, "max_amount": {"x": "9" * 78}})
        with self.assertRaises(rp.Bad):
            rp.parse_policy({"apc_policy": 1, "max_amount": {"x": "9" * 79}})

    def test_settlement_amount_without_a_single_matching_transfer(self):
        with open(os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")) as fh:
            d = json.load(fh)
        st_amount = str(int(d["payment_payload"]["accepted"]["amount"]))
        d["settlement"]["amount"] = st_amount
        d["payment_payload"]["accepted"]["amount"] = str(int(st_amount) + 1)     # no transfer pays that much
        r = av.verify_bundle(d)
        self.assertEqual(r["checks"]["S2"], "failed:no_matching_transfer")
        self.assertEqual(r["checks"]["T1"], "verified")
        self.assertIn("T1: settlement.amount not compared (no single matching transfer)", r["notes"])


    def test_pending_settlement_stays_pending_with_another_payer(self):
        """the payer comparison reads only a verified T1: a pending reply stays not_evaluated, not failed"""
        with open(os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")) as fh:
            d = json.load(fh)
        d["settlement"].update(success=False, errorReason="settlement_pending", payer="1" * 32)
        r = av.verify_bundle(d)
        self.assertEqual((r["verdict"], r["checks"]["T1"]), ("chain_incomplete", "not_evaluated:settlement_pending"))

    def test_transaction_size_boundary(self):
        import apc_solana as sol
        k, k2 = bytes(range(32)), bytes(range(1, 33))
        for n, refused in ((1062, False), (1063, True)):                       # 1232 and 1233 bytes
            msg = (bytes([1, 0, 1, 2]) + k + k2 + bytes(32) + bytes([1, 1, 0])
                   + bytes([0x80 | (n & 0x7f), n >> 7]) + bytes(n))
            raw = bytes([1]) + bytes(64) + msg
            if refused:
                with self.assertRaises(sol.SolRefusal) as cm:
                    sol.parse_tx(raw)
                self.assertEqual(str(cm.exception), "transaction_larger_than_1232_bytes")
            else:
                self.assertEqual(len(raw), 1232)
                sol.parse_tx(raw)


@unittest.skipUnless(CASES, "APC_PULSE_CASES not set")
class MandateCrashes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CASES, "rb") as fh:
            raw = fh.read()
        assert hashlib.sha256(raw).hexdigest() == PULSE_SHA256
        cls.good = [c for c in json.loads(raw)["cases"] if c["expected"]["consistent"]][0]

    def cases(self):
        def one(f):
            c = copy.deepcopy(self.good)
            f(c)
            return c
        cm = lambda c: c["ap2"]["closedMandate"]                                   # noqa: E731
        yield "caseVersion list", one(lambda c: c.__setitem__("caseVersion", [1]))
        yield "caseVersion object", one(lambda c: c.__setitem__("caseVersion", {"a": 1}))
        yield "payee.website", one(lambda c: cm(c)["payee"].__setitem__("website", "http://[bad"))
        yield "frequency list", one(lambda c: c["ap2"]["openMandate"]["constraints"].append(
            {"type": "payment.agent_recurrence", "frequency": ["DAILY"]}))

    def test_schema_invalid_not_crashed(self):
        for name, c in self.cases():
            self.assertEqual(a2.verify_case(c)["failureCodes"], ["INPUT_SCHEMA_INVALID"], name)

    def test_bundle_refused_not_crashed(self):
        for name, c in self.cases():
            d = {"bundle_version": "apc-0.1", "payment_payload": copy.deepcopy(c["x402"]["payload"]),
                 "mandate": {"profile": "pulse-ap2-x402/0.3", "case": c}}
            with self.assertRaises(av.Refusal, msg=name):
                av.verify_bundle(d)


if __name__ == "__main__":
    unittest.main()
