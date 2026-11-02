"""SPEC 0.6: apc_mcp.py on its real transport (a subprocess speaking JSON-RPC 2.0 on stdin/stdout, as an MCP client
starts it), with real bundles: the reports equal apc_verify's; refusals, unknown tools and bad requests fail closed."""
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm", "real_v04_l1state")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402

SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")
L1 = os.path.join(ROOT, "bundles", "real_v04_l1state", "v001_b001_indirect_l1state.json")


def text(p):
    with open(p) as fh:
        return fh.read()


def session(messages):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    lines = "".join((m if isinstance(m, str) else json.dumps(m)) + "\n" for m in messages)
    r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_mcp.py")], input=lines, capture_output=True,
                       text=True, env=env, timeout=600)
    assert r.returncode == 0, r.stderr
    return [json.loads(x) for x in r.stdout.splitlines()]


def call(i, name, args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


class Mcp(unittest.TestCase):
    def test_handshake_and_list(self):
        out = session([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                       {"jsonrpc": "2.0", "method": "notifications/initialized"},
                       {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                       {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}},
                       {"jsonrpc": "2.0", "id": 4, "method": "ping"}])
        self.assertEqual([m["id"] for m in out], [1, 2, 3, 4])          # the notification got no reply
        self.assertEqual(out[0]["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(out[2]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(sorted(t["name"] for t in out[1]["result"]["tools"]), ["apply_policy", "verify_bundle"])
        self.assertEqual(out[3]["result"], {})

    def test_reports_equal_the_cli(self):
        cp = json.load(open(os.path.join(ROOT, "bundles", "real_v04_l1state", "MANIFEST.json")))["bundles"][0]["checkpoint"]
        out = session([call(1, "verify_bundle", {"bundle_json": text(SVM)}),
                       call(2, "verify_bundle", {"bundle_json": text(L1), "l1_checkpoint": cp}),
                       call(3, "verify_bundle", {"bundle_json": text(L1)})])
        r = [json.loads(m["result"]["content"][0]["text"]) for m in out]
        self.assertEqual(r[0], av.verify_bundle(av.strict_json(text(SVM))))
        self.assertEqual((r[1]["l1_state"], r[2]["l1_state"]), ("proven", "not_shown"))
        self.assertEqual(r[1], av.verify_bundle(av.strict_json(text(L1)), cp))
        self.assertFalse(any(m["result"]["isError"] for m in out))

    def test_policy(self):
        doc = av.strict_json(text(SVM))
        a = doc["payment_payload"]["accepted"]
        pol = json.dumps({"apc_policy": 1, "assets": [a["asset"]], "max_amount": {a["asset"]: "1"}})
        out = session([call(1, "apply_policy", {"policy_json": pol, "bundle_json": text(SVM)}),
                       call(2, "apply_policy", {"policy_json": "{\"apc_policy\": 2}", "bundle_json": text(SVM)})])
        r = json.loads(out[0]["result"]["content"][0]["text"])
        self.assertEqual((r["policy"]["P2"], r["policy"]["P3"], r["policy_verdict"]),
                         ("verified", "failed:amount_above_cap", "policy_failed"))
        self.assertTrue(out[1]["result"]["isError"])
        self.assertEqual(json.loads(out[1]["result"]["content"][0]["text"])["verdict"], "refused")

    def test_fail_closed(self):
        dup = text(SVM).replace('"bundle_version"', '"bundle_version": "apc-0.5", "bundle_version"', 1)
        out = session([call(1, "verify_bundle", {"bundle_json": dup}),
                       call(2, "verify_bundle", {"bundle_json": text(SVM), "zz": 1}),
                       call(3, "verify_bundle", {"bundle_json": 5}),
                       call(4, "verify_bundle", {"bundle_json": text(L1), "l1_checkpoint": "0x12"}),
                       call(5, "nope", {}),
                       {"jsonrpc": "2.0", "id": 6, "method": "resources/list"},
                       "not json",
                       {"id": 7, "method": "ping"},
                       call(8, "verify_bundle", {"bundle_json": "{\"bundle_version\": \"apc-0.9\"}"})])
        by = {m["id"]: m for m in out}
        self.assertTrue(by[1]["result"]["isError"])
        self.assertIn("duplicate member", json.loads(by[1]["result"]["content"][0]["text"])["reason"])
        self.assertEqual([by[i]["error"]["code"] for i in (2, 3, 4, 5, 6)], [-32602, -32602, -32602, -32602, -32601])
        self.assertEqual([m["error"]["code"] for m in out if m["id"] is None], [-32700, -32600])
        self.assertEqual(json.loads(by[8]["result"]["content"][0]["text"])["verdict"], "refused")


if __name__ == "__main__":
    unittest.main()
