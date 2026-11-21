"""SPEC section 8 (Amendment 0.21.6, Unreleased): apc_mcp.py as a dual-era MCP server on its real stdio transport. A
client per era, its messages written from the specification read 2026-11-21 (modelcontextprotocol/modelcontextprotocol
main 2f3a950): 2026-07-28 (server/discover, version and capabilities in each request's _meta, resultType, ttlMs and
cacheScope, -32022), 2025-11-25 (initialize; input validation errors are tool execution errors), 2025-06-18 and
earlier (initialize; -32602 as before). No real corpus: the bundle is the x402 http.md example payment of
sources/http_20261025. Positive control: on 3fe46aa (before this amendment) 8 of these 9 tests fail; the one that passes
there checks what does not change (2025-06-18 and earlier keep -32602 for invalid arguments)."""
import json
import os
import random
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODERN = "2026-07-28"


def session(messages):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    lines = "".join((m if isinstance(m, str) else json.dumps(m)) + "\n" for m in messages)
    p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_mcp.py")], input=lines.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=300)
    if p.returncode == 64:
        raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f))")
    assert p.returncode == 0, p.stderr[-300:]
    return [json.loads(x) for x in p.stdout.decode().splitlines()]


def md_bundle_text():
    with open(os.path.join(ROOT, "sources", "http_20261025", "http.md")) as fh:
        md = fh.read()
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", md, re.S)]
    return json.dumps({"bundle_version": "apc-0.3", "payment_payload": blocks[1], "payment_required": blocks[0],
                       "settlement": blocks[2]})


def meta(version=MODERN, caps=True):
    m = {"io.modelcontextprotocol/protocolVersion": version,
         "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"}}
    if caps:
        m["io.modelcontextprotocol/clientCapabilities"] = {}
    return m


def modern(i, method, params=None, **kw):
    p = dict(params or {})
    p["_meta"] = meta(**kw)
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": p}


def legacy(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return m


def init(i, version):
    return legacy(i, "initialize", {"protocolVersion": version, "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "0"}})


class ModernClient(unittest.TestCase):
    def test_discover_list_call(self):
        good = {"name": "verify_bundle", "arguments": {"bundle_json": md_bundle_text()}}
        out = session([modern(1, "server/discover"), modern(2, "tools/list"), modern(3, "tools/call", good),
                       modern(4, "tools/call", {"name": "verify_bundle", "arguments": {"bundle_json": 5}}),
                       modern(5, "tools/call", {"name": "nope", "arguments": {}})])
        by = {m["id"]: m for m in out}
        d = by[1]["result"]
        self.assertEqual((d["resultType"], d["supportedVersions"], d["capabilities"], d["ttlMs"], d["cacheScope"]),
                         ("complete", [MODERN], {"tools": {}}, 3600000, "public"))
        self.assertEqual(sorted(d["_meta"]), ["io.modelcontextprotocol/serverInfo"])
        self.assertEqual(d["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "agent-payment-chain")
        t = by[2]["result"]
        self.assertEqual((t["resultType"], t["ttlMs"], t["cacheScope"], sorted(x["name"] for x in t["tools"])),
                         ("complete", 3600000, "public", ["apply_policy", "verify_bundle"]))
        c = by[3]["result"]
        self.assertEqual((c["resultType"], c["isError"], json.loads(c["content"][0]["text"])["verdict"]),
                         ("complete", False, "chain_verified"))
        self.assertIn("io.modelcontextprotocol/serverInfo", c["_meta"])
        e = by[4]["result"]                              # input validation: a tool execution error (server/tools)
        self.assertEqual((e["resultType"], e["isError"]), ("complete", True))
        self.assertTrue(e["content"][0]["text"].startswith("invalid arguments: bundle_json"))
        self.assertEqual(by[5]["error"]["code"], -32602)

    def test_no_initialize_needed_and_removed_methods(self):
        out = session([modern(1, "tools/list"), modern(2, "initialize", {"protocolVersion": MODERN}),
                       modern(3, "ping"), modern(4, "logging/setLevel", {"level": "info"}),
                       modern(5, "resources/list")])
        self.assertEqual(out[0]["result"]["resultType"], "complete")
        self.assertEqual([m["error"]["code"] for m in out[1:]], [-32601] * 4)

    def test_version_and_meta_errors(self):
        out = session([modern(1, "tools/list", version="2099-01-01"), modern(2, "tools/list", version="2025-11-25"),
                       modern(3, "server/discover", version=7), modern(4, "tools/list", caps=False),
                       {"jsonrpc": "2.0", "id": 5, "method": "tools/list",
                        "params": {"_meta": dict(meta(), **{"io.modelcontextprotocol/clientCapabilities": []})}}])
        self.assertEqual(out[0]["error"], {"code": -32022, "message": "Unsupported protocol version",
                                           "data": {"supported": [MODERN], "requested": "2099-01-01"}})
        self.assertEqual(out[1]["error"]["data"], {"supported": [MODERN], "requested": "2025-11-25"})
        self.assertEqual([m["error"]["code"] for m in out[2:]], [-32602] * 3)


class LegacyClients(unittest.TestCase):
    def test_nothing_but_ping_before_initialize(self):
        out = session([legacy(1, "tools/list"), legacy(2, "tools/call", {"name": "verify_bundle",
                                                                          "arguments": {"bundle_json": "{}"}}),
                       legacy(3, "server/discover"), legacy(4, "ping"), init(5, "2025-06-18"), legacy(6, "tools/list"),
                       legacy(7, "server/discover")])
        self.assertEqual([m.get("error", {}).get("code") for m in out], [-32600, -32600, -32600, None, None, None,
                                                                          -32601])
        self.assertEqual(out[3]["result"], {})
        self.assertNotIn("resultType", out[5]["result"])

    def test_2025_11_25_input_errors_are_tool_errors(self):
        bad = {"name": "verify_bundle", "arguments": {"bundle_json": md_bundle_text(), "zz": 1}}
        good = {"name": "verify_bundle", "arguments": {"bundle_json": md_bundle_text()}}
        out = session([init(1, "2025-11-25"), legacy(2, "tools/call", bad), legacy(3, "tools/call", good)])
        self.assertEqual(out[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(out[1]["result"], {"content": [{"type": "text", "text": "invalid arguments: arguments: "
                                                         "unknown member(s)"}], "isError": True})
        self.assertEqual((out[2]["result"]["isError"], "resultType" in out[2]["result"]), (False, False))

    def test_older_revisions_keep_protocol_errors(self):
        bad = {"name": "verify_bundle", "arguments": {"bundle_json": md_bundle_text(), "zz": 1}}
        for v in ("2025-06-18", "2025-03-26", "2024-11-05"):
            out = session([init(1, v), legacy(2, "tools/call", bad)])
            self.assertEqual((out[0]["result"]["protocolVersion"], out[1]["error"]["code"]), (v, -32602), v)

    def test_unknown_or_modern_version_in_initialize(self):
        for asked in ("2026-07-28", "1999-01-01", None, 5, ["2025-06-18"], {"v": 1}):
            out = session([init(1, asked)])
            self.assertEqual(out[0]["result"]["protocolVersion"], "2025-11-25", asked)

    def test_both_eras_on_one_process(self):
        out = session([init(1, "2025-06-18"), modern(2, "tools/list"), legacy(3, "tools/list"),
                       modern(4, "tools/call", {"name": "verify_bundle", "arguments": {"bundle_json": 5}}),
                       legacy(5, "tools/call", {"name": "verify_bundle", "arguments": {"bundle_json": 5}})])
        self.assertEqual(out[1]["result"]["resultType"], "complete")
        self.assertNotIn("resultType", out[2]["result"])
        self.assertTrue(out[3]["result"]["isError"])     # modern: a tool error
        self.assertEqual(out[4]["error"]["code"], -32602)  # legacy 2025-06-18: a protocol error


class Generated(unittest.TestCase):
    def test_every_request_gets_one_reply_and_tools_are_served_only_in_an_era(self):
        rng = random.Random(20261121)
        vals = [MODERN, "2025-11-25", "2025-06-18", "x", 7, None, [], {}]
        msgs, kinds = [], []
        for i in range(400):
            method = rng.choice(["tools/list", "tools/call", "server/discover", "ping", "initialize", "nope"])
            params = {"name": "verify_bundle", "arguments": {"bundle_json": "{}"}} if method == "tools/call" else {}
            shape = rng.randrange(5)
            if shape == 0:
                params["_meta"] = {"io.modelcontextprotocol/protocolVersion": rng.choice(vals),
                                   "io.modelcontextprotocol/clientCapabilities": rng.choice([{}, [], None, "x"])}
            elif shape == 1:
                params["_meta"] = rng.choice([[], "x", 5, None, {"other": 1}])
            elif shape == 2 and method == "initialize":
                params["protocolVersion"] = rng.choice(vals)
            msgs.append({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
            m = params.get("_meta")
            kinds.append("modern" if isinstance(m, dict) and "io.modelcontextprotocol/protocolVersion" in m
                         else "legacy")
        out = session(msgs)
        self.assertEqual([m["id"] for m in out], list(range(400)))
        initialized = False
        for msg, kind, r in zip(msgs, kinds, out):
            self.assertEqual(sorted(r), sorted(["jsonrpc", "id", "result" if "result" in r else "error"]))
            m = msg["params"].get("_meta")
            if kind == "modern":
                ok_meta = isinstance(m["io.modelcontextprotocol/protocolVersion"], str) and \
                    isinstance(m["io.modelcontextprotocol/clientCapabilities"], dict)
                if not ok_meta:
                    self.assertEqual(r["error"]["code"], -32602)
                elif m["io.modelcontextprotocol/protocolVersion"] != MODERN:
                    self.assertEqual(r["error"]["code"], -32022)
                elif msg["method"] in ("tools/list", "tools/call", "server/discover"):
                    self.assertEqual(r["result"]["resultType"], "complete")
                else:
                    self.assertEqual(r["error"]["code"], -32601)
            else:
                if msg["method"] == "initialize":
                    initialized = True
                    self.assertIn(r["result"]["protocolVersion"], ("2025-11-25", "2025-06-18"))
                elif msg["method"] == "ping":
                    self.assertEqual(r["result"], {})
                elif not initialized:
                    self.assertEqual(r["error"]["code"], -32600)
                elif msg["method"] in ("tools/list", "tools/call"):
                    self.assertIn("result", r)
                    self.assertNotIn("resultType", r["result"])
                else:
                    self.assertEqual(r["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
