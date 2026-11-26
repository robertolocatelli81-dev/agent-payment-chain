"""apc_mcp.py (SPEC section 8), defects re-measured on edec562 on 2026-11-20: a message line holding NaN, Infinity or
-Infinity, which are not JSON (RFC 8259 6), was read as JSON (SPEC section 8: a line that is not JSON is a parse error,
-32700) and an id NaN was echoed, so the reply was not JSON either; an id that is a boolean, an object or an array was
echoed (JSON-RPC 2.0 section 4: String, Number or Null; MCP basic, 2025-06-18: a string or an integer, never null).
The server runs on its real stdio transport; no real corpus is needed."""
import json
import os
import random
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def session(lines):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, os.path.join(ROOT, "apc_mcp.py")], input="".join(l + "\n" for l in lines).encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=300)
    if p.returncode == 64:
        raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f)): %s" % p.stderr.decode()[:200])
    return p.returncode, p.stdout.decode().splitlines()


def strict(text):
    def refuse(c):
        raise ValueError("not JSON: %s" % c)
    return json.loads(text, parse_constant=refuse)


class McpLinesAndIds(unittest.TestCase):
    def test_non_json_constants_are_a_parse_error(self):
        lines = ['{"jsonrpc":"2.0","id":NaN,"method":"ping"}', '{"jsonrpc":"2.0","id":Infinity,"method":"ping"}',
                 '{"jsonrpc":"2.0","id":-Infinity,"method":"ping"}', '{"jsonrpc":"2.0","id":7,"method":"ping","params":{"x":NaN}}',
                 '{"jsonrpc":"2.0","id":8,"method":"tools/list","params":{"a":[1,{"b":-Infinity}]}}']
        rc, out = session(lines)
        self.assertEqual(rc, 0)
        self.assertEqual(len(out), len(lines))
        for line in out:
            r = strict(line)
            self.assertIsNone(r["id"])
            self.assertEqual(r["error"]["code"], -32700)

    def test_ids_outside_string_or_integer_are_an_invalid_request(self):
        bad = ["true", "false", "null", "1.5", "1.0", "1e2", "1e999", "{}", '{"a":1}', "[]", "[1]"]
        good = ["1", "0", "-3", '"a"', '""', "9007199254740993"]
        rc, out = session(['{"jsonrpc":"2.0","id":%s,"method":"ping"}' % i for i in bad + good])
        self.assertEqual(rc, 0)
        self.assertEqual(len(out), len(bad) + len(good))
        for i, line in zip(bad, out[:len(bad)]):
            r = strict(line)
            self.assertEqual((r["id"], r["error"]["code"]), (None, -32600), i)
        for i, line in zip(good, out[len(bad):]):
            r = strict(line)
            self.assertEqual(r, {"jsonrpc": "2.0", "id": json.loads(i), "result": {}}, i)

    def test_a_repeated_member_is_an_invalid_request(self):
        rc, out = session(['{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
                           '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"a":1,"a":2}}',
                           '{"jsonrpc":"2.0","id":5,"method":"ping","z":1,"z":2}',
                           '{"jsonrpc":"2.0","id":4,"method":"ping"}'])
        self.assertEqual([strict(l).get("error", {}).get("code") for l in out], [-32600, -32600, -32600, None])
        self.assertEqual(strict(out[2])["error"]["message"], "invalid request: member repeated: z")   # the name repeated
        self.assertEqual(strict(out[3])["id"], 4)

    def test_a_line_that_is_not_json_is_a_parse_error_wherever_a_repeated_member_stands(self):
        rc, out = session(['{"jsonrpc":"2.0","id":1,"method":"ping","p":{"a":1,"a":2},"q":NaN}',
                           '{"jsonrpc":"2.0","id":1,"method":"ping","q":NaN,"p":{"a":1,"a":2}}',
                           '{"jsonrpc":"2.0","id":1,"method":"ping","p":{"a":1,"a":2}} trailing',
                           '{"jsonrpc":"2.0","id":1,"p":{"a":1,"a":2},',
                           '{"jsonrpc":"2.0","id":1,"method":"ping","p":{"b":1,"b":2},"a":1,"a":2}'])
        self.assertEqual(rc, 0)
        self.assertEqual([strict(l)["error"]["code"] for l in out], [-32700, -32700, -32700, -32700, -32600])
        self.assertEqual(strict(out[4])["error"]["message"], "invalid request: member repeated: a")
        self.assertTrue(all(strict(l)["id"] is None for l in out))
        rc, out = session(['{"jsonrpc":"2.0","id":1,"method":"ping","%s":1,"%s":2}' % ("n" * 200, "n" * 200)])
        self.assertEqual(strict(out[0])["error"]["message"], "invalid request: member repeated: (a name of 200 characters, not repeated)")   # SPEC 32.17 (c)

    def test_finding_a_repeated_member_takes_time_linear_in_the_line(self):
        # measured on 3ae909a: 20000, 40000 and 80000 distinct names and one repeat took 10.5 s, 35.1 s and 166.7 s
        # (names.count once per name); the same lines without the repeat 0.09-0.15 s
        import time
        def line(n):
            return ('{"jsonrpc":"2.0","id":1,"method":"ping","p":{' + ",".join('"k%d":1' % i for i in range(n))
                    + ',"k0":2}}')
        t = time.time()
        rc, out = session([line(80000)])
        self.assertEqual((rc, strict(out[0])["error"]["code"]), (0, -32600))
        self.assertLess(time.time() - t, 30)
        self.assertEqual(strict(out[0])["error"]["message"], "invalid request: member repeated: k0")

    def test_generated_messages_always_get_a_json_reply_with_an_admitted_id(self):
        rnd = random.Random(20261120)
        ids = ["1", "42", '"x"', "true", "null", "2.5", "[1]", '{"k":0}', "NaN", "Infinity", "-Infinity", None]
        methods = ['"ping"', '"tools/list"', '"nope"', "1", "null"]
        lines, expect = [], []
        for _ in range(300):
            i = rnd.choice(ids)
            meth = rnd.choice(methods)
            members = ['"jsonrpc":"2.0"', '"method":%s' % meth]
            if i is not None:
                members.append('"id":%s' % i)
            extra = rnd.choice(["", ',"params":{"v":%s}' % rnd.choice(["1", "NaN", "-Infinity", '"s"']), ',"params":{"d":1,"d":2}'])
            rnd.shuffle(members)
            lines.append("{" + ",".join(members) + extra + "}")
            nonjson = i in ("NaN", "Infinity", "-Infinity") or "NaN" in extra or "Infinity" in extra
            dup = '"d":1,"d":2' in extra
            # a method that is not a string is not a Request object: -32600 id null, with or without an id (JSON-RPC
            # 2.0 section 4 and its example; SPEC 8, Amendment 0.21.6)
            expect.append("parse" if nonjson else "dup" if dup else "badid" if meth in ("1", "null")
                          else "notification" if i is None else "badid" if i not in ("1", "42", '"x"') else "ok")
        rc, out = session(lines)
        self.assertEqual(rc, 0)
        replies = iter(out)
        for line, e in zip(lines, expect):
            if e == "notification":
                continue
            r = strict(next(replies))
            self.assertTrue(r["id"] is None or isinstance(r["id"], str) or type(r["id"]) is int, line)
            if e == "parse":
                self.assertEqual((r["id"], r["error"]["code"]), (None, -32700), line)
            elif e in ("dup", "badid"):
                self.assertEqual((r["id"], r["error"]["code"]), (None, -32600), line)
            else:
                self.assertEqual(r["id"], json.loads(line)["id"], line)
        self.assertIsNone(next(replies, None))


class McpRevisions(unittest.TestCase):
    """SPEC section 8 (Amendment 0.21.6): a dual-era server, 2026-07-28 by _meta, 2025-11-25 to 2024-11-05 by
    initialize (tests/test_mcp_eras_20261121.py for the rest)."""

    def test_initialize_answers_a_legacy_revision_and_discover_with_meta_is_modern(self):
        rc, out = session(['{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":'
                           '{"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
                           '"io.modelcontextprotocol/clientCapabilities":{}}}}',
                           '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}',
                           '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}',
                           '{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'])
        self.assertEqual(rc, 0)
        r = [strict(x) for x in out]
        self.assertEqual((r[0]["id"], r[0]["result"]["supportedVersions"], r[0]["result"]["resultType"]),
                         (1, ["2026-07-28"], "complete"))
        self.assertEqual([x["result"]["protocolVersion"] for x in r[1:]], ["2025-11-25", "2025-11-25", "2025-06-18"])

    def test_the_list_is_the_one_measured(self):
        env_ok = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import apc_mcp; "
                                 "print(','.join(apc_mcp.PROTOCOLS))" % ROOT], capture_output=True, text=True,
                                env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"}, timeout=120)
        if env_ok.returncode == 64:
            raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f))")
        self.assertEqual(env_ok.stdout.strip(), "2026-07-28,2025-11-25,2025-06-18,2025-03-26,2024-11-05")

if __name__ == "__main__":
    unittest.main()
