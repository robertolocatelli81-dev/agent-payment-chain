"""SPEC section 8 (Amendment 0.21.6): JSON-RPC batches, served only on a session whose initialize
negotiated MCP 2025-03-26 (2025-03-26 basic: implementations "MUST support receiving JSON-RPC batches"; lifecycle:
"The initialize request MUST NOT be part of a JSON-RPC batch"; 2025-06-18 removed batching). Replies as JSON-RPC 2.0
section 6 says and the examples of its section 7 show ([] -> one -32600; [1] -> [-32600]; no reply for notifications,
no empty array). The server on its real stdio transport; no real corpus. Positive control: on ad0facc (before batches)
every test of this file that sends a batch on a 2025-03-26 session fails (5 of the 6). The last two tests fail when
the replies of a batch are held in a list and written together, or when an object without "jsonrpc": "2.0" that
names initialize or a protocol version is taken for a notification (review of 2026-11-21)."""
import json
import os
import random
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PV = "io.modelcontextprotocol/protocolVersion"


def session(lines):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    data = "".join(json.dumps(x) + "\n" for x in lines)
    p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_mcp.py")], input=data.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=300)
    if p.returncode == 64:
        raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f))")
    assert p.returncode == 0, p.stderr[-300:]
    return [json.loads(x) for x in p.stdout.decode().splitlines()]


def init(i, v):
    return {"jsonrpc": "2.0", "id": i, "method": "initialize", "params": {"protocolVersion": v, "capabilities": {},
                                                                          "clientInfo": {"name": "t", "version": "0"}}}


def req(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return m


NOTE = {"jsonrpc": "2.0", "method": "notifications/initialized"}
BAD_ARGS = {"name": "verify_bundle", "arguments": {"bundle_json": 5}}
MODERN = {"_meta": {PV: "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}


class Batches(unittest.TestCase):
    def test_a_batch_on_2025_03_26(self):
        b = [req(1, "ping"), req(2, "tools/list"), NOTE, req(3, "tools/call", BAD_ARGS), req(4, "nope"), 1,
             {"foo": "boo"}, init(5, "2025-03-26"), req(6, "tools/list", MODERN), dict(init(7, "x"), id=True),
             {"jsonrpc": "2.0", "method": "initialize"},
             req(11, "tools/list", {"_meta": {"progressToken": "t"}})]        # a _meta without a version: legacy
        out = session([init(0, "2025-03-26"), b, req(8, "ping")])
        self.assertEqual(out[0]["result"]["protocolVersion"], "2025-03-26")
        r = out[1]
        self.assertIsInstance(r, list)
        self.assertEqual([x.get("id") for x in r], [1, 2, 3, 4, None, None, 5, 6, None, 11])
        self.assertEqual(r[0], {"jsonrpc": "2.0", "id": 1, "result": {}})
        self.assertEqual(sorted(t["name"] for t in r[1]["result"]["tools"]), ["apply_policy", "verify_bundle"])
        self.assertEqual([x.get("error", {}).get("code") for x in r[2:9]],
                         [-32602, -32601, -32600, -32600, -32600, -32600, -32600])
        self.assertEqual(sorted(t["name"] for t in r[9]["result"]["tools"]), ["apply_policy", "verify_bundle"])
        self.assertEqual(out[2], {"jsonrpc": "2.0", "id": 8, "result": {}})
        self.assertEqual(len(out), 3)

    def test_the_examples_of_json_rpc_section_7(self):
        out = session([init(0, "2025-03-26"), [], [1], [1, 2, 3], [NOTE, NOTE], [[req(9, "ping")]], req(10, "ping")])
        self.assertEqual(out[1], {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32600, "message": "invalid request: an empty batch"}})
        self.assertEqual([x["error"]["code"] for x in out[2]], [-32600])
        self.assertEqual([(x["id"], x["error"]["code"]) for x in out[3]], [(None, -32600)] * 3)
        # [NOTE, NOTE] gets no reply at all; a nested array is a member that is not an object
        self.assertEqual([(x["id"], x["error"]["code"]) for x in out[4]], [(None, -32600)])
        self.assertEqual(out[5], {"jsonrpc": "2.0", "id": 10, "result": {}})
        self.assertEqual(len(out), 6)

    def test_no_batch_outside_2025_03_26(self):
        b = [req(1, "ping"), req(2, "tools/list")]
        for opening in ([], [init(0, "2025-06-18")], [init(0, "2025-11-25")], [init(0, "2024-11-05")],
                        [init(0, "2025-03-26"), init(9, "2025-06-18")]):
            out = session(opening + [b])
            self.assertEqual(out[-1], {"jsonrpc": "2.0", "id": None, "error": {"code": -32600,
                                                                               "message": "invalid request"}}, opening)

    def test_generated_batches_answer_as_the_members_alone(self):
        rng = random.Random(20261121)
        pool = [lambda i: req(i, "ping"), lambda i: req(i, "tools/list"), lambda i: NOTE,
                lambda i: req(i, "tools/call", BAD_ARGS), lambda i: req(i, "tools/call", {"name": 7}),
                lambda i: req(i, "nope"), lambda i: req(i, "server/discover"), lambda i: {"jsonrpc": "1.0", "id": i},
                lambda i: req(None, "ping"), lambda i: req(i, "initialize"), lambda i: req(i, "tools/list", MODERN),
                lambda i: rng.choice([1, "x", None, [], {}])]
        batches = [[rng.choice(pool)(i * 100 + j) for j in range(rng.randint(1, 6))] for i in range(60)]

        def batched_only(m):                            # answered -32600 in a batch; alone it would change the session
            return isinstance(m, dict) and (m.get("method") == "initialize" or m.get("params") == MODERN)

        def notification(m):
            return isinstance(m, dict) and "id" not in m and "method" in m and m.get("jsonrpc") == "2.0"
        alone = [m for b in batches for m in b if not batched_only(m)]
        out_b = session([init(0, "2025-03-26")] + batches)[1:]
        out_a = iter(session([init(0, "2025-03-26")] + alone)[1:])
        got = iter(out_b)
        for b in batches:
            want = []
            for m in b:
                if batched_only(m):
                    want.append((m["id"], -32600, False))
                elif not notification(m):
                    r = next(out_a)
                    want.append((r.get("id"), r.get("error", {}).get("code"), "result" in r))
            if not want:
                continue
            g = next(got)
            self.assertIsInstance(g, list, b)
            self.assertEqual([(x.get("id"), x.get("error", {}).get("code"), "result" in x) for x in g], want, b)
        self.assertIsNone(next(out_a, None))
        self.assertIsNone(next(got, None))

    def test_an_object_that_is_not_json_rpc_2_0_is_answered_as_alone(self):
        """JSON-RPC 2.0 section 7, "rpc call with invalid Request object": -32600 with id null. Such an object is not a
        notification, whatever method or _meta it carries; with "jsonrpc": "2.0" and no id it is one."""
        odd = [{"method": "initialize"}, {"foo": 1, "params": MODERN}, {"jsonrpc": "1.0", "method": "initialize"},
               {"id": 3, "method": "initialize"}, {"jsonrpc": "1.0", "id": 4, "method": "tools/list", "params": MODERN}]
        alone = session([init(0, "2025-03-26")] + odd)[1:]
        bad = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        self.assertEqual(alone, [bad] * 5)
        out = session([init(0, "2025-03-26"), odd, [odd[0]], [odd[0], NOTE],
                       [{"jsonrpc": "2.0", "method": "initialize"}, {"jsonrpc": "2.0", "method": "x", "params": MODERN}],
                       odd[:1] + [init(5, "2025-06-18")], [req(6, "ping")]])[1:]
        self.assertEqual(out[0], [bad] * 5)
        self.assertEqual(out[1], [bad])
        self.assertEqual(out[2], [bad])
        # the two JSON-RPC 2.0 notifications get no reply; initialize in a batch is refused and negotiates nothing
        self.assertEqual([(x["id"], x["error"]["code"]) for x in out[3]], [(None, -32600), (5, -32600)])
        self.assertEqual(out[4], [{"jsonrpc": "2.0", "id": 6, "result": {}}])
        self.assertEqual(len(out), 5)

    def test_the_replies_of_a_batch_are_written_one_by_one(self):
        """SPEC 8 and 29.2: the line written for a batch is, byte for byte, json.dumps of the list of its replies, and
        each reply is written as it is made: no write holds more than one reply, and the end of every line is
        flushed. apc_mcp.main() with a standard output that records the size of every write (negative when it ends a
        line) and every flush (0)."""
        driver = ("import io, json, sys\nsys.path.insert(0, %r)\ntry:\n    import apc_mcp\nexcept ImportError:\n"
                  "    sys.exit(64)\nreal, sizes = sys.stdout, []\nclass Out(io.StringIO):\n"
                  "    def write(self, s):\n        sizes.append(len(s) if s[-1:] != '\\n' else -len(s))\n"
                  "        return io.StringIO.write(self, s)\n    def flush(self):\n        sizes.append(0)\n"
                  "sys.stdout = Out()\napc_mcp.main()\n"
                  "real.write(json.dumps({'sizes': sizes, 'out': sys.stdout.getvalue()}))\n" % ROOT)
        n = 300
        b = [req(i, "tools/list") if i % 3 else NOTE for i in range(n)] + [1, req("z", "nope")]
        lines = [init(0, "2025-03-26"), b, [NOTE, NOTE], [], req(9, "ping")]
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        p = subprocess.run([sys.executable, "-B", "-c", driver], input="".join(json.dumps(x) + "\n" for x in lines).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=300)
        if p.returncode == 64:
            raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f))")
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        got = json.loads(p.stdout.decode())
        out = got["out"].splitlines()
        self.assertEqual(len(out), 4)                            # initialize, the batch, the empty array, the ping
        replies = json.loads(out[1])
        self.assertEqual(len(replies), 202)                     # 200 tools/list, the member 1, the unknown method
        self.assertEqual([x["id"] for x in replies], [i for i in range(n) if i % 3] + [None, "z"])
        self.assertEqual(out[1], json.dumps(replies))            # the bytes json.dumps writes for the list
        one = max(len(json.dumps(x)) for x in replies)
        self.assertGreater(len(out[1]), 50 * one)
        sizes = got["sizes"]
        self.assertLessEqual(max(abs(x) for x in sizes), one + 2)    # "[" or ", " and one reply: never the whole array
        ends = [i for i, x in enumerate(sizes) if x < 0]
        self.assertEqual(len(ends), 4)
        self.assertEqual([sizes[i + 1:i + 2] for i in ends], [[0]] * 4)     # a line written is a line flushed
        self.assertEqual(json.loads(out[2])["error"]["message"], "invalid request: an empty batch")
        self.assertEqual(json.loads(out[3]), {"jsonrpc": "2.0", "id": 9, "result": {}})


if __name__ == "__main__":
    unittest.main()
