"""SPEC section 8 (Amendment 0.21.6): a JSON line nested deeper than 64 is -32600 on every interpreter,
counted before it is read, and a line that is not JSON stays -32700 however deep; a message that is not a JSON-RPC
2.0 Request object (JSON-RPC 2.0 section 4: method "A String", params "a Structured value") is -32600 with id null,
with or without an id, alone and in a 2025-03-26 batch. The server on its real stdio transport; no real corpus.
Positive control: on 50757c9 (before this) the tests of this file that send such lines fail (the line of 5000
nested arrays gave -32700 on Python 3.9 and 3.11, -32600 on 3.13)."""
import json
import os
import random
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def session(lines):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    data = "".join((x if isinstance(x, str) else json.dumps(x)) + "\n" for x in lines)
    p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_mcp.py")], input=data.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=300)
    if p.returncode == 64:
        raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f))")
    assert p.returncode == 0, p.stderr[-300:]
    return [json.loads(x) for x in p.stdout.decode().splitlines()]


DEEP = {"code": -32600, "message": "invalid request: nested deeper than 64 (SPEC 8)"}
BAD = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600,
                                               "message": "invalid request: not a JSON-RPC 2.0 Request object"}}


def ping(i, inner):
    return '{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"x":%s}}' % (i, inner)


class Depth(unittest.TestCase):
    def test_the_bound_is_64_whatever_the_interpreter(self):
        # the message is level 1, params 2; 62 arrays inside params.x reach 64, 63 reach 65
        out = session([ping(1, "[" * 62 + "]" * 62), ping(2, "[" * 63 + "]" * 63), "[" * 5000 + "]" * 5000,
                       "[" * 5000, '{"a":' * 70 + "1" + "}" * 70, ping(3, '"' + "[" * 200 + '"'),
                       ping(4, '"\\"' + "[" * 200 + '"'), '{"jsonrpc":"2.0","id":5,"method":"ping"}'])
        self.assertEqual(out[0], {"jsonrpc": "2.0", "id": 1, "result": {}})
        # "[" * 5000 alone is not JSON: a parse error however deep (JSON-RPC 2.0 section 5.1; DeepButNotJson below)
        self.assertEqual([(m["id"], m["error"]) for m in out[1:5]],
                         [(None, DEEP), (None, DEEP), (None, {"code": -32700, "message": "parse error"}), (None, DEEP)])
        self.assertEqual([m.get("result") for m in out[5:]], [{}, {}, {}])     # brackets inside strings do not count

    def test_the_count_against_the_parsed_depth(self):
        import apc_mcp

        def depth(v):
            if isinstance(v, (dict, list)):
                return 1 + max([depth(x) for x in (v.values() if isinstance(v, dict) else v)], default=0)
            return 0
        rng = random.Random(20261121)
        texts = ['"[\\"{"', '"]]]}}"', '"\\\\"', "x[", "[]", "{}"]

        def gen(d):
            # one child goes on to depth d, its siblings are leaves: the value stays small at any depth
            if d <= 0:
                return rng.choice([1, "a[b", "\\\"[", "}{", None, True, rng.choice(texts)])
            kids = [gen(d - 1)] + [gen(0) for _ in range(rng.randint(0, 2))]
            rng.shuffle(kids)
            if rng.random() < 0.5:
                return kids
            return {"k%d" % i: k for i, k in enumerate(kids)}
        for _ in range(400):
            v = gen(rng.randint(0, 80))
            text = json.dumps(v)
            for limit in (0, 1, 7, 64):
                self.assertEqual(apc_mcp.too_deep(text, limit), depth(v) > limit, (limit, text[:80]))


class DeepButNotJson(unittest.TestCase):
    def test_a_deep_line_that_is_not_json_is_a_parse_error(self):
        # JSON-RPC 2.0 section 5.1: invalid JSON is -32700; as for a repeated member, not JSON comes first (SPEC 8)
        parse = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        out = session(["[" * 65 + "x", "[" * 65 + "NaN" + "]" * 65, '{"a":1,"a":2' + "[" * 70, "[" * 65 + "]" * 64,
                       "[" * 65 + "]" * 66, "[" * 65 + "]" * 65 + "[", "[" * 65 + "]" * 65])
        self.assertEqual(out[:6], [parse] * 6)
        self.assertEqual(out[6], {"jsonrpc": "2.0", "id": None, "error": DEEP})

    def test_json_text_against_json_loads(self):
        import itertools
        import apc_mcp

        def loads(t):
            try:
                json.loads(t, parse_constant=apc_mcp._not_json)
                return True
            except (ValueError, RecursionError):
                return False
        alphabet = ['[', ']', '{', '}', '"', '\\', ':', ',', '1', '-', 'e', ' ']
        for n in range(1, 6):
            for t in itertools.product(alphabet, repeat=n):
                s = "".join(t)
                self.assertEqual(apc_mcp.json_text(s), loads(s), s)
        for s in ("1\u0662", "[1\u0662]", "-\uff11", "1.\u0663", "1e\u0664"):    # digits that are not ASCII: not JSON
            self.assertEqual((apc_mcp.json_text(s), loads(s)), (False, False), s)
        rng = random.Random(20261122)
        words = ['{"a":[1,-2.5e3,true,false,null,"\\"\\\\\\u00e9"]}', "NaN", "Infinity", "01", "1.", ".5", "tru", "nul",
                 '"\x01"', '"\\x"', "\u00e9", "[", "]", "{", "}", ",", ":", '"k"', " ", "\n", "\t", "\u00a0", "1e", "-",
                 "1\u0662", "\uff11"]
        for _ in range(20000):
            s = "".join(rng.choice(words) for _ in range(rng.randint(1, 8)))
            self.assertEqual(apc_mcp.json_text(s), loads(s), s)


class RequestObjects(unittest.TestCase):
    def test_not_a_request_object_is_minus_32600_with_id_null(self):
        lines = [{"jsonrpc": "2.0", "method": 1}, {"jsonrpc": "2.0", "method": 1, "params": "bar"},
                 {"jsonrpc": "2.0", "method": None, "id": 5}, {"jsonrpc": "2.0", "id": 6},
                 {"jsonrpc": "2.0", "method": "ping", "id": 7, "params": "bar"},
                 {"jsonrpc": "2.0", "method": "ping", "id": 8, "params": 3},
                 {"jsonrpc": "2.0", "method": "notifications/initialized", "params": "x"},
                 {"jsonrpc": "2.0", "method": "ping", "id": 11, "params": None},      # null is not structured
                 {"jsonrpc": "2.0", "method": True, "id": 12},                       # a boolean is not a String
                 {"jsonrpc": "2.0", "method": "notifications/initialized"},
                 {"jsonrpc": "2.0", "method": "ping", "id": 9, "params": []},
                 {"jsonrpc": "2.0", "method": "ping", "id": 10}]
        out = session(lines)
        self.assertEqual(out[:9], [BAD] * 9)
        self.assertEqual(out[9:], [{"jsonrpc": "2.0", "id": 9, "result": {}},
                                   {"jsonrpc": "2.0", "id": 10, "result": {}}])

    def test_in_a_2025_03_26_batch_as_alone(self):
        init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}
        out = session([init, [{"jsonrpc": "2.0", "method": 1}, {"jsonrpc": "2.0", "method": "ping", "id": 1},
                              {"jsonrpc": "2.0", "method": "notifications/initialized"},
                              {"jsonrpc": "2.0", "method": "ping", "params": "bar"}]])
        self.assertEqual(out[1], [BAD, {"jsonrpc": "2.0", "id": 1, "result": {}}, BAD])


if __name__ == "__main__":
    unittest.main()
