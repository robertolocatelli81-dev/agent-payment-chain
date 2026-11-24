"""SPEC 29.1 and 32.12 on every platform of the CI (2026-11-24; run 45334985210 of ci-prova-http-sig-9421 failed on
Python 3.14, macOS and Windows). Here: JSON nesting counted on the text before any parser, the same answer on every
Python (json.loads raised RecursionError at 100,000 nested arrays on 3.9-3.13 and on the local 3.14.8, and read them on
the 3.14 of the CI, so a reader that relied on the RecursionError gave another reason there). No real corpus.
Positive control: on e18d024 every test of JsonDepthBeforeTheParser but the count's own fails."""
import json
import os
import random
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import apc_siglib  # noqa: E402

DEPTHS = (65, 100, 100000)          # 100: read by json.loads on every Python; 100000: RecursionError on most, not all


def deep(n):
    return "[" * n + "]" * n


def old_count(text, limit):
    """apc_mcp.too_deep of e18d024, one character at a time: the oracle of the count"""
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def library():
    try:
        apc_siglib.load()
    except apc_siglib.SiglibError as e:
        raise unittest.SkipTest("the signature library is absent (SPEC 32.12 (f)): %s" % str(e)[:120])


class JsonDepthBeforeTheParser(unittest.TestCase):
    def test_the_count_is_the_character_count_on_any_text(self):
        rng = random.Random(20261124)
        alphabet = '[]{}"\\ a,:'
        for _ in range(4000):
            t = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
            for limit in (0, 1, 2, 3, 5):
                self.assertEqual(apc_siglib.json_too_deep(t, limit), old_count(t, limit), (t, limit))
        for enc in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-32"):       # bytes as json.loads decodes them
            for n, limit in ((3, 2), (3, 3)):
                self.assertEqual(apc_siglib.json_too_deep(deep(n).encode(enc), limit), n > limit, enc)

    def test_apc_verify_one_reason(self):
        library()
        import apc_verify as av
        for n in DEPTHS:
            with self.assertRaises(av.Refusal) as cm:
                av.strict_json(deep(n))
            self.assertEqual(str(cm.exception), "JSON nested deeper than 64 (SPEC 29.1)", n)
        self.assertEqual(json.dumps(av.strict_json(deep(64)), separators=(",", ":")), deep(64))    # control: 64 read

    def test_apc_ap2_one_reason(self):
        library()
        import apc_ap2
        for n in DEPTHS:
            with self.assertRaises(ValueError) as cm:
                apc_ap2._json(deep(n).encode())
            self.assertEqual(str(cm.exception), "JSON nested deeper than 64", n)
        self.assertIsInstance(apc_ap2._json(deep(64)), list)                      # control: 64 is read

    def test_apc_registry_one_reason(self):
        import apc_registry as rg
        for n in DEPTHS:
            with self.assertRaises(rg.Bad) as cm:
                rg.strict_json(deep(n))
            self.assertEqual(str(cm.exception), "not JSON: nested deeper than 64 (SPEC 29.1)", n)
        self.assertIsInstance(rg.strict_json(deep(64)), list)

    def test_rebuild_corpus_one_reason(self):
        library()
        import rebuild_corpus as rc
        for n in DEPTHS:
            with self.assertRaises(rc.Rejected) as cm:
                rc.loads(deep(n).encode(), "rpc:h:m")
            self.assertEqual(str(cm.exception), "json_too_nested:rpc:h:m", n)
        self.assertIsInstance(rc.loads(deep(64).encode(), "rpc:h:m"), list)

    def test_bench_journal_one_reason(self):
        import bench_journal as bj
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            for n in DEPTHS:
                with open(p, "wb") as fh:
                    fh.write(deep(n).encode() + b"\n")
                with self.assertRaises(bj.JournalError) as cm:
                    bj.read(p)
                self.assertEqual(str(cm.exception), "line 0: nested deeper than 8", n)
            with open(p, "wb") as fh:                                           # control: 8 is read (then refused
                fh.write(deep(8).encode() + b"\n")                              # as a record, for another reason)
            with self.assertRaises(bj.JournalError) as cm:
                bj.read(p)
            self.assertNotIn("nested", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
