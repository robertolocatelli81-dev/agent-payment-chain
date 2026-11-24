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


def crlf_copy(src, dst, files):
    """the files of src copied to dst as a checkout with git core.autocrlf=true writes them (LF turned into CRLF)"""
    for rel in files:
        with open(os.path.join(src, *rel.split("/")), "rb") as fh:
            data = fh.read()
        os.makedirs(os.path.dirname(os.path.join(dst, *rel.split("/"))), exist_ok=True)
        with open(os.path.join(dst, *rel.split("/")), "wb") as fh:
            fh.write(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))


class CrlfCheckout(unittest.TestCase):
    """A checkout of the signature library or of the pack with CRLF line ends (git core.autocrlf=true, the default of Git
    for Windows; CI run 45334985210 on Windows) is refused as before (other bytes: exit 64, MP1-MP7 not evaluated), and
    the refusal now says that the line ends are the cause and how to check out again."""

    def test_library_with_crlf_exit_64_with_the_cause(self):
        import subprocess
        lib = os.environ.get("APC_SIGLIB") or apc_siglib.siglib_dir()
        if not os.path.isfile(os.path.join(lib, "lib", "eip712.py")):
            self.skipTest("the signature library is absent (SPEC 32.12 (f))")
        with tempfile.TemporaryDirectory() as d:
            crlf_copy(lib, d, apc_siglib.SIGLIB_SHA256)
            for alter, said in ((lambda b: b, True), (lambda b: b + b"#", False)):     # control: other bytes, no cause
                p = os.path.join(d, "lib", "eip712.py")
                with open(p, "rb") as fh:
                    data = fh.read()
                with open(p, "wb") as fh:
                    fh.write(alter(data))
                env = dict(os.environ, APC_SIGLIB=d)
                env.pop("PYTHONPATH", None)
                r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), "x.json"], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
                err = r.stderr.decode()
                self.assertEqual((r.returncode, r.stdout, len(err.splitlines())), (64, b"", 1), err)
                self.assertEqual(err.count("CRLF line ends"), 2 if said else 1, err)          # secp256k1.py stays CRLF
                self.assertIn("git -c core.autocrlf=false clone", err)

    def test_pack_with_crlf_names_the_cause(self):
        import subprocess
        pack = os.environ.get("APC_AP2EV")
        if not pack or not os.path.isfile(os.path.join(pack, "ap2_evidence.py")):
            self.skipTest("APC_AP2EV does not name ap2-evidence-pack (SPEC 32.11)")
        library()
        with tempfile.TemporaryDirectory() as d:
            crlf_copy(pack, d, ("ap2_evidence.py", "pqcrypto/sigsuite.py"))
            code = "import apc_mandate as m; m._load(); print(m.cause())"
            for env_pack, said in ((d, True), (pack, False)):                      # control: the real pack, no cause
                env = dict(os.environ, APC_AP2EV=env_pack)
                env.pop("PYTHONPATH", None)
                r = subprocess.run([sys.executable, "-B", "-c", code], env=env, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
                self.assertEqual(r.returncode, 0, r.stderr[-300:])
                self.assertEqual("CRLF line ends" in r.stdout.decode(), said, r.stdout)

    def test_this_checkout_has_the_committed_line_ends(self):
        """.gitattributes (`* -text`): no file of this tree is converted at checkout; a Python source with CRLF here
        means a checkout that ignored it (CI run 45334985210 on Windows: the sources searched for "\\nM = [\\n")"""
        crlf = []
        for top, dirs, files in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x not in (".git", "__pycache__", "bundles", "oracle")]
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(top, f), "rb") as fh:
                        if b"\r\n" in fh.read():
                            crlf.append(os.path.join(top, f))
        self.assertEqual(crlf, [])
        with open(os.path.join(ROOT, ".gitattributes"), "rb") as fh:
            self.assertIn(b"\n* -text\n", fh.read())


if __name__ == "__main__":
    unittest.main()
