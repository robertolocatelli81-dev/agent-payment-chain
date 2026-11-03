"""SPEC 32.11 (Amendment 0.21.2; apc_verify 0.21.2): the verifier's environment, measured as a reader meets it (review of
the public tree built from 95d2c11, 2026-11-02, F1-F4). F1: with APC_AP2EV unset the pack beside the verifier's folder is
read, at the hashes of v1.7.1. F2: when the pack cannot be used the note names the true cause (`cryptography` absent, not
the path). F3: without the signature library the verifier writes one line on standard error and exits 64, never a
traceback's 1. F4: the mandate suite skips with the reason. No test here needs the real corpus but the last class; the
ones that need the pack skip, naming it. Six of the first seven failed on 95d2c11 with an AssertionError (measured 2026-11-02); the seventh,
test_another_missing_module_is_raised_as_it_is, is the closure control of the guard and passes there too.
SPEC 32.12 (Amendment 0.21.3): the code run is the code hashed, the pack (e) and the signature library (f); exit 64 kept
with standard error closed or full (g); the empty variable said (h); APC_REQUIRE_DEPS=1 turns the skips for the pack into
failures, for the CI's dependency step (i). Each test of PackCodeIsTheHashedBytes and SignatureLibraryIsTheHashedBytes,
DependenciesRequired and the new test of MandateSuiteSkips failed on 7e4531e with an AssertionError (measured 2026-11-02, this
file on that code); RequireDepsSwitch tests this file's own switch and passes there. OtherProgramsWithoutTheLibrary (2):
apc_block, apc_ap2, apc_batch, apc_report and apc_mcp without the library behave as apc_verify does (one line, exit 64, as a
module a SiglibError); both failed on bee5c17 with an AssertionError (26 subcases, measured 2026-11-02: a traceback's 1, or 120)."""
import glob
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
import apc_mandate as am  # noqa: E402

VERIFY = os.path.join(ROOT, "apc_verify.py")
FIX = os.path.join(ROOT, "tests", "fixtures_mandate", "base.json")       # made with the SDK: MP1 verified with the pack
SIGLIB = os.environ.get("APC_SIGLIB", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "x402-signature-vectors"))
PACK = os.environ.get("APC_AP2EV", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "ap2-evidence-pack"))
UNAVAILABLE = "not_evaluated:ap2_evidence_pack_unavailable"
NOT_171 = "not_evaluated:ap2_evidence_pack_not_1.7.1"


def _pack_usable():
    """(ok, why): the two files of PACK at the hashes of v1.7.1, and `cryptography` importable by this interpreter."""
    for name, rel in (("ap2_evidence.py", "ap2_evidence.py"), ("sigsuite.py", os.path.join("pqcrypto", "sigsuite.py"))):
        try:
            with open(os.path.join(PACK, rel), "rb") as fh:
                h = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            h = None
        if h != am.AP2EV_SHA256[name]:
            return False, "needs ap2-evidence-pack v1.7.1 at APC_AP2EV or beside the repository (%s: %s is not the file of the tag)" % (PACK, rel)
    if importlib.util.find_spec("cryptography") is None:
        return False, "needs the `cryptography` package in this interpreter (%s): pip install cryptography" % sys.executable
    return True, ""


PACK_OK, PACK_WHY = _pack_usable()
REQUIRE_DEPS = os.environ.get("APC_REQUIRE_DEPS") == "1"    # SPEC 32.12 (i): the CI's dependency step; a skip becomes a failure
EIP712_SHA256 = "8f1ae28568fdeab8713c3595631ab313ec9cc14bddc6772e0dd78946b804e608"      # SPEC 32.12 (f), tag v1.4.0
SECP_SHA256 = "7e10ceb85840d1049dc2fbdef4c03e14a5af9a29c78eba54d4393695402a1f69"


def needs_pack(test):
    """The test needs the pack: skipped with the reason, or, under APC_REQUIRE_DEPS=1, FAILED with it (SPEC 32.12 (i))."""
    if PACK_OK:
        return test
    if REQUIRE_DEPS:
        def failed(self):
            self.fail("APC_REQUIRE_DEPS=1 and the dependency is not usable: " + PACK_WHY)
        failed.__name__, failed.__doc__ = test.__name__, test.__doc__
        return failed
    return unittest.skip(PACK_WHY)(test)


def env(**over):
    """The subprocess environment of the bench: no PYTHONPATH, no APC_AP2EV, no APC_REQUIRE_DEPS (the CI's dependency step
    sets it for this process, not for the subprocesses it measures), the signature library named; `over` wins."""
    e = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "APC_AP2EV", "APC_REQUIRE_DEPS")}
    e["APC_SIGLIB"] = SIGLIB
    e.update(over)
    return e


def verify(bundle, e, script=VERIFY):
    return subprocess.run([sys.executable, "-B", script, bundle], capture_output=True, env=e, cwd=ROOT)


def report(r):
    rep = json.loads(r.stdout.decode("utf-8"))
    return rep, [n for n in rep.get("notes", []) if n.startswith("MP1-MP7")]


def blocker(tmp):
    """A `cryptography` package that raises at import, first on PYTHONPATH: the interpreter without it, reproduced."""
    d = os.path.join(tmp, "cryptography")
    os.mkdir(d)
    with open(os.path.join(d, "__init__.py"), "w") as fh:
        fh.write("raise ModuleNotFoundError(\"No module named 'cryptography'\", name='cryptography')\n")
    return tmp


class SiblingPack(unittest.TestCase):
    """32.11 (a), review F1: the verifier reads ../ap2-evidence-pack beside its own folder when APC_AP2EV is unset."""

    def copy_beside(self, tmp):
        repo = os.path.join(tmp, "repo")
        os.mkdir(repo)
        for f in glob.glob(os.path.join(ROOT, "apc_*.py")):
            os.symlink(f, os.path.join(repo, os.path.basename(f)))
        return os.path.join(repo, "apc_verify.py")

    @needs_pack
    def test_sibling_is_read_without_the_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self.copy_beside(tmp)
            r = verify(FIX, env(), script)                            # no sibling yet
            rep, notes = report(r)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(rep["checks"]["MP1"], UNAVAILABLE)
            self.assertIn("APC_AP2EV is unset", notes[0])              # 32.11 (b): the cause, and how to get the pack
            self.assertIn("tag v1.7.1", notes[0])
            os.symlink(PACK, os.path.join(tmp, "ap2-evidence-pack"))
            rep, notes = report(verify(FIX, env(), script))
            self.assertEqual(rep["checks"]["MP1"], "verified", rep.get("notes"))
            self.assertEqual(rep["checks"]["MP2"], "verified")
            # the variable, when set, wins over the sibling whatever it names
            rep, notes = report(verify(FIX, env(APC_AP2EV=os.path.join(tmp, "nowhere")), script))
            self.assertEqual(rep["checks"]["MP1"], NOT_171)
            self.assertIn("APC_AP2EV", notes[0])

    def test_sibling_at_another_tag_is_not_1_7_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self.copy_beside(tmp)
            other = os.path.join(tmp, "ap2-evidence-pack")
            os.makedirs(os.path.join(other, "pqcrypto"))
            for rel in ("ap2_evidence.py", os.path.join("pqcrypto", "sigsuite.py")):
                with open(os.path.join(other, rel), "w") as fh:
                    fh.write("# not tag v1.7.1\n")
            r = verify(FIX, env(), script)
            self.assertEqual(r.returncode, 2, r.stdout[-300:])          # a verdict, not an error of the verifier (exit 3)
            rep, notes = report(r)
            self.assertEqual(rep["checks"]["MP1"], NOT_171, rep.get("notes"))
            self.assertEqual(set(rep["mandate"]["ap2_evidence_sha256"]), {"ap2_evidence.py", "sigsuite.py"})
            self.assertIn("not those of ap2-evidence-pack tag v1.7.1", notes[0])


class CauseNamed(unittest.TestCase):
    """32.11 (b), review F2: `cryptography` absent is said, with the interpreter and the command; APC_AP2EV is not blamed."""

    @needs_pack
    def test_cryptography_absent_is_the_cause_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = verify(FIX, env(APC_AP2EV=PACK, PYTHONPATH=blocker(tmp)))
            rep, notes = report(r)
            self.assertEqual(r.returncode, 2)
            self.assertEqual({rep["checks"][k] for k in am.CHECKS}, {UNAVAILABLE})
            self.assertIn("pip install cryptography", notes[0])
            self.assertIn(sys.executable, notes[0])
            self.assertNotIn("APC_AP2EV names", notes[0])
            rep, _ = report(verify(FIX, env(APC_AP2EV=PACK)))          # control: the same interpreter with the package
            self.assertEqual(rep["checks"]["MP1"], "verified")


class SignatureLibrary(unittest.TestCase):
    """32.11 (c), review F3: no library, no verifier: one line, exit 64; as a module an ImportError that names the way."""

    def test_without_the_library_exit_64_one_line_no_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = verify(FIX, env(APC_SIGLIB=os.path.join(tmp, "nowhere")))
            err = r.stderr.decode("utf-8")
            self.assertEqual(r.returncode, 64, err[-300:])
            self.assertEqual(r.stdout, b"")
            self.assertNotIn("Traceback", err)
            self.assertEqual(err.count("\n"), 1, err)
            self.assertIn("APC_SIGLIB", err)
            self.assertIn("../x402-signature-vectors", err)
            self.assertIn(os.path.join(tmp, "nowhere"), err)
            r = verify(FIX, env())                                   # control: with the library, a verdict (exit 2)
            self.assertEqual(r.returncode, 2, r.stderr[-300:])
            os.mkdir(os.path.join(tmp, "lib"))                        # another tree: a `lib` package without the modules
            open(os.path.join(tmp, "lib", "__init__.py"), "w").close()
            r = verify(FIX, env(APC_SIGLIB=tmp))
            self.assertEqual(r.returncode, 64, r.stderr[-300:])
            self.assertEqual(r.stderr.decode("utf-8").count("\n"), 1)
            r = subprocess.run([sys.executable, "-B", "-c", "import apc_verify"], capture_output=True, cwd=ROOT,
                               env=env(APC_SIGLIB=os.path.join(tmp, "nowhere")))
            err = r.stderr.decode("utf-8")
            self.assertEqual(r.returncode, 1)
            self.assertIn("ImportError: apc_verify: the signature library", err)
            self.assertIn("APC_SIGLIB", err)

    def test_another_missing_module_is_raised_as_it_is(self):
        # the guard is closed on lib, lib.eip712, lib.secp256k1: a defect of the verifier is not dressed as a missing library
        code = ("import builtins, runpy, sys\n"
                "real = builtins.__import__\n"
                "def imp(n, *a, **k):\n"
                "    if n == 'apc_mandate': raise ModuleNotFoundError('No module named apc_mandate', name='apc_mandate')\n"
                "    return real(n, *a, **k)\n"
                "builtins.__import__ = imp\n"
                "sys.argv = [%r, %r]\n"
                "runpy.run_path(sys.argv[0], run_name='__main__')\n" % (VERIFY, FIX))
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=env())
        err = r.stderr.decode("utf-8")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ModuleNotFoundError: No module named apc_mandate", err)
        self.assertNotIn("APC_SIGLIB", err)


class PackCodeIsTheHashedBytes(unittest.TestCase):
    """32.11 (e), review of 7e4531e: the code run is the two files hashed and nothing else of the folder; a FIFO in the
    folder does not stall the verifier; standard error closed or full does not change exit 64."""

    def sibling(self, tmp):
        """A copy of the verifier beside a folder holding only the two hashed files of PACK."""
        script = SiblingPack.copy_beside(self, tmp)
        pack = os.path.join(tmp, "ap2-evidence-pack")
        os.makedirs(os.path.join(pack, "pqcrypto"))
        for rel in ("ap2_evidence.py", os.path.join("pqcrypto", "sigsuite.py")):
            with open(os.path.join(PACK, rel), "rb") as a, open(os.path.join(pack, rel), "wb") as b:
                b.write(a.read())
        return script, pack

    @needs_pack
    def test_no_other_file_of_the_folder_runs(self):
        planted = {
            # a package wins over the hashed module of the same name when imported by name
            os.path.join("pqcrypto", "sigsuite", "__init__.py"):
                "open(%r, 'w').write('ran')\nexec(compile(open(__file__[:-len('/sigsuite/__init__.py')] + '/sigsuite.py', 'rb')"
                ".read(), 'sigsuite.py', 'exec'))\n",
            # a package that shadows the dependency the pack imports
            os.path.join("cryptography", "__init__.py"): "open(%r, 'w').write('ran')\nraise ImportError('planted')\n",
        }
        for rel, code in planted.items():
            with self.subTest(rel), tempfile.TemporaryDirectory() as tmp:
                script, pack = self.sibling(tmp)
                marker = os.path.join(tmp, "PLANTED_RAN")
                os.makedirs(os.path.dirname(os.path.join(pack, rel)), exist_ok=True)
                with open(os.path.join(pack, rel), "w") as fh:
                    fh.write(code % marker)
                rep, notes = report(verify(FIX, env(), script))
                self.assertFalse(os.path.exists(marker), rel)
                self.assertEqual(rep["checks"]["MP1"], "verified", notes)

    @needs_pack
    def test_cached_bytecode_does_not_stand_in(self):
        import importlib._bootstrap_external as be
        with tempfile.TemporaryDirectory() as tmp:
            script, pack = self.sibling(tmp)
            marker = os.path.join(tmp, "PLANTED_RAN")
            src = os.path.join(pack, "pqcrypto", "sigsuite.py")
            st = os.stat(src)
            code = compile("open(%r, 'w').write('ran')\nraise ImportError('planted')\n" % marker, src, "exec")
            pyc = importlib.util.cache_from_source(src)
            os.makedirs(os.path.dirname(pyc))
            with open(pyc, "wb") as fh:          # a bytecode file whose header matches the hashed source (mtime, size)
                fh.write(be._code_to_timestamp_pyc(code, int(st.st_mtime), st.st_size))
            rep, notes = report(verify(FIX, env(), script))
            self.assertFalse(os.path.exists(marker))
            self.assertEqual(rep["checks"]["MP1"], "verified", notes)

    @needs_pack
    def test_a_module_sigsuite_from_elsewhere_is_refused(self):
        import types
        saved, saved_mod, saved_env = list(am._AP2EV), sys.modules.get("sigsuite"), os.environ.get("APC_AP2EV")
        fake = types.ModuleType("sigsuite")
        fake.__file__ = os.path.join(tempfile.gettempdir(), "elsewhere", "sigsuite.py")
        try:
            am._AP2EV.clear()
            os.environ["APC_AP2EV"] = PACK
            sys.modules["sigsuite"] = fake
            mod, _, why = am._load()
            self.assertIsNone(mod)
            self.assertEqual(why, UNAVAILABLE)
            self.assertIn("a module sigsuite was already loaded from another place", am.cause())
        finally:
            am._AP2EV[:] = saved
            if saved_mod is None:
                sys.modules.pop("sigsuite", None)
            else:
                sys.modules["sigsuite"] = saved_mod
            if saved_env is None:
                os.environ.pop("APC_AP2EV", None)
            else:
                os.environ["APC_AP2EV"] = saved_env

    @needs_pack
    def test_the_load_leaves_sys_path_and_sys_modules_as_found(self):
        saved, saved_env = list(am._AP2EV), os.environ.get("APC_AP2EV")
        names = ("ap2_evidence", "sigsuite")
        before = {n: sys.modules.get(n) for n in names}
        try:
            for n in names:
                sys.modules.pop(n, None)
            am._AP2EV.clear()
            os.environ["APC_AP2EV"] = PACK
            path = list(sys.path)
            mod, _, why = am._load()
            self.assertIsNotNone(mod, am.cause())
            self.assertEqual(sys.path, path)
            self.assertEqual([n for n in names if n in sys.modules], [])
            self.assertEqual(mod.__file__, os.path.join(PACK, "ap2_evidence.py"))
        finally:
            am._AP2EV[:] = saved
            for n, m in before.items():
                if m is None:
                    sys.modules.pop(n, None)
                else:
                    sys.modules[n] = m
            if saved_env is None:
                os.environ.pop("APC_AP2EV", None)
            else:
                os.environ["APC_AP2EV"] = saved_env

    def test_a_fifo_in_the_folder_does_not_stall(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs on this system")
        with tempfile.TemporaryDirectory() as tmp:
            pack = os.path.join(tmp, "pack")
            os.makedirs(os.path.join(pack, "pqcrypto"))
            os.mkfifo(os.path.join(pack, "ap2_evidence.py"))
            open(os.path.join(pack, "pqcrypto", "sigsuite.py"), "w").close()
            try:
                r = subprocess.run([sys.executable, "-B", VERIFY, FIX], capture_output=True, cwd=ROOT, timeout=60,
                                   env=env(APC_AP2EV=pack))
            except subprocess.TimeoutExpired:
                self.fail("a FIFO named ap2_evidence.py stalled the verifier")
            rep, _ = report(r)
            self.assertEqual(rep["checks"]["MP1"], NOT_171)
            self.assertIsNone(rep["mandate"]["ap2_evidence_sha256"]["ap2_evidence.py"])

    def test_empty_variable_is_said(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = SiblingPack.copy_beside(self, tmp)
            rep, notes = report(verify(FIX, env(APC_AP2EV=""), script))
            self.assertEqual(rep["checks"]["MP1"], UNAVAILABLE)
            self.assertIn("APC_AP2EV is unset (or empty)", notes[0])

    def test_exit_64_with_standard_error_closed_or_full(self):
        cases = [("closed", "2>&-")] + ([("full", "2>/dev/full")] if os.path.exists("/dev/full") else [])
        for name, redir in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                r = subprocess.run(["/bin/sh", "-c", 'exec "$0" -B "$1" "$2" ' + redir, sys.executable, VERIFY, FIX],
                                   capture_output=False, stdout=subprocess.PIPE, cwd=ROOT,
                                   env=env(APC_SIGLIB=os.path.join(tmp, "nowhere")))
                self.assertEqual(r.returncode, 64, name)
                self.assertEqual(r.stdout, b"")


class SignatureLibraryIsTheHashedBytes(unittest.TestCase):
    """32.12 (f): the library run is the two files of x402-signature-vectors v1.4.0 at their hashes, from the bytes hashed:
    other bytes are exit 64, nothing else of the folder runs, the folder is never on sys.path, a module of the name loaded
    from elsewhere is refused, an empty APC_SIGLIB counts as unset."""

    def lib_copy(self, tmp, name="siglib"):
        """A folder holding copies of the two files of SIGLIB (the machine's library, at the hashes of the tag)."""
        d = os.path.join(tmp, name)
        os.makedirs(os.path.join(d, "lib"))
        for rel in ("eip712.py", "secp256k1.py"):
            with open(os.path.join(SIGLIB, "lib", rel), "rb") as a, open(os.path.join(d, "lib", rel), "wb") as b:
                b.write(a.read())
        return d

    def test_other_bytes_are_exit_64_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = self.lib_copy(tmp, "good")
            r = verify(FIX, env(APC_SIGLIB=good))                                       # control: the copy is accepted
            self.assertEqual(r.returncode, 2, r.stderr[-300:])
            changed = self.lib_copy(tmp, "changed")
            with open(os.path.join(changed, "lib", "eip712.py"), "ab") as fh:
                fh.write(b"\n# one byte more\n")
            one = self.lib_copy(tmp, "one")
            os.remove(os.path.join(one, "lib", "secp256k1.py"))
            cases = [("one byte appended", changed, "lib/eip712.py sha256 "), ("the stand-in", os.path.join(ROOT, "tools", "siglib_standin"), "lib/eip712.py sha256 "),
                     ("one file absent", one, "lib/secp256k1.py sha256 absent")]
            for name, d, said in cases:
                with self.subTest(name):
                    r = verify(FIX, env(APC_SIGLIB=d))
                    err = r.stderr.decode("utf-8")
                    self.assertEqual(r.returncode, 64, err[-300:])
                    self.assertEqual(r.stdout, b"")
                    self.assertNotIn("Traceback", err)
                    self.assertEqual(err.count("\n"), 1, err)
                    self.assertIn(d, err)
                    self.assertIn(said, err)
                    self.assertIn("v1.4.0", err)
                    self.assertIn("APC_SIGLIB", err)

    def test_no_other_file_of_the_folder_runs(self):
        import importlib._bootstrap_external as be
        with tempfile.TemporaryDirectory() as tmp:
            d = self.lib_copy(tmp)
            marker = os.path.join(tmp, "PLANTED_RAN")
            with open(os.path.join(d, "lib", "__init__.py"), "w") as fh:        # the package's own code, run by an import by name
                fh.write("open(%r, 'w').write('ran')\n" % marker)
            src = os.path.join(d, "lib", "eip712.py")
            st = os.stat(src)
            code = compile("open(%r, 'w').write('ran')\nraise ImportError('planted')\n" % marker, src, "exec")
            pyc = importlib.util.cache_from_source(src)
            os.makedirs(os.path.dirname(pyc))
            with open(pyc, "wb") as fh:          # a bytecode file whose header matches the hashed source (mtime, size)
                fh.write(be._code_to_timestamp_pyc(code, int(st.st_mtime), st.st_size))
            r = verify(FIX, env(APC_SIGLIB=d))
            self.assertFalse(os.path.exists(marker), "a planted file of the library's folder ran")
            self.assertEqual(r.returncode, 2, r.stderr[-300:])

    def test_a_module_lib_from_elsewhere_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = os.path.join(tmp, "elsewhere", "lib", "eip712.py")
            pre = ("import sys, types\nm = types.ModuleType('lib.eip712')\nm.__file__ = %r\nsys.modules['lib.eip712'] = m\n" % elsewhere)
            r = subprocess.run([sys.executable, "-B", "-c", pre + "import apc_verify\n"], capture_output=True, cwd=ROOT, env=env())
            err = r.stderr.decode("utf-8")
            self.assertEqual(r.returncode, 1)
            self.assertIn("ImportError: apc_verify: the signature library", err)
            self.assertIn("already loaded from another place", err)
            self.assertIn(elsewhere, err)
            r = subprocess.run([sys.executable, "-B", "-c", pre + "import runpy\nsys.argv = [%r, %r]\n"
                                "runpy.run_path(sys.argv[0], run_name='__main__')\n" % (VERIFY, FIX)],
                               capture_output=True, cwd=ROOT, env=env())
            self.assertEqual(r.returncode, 64, r.stderr[-300:])
            self.assertEqual(r.stdout, b"")
            self.assertEqual(r.stderr.decode("utf-8").count("\n"), 1)

    def test_a_module_replaced_after_the_load_is_refused(self):
        # the package `lib` is ours, `lib.eip712` was replaced afterwards: a second load refuses it, it never returns early
        code = ("import sys, types, apc_siglib\napc_siglib.load()\nm = types.ModuleType('lib.eip712')\n"
                "m.__file__ = '/elsewhere/lib/eip712.py'\nsys.modules['lib.eip712'] = m\n"
                "try:\n    apc_siglib.load()\nexcept apc_siglib.SiglibError as e:\n    print('refused', e)\n"
                "else:\n    print('accepted')\n")
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=env())
        out = r.stdout.decode("utf-8")
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertTrue(out.startswith("refused"), out)
        self.assertIn("a module lib.eip712 was already loaded from another place (/elsewhere/lib/eip712.py)", out)

    def test_a_load_failed_half_way_leaves_nothing(self):
        # the second file fails to compile (MemoryError planted): no half-run module of the three names stays marked as
        # apc_siglib's, so the next load runs both files again instead of returning the half-run package
        code = ("import sys, apc_siglib\nreal = compile\n"
                "def broken(src, name, *a, **k):\n"
                "    if name.endswith('secp256k1.py'):\n        raise MemoryError('planted')\n"
                "    return real(src, name, *a, **k)\n"
                "apc_siglib.compile = broken\n"
                "try:\n    apc_siglib.load()\nexcept MemoryError:\n    pass\n"
                "left = sorted(n for n in sys.modules if n == 'lib' or n.startswith('lib.'))\n"
                "del apc_siglib.compile\nlib = apc_siglib.load()\n"
                "print(left, hasattr(lib.secp256k1, 'recover_public_key'))\n")
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=env())
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertEqual(r.stdout.decode("utf-8").strip(), "[] True")

    def test_the_folder_is_not_on_sys_path_and_the_package_holds_two_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self.lib_copy(tmp)
            with open(os.path.join(d, "lib", "other.py"), "w") as fh:
                fh.write("X = 1\n")
            code = ("import json, os, sys\nimport apc_verify\nimport lib.eip712, lib.secp256k1\n"
                    "try:\n    import lib.other\n    other = 'imported'\nexcept ModuleNotFoundError as e:\n    other = type(e).__name__\n"
                    "print(json.dumps({'on_path': any(os.path.realpath(p) == os.path.realpath(%r) for p in sys.path), "
                    "'hashes': [getattr(lib.eip712, '__apc_siglib_sha256__', None), getattr(lib.secp256k1, '__apc_siglib_sha256__', None)], "
                    "'files': [lib.eip712.__file__, lib.secp256k1.__file__], 'other': other}))\n" % d)
            r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=env(APC_SIGLIB=d))
            self.assertEqual(r.returncode, 0, r.stderr[-300:])
            out = json.loads(r.stdout.decode("utf-8"))
            self.assertFalse(out["on_path"], "the library's folder is on sys.path")
            self.assertEqual(out["hashes"], [EIP712_SHA256, SECP_SHA256])
            self.assertEqual(out["files"], [os.path.join(d, "lib", "eip712.py"), os.path.join(d, "lib", "secp256k1.py")])
            self.assertEqual(out["other"], "ModuleNotFoundError")

    def test_empty_variable_counts_as_unset(self):
        # the default made present wherever this runs, so that nothing skips: the author's default under a HOME of the test
        # (his working tree) and ../x402-signature-vectors beside a copy of the verifier (the public tree)
        with tempfile.TemporaryDirectory() as tmp:
            script = SiblingPack.copy_beside(self, tmp)
            home = os.path.join(tmp, "home")
            r = verify(FIX, env(APC_SIGLIB="", HOME=home), script)          # control: no default anywhere, exit 64
            self.assertEqual(r.returncode, 64, r.stderr[-300:])
            os.makedirs(os.path.join(home, "progetti"))
            os.symlink(os.path.abspath(SIGLIB), os.path.join(home, "progetti", "x402-signature-vectors"))
            os.symlink(os.path.abspath(SIGLIB), os.path.join(tmp, "x402-signature-vectors"))
            r = verify(FIX, env(APC_SIGLIB="", HOME=home), script)          # the empty value is not a path: the default
            self.assertEqual(r.returncode, 2, r.stderr[-300:])
            self.assertEqual(json.loads(r.stdout.decode("utf-8"))["verifier"], json.loads(verify(FIX, env()).stdout.decode("utf-8"))["verifier"])


class OtherProgramsWithoutTheLibrary(unittest.TestCase):
    """32.12 (f), review of bee5c17 (pre-existing): apc_block, apc_ap2, apc_batch, apc_report and apc_mcp without the library
    behave as apc_verify does: one line, exit 64, nothing of a report, never a traceback's 1 (apc_batch reads 1 as a failure);
    as modules a SiglibError with the same sentence. On bee5c17 every one ended with a traceback, exit 1."""

    PROGRAMS = (("apc_block.py", [], 64), ("apc_ap2.py", [], 64), ("apc_batch.py", [FIX], 0), ("apc_report.py", ["sarif", FIX], 0),
                ("apc_mcp.py", [], 0))      # (program, arguments, the exit WITH the library: usage, a verdict, done, or stdin at end)

    def run_program(self, prog, args, e, redir=None):
        cmd = [sys.executable, "-B", os.path.join(ROOT, prog)] + args
        if redir is None:
            return subprocess.run(cmd, capture_output=True, env=e, cwd=ROOT, stdin=subprocess.DEVNULL)
        sh = 'exec "$0" ' + " ".join('"$%d"' % i for i in range(1, len(cmd))) + " " + redir
        return subprocess.run(["/bin/sh", "-c", sh] + cmd, stdout=subprocess.PIPE, cwd=ROOT, env=e, stdin=subprocess.DEVNULL)

    def test_one_line_exit_64_no_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = SignatureLibraryIsTheHashedBytes.lib_copy(self, tmp, "changed")
            with open(os.path.join(changed, "lib", "eip712.py"), "ab") as fh:
                fh.write(b"\n# one byte more\n")
            cases = [("absent", os.path.join(tmp, "nowhere"), "APC_SIGLIB"), ("one byte appended", changed, "v1.4.0")]
            for prog, args, rc_with in self.PROGRAMS:
                r = self.run_program(prog, args, env())                               # control: with the library
                self.assertEqual(r.returncode, rc_with, (prog, r.stderr[-300:]))
                self.assertNotIn(b"Traceback", r.stderr)
                for name, d, said in cases:
                    with self.subTest(prog, case=name):
                        r = self.run_program(prog, args, env(APC_SIGLIB=d))
                        err = r.stderr.decode("utf-8")
                        self.assertEqual(r.returncode, 64, err[-300:])
                        self.assertEqual(r.stdout, b"")
                        self.assertNotIn("Traceback", err)
                        self.assertEqual(err.count("\n"), 1, err)
                        self.assertTrue(err.startswith(prog[:-3] + ": the signature library"), err)
                        self.assertIn(d, err)
                        self.assertIn(said, err)
                for name, redir in [("closed", "2>&-")] + ([("full", "2>/dev/full")] if os.path.exists("/dev/full") else []):
                    with self.subTest(prog, stderr=name):
                        r = self.run_program(prog, args, env(APC_SIGLIB=os.path.join(tmp, "nowhere")), redir)
                        self.assertEqual(r.returncode, 64)
                        self.assertEqual(r.stdout, b"")

    def test_as_a_module_the_import_error_and_the_guard_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for prog, _, _ in self.PROGRAMS:
                with self.subTest(prog):
                    r = subprocess.run([sys.executable, "-B", "-c", "import " + prog[:-3]], capture_output=True, cwd=ROOT,
                                       env=env(APC_SIGLIB=os.path.join(tmp, "nowhere")))
                    err = r.stderr.decode("utf-8")
                    self.assertEqual(r.returncode, 1)
                    self.assertIn("apc_siglib.SiglibError: %s: the signature library of x402-signature-vectors" % prog[:-3], err)
                    self.assertIn("APC_SIGLIB", err)
            # a failure of the load that is not a SiglibError is not dressed as a missing library: raised as it is, as the program too
            code = ("import apc_siglib\napc_siglib.load = lambda: (_ for _ in ()).throw(RuntimeError('planted'))\n"
                    "apc_siglib.guard('apc_x', True)\n")
            r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=env())
            err = r.stderr.decode("utf-8")
            self.assertEqual(r.returncode, 1, err[-300:])
            self.assertIn("RuntimeError: planted", err)
            self.assertNotIn("APC_SIGLIB", err)


class ToolsWithoutTheLibrary(unittest.TestCase):
    """32.12 (f), second commit (2026-11-02): the 35 tools under tools/ that need the library behave as the programs do.
    Run as the program without it (absent, or one byte appended): one line `tools/<name>: <sentence>` on standard error,
    exit 64, nothing on standard output, never a traceback. Imported as a module without it: a SiglibError naming the tool.
    Control: with the library each imports (exit 0, nothing on standard error), but those whose import needs what the
    bench may not have (the AP2 SDK; the real corpus; in the public tree, the saved RPC replies of sources/l1proof_20261024,
    kept with the corpus), which end with that reason and never with the library's. On c0f699c each program ended with
    a traceback, exit 1."""

    TOOLS = ("anchor_msca", "canonical", "census_eip3009", "check_eip3009_oracle", "count_removed_zero", "coverage_census",
             "fetch_authcap_permit2", "fetch_authcapture", "fetch_base_eip3009", "fetch_payer_wallets", "fetch_permit2_state",
             "fuzz_bundles", "gen_mandate_fixtures", "inclusion", "log_pairs", "make_bundle_issue1062", "make_bundle_reverted",
             "make_bundles_authcap", "make_bundles_l1state", "make_bundles_msca", "make_bundles_negatives", "make_bundles_permit2",
             "make_bundles_permit2_state", "make_bundles_v02", "make_bundles_v03", "make_corpus_manifest", "make_real_bundles",
             "make_webauthn_oracle", "rebuild_corpus", "regress", "run_ordered", "scan_logs", "scan_webauthn",
             "synth_mandate_block", "world_bundles")
    # the import with the library may end for a reason of its own, named here (closed list), never for the library
    IMPORT_NEEDS = {"gen_mandate_fixtures": "KeyError: 'AP2_SDK_PATH'",
                    "synth_mandate_block": "unittest.case.SkipTest: real corpus not present: bundles/real_svm_mandate",
                    "make_bundles_l1state": "sources/l1proof_20261024: the saved RPC replies are not in the public tree",
                    "anchor_msca": "sources/l1proof_20261024: the saved RPC replies are not in the public tree"}

    def run_tool(self, t, e, program=True):
        cmd = [sys.executable, "-B"] + ([os.path.join(ROOT, "tools", t + ".py")] if program else ["-c", "import tools." + t])
        return subprocess.run(cmd, capture_output=True, env=e, cwd=ROOT, stdin=subprocess.DEVNULL)

    def test_the_list_and_the_guard_line(self):
        self.assertEqual(len(self.TOOLS), 35)
        self.assertEqual(len(set(self.TOOLS)), 35)
        for t in self.TOOLS:
            with self.subTest(t):
                with open(os.path.join(ROOT, "tools", t + ".py"), encoding="utf-8") as fh:
                    lines = fh.read().split("\n")
                guard = 'apc_siglib.guard("tools/%s", __name__ == "__main__")' % t
                at = [i for i, l in enumerate(lines) if l.startswith(guard)]
                self.assertEqual(len(at), 1, (t, at))
                # the guard precedes every import of this folder's code (apc_*, lib.*, tools.*, another tool by name)
                first = [i for i, l in enumerate(lines) if (l.startswith("import ") or l.startswith("from "))
                         and "# noqa: E402" in l and not l.startswith("import apc_siglib")]
                self.assertTrue(not first or first[0] > at[0], (t, first[:1], at))

    def test_as_the_program_one_line_exit_64(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = SignatureLibraryIsTheHashedBytes.lib_copy(self, tmp, "changed")
            with open(os.path.join(changed, "lib", "eip712.py"), "ab") as fh:
                fh.write(b"\n# one byte more\n")
            cases = [("absent", os.path.join(tmp, "nowhere"), "APC_SIGLIB"), ("one byte appended", changed, "v1.4.0")]
            for t in self.TOOLS:
                for name, d, said in cases:
                    with self.subTest(t, case=name):
                        r = self.run_tool(t, env(APC_SIGLIB=d))
                        err = r.stderr.decode("utf-8")
                        self.assertEqual(r.returncode, 64, err[-300:])
                        self.assertEqual(r.stdout, b"")
                        self.assertNotIn("Traceback", err)
                        self.assertEqual(err.count("\n"), 1, err)
                        self.assertTrue(err.startswith("tools/" + t + ": the signature library"), err)
                        self.assertIn(d, err)
                        self.assertIn(said, err)

    def test_as_a_module_the_error_and_the_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            for t in self.TOOLS:
                with self.subTest(t):
                    r = self.run_tool(t, env(APC_SIGLIB=os.path.join(tmp, "nowhere")), program=False)
                    err = r.stderr.decode("utf-8")
                    self.assertEqual(r.returncode, 1, err[-300:])
                    self.assertIn("apc_siglib.SiglibError: tools/%s: the signature library of x402-signature-vectors" % t, err)
                    self.assertIn("APC_SIGLIB", err)
                    ctl = env(); ctl.pop("AP2_SDK_PATH", None)          # 03/11: the expected IMPORT_NEEDS assume no SDK path; with
                    r = self.run_tool(t, ctl, program=False)              # one in the caller's environment gen_mandate_fixtures went on to
                    # the next variable (KeyError: 'APC_AP2EV') and the test failed by environment, not by code
                    # control: with the library the guard is silent
                    err = r.stderr.decode("utf-8")
                    self.assertEqual(r.stdout, b"")
                    self.assertNotIn("signature library", err)
                    self.assertNotIn("SiglibError", err)
                    if r.returncode == 0:
                        self.assertEqual(err, "")
                    else:
                        self.assertIn(t, self.IMPORT_NEEDS, err[-300:])
                        self.assertEqual(r.returncode, 1, err[-300:])
                        self.assertIn(self.IMPORT_NEEDS[t], err.strip().splitlines()[-1])


class RequireDepsSwitch(unittest.TestCase):
    """32.12 (i): under APC_REQUIRE_DEPS=1 a test that would skip for the pack fails with the skip's reason."""

    def test_skips_for_the_pack_become_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            cmd = [sys.executable, "-B", "-m", "unittest", "tests.test_amend0212.CauseNamed"]
            r = subprocess.run(cmd, capture_output=True, cwd=ROOT, env=env(APC_AP2EV=tmp, APC_REQUIRE_DEPS="1"))
            err = r.stderr.decode("utf-8")
            self.assertEqual(r.returncode, 1, err[-300:])
            self.assertIn("FAILED (failures=1)", err)
            self.assertIn("APC_REQUIRE_DEPS=1 and the dependency is not usable", err)
            self.assertNotIn("skipped", err)
            r = subprocess.run(cmd, capture_output=True, cwd=ROOT, env=env(APC_AP2EV=tmp))      # control: without it, a skip
            self.assertEqual(r.returncode, 0)
            self.assertIn("OK (skipped=1)", r.stderr.decode("utf-8"))


@unittest.skipUnless(REQUIRE_DEPS, "APC_REQUIRE_DEPS=1 is not set: the CI's dependency step alone runs this class (SPEC 32.12 (i))")
class DependenciesRequired(unittest.TestCase):
    """32.12 (i): in the CI the library of v1.4.0 and the pack of v1.7.1 MUST load here; a skip is not a pass."""

    def test_library_and_pack_load_here(self):
        code = ("import json, apc_verify, apc_mandate, lib.eip712, lib.secp256k1\nm, h, why = apc_mandate._load()\n"
                "print(json.dumps({'lib': [lib.eip712.__apc_siglib_sha256__, lib.secp256k1.__apc_siglib_sha256__], "
                "'pack': m is not None, 'cause': apc_mandate.cause(), 'hashes': h, 'why': why}))\n")
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=env(APC_AP2EV=PACK))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8")[-500:])
        out = json.loads(r.stdout.decode("utf-8"))
        self.assertEqual(out["lib"], [EIP712_SHA256, SECP_SHA256])
        self.assertTrue(out["pack"], out)
        self.assertIsNone(out["cause"], out)
        rep, notes = report(verify(FIX, env(APC_AP2EV=PACK)))
        self.assertEqual(rep["checks"]["MP1"], "verified", notes)


@unittest.skipUnless(real_corpus.has_set("real_svm_mandate"),
                     "needs bundles/real_svm_mandate (SPEC 33): tests/test_mandate.py skips for the corpus before it looks for the pack")
class MandateSuiteSkips(unittest.TestCase):
    """32.11 (d), review F4: with the corpus present and the pack unusable, tests/test_mandate.py is skipped with the reason."""

    def discover(self, e):
        r = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-t", ".",
                            "-p", "test_mandate.py", "-v"], capture_output=True, cwd=ROOT, env=e)
        return r.returncode, r.stderr.decode("utf-8")

    def test_pack_absent_skips_with_the_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self.discover(env(APC_AP2EV=os.path.join(tmp, "nowhere")))
            self.assertEqual(rc, 0, out[-600:])
            self.assertIn("OK (skipped=1)", out)
            self.assertIn("not usable from APC_AP2EV=", out)
            self.assertIn("tag v1.7.1", out)
            self.assertNotIn("RuntimeError", out)

    def test_pack_absent_is_an_error_under_require_deps(self):
        # 32.12 (i): the CI's dependency step; the corpus is present here, so the module reaches the pack and must not skip
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self.discover(env(APC_AP2EV=os.path.join(tmp, "nowhere"), APC_REQUIRE_DEPS="1"))
            self.assertEqual(rc, 1, out[-600:])
            self.assertIn("FAILED (errors=1)", out)
            self.assertIn("RuntimeError: the tests of SPEC 31 do not run", out)
            self.assertNotIn("skipped", out)

    @needs_pack
    def test_cryptography_absent_skips_naming_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self.discover(env(APC_AP2EV=PACK, PYTHONPATH=blocker(tmp)))
            self.assertEqual(rc, 0, out[-600:])
            self.assertIn("OK (skipped=1)", out)
            self.assertIn("pip install cryptography", out)


if __name__ == "__main__":
    unittest.main()
