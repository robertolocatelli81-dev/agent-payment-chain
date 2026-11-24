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
        alphabet = '[]{}"\\ a,:\n'          # a line end after a backslash is still inside the string
        for _ in range(4000):
            t = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
            for limit in (0, 1, 2, 3, 5):
                self.assertEqual(apc_siglib.json_too_deep(t, limit), old_count(t, limit), (t, limit))
        for enc in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-32"):       # bytes as json.loads decodes them
            for n, limit in ((3, 2), (3, 3)):
                self.assertEqual(apc_siglib.json_too_deep(deep(n).encode(enc), limit), n > limit, enc)
        # a lone surrogate in UTF-8 bytes: json.loads reads it (surrogatepass), so the count must not raise
        self.assertEqual(json.loads(b'["\xed\xa0\x80"]'), ["\ud800"])
        self.assertFalse(apc_siglib.json_too_deep(b'["\xed\xa0\x80"]', 64))
        self.assertTrue(apc_siglib.json_too_deep(bytearray(deep(3).encode()), 2))      # json.loads takes a bytearray too

    def test_the_count_keeps_no_state_per_escape(self):
        """a string of escapes is counted in constant memory (one pattern for the whole string kept the regex engine's
        state for each escape: 114 to 144 bytes, so 30 MiB and more for this text)"""
        import tracemalloc
        text = json.dumps(['"' * 300000, [1]])
        tracemalloc.start()
        try:
            self.assertFalse(apc_siglib.json_too_deep(text, 2))
            self.assertTrue(apc_siglib.json_too_deep(text, 1))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 1 << 20, peak)

    def test_apc_verify_one_reason(self):
        library()
        import apc_verify as av
        for n in DEPTHS:
            with self.assertRaises(av.Refusal) as cm:
                av.strict_json(deep(n))
            self.assertEqual(str(cm.exception), "JSON nested deeper than 64 (SPEC 29.1)", n)
        self.assertEqual(json.dumps(av.strict_json(deep(64)), separators=(",", ":")), deep(64))    # control: 64 read
        for text, reason in (("[" * 65 + "x", "JSON nested deeper than 64 (SPEC 29.1)"),        # the count comes first,
                             ("[" * 64 + "x", "not JSON: Expecting value")):                    # on a text not JSON too
            with self.assertRaises(av.Refusal) as cm:
                av.strict_json(text)
            self.assertTrue(str(cm.exception).startswith(reason), (len(text), str(cm.exception)))

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

    def test_bench_journal_counts_as_the_readers_do(self):
        import bench_journal as bj
        self.assertFalse(bj._too_deep("[" + "[]," * 20 + "[]]"))                  # 21 arrays side by side nest 2
        self.assertFalse(bj._too_deep(json.dumps({"a": "[" * 20 + '\\"{'})))      # brackets inside a string
        for t in ("[" * 9 + "]" * 9, '{"a":' * 9 + "1" + "}" * 9, "[" + "[]," * 20 + "[]]", '["[[[[[[[[[\\"[[[", 1]',
                  '\\"[[[[[[[[['):          # a backslash outside a string escapes nothing: the quote opens one
            self.assertEqual(bj._too_deep(t), apc_siglib.json_too_deep(t, bj.MAX_DEPTH), t)

    def test_bench_journal_does_not_write_what_it_refuses_to_read(self):
        import bench_journal as bj
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            j = bj.Journal(p, {"a": [[[[[[1]]]]]]})                          # the line nests 8: written and read
            with self.assertRaises(bj.JournalError) as cm:
                j.append("mutant", {"a": [[[[[[[1]]]]]]]})                   # 9: refused before the write
            self.assertIn("not written", str(cm.exception))
            self.assertEqual(len(bj.read(p)[0]), 1)


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


class FuzzChildOnThisPlatform(unittest.TestCase):
    """tools/fuzz_bundles.run_child runs apc_verify in a limited child on every platform: a fork with setrlimit on
    POSIX, a process in its own Job Object on Windows (no fork, no setrlimit there; CI run 45334985210 ended the module
    at `import resource`). The peak memory is read in MiB on each (macOS reports ru_maxrss in bytes, Linux in KiB)."""

    def test_a_case_runs_and_is_measured(self):
        library()
        import fuzz_bundles as fb
        with tempfile.TemporaryDirectory() as d:
            case = os.path.join(d, "case.json")
            with open(case, "wb") as fh:
                fh.write(b"{}")
            before = fb.CHILDREN_CPU[0]
            res, out, err = fb.run_child(case, [], 5, 2048, d)
        self.assertEqual(res.get("exit"), 3, (res, err))
        rep = json.loads(out)
        self.assertEqual(rep["verdict"], "refused")
        self.assertEqual(fb.classify(res, out, err, "refused", rep.get("checks", {}), False, 5, 2048)[0], None)
        self.assertTrue(5 <= res["maxrss_mib"] <= 2048, res)        # an interpreter with apc_verify: tens of MiB
        self.assertTrue(0 < res["cpu"] < 20 and fb.CHILDREN_CPU[0] > before, res)


class FuzzChildLimits(unittest.TestCase):
    """The limits of tools/fuzz_bundles.run_child, driven by real children on this platform (NEMESIS apc3: on Windows none
    was measured): past the memory cap, a CPU loop, a child that never ends. POSIX: RLIMIT_AS, RLIMIT_CPU and the alarm;
    Windows: the Job Object's process memory and user time limits and TerminateJobObject at the wall-clock stop."""
    REPORT = 'import sys\nsys.stdout.write(\'{"verdict": "refused", "checks": {}}\')\nsys.stdout.flush()\n'

    def run_work(self, work, cpu_cap=0.25, mem_cap=256):
        import fuzz_bundles as fb
        with tempfile.TemporaryDirectory() as d:
            case = os.path.join(d, "case.json")
            with open(case, "wb") as fh:
                fh.write(b"{}")
            res, out, err = fb.run_child(case, [], cpu_cap, mem_cap, d, work=work)
        return res, fb.classify(res, out, err, "refused", {}, False, cpu_cap, mem_cap)[0]

    def test_past_the_memory_cap(self):
        # 1 GiB written with a cap of 256 MiB: MemoryError (exit 71) where the cap is enforced, else the peak after
        # the run (a system that refuses RLIMIT_AS); either way the case is a memory defect
        work = ("import os\ntry:\n    b = bytearray(b'x') * (1 << 30)\nexcept MemoryError:\n    os._exit(71)\n"
                + self.REPORT + "os._exit(3)\n")
        res, kind = self.run_work(work, cpu_cap=5)          # CPU cap wide: writing 1 GiB takes about a second
        self.assertEqual(kind, "memory", res)
        res, kind = self.run_work(self.REPORT + "import os\nos._exit(3)\n")       # control: the same child, no allocation
        self.assertEqual(kind, None, res)
        res, kind = self.run_work(work, cpu_cap=5, mem_cap=2048)            # control: the same allocation under the cap
        self.assertEqual(kind, None, res)

    def test_a_cpu_loop_is_stopped(self):
        import time
        t0 = time.monotonic()
        res, kind = self.run_work("while True:\n    pass\n")          # cpu_cap 0.25: hard stop at 2 s of CPU
        self.assertEqual(kind, "time", res)
        if res["wall"] >= 3.9 and res["cpu"] < 2.5:       # the loop got less than half a core: the wall stop came first
            self.skipTest("starved: %r" % (res,))         # and the run decides nothing (a limit not applied reads 4 s)
        self.assertGreater(res["cpu"], 1.5, res)                          # it ran until the CPU limit,
        self.assertLess(res["wall"], 3.9, res)                            # not until the wall-clock stop at 4 s
        self.assertLess(time.monotonic() - t0, 60, res)

    def test_a_child_that_never_ends_is_stopped(self):
        import time
        t0 = time.monotonic()
        res, kind = self.run_work("import time\ntime.sleep(600)\n")    # wall-clock stop at 2 * 2 s
        self.assertEqual(kind, "time", res)
        self.assertLess(res["cpu"], 1.5, res)                             # stopped by the wall clock, not the CPU
        self.assertTrue(3.5 < res["wall"] < 8, res)                       # at the 4 s stop, not at a later one
        self.assertTrue(3.5 < time.monotonic() - t0 < 60, res)

    def test_work_that_ends_is_exit_0(self):
        # source that runs to its end: the child ends there with exit 0 and never goes on into the parent's code
        res, _ = self.run_work(self.REPORT)
        self.assertEqual(res.get("exit"), 0, res)

    def test_windows_stop_reads_user_time_only(self):
        import fuzz_bundles as fb
        # the job's limit is on user time: kernel time past it is no stop (NEMESIS apc3, note on `cpu > hard`)
        self.assertEqual([fb._windows_stopped(0, u, 2) for u in (0.0, 1.99, 2.0)], [False, False, True])
        self.assertTrue(fb._windows_stopped(fb._TIMEOUT_EXIT, 0.0, 2) and fb._windows_stopped(fb._CPU_EXIT, 0.0, 2))

    def test_windows_invalid_handle_is_a_failure(self):
        import ctypes
        import fuzz_bundles as fb
        # CreateToolhelp32Snapshot fails with INVALID_HANDLE_VALUE (-1), true for a truth test (NEMESIS apc3)
        self.assertEqual([fb._valid_handle(h) for h in (None, 0, ctypes.c_void_p(-1).value, 1234)],
                         [False, False, False, True])


class NoPosixOnlyImport(unittest.TestCase):
    """Every program and tool of the tree imports on a Python without the POSIX-only modules (Windows has no resource,
    fcntl, termios, pwd or grp): those are imported where they are used, on the platform that has them (CI run
    45334985210: tools/fuzz_bundles.py ended at `import resource` on Windows)."""

    def test_no_module_imports_them_at_its_top(self):
        """read on the sources (ast): an import of the five at module level, outside a def or a class, ends the
        program on Windows before its first line runs"""
        import ast
        blocked = {"resource", "fcntl", "termios", "pwd", "grp"}
        files = [os.path.join(ROOT, n) for n in sorted(os.listdir(ROOT)) if n.endswith(".py")]
        for sub in ("tools", "tests"):
            files += [os.path.join(ROOT, sub, n) for n in sorted(os.listdir(os.path.join(ROOT, sub))) if n.endswith(".py")]
        found = []
        for f in files:
            with open(f, "rb") as fh:
                tree = ast.parse(fh.read(), f)
            stack = list(tree.body)
            while stack:
                n = stack.pop()
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(n, ast.Import):
                    found += ["%s: %s" % (os.path.relpath(f, ROOT), a.name) for a in n.names if a.name in blocked]
                elif isinstance(n, ast.ImportFrom) and n.module in blocked:
                    found.append("%s: %s" % (os.path.relpath(f, ROOT), n.module))
                else:
                    stack.extend(ast.iter_child_nodes(n))
        self.assertGreater(len(files), 150)
        self.assertEqual(found, [])

class RegisterLock(unittest.TestCase):
    """apc_registry._lock (SPEC 11.3, one writer at a time) on this platform: flock on POSIX, msvcrt.locking on Windows
    (until 2026-11-24 no lock at all there: fcntl was missing and the error was passed over). A second writer waits."""

    def test_a_second_writer_waits(self):
        import subprocess
        import time
        import apc_registry as rg
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "reg.jsonl")
            with open(reg, "wb") as fh:
                fh.write(b"x\n")
            code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import apc_registry as rg\n"
                    "fh = open(sys.argv[2], 'r+b'); rg._lock(fh); print('locked', flush=True); time.sleep(3)\n")
            p = subprocess.Popen([sys.executable, "-B", "-c", code, ROOT, reg], stdout=subprocess.PIPE)
            try:
                self.assertEqual(p.stdout.readline().strip(), b"locked")
                t0 = time.monotonic()
                with open(reg, "r+b") as fh:
                    rg._lock(fh)
                    waited = time.monotonic() - t0
                    self.assertEqual(fh.tell(), 0)                   # the position is kept
                    fh.seek(0)
                    self.assertEqual(fh.read(), b"x\n")             # readers are not blocked by the lock's byte
            finally:
                p.stdout.close()
                p.wait()
            self.assertGreater(waited, 1.5)


    def holder(self, reg, seconds):
        import subprocess
        code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import apc_registry as rg\n"
                "fh = open(sys.argv[2], 'r+b'); rg._lock(fh); print('locked', flush=True); time.sleep(%s)\n" % seconds)
        p = subprocess.Popen([sys.executable, "-B", "-c", code, ROOT, reg], stdout=subprocess.PIPE)
        self.assertEqual(p.stdout.readline().strip(), b"locked")
        return p

    def test_a_reader_of_another_process_is_not_blocked(self):
        import time
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "reg.jsonl")
            with open(reg, "wb") as fh:
                fh.write(b"x\n")
            p = self.holder(reg, 5)
            try:
                t0 = time.monotonic()
                with open(reg, "rb") as fh:                   # this process, while the other holds the lock
                    self.assertEqual(fh.read(), b"x\n")
                self.assertLess(time.monotonic() - t0, 2)
                self.assertIsNone(p.poll())                     # the lock was still held
            finally:
                p.stdout.close()
                p.wait()

    def test_a_writer_waits_past_ten_seconds(self):
        # Windows: msvcrt.locking LK_LOCK gives up after 10 tries of 1 s (EDEADLOCK); _lock tries again, as flock waits
        import time
        import apc_registry as rg
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "reg.jsonl")
            with open(reg, "wb") as fh:
                fh.write(b"x\n")
            p = self.holder(reg, 13)
            try:
                t0 = time.monotonic()
                with open(reg, "r+b") as fh:
                    rg._lock(fh)
                    waited = time.monotonic() - t0
                p.wait(timeout=10)                              # the lock came with the holder's end
            finally:
                p.stdout.close()
                p.wait()
            self.assertGreater(waited, 11)

    def test_a_torn_tail_is_cut_under_the_lock(self):
        import subprocess
        e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}

        def cli(*a):
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_registry.py")] + list(a), env=e,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            return r.returncode, r.stdout.decode(), r.stderr
        with tempfile.TemporaryDirectory() as d:
            reg, rep = os.path.join(d, "reg.jsonl"), os.path.join(d, "rep.json")
            with open(rep, "w") as fh:
                json.dump({"verifier": "apc_verify 0", "verdict": "refused"}, fh)
            self.assertEqual(cli("init", reg)[0], 0)
            self.assertEqual(cli("record", reg, "--report", rep)[:1], (0,))
            with open(reg, "ab") as fh:
                fh.write(b'{"apc_register": "torn' + b"x" * 100000)    # a last line half written, no newline, longer
            size = os.path.getsize(reg)
            code, out, err = cli("record", reg, "--report", rep)
            self.assertEqual((code, err), (0, b""), out)
            self.assertTrue(json.loads(out)["torn_tail_recorded"], out)
            with open(reg, "rb") as fh:
                data = fh.read()
            self.assertNotIn(b'"torn{', data)
            self.assertNotIn(b"xxxx", data)                     # than what record writes after it: nothing of it is left
            self.assertTrue(data.endswith(b"\n") and len(data) < size, len(data))          # cut, never grown to 1 TiB
            self.assertEqual(cli("verify", reg)[0], 0)


class RegisterWritesWhatItReads(unittest.TestCase):
    """SPEC 11.3: an entry is recorded only if its line reads back. A report nested 62 to 64 deep is read (29.1), its
    check entry nests three deeper: with the count before the parser and no check at writing, record answered exit 0
    and the register was damaged from then on."""

    def run_cli(self, *args):
        import subprocess
        e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_registry.py")] + list(args), env=e,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout.decode(), r.stderr

    def test_a_report_whose_entry_would_nest_past_64_is_not_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            reg, rep = os.path.join(d, "reg.jsonl"), os.path.join(d, "rep.json")
            self.assertEqual(self.run_cli("init", reg)[0], 0)
            for n, want in ((61, 0), (62, 3), (64, 3), (61, 0)):        # the report's own nesting; 61 + 3 = 64 is read
                x = 1
                for _ in range(n - 1):
                    x = [x]
                with open(rep, "w") as fh:
                    json.dump({"verifier": "apc_verify 0", "verdict": "refused", "extra": x}, fh)
                with open(reg, "rb") as fh:
                    before = fh.read()
                code, out, err = self.run_cli("record", reg, "--report", rep)
                self.assertEqual((code, err), (want, b""), (n, out))
                with open(reg, "rb") as fh:
                    after = fh.read()
                if want:
                    self.assertIn("nothing written", out)
                    self.assertIn("nested deeper than 64", out)
                    self.assertEqual(after, before, n)
                else:
                    self.assertGreater(len(after), len(before), n)
                self.assertEqual(self.run_cli("verify", reg)[0], 0, n)       # the register stays intact

    def test_an_entry_longer_than_a_line_is_not_recorded(self):
        import apc_registry as rg
        base = len(rg.canonical({"apc_register": rg.FORMAT, "seq": 0, "prev": rg.ZERO, "kind": "open",
                                 "body": {"x": ""}, "hash": rg.ZERO}))
        for extra, said in ((0, False), (1, True)):                 # a line of MAX_LINE bytes is read, one more is not
            with self.assertRaises(rg.Bad) as cm:                   # (refused here either way: no member x in an open)
                rg._entry([], "open", {"x": "a" * (rg.MAX_LINE - base + extra)})
            self.assertIn("nothing written", str(cm.exception))
            self.assertEqual("longer than" in str(cm.exception), said, extra)


if __name__ == "__main__":
    unittest.main()
