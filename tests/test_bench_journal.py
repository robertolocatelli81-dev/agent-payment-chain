"""tools/bench_journal.py, tools/bench_cert.py and the APC_MUT_JOURNAL path of tools/mutants03.py.

The real driver runs on a small tree: its own main() with a list of 5 mutants of a 3-function module (2 killed, 1
surviving, 1 stale, 1 killed by the second check) and a run_ordered.py of two asserts that sleeps a little, so that a
run can be killed (SIGKILL to its process group) at any point and resumed.
"""
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import bench_journal as bj  # noqa: E402

LIB = "def add(a, b):\n    return a + b\n\n\ndef neg(x):\n    return -x\n\n\ndef keep(x):\n    return x\n"
FAKE_M = '''M = [
    ("lib.py", "add broken", "return a + b", "return a - b"),
    ("lib.py", "neg broken", "return -x", "return x"),
    ("lib.py", "keep untested", "    return x\\n", "    return x + 0\\n"),
    ("lib.py", "stale pattern", "return a * b", "return 0"),
    ("lib.py", "add zero", "return a + b", "return a + b + 0 * a + (a == 2)"),
    ("lib.py", "crash exit", "return -x", "import os; os._exit(3)"),
    ("lib.py", "exit one at import", "def keep(x):", "import os\\nos._exit(1)\\n\\n\\ndef keep(x):"),
]
'''
RUNNER = '''import os, sys, time, unittest
sys.path.insert(0, os.getcwd())
import lib


class T(unittest.TestCase):
    def test_add(self):
        time.sleep(float(os.environ.get("FAKE_SLEEP", "0")))
        self.assertEqual(lib.add(2, 3), 5)

    def test_neg(self):
        self.assertEqual(lib.neg(4), -4)


r = unittest.TextTestRunner(failfast=True, verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(T))
sys.exit(0 if r.wasSuccessful() else 1)
'''
WANT = {"add broken": "killed", "neg broken": "killed", "keep untested": "SURVIVED", "stale pattern": "STALE(0)",
        "add zero": "killed", "crash exit": "INVALID(3)", "exit one at import": "INVALID(1)"}
NOT_KILLED = ["crash exit", "exit one at import", "keep untested", "stale pattern"]


def read(p):
    with open(p, "rb") as fh:
        return fh.read()


def write(p, data):
    with open(p, "wb") as fh:
        fh.write(data)


def make_tree(d):
    t = os.path.join(d, "tree")
    os.makedirs(os.path.join(t, "tools"))
    src = read(os.path.join(ROOT, "tools", "mutants03.py")).decode()
    a = src.index("\nM = [\n") + 1
    b = src.index("\n]\n", a) + 3
    with open(os.path.join(t, "tools", "mutants03.py"), "w") as fh:
        fh.write(src[:a] + FAKE_M + src[b:])
    shutil.copy(os.path.join(ROOT, "tools", "bench_journal.py"), os.path.join(t, "tools"))
    for name, text in (("tools/__init__.py", ""), ("tools/run_ordered.py", RUNNER), ("lib.py", LIB)):
        with open(os.path.join(t, name), "w") as fh:
            fh.write(text)
    for name in ("siglib.txt", "pulse.json"):
        with open(os.path.join(d, name), "w") as fh:
            fh.write(name)
    return t


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="bjtest_")
        self.tree = make_tree(self.d)
        self.env = dict(os.environ, APC_SIGLIB=os.path.join(self.d, "siglib.txt"),
                        APC_PULSE_CASES=os.path.join(self.d, "pulse.json"), FAKE_SLEEP="0",
                        TMPDIR=self.d)          # a run killed on purpose leaves its copy here, not in /tmp
        self.env.pop("APC_MUT_FIRST", None)
        self.env.pop("APC_MUT_SET", None)

    def tearDown(self):
        shutil.rmtree(self.d)

    def j(self, i):
        return os.path.join(self.d, "j_%d.jsonl" % i)

    def cmd(self, i, n):
        return [sys.executable, "-B", os.path.join(self.tree, "tools", "mutants03.py"), self.tree, "", "%d/%d" % (i, n)]

    def run_shard(self, i, n, **env):
        e = dict(self.env, APC_MUT_JOURNAL=self.j(i), **env)
        return subprocess.run(self.cmd(i, n), env=e, capture_output=True, text=True)

    def cert(self, n, *extra):
        out = os.path.join(self.d, "cert.json")
        r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "tools", "bench_cert.py"), self.tree]
                           + [self.j(i) for i in range(n)] + list(extra) + ["--out", out],
                           capture_output=True, text=True)
        cert = None
        if r.returncode in (0, 1):
            cert = json.loads(read(out))
        return r.returncode, cert, r.stdout

    def verdicts(self, n):
        v = {}
        for i in range(n):
            for r in bj.read(self.j(i))[0]:
                if r["kind"] == "mutant":
                    self.assertNotIn(r["body"]["name"], v)
                    v[r["body"]["name"]] = r["body"]["verdict"]
                    if r["body"]["verdict"] == "killed":
                        self.assertRegex(r["body"]["failed_test"], r"^FAIL: test_\w+ \(")
        return v

    def rewrite(self, i, fn):
        """apply fn to the parsed lines of journal i and write them back with every hash and prev recomputed (the
        forgery a crash cannot produce but a careless edit or a forger with write access can)"""
        recs, _ = bj.read(self.j(i))
        recs = fn(recs)
        prev = bj.ZERO
        with open(self.j(i), "wb") as fh:
            for k, r in enumerate(recs):
                r = {"seq": k, "prev": prev, "kind": r["kind"], "body": r["body"]}
                r["hash"] = hashlib.sha256(bj.canonical(r)).hexdigest()
                prev = r["hash"]
                fh.write(bj.canonical(r) + b"\n")


class Complete(Base):
    def test_uninterrupted_two_shards(self):
        for i in range(2):
            self.run_shard(i, 2)
        self.assertEqual(self.verdicts(2), WANT)
        rc, cert, _ = self.cert(2)
        self.assertEqual(rc, 1)                            # one survivor and one stale: certificate, exit 1
        self.assertEqual(cert["not_killed"], NOT_KILLED)
        self.assertEqual(cert["mutants"], 7)
        self.assertEqual(cert["tree"], bj.tree_digest(self.tree))
        body = dict(cert)
        del body["cert_sha256"]
        self.assertEqual(cert["cert_sha256"], hashlib.sha256(bj.canonical(body)).hexdigest())

    def test_all_killed_exit_zero(self):
        self.run_shard(0, 1, APC_MUT_FIRST=self._first(["add broken", "neg broken", "add zero"]), APC_MUT_SET="first")
        rc, cert, out = self.cert(1)
        self.assertEqual((rc, cert["not_killed"], cert["mutants"]), (0, [], 3), out)

    def _first(self, names):
        p = os.path.join(self.d, "first.txt")
        with open(p, "w") as fh:
            fh.write("\n".join(names))
        return p

    def test_resume_of_finished_run_runs_nothing(self):
        self.run_shard(0, 1)
        before = read(self.j(0))
        r = self.run_shard(0, 1)
        self.assertEqual(read(self.j(0)), before)
        self.assertEqual(r.stdout.count("(recorded in the journal)"), 8)       # control + 7 mutants
        self.assertIn("not killed ['keep untested', 'stale pattern', 'crash exit', 'exit one at import']", r.stdout)
        self.assertEqual(r.returncode, 1)                  # a recorded survivor still fails the run


class Interrupted(Base):
    def kill_after(self, i, n, lines, sleep="0.15"):
        """start shard i/n and SIGKILL its process group once journal i has at least LINES lines"""
        e = dict(self.env, APC_MUT_JOURNAL=self.j(i), FAKE_SLEEP=sleep)
        p = subprocess.Popen(self.cmd(i, n), env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        t0 = time.time()
        while time.time() - t0 < 60:
            if os.path.exists(self.j(i)) and read(self.j(i)).count(b"\n") >= lines:
                break
            if p.poll() is not None:
                break
            time.sleep(0.01)
        time.sleep(random.uniform(0, 0.2))                  # inside the next step, at a random point
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()

    def test_kill_anywhere_then_resume_gives_the_uninterrupted_result(self):
        random.seed(20261025)
        for trial in range(4):
            for i in range(2):
                if os.path.exists(self.j(i)):
                    os.remove(self.j(i))
            for i in range(2):
                for lines in sorted(random.sample(range(1, 5), 2)):
                    self.kill_after(i, 2, lines)
                r = self.run_shard(i, 2)
                self.assertNotIn("Traceback", r.stdout + r.stderr)
            self.assertEqual(self.verdicts(2), WANT, "trial %d" % trial)
            rc, cert, out = self.cert(2)
            self.assertEqual((rc, cert["not_killed"]), (1, NOT_KILLED), out)

    def test_torn_tail_is_dropped_recorded_and_redone(self):
        self.run_shard(0, 1)
        raw = read(self.j(0))
        last = raw[:-1].rfind(b"\n") + 1
        name = json.loads(raw[last:])["body"]["name"]
        with open(self.j(0), "wb") as fh:                  # the last line half written, no newline
            fh.write(raw[:last] + raw[last:last + 40])
        rc, _, out = self.cert(1)
        self.assertEqual(rc, 2)
        self.assertIn("torn line", out)
        r = self.run_shard(0, 1)
        self.assertIn(name, [ln.split("  ")[0].strip() for ln in r.stdout.splitlines()
                             if "recorded" not in ln and not ln.startswith("MUTANTS")
                             and re.search(r"(killed|SURVIVED|STALE|INVALID)", ln)])
        recs = bj.read(self.j(0))[0]
        torn = [x for x in recs if x["kind"] == "torn_tail"]
        self.assertEqual(len(torn), 1)
        self.assertEqual(torn[0]["body"]["sha256"], hashlib.sha256(raw[last:last + 40]).hexdigest())
        rc, cert, _ = self.cert(1)
        self.assertEqual((rc, cert["journals"][0]["torn_tails"], self.verdicts(1)), (1, 1, WANT))

    def test_torn_first_line(self):
        with open(self.j(0), "wb") as fh:
            fh.write(b'{"body":{"tool"')
        self.run_shard(0, 1)
        recs = bj.read(self.j(0))[0]
        self.assertEqual([recs[0]["kind"], recs[1]["kind"]], ["open", "torn_tail"])
        self.assertEqual(self.verdicts(1), WANT)


class Refusals(Base):
    def setUp(self):
        super().setUp()
        for i in range(2):
            self.run_shard(i, 2)
        self.assertEqual(self.cert(2)[0], 1)               # positive control: the untouched bench is certified

    def refused(self, why, *extra, n=2):
        rc, cert, out = self.cert(n, *extra)
        self.assertEqual((rc, cert), (2, None), out)
        self.assertIn(why, out)

    def test_tree_changed_after_the_run(self):
        with open(os.path.join(self.tree, "lib.py"), "a") as fh:
            fh.write("# x\n")
        self.refused("not a mutants03 journal of this tree")

    def test_resume_under_another_tree_is_refused(self):
        with open(os.path.join(self.tree, "lib.py"), "a") as fh:
            fh.write("# x\n")
        r = self.run_shard(0, 2)
        self.assertEqual(r.returncode, 3)
        self.assertIn("JOURNAL REFUSED", r.stdout)

    def test_resume_with_other_inputs_is_refused(self):
        with open(self.env["APC_PULSE_CASES"], "a") as fh:
            fh.write("x")
        self.assertEqual(self.run_shard(1, 2).returncode, 3)

    def test_verdict_edited_in_place(self):
        for i in range(2):
            raw = read(self.j(i))
            if b'"verdict":"SURVIVED"' in raw:
                write(self.j(i), raw.replace(b'"verdict":"SURVIVED"', b'"verdict":"killed"', 1))
        self.refused("hash does not match")

    def test_tool_file_changed_after_the_run(self):
        p = os.path.join(self.tree, "tools", "run_ordered.py")
        write(p, read(p) + b"\n")
        self.refused("not a mutants03 journal of this tree")

    def test_prev_wrong_with_seq_right(self):
        lines = read(self.j(0)).splitlines(True)
        recs = [json.loads(x) for x in lines]
        del recs[2]
        out = []
        for k, r in enumerate(recs):
            r = {"seq": k, "prev": r["prev"], "kind": r["kind"], "body": r["body"]}
            r["hash"] = hashlib.sha256(bj.canonical(r)).hexdigest()
            out.append(bj.canonical(r) + b"\n")
        write(self.j(0), b"".join(out))
        self.refused("line 2: prev does not chain")

    def test_driver_refuses_a_name_recorded_twice(self):
        self.rewrite(0, lambda recs: recs + [r for r in recs if r["kind"] == "mutant"][:1])
        r = self.run_shard(0, 2)
        self.assertEqual(r.returncode, 3)
        self.assertIn("recorded twice", r.stdout)

    def test_job_without_journal(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "bench_journal.py"), "job",
                            os.path.join(self.d, "none.jsonl"), "x", os.path.join(self.d, "x.log"), "--", "true"],
                           capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (3, ""))
        self.assertIn("open it first", r.stdout)

    def test_line_deleted(self):
        lines = read(self.j(0)).splitlines(True)
        write(self.j(0), b"".join(lines[:2] + lines[3:]))
        self.refused("line 2: seq 3")

    def test_missing_mutant_even_with_a_valid_chain(self):
        self.rewrite(0, lambda recs: recs[:-1])
        self.refused("missing")

    def test_mutant_of_another_shard(self):
        other = [r for r in bj.read(self.j(1))[0] if r["kind"] == "mutant"][0]
        self.rewrite(0, lambda recs: recs + [other])
        self.refused("not of this shard")

    def test_recorded_twice(self):
        self.rewrite(0, lambda recs: recs + [r for r in recs if r["kind"] == "mutant"][:1])
        self.refused("recorded twice")

    def test_control_failed_or_missing(self):
        self.rewrite(0, lambda recs: [dict(r, body={"name": "control", "rc": 1}) if r["kind"] == "control" else r
                                      for r in recs])
        self.refused("control lines")
        self.rewrite(0, lambda recs: [r for r in recs if r["kind"] != "control"])
        self.refused("control lines")

    def test_missing_and_duplicate_shard(self):
        self.refused("missing [1]", n=1)
        r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "tools", "bench_cert.py"), self.tree,
                            self.j(0), self.j(0)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("twice", r.stdout)

    def test_unknown_kind_and_unknown_body_member(self):
        self.rewrite(0, lambda recs: recs + [{"kind": "note", "body": {}}])
        self.refused("unknown kind")
        self.rewrite(0, lambda recs: [dict(r, body=dict(r["body"], extra=1)) if r["kind"] == "mutant" else r
                                      for r in recs[:-1]])
        self.refused("members")

    def forge(self, name, **changes):
        for i in range(2):
            if any(r["kind"] == "mutant" and r["body"]["name"] == name for r in bj.read(self.j(i))[0]):
                self.rewrite(i, lambda recs: [dict(r, body=dict(r["body"], **changes))
                                              if r["kind"] == "mutant" and r["body"]["name"] == name else r
                                              for r in recs])

    def test_forged_verdict_with_a_valid_chain(self):
        self.forge("keep untested", verdict="killed", failed_test="FAIL: test_add (x.T.test_add)")
        self.refused("its evidence gives ('SURVIVED', '')")

    def test_forged_rc_without_a_failing_test(self):
        self.forge("keep untested", verdict="killed", rc=1)
        self.refused("its evidence gives ('INVALID(1)', '')")

    def test_invalid_cannot_be_called_killed(self):
        self.forge("crash exit", verdict="killed")
        self.refused("its evidence gives ('INVALID(3)', '')")

    def test_forged_mutated_file(self):
        self.forge("add broken", mutated_sha256="0" * 64)
        self.refused("not the mutant of this tree")

    def test_forged_stale_count(self):
        self.forge("stale pattern", count=2, verdict="STALE(2)")
        self.refused("the tree has the pattern 0 times")

    def test_forged_failed_test(self):
        self.forge("add broken", failed_test="FAIL: test_other (x.T.test_other)")
        self.refused("its evidence gives ('killed', 'FAIL: test_add")

    def test_forged_stale_verdict(self):
        self.forge("stale pattern", verdict="STALE(9)")
        self.refused("the tree has the pattern 0 times")

    def test_stale_recorded_as_run(self):
        src = read(os.path.join(self.tree, "lib.py"))
        body = {"verdict": "SURVIVED", "rc": 0, "failed_test": "", "stderr_sha256": "0" * 64, "stderr_excerpt": "",
                "seconds": 1, "utc": "2026-10-25T00:00:00Z", "mutated_sha256": hashlib.sha256(src).hexdigest()}
        for i in range(2):
            self.rewrite(i, lambda recs: [dict(r, body=dict(body, name="stale pattern"))
                                          if r["kind"] == "mutant" and r["body"]["name"] == "stale pattern" else r
                                          for r in recs])
        self.refused("was run, but its pattern is 0 times")

    def test_forged_control_evidence(self):
        for bad in ({"utc": "x"}, {"extra": 1}):
            self.rewrite(0, lambda recs: [dict(r, body=dict(r["body"], **bad)) if r["kind"] == "control" else r
                                          for r in recs])
            self.refused("control" if "extra" in bad else "wrong types")
            os.remove(self.j(0))
            self.run_shard(0, 2)

    def test_name_not_in_the_list(self):
        self.rewrite(0, lambda recs: [dict(r, body=dict(r["body"], name="no such mutant")) if r["kind"] == "mutant"
                                      else r for r in recs])
        self.refused("no such mutant is not of this shard")

    def test_evidence_types(self):
        for bad in ({"rc": "1"}, {"seconds": -1}, {"utc": "yesterday"}, {"stderr_sha256": "x"},
                    {"stderr_excerpt": "x" * 2001}):
            self.forge("add broken", **bad)
            self.refused("wrong types or values")
            for i in range(2):
                os.remove(self.j(i))
                self.run_shard(i, 2)

    def test_binding_differs_between_shards(self):
        self.rewrite(1, lambda recs: [dict(recs[0], body=dict(recs[0]["body"], python="other"))] + recs[1:])
        self.refused("same arguments")


class Edges(Base):
    def test_symlink_bound_by_its_target(self):
        os.symlink("lib.py", os.path.join(self.tree, "link.py"))
        os.symlink("tools", os.path.join(self.tree, "dlink"))
        before = bj.tree_digest(self.tree)
        self.assertEqual(self.run_shard(0, 1).returncode, 1)          # runs (1 = the known survivor)
        os.remove(os.path.join(self.tree, "link.py"))
        os.symlink("tools/run_ordered.py", os.path.join(self.tree, "link.py"))
        self.assertNotEqual(bj.tree_digest(self.tree), before)
        self.assertEqual(self.run_shard(0, 1).returncode, 3)          # retargeted link = another tree
        os.remove(os.path.join(self.tree, "link.py"))
        os.symlink("lib.py", os.path.join(self.tree, "link.py"))
        self.assertEqual(bj.tree_digest(self.tree), before)
        os.remove(os.path.join(self.tree, "dlink"))
        os.symlink(".", os.path.join(self.tree, "dlink"))
        self.assertNotEqual(bj.tree_digest(self.tree), before)        # a directory link is bound too

    def test_tree_of_a_missing_folder_refused(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "bench_journal.py"), "tree",
                            os.path.join(self.d, "none")], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (3, ""))
        self.assertIn("not a directory", r.stdout)

    def test_reserved_keys_of_open(self):
        tool = os.path.join(ROOT, "tools", "bench_journal.py")
        for extra in (["tree=x"], ["tool=x"], ["a=1", "a=2"], ["noequal"]):
            r = subprocess.run([sys.executable, tool, "open", os.path.join(self.d, "jj"), self.tree] + extra,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 3, extra)
            self.assertFalse(os.path.exists(os.path.join(self.d, "jj")))

    def test_recorded_control_failure_is_kept(self):
        write(os.path.join(self.tree, "tools", "run_ordered.py"), b"raise SystemExit(1)\n")
        self.assertEqual(self.run_shard(0, 1).returncode, 2)
        r = self.run_shard(0, 1)
        self.assertEqual(r.returncode, 2)
        self.assertIn("CONTROL FAILED (recorded in the journal)", r.stdout)
        self.assertEqual([x["kind"] for x in bj.read(self.j(0))[0]], ["open", "control"])

    def test_duplicate_mutant_names_refused_by_the_certificate(self):
        p = os.path.join(self.tree, "tools", "mutants03.py")
        write(p, read(p).replace(b'"add zero"', b'"add broken"'))
        self.run_shard(0, 1)
        rc, cert, out = self.cert(1)
        self.assertEqual(rc, 2)
        self.assertIn("share a name", out)


class ClosedFormat(unittest.TestCase):
    """every line that is not exactly a canonical 5-member record is refused (generative over members, types,
    encodings); the unchanged line is accepted (positive control)"""

    def line(self):
        r = {"seq": 0, "prev": bj.ZERO, "kind": "open", "body": {"a": 1}}
        r["hash"] = hashlib.sha256(bj.canonical(r)).hexdigest()
        return r

    def chain(self):
        out = [self.line()]
        for k, kind in ((1, "mutant"), (2, "mutant")):
            r = {"seq": k, "prev": out[-1]["hash"], "kind": kind, "body": {"name": "n%d" % k, "verdict": "killed"}}
            r["hash"] = hashlib.sha256(bj.canonical(r)).hexdigest()
            out.append(r)
        return out

    def test_generative_rehashed(self):
        """members, types and values changed on any of 3 lines, the hash RECOMPUTED (so that only the structural
        checks can refuse), the next line re-chained to it: every change is refused"""
        rnd = random.Random(11)
        values = [None, True, False, 0, 1, 2, -1, 1.0, "", "x", "open", [], {}, [1], bj.ZERO, "a" * 64, "A" * 64,
                  "0" * 63, 2 ** 70]
        n = 0
        for _ in range(1500):
            recs = self.chain()
            i = rnd.randrange(3)
            r = recs[i]
            op = rnd.randrange(3)
            if op == 0:
                r[rnd.choice(["extra", "Seq", "hash2", "", "seq "])] = rnd.choice(values)
            elif op == 1:
                del r[rnd.choice(sorted(k for k in r if k != "hash"))]
            else:
                k = rnd.choice(["seq", "prev", "kind", "body"])
                v = rnd.choice(values)
                if v == r[k] and type(v) is type(r[k]):
                    continue
                if k == "body" and isinstance(v, dict) or k == "kind" and i > 0 and isinstance(v, str) and v \
                        and v != "open":
                    continue                                # still a valid journal by the format
                r[k] = v
            if "hash" in r:
                del r["hash"]
                r["hash"] = hashlib.sha256(bj.canonical(r)).hexdigest()
            if i < 2:
                nxt = recs[i + 1]
                nxt["prev"] = r["hash"]
                del nxt["hash"]
                nxt["hash"] = hashlib.sha256(bj.canonical(nxt)).hexdigest()
                if i == 0 and len(recs) > 2:
                    recs[2]["prev"] = nxt["hash"]
                    del recs[2]["hash"]
                    recs[2]["hash"] = hashlib.sha256(bj.canonical(recs[2])).hexdigest()
            data = b"".join(bj.canonical(x) + b"\n" for x in recs)
            n += 1
            with self.assertRaises(bj.JournalError, msg=data):
                self.check(data)
        self.assertGreater(n, 1300)

    def check(self, data):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "j")
            write(p, data)
            return bj.read(p)
        finally:
            shutil.rmtree(d)

    def test_positive_control(self):
        recs, torn = self.check(bj.canonical(self.line()) + b"\n")
        self.assertEqual((len(recs), torn), (1, b""))

    def test_generative(self):
        rnd = random.Random(7)
        values = [None, True, 0, -1, 1.5, "", "x", [], {}, [1], {"k": 1}, bj.ZERO, "A" * 64, 2 ** 70]
        n = 0
        for _ in range(600):
            r = self.line()
            op = rnd.randrange(5)
            if op == 0:
                r[rnd.choice(["extra", "Seq", "hash2", "", "seq "])] = rnd.choice(values)
            elif op == 1:
                del r[rnd.choice(sorted(r))]
            elif op == 2:
                k = rnd.choice(sorted(r))
                v = rnd.choice(values)
                if v == r[k] and type(v) is type(r[k]):
                    continue
                r[k] = v
            elif op == 3:
                raw = bj.canonical(r)
                i = rnd.randrange(len(raw))
                data = raw[:i] + bytes([rnd.randrange(256)]) + raw[i + 1:]
                if data == raw:
                    continue
                n += 1
                with self.assertRaises(bj.JournalError, msg=data):
                    self.check(data + b"\n")
                continue
            else:
                raw = rnd.choice([b"\xef\xbb\xbf" + bj.canonical(r), bj.canonical(r).replace(b",", b", ", 1),
                                  json.dumps(r).encode(), bj.canonical(r)[:-1] + b',"seq":0}',
                                  bj.canonical(r).replace(b"}", b"}\r", 1)[:-1] + b"}", b"[]", b"null",
                                  bj.canonical(r).replace(b'"a":1', b'"a":NaN')])
                n += 1
                with self.assertRaises(bj.JournalError, msg=raw):
                    self.check(raw + b"\n")
                continue
            n += 1
            data = json.dumps(r, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            with self.assertRaises(bj.JournalError, msg=data):
                self.check(data)
        self.assertGreater(n, 500)

    def test_second_open_and_first_not_open(self):
        a = self.line()
        b = {"seq": 1, "prev": a["hash"], "kind": "open", "body": {}}
        b["hash"] = hashlib.sha256(bj.canonical(b)).hexdigest()
        with self.assertRaises(bj.JournalError):
            self.check(bj.canonical(a) + b"\n" + bj.canonical(b) + b"\n")
        c = dict(a, kind="mutant")
        del c["hash"]
        c["hash"] = hashlib.sha256(bj.canonical(c)).hexdigest()
        with self.assertRaises(bj.JournalError):
            self.check(bj.canonical(c) + b"\n")


class Jobs(Base):
    def test_job_once_and_certified(self):
        jj = os.path.join(self.d, "jobs.jsonl")
        tool = os.path.join(ROOT, "tools", "bench_journal.py")
        self.assertEqual(subprocess.run([sys.executable, tool, "open", jj, self.tree, "bench=b"]).returncode, 0)
        log = os.path.join(self.d, "suite.log")
        cmd = [sys.executable, tool, "job", jj, "suite", log, "--", "sh", "-c", "echo run >> %s.count; echo ok" % log]
        for _ in range(3):
            subprocess.run(cmd, capture_output=True)
        self.assertEqual(read(log + ".count"), b"run\n")          # run once, recorded twice as done
        self.run_shard(0, 1)
        rc, cert, out = self.cert(1, "--jobs", jj, "suite")
        self.assertEqual((rc, cert["jobs"]["names"]), (1, ["suite"]), out)
        write(log, read(log) + b"changed")
        rc, cert, out = self.cert(1, "--jobs", jj, "suite")
        self.assertEqual(rc, 2)
        self.assertIn("changed since", out)
        r = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)

    def test_log_outside_the_journal_folder_refused(self):
        jj = os.path.join(self.d, "jobs.jsonl")
        tool = os.path.join(ROOT, "tools", "bench_journal.py")
        subprocess.run([sys.executable, tool, "open", jj, self.tree])
        r = subprocess.run([sys.executable, tool, "job", jj, "x", os.path.join(self.tree, "x.log"), "--", "true"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)
        self.assertNotIn("x.log", os.listdir(self.tree))


if __name__ == "__main__":
    unittest.main()
