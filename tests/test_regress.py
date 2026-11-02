"""Frozen regression corpus (tools/regress.py, regress/VERDICTS.json, regress/CHANGES.md).

Default: a deterministic sample of the corpus through apc_verify (tools/regress.py check --sample), the sha256 of EVERY
bundle against the frozen file, and the positive controls of the comparison (a changed verdict, check, digest, an
added or removed bundle must each fail without its CHANGES.md row and pass with it). The full corpus through apc_verify
is `python3 tools/regress.py check`, a job of the final round (time in regress/MANIFEST)."""
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("*", "real_v03_canonical", "real_v04_l1state", "xlm_real_20261026")   # the frozen corpus is the whole corpus   # the real corpus is not distributed (SPEC 33): skip with the reason
from tools import regress as rg  # noqa: E402

FROZEN = rg.load_frozen()


def quiet(*_a):
    pass


def changes(text):
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as fh:
        fh.write(text)
    try:
        return rg.read_changes(fh.name)
    finally:
        os.unlink(fh.name)


HEAD = "| path | field | old | new | SPEC | reason |\n|---|---|---|---|---|---|\n"


class Corpus(unittest.TestCase):
    def test_every_bundle_frozen_with_its_digest(self):
        paths = rg.corpus()
        self.assertEqual(sorted(FROZEN), paths)
        for p in paths:
            self.assertEqual(hashlib.sha256(open(os.path.join(ROOT, p), "rb").read()).hexdigest(), FROZEN[p]["sha256"], p)

    def test_sample_unchanged(self):
        now, d, bad = rg.check(sample=True, log=quiet)
        self.assertEqual(bad, [])
        self.assertGreater(len(now), 30)
        dirs = {rg.directory(p) for p in now}
        self.assertEqual(dirs, {rg.directory(p) for p in FROZEN})

    def test_frozen_file_canonical_and_in_manifest(self):
        text = open(os.path.join(rg.REG, "VERDICTS.json"), encoding="utf-8").read()
        doc = json.loads(text)
        rows = doc["bundles"]
        self.assertEqual([r["path"] for r in rows], sorted(r["path"] for r in rows))
        want = '{"bundles":[\n' + ",\n".join(rg.canon(r) for r in rows) + '\n],"verifier":' + rg.canon(doc["verifier"]) + "}\n"
        self.assertEqual(text, want)
        man = open(os.path.join(rg.REG, "MANIFEST"), encoding="utf-8").read()
        self.assertIn("VERDICTS.json sha256: " + hashlib.sha256(text.encode()).hexdigest(), man)
        self.assertEqual(set(rows[0]), {"path", "sha256", "bundle_version", "options", "exit", "verdict", "checks", "verifier"})

    def test_changes_file_parses(self):
        rg.read_changes()


class Controls(unittest.TestCase):
    """Positive controls: the comparison must see each kind of change."""

    @classmethod
    def setUpClass(cls):
        verified = sorted(p for p in FROZEN if FROZEN[p]["verdict"] == "chain_verified")
        failed = sorted(p for p in FROZEN if FROZEN[p]["verdict"] == "chain_failed")
        cls.paths = [verified[0], failed[0]]
        cls.now = {p: rg.run_one(p) for p in cls.paths}
        cls.frozen = {p: FROZEN[p] for p in cls.paths}

    def test_identical(self):
        self.assertEqual(rg.diffs(self.frozen, self.now), [])

    def test_verdict_changed(self):
        p = self.paths[0]
        f = copy.deepcopy(self.frozen)
        f[p]["verdict"] = "chain_failed"
        self.assertEqual(rg.diffs(f, self.now), [(p, "verdict", "chain_failed", "chain_verified")])

    def test_check_changed_added_dropped(self):
        p = self.paths[1]
        c = sorted(self.now[p]["checks"])[0]
        f = copy.deepcopy(self.frozen)
        f[p]["checks"][c] = "not_evaluated:x"
        f[p]["checks"]["ZZ9"] = "verified"
        d = rg.diffs(f, self.now)
        self.assertIn((p, "check:" + c, "not_evaluated:x", self.now[p]["checks"][c]), d)
        self.assertIn((p, "check:ZZ9", "verified", "-"), d)
        self.assertEqual(len(d), 2)

    def test_digest_version_exit_changed(self):
        p = self.paths[0]
        for k, v in (("sha256", "00" * 32), ("bundle_version", "apc-9"), ("exit", 7)):
            f = copy.deepcopy(self.frozen)
            f[p][k] = v
            self.assertEqual(rg.diffs(f, self.now), [(p, k, str(v), str(self.now[p][k]))], k)

    def test_added_removed(self):
        p, q = self.paths
        self.assertEqual(rg.diffs({p: self.frozen[p]}, self.now), [(q, "added", "-", self.now[q]["verdict"])])
        self.assertEqual(rg.diffs(self.frozen, {p: self.now[p]}), [(q, "removed", self.frozen[q]["verdict"], "-")])

    def test_verifier_string(self):
        p = self.paths[0]
        f = copy.deepcopy(self.frozen)
        f[p]["verifier"] = "apc_verify 0.0.1"
        self.assertEqual(rg.diffs(f, self.now), [])            # the current release: no row needed
        n = copy.deepcopy(self.now)
        n[p]["verifier"] = "apc_verify 9.9.9"
        self.assertEqual(rg.diffs(f, n), [(p, "verifier", "apc_verify 0.0.1", "apc_verify 9.9.9")])

    def test_check_fails_without_row_passes_with_row(self):
        p = self.paths[0]
        f = copy.deepcopy(FROZEN)
        f[p]["verdict"] = "chain_incomplete"
        with mock.patch.object(rg, "corpus", return_value=list(self.paths)):
            bad = rg.check(frozen={k: f[k] for k in self.paths}, changes=set(), log=quiet)[2]
            self.assertEqual(bad, [(p, "verdict", "chain_incomplete", "chain_verified")])
            row = changes(HEAD + "| %s | verdict | chain_incomplete | chain_verified | §29 | control |\n" % p)
            self.assertEqual(rg.check(frozen={k: f[k] for k in self.paths}, changes=row, log=quiet)[2], [])
            stale = row | {(self.paths[1], "verdict", "chain_failed", "chain_verified")}
            with self.assertRaises(rg.Refused):
                rg.check(frozen={k: f[k] for k in self.paths}, changes=stale, log=quiet)

    def test_sample_sees_a_changed_verdict(self):
        """the sampled path: a frozen verdict changed in memory on a bundle the sample takes is unjustified"""
        f = copy.deepcopy(FROZEN)
        pick = sorted((v["sha256"], p) for p, v in f.items() if rg.directory(p) == "bundles/real"
                      and v["verdict"] == "chain_verified")[0][1]
        f[pick]["verdict"] = "chain_failed"
        with mock.patch.object(rg, "corpus", return_value=sorted(p for p in FROZEN if rg.directory(p) == "bundles/real")):
            bad = rg.check(sample=True, frozen=f, changes=set(), log=quiet)[2]
        self.assertEqual(bad, [(pick, "verdict", "chain_failed", "chain_verified")])


class ChangesGrammar(unittest.TestCase):
    def test_rows(self):
        p = "bundles/real/real_001_envelope_reconstructed.json"
        self.assertEqual(changes(HEAD + "| %s | check:L2.sig | verified | failed:x | §29.1 | why |\n" % p),
                         {(p, "check:L2.sig", "verified", "failed:x")})
        self.assertEqual(changes(HEAD + "text\n\n"), set())

    def test_refused(self):
        p = "bundles/real/real_001_envelope_reconstructed.json"
        for bad in ("| %s | verdict | a | b | 29 | why |" % p,              # section without §
                    "| %s | verdict | a | b | §29 | |" % p,               # no reason
                    "| %s | verdict | a | b | §29 |  |" % p,              # empty reason
                    "| %s | verdict | a | b | §29 |   |" % p,             # blank reason
                    "| %s | colour | a | b | §29 | why |" % p,            # unknown field
                    "| other/x.json | verdict | a | b | §29 | why |",
                    "| %s | verdict | a | b | §29 | why | extra |" % p,
                    "|%s | verdict | a | b | §29 | why |" % p):
            with self.assertRaises(rg.Refused, msg=bad):
                changes(HEAD + bad + "\n")

    def test_outside_dirs_refused(self):
        with self.assertRaises(rg.Refused):
            rg.directory("bundles/unknown_dir/x.json")
        self.assertEqual(rg.directory("bundles/real_world_20261026/arb_usdc/x.json"), "bundles/real_world_20261026")


class Cli(unittest.TestCase):
    def test_check_exit_and_write_refusal(self):
        """main: check exits 1 on an unjustified change, write refuses it and leaves the frozen file as it was, and
        writes once the CHANGES.md row is there"""
        verified = sorted(p for p in FROZEN if FROZEN[p]["verdict"] == "chain_verified")[:1]
        failed = sorted(p for p in FROZEN if FROZEN[p]["verdict"] == "chain_failed")[:1]
        paths = verified + failed
        with tempfile.TemporaryDirectory() as reg:
            bad = copy.deepcopy({p: FROZEN[p] for p in paths})
            bad[paths[0]]["verdict"] = "chain_incomplete"
            text = '{"bundles":[\n' + ",\n".join(rg.canon(bad[p]) for p in paths) + '\n],"verifier":"x"}\n'
            with open(os.path.join(reg, "VERDICTS.json"), "w") as fh:
                fh.write(text)
            with open(os.path.join(reg, "CHANGES.md"), "w") as fh:
                fh.write(HEAD)
            with mock.patch.object(rg, "REG", reg), mock.patch.object(rg, "corpus", return_value=paths), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(rg.main(["regress.py", "check"]), 1)
                self.assertEqual(rg.main(["regress.py", "check", "--sample"]), 1)
                self.assertEqual(rg.main(["regress.py", "write"]), 1)
                self.assertEqual(open(os.path.join(reg, "VERDICTS.json")).read(), text)
                with open(os.path.join(reg, "CHANGES.md"), "a") as fh:
                    fh.write("| %s | verdict | chain_incomplete | chain_verified | §29 | control |\n" % paths[0])
                self.assertEqual(rg.main(["regress.py", "check"]), 0)
                self.assertEqual(rg.main(["regress.py", "write"]), 0)
                rows = {r["path"]: r for r in json.load(open(os.path.join(reg, "VERDICTS.json")))["bundles"]}
                self.assertEqual(rows[paths[0]]["verdict"], "chain_verified")
                self.assertTrue(os.path.exists(os.path.join(reg, "MANIFEST")))
                with open(os.path.join(reg, "CHANGES.md"), "a") as fh:
                    fh.write("| bad row |\n")
                self.assertEqual(rg.main(["regress.py", "check"]), 3)
            with open(os.path.join(reg, "VERDICTS.json"), "w") as fh:          # a bundle the frozen file lacks
                fh.write('{"bundles":[\n' + rg.canon(FROZEN[paths[0]]) + '\n],"verifier":"x"}\n')
            with open(os.path.join(reg, "CHANGES.md"), "w") as fh:
                fh.write(HEAD)
            with mock.patch.object(rg, "REG", reg), mock.patch.object(rg, "corpus", return_value=paths), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(rg.main(["regress.py", "check", "--sample"]), 1)

    def test_usage(self):
        for argv in ([], ["x"], ["check", "--full"], ["write", "--sample"], ["check", "--sample", "--sample"]):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(rg.main(["regress.py"] + argv), 64, argv)


if __name__ == "__main__":
    unittest.main()
