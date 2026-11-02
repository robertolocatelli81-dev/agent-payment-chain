"""SPEC 29.6 and 29.8 for the equivalence tools: tools/equiv_x04.py, tools/equiv_r02.py and tools/equiv_mutants.py (c3)
read the real bundles by the closed table of bundle versions (tests/test_apc03.real_bundles), never by a glob. Until
2026-10-27 equiv_x04 also read the 562 (564 since 2026-10-31) Solana and XRPL bundles of bundles/real* that carry settlement and chain_tx,
equiv_r02 read bundles/*/*.json (every directory, real or not), and equiv_mutants c3 took its files in the file
system's order. A bundle of a version not in the table must stop all three."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
from test_apc03 import REAL_KINDS, load, real_bundles  # noqa: E402


def listed(root, *args):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.setdefault("APC_SIGLIB", os.path.join(ROOT, os.pardir, "x402-signature-vectors"))   # the copy is elsewhere
    r = subprocess.run([sys.executable, "-B"] + list(args) + ["--list"], cwd=root, env=env, capture_output=True, text=True)
    return r.returncode, r.stdout.split(), r.stderr


def tree_with(extra_dir, doc):
    """A copy of the repository made of symbolic links, with one more directory bundles/EXTRA_DIR holding DOC."""
    tmp = tempfile.mkdtemp(prefix="apceq_")
    for name in os.listdir(ROOT):
        if name not in ("bundles", ".git", "__pycache__"):
            os.symlink(os.path.join(ROOT, name), os.path.join(tmp, name))
    os.mkdir(os.path.join(tmp, "bundles"))
    for name in os.listdir(os.path.join(ROOT, "bundles")):
        os.symlink(os.path.join(ROOT, "bundles", name), os.path.join(tmp, "bundles", name))
    os.mkdir(os.path.join(tmp, "bundles", extra_dir))
    with open(os.path.join(tmp, "bundles", extra_dir, "b001.json"), "w") as fh:
        json.dump(doc, fh)
    return tmp


class EquivX04(unittest.TestCase):
    def test_reads_only_evm_bundles(self):
        rc, paths, err = listed(ROOT, "tools/equiv_x04.py", ".")
        self.assertEqual(rc, 0, err)
        want = [os.path.relpath(p, ROOT) for p in real_bundles("evm")
                if "settlement" in load(p) and "chain_tx" in load(p)]
        self.assertEqual(paths, want)
        self.assertGreater(len(paths), 200)
        # the check can fail: the corpus holds Solana and XRPL bundles with settlement and chain_tx
        other = [p for k in ("solana", "xrpl") for p in real_bundles(k) if "settlement" in load(p) and "chain_tx" in load(p)]
        self.assertEqual(len(other), 564)     # 562 until 2026-10-30; + the 2 of bundles/real_svm_mandate (SPEC 31.9)
        self.assertFalse(set(os.path.relpath(p, ROOT) for p in other) & set(paths))

    def test_unknown_version_stops_it(self):
        doc = load(real_bundles("evm")[0])
        self.assertIn("settlement", doc)
        doc["bundle_version"] = "apc-0.99"
        tmp = tree_with("real_zz_unknown", doc)
        try:
            rc, paths, err = listed(tmp, "tools/equiv_x04.py", ".")
        finally:
            shutil.rmtree(tmp)
        self.assertNotEqual(rc, 0)
        self.assertIn("is not in REAL_KINDS", err)


class EquivR02(unittest.TestCase):
    def test_reads_only_real_evm_bundles(self):
        rc, paths, err = listed(ROOT, "tools/equiv_r02.py", ".")
        self.assertEqual(rc, 0, err)
        want = [os.path.relpath(p, ROOT) for p in real_bundles("evm") if isinstance(load(p).get("chain_tx"), dict)]
        self.assertEqual(paths, want)
        self.assertGreater(len(paths), 200)
        self.assertTrue(all(p.split(os.sep)[1].startswith("real") for p in paths))

    def test_unknown_version_stops_it(self):
        doc = load(real_bundles("evm")[0])
        doc["bundle_version"] = "apc-0.99"
        tmp = tree_with("real_zz_unknown", doc)
        try:
            rc, paths, err = listed(tmp, "tools/equiv_r02.py", ".")
        finally:
            shutil.rmtree(tmp)
        self.assertNotEqual(rc, 0)
        self.assertIn("is not in REAL_KINDS", err)


class EquivC3(unittest.TestCase):
    @real_corpus.unless("real_v03_canonical")          # the glob of real_v02*/real_v03* counts the local_only set too
    def test_reads_evm_bundles_sorted(self):
        rc, paths, err = listed(ROOT, "tools/equiv_mutants.py", ".", "c3", "1")
        self.assertEqual(rc, 0, err)
        self.assertEqual(paths, sorted(paths))
        self.assertGreater(len(paths), 90)
        for p in paths:
            self.assertEqual(REAL_KINDS[load(os.path.join(ROOT, p))["bundle_version"]], "evm", p)
            self.assertTrue(p.split(os.sep)[1].startswith(("real_v02", "real_v03")), p)

    def test_unknown_version_stops_it(self):
        doc = next(d for d in map(load, real_bundles("evm")) if d["bundle_version"] == "apc-0.3" and "chain_tx" in d
                   and d["chain_tx"]["tx"]["to"].lower() != d["payment_payload"]["accepted"]["asset"].lower())
        doc["bundle_version"] = "apc-0.99"
        tmp = tree_with("real_v03_zz_unknown", doc)
        try:
            rc, paths, err = listed(tmp, "tools/equiv_mutants.py", ".", "c3", "1")
        finally:
            shutil.rmtree(tmp)
        self.assertNotEqual(rc, 0)
        self.assertIn("is not in REAL_KINDS", err)


if __name__ == "__main__":
    unittest.main()
