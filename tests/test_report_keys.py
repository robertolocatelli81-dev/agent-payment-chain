"""SPEC 0.14 (section 22): signed report version 2 (the signature covers signed_at) and the reader's key validity
windows. Key: RFC 8032 7.1 test 1 (its seed and public key). Real report: apc_verify's report on a real bundle.
Positive control: apc_report 0.8.0 (5cbe7c7) does not read a version 2 document (refused, exit 3)."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_report as rp  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
V002 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")


def old_tree(tmp):
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def report():
    with open(V002) as fh:
        return av.verify_bundle(av.strict_json(fh.read()))


def keys(vf="2026-01-01T00:00:00Z", vt="2026-12-31T23:59:59Z", pub=PUB):
    return rp.parse_keys({"apc_report_keys": 1, "keys": [{"public_key": pub, "valid_from": vf, "valid_to": vt}]})


class Window(unittest.TestCase):
    def test_rfc8032_key(self):
        self.assertEqual(rp.sign(report(), SEED)["public_key"], PUB)

    def test_window(self):
        r = report()
        s = rp.sign(r, SEED, "2026-10-26T08:00:00Z")
        self.assertEqual(s["apc_signed_report"], 2)
        self.assertEqual(rp.verify(s), "verified")
        self.assertEqual(rp.verify(s, None, keys()), "verified")
        self.assertEqual(rp.verify(s, None, keys(vt=None)), "verified")
        self.assertEqual(rp.verify(s, None, keys(vf="2026-10-26T08:00:01Z")), "failed:key_not_valid_before_valid_from")
        self.assertEqual(rp.verify(s, None, keys(vt="2026-10-26T07:59:59Z")), "failed:key_not_valid_after_valid_to")
        self.assertEqual(rp.verify(s, None, keys(vf="2026-10-26T08:00:00Z", vt="2026-10-26T08:00:00Z")), "verified")
        self.assertEqual(rp.verify(s, None, keys(pub="00" * 32)), "failed:signed_by_another_key")
        t = copy.deepcopy(s)
        t["signed_at"] = "2026-03-01T00:00:00Z"                  # moving the time breaks the signature
        self.assertEqual(rp.verify(t, None, keys()), "failed:signature_invalid")
        v1 = rp.sign(r, SEED)
        self.assertEqual(rp.verify(v1), "verified")
        self.assertEqual(rp.verify(v1, None, keys()), "not_evaluated:v1_has_no_signed_at")

    def test_grammar(self):
        s = rp.sign(report(), SEED, "2026-10-26T08:00:00Z")
        for mut in (lambda d: d.pop("signed_at"), lambda d: d.__setitem__("signed_at", "2026-10-26 08:00:00"),
                    lambda d: d.__setitem__("signed_at", "2026-02-30T00:00:00Z"), lambda d: d.__setitem__("x", 1),
                    lambda d: d.__setitem__("apc_signed_report", 3), lambda d: d.__setitem__("apc_signed_report", True)):
            d = copy.deepcopy(s)
            mut(d)
            with self.assertRaises(rp.Bad):
                rp.verify(d)
        for bad in (None, {}, {"apc_report_keys": 1, "keys": []},
                    {"apc_report_keys": 1, "keys": [{"public_key": PUB, "valid_from": "2026-01-01T00:00:00Z"}]},
                    {"apc_report_keys": 1, "keys": [{"public_key": PUB, "valid_from": "2026-02-01T00:00:00Z",
                                                     "valid_to": "2026-01-01T00:00:00Z"}]},
                    {"apc_report_keys": 1, "keys": [{"public_key": PUB, "valid_from": "2026-01-01T00:00:00Z", "valid_to": None}] * 2}):
            with self.assertRaises(rp.Bad):
                rp.parse_keys(bad)
        with self.assertRaises(rp.Bad):
            rp.sign(report(), SEED, "yesterday")

    def test_cli_and_positive_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed, rep, sig, ks = (os.path.join(tmp, n) for n in ("seed", "r.json", "s.json", "k.json"))
            with open(seed, "w") as fh:
                fh.write(SEED.hex() + "\n")
            with open(rep, "w") as fh:
                json.dump(report(), fh)
            with open(ks, "w") as fh:
                json.dump({"apc_report_keys": 1, "keys": [{"public_key": PUB, "valid_from": "2026-11-01T00:00:00Z",
                                                           "valid_to": None}]}, fh)
            run = lambda *a: subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_report.py")] + list(a),  # noqa: E731
                                            capture_output=True, text=True)
            out = run("sign", seed, rep, "--signed-at", "2026-10-26T08:00:00Z")
            with open(sig, "w") as fh:
                fh.write(out.stdout)
            r = run("verify", sig, "--keys", ks)
            self.assertEqual((r.returncode, json.loads(r.stdout)["signature"]), (1, "failed:key_not_valid_before_valid_from"))
            self.assertEqual(run("verify", sig).returncode, 0)
            os.makedirs(os.path.join(tmp, "old"))
            old_tree(os.path.join(tmp, "old"))
            r = subprocess.run([sys.executable, "-B", os.path.join(tmp, "old", "apc_report.py"), "verify", sig],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 3)


if __name__ == "__main__":
    unittest.main()
