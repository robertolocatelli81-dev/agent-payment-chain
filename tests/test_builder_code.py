"""Amendment 0.11.1: the x402 builder-code attribution (ERC-8021 Schema 2 CBOR in settlement calldata; BC1). Real data:
every Schema 2 suffix of the transactions in oracle/ (Base, read by public RPC); the real bundles of bundles/. Positive
control: apc_verify 0.8.0 (5cbe7c7) keeps chain_verified for a bundle whose echoed app code contradicts the declared
one."""
import copy
import glob
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_builder as bc  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
AW = os.path.join(ROOT, "bundles", "real", "real_003_envelope_reconstructed.json")         # calldata {a, w}
W = os.path.join(ROOT, "bundles", "real", "real_001_envelope_reconstructed.json")          # calldata {w}


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Refusal as e:
        return {"verdict": "refused", "checks": {}, "reason": str(e)}


def real_suffixes():
    seen, out = set(), []
    for f in sorted(glob.glob(os.path.join(ROOT, "oracle", "*.json"))):
        with open(f) as fh:
            d = json.load(fh)
        for c in d.get("calls", []) if isinstance(d, dict) else []:
            if c.get("method") != "eth_getTransactionByHash" or not isinstance(c.get("result"), dict):
                continue
            tx = c["result"]
            if tx["hash"] in seen:
                continue
            seen.add(tx["hash"])
            b = bytes.fromhex(tx["input"][2:])
            if len(b) >= 19 and b[-16:] == av.ERC8021_MARKER and b[-17] == 2:
                n = int.from_bytes(b[-19:-17], "big")
                out.append(b[-19 - n:-19])
    return out


def cbor_text(s):
    b = s.encode()
    return (bytes([0x60 + len(b)]) if len(b) < 24 else bytes([0x78, len(b)])) + b


# oracle/*.json: the census windows (local_only in the list) and the reverted-call scan (not in the list)
@real_corpus.unless(oracle=("census_base_*.json", "reverted_base_53101000_2000.json"))
class RealSuffixes(unittest.TestCase):
    def test_every_real_suffix_decodes(self):
        sx = real_suffixes()
        kinds = {}
        for cb in sx:
            v, why = bc.decode(cb)
            self.assertIsNone(why, cb.hex())
            kinds[",".join(v)] = kinds.get(",".join(v), 0) + 1
        # 1099 since oracle/reverted_base_53101000_2000.json (ad03a85): one more "w" suffix, on a reverted transaction
        self.assertEqual(len(sx), 1099)
        self.assertEqual(kinds, {"w": 839, "a,w": 220, "w,s": 29, "a,w,s": 11})

    def test_mutated_real_suffixes_never_raise(self):
        rnd = random.Random(26)
        sx = real_suffixes()[::50]
        n = 0
        for cb in sx:
            for _ in range(60):
                b = bytearray(cb)
                op = rnd.randrange(3)
                if op == 0:
                    b[rnd.randrange(len(b))] = rnd.randrange(256)
                elif op == 1:
                    del b[rnd.randrange(len(b)):]
                else:
                    b.insert(rnd.randrange(len(b) + 1), rnd.randrange(256))
                v, why = bc.decode(bytes(b))
                self.assertTrue((v is None) != (why is None))
                if v is not None:
                    self.assertTrue(set(v) <= {"a", "w", "s", "m"})
                n += 1
        self.assertGreater(n, 1000)


class Grammar(unittest.TestCase):
    def test_rules(self):
        w = cbor_text("w") + cbor_text("cdp_facil1")
        s = cbor_text("s") + b"\x81" + cbor_text("blockrun")
        self.assertEqual(bc.decode(b"\xa1" + w), ({"w": "cdp_facil1"}, None))
        self.assertEqual(bc.decode(b"\xa2" + w + s)[0], {"w": "cdp_facil1", "s": ["blockrun"]})
        cases = {
            "top_level_keys_not_in_order_a_w_s_m": b"\xa2" + s + w,
            "top_level_keys_not_in_order_a_w_s_m ": b"\xa2" + w + w,          # duplicate
            "not_shortest_form": b"\xb8\x01" + w,
            "indefinite_or_reserved_length": b"\xbf" + w + b"\xff",
            "bytes_after_the_map": b"\xa1" + w + b"\x00",
            "key_not_x402_builder_code:r": b"\xa2" + w + cbor_text("r") + cbor_text("x"),
            "w_not_a_builder_code": b"\xa1" + cbor_text("w") + cbor_text("CDP"),
            "s_not_builder_codes": b"\xa1" + cbor_text("s") + b"\x80",
            "m_key_not_x402": b"\xa1" + cbor_text("m") + b"\xa1" + cbor_text("foo") + b"\x01",
            "major_type_1_not_allowed": b"\xa1" + cbor_text("m") + b"\xa1" + cbor_text("x402a") + b"\x20",
            "major_type_2_not_allowed": b"\xa1" + cbor_text("m") + b"\xa1" + cbor_text("x402a") + b"\x41\x00",
            "major_type_7_not_allowed": b"\xa1" + cbor_text("m") + b"\xa1" + cbor_text("x402a") + b"\xf5",
            "map_keys_not_sorted_bytewise": b"\xa1" + cbor_text("m") + b"\xa2" + cbor_text("x402b") + b"\x01"
                                            + cbor_text("x402a") + b"\x01",
            "text_not_utf8": b"\xa1" + cbor_text("w") + b"\x62\xff\xfe",
            "truncated": b"\xa1" + cbor_text("w") + b"\x6a\x63",
            "not_a_map": b"\x80",
            "empty_map": b"\xa0",
            "nested_too_deep": b"\xa1" + cbor_text("m") + b"\xa1" + cbor_text("x402a") + b"\x81" * 20 + b"\x00",
        }
        for want, raw in cases.items():
            self.assertEqual(bc.decode(raw), (None, want.strip()), want)
        ok = b"\xa1" + cbor_text("m") + b"\xa2" + cbor_text("x402a") + b"\x01" + cbor_text("x402b") + b"\x18\x18"
        self.assertEqual(bc.decode(ok)[0], {"m": {"x402a": 1, "x402b": 24}})


class Bundles(unittest.TestCase):
    def decl(self, d, srv=None, cli=None):
        if srv is not None:
            d["payment_required"] = {"x402Version": 2, "resource": {"url": "https://api.example.com/r"},
                                     "accepts": [d["payment_payload"]["accepted"]],
                                     "extensions": {"builder-code": {"info": srv}}}
        if cli is not None:
            d["payment_payload"].setdefault("extensions", {})["builder-code"] = cli
        return d

    def test_report_member_on_real_bundles(self):
        r = run(load(AW))
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertEqual(set(r["builder_code"]["calldata"]), {"a", "w"})
        self.assertNotIn("BC1", r["checks"])
        self.assertNotIn("builder_code", run(load(os.path.join(ROOT, "bundles", "real", "real_012_envelope_reconstructed.json"))))

    def test_bc1(self):
        a = run(load(AW))["builder_code"]["calldata"]["a"]
        for srv, cli, want in (({"a": a}, {"a": a}, "verified"),
                               ({"a": a}, {"a": "other_app"}, "failed:builder_code_app_echo_mismatch"),
                               ({}, {"a": a}, "failed:builder_code_app_not_declared"),
                               ({"a": "other_app"}, {"a": "other_app"}, "failed:builder_code_calldata_app_mismatch"),
                               ({"a": a}, None, "verified")):
            r = run(self.decl(load(AW), srv, cli))
            self.assertEqual(r["checks"]["BC1"], want, (srv, cli))
        r = run(self.decl(load(W), {"a": "my_app"}, {"a": "my_app"}))
        # the facilitator wrote a suffix ({w}) without the echoed a: BC Facilitator Behavior step 1 reads a from the payload
        self.assertEqual(r["checks"]["BC1"], "failed:builder_code_calldata_app_mismatch")
        # closed declarations
        for srv, cli in (({"a": "My_App"}, None), ({"a": "x", "z": 1}, None), (None, {"a": "x", "w": "y"}),
                         (None, {"s": []}), (None, {"s": 5})):
            self.assertEqual(run(self.decl(load(AW), srv, cli))["verdict"], "refused", (srv, cli))

    def test_positive_control_old_verifier(self):
        d = self.decl(load(AW), {"a": "other_app"}, {"a": "other_app"})
        self.assertEqual(run(d)["verdict"], "chain_failed")
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            p = os.path.join(tmp, "b.json")
            with open(p, "w") as fh:
                json.dump(d, fh)
            rep = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), p],
                                            capture_output=True, text=True).stdout)
            self.assertEqual((rep["verifier"], rep["verdict"]), ("apc_verify 0.8.0", "chain_verified"))


if __name__ == "__main__":
    unittest.main()
