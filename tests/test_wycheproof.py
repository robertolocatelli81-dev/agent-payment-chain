"""SPEC 0.17 (section 28.1, 28.2, 28.4): every vector of five Wycheproof files (C2SP/wycheproof d17cc89,
sources/wycheproof_d17cc89, Apache-2.0) run against our own signature code, counted by result and flag. Wycheproof's
`result` is the reference; a difference is either a declared chain rule (counted apart, with the rule) or a defect.

What each class measures:
- Ed25519 (ed25519_test.json, 210): apc_solana.ed25519_verify under the three rules of 28.1.
- secp256k1 DER (ecdsa_secp256k1_sha256_bitcoin_test.json 464, ecdsa_secp256k1_sha256_test.json 476): apc_xrpl's
  rippled rule (strict DER, fully canonical) with the vector's key compressed to the 33 bytes XRPL carries and the
  digest SHA-256(msg) in place of SHA-512Half.
- secp256k1 r || s (ecdsa_secp256k1_sha256_p1363_test.json, 252): the recovery of x402-signature-vectors (APC_SIGLIB)
  that L2.sig uses; the vectors carry no v, so the four recovery ids are tried and the key compared: this measures
  that recovery accepts what verification accepts, not the v byte.
- P-256 r || s (ecdsa_secp256r1_sha256_p1363_test.json, 262): apc_ap2.es256_verify.
- The compressed-key decoders of apc_offer (secp256k1 and P-256) on every key of the ECDSA files."""
import collections
import hashlib
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))          # test_svm, test_xrp: their builders
import apc_ap2  # noqa: E402
import apc_offer  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_xrpl as xr  # noqa: E402
from lib.secp256k1 import recover_public_key  # noqa: E402

WY = os.path.join(ROOT, "sources", "wycheproof_d17cc89")
K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def tests_of(name, n):
    with open(os.path.join(WY, name)) as fh:
        d = json.load(fh)
    out = [(g, t) for g in d["testGroups"] for t in g["tests"]]
    assert len(out) == d["numberOfTests"] == n, (name, len(out))
    return out


def tally(cases, fn):
    """Counter of (result, first flag or '-', our verdict)."""
    c = collections.Counter()
    for g, t in cases:
        c[(t["result"], (t["flags"] or ["-"])[0], fn(g, t))] += 1
    return c


def point(g):
    u = bytes.fromhex(g["publicKey"]["uncompressed"])
    assert len(u) == 65 and u[0] == 4
    return int.from_bytes(u[1:33], "big"), int.from_bytes(u[33:], "big")


def compressed(q):
    return bytes([2 + (q[1] & 1)]) + q[0].to_bytes(32, "big")


def der(r, s):
    def part(v):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        return b"\x02" + bytes([len(b) + (b[0] >> 7)]) + (b"\x00" if b[0] >> 7 else b"") + b
    body = part(r) + part(s)
    return b"\x30" + bytes([len(body)]) + body


def agree(c):
    """The entries where our verdict is not Wycheproof's; `acceptable` is left to the caller."""
    return {k: v for k, v in c.items() if k[0] != "acceptable" and k[2] != (k[0] == "valid")}


class Ed25519(unittest.TestCase):
    CASES = tests_of("ed25519_test.json", 210)

    def run_rule(self, rule):
        return tally(self.CASES, lambda g, t: sol.ed25519_verify(bytes.fromhex(g["publicKey"]["pk"]),
                                                                  bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]), rule))

    def test_valid_and_invalid_agree_under_every_rule(self):
        for rule in sol.ED25519_RULES:
            c = self.run_rule(rule)
            self.assertEqual(agree(c), {}, rule)
            self.assertEqual(sum(v for k, v in c.items() if k[0] == "valid" and k[2]), 117, rule)
            self.assertEqual(sum(v for k, v in c.items() if k[0] == "invalid" and not k[2]), 64, rule)

    def test_acceptable_cases_follow_the_chain_rule(self):
        # 8 small-order public keys: refused by Solana and Soroban (verify_dalek / verify_strict), accepted by rippled
        # (donna has no order test) and by RFC 8032's cofactorless equation; 21 mixed-order keys: accepted by all
        want = {"rfc8032": {("SmallOrderPublicKey", True): 8, ("MixedOrderPublicKey", True): 21},
                "donna": {("SmallOrderPublicKey", True): 8, ("MixedOrderPublicKey", True): 21},
                "dalek_strict": {("SmallOrderPublicKey", False): 8, ("MixedOrderPublicKey", True): 21}}
        for rule in sol.ED25519_RULES:
            got = {(k[1], k[2]): v for k, v in self.run_rule(rule).items() if k[0] == "acceptable"}
            self.assertEqual(got, want[rule], rule)

    def test_rfc8032_rule_is_the_function_of_0_16(self):
        """The default rule is byte for byte the 0.16 function (git 6b2049d), on every vector and on random inputs."""
        got = subprocess.run(["git", "-C", ROOT, "show", "6b2049d:apc_solana.py"], capture_output=True)
        if got.returncode != 0 or not got.stdout:
            raise unittest.SkipTest("needs the git history of ROOT")
        src = got.stdout
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "apc_solana_016.py")
            with open(p, "wb") as fh:
                fh.write(src)
            spec = importlib.util.spec_from_file_location("apc_solana_016", p)
            old = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(old)
        rnd = random.Random(27)
        inputs = [(bytes.fromhex(g["publicKey"]["pk"]), bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]))
                  for g, t in self.CASES]
        seed = bytes(range(32))
        pk = sol.ed25519_public(seed)
        for i in range(40):
            m = rnd.randbytes(i)
            s = sol.ed25519_sign(seed, m)
            inputs += [(pk, m, s), (pk, m, s[:32] + bytes([s[32] ^ 1]) + s[33:]), (rnd.randbytes(32), m, s)]
        for a, m, s in inputs:
            self.assertEqual(sol.ed25519_verify(a, m, s), old.ed25519_verify(a, m, s))
            self.assertEqual(sol.ed25519_verify(a, m, s, "rfc8032"), old.ed25519_verify(a, m, s))


class Ed25519ChainRules(unittest.TestCase):
    """Cases Wycheproof does not carry, built from the rules' own algebra; each one decides between the rules."""
    IDENT = [(1).to_bytes(32, "little"),                                   # canonical identity (y = 1)
             (sol.P + 1).to_bytes(32, "little"),                           # y = p + 1: non-canonical
             ((1 << 255) | 1).to_bytes(32, "little")]                      # y = 1 with the sign bit: x = -0

    def test_unknown_rule_is_refused(self):
        seed = bytes(range(32))
        sig = sol.ed25519_sign(seed, b"")
        for rule in ("zip215", "", None, "RFC8032"):
            with self.assertRaises(ValueError):
                sol.ed25519_verify(sol.ed25519_public(seed), b"", sig, rule)

    def test_identity_key_forms(self):
        """A = identity: [S]B is a signature on any message. rippled (donna) accepts every encoding of it; Solana and
        Soroban refuse it (small order); RFC 8032 decoding accepts only the canonical one."""
        for i, a in enumerate(self.IDENT):
            for s in (1, 2, 12345, sol.L - 1):
                sig = sol._encode(sol._mul(s, sol.G)) + s.to_bytes(32, "little")
                self.assertTrue(sol.ed25519_verify(a, b"any", sig, "donna"), (i, s))
                self.assertFalse(sol.ed25519_verify(a, b"any", sig, "dalek_strict"), (i, s))
                self.assertEqual(sol.ed25519_verify(a, b"any", sig, "rfc8032"), i == 0, (i, s))
                big = sig[:32] + (s + sol.L).to_bytes(32, "little")     # S >= L: refused by all three
                for rule in sol.ED25519_RULES:
                    self.assertFalse(sol.ed25519_verify(a, b"any", big, rule), (i, rule))

    def test_small_order_r_with_a_mixed_order_key(self):
        """A = [a]B + T (T of order 8), R of small order, S = k a: the cofactorless equation holds when
        R + [k]T is the identity. donna and RFC 8032 accept, dalek_strict refuses R of small order."""
        rnd = random.Random(8)
        t8 = None
        while t8 is None:
            p = sol._decompress_lax(rnd.randbytes(32))
            if p is not None:
                q = sol._mul(sol.L, p)
                if not sol._eq(sol._mul(4, q), (0, 1, 1, 0)):
                    t8 = q
        small = [sol._mul(j, t8) for j in range(8)]
        a = rnd.randrange(1, sol.L)
        A = sol._add(sol._mul(a, sol.G), t8)
        ab = sol._encode(A)
        found = 0
        for n in range(400):
            m = b"m%d" % n
            for R in small:
                rb = sol._encode(R)
                k = int.from_bytes(hashlib.sha512(rb + ab + m).digest(), "little") % sol.L
                if not sol._eq(sol._add(R, sol._mul(k, t8)), (0, 1, 1, 0)):
                    continue
                sig = rb + (k * a % sol.L).to_bytes(32, "little")
                self.assertTrue(sol.ed25519_verify(ab, m, sig, "donna"))
                self.assertTrue(sol.ed25519_verify(ab, m, sig, "rfc8032"))
                self.assertFalse(sol.ed25519_verify(ab, m, sig, "dalek_strict"))
                found += 1
            if found >= 6:
                break
        self.assertGreaterEqual(found, 6)

    def test_lax_decoding_equals_canonical_on_reduced_inputs(self):
        rnd = random.Random(3)
        n = 0
        for _ in range(300):
            b = rnd.randbytes(32)
            c = sol._decompress(b)
            lax = sol._decompress_lax(b)
            if c is not None:
                self.assertIsNotNone(lax)
                self.assertEqual(sol._encode(c), sol._encode(lax))
                n += 1
            if int.from_bytes(b, "little") & ((1 << 255) - 1) < sol.P:
                self.assertEqual(c is None, lax is None or (lax[0] == 0 and b[31] >> 7))
        self.assertGreater(n, 100)
        for y in range(19):                       # y + p: the same point as y, for each y of a curve point
            canon = sol._decompress_lax(y.to_bytes(32, "little"))
            nc = sol._decompress_lax((y + sol.P).to_bytes(32, "little"))
            self.assertEqual(canon is None, nc is None, y)
            if canon:
                self.assertEqual(sol._encode(canon), sol._encode(nc))
                self.assertIsNone(sol._decompress((y + sol.P).to_bytes(32, "little")))
        self.assertIsNone(sol._decompress_lax(b"\x00" * 31))


class Secp256k1Der(unittest.TestCase):
    """The rippled rule (apc_xrpl.secp256k1_verify) on the two DER files."""

    def run_file(self, name, n):
        def fn(g, t):
            return xr.secp256k1_verify(compressed(point(g)), hashlib.sha256(bytes.fromhex(t["msg"])).digest(),
                                       bytes.fromhex(t["sig"]))
        return [(g, t, fn(g, t)) for g, t in tests_of(name, n)]

    def test_bitcoin_file_agrees_entirely(self):
        """The bitcoin variant requires low s, as rippled does: 162 valid verified, 302 invalid refused."""
        rows = self.run_file("ecdsa_secp256k1_sha256_bitcoin_test.json", 464)
        self.assertEqual(sum(t["result"] == "valid" and v == "verified" for g, t, v in rows), 162)
        self.assertEqual(sum(t["result"] == "invalid" and v != "verified" for g, t, v in rows), 302)
        self.assertEqual(sum(t["result"] == "acceptable" for g, t, v in rows), 0)

    def test_plain_file_differs_only_by_the_low_s_rule(self):
        """Of 168 valid signatures, the 72 with s > n/2 are refused as not fully canonical (rippled PublicKey.cpp
        235 with PublicKey.h 240): the rule of the chain; their low-s twins (s' = n - s) verify. 308 invalid refused."""
        rows = self.run_file("ecdsa_secp256k1_sha256_test.json", 476)
        valid = [(g, t, v) for g, t, v in rows if t["result"] == "valid"]
        self.assertEqual(len(valid), 168)
        self.assertEqual(sum(v == "verified" for g, t, v in valid), 96)
        high = [(g, t) for g, t, v in valid if v != "verified"]
        self.assertEqual(len(high), 72)
        for g, t, v in valid:
            self.assertEqual(v != "verified", v == "failed:signature_not_fully_canonical", t["tcId"])
        for g, t in high:
            sig = bytes.fromhex(t["sig"])
            r, s = xr._der(sig)
            self.assertGreater(s, K1_N // 2)
            self.assertEqual(xr.secp256k1_verify(compressed(point(g)), hashlib.sha256(bytes.fromhex(t["msg"])).digest(),
                                                 der(r, K1_N - s)), "verified", t["tcId"])
        self.assertEqual(sum(t["result"] == "invalid" and v != "verified" for g, t, v in rows), 308)


class Secp256k1Recovery(unittest.TestCase):
    def test_p1363_file_by_recovery(self):
        def fn(g, t):
            sig, q = bytes.fromhex(t["sig"]), point(g)
            if len(sig) != 64:
                return False
            dg = hashlib.sha256(bytes.fromhex(t["msg"])).digest()
            r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            for rec in range(4):
                try:
                    if recover_public_key(dg, r, s, rec) == q:
                        return True
                except ValueError:
                    pass
            return False
        c = tally(tests_of("ecdsa_secp256k1_sha256_p1363_test.json", 252), fn)
        self.assertEqual(agree(c), {})
        self.assertEqual(sum(v for k, v in c.items() if k[0] == "valid"), 167)
        self.assertEqual(sum(v for k, v in c.items() if k[0] == "invalid"), 85)


class P256(unittest.TestCase):
    CASES = tests_of("ecdsa_secp256r1_sha256_p1363_test.json", 262)

    def test_es256_agrees_entirely(self):
        def fn(g, t):
            q = point(g)
            self.assertTrue(apc_ap2.p256_on_curve(q))
            return apc_ap2.es256_verify(q, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]))
        c = tally(self.CASES, fn)
        self.assertEqual(agree(c), {})
        self.assertEqual(sum(v for k, v in c.items() if k[0] == "valid"), 173)
        self.assertEqual(sum(v for k, v in c.items() if k[0] == "invalid"), 89)


class CompressedKeys(unittest.TestCase):
    def test_offer_decoders_on_every_key(self):
        n = 0
        for name, curve, size in (("ecdsa_secp256k1_sha256_p1363_test.json", apc_offer.K1, 252),
                                  ("ecdsa_secp256r1_sha256_p1363_test.json", apc_offer.R1, 262)):
            seen = set()
            for g, t in tests_of(name, size):
                q = point(g)
                if q in seen:
                    continue
                seen.add(q)
                self.assertEqual(apc_offer._decompress(curve, compressed(q)), q)
                n += 1
        self.assertGreater(n, 20)


class ChainCallSites(unittest.TestCase):
    """Each chain verifier calls its own rule (SPEC 28.1): a key of small order (the identity, [S]B signs anything)
    is refused by Solana and Soroban and accepted by rippled, also in its non-canonical encoding y = p + 1."""
    IDENT = (1).to_bytes(32, "little")
    IDENT_NC = (sol.P + 1).to_bytes(32, "little")

    @staticmethod
    def any_sig(s=7):
        return sol._encode(sol._mul(s, sol.G)) + s.to_bytes(32, "little")

    def test_solana_signer_of_small_order_is_refused(self):
        import test_svm as ts

        class Ident(ts.Key):
            def __init__(self, n):
                super().__init__(n)
                if n == 2:                                    # the client authority, signer 1
                    self.pub = ChainCallSites.IDENT
                    self.addr = sol.b58encode(self.pub)
                    self.sign = lambda m: ChainCallSites.any_sig()
        good = ts.run(ts.built())
        self.assertEqual(good["checks"]["S1"], "verified")
        orig = ts.Key
        ts.Key = Ident
        try:
            d = ts.built()
        finally:
            ts.Key = orig
        self.assertTrue(sol.ed25519_verify(self.IDENT, b"", self.any_sig(), "rfc8032"))
        self.assertEqual(ts.run(d)["checks"]["S1"], "failed:signer_1_signature_invalid")

        class IdentFeePayer(ts.Key):                          # the fee payer (account 0) signs the confirmed copy
            def __init__(self, n):
                super().__init__(n)
                if n == 1:
                    self.pub = ChainCallSites.IDENT
                    self.addr = sol.b58encode(self.pub)
                    self.sign = lambda m: ChainCallSites.any_sig()
        self.assertEqual(ts.run(ts.built(chain=True))["checks"]["C1"], "verified")
        ts.Key = IdentFeePayer
        try:
            d = ts.built(chain=True)
        finally:
            ts.Key = orig
        self.assertEqual(ts.run(d)["checks"]["C1"], "failed:fee_payer_signature_invalid")

    def test_soroban_key_of_small_order_is_refused(self):
        import apc_stellar as xs
        import apc_xlm
        for pk, sig, want in ((self.IDENT, self.any_sig(), "failed:auth_signature_invalid"),):
            entry = {"credentials": {"type": 1, "nonce": 1, "expiration": 2, "signature": ("vec", [("map", [
                (("symbol", b"public_key"), ("bytes", pk)), (("symbol", b"signature"), ("bytes", sig))])])},
                "invocation": {"raw": b"\x00" * 8}}
            frm = xs.strkey_encode("G", pk)
            self.assertEqual(apc_xlm._sig_g(entry, "stellar:pubnet", frm), want)
        seed = bytes(range(32))                         # positive control: an ordinary key verifies on the same path
        pk = sol.ed25519_public(seed)
        entry = {"credentials": {"type": 1, "nonce": 1, "expiration": 2, "signature": ("vec", [])},
                 "invocation": {"raw": b"\x00" * 8}}
        sig = sol.ed25519_sign(seed, xs.auth_preimage(entry, "stellar:pubnet"))
        entry["credentials"]["signature"] = ("vec", [("map", [(("symbol", b"public_key"), ("bytes", pk)),
                                                               (("symbol", b"signature"), ("bytes", sig))])])
        self.assertEqual(apc_xlm._sig_g(entry, "stellar:pubnet", xs.strkey_encode("G", pk)), "verified")

    def test_rippled_accepts_a_non_canonical_key_of_small_order(self):
        import test_xrp as tx
        good = tx.run(tx.bundle(tx.payment(tx.ED)[0]))
        self.assertEqual(good["checks"]["R10"], "verified")
        pub, sign = sol.ed25519_public, sol.ed25519_sign
        for enc in (self.IDENT, self.IDENT_NC):
            sol.ed25519_public = lambda seed, enc=enc: enc
            sol.ed25519_sign = lambda seed, m: ChainCallSites.any_sig()
            try:
                blob = tx.payment(tx.ED)[0]
            finally:
                sol.ed25519_public, sol.ed25519_sign = pub, sign
            r = tx.run(tx.bundle(blob))
            self.assertEqual(r["checks"]["R10"], "verified", enc.hex())
        self.assertFalse(sol.ed25519_verify(self.IDENT_NC, b"", self.any_sig(), "rfc8032"))


if __name__ == "__main__":
    unittest.main()
