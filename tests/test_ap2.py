"""SPEC 0.7 (section 9): apc_ap2.py, an independent evaluator of the Pulse AP2-x402 conformance profile. The corpus is
not redistributed here: APC_PULSE_CASES names fixtures/v0.3/cases.json of shibutatsu/pulse-ap2-x402-conformance at
e06a6cbf (Apache-2.0), checked by its SHA-256. ES256 is first checked against RFC 6979 A.2.5 (P-256, SHA-256)."""
import copy
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_ap2 as a  # noqa: E402

CASES = os.environ.get("APC_PULSE_CASES")
PULSE_SHA256 = "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"


def corpus():
    with open(CASES, "rb") as fh:
        raw = fh.read()
    assert hashlib.sha256(raw).hexdigest() == PULSE_SHA256, "not the pinned Pulse corpus"
    return json.loads(raw)["cases"]


class P256(unittest.TestCase):
    def test_rfc6979_a25(self):
        x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        q = (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
             0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
        p = a._jmul(x, a.P256_G)
        zi = pow(p[2], -1, a.P256_P)
        self.assertEqual((p[0] * zi * zi % a.P256_P, p[1] * zi * zi * zi % a.P256_P), q)
        self.assertTrue(a.p256_on_curve(q))
        self.assertIsNone(a._jmul(a.P256_N, a.P256_G))
        r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
        s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        self.assertTrue(a.es256_verify(q, b"sample", sig))
        for bad_msg, bad_sig in ((b"samplf", sig), (b"sample", sig[:-1] + bytes([sig[-1] ^ 1])),
                                 (b"sample", sig[:63]), (b"sample", bytes(32) + sig[32:]),
                                 (b"sample", sig[:32] + a.P256_N.to_bytes(32, "big"))):
            self.assertFalse(a.es256_verify(q, bad_msg, bad_sig))

    def test_points(self):
        self.assertTrue(a.p256_on_curve(a.P256_G))
        self.assertFalse(a.p256_on_curve((a.P256_G[0], a.P256_G[1] + 1)))
        self.assertFalse(a.p256_on_curve((a.P256_P, 0)))


class Canonical(unittest.TestCase):
    def test_rfc8785(self):
        self.assertEqual(a.canonical({"b": [1, 2.0, True, None], "a": "é\n", "€": 1, "\U0001f600": 2}),
                         '{"a":"é\\n","b":[1,2,true,null],"€":1,"\U0001f600":2}')
        # UTF-16 order: U+FF01 (one unit, 0xFF01) after U+1F600 (high surrogate 0xD83D), unlike code point order
        self.assertEqual(a.canonical({"！": 1, "\U0001f600": 2}), '{"\U0001f600":2,"！":1}')
        self.assertEqual(a.canonical(1e21), "1e+21")
        self.assertEqual(a.canonical(0.5), "0.5")
        for bad in (float("inf"), float("nan"), b"x"):
            with self.assertRaises(TypeError):
                a.canonical(bad)

    def test_base64url(self):
        self.assertEqual(a.b64u_decode("AQ"), b"\x01")
        for bad in ("AR", "A", "AQ==", "A+", "A/"):
            with self.assertRaises(ValueError, msg=bad):
                a.b64u_decode(bad)


def p256_sign(d, msg):
    """ECDSA P-256/SHA-256 for built cases (a deterministic k derived from d and msg; not RFC 6979)"""
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    k = int.from_bytes(hashlib.sha256(d.to_bytes(32, "big") + msg).digest(), "big") % a.P256_N or 1
    r = a._affine_x(a._jmul(k, a.P256_G)) % a.P256_N
    return r.to_bytes(32, "big") + (pow(k, -1, a.P256_N) * (e + r * d) % a.P256_N).to_bytes(32, "big")


class Key:
    def __init__(self, n):
        self.d = int.from_bytes(hashlib.sha256(b"apc ap2 test key %d" % n).digest(), "big") % a.P256_N
        p = a._jmul(self.d, a.P256_G)
        zi = pow(p[2], -1, a.P256_P)
        self.pt = (p[0] * zi * zi % a.P256_P, p[1] * zi * zi * zi % a.P256_P)
        self.jwk = {"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "k%d" % n,
                    "x": a.b64u(self.pt[0].to_bytes(32, "big")), "y": a.b64u(self.pt[1].to_bytes(32, "big"))}

    def jws(self, header, payload):
        h = a.b64u(json.dumps(header).encode())
        p = a.b64u(json.dumps(payload).encode())
        return h + "." + p + "." + a.b64u(p256_sign(self.d, (h + "." + p).encode()))


REF = a.b64u(hashlib.sha256(b"checkout").digest())


def chain(**kw):
    """a one-hop AP2 open -> closed Payment Mandate chain and a receipt, built and signed here; kw breaks one thing"""
    root, holder, rk = Key(1), Key(2), Key(3)
    opn = {"vct": "mandate.payment.open.1", "constraints": [{"type": "payment.reference",
                                                              "conditional_transaction_id": REF}],
           "cnf": {"jwk": holder.jwk}, "iat": 100, "exp": 10 ** 6}
    closed = {"vct": "mandate.payment.1", "transaction_id": REF, "payee": {"id": "m", "name": "M"},
              "payment_amount": {"amount": 5, "currency": "USD"},
              "payment_instrument": {"id": "i", "type": "x402"}, "iat": 100, "exp": 10 ** 6}
    dr = a.b64u(json.dumps(["salt-r", opn]).encode())
    rpay = {"delegate_payload": [{"...": a.sha_b64u(dr)}], "_sd_alg": "sha-256"}
    rjwt = root.jws(kw.get("root_header", {"alg": "ES256", "typ": "example+sd-jwt"}), rpay)
    rdisc = [dr] + kw.get("root_extra", [])
    rsd = rjwt + "~" + "~".join(rdisc) + "~"
    dl = a.b64u(json.dumps(["salt-l", closed]).encode())
    lpay = {"delegate_payload": [{"...": a.sha_b64u(dl)}], "_sd_alg": "sha-256",
            "sd_hash": kw.get("sd_hash", a.sha_b64u(rsd)), "aud": "aud", "nonce": "n", "iat": 100}
    ljwt = holder.jws(kw.get("leaf_header", {"alg": "ES256", "typ": "kb+sd-jwt"}), lpay)
    ldisc = [dl] * kw.get("leaf_copies", 1)
    receipt = {"status": "Success", "iss": "f", "iat": 100, "reference": kw.get("reference", a.sha_b64u(ljwt)),
               "payment_id": "p", "psp_confirmation_id": "q", "network_confirmation_id": "0x" + "ab" * 32}
    ev = {"mandateChain": rsd[:-1] + "~~" + ljwt + "~" + "~".join(ldisc) + "~",
          "trustedRootPublicJwk": kw.get("root_jwk", root.jwk), "paymentReceiptJwt": rk.jws({"alg": "ES256"}, receipt),
          "trustedReceiptPublicJwk": rk.jwk, "expectedAudience": "aud", "expectedNonce": "n"}
    return ev, opn, closed, receipt


def crypto(**kw):
    ev = chain(**kw)[0]
    try:
        a.verify_ap2(ev, 1000, 0, REF)
        return "verified"
    except a.CryptoFail as e:
        return "%s %s" % (e.stage, e.code)


class Built(unittest.TestCase):
    def test_control(self):
        ev, opn, closed, receipt = chain()
        o, c, r, ref = a.verify_ap2(ev, 1000, 0, REF)
        self.assertEqual((o, c, r), (opn, closed, receipt))

    def test_each_binding(self):
        self.assertEqual(crypto(sd_hash="A" * 43), "leaf-binding SD_HASH_INVALID")
        self.assertEqual(crypto(leaf_header={"alg": "ES256", "typ": "JWT"}), "leaf-header TYP_INVALID")
        self.assertEqual(crypto(reference="B" * 43), "receipt-claims RECEIPT_REFERENCE_MISMATCH")
        self.assertEqual(crypto(root_header={"alg": "ES256", "typ": "kb+sd-jwt"}), "root-header TYP_INVALID")
        self.assertEqual(crypto(root_header={"alg": "ES256", "crit": ["exp"], "typ": "x+sd-jwt"}),
                         "root-signature SIGNATURE_INVALID")
        self.assertEqual(crypto(leaf_copies=2), "leaf-disclosures DISCLOSURE_INVALID")       # the same disclosure twice
        self.assertEqual(crypto(root_extra=[a.b64u(b'["s", "unbound"]')]), "root-disclosures DISCLOSURE_INVALID")

    def test_key_off_the_curve(self):
        bad = dict(Key(1).jwk, y=a.b64u(((Key(1).pt[1] + 1) % a.P256_P).to_bytes(32, "big")))
        with self.assertRaises(a.CryptoFail) as e:
            a._jwk_key(bad, "root-signature")
        self.assertEqual(e.exception.code, "JWK_INVALID")
        self.assertEqual(crypto(root_jwk=bad), "root-signature JWK_INVALID")


@unittest.skipUnless(CASES, "APC_PULSE_CASES not set: the Pulse corpus is not redistributed (tools/mutants03.py requires it)")
class Corpus(unittest.TestCase):
    def test_all_80_cases(self):
        cases = corpus()
        self.assertEqual(len(cases), 80)
        for c in cases:
            r = a.verify_case(copy.deepcopy(c))
            self.assertEqual((r["consistent"], r["failureCodes"]),
                             (c["expected"]["consistent"], c["expected"]["failureCodes"]), c["id"])
        self.assertEqual(sum(c["expected"]["consistent"] for c in cases), 20)

    def test_expected_is_not_read(self):
        """the decision does not come from `expected`: a case with its expectation inverted gets the same result"""
        for c in corpus()[:6] + corpus()[-6:]:
            d = copy.deepcopy(c)
            d["expected"] = {"consistent": not c["expected"]["consistent"], "failureCodes": []}
            self.assertEqual(a.verify_case(d)["failureCodes"], c["expected"]["failureCodes"], c["id"])

    def test_breaking_a_valid_case_every_way(self):
        valid = [c for c in corpus() if c["expected"]["consistent"]][0]
        ev = valid["ap2"]["verification"]["cryptographicEvidence"]
        jwt = ev["paymentReceiptJwt"]

        def run(edit):
            d = copy.deepcopy(valid)
            edit(d)
            return a.verify_case(d)["failureCodes"]
        self.assertEqual(run(lambda d: None), [])
        last = "B" if jwt[-2] == "A" else "A"                       # another character: the signature changes
        self.assertIn("AP2_RECEIPT_UNVERIFIED", run(lambda d: d["ap2"]["verification"]["cryptographicEvidence"]
                                                    .__setitem__("paymentReceiptJwt", jwt[:-2] + last + jwt[-1])))
        self.assertIn("AP2_OPEN_MANDATE_UNVERIFIED", run(lambda d: d["ap2"]["verification"]["cryptographicEvidence"]
                                                         ["trustedRootPublicJwk"].__setitem__(
                                                             "x", ev["trustedReceiptPublicJwk"]["x"])))
        self.assertEqual(run(lambda d: d["ap2"]["verification"]["cryptographicEvidence"]          # any edit
                             .__setitem__("expectedAudience", "x")), ["INPUT_HASH_MISMATCH", "AP2_KEY_BINDING_UNVERIFIED"])
        self.assertEqual(run(lambda d: d["ap2"]["verification"]["cryptographicEvidence"]          # any edit
                             .__setitem__("expectedNonce", "x")), ["INPUT_HASH_MISMATCH", "AP2_KEY_BINDING_UNVERIFIED"])
        self.assertEqual(run(lambda d: d.__setitem__("zz", 1)), ["INPUT_SCHEMA_INVALID"])
        self.assertEqual(run(lambda d: d["x402"]["settlement"].__setitem__("constructor", 1)), ["INPUT_SCHEMA_INVALID"])
        self.assertEqual(run(lambda d: d.__setitem__("inputHash", "A" * 43)), ["INPUT_HASH_MISMATCH"])
        self.assertIn("SETTLEMENT_NETWORK_MISMATCH", run(lambda d: d["x402"]["settlement"].__setitem__("network",
                                                                                                         "eip155:1")))
        chain = ev["mandateChain"]
        self.assertIn("AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID", run(lambda d: d["ap2"]["verification"]   # two hops
                                                               ["cryptographicEvidence"].__setitem__(
                                                                   "mandateChain", chain.replace("~~", "~~x~~", 1))))
        i = chain.find("~~")
        extra = a.b64u(b'["salt", "unbound"]')                     # a disclosure no digest names, in the root token
        self.assertIn("AP2_OPEN_MANDATE_UNVERIFIED", run(lambda d: d["ap2"]["verification"]["cryptographicEvidence"]
                                                         .__setitem__("mandateChain",
                                                                      chain[:i] + "~" + extra + chain[i:])))
        self.assertIn("AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID", run(lambda d: d["ap2"]["verification"]
                                                               ["cryptographicEvidence"].__setitem__(
                                                                   "mandateChain", chain[:i] + "~" + chain[i + 2:])))

    def test_rules_the_corpus_does_not_isolate(self):
        valid = [c for c in corpus() if c["expected"]["consistent"]][0]

        def run(edit):
            d = copy.deepcopy(valid)
            edit(d)
            return a.verify_case(d)["failureCodes"]

        def other_extension(d):     # an allowed instrument with the same id and type but another x402 extension
            k = next(k for k in d["ap2"]["openMandate"]["constraints"]
                     if k["type"] == "payment.allowed_payment_instruments")
            k["allowed"][0]["x402"]["amount"] = "1"
        self.assertIn("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED", run(other_extension))

        def closed_expires_first(d):  # the authorization outlives the closed mandate, not the open one
            vb = int(d["x402"]["payload"]["payload"]["authorization"]["validBefore"])
            d["ap2"]["closedMandate"]["exp"] = vb - 1
            d["ap2"]["openMandate"]["exp"] = vb + 100
        self.assertIn("EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY", run(closed_expires_first))

        def other_payer(d):           # the signature recovers the original payer, not the new from
            d["x402"]["payload"]["payload"]["authorization"]["from"] = "0x" + "11" * 20
        self.assertIn("EIP3009_SIGNATURE_INVALID", run(other_payer))
        self.assertEqual(run(lambda d: d["x402"]["settlement"].__setitem__("extra", {"constructor": 1})),
                         ["INPUT_SCHEMA_INVALID"])         # inside an open record, where the schema allows any key

    def test_m1_in_an_apc_bundle(self):
        """SPEC 0.7 M1: the mandate binds this very payment payload"""
        import apc_verify as av
        cases = corpus()
        valid = [c for c in cases if c["expected"]["consistent"]]

        def bundle(case, payload=None):
            return {"bundle_version": "apc-0.1", "payment_payload": copy.deepcopy(payload or case["x402"]["payload"]),
                    "mandate": {"profile": "pulse-ap2-x402/0.3", "case": copy.deepcopy(case)}}
        for c in valid:
            r = av.verify_bundle(bundle(c))
            self.assertEqual((r["checks"]["M1"], r["checks"]["L2.sig"]), ("verified", "verified"), c["id"])
        r = av.verify_bundle(bundle(valid[0], valid[1]["x402"]["payload"]))
        self.assertEqual(r["checks"]["M1"], "failed:mandate_binds_another_payment")
        self.assertEqual(r["checks"]["L2.sig"], "verified")                 # the other payload is itself valid
        bad = next(c for c in cases if c["expected"]["failureCodes"] == ["EIP3009_PAYER_MISMATCH"])
        self.assertEqual(av.verify_bundle(bundle(bad))["checks"]["M1"], "failed:ap2_eip3009_payer_mismatch")
        schema = next(c for c in cases if c["expected"]["failureCodes"] == ["INPUT_SCHEMA_INVALID"])
        with self.assertRaises(av.Refusal):
            av.verify_bundle(bundle(schema))
        d = bundle(valid[0])
        d["mandate"]["zz"] = 1
        with self.assertRaises(av.Refusal):
            av.verify_bundle(d)

    def test_cli(self):
        import subprocess
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_ap2.py"), CASES], capture_output=True,
                           text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stdout[-500:])
        self.assertTrue(r.stdout.strip().endswith("80/80 cases equal their recorded expectation"))


if __name__ == "__main__":
    unittest.main()
