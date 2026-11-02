"""SPEC 0.8 (section 10): the HTTP exchange that carried the payment, X1-X7 (apc_http.py). Oracles from outside this
work: RFC 9421 Appendix B.1.3, B.1.4, B.2.4, B.2.6 (keys, signature bases, signatures), RFC 9530 Appendix B.1, B.2
(Content-Digest of known content), the header examples of x402 specs/transports-v2/http.md @0aee759 (each base64 value
next to the JSON it decodes to), and the fixtures of peacprotocol/x402-solana-evidence @8a7a1f5 (Apache-2.0: their
recorded RFC 9421 components and body digest), all copied under sources/ with sha256."""
import base64
import copy
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_http as h  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402

SRC = os.path.join(ROOT, "sources", "http_20261025")
PEAC = os.path.join(ROOT, "sources", "peac_8a7a1f5", "fixtures", "expected-evidence")
SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64(b):
    return base64.b64encode(b).decode()


# RFC 9421 B.1.4 (test-key-ed25519, JWK x and d) and B.1.3 (test-key-ecc-p256, JWK x and y)
ED_PUB = b64u("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
ED_SEED = b64u("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")
EC_PUB = b"\x04" + b64u("qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA") + b64u("Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0")
KEYS = {"apc_http_keys": 1, "keys": {"test-key-ed25519": {"alg": "ed25519", "public_key": ED_PUB.hex()},
                                     "test-key-ecc-p256": {"alg": "ecdsa-p256-sha256", "public_key": EC_PUB.hex()}}}

# RFC 9421 B.2: test-request and test-response with the B.2.6 and B.2.4 signatures, as written in the RFC
TEST_REQUEST = {"method": "POST", "target_uri": "https://example.com/foo?param=Value&Pet=dog", "fields": [
    ["Host", "example.com"], ["Date", "Tue, 20 Apr 2021 02:07:55 GMT"], ["Content-Type", "application/json"],
    ["Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJ"
                       "wew==:"],
    ["Content-Length", "18"],
    ["Signature-Input", 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");'
                        'created=1618884473;keyid="test-key-ed25519"'],
    ["Signature", "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"]],
    "body": b64(b'{"hello": "world"}')}
TEST_RESPONSE = {"status": 200, "fields": [
    ["Date", "Tue, 20 Apr 2021 02:07:56 GMT"], ["Content-Type", "application/json"],
    ["Content-Digest", "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfL"
                       "Q==:"],
    ["Content-Length", "23"],
    ["Signature-Input", 'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;'
                        'keyid="test-key-ecc-p256"'],
    ["Signature", "sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:"]],
    "body": b64(b'{"message": "good dog"}')}
B26_BASE = ('"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@authority": example.com\n'
            '"content-type": application/json\n"content-length": 18\n"@signature-params": ("date" "@method" "@path" '
            '"@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"')


def rfc_doc():
    return {"payment_payload": {}, "exchange": {"request": copy.deepcopy(TEST_REQUEST),
                                                "response": copy.deepcopy(TEST_RESPONSE)}}


def sigs(doc, keys=KEYS):
    return h.check(doc, h.parse_keys(keys) if keys is not None else None)


def http_md():
    """x402 http.md @0aee759: the three header values and the JSON objects shown under them"""
    with open(os.path.join(SRC, "http.md")) as fh:
        md = fh.read()
    one = dict(re.findall(r"^(PAYMENT-SIGNATURE|PAYMENT-REQUIRED): (\S+)$", md, re.M))
    responses = re.findall(r"^PAYMENT-RESPONSE: (\S+)$", md, re.M)
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", md, re.S)]
    return one, responses, blocks


def md_bundle():
    one, responses, blocks = http_md()
    return {"bundle_version": "apc-0.3", "payment_payload": blocks[1], "payment_required": blocks[0],
            "settlement": blocks[2],
            "exchange": {"request": {"method": "POST", "target_uri": "https://api.example.com/premium-data",
                                     "fields": [["Host", "api.example.com"], ["PAYMENT-SIGNATURE", one["PAYMENT-SIGNATURE"]],
                                                ["Content-Type", "application/json"]]},
                         "response": {"status": 200, "fields": [["Content-Type", "application/json"],
                                                                ["PAYMENT-RESPONSE", responses[0]]]}}}


def run(d, keys=None):
    try:
        return av.verify_bundle(d, None, keys)
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e)}


def sign_ed(base_lines, params):
    """our own Ed25519 signature with the RFC's test key: the base is RFC 9421 2.5 written out by hand"""
    base = "\n".join(base_lines + ['"@signature-params": ' + params]).encode()
    return b64(sol.ed25519_sign(ED_SEED, base))


class RFC9421Vectors(unittest.TestCase):
    def test_keys_are_the_rfc_pairs(self):
        self.assertEqual(sol.ed25519_public(ED_SEED), ED_PUB)     # B.1.4: d and x are one key pair
        h.parse_keys(KEYS)                                        # the P-256 point of B.1.3 is on the curve

    def test_b26_signature_base_is_the_rfc_listing(self):
        ex = h.parse_exchange(rfc_doc()["exchange"])
        ex["request"] = {"fields": ex["fields"], "body": ex["body"]}
        (label, (val, ps)), = h.parse_dictionary(h.combined(ex["fields"], "signature-input"))
        self.assertEqual(h.signature_base(val, h.ser_inner(val, ps), ex["request"], ex, True).decode(), B26_BASE)

    def test_b26_b24_verify(self):
        res, _, m = sigs(rfc_doc())
        self.assertEqual(res["X7"], "verified")
        self.assertEqual([(s["where"], s["label"], s["alg"], s["keyid"], s["result"]) for s in m["signatures"]],
                         [("request", "sig-b26", None, "test-key-ed25519", "verified"),
                          ("response", "sig-b24", None, "test-key-ecc-p256", "verified")])
        self.assertEqual(m["signatures"][1]["covered"], ['"@status"', '"content-type"', '"content-digest"',
                                                         '"content-length"'])
        self.assertEqual(m["signatures"][0]["created"], 1618884473)

    def test_any_covered_change_fails(self):
        for where, i, new in (("request", 1, "Tue, 20 Apr 2021 02:07:56 GMT"), ("request", 2, "text/plain"),
                              ("request", 4, "19"), ("response", 1, "text/plain"), ("response", 3, "24")):
            d = rfc_doc()
            d["exchange"][where]["fields"][i][1] = new
            self.assertEqual(sigs(d)[0]["X7"], "failed:signature_invalid", (where, i))
        d = rfc_doc()
        d["exchange"]["request"]["target_uri"] = "https://example.com/fob?param=Value&Pet=dog"   # @path
        self.assertEqual(sigs(d)[0]["X7"], "failed:signature_invalid")
        d = rfc_doc()
        d["exchange"]["response"]["status"] = 201
        self.assertEqual(sigs(d)[0]["X7"], "failed:signature_invalid")

    def test_uncovered_change_still_verifies(self):
        d = rfc_doc()
        d["exchange"]["request"]["target_uri"] = "https://example.com/foo?param=Other"   # @query is not covered
        d["exchange"]["request"]["fields"][0][1] = "example.org"                          # nor Host
        self.assertEqual(sigs(d)[0]["X7"], "verified")

    def test_signature_bytes_changed(self):
        for where, i in (("request", 6), ("response", 5)):
            d = rfc_doc()
            f = d["exchange"][where]["fields"][i]
            label, rest = f[1].split("=:", 1)
            raw = bytearray(base64.b64decode(rest[:-1]))
            raw[10] ^= 1
            f[1] = label + "=:" + b64(bytes(raw)) + ":"
            self.assertEqual(sigs(d)[0]["X7"], "failed:signature_invalid")

    def test_keys_and_algorithms(self):
        self.assertEqual(sigs(rfc_doc(), None)[0]["X7"], "not_evaluated:absent:no_http_keys")
        swapped = {"apc_http_keys": 1, "keys": {"test-key-ed25519": {"alg": "ed25519", "public_key": ED_PUB.hex()},
                                                "test-key-ecc-p256": {"alg": "ed25519", "public_key": ED_PUB.hex()}}}
        self.assertEqual(sigs(rfc_doc(), swapped)[2]["signatures"][1]["result"], "failed:signature_invalid")
        only = {"apc_http_keys": 1, "keys": {"test-key-ed25519": KEYS["keys"]["test-key-ed25519"]}}
        r = sigs(rfc_doc(), only)
        self.assertEqual(r[2]["signatures"][1]["result"], "failed:unknown_keyid")
        self.assertEqual(r[0]["X7"], "failed:unknown_keyid")
        d = rfc_doc()
        d["exchange"]["request"]["fields"][5][1] += ';alg="ecdsa-p256-sha256"'
        self.assertEqual(sigs(d)[0]["X7"], "failed:alg_not_the_key_algorithm")
        d = rfc_doc()
        d["exchange"]["request"]["fields"][5][1] += ';alg="rsa-pss-sha512"'
        self.assertEqual(sigs(d)[0]["X7"], "failed:alg_not_the_key_algorithm")

    def test_missing_signature_and_malformed_input(self):
        d = rfc_doc()
        del d["exchange"]["request"]["fields"][6]
        self.assertEqual(sigs(d)[0]["X7"], "failed:signature_missing")
        for bad in ('sig-b26=("date" "@method"', 'sig-b26=(date "@method");keyid="test-key-ed25519"',
                    'sig-b26=("date");keyid=test-key-ed25519', 'sig-b26=("date");created="1"',
                    'sig-b26=("date" "date");keyid="test-key-ed25519"', 'Sig=("date")'):
            d = rfc_doc()
            d["exchange"]["request"]["fields"][5][1] = bad
            self.assertEqual(sigs(d)[0]["X7"], "failed:signature_input_malformed", bad)
            self.assertEqual(sigs(d, None)[0]["X7"], "not_evaluated:absent:no_http_keys", bad)

    def test_signature_without_input(self):
        """found by the fuzzer: an emptied or absent Signature-Input left the Signature unread and X7 verified"""
        for v in ("", None):
            d = rfc_doc()
            if v is None:
                del d["exchange"]["request"]["fields"][5]
            else:
                d["exchange"]["request"]["fields"][5][1] = v
            res, _, m = sigs(d)
            self.assertEqual(res["X7"], "failed:signature_without_input", repr(v))
            self.assertEqual([(s["label"], s["result"]) for s in m["signatures"]],
                             [("sig-b26", "failed:signature_without_input"), ("sig-b24", "verified")])
            self.assertEqual(sigs(d, None)[0]["X7"], "not_evaluated:absent:no_http_keys")
        d = rfc_doc()
        d["exchange"]["request"]["fields"][6][1] += ", other=:AAAA:"
        self.assertEqual(sigs(d)[0]["X7"], "failed:signature_without_input")

    def test_signature_member_not_bytes(self):
        for v in ("sig-b26=1", 'sig-b26="AAAA"', "sig-b26=(:AAAA:)", "sig-b26"):
            d = rfc_doc()
            d["exchange"]["request"]["fields"][6][1] = v
            self.assertEqual(sigs(d)[0]["X7"], "failed:signature_missing", v)

    def test_repeated_label_fails(self):
        d = rfc_doc()
        d["exchange"]["request"]["fields"].append(["Signature-Input", 'sig-b26=("date");keyid="test-key-ed25519"'])
        self.assertEqual(sigs(d)[0]["X7"], "failed:signature_input_malformed")

    def test_components_not_supported_or_missing(self):
        for ident in ('"@query-param";name="Pet"', '"content-type";sf', '"content-digest";key="sha-512"',
                      '"date";bs', '"date";tr', '"@unknown"'):
            d = rfc_doc()
            d["exchange"]["request"]["fields"][5][1] = 'sig-b26=(%s);keyid="test-key-ed25519"' % ident
            self.assertEqual(sigs(d)[0]["X7"], "not_evaluated:component_not_supported:%s" % ident, ident)
        d = rfc_doc()
        d["exchange"]["request"]["fields"][5][1] = 'sig-b26=("x-absent");keyid="test-key-ed25519"'
        self.assertEqual(sigs(d)[0]["X7"], 'failed:component_not_in_message:"x-absent"')
        for ident in ('"@status"', '"Date"', '"@method";req'):
            d = rfc_doc()
            d["exchange"]["request"]["fields"][5][1] = 'sig-b26=(%s);keyid="test-key-ed25519"' % ident
            self.assertEqual(sigs(d)[0]["X7"], "failed:signature_input_malformed", ident)

    def test_derived_components_and_req(self):
        """our own signatures (RFC test key) over every supported derived component, and req in a response"""
        uri = "https://Example.COM:443/a%2Fb/c?x=1&y=%20"
        lines = ['"@method": GET', '"@target-uri": ' + uri, '"@authority": example.com', '"@scheme": https',
                 '"@request-target": /a%2Fb/c?x=1&y=%20', '"@path": /a%2Fb/c', '"@query": ?x=1&y=%20']
        comps = '("@method" "@target-uri" "@authority" "@scheme" "@request-target" "@path" "@query")'
        params = comps + ';keyid="test-key-ed25519"'
        doc = {"payment_payload": {}, "exchange": {"request": {"method": "GET", "target_uri": uri, "fields": [
            ["Signature-Input", "s=" + params], ["Signature", "s=:%s:" % sign_ed(lines, params)]]}}}
        self.assertEqual(sigs(doc)[0]["X7"], "verified")
        doc["exchange"]["request"]["target_uri"] = "https://example.com/a%2Fb/c?x=1&y=%20"
        self.assertEqual(sigs(doc)[0]["X7"], "failed:signature_invalid")     # @target-uri is the recorded string
        for uri, auth, path, query in (("http://h.example:8080", "h.example:8080", "/", "?"),
                                       ("http://h.example:80/p?", "h.example", "/p", "?"),
                                       ("https://[2001:DB8::1]:8443/x", "[2001:db8::1]:8443", "/x", "?")):
            ex = h.parse_exchange({"request": {"method": "GET", "target_uri": uri, "fields": [["A", "b"]]}})
            self.assertEqual([h._derived(n, None, ex, True) for n in ("@authority", "@path", "@query")],
                             [auth, path, query], uri)
        # a response signature covering the request's @method and PAYMENT-SIGNATURE with req (2.4)
        params = '("@status" "@method";req "payment-signature";req);keyid="test-key-ed25519"'
        lines = ['"@status": 200', '"@method";req: POST', '"payment-signature";req: AAAA']
        doc = {"payment_payload": {}, "exchange": {
            "request": {"method": "POST", "target_uri": "https://e.example/", "fields": [["PAYMENT-SIGNATURE", "AAAA"]]},
            "response": {"status": 200, "fields": [["Signature-Input", "r=" + params],
                                                   ["Signature", "r=:%s:" % sign_ed(lines, params)]]}}}
        self.assertEqual(sigs(doc)[2]["signatures"][0]["result"], "verified")
        doc["exchange"]["request"]["method"] = "PUT"
        self.assertEqual(sigs(doc)[2]["signatures"][0]["result"], "failed:signature_invalid")

    def test_combined_field_lines(self):
        params = '("x-multi");keyid="test-key-ed25519"'
        doc = {"payment_payload": {}, "exchange": {"request": {"method": "GET", "target_uri": "https://e.example/",
               "fields": [["X-Multi", "a"], ["x-multi", "b, c"], ["Signature-Input", "s=" + params],
                          ["Signature", "s=:%s:" % sign_ed(['"x-multi": a, b, c'], params)]]}}}
        self.assertEqual(sigs(doc)[0]["X7"], "verified")     # RFC 9421 2.1: lines combined with ", "


class RFC9530Digests(unittest.TestCase):
    def digest(self, body, field, extra=()):
        doc = rfc_doc()
        rs = doc["exchange"]["response"]
        rs["fields"] = [["Content-Digest", field]] + list(extra)
        if body is None:
            del rs["body"]
        else:
            rs["body"] = b64(body)
        return sigs(doc, None)[0]["X5r"]

    def test_rfc_examples(self):
        # B.1: {"hello": "world"} followed by an LF (19 bytes); B.2: empty content
        self.assertEqual(self.digest(b'{"hello": "world"}\n', "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:"),
                         "verified")
        self.assertEqual(self.digest(b"", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"), "verified")
        self.assertEqual(self.digest(None, "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
                                     [["Content-Length", "0"]]), "verified")
        self.assertEqual(self.digest(None, "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"),
                         "not_evaluated:absent:no_body")
        # the RFC 9421 test request and response carry sha-512 digests of their content
        self.assertEqual(sigs(rfc_doc(), None)[0]["X5q"], "verified")
        self.assertEqual(sigs(rfc_doc(), None)[0]["X5r"], "verified")

    def test_mismatch_and_malformed(self):
        self.assertEqual(self.digest(b'{"hello": "world"}', "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:"),
                         "failed:content_digest_mismatch")
        ok, bad = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:", "sha-512=:" + b64(b"\0" * 64) + ":"
        self.assertEqual(self.digest(b"", ok + ", " + bad), "failed:content_digest_mismatch")
        for f in ("sha-256=47DEQ", "sha-256=:47DEQ", "sha-256", "sha-256=(:AA==:)", "SHA-256=:AA==:", "sha-256=:AA==:,"):
            self.assertEqual(self.digest(b"", f), "failed:content_digest_malformed", f)

    def test_other_algorithms_ignored(self):
        self.assertEqual(self.digest(b"", "md5=:1B2M2Y8AsgTpgAmY7PhCfg==:"), "not_evaluated:no_supported_digest")
        doc = rfc_doc()
        doc["exchange"]["response"]["fields"][2][1] += ", unixsum=:AA==:"
        res, notes, _ = sigs(doc, None)
        self.assertEqual(res["X5r"], "verified")
        self.assertIn("X5r: Content-Digest algorithm(s) ignored (RFC 9530 2): unixsum", notes)

    def test_absent(self):
        doc = rfc_doc()
        del doc["exchange"]["request"]["fields"][3]
        self.assertEqual(sigs(doc, None)[0]["X5q"], "not_evaluated:absent:no_content_digest")
        del doc["exchange"]["response"]
        r = sigs(doc, None)[0]
        self.assertEqual((r["X3"], r["X4"], r["X5r"], r["X6"]), ("not_evaluated:absent:no_response",) * 4)


class X402HttpMd(unittest.TestCase):
    def test_spec_headers_decode_to_the_json_shown(self):
        one, responses, blocks = http_md()
        vals = [one["PAYMENT-REQUIRED"], one["PAYMENT-SIGNATURE"]] + responses
        self.assertEqual(len(vals), 4)
        self.assertEqual([av.strict_json(h.b64decode(v).decode()) for v in vals], blocks[:4])

    def test_spec_example_bundle(self):
        r = run(md_bundle())
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertEqual({k: v for k, v in r["checks"].items() if k.startswith("X")},
                         {"X1": "verified", "X2": "verified", "X3": "verified", "X4": "verified",
                          "X5q": "not_evaluated:absent:no_content_digest", "X5r": "not_evaluated:absent:no_content_digest",
                          "X6": "verified", "X7": "not_evaluated:absent:no_signature"})
        self.assertEqual(r["exchange"], {"status": 200, "request_body_sha256": None, "response_body_sha256": None,
                                         "signatures": []})
        self.assertTrue(any(n.startswith("exchange (declared)") for n in r["notes"]))

    def test_spec_failure_example(self):
        one, responses, blocks = http_md()
        d = md_bundle()
        d["settlement"] = blocks[3]
        d["exchange"]["response"] = {"status": 402, "fields": [["PAYMENT-RESPONSE", responses[1]]]}
        r = run(d)
        self.assertEqual((r["checks"]["X3"], r["checks"]["X4"]), ("verified", "verified"))
        d["exchange"]["response"]["status"] = 200
        self.assertEqual(run(d)["checks"]["X4"], "failed:status_contradicts_settlement")

    def x(self, d, k):
        return run(d)["checks"][k]

    def test_each_x_fails(self):
        one, responses, blocks = http_md()
        d = md_bundle()
        d["payment_payload"]["payload"]["authorization"]["value"] = "10001"
        self.assertEqual(self.x(d, "X1"), "failed:request_carries_another_payment")
        d = md_bundle()
        d["exchange"]["request"]["fields"].append(["payment-signature", one["PAYMENT-SIGNATURE"]])
        self.assertEqual(self.x(d, "X1"), "failed:payment_signature_repeated")
        for v, why in ((one["PAYMENT-SIGNATURE"][:-1], "not_base64"), (b64(b"not json"), "not_json"),
                       (b64(b'{"a":1,"a":2}'), "not_json"), (b64(b"\xff"), "not_base64"),
                       (one["PAYMENT-SIGNATURE"].replace("=", "") + "", "not_base64")):
            d = md_bundle()
            d["exchange"]["request"]["fields"][1][1] = v
            self.assertEqual(self.x(d, "X1"), "failed:payment_signature_" + why, v[:20])
        d = md_bundle()
        del d["exchange"]["request"]["fields"][1]
        self.assertEqual(self.x(d, "X1"), "failed:request_without_payment_signature")
        d = md_bundle()
        d["exchange"]["request"]["target_uri"] = "https://api.example.com/premium-data?x=1"
        self.assertEqual(self.x(d, "X2"), "failed:request_not_for_the_resource")
        d = md_bundle()
        d["settlement"]["transaction"] = "0x" + "ab" * 32
        self.assertEqual(self.x(d, "X3"), "failed:response_carries_another_settlement")
        d = md_bundle()
        del d["exchange"]["response"]["fields"][1]
        self.assertEqual(self.x(d, "X3"), "failed:response_without_payment_response")
        d = md_bundle()
        del d["settlement"]
        self.assertEqual(self.x(d, "X3"), "failed:settlement_not_in_bundle")
        self.assertEqual(self.x(d, "X4"), "not_evaluated:absent:no_settlement")
        del d["exchange"]["response"]["fields"][1]
        self.assertEqual(self.x(d, "X3"), "not_evaluated:absent:no_payment_response")
        d = md_bundle()
        d["exchange"]["response"]["fields"].append(["Payment-Response", responses[0]])
        self.assertEqual(self.x(d, "X3"), "failed:payment_response_repeated")
        for st in (402, 100, 199, 300, 302, 399, 500):
            d = md_bundle()
            d["exchange"]["response"]["status"] = st
            self.assertEqual(self.x(d, "X4"), "failed:status_contradicts_settlement", st)
        for st in (200, 201, 299):
            d = md_bundle()
            d["exchange"]["response"]["status"] = st
            self.assertEqual(self.x(d, "X4"), "verified", st)
        for ct, want in (("text/html", "failed:content_type_not_the_declared_mime_type"),
                         ("Application/JSON; charset=utf-8", "verified"), ("application/json+x", "failed:"
                                                                           "content_type_not_the_declared_mime_type")):
            d = md_bundle()
            d["exchange"]["response"]["fields"][0][1] = ct
            self.assertEqual(self.x(d, "X6"), want, ct)
        d = md_bundle()
        del d["exchange"]["response"]["fields"][0]
        self.assertEqual(self.x(d, "X6"), "not_evaluated:absent:no_content_type")
        d = md_bundle()
        del d["payment_payload"]["resource"]["mimeType"]
        self.assertEqual(self.x(d, "X6"), "verified")            # the mimeType of payment_required
        del d["payment_required"]["resource"]["mimeType"]
        self.assertEqual(self.x(d, "X6"), "not_evaluated:absent:no_mime_type")
        d = md_bundle()
        del d["payment_payload"]["resource"]
        self.assertEqual(self.x(d, "X2"), "verified")            # the url of payment_required
        del d["payment_required"]
        self.assertEqual(self.x(d, "X2"), "not_evaluated:absent:no_resource_url")

    def test_failed_x_decides_the_verdict(self):
        d = md_bundle()
        d["exchange"]["request"]["target_uri"] = "https://api.example.com/other"
        r = run(d)
        self.assertEqual((r["verdict"], r["failed"]), ("chain_failed", ["X2"]))

    def test_cli_http_keys(self):
        d = md_bundle()
        d["exchange"]["response"]["fields"] += [["Signature-Input", 's=("@status");keyid="test-key-ed25519"'],
                                                ["Signature", "s=:%s:" % sign_ed(['"@status": 200'],
                                                                                '("@status");keyid="test-key-ed25519"')]]
        with tempfile.TemporaryDirectory() as t:
            bp, kp = os.path.join(t, "b.json"), os.path.join(t, "k.json")
            with open(bp, "w") as fh:
                json.dump(d, fh)
            with open(kp, "w") as fh:
                json.dump(KEYS, fh)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            outs = [subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), bp] + a,
                                   capture_output=True, text=True, env=env) for a in ([], ["--http-keys", kp])]
        r0, r1 = (json.loads(o.stdout) for o in outs)
        self.assertEqual((outs[0].returncode, r0["checks"]["X7"]), (0, "not_evaluated:absent:no_http_keys"))
        self.assertEqual((outs[1].returncode, r1["checks"]["X7"]), (0, "verified"))
        o = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), "x.json", "--http-keys"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(o.returncode, 64)


class PeacFixtures(unittest.TestCase):
    """their recorded components and body digest are an independent oracle for X2, the derived components and the
    reported body digest; their payload is a placeholder transaction, so check() is run on its own"""
    def setUp(self):
        def rd(p, mode="r"):
            with open(os.path.join(PEAC, p), mode) as fh:
                return fh.read()
        self.art = {k: rd("artifacts/%s.txt" % k) for k in ("payment-required", "payment-signature", "payment-response")}
        self.rb, self.ob = json.loads(rd("request-binding.json")), json.loads(rd("origin-result-binding.json"))
        self.body = rd("origin-result-body.bin", "rb")

    def test_x_on_their_bytes(self):
        c = self.rb["components"]
        dec = {k: av.strict_json(h.b64decode(v).decode()) for k, v in self.art.items()}
        doc = {"payment_payload": dec["payment-signature"], "payment_required": dec["payment-required"],
               "settlement": dec["payment-response"],
               "exchange": {"request": {"method": c["@method"], "target_uri": "%s://%s%s%s" % (
                   c["@scheme"], c["@authority"], c["@path"], c["@query"]),
                   "fields": [["Host", c["@authority"]], ["PAYMENT-SIGNATURE", self.art["payment-signature"]]]},
                   "response": {"status": self.ob["status"], "fields": [["Content-Type", self.ob["contentType"]],
                                                                         ["PAYMENT-RESPONSE", self.art["payment-response"]]],
                                "body": b64(self.body)}}}
        res, _, m = h.check(doc)
        self.assertEqual([res[k] for k in ("X1", "X2", "X3", "X4", "X6")], ["verified"] * 5)
        self.assertEqual("sha256:" + m["response_body_sha256"], self.ob["bodyDigest"])
        ex = h.parse_exchange(doc["exchange"])
        for k in ("@method", "@scheme", "@authority", "@path", "@query"):
            self.assertEqual(h._derived(k, None, ex, True), c[k], k)
        self.assertEqual("sha256:" + hashlib.sha256(self.art["payment-signature"].encode()).hexdigest(),
                         self.rb["selectedHeaders"][0]["observedValueDigest"])


class Grammar(unittest.TestCase):
    """closed at every level: unknown members, wrong types and out-of-grammar values are refused with their path"""
    def refused(self, d, why=""):
        r = run(d)
        self.assertEqual(r["verdict"], "refused", why)
        self.assertIn("exchange", r["reason"], why)

    def test_unknown_members_at_every_level(self):
        rng = random.Random(8)
        for path in ((), ("request",), ("response",)):
            for _ in range(5):
                d = md_bundle()
                o = d["exchange"]
                for k in path:
                    o = o[k]
                o["".join(rng.choice("abcdefgh_") for _ in range(rng.randint(1, 9))) + "x"] = rng.choice([1, "a", None, {}])
                self.refused(d, path)

    def test_values_out_of_grammar(self):
        cases = [
            (("request", "method"), "GE T"), (("request", "method"), ""), (("request", "method"), 1),
            (("request", "target_uri"), "ftp://e.example/"), (("request", "target_uri"), "https://e.example/#f"),
            (("request", "target_uri"), "https://u@e.example/"), (("request", "target_uri"), "https://e.example:99999/"),
            (("request", "target_uri"), "https:///p"), (("request", "target_uri"), "HTTPS://e.example/"),
            (("request", "target_uri"), "https://e.example/\u00e8"), (("request", "target_uri"), "https://e.example/ x"),
            (("request", "fields"), []), (("request", "fields"), [["A", "b"]] * 257), (("request", "fields"), {}),
            (("request", "fields"), [["A"]]), (("request", "fields"), [["A", 1]]), (("request", "fields"), [["A B", "c"]]),
            (("request", "fields"), [["", "c"]]), (("request", "fields"), [["A", " c"]]), (("request", "fields"), [["A", "c "]]),
            (("request", "fields"), [["A", "c\r\nX: y"]]), (("request", "fields"), [["A", "\u00e8"]]),
            (("request", "fields"), [["A", "c\x00"]]), (("request", "body"), "YQ"), (("request", "body"), "YQ= ="),
            (("request", "body"), "YR=="), (("request", "body"), 1), (("request", "body"), "Y Q=="),
            (("response", "status"), True), (("response", "status"), 99), (("response", "status"), 600),
            (("response", "status"), 200.0), (("response", "status"), "200"), (("response", "fields"), None),
            (("response", "body"), "-_-_")]
        for path, v in cases:
            d = md_bundle()
            d["exchange"][path[0]][path[1]] = v
            self.refused(d, (path, repr(v)[:30]))
        for k in ("method", "target_uri", "fields"):
            d = md_bundle()
            del d["exchange"]["request"][k]
            self.refused(d, k)
        for k in ("status", "fields"):
            d = md_bundle()
            del d["exchange"]["response"][k]
            self.refused(d, k)
        d = md_bundle()
        del d["exchange"]["request"]
        self.refused(d)
        for v in ([], "x", None):
            d = md_bundle()
            d["exchange"] = v
            self.refused(d, repr(v))

    def test_body_limit(self):
        d = md_bundle()
        d["exchange"]["response"]["body"] = b64(b"\0" * (h.MAX_BODY + 1))
        self.refused(d)
        d["exchange"]["response"]["body"] = b64(b"\0" * h.MAX_BODY)
        self.assertNotEqual(run(d)["verdict"], "refused")

    def test_only_apc03_and_apc05(self):
        d = md_bundle()
        for v in ("apc-0.1", "apc-0.2"):
            d["bundle_version"] = v
            r = run(d)
            self.assertEqual(r["verdict"], "refused")
            self.assertIn("exchange", r["reason"])

    def test_http_keys_closed(self):
        good = KEYS["keys"]["test-key-ed25519"]
        for k in ({"apc_http_keys": 2, "keys": {"a": good}}, {"apc_http_keys": True, "keys": {"a": good}},
                  {"apc_http_keys": 1, "keys": {}}, {"apc_http_keys": 1, "keys": {"a": good}, "x": 1},
                  {"apc_http_keys": 1, "keys": {"a": dict(good, x=1)}},
                  {"apc_http_keys": 1, "keys": {"a": {"alg": "rsa-pss-sha512", "public_key": good["public_key"]}}},
                  {"apc_http_keys": 1, "keys": {"a": {"alg": "ed25519", "public_key": good["public_key"][:-2]}}},
                  {"apc_http_keys": 1, "keys": {"a": {"alg": "ed25519", "public_key": good["public_key"].upper()}}},
                  {"apc_http_keys": 1, "keys": {"a": {"alg": "ecdsa-p256-sha256", "public_key": "04" + "11" * 64}}},
                  {"apc_http_keys": 1, "keys": {"a": {"alg": "ecdsa-p256-sha256", "public_key": "03" + EC_PUB[1:].hex()}}},
                  []):
            self.assertEqual(run(md_bundle(), k)["verdict"], "refused", k)


class StructuredFields(unittest.TestCase):
    """RFC 9651 parsing of the types these fields use; the examples are the RFC's"""
    def test_rfc_examples(self):
        d = dict(h.parse_dictionary('en="Applepie", da=:w4ZibGV0w6ZydGU=:'))
        self.assertEqual((d["en"][0], d["da"][0]), ("Applepie", base64.b64decode("w4ZibGV0w6ZydGU=")))
        d = dict(h.parse_dictionary("a=?0, b, c; foo=bar"))
        self.assertEqual((d["a"][0], d["b"][0], d["c"]), (False, True, (True, [("foo", "bar")])))
        d = dict(h.parse_dictionary("rating=1.5, feelings=(joy sadness)"))
        self.assertEqual(d["rating"][0], ("decimal", "1.5"))
        self.assertEqual([v for v, _ in d["feelings"][0]], ["joy", "sadness"])
        self.assertEqual(h.parse_dictionary('a=%"This is intended for display to %c3%bcsers."')[0][1][0],
                         "This is intended for display to \u00fcsers.")
        self.assertEqual(h.parse_dictionary("d=@1659578233")[0][1][0], ("date", 1659578233))

    def test_invalid(self):
        for s in ("a=1,", "a=1 b=2", "A=1", "a=(1 2", 'a="x', 'a="\\x"', "a=:YQ", "a=?2", "a=1.2345", "a=1234567890123456",
                  "a=1.", "a=-", 'a=%"%C3"', 'a=%"%c3"', "a=\u00e8", 'a="\u00e8"', 'a="x\x01"', "a=@1.5", "a=(1)2",
                  "a=:YQ-_:"):
            with self.assertRaises(h.SFError, msg=s):
                h.parse_dictionary(s)

    def test_serialize_round_trip(self):
        s = '("@method" "content-digest";req "x";key="a");created=1618884473;keyid="k\\"q";alg="ed25519"'
        (_, (val, ps)), = h.parse_dictionary("s=" + s)
        self.assertEqual(h.ser_inner(val, ps), s)


class Svm(unittest.TestCase):
    def test_apc05_with_exchange(self):
        with open(SVM) as fh:
            d = av.strict_json(fh.read())
        r0 = run(d)
        self.assertIsNone(r0["exchange"])
        self.assertFalse(any(k.startswith("X") for k in r0["checks"]))
        url = d["payment_payload"].get("resource", {}).get("url") or "https://e.example/"
        d["exchange"] = {"request": {"method": "GET", "target_uri": url, "fields": [
            ["PAYMENT-SIGNATURE", b64(json.dumps(d["payment_payload"]).encode())]]}}
        r = run(d)
        self.assertEqual(r["checks"]["X1"], "verified")
        self.assertEqual(r["verdict"], r0["verdict"])
        d["exchange"]["request"]["fields"][0][1] = b64(b"{}")
        r = run(d)
        self.assertEqual((r["checks"]["X1"], r["verdict"]), ("failed:request_carries_another_payment", "chain_failed"))


if __name__ == "__main__":
    unittest.main()
