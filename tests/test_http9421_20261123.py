"""SPEC 10.2 (Amendment 0.21.7, section 32.16, 2026-11-24): X7 under the sources in force on 2026-11-23. Oracles from outside
this work, copied under sources/webbotauth_c2sp_20261123 with sha256: draft-ietf-webbotauth-httpsig-protocol-01
Appendix E (signature bases and signatures; the RSA vectors are not verified here, E.1 is `algorithm_not_supported`),
c2sp.org/httpsig-pq v1.0.1 (its machine-readable vectors and its list of negative tests), and the examples of RFC 9421
2.1.2 and 2.2.8 (sources/http_20261025). The generative classes compare X7 with an oracle written here from the IANA
registry read the same day, or with Python's own urllib for the form encoding. No real corpus needed."""
import base64
import builtins
import hashlib
import json
import os
import random
import re
import sys
import unittest
from unittest import mock
from urllib.parse import parse_qsl, quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_http as h  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402

SRC = os.path.join(ROOT, "sources", "webbotauth_c2sp_20261123")
WBA = os.path.join(SRC, "draft-ietf-webbotauth-httpsig-protocol-01.txt")
C2SP = os.path.join(SRC, "c2sp_httpsig-pq_v1.0.1_63169cf.md")
try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:                                     # SPEC 10.2 (a): ML-DSA needs the cryptography package
    mldsa = None
NEED_MLDSA = unittest.skipIf(mldsa is None and os.environ.get("APC_REQUIRE_DEPS") != "1",
                             "the cryptography package with ML-DSA is not installed (SPEC 10.2 a)")


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64(b):
    return base64.b64encode(b).decode()


# RFC 9421 B.1.4 (test-key-ed25519), the key of the -01 vectors E.2 (their keyid is its JWK thumbprint)
ED_PUB = b64u("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
ED_SEED = b64u("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")
ED_TP = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


def keys(**ks):
    return h.parse_keys({"apc_http_keys": 1, "keys": {k: {"alg": a, "public_key": p.hex()} for k, (a, p) in ks.items()}})


def check(ex, ks):
    return h.check({"payment_payload": {}, "exchange": ex}, ks)[2]["signatures"]


def unfold(lines):
    """RFC 8792 section 7 ('\\' line wrapping): a line ending in a backslash goes on with the next, leading spaces cut"""
    out, cur = [], None
    for ln in lines:
        if cur is not None:
            ln = ln.lstrip(" ")
            cur += ln
        else:
            cur = ln
        if cur.endswith("\\"):
            cur = cur[:-1]
            continue
        out.append(cur)
        cur = None
    return out


def wba_section(title):
    """the lines of an Appendix E subsection of -01, page headers and footers and blank lines removed"""
    with open(WBA, encoding="ascii") as fh:
        txt = fh.read()
    lines = [ln for ln in txt.split("\n") if ln.strip() and not ln.startswith("\f") and
             not re.match(r"(Meunier & Major .*\[Page \d+\]|Internet-Draft .*)$", ln)]
    i = [k for k, ln in enumerate(lines) if ln.startswith(title)][-1]     # the section, not the table of contents
    j = next(k for k in range(i + 1, len(lines)) if re.match(r"(E\.\d\.\d\.|E\.\d\.|Appendix F)", lines[k]))
    return lines[i + 1:j]


def wba_vector(title):
    """(signature base, header fields) of a vector of -01: the folded blocks after each NOTE line"""
    sec = wba_section(title)
    blocks, k = [], 0
    while k < len(sec):
        if sec[k].startswith("NOTE: '\\' line wrapping"):
            j = k + 1
            while j < len(sec) and (sec[j].startswith('"') or sec[j].startswith(" ;") or
                                    re.match(r"[A-Z][A-Za-z-]+: ", sec[j]) or sec[j - 1].endswith("\\")):
                j += 1
            blocks.append(unfold(sec[k + 1:j]))
            k = j
        else:
            k += 1
    base = "\n".join(blocks[0]).encode()
    fields = [ln.split(": ", 1) for ln in blocks[1]]
    return base, fields


class WebBotAuth01(unittest.TestCase):
    """draft-ietf-webbotauth-httpsig-protocol-01 Appendix E, test-request of RFC 9421 B.2 (POST /foo?param=Value&Pet=dog)"""

    def request(self, fields):
        return {"request": {"method": "POST", "target_uri": "https://example.com/foo?param=Value&Pet=dog",
                            "fields": [["Host", "example.com"]] + fields}}

    def test_e2_ed25519_vectors_verify_and_their_bases_are_the_draft_listing(self):
        ks = keys(**{ED_TP: ("ed25519", ED_PUB)})
        for title, prof in (("E.2.1.", []), ("E.2.2.", [])):
            base, fields = wba_vector(title)
            ex = self.request(fields)
            s = check(ex, ks)
            self.assertEqual(s[0]["result"], "verified", title)
            self.assertEqual(s[0]["profile"], {"name": "draft-ietf-webbotauth-httpsig-protocol-01", "missing": prof})
            si = h.parse_dictionary(dict((k.lower(), v) for k, v in fields)["signature-input"])[0][1]
            px = h.parse_exchange(ex)
            px["request"] = {"fields": px["fields"], "body": None}
            self.assertEqual(h.signature_base(si[0], h.ser_inner(*si), px["request"], px, True), base, title)

    def test_e21_needs_the_key_parameter(self):
        # positive control: on 111de70 (no `key`) this vector was not_evaluated:component_not_supported
        base, fields = wba_vector("E.2.1.")
        self.assertIn(';key="sig2"', fields[1][1])
        fields[0][1] = 'sig2="https://other.test"'          # the covered member changed: the signature fails
        self.assertEqual(check(self.request(fields), keys(**{ED_TP: ("ed25519", ED_PUB)}))[0]["result"],
                         "failed:signature_invalid")

    def test_e23_signed_directory_response(self):
        sec = wba_section("E.2.3.")
        i = next(k for k, ln in enumerate(sec) if ln.strip().startswith('{"keys"'))
        body = "".join(ln.strip() for ln in unfold([x.strip() for x in sec[i:i + 3]])).encode()
        _, fields = wba_vector("E.2.3.")
        ex = {"request": {"method": "GET", "target_uri": "https://signature-agent.test/.well-known/"
                          "http-message-signatures-directory", "fields": [["Host", "signature-agent.test"]]},
              "response": {"status": 200, "fields": fields, "body": b64(body)}}
        res, _, m = h.check({"payment_payload": {}, "exchange": ex}, keys(**{ED_TP: ("ed25519", ED_PUB)}))
        self.assertEqual(res["X5r"], "verified")             # the Content-Digest the draft prints is that of the body
        self.assertEqual(m["signatures"][0]["result"], "verified")
        self.assertEqual(m["signatures"][0]["profile"], None)   # tag http-message-signatures-directory: no profile

    def test_e1_rsa_vectors_are_not_judged(self):
        for title in ("E.1.1.", "E.1.2."):
            _, fields = wba_vector(title)
            s = check(self.request(fields), keys(**{ED_TP: ("ed25519", ED_PUB)}))
            self.assertEqual(s[0]["result"], "not_evaluated:algorithm_not_supported", title)

    def test_thumbprints(self):
        self.assertEqual(h.thumbprint("ed25519", ED_PUB), ED_TP)          # the keyid of -01 E.2
        # RFC 7638 3.1: the thumbprint of its example is of an RSA key; for P-256 RFC 9421 B.1.3 with its own members
        x, y = b64u("qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA"), b64u("Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0")
        jwk = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (base64.urlsafe_b64encode(x).rstrip(b"=").decode(),
                                                                base64.urlsafe_b64encode(y).rstrip(b"=").decode())
        self.assertEqual(h.thumbprint("ecdsa-p256-sha256", (int.from_bytes(x, "big"), int.from_bytes(y, "big"))),
                         base64.urlsafe_b64encode(hashlib.sha256(jwk.encode()).digest()).rstrip(b"=").decode())
        self.assertIsNone(h.thumbprint("ml-dsa-65", b"\0" * 1952))

    def test_profile_missing_names(self):
        """our own Ed25519 signatures under tag web-bot-auth, each short of one requirement of -01 5.2 and 5.2.1"""
        ks = keys(**{ED_TP: ("ed25519", ED_PUB), "other": ("ed25519", ED_PUB)})
        good = ('("@authority" "signature-agent";key="s")', 'created=1;expires=2;keyid="%s";tag="web-bot-auth"' % ED_TP,
                [["Signature-Agent", 's="https://a.test/j"']])
        cases = [(good, []),
                 ((good[0].replace('"@authority" ', ""), good[1], good[2]), ["@authority|@target-uri"]),
                 ((good[0], good[1].replace("expires=2;", ""), good[2]), ["expires"]),
                 ((good[0], good[1].replace(ED_TP, "other"), good[2]), ["keyid_jwk_thumbprint"]),
                 ((good[0], good[1], [["Signature-Agent", 's="http://a.test/j"']]), ["signature-agent"]),
                 ((good[0], good[1], [["Signature-Agent", 's="https://a.test/j";type=jwks_uri']]), ["signature-agent"]),
                 ((good[0], good[1], [["Signature-Agent", 's="https://a.test/<j>"']]), ["signature-agent"]),
                 ((good[0], good[1], [["Signature-Agent", 's="https://a.test/j#f"']]), ["signature-agent"]),
                 ((good[0], good[1], [["Signature-Agent", 't="https://a.test/j"']]), ["signature-agent"]),
                 ((good[0], good[1], []), ["signature-agent"]),
                 (('("@authority" "signature-agent")', good[1], [["Signature-Agent", '"https://a.test/j"']]), []),
                 (('("@authority" "signature-agent")', good[1], [["Signature-Agent", '"https://a.test/j" x']]),
                  ["signature-agent"]),
                 (('("@authority" "signature-agent")', good[1], [["Signature-Agent", '"https://a.test/j";p']]),
                  ["signature-agent"]),
                 (('("@target-uri")', good[1].replace("created=1;", ""), good[2]), ["created", "signature-agent"]),
                 ((good[0], good[1].replace('keyid="%s";' % ED_TP, ""), good[2]), ["keyid"])]
        for (comps, params, extra), missing in cases:
            p = comps + ";" + params                # unsigned: the profile is read whatever the result
            ex = self.request(extra + [["Signature-Input", "s=" + p]])
            s = check(ex, ks)
            self.assertEqual(s[0]["profile"], {"name": "draft-ietf-webbotauth-httpsig-protocol-01", "missing": missing},
                             (p, extra))
            self.assertEqual(s[0]["tag"], "web-bot-auth")

    def test_profile_is_reported_never_a_result(self):
        p = '("@method");created=1;keyid="k";tag="web-bot-auth"'
        base = ('"@method": POST\n"@signature-params": ' + p).encode()
        ex = self.request([["Signature-Input", "s=" + p], ["Signature", "s=:%s:" % b64(sol.ed25519_sign(ED_SEED, base))]])
        s = check(ex, keys(k=("ed25519", ED_PUB)))
        self.assertEqual(s[0]["result"], "verified")
        self.assertEqual(s[0]["profile"]["missing"], ["@authority|@target-uri", "expires", "keyid_jwk_thumbprint",
                                                   "signature-agent"])
        # without the reader's keys the profile is still read, and no thumbprint is compared
        s = check(ex, None)
        self.assertEqual((s[0]["result"], s[0]["profile"]["missing"]),
                         ("not_evaluated:absent:no_http_keys", ["@authority|@target-uri", "expires", "signature-agent"]))
        # an ML-DSA key: -01 defines no thumbprint, none is compared; a member that is not a String is not a URI
        ex = self.request([["Signature-Agent", "s=1"], ["Signature-Input", 's=("@authority" "signature-agent";key="s");'
                                                         'created=1;expires=2;keyid="m";tag="web-bot-auth"']])
        self.assertEqual(check(ex, keys(m=("ml-dsa-65", b"\1" * 1952)))[0]["profile"]["missing"], ["signature-agent"])

    def test_no_tag_or_another_tag_is_profile_null(self):
        """SPEC 10.2 (d): "Another tag, or none, is profile null"; a tag that is not a String is no tag"""
        for t, tag in (("", None), (";tag=web-bot-auth", None), (";tag=1", None), (';tag=%"web-bot-auth"', None),
                       (';tag="other"', "other"), (';tag="Web-Bot-Auth"', "Web-Bot-Auth")):
            for ks in (None, keys(k=("ed25519", ED_PUB))):
                s = check(self.request([["Signature-Input", 's=("@authority");created=1;keyid="k"' + t]]), ks)
                self.assertEqual((s[0]["tag"], s[0]["profile"]), (tag, None), t)

    def test_signature_agent_with_brackets(self):
        """values Python's urlsplit raises ValueError on, or reads differently from one version to another: the label
        has its result on every Python, and only an https URI whose brackets are those of an IP literal is one"""
        p = '(%s);created=1;expires=2;keyid="%s";tag="web-bot-auth"'
        for uri, ok in (("https://[x", False), ("https://a]/", False), ("https://[::1]x/", False), ("https://[]/", False),
                        ("https://a.test/[1]", False), ("https://a.test/?q=[", False), ("https://", False),
                        ("https:///j", False), ("https:a.test", False), ("https://[::1]/j", True),
                        ("https://[::1]:8443/j", True), ("https://a.test:8443", True), ("https://a.test?x", True),
                        ("HTTPS://a.test/j", True), ("https://[a]/j", False), ("https://[1.2.3.4]/j", False),
                        ("https://[fe80::1%25eth0]/j", False), ("https://[2001:db8::1]/j", True),
                        ("https://[v1.abc]/j", True), ("https://[V1F.a:b]/j", True), ("https://[v1abc]/j", False),
                        ("https://[v.abc]/j", False), ("https://[v1.]/j", False), ("https://[v1.a%41]/j", False)):
            for cov, field in (('"@authority" "signature-agent";key="s"', 's="%s"' % uri),
                               ('"@authority" "signature-agent"', '"%s"' % uri)):
                for ks in (None, keys(**{ED_TP: ("ed25519", ED_PUB)})):
                    s = check(self.request([["Signature-Agent", field], ["Signature-Input", "s=" + p % (cov, ED_TP)],
                                            ["Signature", "s=:AAAA:"]]), ks)
                    self.assertEqual(s[0]["profile"]["missing"], [] if ok else ["signature-agent"], (uri, cov))
                    self.assertEqual(s[0]["result"], "not_evaluated:absent:no_http_keys" if ks is None
                                     else "failed:signature_invalid", (uri, cov))
        for c in ' <>"\\^`{|}#':                           # each character the check excludes, in a path
            uri = h.ser_bare("https://a.test/x%sy" % c)
            for cov, field in (('"@authority" "signature-agent";key="s"', "s=" + uri), ('"@authority" "signature-agent"', uri)):
                s = check(self.request([["Signature-Agent", field], ["Signature-Input", "s=" + p % (cov, ED_TP)]]), None)
                self.assertEqual(s[0]["profile"]["missing"], ["signature-agent"], (c, cov))
        for field in ('s="https://a.test/j"', '"https://a.test/j"'):      # a good value the label does not cover
            s = check(self.request([["Signature-Agent", field], ["Signature-Input", "s=" + p % ('"@authority"', ED_TP)]]),
                      None)
            self.assertEqual(s[0]["profile"]["missing"], ["signature-agent"], field)

    def test_entries_without_a_label_carry_the_members(self):
        """a Signature-Input that does not parse, and a Signature label without input: tag and profile null, with and
        without keys (SPEC 10.2 d: every entry carries them)"""
        for fields, want in (([["Signature-Input", "s=("], ["Signature", "s=:AAAA:"]], "failed:signature_input_malformed"),
                             ([["Signature", "t=:AAAA:"]], "failed:signature_without_input")):
            for ks in (None, keys(k=("ed25519", ED_PUB))):
                s = check(self.request(fields), ks)
                self.assertEqual([(e["tag"], e["profile"], e["result"]) for e in s],
                                 [(None, None, "not_evaluated:absent:no_http_keys" if ks is None else want)])
                if want.endswith("without_input"):
                    self.assertEqual((s[0]["keyid"], s[0]["expires"], s[0]["covered"]), (None, None, None))


def c2sp_vectors():
    with open(C2SP, encoding="utf-8") as fh:
        md = fh.read()
    return json.loads(re.findall(r"```json\n(.*?)```", md, re.S)[-1])["vectors"]


@NEED_MLDSA
class C2spHttpsigPq(unittest.TestCase):
    """c2sp.org/httpsig-pq v1.0.1: its three deterministic vectors through X7, and its "Negative tests" list"""

    def exchange(self, v, sig=None):
        si = v["serialized_signature_input"].split(": ", 1)[1]
        return {"request": {"method": "GET", "target_uri": "https://example.com/foo?param=Value&Pet=dog",
                            "fields": [["Host", "example.com"], ["Date", "Mon, 06 Jul 2026 20:00:00 GMT"],
                                       ["Signature-Input", si],
                                       ["Signature", "sig1=:%s:" % (sig or v["deterministic_signature_base64"])]]}}

    def ks(self, v, pk=None):
        return keys(**{"test-key-" + v["algorithm"].replace("-", ""): (v["algorithm"],
                                                                         pk or base64.b64decode(v["public_key_base64"]))})

    def test_vectors(self):
        vs = c2sp_vectors()
        self.assertEqual([v["algorithm"] for v in vs], ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"])
        for v in vs:
            ex = self.exchange(v)
            s = check(ex, self.ks(v))
            self.assertEqual(s[0]["result"], "verified", v["id"])
            px = h.parse_exchange(ex)
            px["request"] = {"fields": px["fields"], "body": None}
            si = h.parse_dictionary(ex["request"]["fields"][2][1])[0][1]
            base = h.signature_base(si[0], h.ser_inner(*si), px["request"], px, True)
            self.assertEqual(base, base64.b64decode(v["signature_base_base64"]))
            self.assertEqual(hashlib.sha256(base).hexdigest(), v["signature_base_sha256"])
            if hasattr(mldsa.MLDSA44PrivateKey, "from_seed_bytes"):   # the seed gives the vector's public key
                cls = {"ml-dsa-44": mldsa.MLDSA44PrivateKey, "ml-dsa-65": mldsa.MLDSA65PrivateKey,
                       "ml-dsa-87": mldsa.MLDSA87PrivateKey}[v["algorithm"]]
                sk = cls.from_seed_bytes(bytes.fromhex(v["private_key_seed_hex"]))
                self.assertEqual(sk.public_key().public_bytes_raw(), base64.b64decode(v["public_key_base64"]))

    def test_negative_list(self):
        for v in c2sp_vectors():
            alg, sig = v["algorithm"], base64.b64decode(v["deterministic_signature_base64"])
            pk = base64.b64decode(v["public_key_base64"])
            base = base64.b64decode(v["signature_base_base64"])
            self.assertTrue(h._verify_sig(alg, pk, base, sig))
            for b in (base.replace(b"GET", b"PUT"), base.replace(b"\n", b"\r\n"), base + b"\n",
                      b"\n".join(base.split(b"\n")[1:]), base.replace(alg.encode(), b"ed25519"),
                      hashlib.sha256(base).digest()):
                self.assertFalse(h._verify_sig(alg, pk, b, sig), (alg, b[:40]))
            for s in (sig[:-1], sig + b"\0", bytes([sig[0] ^ 1]) + sig[1:], sig[:-1] + bytes([sig[-1] ^ 0x80])):
                self.assertFalse(h._verify_sig(alg, pk, base, s), alg)
            other = [x for x in c2sp_vectors() if x["algorithm"] != alg]   # a key of another set: refused by length
            for x in other:
                with self.assertRaises(av.Refusal):
                    self.ks(v, base64.b64decode(x["public_key_base64"]))
            if hasattr(mldsa.MLDSA44PrivateKey, "from_seed_bytes"):
                cls = {"ml-dsa-44": mldsa.MLDSA44PrivateKey, "ml-dsa-65": mldsa.MLDSA65PrivateKey,
                       "ml-dsa-87": mldsa.MLDSA87PrivateKey}[alg]
                sk2 = cls.from_seed_bytes(bytes(32))             # another key of the same set
                self.assertFalse(h._verify_sig(alg, sk2.public_key().public_bytes_raw(), base, sig))
                sk = cls.from_seed_bytes(bytes.fromhex(v["private_key_seed_hex"]))
                self.assertTrue(h._verify_sig(alg, pk, base, sk.sign(base)))          # hedged: equally valid
                self.assertFalse(h._verify_sig(alg, pk, base, sk.sign(base, b"x")))   # a non-empty context
            # through X7: the substituted alg is the key's mismatch; a flipped signature fails
            ex = self.exchange(v)
            ex["request"]["fields"][2][1] = ex["request"]["fields"][2][1].replace(alg, "ed25519")
            self.assertEqual(check(ex, self.ks(v))[0]["result"], "failed:alg_not_the_key_algorithm")
            ex = self.exchange(v, b64(bytes([sig[0] ^ 1]) + sig[1:]))
            self.assertEqual(check(ex, self.ks(v))[0]["result"], "failed:signature_invalid")

    def test_key_lengths(self):
        for alg, (n, _) in h.MLDSA.items():
            for m in (0, n - 1, n + 1, 32, 65):
                with self.assertRaisesRegex(av.Refusal, "an %s key is %d bytes" % (alg.upper(), n) if m else "hex"):
                    keys(k=(alg, b"\1" * m))
            self.assertEqual(keys(k=(alg, b"\1" * n))["k"], (alg, b"\1" * n))

    def test_without_the_library(self):
        real = builtins.__import__

        def no_crypto(name, *a, **k):
            if name.startswith("cryptography"):
                raise ImportError("no cryptography")
            return real(name, *a, **k)
        v = c2sp_vectors()[1]
        with mock.patch.object(builtins, "__import__", no_crypto):
            self.assertEqual(check(self.exchange(v), self.ks(v))[0]["result"], "not_evaluated:ml_dsa_needs_cryptography")


    def test_a_backend_without_ml_dsa(self):
        """the package is installed and its backend has no ML-DSA (it raises UnsupportedAlgorithm): not judged"""
        from cryptography.hazmat.backends.openssl.backend import backend
        with mock.patch.object(type(backend), "mldsa_supported", lambda self: False):
            for v in c2sp_vectors():
                self.assertEqual(check(self.exchange(v), self.ks(v))[0]["result"],
                                 "not_evaluated:ml_dsa_needs_cryptography", v["id"])


@unittest.skipIf(mldsa is not None, "the cryptography package with ML-DSA is installed: C2spHttpsigPq runs instead")
class WithoutCryptography(unittest.TestCase):
    def test_vectors_not_judged(self):
        for v in c2sp_vectors():
            ex = C2spHttpsigPq.exchange(None, v)
            s = check(ex, C2spHttpsigPq.ks(None, v))
            self.assertEqual(s[0]["result"], "not_evaluated:ml_dsa_needs_cryptography", v["id"])


def iana_oracle(name, params):
    """the classification written from the IANA registry (2026-10-23) and RFC 9421 2.5, independent of apc_http"""
    derived = {"@method", "@authority", "@scheme", "@target-uri", "@request-target", "@path", "@query",
               "@query-param", "@status"}
    keys_ = [k for k, _ in params]
    if name.startswith("@"):
        ok = name in derived and all(k == "req" or (k == "name" and name == "@query-param") for k in keys_)
    else:
        ok = all(k in ("req", "key", "sf", "bs", "tr") for k in keys_)
    if not ok:
        return "failed:component_not_valid"
    if any(k in ("sf", "bs", "tr") for k in keys_):
        return "not_evaluated:component_not_supported"
    return "built"


class Components(unittest.TestCase):
    def ex(self, uri="https://example.com/p?a=1&b=x+y&c=%41", fields=()):
        e = h.parse_exchange({"request": {"method": "GET", "target_uri": uri, "fields": [["Host", "example.com"]] +
                                          [list(f) for f in fields]}})
        e["request"] = {"fields": e["fields"], "body": None}
        return e

    def base(self, comps, ex):
        val = h.parse_dictionary("s=(%s)" % comps)[0][1]
        return h.signature_base(val[0], h.ser_inner(*val), ex["request"], ex, True)

    def test_rfc_2_1_2_examples(self):
        ex = self.ex(fields=[["Example-Dict", "a=1, b=2;x=1;y=2, c=(a   b    c), d"]])
        got = self.base('"example-dict";key="a" "example-dict";key="d" "example-dict";key="b" "example-dict";key="c"',
                        ex).decode().split("\n")[:4]
        self.assertEqual(got, ['"example-dict";key="a": 1', '"example-dict";key="d": ?1',
                               '"example-dict";key="b": 2;x=1;y=2', '"example-dict";key="c": (a b c)'])
        ex = self.ex(fields=[["Example-Dict", "a=1"], ["Example-Dict", "b=2"]])   # lines combined (2.1.2)
        self.assertEqual(self.base('"example-dict";key="b"', ex).split(b"\n")[0], b'"example-dict";key="b": 2')
        ex = self.ex(fields=[["Example-Dict", "a=(1   2;q);p=1, b"]])              # an Inner List keeps its parameters
        self.assertEqual(self.base('"example-dict";key="a"', ex).split(b"\n")[0], b'"example-dict";key="a": (1 2;q);p=1')
        with self.assertRaises(h.Missing):
            self.base('"example-dict";key="c"', self.ex(fields=[["Example-Dict", "a=1, b=2"]]))   # 2.5 example
        with self.assertRaises(h.Failed):
            self.base('"x";key="a"', self.ex(fields=[["X", "a=1,"]]))

    def test_parameter_values_typed(self):
        # req is a Boolean flag (2.4); name and key are Strings (2.1.2, 2.2.8); @query-param needs its name
        ex = self.ex(fields=[["X", "a=1"]])
        for comp in ('"x";key=1', '"x";key=a', '"@query-param";name=1', '"@query-param"', '"x";req=1', '"x";req=?0'):
            with self.assertRaises(h.SFError, msg=comp):
                self.base(comp, ex)
        self.assertEqual(self.base('"x";key="a"', ex).split(b"\n")[0], b'"x";key="a": 1')
        # on a response: req is a flag, and @query-param is a component of the request, read only with req (2.4)
        ex["response"] = {"status": 200, "fields": [["Y", "1"]], "body": None}
        for comp, want in (('"@method";req=?0', None), ('"@method";req=1', None), ('"@query-param";name="a"', None),
                           ('"@query-param";name="a";req', b'"@query-param";name="a";req: 1'),
                           ('"@method";req', b'"@method";req: GET')):
            val = h.parse_dictionary("s=(%s)" % comp)[0][1]
            if want is None:
                with self.assertRaises(h.SFError, msg=comp):
                    h.signature_base(val[0], h.ser_inner(*val), ex["response"], ex, False)
            else:
                self.assertEqual(h.signature_base(val[0], h.ser_inner(*val), ex["response"], ex, False)
                                 .split(b"\n")[0], want)

    def test_rfc_2_2_8_examples(self):
        ex = self.ex("https://www.example.com/path?param=value&foo=bar&baz=batman&qux=")
        self.assertEqual(self.base('"@query-param";name="baz" "@query-param";name="qux" "@query-param";name="param"',
                                   ex).decode().split("\n")[:3],
                         ['"@query-param";name="baz": batman', '"@query-param";name="qux": ',
                          '"@query-param";name="param": value'])
        ex = self.ex("https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&"
                     "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
        self.assertEqual(self.base('"@query-param";name="var" "@query-param";name="bar" '
                                   '"@query-param";name="fa%C3%A7ade%22%3A%20"', ex).decode().split("\n")[:3],
                         ['"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value',
                          '"@query-param";name="bar": with%20plus%20whitespace',
                          '"@query-param";name="fa%C3%A7ade%22%3A%20": something'])

    def test_generated_query_params_against_urllib(self):
        rnd = random.Random(9421)
        alphabet = ["a", "B", "0", "=", "&", "+", "%", "%2", "%41", "%zz", "%C3%A7", "%FF", "~", "*", "-", ".", "_",
                    "!", "'", "(", ";", ":", "/", "?", "%20", "%26", "%3D"]
        ref = lambda s: quote(s, safe="*-._").replace("~", "%7E")     # noqa: E731 WHATWG urlencoded set, %20
        for _ in range(4000):
            q = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 14)))
            ex = self.ex("https://h.example/p?" + q)
            pairs = parse_qsl(q, keep_blank_values=True, errors="replace")
            for name in {ref(n) for n, _ in pairs} | {"a", "zz"}:
                want = [ref(v) for n, v in pairs if ref(n) == name]
                ident = '"@query-param";name=%s' % h.ser_bare(name)
                try:
                    got = self.base(ident, ex).split(b"\n")[0].decode()
                except h.Missing:
                    self.assertEqual(want, [], q)
                    continue
                except h.Failed as e:
                    self.assertGreater(len(want), 1, q)
                    self.assertEqual(str(e), "failed:query_param_repeated:" + ident)
                    continue
                self.assertEqual([got], ["%s: %s" % (ident, want[0])], q)
                self.assertEqual(len(want), 1, q)

    def test_generated_identifiers_are_closed(self):
        """every derived name and parameter, registered or not, on a field or a derived component: X7 builds the line,
        says not supported, or fails, as the oracle written from the registry says (positive control: 111de70 said
        not_supported for @foo, ;foo and @signature-params)"""
        rnd = random.Random(23)
        names = ["@method", "@authority", "@scheme", "@target-uri", "@request-target", "@path", "@query",
                 "@query-param", "@status", "@signature-params", "@foo", "@Method", "host", "example-dict", "x-a"]
        pk = ["req", "name", "key", "sf", "bs", "tr", "foo", "keyid", "alg"]
        ex = self.ex(fields=[["Example-Dict", "a=1"], ["X-A", "a=1"]])
        seen = set()
        for _ in range(3000):
            n = rnd.choice(names)
            ps = [(k, '"a"' if k in ("name", "key") else None) for k in rnd.sample(pk, rnd.randint(0, 2))]
            comp = h.ser_bare(n) + "".join(";" + k + ("=" + v if v else "") for k, v in ps)
            want = iana_oracle(n, ps)
            try:
                self.base(comp, ex)
                got = "built"
            except h.Failed as e:
                got = str(e).rsplit(":", 1)[0] if str(e).startswith("failed:component_not_valid") else str(e)
                got = "failed:component_not_valid" if got.startswith("failed:component_not_valid") else got
            except h.NotSupported:
                got = "not_evaluated:component_not_supported"
            except (h.Missing, h.SFError):
                got = "built"            # past the identifier rule: the value is absent or the message refuses it
            self.assertEqual(got, want, comp)
            seen.add(want)
        self.assertEqual(seen, {"built", "failed:component_not_valid", "not_evaluated:component_not_supported"})


class NoCrash(unittest.TestCase):
    def test_generated_inputs_always_give_a_result(self):
        """random Signature-Input, Signature, Signature-Agent, Dictionary fields and queries, with Ed25519 and ML-DSA keys:
        every label gets a result from the closed list of section 10 and 10.2, never an exception"""
        rnd = random.Random(1123)
        ks = keys(k=("ed25519", ED_PUB), m=("ml-dsa-65", b"\1" * 1952))
        atoms = ['"@method"', '"@query-param";name="a"', '"@query-param"', '"d";key="a"', '"d";key=1', '"d";sf',
                 '"signature-agent";key="s"', '"signature-agent"', '"@authority";req', '"@foo"', '"x";foo', '"@path"',
                 '"@status"', '"d";bs;key="a"', '"@query-param";name="a";key="b"']
        params = ['keyid="k"', 'keyid="m"', 'alg="ed25519"', 'alg="ml-dsa-65"', 'alg="rsa-pss-sha256"',
                  'alg="hmac-sha256"', "created=1", "expires=0", 'tag="web-bot-auth"', 'tag="agent-payer-auth"',
                  "tag=x", 'nonce="n"', "keyid=1"]
        dvals = ["a=1", "a=(1 2);p", "a", "a=1, a=2", "b=?0", "a=\"s\"", ",", "a=:AAAA:", "a=%\"x\"", "a=@1"]
        allowed = re.compile(r"(verified|failed:[a-z_]+(:.*)?|not_evaluated:[a-z_.0-9]+(:.*)?)\Z")
        for _ in range(2500):
            comps = " ".join(rnd.sample(atoms, rnd.randint(0, 4)))
            p = "(%s);%s" % (comps, ";".join(rnd.sample(params, rnd.randint(0, 5))))
            sig = rnd.choice([":AAAA:", ":" + b64(bytes(64)) + ":", ":" + b64(bytes(3309)) + ":", "1", '"x"'])
            q = "".join(rnd.choice(["a=1", "&", "a", "=", "%", "%C3", "+", "b=2"]) for _ in range(rnd.randint(0, 6)))
            fields = [["Host", "e.example"], ["Signature-Input", "s=" + p], ["Signature", "s=" + sig],
                      ["D", rnd.choice(dvals)], ["Signature-Agent", rnd.choice(['s="https://a.test"', '"https://a"',
                                                                                's=1', 's="x";t'])]]
            ex = {"request": {"method": "GET", "target_uri": "https://e.example/p?" + q, "fields": fields},
                  "response": {"status": 200, "fields": [["Signature-Input", "r=" + p], ["Signature", "r=" + sig]]}}
            for e in check(ex, ks):
                self.assertRegex(e["result"], allowed, (p, q))
                self.assertIn(e["tag"] is None or isinstance(e["tag"], str), (True,))


class Algorithms(unittest.TestCase):
    def label(self, params, ks, comps='("@method")'):
        p = comps + ";" + params
        base = ('"@method": GET\n"@signature-params": ' + p).encode()
        ex = {"request": {"method": "GET", "target_uri": "https://shop.example/p", "fields": [
            ["Host", "shop.example"], ["Signature-Input", "s=" + p],
            ["Signature", "s=:%s:" % b64(sol.ed25519_sign(ED_SEED, base))]]}}
        return check(ex, ks)[0]

    def test_registry_closed(self):
        ks = keys(k=("ed25519", ED_PUB))
        self.assertEqual(self.label('keyid="k";alg="ed25519"', ks)["result"], "verified")
        for a in ("rsa-pss-sha256", "ED25519", "ed25519 ", "rsa-pss", "es256", "ML-DSA-65", "mldsa65", ""):
            self.assertEqual(self.label('keyid="k";alg=%s' % h.ser_bare(a), ks)["result"],
                             "failed:algorithm_not_registered", a)
        for a in ("rsa-pss-sha512", "rsa-v1_5-sha256", "hmac-sha256", "ecdsa-p384-sha384"):
            self.assertEqual(self.label('keyid="nobody";alg="%s"' % a, ks)["result"],
                             "not_evaluated:algorithm_not_supported", a)
            self.assertEqual(self.label('keyid="k";alg="%s"' % a, ks)["result"], "failed:alg_not_the_key_algorithm")
        for a in ("ed25519", "ecdsa-p256-sha256", "ml-dsa-65", None):
            self.assertEqual(self.label('keyid="nobody"' + (';alg="%s"' % a if a else ""), ks)["result"],
                             "failed:unknown_keyid", a)
        rnd = random.Random(5)
        for _ in range(300):
            a = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789-_") for _ in range(rnd.randint(1, 18)))
            r = self.label('keyid="k";alg="%s"' % a, ks)["result"]
            self.assertEqual(r, "verified" if a == "ed25519" else "failed:alg_not_the_key_algorithm"
                             if a in h.IANA_ALGS else "failed:algorithm_not_registered", a)

    def test_visa_tap_shapes(self):
        """the shape the READMEs of visa/trusted-agent-protocol @16d59bd describe, signed by us with the RFC key"""
        ks = keys(k=("ed25519", ED_PUB))
        comps = '("@authority" "@path")'
        params = 'created=1;expires=2;keyid="k";alg="ed25519";nonce="n";tag="agent-payer-auth"'
        p = comps + ";" + params
        base = ('"@authority": shop.example\n"@path": /p\n"@signature-params": ' + p).encode()
        ex = {"request": {"method": "GET", "target_uri": "https://shop.example/p", "fields": [
            ["Host", "shop.example"], ["Signature-Input", "s=" + p],
            ["Signature", "s=:%s:" % b64(sol.ed25519_sign(ED_SEED, base))]]}}
        s = check(ex, ks)[0]
        self.assertEqual((s["result"], s["tag"], s["profile"]),
                         ("verified", "agent-payer-auth", {"name": "visa-tap-16d59bd", "missing": []}))
        ex["request"]["fields"][1][1] = ex["request"]["fields"][1][1].replace('nonce="n";', "")
        self.assertEqual(check(ex, ks)[0]["profile"]["missing"], ["nonce"])
        ex["request"]["fields"][1][1] = 's=("@authority");created=1;tag="agent-browser-auth"'
        self.assertEqual(check(ex, ks)[0]["profile"]["missing"], ["@path", "expires", "nonce", "keyid"])
        # the README's own example: keyId is not an RFC 9651 key
        ex["request"]["fields"][1][1] = 's=("@authority" "@path"); created=1; keyId="k"; alg="ed25519"'
        self.assertEqual(check(ex, ks)[0]["result"], "failed:signature_input_malformed")
        ex["request"]["fields"][1][1] = 's=' + comps + ';created=1;keyid="k";alg="rsa-pss-sha256";tag="agent-browser-auth"'
        s = check(ex, ks)[0]
        self.assertEqual((s["result"], s["profile"]["name"]), ("failed:algorithm_not_registered", "visa-tap-16d59bd"))
        for tag in ("web-bot-auth ", "agent-payer", "Agent-Payer-Auth", "x"):
            ex["request"]["fields"][1][1] = 's=' + comps + ';keyid="k";tag=%s' % h.ser_bare(tag)
            self.assertIsNone(check(ex, ks)[0]["profile"], tag)


class HostileInput20261123(unittest.TestCase):
    """SPEC 29 (the bundle as hostile input) on the code of 10.2 (independent hunt 2026-11-23). D1: a field read by n
    `key` components, a query read by n @query-param components, or a Signature-Agent read by the profile of each of 64
    labels was parsed once per component or label (quadratic: 32 s of CPU for n = 2000 `key` components, 5 s for 2000
    @query-param, measured on 30b0ac0); it is parsed once. D2: a target_uri whose host urlsplit cannot read ("[" outside
    an IPv6 literal) raised ValueError, verdict `error` (SPEC 29.3); it is refused."""
    N = 300

    def request(self, uri, fields, comps):
        return {"request": {"method": "GET", "target_uri": uri, "fields": [["Host", "api.example.com"]] + fields + [
            ["Signature-Input", 'sig1=(%s);keyid="k"' % " ".join(comps)], ["Signature", "sig1=:" + "A" * 86 + "==:"]]}}

    def counted(self, ex, name, ks):
        calls = []
        real = getattr(h, name)
        with mock.patch.object(h, name, side_effect=lambda *a, **k: calls.append(a[-1] if name == "combined" else a[0]) or real(*a, **k)):
            s = check(ex, ks)
        return s, calls

    def test_key_components_parse_the_field_once(self):
        val = ", ".join("a%d=1" % i for i in range(self.N))
        ex = self.request("https://api.example.com/p", [["X", val]], ['"x";key="a%d"' % i for i in range(self.N)])
        s, calls = self.counted(ex, "parse_dictionary", keys(k=("ed25519", ED_PUB)))
        self.assertEqual(s[0]["result"], "failed:signature_invalid")
        self.assertEqual(calls.count(val), 1)

    def test_query_param_components_split_the_query_once(self):
        q = "&".join("a%d=1" % i for i in range(self.N))
        ex = self.request("https://api.example.com/p?" + q, [], ['"@query-param";name="a%d"' % i for i in range(self.N)])
        s, calls = self.counted(ex, "_form", keys(k=("ed25519", ED_PUB)))
        self.assertEqual(s[0]["result"], "failed:signature_invalid")
        self.assertLessEqual(len(calls), 2 * self.N)

    def test_signature_agent_parsed_once_for_64_labels(self):
        for cov, tail in (('"signature-agent";key="sig%d"', 'sig0="https://a.example/x"'), ('"signature-agent"', '"https://a.example/x"')):
            ex = {"request": {"method": "GET", "target_uri": "https://api.example.com/p", "fields": [
                ["Host", "api.example.com"], ["Signature-Agent", tail],
                ["Signature-Input", ", ".join(('sig%d=("@authority" ' + cov + ');tag="web-bot-auth"') % ((i, i) if "%d" in cov else (i,))
                                              for i in range(64))]]}}
            s, c1 = self.counted(ex, "parse_dictionary", None)
            _, c2 = self.counted(ex, "_item", None)
            self.assertEqual(len(s), 64)
            self.assertEqual(c1.count(tail) + c2.count(tail), 1, cov)
            self.assertNotIn("signature-agent", s[0]["profile"]["missing"])

    def test_a_field_is_joined_once_for_its_components_and_labels(self):
        val = ", ".join("a%d=1" % i for i in range(self.N))
        comps = " ".join('"x";key="a%d"' % i for i in range(self.N))
        ex = {"request": {"method": "GET", "target_uri": "https://api.example.com/p", "fields": [
            ["Host", "api.example.com"], ["X", val], ["X", "z=2"],
            ["Signature-Input", ", ".join('s%d=(%s);keyid="k"' % (i, comps) for i in range(64))],
            ["Signature", ", ".join("s%d=:%s==:" % (i, "A" * 86) for i in range(64))]]}}
        s, calls = self.counted(ex, "combined", keys(k=("ed25519", ED_PUB)))
        self.assertEqual({x["result"] for x in s}, {"failed:signature_invalid"})
        self.assertEqual(calls.count("x"), 1)      # 2 lines, 300 components, 64 labels: joined once

    def test_a_field_that_is_not_a_dictionary_stays_one_failure_per_label(self):
        ex = self.request("https://api.example.com/p", [["X", "(("]], ['"x";key="a"'])
        self.assertEqual(check(ex, keys(k=("ed25519", ED_PUB)))[0]["result"], 'failed:component_not_a_dictionary:"x";key="a"')

    def test_unreadable_host_is_refused(self):
        for uri in ("https://A[pi.example.com/p", "https://api.example.com]/p", "https://[::1/p"):
            with self.assertRaises(av.Refusal, msg=uri):
                h.check({"payment_payload": {}, "exchange": {"request": {"method": "GET", "target_uri": uri,
                                                                         "fields": [["Host", "x"]]}}})
        self.assertEqual(check({"request": {"method": "GET", "target_uri": "https://[::1]/p", "fields": [["Host", "x"]]}},
                               None), [])                                  # control: an IPv6 literal is read

    def test_seventeen_dictionary_fields_are_each_parsed_once(self):
        """review 2026-11-23: with the parses in a cache of 16 values, 17 fields read in turn were parsed again at every
        component (15.9 s of CPU for 17 fields of 2000 members and 1020 components); they are kept in the message"""
        vals = [", ".join("a%d=%d" % (i, f) for i in range(40)) for f in range(17)]
        ex = self.request("https://api.example.com/p", [["X%d" % f, v] for f, v in enumerate(vals)],
                          ['"x%d";key="a%d"' % (f, i) for i in range(40) for f in range(17)])
        s, calls = self.counted(ex, "parse_dictionary", keys(k=("ed25519", ED_PUB)))
        self.assertEqual(s[0]["result"], "failed:signature_invalid")
        self.assertEqual([calls.count(v) for v in vals], [1] * 17)

    def test_a_parse_is_of_its_own_check(self):
        for val, want in (("a=1", "failed:signature_invalid"), ("((", 'failed:component_not_a_dictionary:"x";key="a"'),
                          ("b=1", 'failed:component_not_in_message:"x";key="a"'), ("a=2", "failed:signature_invalid")):
            ex = self.request("https://api.example.com/p?a=" + val[-1], [["X", val]], ['"x";key="a"'])
            self.assertEqual(check(ex, keys(k=("ed25519", ED_PUB)))[0]["result"], want, val)
        for q, want in (("a=1", "failed:signature_invalid"),
                        ("b=1", 'failed:component_not_in_message:"@query-param";name="a"'),
                        ("a=1&a=2", 'failed:query_param_repeated:"@query-param";name="a"')):
            ex = self.request("https://api.example.com/p?" + q, [], ['"@query-param";name="a"'])
            self.assertEqual(check(ex, keys(k=("ed25519", ED_PUB)))[0]["result"], want, q)

    def test_signature_agent_read_as_a_dictionary_and_as_an_item_in_one_check(self):
        ex = {"request": {"method": "GET", "target_uri": "https://api.example.com/p", "fields": [
            ["Host", "api.example.com"], ["Signature-Agent", '"https://a.example/x"'],
            ["Signature-Input", 'a=("@authority" "signature-agent";key="a");tag="web-bot-auth", '
                                'b=("@authority" "signature-agent");tag="web-bot-auth"']]}}
        s = check(ex, None)
        self.assertEqual(["signature-agent" in x["profile"]["missing"] for x in s], [True, False])

    def test_target_uri_authority_is_read_the_same_on_every_python(self):
        """SPEC 10 (review 2026-11-23): urlsplit took "[::1%25eth0]" as a host, refused "[V1.x]" on Python 3.9 and 3.11
        and read it on 3.13, and on 3.9 read the ports "+0" and "8_1"; the authority is read by one grammar first"""
        def read(uri):
            try:
                u = h.parse_exchange({"request": {"method": "GET", "target_uri": uri, "fields": [["Host", "x"]]}})
                return u["split"].hostname, u["split"].port
            except av.Refusal as e:
                return str(e)
        for uri, want in (("https://[::1]/p", ("::1", None)), ("https://[V1.x]:8/p", ("v1.x", 8)),
                          ("http://[v1.x]/", ("v1.x", None)), ("https://[::FFFF:1.2.3.4]:443", ("::ffff:1.2.3.4", 443)),
                          ("https://a.example:/p?x=[1]", ("a.example", None)),
                          ("https://a.example/[", ("a.example", None)),
                          ("http://a.example?x=[1]", ("a.example", None))):
            self.assertEqual(read(uri), want, uri)
        for uri in ("https://[::1%25eth0]/", "https://[fe80::1%251]/", "https://[1.2.3.4]/", "https://[::1]x/",
                    "https://[x]/", "https://[]/", "https://x@[::1]/", "https://[[::1]]/", "https://[v1.]/",
                    "https://[::1]:8]/", "https://[::01.2.3.4]/", "https://[1::2::3]/", "http://[::1%25eth0]/",
                    "https://a.example]/", "https://a[.example/", "https://[v1x]/", "https://[v.x]/",
                    "https://[v1.a%41]/"):
            self.assertEqual(read(uri), "exchange.request.target_uri: host not readable (RFC 3986 3.2.2)", uri)
        for uri in ("https://a.example:+0/", "https://a.example:8_1/", "https://a.example:-0/", "https://[::1]:+8/",
                    "https://a.example:65536/", "https://a.example:8:8/"):
            self.assertEqual(read(uri), "exchange.request.target_uri: port not a number in range", uri)


if __name__ == "__main__":
    unittest.main()
