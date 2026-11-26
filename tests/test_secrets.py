"""SPEC 32.17 (0.21.8): a secret given to this work does not come out of it. A canary — an Ed25519 seed, a password in a
URL, a key id or member name that is a key put there by mistake — goes into every input that takes a key, a URL or a
token (apc_registry --tsa, --key, apc_verify --http-keys and --signer-trust, apc_report sign, a did:jwk), and is
searched in everything that comes out: standard output and error, the register written, the report, the exception. It
is searched raw and in hex, base64, base64url (at each of the three offsets, so inside a longer text too) and decimal.
With it the platform rules of the same amendment: no program found by a bare name, no temporary folder by tempfile, a
bounded read that does not ask the allocator for its bound, integers of more than 4300 digits refused on every Python.

Positive control: a producer that leaks is found in each of those forms; and on 0.21.7 (2fdf128) the tests that state
the new behaviour fail (SPEC 32.17 names them)."""
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_registry as rg  # noqa: E402
import apc_siglib  # noqa: E402

SEED = hashlib.sha256(b"apc test_secrets canary seed").digest()          # a test key, not anyone's
PASSWORD = "Pw" + base64.urlsafe_b64encode(SEED).decode()[:30]
KEYNAME = base64.urlsafe_b64encode(SEED).decode().rstrip("=")             # 43 characters: a key put where a name goes
CANARIES = (SEED, SEED.hex().encode(), PASSWORD.encode(), KEYNAME.encode())
REPORT = {"verifier": "apc_verify 0.8.0", "verdict": "chain_verified", "checks": {}}
PY = [sys.executable, "-B"]


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):          # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")      # JSON may escape the slash of base64
    return sorted(n for n, f in forms(secret).items() if f in blob)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="apcsec-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def file(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def left(self):
        out = []
        for base, _, files in os.walk(self.d):
            for n in files:
                with open(os.path.join(base, n), "rb") as f:
                    out.append(f.read())
        return out

    def none(self, what, *outputs, inputs=()):
        """No canary in the outputs nor in any file of the folder but the inputs (which hold it by construction)."""
        files = [b for b in self.left() if not any(c in b for c in inputs)]
        for c in CANARIES:
            self.assertEqual(found(c, *outputs, *files), [], what)

    def cli(self, script, *argv, env=None, cwd=None, stdin=None):
        e = dict(os.environ, **(env or {}))
        return subprocess.run(PY + [os.path.join(ROOT, script)] + list(argv), capture_output=True, timeout=120,
                              cwd=cwd or self.d, env=e, input=stdin)

    def register(self):
        reg = os.path.join(self.d, "reg")
        self.assertEqual(self.cli("apc_registry.py", "init", reg).returncode, 0)
        return reg, self.file("rep.json", json.dumps(REPORT))

    def ca(self):
        # the network is reached only with a trust store: a runner without a system one (Windows has no CA file)
        # stops before it, "--tsa: no system trust store found"; this file is never read before the reply
        return self.file("ca.pem", "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n")


class TheSearchFinds(Base):
    """Positive control of the search, and of a producer that leaks."""

    def test_every_form(self):
        s = SEED
        for name, text in (("raw", b"x" + s + b"y"), ("hex", b'"' + s.hex().encode()), ("HEX", s.hex().upper().encode()),
                           ("decimal", str(int.from_bytes(s, "big")).encode()), ("base64+0", base64.b64encode(s)),
                           ("base64+1", base64.b64encode(b"{" + s + b"}")), ("base64+2", base64.b64encode(b'{"' + s)),
                           ("base64url+0", base64.urlsafe_b64encode(s)), ("base64url+1", base64.urlsafe_b64encode(b"a" + s)),
                           ("base64url+2", base64.urlsafe_b64encode(b"ab" + s + b"c"))):
            self.assertIn(name, found(s, text), name)
        self.assertEqual(found(s, b"nothing", hashlib.sha256(s).hexdigest()), [])

    def test_a_producer_that_leaks_is_found(self):
        reg, rep = self.register()
        url = "http://127.0.0.1:1/" + PASSWORD
        with mock.patch.object(rg, "net_reason", lambda e: "%s %s" % (url, e)), \
                mock.patch("urllib.request.urlopen", side_effect=OSError(111, "refused")), \
                mock.patch.object(rg, "_openssl", lambda: sys.executable), \
                mock.patch.object(rg.subprocess, "run", lambda *a, **k: open(a[0][-1], "wb").close() or
                                  subprocess.CompletedProcess(a[0], 0, b"", b"")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rg.main(["apc_registry.py", "record", reg, "--report", rep, "--tsa", url, "--tsa-ca", self.ca()])
        self.assertIn("raw", found(PASSWORD.encode(), out.getvalue()))
        with self.assertRaises(AssertionError):
            self.none("a leak", out.getvalue())
        self.file("leak.txt", base64.b64encode(b"ab" + SEED))
        with self.assertRaises(AssertionError):
            self.none("a leak in a file")


class Register(Base):
    URLS = ("http://u:%s@127.0.0.1:1/" % PASSWORD, "http://%s@127.0.0.1:1/" % PASSWORD,
            "HTTPS://u:%s@127.0.0.1:1/" % PASSWORD, "http://%s:@127.0.0.1:1/" % PASSWORD,
            "http://u:%s@[::1]:1/" % PASSWORD, "http://127.0.0.1:1/\\@" + PASSWORD,
            "http://127.0.0.1:1/ " + PASSWORD, "http://127.0.0.1:1/\x00" + PASSWORD, "http://127.0.0.1:1/é" + PASSWORD,
            "ftp://" + PASSWORD + "/", PASSWORD, "http://127.0.0.1:99999/" + PASSWORD,
            # outside the grammar of tsa_url (11.2): asked first and refused after, the digest had left the machine
            "HTTP://127.0.0.1:1/" + PASSWORD, "Https://127.0.0.1:1/" + PASSWORD, "http://127.0.0.1:1/" + PASSWORD + "a" * 500)

    def test_a_url_with_user_information_is_refused_before_the_network(self):
        reg, rep = self.register()
        for url in self.URLS:
            with mock.patch("urllib.request.urlopen") as net:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = rg.main(["apc_registry.py", "record", reg, "--report", rep, "--tsa", url])
            self.assertEqual((rc, net.call_count), (3, 0), url)
            self.assertIn("not repeated here", out.getvalue(), url)
            self.none(url, out.getvalue())
        with open(reg, "rb") as f:
            self.assertEqual(f.read().count(b"\n"), 1, "nothing recorded")
        ca = self.file("ca.pem", "x")                # the longest URL the register can hold is accepted, one more is not
        self.assertEqual(rg.tsa_trust("https://" + "h" * 500, ca)[0], "user_ca")
        with self.assertRaises(rg.Bad):
            rg.tsa_trust("https://" + "h" * 501, ca)

    def test_the_cli_too(self):
        reg, rep = self.register()
        r = self.cli("apc_registry.py", "record", reg, "--report", rep, "--tsa", self.URLS[0])
        self.assertEqual(r.returncode, 3)
        self.none("cli", r.stdout, r.stderr)

    def test_a_network_error_says_its_kind_not_its_text(self):
        import urllib.error
        for e in (urllib.error.URLError(OSError(111, "refused " + PASSWORD)), urllib.error.URLError("x " + PASSWORD),
                  urllib.error.HTTPError("http://h/" + PASSWORD, 403, PASSWORD, {}, None), OSError(5, PASSWORD),
                  ValueError(PASSWORD), TimeoutError(PASSWORD)):
            why = rg.net_reason(e)
            self.none(repr(e), why)
            self.assertTrue(why.split(":")[0].replace(" [Errno 5]", "") in ("URLError", "HTTPError", "OSError",
                                                                          "ValueError", "TimeoutError"), why)
        self.assertEqual(rg.net_reason(urllib.error.HTTPError("u", 403, "m", {}, None)), "HTTPError: 403")

    @unittest.skipIf(shutil.which("openssl") is None, "openssl is not on PATH")
    def test_a_url_that_cannot_be_reached_is_not_repeated(self):
        reg, rep = self.register()
        r = self.cli("apc_registry.py", "record", reg, "--report", rep, "--tsa", "http://127.0.0.1:1/" + PASSWORD,
                     "--tsa-ca", self.ca())
        self.assertEqual(r.returncode, 3)
        self.assertIn(b"--tsa: no reply: ", r.stdout)
        self.none("unreachable", r.stdout, r.stderr)

    def test_the_seed_never_comes_out(self):
        reg, rep = self.register()
        key = self.file("seed", SEED.hex() + "\n")
        r = self.cli("apc_registry.py", "record", reg, "--report", rep, "--key", key)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.none("seed", r.stdout, r.stderr, inputs=(SEED.hex().encode(),))
        for bad in (SEED.hex() + "0", "\xff" + SEED.hex(), SEED + b"\xff", SEED.hex() * 9):
            r = self.cli("apc_registry.py", "record", reg, "--report", rep, "--key", self.file("bad", bad))
            self.assertEqual((r.returncode, json.loads(r.stdout)), (3, {"error": "the seed file is not one 32-byte hex line"}))
            self.none("bad seed", r.stdout, r.stderr, inputs=(SEED, SEED.hex().encode()))

    def test_an_internal_error_says_its_type_only(self):
        reg, rep = self.register()
        out = io.StringIO()
        with mock.patch.object(rg, "cmd_record", side_effect=RuntimeError(PASSWORD)), contextlib.redirect_stdout(out):
            self.assertEqual(rg.main(["apc_registry.py", "record", reg, "--report", rep]), 3)
        self.assertEqual(json.loads(out.getvalue()), {"error": "internal error, nothing more done: RuntimeError"})


class ReaderKeys(Base):
    """--http-keys and --signer-trust: public keys only by their grammar; a name that could be a key is not repeated."""

    def docs(self, top, inner):
        pub = "11" * 32
        good = {"alg": inner, "public_key": pub}
        return [{top: 1, "keys": {KEYNAME: {"alg": "nope", "public_key": pub}}},
                {top: 1, "keys": {KEYNAME: dict(good, d=SEED.hex())}},
                {top: 1, "keys": {"k": dict(good, **{KEYNAME: 1})}},
                {top: 1, "keys": {"k": good}, KEYNAME: 1},
                '{"%s": 1, "keys": {"%s": 1, "%s": 2}}' % (top, KEYNAME, KEYNAME)]

    def test_http_keys(self):
        bundle = self.file("b.json", "{}")
        for doc in self.docs("apc_http_keys", "ed25519"):
            k = self.file("k.json", doc if isinstance(doc, str) else json.dumps(doc))
            r = self.cli("apc_verify.py", bundle, "--http-keys", k)
            self.assertEqual(r.returncode, 3, r.stdout)
            self.assertEqual(json.loads(r.stdout)["verdict"], "refused")
            self.none(doc, r.stdout, r.stderr, inputs=(KEYNAME.encode(),))

    def test_signer_trust(self):
        import apc_offer
        import apc_verify as av
        for doc in self.docs("apc_signer_trust", "EdDSA"):
            try:
                doc = av.strict_json(doc) if isinstance(doc, str) else dict(doc, authorized=[])
                apc_offer.parse_trust(doc)
                self.fail("accepted")
            except av.Refusal as e:
                self.none(doc, str(e))

    def test_a_did_jwk_with_a_private_member_is_refused(self):
        import apc_offer
        import apc_verify as av
        x = base64.urlsafe_b64encode(b"\x11" * 32).decode().rstrip("=")
        d = base64.urlsafe_b64encode(SEED).decode().rstrip("=")
        self.assertEqual(sorted(apc_offer.JWK_PRIVATE), sorted(("d", "p", "q", "dp", "dq", "qi", "oth", "k")))
        for m in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
            with self.assertRaises(av.Refusal) as c:
                apc_offer._jwk_key({"kty": "OKP", "crv": "Ed25519", "x": x, m: d}, [])
            self.assertIn("private key member " + m, str(c.exception))
            self.none(m, str(c.exception))
        notes = []
        try:
            apc_offer._jwk_key({"kty": "OKP", "crv": "Ed25519", "x": x, KEYNAME: 1}, notes)
        except av.Refusal:
            pass
        self.none("ignored member named", notes)
        notes = []          # a short name is repeated as in 0.21.7, byte for byte (no quotes)
        apc_offer._jwk_key({"kty": "OKP", "crv": "Ed25519", "x": x, "use": "sig", "kid": "k1"}, notes)
        self.assertEqual(notes, ["did:jwk members ignored (RFC 7517 4): kid, use"])
        notes = []          # the bound: 32 characters repeated, 33 named by their length
        apc_offer._jwk_key({"kty": "OKP", "crv": "Ed25519", "x": x, "a" * 32: 1, "b" * 33: 1}, notes)
        self.assertEqual(notes, ["did:jwk members ignored (RFC 7517 4): %s, (a name of 33 characters, not repeated)"
                                 % ("a" * 32)])


class SignedReports(Base):
    def test_sign_never_writes_the_seed(self):
        rep = self.file("rep.json", json.dumps(REPORT))
        r = self.cli("apc_report.py", "sign", self.file("seed", SEED.hex()), rep)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.none("sign", r.stdout, r.stderr, inputs=(SEED.hex().encode(),))
        for bad in (SEED.hex() + "0", b"\xff" + SEED, SEED.hex() * 9):
            r = self.cli("apc_report.py", "sign", self.file("bad", bad), rep)
            self.assertEqual(json.loads(r.stdout), {"error": "the seed file is not one 32-byte hex line"})
            self.none("bad seed", r.stdout, r.stderr, inputs=(SEED, SEED.hex().encode()))


class Platforms(Base):
    """SPEC 32.17: the programs, the temporary folders, the reads and the integers."""

    def test_no_program_by_bare_name_no_tempfile_folder(self):
        bad = re.compile(r"shutil\.which\(|tempfile\.mk[sd]temp|NamedTemporaryFile|TemporaryDirectory")
        hits = []
        for n in sorted(os.listdir(ROOT)):
            if n.startswith("apc_") and n.endswith(".py"):
                with open(os.path.join(ROOT, n), encoding="utf-8") as f:
                    hits += ["%s:%d" % (n, i) for i, line in enumerate(f, 1) if bad.search(line.split("#")[0])]
        self.assertEqual(hits, [])
        self.the_tools_write_the_host_of_an_endpoint_only()

    def the_tools_write_the_host_of_an_endpoint_only(self):
        """An endpoint URL carries the provider's key in its path or query: a tool writes scheme://host[:port] of it."""
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        from endpoint import where
        for url, want in (("https://h.example/v2/" + PASSWORD, "https://h.example"), ("http://127.0.0.1:8545/?k=" + PASSWORD, "http://127.0.0.1:8545"),
                          ("https://u:%s@h.example:8443/x#%s" % (PASSWORD, PASSWORD), "https://h.example:8443"),
                          ("http://[::1]:99/" + PASSWORD, "http://[::1]:99"), ("https://h.example:99999/" + PASSWORD, "?"),
                          (PASSWORD, "://?"), (None, "?")):
            self.assertEqual(where(url), want)
        # no tool writes the variable that holds the URL: every "rpc"/"server"/"url"/"horizon"/"facilitator" it writes is where(...)
        bad = re.compile(r'''"(?:rpc|server|url|horizon|facilitator)": *(?:RPC|url|u|fb\.RPC|c\["rpc"\]|SUPPORTED|HORIZON)\b|\[k\] = url\b''')
        hits = []
        for folder in ("tools", os.path.join("sources", "l1proof_20261024")):
            for n in sorted(os.listdir(os.path.join(ROOT, folder))):
                if n.endswith(".py"):
                    with open(os.path.join(ROOT, folder, n), encoding="utf-8") as f:
                        hits += ["%s:%d" % (n, i) for i, line in enumerate(f, 1) if bad.search(line)]
        self.assertEqual(hits, [])
        out = os.path.join(self.d, "out.json")          # and one of them run: no block asked, so no network
        r = self.cli(os.path.join("tools", "scan_reverted.py"), "1", "0", out, "http://127.0.0.1:1/v2/" + PASSWORD)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        with open(out, "rb") as f:
            data = f.read()
        self.assertEqual(json.loads(data)["summary"]["rpc"], "http://127.0.0.1:1")
        self.none("tool output", r.stdout, r.stderr, data)

    @unittest.skipIf(os.name == "nt", "POSIX: an empty PATH entry is the current folder (on Windows the current folder is "
                     "searched first by shutil.which; nucleo/programs.py is tested there by omega-nucleo-comune's CI)")
    def test_an_openssl_in_the_current_folder_is_not_run(self):
        reg, rep = self.register()
        mark = os.path.join(self.d, "ran")
        fake = self.file("openssl", "#!/bin/sh\ntouch '%s'\nexit 1\n" % mark)
        os.chmod(fake, 0o755)
        path = os.pathsep.join([""] + [p for p in os.environ.get("PATH", "").split(os.pathsep) if os.path.isabs(p)])
        self.cli("apc_registry.py", "record", reg, "--report", rep, "--tsa", "http://127.0.0.1:1/", env={"PATH": path})
        self.assertFalse(os.path.exists(mark), "the openssl of the current folder ran")

    def test_a_bounded_read_asks_for_pieces(self):
        asked = []

        class F(io.BytesIO):
            def read(self, n=-1):
                asked.append(n)
                return super().read(n)
        self.assertEqual(apc_siglib.read_bounded(F(b"x"), 1 << 26), b"x")
        self.assertEqual(apc_siglib.read_bounded(F(b"y" * 10), 4), b"yyyyy")
        self.assertEqual(apc_siglib.read_bounded(F(b"z" * (3 << 20)), 1 << 26), b"z" * (3 << 20))
        self.assertTrue(asked and max(asked) <= apc_siglib.READ_CHUNK and min(asked) > 0, asked)

        class Drip(io.BytesIO):         # a reader that returns less than asked (a pipe, a slow device)
            def read(self, n=-1):
                return super().read(min(n, 1))
        self.assertEqual(apc_siglib.read_bounded(Drip(b"q" * 10), 4), b"qqqqq")
        self.assertEqual(apc_siglib.read_bounded(Drip(b"q" * 4), 4), b"qqqq")

    @unittest.skipUnless(sys.platform.startswith("linux"), "RLIMIT_DATA is enforced by Linux (macOS ignores it; "
                         "Windows has none): the piecewise read is proved on every system by the test above")
    def test_a_one_byte_bundle_under_a_data_limit(self):
        b = self.file("b.json", "{}")
        code = ("import resource,sys;resource.setrlimit(resource.RLIMIT_DATA,(60000*1024,60000*1024));"
                "sys.path.insert(0,%r);import apc_verify as av;print(av.read_bundle_bytes(%r))" % (ROOT, b))
        r = subprocess.run(PY + ["-c", code], capture_output=True, timeout=120)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, b"b'{}'"), r.stderr[-400:])

    def test_integers_past_4300_digits_on_every_python(self):
        import apc_verify as av
        self.assertEqual(av.strict_json("[%s]" % ("9" * 4300)), [int("9" * 4300)])
        self.assertEqual(av.strict_json("[-%s]" % ("9" * 4300)), [-int("9" * 4300)])
        for t in ("[%s]" % ("1" * 4301), "[-%s]" % ("1" * 4301), '{"a": %s}' % ("2" * 100000)):
            with self.assertRaises(av.Refusal) as c:
                av.strict_json(t)
            self.assertEqual(str(c.exception), "not JSON: an integer of more than 4300 digits")
            with self.assertRaises(rg.Bad) as c:
                rg.strict_json(t)
            self.assertEqual(str(c.exception), "not JSON: an integer of more than 4300 digits")

    def test_a_duplicate_name_that_could_be_a_key(self):
        import apc_verify as av
        t = '{"%s": 1, "%s": 2}' % (KEYNAME, KEYNAME)
        for f, err in ((av.strict_json, av.Refusal), (rg.strict_json, rg.Bad)):
            with self.assertRaises(err) as c:
                f(t)
            self.assertEqual(str(c.exception), "duplicate member (a name of 43 characters, not repeated)")
            with self.assertRaises(err) as c:
                f('{"ab": 1, "ab": 2}')
            self.assertEqual(str(c.exception), "duplicate member 'ab'")
        import apc_mcp                      # the MCP server's reader: the same rule (its reply repeated 80 characters)
        with self.assertRaises(apc_mcp.DuplicateMember) as c:
            apc_mcp.parse_line(t)
        self.assertEqual(str(c.exception), "member repeated: (a name of 43 characters, not repeated)")
        with self.assertRaises(apc_mcp.DuplicateMember) as c:
            apc_mcp.parse_line('{"ab": 1, "ab": 2}')
        self.assertEqual(str(c.exception), "member repeated: ab")
        r = self.cli("apc_mcp.py", stdin=(t + "\n").encode())
        self.none("mcp", r.stdout, r.stderr)



class NamesOfTheBundle(unittest.TestCase):
    """SPEC 32.17 (c), 0.21.8: the reasons and notes that name a member of the bundle repeat a name of at most 32
    characters byte for byte and never a longer one (until db14f24: 40 or 64 characters, or whole)."""

    def test_32_repeated_33_not(self):
        import apc_drafts2
        import apc_offer
        import apc_verify as av
        import apc_webauthn
        for n in (1, 32, 33, 40, 64, 65, 300):
            name = "S" * n
            shown = n <= 32
            c = {k: "x" for k in apc_drafts2.CLAIM_REQ}
            c[name] = 1
            texts = [apc_drafts2.claim_checks(c)["DC1"]]
            with self.assertRaises(apc_offer.Open) as e:
                apc_offer._closed({"a": 1, name: 1}, "o.p", ("a",))
            texts.append(str(e.exception))
            with self.assertRaises(rg.Damaged) as e:
                rg._members({"a": 1, name: 1}, "p", ("a",))
            texts.append(str(e.exception))
            _, note = av.payment_required_obj({"a": "x", name: 1}, "p", ("a",))
            texts.append(" ".join(note))
            for t in texts:
                self.assertEqual(name in t, shown, (n, t[:120]))
                if not shown:
                    self.assertIn("(a name of %d characters, not repeated)" % n, t)
            self.assertIn("claim_member_not_in_proposal(%s)" % (name if shown else
                          "(a name of %d characters, not repeated)" % n), texts[0])
        src = open(apc_webauthn.__file__, encoding="utf-8").read()   # its note: the same helper, no slice of a name
        self.assertIn("[apc_siglib.bare_name(k) for k in other[:8]]", src)
        self.assertNotIn("k[:40]", src)

if __name__ == "__main__":
    unittest.main()
