"""SPEC 0.20 (section 31): MP1-MP7, the AP2 mandate as an ap2-evidence-pack 1.7.1 pack.

Needs ap2-evidence-pack v1.7.1 (APC_AP2EV; default: a sibling checkout ../ap2-evidence-pack at tag v1.7.1 for this suite only), the
`cryptography` it needs, and openssl (a local RFC 3161 TSA for MP7). A missing one SKIPS the whole module with the
dependency named and how to get it (SPEC 32.11 (d); until 0.21.1 a RuntimeError, exit 1): a skip is counted and shown,
it never reads as a passed check. Tokens are issued here (ES256, keys made per run) in the forms of the AP2
SDK at e1ea56d (delegate_payload with one array-element disclosure; the closed hop a kb+sd-jwt carrying sd_hash, aud,
nonce, as MandateClient.present writes it); tests/fixtures_mandate holds bundles made with the SDK itself
(tools/gen_mandate_fixtures.py)."""
import base64
import copy
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm_mandate")   # the real corpus is not distributed (SPEC 33): skip with the reason
os.environ.setdefault("APC_AP2EV", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "ap2-evidence-pack"))
import apc_mandate as am  # noqa: E402
import apc_verify as av  # noqa: E402
from lib.secp256k1 import GX, GY, _mul, sign  # noqa: E402

AP2, HASHES, WHY = am._load()
# SPEC 32.11 (d): skipped with the reason, never an error (unittest discover, tests/__init__.py, tools/run_ordered.py);
# SPEC 32.12 (i): with APC_REQUIRE_DEPS=1 (the CI's dependency step) a missing dependency is an error, never a skip
_NOT_RUN = RuntimeError if os.environ.get("APC_REQUIRE_DEPS") == "1" else unittest.SkipTest
if AP2 is None:
    raise _NOT_RUN("the tests of SPEC 31 do not run: ap2-evidence-pack v1.7.1 is not usable from APC_AP2EV=%s "
                   "(%s; hashes %s): %s" % (os.environ.get("APC_AP2EV"), WHY, HASHES, am.cause()))
if shutil.which("openssl") is None:
    raise _NOT_RUN("the tests of SPEC 31 do not run: openssl is absent (the local RFC 3161 TSA of the MP7 tests "
                   "runs it): install openssl")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

PAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
PAYEE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
JPYC = "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29"
MERCHANT = {"id": "merchant-1", "name": "Demo Merchant", "website": "https://merchant.example"}
INSTRUMENT = {"id": "x402-base-usdc", "type": "x402", "description": "USDC on Base"}
NOW = int(time.time())


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class Key:
    def __init__(self):
        self.sk = ec.generate_private_key(ec.SECP256R1())
        n = self.sk.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}

    def jws(self, header, payload):
        si = b64u(json.dumps(header).encode()) + "." + b64u(json.dumps(payload).encode())
        r, s = decode_dss_signature(self.sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        return si + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


USER, AGENT, OTHER = Key(), Key(), Key()


def disc(value):
    return b64u(json.dumps([b64u(os.urandom(12)), value]).encode("utf-8"))


def digest(d):
    return b64u(hashlib.sha256(d.encode("ascii")).digest())


def issue(content, key=USER, top=None, form="delegate"):
    """An SD-JWT in the AP2 SDK's delegate_payload form (or the payload form), final `~`."""
    if form == "delegate":
        d = disc(content)
        payload = dict(top or {}, _sd_alg="sha-256", delegate_payload=[{"...": digest(d)}])
        return key.jws({"alg": "ES256", "typ": "example+sd-jwt"}, payload) + "~" + d + "~"
    return key.jws({"alg": "ES256", "typ": "example+sd-jwt"}, dict(content, **(top or {}))) + "~"


def present(open_token, closed, key=AGENT, mode="sd_hash", aud="credential-provider", nonce="n1"):
    """The closed hop as MandateClient.present writes it, and the chain (the join strips the open hop's final `~`)."""
    d = disc(closed)
    payload = {"_sd_alg": "sha-256", "delegate_payload": [{"...": digest(d)}], "iat": NOW, "aud": aud, "nonce": nonce}
    if mode in ("sd_hash", "both"):
        payload["sd_hash"] = b64u(hashlib.sha256(open_token.encode("ascii")).digest())
    if mode in ("issuer_jwt_hash", "both"):
        payload["issuer_jwt_hash"] = AP2.issuer_jwt_hash(open_token)
    if mode == "sd_hash_wrong":         # the hash of the open hop's issuer JWT where sd_hash is expected, and vice versa
        payload["sd_hash"] = AP2.issuer_jwt_hash(open_token)
    if mode == "issuer_jwt_hash_wrong":
        payload["issuer_jwt_hash"] = b64u(hashlib.sha256(open_token.encode("ascii")).digest())
    hop = key.jws({"alg": "ES256", "typ": "kb+sd-jwt"}, payload) + "~" + d + "~"
    return hop, open_token[:-1] + "~~" + hop


def open_content(constraints, **kw):
    c = {"vct": "mandate.payment.open.1", "constraints": constraints, "cnf": {"jwk": AGENT.jwk}, "iat": NOW,
         "exp": NOW + 3600}
    c.update(kw)
    return c


def closed_content(cents=1250, **kw):
    c = {"vct": "mandate.payment.1", "transaction_id": "checkout-jwt-hash", "payee": MERCHANT,
         "payment_amount": {"amount": cents, "currency": "USD"}, "payment_instrument": INSTRUMENT}
    c.update(kw)
    return c


def restriction(original, constraints, **kw):
    c = open_content(constraints + [{"type": am.RESTRICTS, "issuer_jwt_hash": AP2.issuer_jwt_hash(original)}], **kw)
    return issue(c)


BASE = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 5000},
        {"type": "payment.allowed_payees", "allowed": [MERCHANT]},
        {"type": "payment.allowed_payment_instruments", "allowed": [INSTRUMENT]}]


class LocalTSA:
    def __init__(self, d):
        self.d, self.key, self.crt = d, os.path.join(d, "tsa.key"), os.path.join(d, "tsa.crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", self.key, "-out", self.crt, "-days", "30", "-subj", "/CN=apc-test-tsa",
                        "-addext", "extendedKeyUsage=critical,timeStamping", "-addext", "basicConstraints=critical,CA:FALSE",
                        "-addext", "keyUsage=critical,digitalSignature"], check=True, capture_output=True)
        with open(os.path.join(d, "serial"), "w") as f:
            f.write("01\n")
        self.cnf = os.path.join(d, "tsa.cnf")
        with open(self.cnf, "w") as f:
            f.write("[ tsa ]\ndefault_tsa = t\n[ t ]\nserial = %s\ncrypto_device = builtin\nsigner_cert = %s\nsigner_key = %s\n"
                    "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\nordering = no\ntsa_name = no\n"
                    "ess_cert_id_chain = no\ness_cert_id_alg = sha256\n" % (os.path.join(d, "serial"), self.crt, self.key))

    def stamp(self, digest_hex, tsa_url, timeout=20):
        q, r = os.path.join(self.d, "q.tsq"), os.path.join(self.d, "r.tsr")
        subprocess.run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q], check=True,
                       capture_output=True)
        subprocess.run(["openssl", "ts", "-reply", "-config", self.cnf, "-queryfile", q, "-out", r], check=True,
                       capture_output=True)
        with open(r, "rb") as f:
            return {"anchored": True, "tsa_url": tsa_url, "tsr_b64": base64.b64encode(f.read()).decode()}


def pack(arts, keys, tsa=None):
    d = tempfile.mkdtemp(prefix="apc-mandate-test-")
    try:
        out = os.path.join(d, "p.json")
        if tsa is not None:
            orig = AP2._rfc3161_stamp
            AP2._rfc3161_stamp = lambda dg, url, timeout=20: tsa.stamp(dg, url)
            try:
                AP2.build_evidence([{"name": n, "sd_jwt": t} for n, t in arts], out, keys=keys, tsa_url="https://tsa.test")
            finally:
                AP2._rfc3161_stamp = orig
        else:
            AP2.build_evidence([{"name": n, "sd_jwt": t} for n, t in arts], out, keys=keys)
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def addr(priv):
    x, y = _mul(priv, (GX, GY))
    return "0x" + av.keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()


def payload(chain, value, to=PAYEE, nonce=None, asset=USDC, domain=("USD Coin", "2")):
    au = {"from": addr(PAYER), "to": to, "value": str(value), "validAfter": "0", "validBefore": str(NOW + 3600),
          "nonce": nonce or "0x" + av.keccak256(chain.encode("ascii")).hex()}
    msg = dict(au, value=int(au["value"]), validAfter=0, validBefore=int(au["validBefore"]))
    dg = av.signing_digest({"name": domain[0], "version": domain[1], "chainId": 8453, "verifyingContract": asset},
                           "TransferWithAuthorization", av.TYPES, msg, av.DOMAIN4)
    r, s, rec = sign(dg, PAYER, int.from_bytes(hashlib.sha256(dg + PAYER.to_bytes(32, "big")).digest(), "big") % av.SECP_N)
    return {"x402Version": 2, "accepted": {"scheme": "exact", "network": "eip155:8453", "amount": str(value),
                                           "asset": asset, "payTo": to, "maxTimeoutSeconds": 60,
                                           "extra": {"name": domain[0], "version": domain[1]}},
            "payload": {"signature": "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])).hex(),
                        "authorization": au}}


def scenario(cons=BASE, cents=1250, closed_kw=None, open_kw=None, extra=(), mode="sd_hash", value=None, to=PAYEE,
             nonce=None, closed_key=AGENT, tsa=None, asset=USDC, domain=("USD Coin", "2"), keys_override=None,
             open_drop=()):
    """(bundle, parts) for one AP2 payment chain in a pack."""
    oc = open_content(cons, **(open_kw or {}))
    for k in open_drop:
        oc.pop(k, None)
    o = issue(oc)
    hop, chain = present(o, closed_content(cents, **(closed_kw or {})), key=closed_key, mode=mode)
    arts = [("open_payment", o), ("closed_payment", hop)]
    keys = {"open_payment": USER.jwk, "closed_payment": closed_key.jwk}
    for n, t in extra:
        arts.append((n, t(o) if callable(t) else t))
        keys[n] = USER.jwk
    keys.update(keys_override or {})
    p = pack(arts, keys, tsa)
    doc = {"bundle_version": "apc-0.1",
           "payment_payload": payload(chain, cents * 10000 if value is None else value, to, nonce, asset, domain),
           "mandate": {"profile": am.PROFILE, "pack": p, "chain": chain}}
    return doc, {"open": o, "hop": hop, "chain": chain}


def run(doc):
    try:
        return av.verify_bundle(copy.deepcopy(doc))
    except av.Refusal as e:
        return {"refused": str(e), "checks": {}}


def direct(doc, btime=None, tsa_cert=None):
    pp = av.parse_payload(doc["payment_payload"])
    return am.check(am.parse_member(copy.deepcopy(doc["mandate"])), pp["auth"], pp["accepted"], btime, tsa_cert)


class TestFixturesFromTheSDK(unittest.TestCase):
    def test_manifest(self):
        d = os.path.join(ROOT, "tests", "fixtures_mandate")
        with open(os.path.join(d, "MANIFEST.json")) as fh:
            man = json.load(fh)["cases"]
        self.assertGreaterEqual(len(man), 9)
        for name, m in man.items():
            with open(os.path.join(d, name + ".json"), "rb") as fh:
                raw = fh.read()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), m["sha256"], name)
            r = run(av.strict_json(raw.decode("utf-8")))
            self.assertEqual({k: r["checks"].get(k) for k in m["expect"]}, m["expect"], name)


class TestOutcomes(unittest.TestCase):
    def test_base_and_report(self):
        doc, parts = scenario()
        r = run(doc)
        c = r["checks"]
        self.assertEqual([c[k] for k in am.CHECKS], ["verified", "verified", "verified",
                         "not_evaluated:mandate_names_no_address", "not_evaluated:absent:no_restriction",
                         "not_evaluated:no_block_time", "not_evaluated:absent:no_restriction"])
        self.assertEqual(c["M1"], "not_applicable:mandate_profile_" + am.PROFILE)
        self.assertEqual(c["L2.sig"], "verified")
        self.assertEqual(r["verdict"], "chain_incomplete")
        m = r["mandate"]
        self.assertEqual(m["x402"], {"nonce": "verified", "amount": "verified", "payee": "not_evaluated:mandate_names_no_address"})
        self.assertEqual((m["open"], m["closed"], m["valid"], m["admission"]), ("open_payment", "closed_payment", True, "admitted"))
        self.assertEqual(m["closed_hop"], {"aud": "credential-provider", "nonce": "n1", "iat": NOW})
        self.assertEqual(m["ap2_evidence_sha256"], am.AP2EV_SHA256)
        self.assertTrue(any("self-asserted" in n for n in r["notes"]))

    def test_no_mandate_and_other_profiles_unchanged(self):
        doc, _ = scenario()
        d = copy.deepcopy(doc)
        del d["mandate"]
        r = run(d)
        self.assertEqual(r["checks"]["M1"], "not_evaluated:absent:no_mandate")
        self.assertFalse(any(k in r["checks"] for k in am.CHECKS))
        self.assertNotIn("mandate", r)
        d["mandate"] = {"profile": "something/else", "x": 1}
        r = run(d)
        self.assertEqual(r["checks"]["M1"], "not_evaluated:ap2_has_no_x402_binding")
        self.assertFalse(any(k in r["checks"] for k in am.CHECKS))

    def test_payee_address_in_the_signed_instrument(self):
        inst = dict(INSTRUMENT, payee_address=PAYEE.upper().replace("0X", "0x"))
        doc, _ = scenario(closed_kw={"payment_instrument": inst},
                          cons=[BASE[0], BASE[1], {"type": "payment.allowed_payment_instruments", "allowed": [inst]}])
        r = run(doc)
        self.assertEqual(r["checks"]["MP4"], "verified")
        doc, _ = scenario(closed_kw={"payment_instrument": dict(INSTRUMENT, payee_address="0x" + "22" * 20)})
        self.assertEqual(run(doc)["checks"]["MP4"], "failed:payee_address_not_the_authorization_to")
        for bad in ("0x" + "22" * 19, 5, None, "22" * 20, "0x" + "zz" * 20):
            doc, _ = scenario(closed_kw={"payment_instrument": dict(INSTRUMENT, payee_address=bad)})
            self.assertEqual(run(doc)["checks"]["MP4"], "failed:malformed", bad)

    def test_amount_rules(self):
        doc, _ = scenario(value=12500001)
        self.assertEqual(run(doc)["checks"]["MP4"], "failed:value_not_the_mandate_amount")
        doc, _ = scenario(closed_kw={"payment_amount": {"amount": 1250, "currency": "EUR"}},
                          cons=[{"type": "payment.amount_range", "currency": "EUR", "max": 5000}])
        self.assertEqual(run(doc)["checks"]["MP4"], "failed:currency_not_the_token_currency")
        # EURC: 6 decimals, EUR minor unit 2
        doc, _ = scenario(closed_kw={"payment_amount": {"amount": 1250, "currency": "EUR"}}, asset=EURC,
                          domain=("EURC", "2"), cons=[{"type": "payment.amount_range", "currency": "EUR", "max": 5000}])
        r = run(doc)
        self.assertEqual(r["mandate"]["x402"]["amount"], "verified")
        # an asset outside the table
        doc, _ = scenario(asset="0x" + "ab" * 20)
        self.assertEqual(run(doc)["mandate"]["x402"]["amount"], "not_evaluated:asset_currency_unknown")
        for bad in ({"amount": "1250", "currency": "USD"}, {"amount": 1250}, {"amount": True, "currency": "USD"},
                    {"amount": 1250, "currency": "USD", "x": 1}, [1250]):
            doc, _ = scenario(closed_kw={"payment_amount": bad}, cons=[BASE[1]])
            self.assertEqual(run(doc)["mandate"]["x402"]["amount"], "failed:payment_amount_malformed", bad)

    def test_nonce(self):
        doc, parts = scenario(nonce="0x" + "11" * 32)
        self.assertEqual(run(doc)["checks"]["MP4"], "failed:nonce_not_the_chain_hash")

    def test_mp2_branches(self):
        doc, parts = scenario()
        d = copy.deepcopy(doc)
        d["mandate"]["chain"] = parts["hop"] + "~~" + parts["open"]
        self.assertEqual(run(d)["checks"]["MP2"], "failed:chain_hop_not_in_pack")
        d["mandate"]["chain"] = parts["chain"] + "~~" + parts["hop"]
        self.assertEqual(run(d)["checks"]["MP2"], "failed:chain_not_two_hops")
        d["mandate"]["chain"] = parts["chain"][:-3] + ("A" if parts["chain"][-3] != "A" else "B") + parts["chain"][-2:]
        self.assertEqual(run(d)["checks"]["MP2"], "failed:chain_hop_not_in_pack")
        # the delegate's key is not the closed hop's signer
        doc, _ = scenario(closed_key=OTHER)
        self.assertEqual(run(doc)["checks"]["MP2"], "failed:closed_hop_not_signed_by_the_delegate")
        # binding modes
        for mode, want in (("issuer_jwt_hash", "verified"), ("both", "failed:closed_hop_not_bound_to_the_open_hop"),
                           ("none", "failed:closed_hop_not_bound_to_the_open_hop"),
                           ("sd_hash_wrong", "failed:closed_hop_not_bound_to_the_open_hop"),
                           ("issuer_jwt_hash_wrong", "failed:closed_hop_not_bound_to_the_open_hop")):
            doc, _ = scenario(mode=mode)
            self.assertEqual(run(doc)["checks"]["MP2"], want, mode)
        # vct and cnf of the hops
        doc, _ = scenario(open_kw={"vct": "mandate.checkout.open.1"})
        self.assertEqual(run(doc)["checks"]["MP2"], "failed:open_hop_not_an_open_payment_mandate")
        doc, _ = scenario(open_kw={"cnf": {"jwk": {"kty": "EC", "crv": "P-384", "x": "a", "y": "b"}}})
        self.assertEqual(run(doc)["checks"]["MP2"], "failed:open_hop_without_cnf_jwk")
        doc, _ = scenario(open_kw={"cnf": "x"})
        self.assertEqual(run(doc)["checks"]["MP2"], "failed:open_hop_without_cnf_jwk")
        doc, _ = scenario(closed_kw={"vct": "mandate.payment.open.1"})
        self.assertEqual(run(doc)["checks"]["MP2"], "failed:closed_hop_not_a_payment_mandate")
        # one hop twice in the pack under two names
        o = issue(open_content(BASE))
        hop, chain = present(o, closed_content())
        p = pack([("a", o), ("b", hop), ("c", o)], {"a": USER.jwk, "b": AGENT.jwk, "c": USER.jwk})
        d = {"bundle_version": "apc-0.1", "payment_payload": payload(chain, 12500000),
             "mandate": {"profile": am.PROFILE, "pack": p, "chain": chain}}
        self.assertEqual(run(d)["checks"]["MP2"], "failed:chain_hop_in_pack_twice")

    def test_delegate_key_with_the_same_x(self):
        """The point -P has the x of P and the other y: private key n - d. A closed hop signed by it is not the delegate's."""
        twin = Key()
        n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        d = AGENT.sk.private_numbers().private_value
        twin.sk = ec.derive_private_key(n - d, ec.SECP256R1())
        pn = twin.sk.public_key().public_numbers()
        twin.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(pn.x.to_bytes(32, "big")), "y": b64u(pn.y.to_bytes(32, "big"))}
        self.assertEqual(twin.jwk["x"], AGENT.jwk["x"])
        self.assertNotEqual(twin.jwk["y"], AGENT.jwk["y"])
        doc, _ = scenario(closed_key=twin)
        self.assertEqual(run(doc)["checks"]["MP2"], "failed:closed_hop_not_signed_by_the_delegate")

    def test_budget_max_readings_major_and_minor(self):
        # SPEC 31.3, amendment 2026-11-01: AP2's schema types budget `max` as `number`; a pack cannot carry a fraction,
        # so this is read on Mandate Contents given directly (case found against the kaldrix-x402-guard vectors)
        def mp3(c):
            return am.eval_terms(open_content([c]), closed_content(), AP2, [], None, None)[0]
        # amendment c (2026-11-01): readings MAJOR (x 10^e, ISO 4217) and MINOR (the integer itself), each only when a
        # whole number of minor units; a verdict only where they agree. C pays 1250 USD cents
        X, N, A, U = ("failed:amount_exceeds_budget", "not_evaluated:budget_needs_past_spend",
                      "not_evaluated:budget_unit_ambiguous", "not_evaluated:budget_unit")
        for mx, want in ((0.29, X), (1.15, X), (10.0, X), (12.49, X), (12.5, N), (13.5, N), (1e300, N), (12.495, U),
                         (12, X), (13, A), (1249, A), (1250, N), (2000, N), (0, X), (-1, X)):
            self.assertEqual(mp3({"type": "payment.budget", "currency": "USD", "max": mx}), want, mx)
        def mp3c(c, amount, cur):
            return am.eval_terms(open_content([c]), closed_content(payment_amount={"amount": amount, "currency": cur}),
                                 AP2, [], None, None)[0]
        for mx, want in ((1250, N), (1249, X), (1250.0, N), (12.5, U), (13, X)):    # JPY: both readings are one
            self.assertEqual(mp3c({"type": "payment.budget", "currency": "JPY", "max": mx}, 1250, "JPY"), want, mx)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "USD", "max": 12.5}, 1251, "USD"), X)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "USD", "max": 10.0}, 10, "USD"), N)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "USD", "max": 10.0}, 11, "USD"), A)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "EUR", "max": 12.5}, 1250, "EUR"),
                         "not_evaluated:budget_needs_past_spend")
        # ISO 4217 List One (2026-09-17): GBP 2 (an integer budget a pack carries keeps its failed), KWD 3, XAU "N.A."
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "GBP", "max": 12}, 1250, "GBP"), X)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "GBP", "max": 13}, 1250, "GBP"), A)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "KWD", "max": 1.25}, 1250, "KWD"), N)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "KWD", "max": 1.249}, 1250, "KWD"), X)
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "XAU", "max": 13}, 1250, "XAU"),
                         "not_evaluated:budget_currency_exponent_unknown")
        # order (AP2 pull request #391): the negative amount before the currency, the range and the exponent
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "EUR", "max": 13}, -5, "USD"),
                         "failed:payment_amount_negative")
        self.assertEqual(mp3c({"type": "payment.amount_range", "currency": "EUR", "max": 9000}, -5, "USD"),
                         "failed:payment_amount_negative")
        self.assertEqual(mp3c({"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 9000}, -5, "USD"),
                         "failed:payment_amount_negative")
        self.assertEqual(mp3c({"type": "payment.budget", "currency": "XAU", "max": 13}, -5, "XAU"),
                         "failed:payment_amount_negative")
        for c in ({"type": "payment.budget", "currency": "USD", "max": 13},
                  {"type": "payment.amount_range", "currency": "USD", "max": 9000}):     # AP2 pull request #391
            self.assertEqual(mp3c(c, -5, "USD"), "failed:payment_amount_negative", c["type"])
            self.assertNotEqual(mp3c(c, 0, "USD"), "failed:payment_amount_negative", c["type"])
        self.assertEqual(mp3({"type": "payment.budget", "currency": "EUR", "max": 0.29}), "failed:currency_differs")
        self.assertEqual(mp3({"type": "payment.budget", "currency": "USD", "max": 0.29, "x": 1}),
                         "not_evaluated:constraint_unknown_member")
        for bad in (float("nan"), float("inf"), float("-inf"), "13", True, None, [13]):
            self.assertEqual(mp3({"type": "payment.budget", "currency": "USD", "max": bad}), "failed:constraint_malformed",
                             repr(bad))
        self.assertEqual(mp3({"type": "payment.budget", "currency": 5, "max": 0.29}), "failed:constraint_malformed")
        self.assertEqual(mp3({"type": "payment.amount_range", "currency": "USD", "max": 9000.5}), "failed:constraint_malformed")
        # Independent review 2 (2026-11-01): an absent max is ("malformed", "max") for _constraint_shape too (316caba: KeyError, verdict
        # "error", exit 3, on a pack ap2-evidence-pack builds); "min" is not a budget member; zero, negative and subnormal
        # floats are read like any float; a float subclass or a Decimal is not a JSON number as json.loads reads it
        def safe(f, *a):
            try:
                return f(*a)
            except Exception as e:  # noqa: BLE001 — a crash must read as a wrong outcome, not as an error of the test
                return "EXC %s" % type(e).__name__
        self.assertEqual(safe(mp3, {"type": "payment.budget", "currency": "USD"}), "failed:constraint_malformed")
        # an integer max of any size is exact (Python integers; a 1000-digit Decimal context trapped above it)
        for mx, want in ((10 ** 1001, N), (-(10 ** 1001), X), (2 ** 3400, N)):
            self.assertEqual(safe(mp3, {"type": "payment.budget", "currency": "USD", "max": mx}), want)
            self.assertEqual(safe(mp3c, {"type": "payment.budget", "currency": "JPY", "max": mx}, 1250, "JPY"), want)
        # ISO4217_EXPONENT is List One of 2026-09-17 (165 codes) exactly: its canonical JSON's SHA-256
        self.assertEqual(hashlib.sha256(json.dumps(am.ISO4217_EXPONENT, sort_keys=True).encode()).hexdigest(),
                         "61bc680199e554e0da3030a20877f6ad5e27f2429d3785fae504a0edb3fd0a8c")
        self.assertEqual(mp3({"type": "payment.budget", "currency": "USD", "max": 0.29, "min": 0}),
                         "not_evaluated:constraint_unknown_member")
        for mx, want in ((-0.0, "failed:amount_exceeds_budget"), (0.0, "failed:amount_exceeds_budget"),
                         (-0.29, "failed:amount_exceeds_budget"), (5e-324, "not_evaluated:budget_unit")):
            self.assertEqual(mp3({"type": "payment.budget", "currency": "USD", "max": mx}), want, mx)
        import decimal
        for odd in (type("F", (float,), {})(0.29), decimal.Decimal("0.29")):
            self.assertEqual(mp3({"type": "payment.budget", "currency": "USD", "max": odd}), "failed:constraint_malformed",
                             repr(odd))
        doc, _ = scenario(cons=BASE + [{"type": "payment.budget", "currency": "USD"}])     # a pack carries it: no float
        self.assertEqual(safe(lambda: run(doc)["checks"]["MP3"]), "failed:constraint_malformed")

    def test_mp3_each_type(self):
        cases = [
            ([{"type": "payment.amount_range", "currency": "USD", "max": 1249}], "failed:amount_out_of_range"),
            ([{"type": "payment.amount_range", "currency": "USD", "max": 1250}], "verified"),
            ([{"type": "payment.amount_range", "currency": "USD", "min": 1251, "max": 9000}], "failed:amount_out_of_range"),
            ([{"type": "payment.amount_range", "currency": "USD", "min": 1250, "max": 9000}], "verified"),
            ([{"type": "payment.amount_range", "currency": "EUR", "max": 9000}], "failed:currency_differs"),
            ([{"type": "payment.allowed_payees", "allowed": [{"id": "x", "name": "N"}]}], "failed:payee_not_allowed"),
            ([{"type": "payment.allowed_payees", "allowed": [{"id": "merchant-1", "name": "Renamed"}]}], "verified"),
            ([{"type": "payment.allowed_payment_instruments", "allowed": [{"id": "other", "type": "x402"}]}],
             "failed:instrument_not_allowed"),
            ([{"type": "payment.allowed_pisps", "allowed": [{"legal_name": "L", "brand_name": "B", "domain_name": "d"}]}],
             "failed:pisp_missing"),
            ([{"type": "payment.execution_date", "not_before": "2026-01-01", "not_after": "2026-01-02"}],
             "not_evaluated:no_execution_date_no_block_time"),
            ([{"type": "payment.execution_date"}], "verified"),
            ([{"type": "payment.budget", "currency": "USD", "max": 12}], "failed:amount_exceeds_budget"),
            ([{"type": "payment.budget", "currency": "USD", "max": 13}], "not_evaluated:budget_unit_ambiguous"),
            ([{"type": "payment.budget", "currency": "USD", "max": 1250}], "not_evaluated:budget_needs_past_spend"),
            ([{"type": "payment.budget", "currency": "EUR", "max": 13}], "failed:currency_differs"),
            ([{"type": "payment.agent_recurrence", "frequency": "MONTHLY"}],
             "failed:recurrence_without_amount_range_or_budget"),
            ([{"type": "payment.agent_recurrence", "frequency": "MONTHLY"},
              {"type": "payment.amount_range", "currency": "USD", "max": 9000},
              {"type": "payment.budget", "currency": "USD", "max": 900}], "not_evaluated:recurrence_needs_past_uses"),
            ([{"type": "payment.reference", "conditional_transaction_id": "nope"}], "not_evaluated:open_checkout_not_in_pack"),
            ([{"type": "x.unknown", "a": 1}], "not_evaluated:unknown_constraint"),
            ([{"type": "checkout.allowed_merchants", "allowed": [MERCHANT]}], "not_evaluated:unknown_constraint"),
            ([{"type": "payment.amount_range", "currency": "USD"}], "failed:constraint_malformed"),
            ([{"type": "payment.amount_range", "currency": "USD", "max": "9000"}], "failed:constraint_malformed"),
            ([{"type": "payment.amount_range", "currency": "USD", "max": 9000, "maximum": 1}],
             "not_evaluated:constraint_unknown_member"),     # review 2026-10-31: not a wrong type nor a missing key
            ([5], "failed:constraint_malformed"),
        ]
        for cons, want in cases:
            doc, _ = scenario(cons=cons)
            self.assertEqual(run(doc)["checks"]["MP3"], want, cons)
        doc, _ = scenario(cons="x")
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:open_mandate_schema:constraints")
        # a failure wins over an earlier not_evaluated
        doc, _ = scenario(cons=[{"type": "x.unknown"}, {"type": "payment.amount_range", "currency": "USD", "max": 1}])
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:amount_out_of_range")

    def test_mp3_pisp_and_dates(self):
        pisp = {"legal_name": "L", "brand_name": "B", "domain_name": "d.example"}
        cons = [{"type": "payment.allowed_pisps", "allowed": [pisp]}]
        doc, _ = scenario(cons=cons, closed_kw={"pisp": pisp})
        self.assertEqual(run(doc)["checks"]["MP3"], "verified")
        doc, _ = scenario(cons=cons, closed_kw={"pisp": dict(pisp, brand_name="X")})
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:pisp_not_allowed")
        win = {"type": "payment.execution_date", "not_before": "2026-10-01", "not_after": "2026-10-31"}
        for d, want in (("2026-10-01", "verified"), ("2026-10-31", "verified"), ("2026-09-30", "failed:execution_date_outside"),
                        ("2026-11-01", "failed:execution_date_outside"), ("2026-10-15T00:00:00Z", "not_evaluated:date_form"),
                        ("2026-02-30", "not_evaluated:date_form"), ("2026-10-1", "not_evaluated:date_form")):
            doc, _ = scenario(cons=[win], closed_kw={"execution_date": d})
            self.assertEqual(run(doc)["checks"]["MP3"], want, d)
        # without execution_date, the block time in the constraint's form
        doc, _ = scenario(cons=[win])
        t_in = calendar_t("2026-10-23T12:00:00Z")
        self.assertEqual(direct(doc, btime=t_in)[0]["MP3"], "verified")
        self.assertEqual(direct(doc, btime=t_in + 30 * 86400)[0]["MP3"], "failed:execution_date_outside")
        dt = {"type": "payment.execution_date", "not_after": "2026-10-23T12:00:00Z"}
        doc, _ = scenario(cons=[dt])
        self.assertEqual(direct(doc, btime=calendar_t("2026-10-23T12:00:00Z"))[0]["MP3"], "verified")
        self.assertEqual(direct(doc, btime=calendar_t("2026-10-23T12:00:01Z"))[0]["MP3"], "failed:execution_date_outside")

    def test_ap2_schemas(self):
        """SPEC 31.3a (found 2026-10-31 by a probe of 40 000 damaged pairs: the SDK refused, MP3 said verified)."""
        for kw, want in ((dict(transaction_id=5), "failed:closed_mandate_schema:transaction_id"),
                         (dict(payee={"id": "merchant-1"}), "failed:closed_mandate_schema:payee"),
                         (dict(payee={"name": "Demo Merchant", "website": "https://merchant.example"}),
                          "failed:closed_mandate_schema:payee"),
                         (dict(payment_instrument={"id": "x402-base-usdc"}), "failed:closed_mandate_schema:payment_instrument"),
                         (dict(execution_date=20261031), "failed:closed_mandate_schema:execution_date"),
                         (dict(risk_data=[]), "failed:closed_mandate_schema:risk_data"),
                         (dict(pisp={"legal_name": "L"}), "failed:closed_mandate_schema:pisp"),
                         (dict(payment_amount={"amount": True, "currency": "USD"}),
                          "failed:closed_mandate_schema:payment_amount"),             # a boolean is not an integer
                         (dict(iat=True), "failed:closed_mandate_schema:iat"),
                         (dict(payee=dict(MERCHANT, extra=1)), "verified")):     # a member outside the schema: left alone
            doc, _ = scenario(cons=[BASE[0]], closed_kw=kw)
            self.assertEqual(run(doc)["checks"]["MP3"], want, kw)
        doc, _ = scenario(cons=[BASE[0]], open_kw={"payment_amount": {"amount": "1250", "currency": "USD"}})
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:open_mandate_schema:payment_amount")
        r = am.evaluate_mp3({"constraints": [], "cnf": {}}, closed_content(), AP2, [], None, None)
        self.assertEqual(r[0], "failed:open_mandate_schema:vct")
        r = am.evaluate_mp3(open_content([]), dict(closed_content(), vct="mandate.payment.2"), AP2, [], None, None)
        self.assertEqual(r[0], "failed:closed_mandate_schema:vct")
        for bad in ([{"id": "m"}], [{"name": "n"}], [{"id": 1, "name": "n"}], [5]):
            doc, _ = scenario(cons=[{"type": "payment.allowed_payees", "allowed": [MERCHANT] + bad}])
            self.assertEqual(run(doc)["checks"]["MP3"], "failed:constraint_malformed", bad)
        doc, _ = scenario(cons=[{"type": "payment.allowed_payment_instruments", "allowed": [INSTRUMENT, {"id": "z"}]}])
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:constraint_malformed")
        doc, _ = scenario(cons=[{"type": "payment.allowed_pisps", "allowed": [{"legal_name": "L", "brand_name": "B"}]}],
                          closed_kw={"pisp": {"legal_name": "L", "brand_name": "B", "domain_name": "d"}})
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:constraint_malformed")

    def test_preset_values(self):
        doc, _ = scenario(open_kw={"payment_amount": {"amount": 1250, "currency": "USD"}, "payee": MERCHANT})
        self.assertEqual(run(doc)["checks"]["MP3"], "verified")
        doc, _ = scenario(open_kw={"payment_amount": {"amount": 1000, "currency": "USD"}})
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:preset_changed:payment_amount")
        doc, _ = scenario(open_kw={"payee": dict(MERCHANT, name="Other name, same id")})
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:preset_changed:payee")     # RFC 8785 equality, declared
        doc, _ = scenario(open_kw={"risk_data": {"a": 1}})
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:preset_changed:risk_data")

    def test_reference_with_the_open_checkout_in_the_pack(self):
        chk = issue({"vct": "mandate.checkout.open.1", "constraints": [], "cnf": {"jwk": AGENT.jwk}})
        ref = b64u(hashlib.sha256(chk.encode("ascii")).digest())
        doc, _ = scenario(cons=BASE + [{"type": "payment.reference", "conditional_transaction_id": ref}],
                          extra=[("open_checkout", chk)])
        self.assertEqual(run(doc)["checks"]["MP3"], "verified")
        bad = ref[:-1] + ("E" if ref.endswith("A") else "A")    # ref ends in "A" one run in 16: never equal to ref
        doc, _ = scenario(cons=BASE + [{"type": "payment.reference", "conditional_transaction_id": bad}],
                          extra=[("open_checkout", chk)])
        self.assertEqual(run(doc)["checks"]["MP3"], "not_evaluated:open_checkout_not_in_pack")

    def test_mp5_restrictions(self):
        narrow = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 2000}] + BASE[1:]
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, narrow))])
        r = run(doc)
        self.assertEqual(r["checks"]["MP5"], "verified")
        self.assertEqual(r["checks"]["MP7"], "verified")       # within R: the time of R changes nothing
        self.assertNotIn("existed_before_payment", r["mandate"]["restrictions"][0])
        tight = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 1000}] + BASE[1:]
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, tight))])
        r = run(doc)
        self.assertEqual(r["checks"]["MP5"], "failed:payment_outside_restriction")
        self.assertEqual(r["checks"]["MP7"], "not_evaluated:no_time_anchor")
        self.assertEqual(r["mandate"]["restrictions"][0]["state"], "verified")
        # a record broader than the original is not verified by ap2-evidence-pack: MP5 not_evaluated, never applied
        broad = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 9000}] + BASE[1:]
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, broad))])
        r = run(doc)
        self.assertEqual(r["checks"]["MP5"], "not_evaluated:restriction_contradicted")
        self.assertEqual(r["checks"]["MP7"], "not_evaluated:no_verified_restriction")
        # a record of another artifact is not applied
        other = issue(open_content(BASE))
        doc, _ = scenario(extra=[("x", other), ("r", restriction(other, tight))])
        r = run(doc)
        self.assertEqual(r["checks"]["MP5"], "not_evaluated:absent:no_restriction")
        # two records: one within, one outside -> failed; one within, one contradicted -> not_evaluated
        doc, _ = scenario(extra=[("r1", lambda o: restriction(o, narrow)), ("r2", lambda o: restriction(o, tight))])
        self.assertEqual(run(doc)["checks"]["MP5"], "failed:payment_outside_restriction")
        doc, _ = scenario(extra=[("r1", lambda o: restriction(o, narrow)), ("r2", lambda o: restriction(o, broad))])
        self.assertEqual(run(doc)["checks"]["MP5"], "not_evaluated:restriction_contradicted")

    def test_restriction_reference_uses_its_own_sd_alg(self):
        chk = issue({"vct": "mandate.checkout.open.1", "constraints": [], "cnf": {"jwk": AGENT.jwk}})
        ref = {"type": "payment.reference", "conditional_transaction_id": b64u(hashlib.sha256(chk.encode("ascii")).digest())}
        narrow = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 2000}] + BASE[1:] + [ref]

        def rec(o, alg):
            c = open_content(narrow + [{"type": am.RESTRICTS, "issuer_jwt_hash": AP2.issuer_jwt_hash(o)}])
            d = disc(c)
            return USER.jws({"alg": "ES256", "typ": "example+sd-jwt"},
                            {"_sd_alg": alg, "delegate_payload": [{"...": digest(d)}]}) + "~" + d + "~"
        doc, _ = scenario(cons=BASE + [ref], extra=[("open_checkout", chk), ("r", lambda o: rec(o, "sha-256"))])
        r = run(doc)
        self.assertEqual((r["checks"]["MP3"], r["checks"]["MP5"]), ("verified", "verified"))
        res = am.eval_terms(open_content(narrow), closed_content(), AP2, [], "sha-512", None)
        self.assertEqual(res[0], "not_evaluated:sd_alg_not_sha256")

    def test_o1_a_time_limit_without_block_time_blocks_the_verdict(self):
        """review observation O1 (31/10): apc-0.1, payee_address signed, a mandate that expired long ago: the verdict must not be
        chain_verified; without any time limit MP6 is verified."""
        inst = dict(INSTRUMENT, payee_address=PAYEE)
        cons = [BASE[0], BASE[1], {"type": "payment.allowed_payment_instruments", "allowed": [inst]}]
        doc, _ = scenario(cons=cons, closed_kw={"payment_instrument": inst}, open_kw={"exp": 946684800})
        r = run(doc)
        self.assertEqual(r["checks"]["MP6"], "not_evaluated:no_block_time")
        self.assertIn("MP6", r["not_evaluated"])
        self.assertNotEqual(r["verdict"], "chain_verified")
        doc, _ = scenario(cons=cons, closed_kw={"payment_instrument": inst}, open_drop=("exp",))
        r = run(doc)
        self.assertEqual(r["checks"]["MP6"], "verified")
        self.assertEqual([r["checks"][k] for k in ("MP1", "MP2", "MP3", "MP4")], ["verified"] * 4)
        win = {"type": "payment.execution_date", "not_after": "2000-01-01"}
        doc, _ = scenario(cons=cons + [win], closed_kw={"payment_instrument": inst}, open_drop=("exp",))
        r = run(doc)
        self.assertEqual(r["checks"]["MP3"], "not_evaluated:no_execution_date_no_block_time")
        self.assertNotEqual(r["verdict"], "chain_verified")

    def test_mp6_times(self):
        doc, _ = scenario()
        self.assertEqual(direct(doc, btime=NOW)[0]["MP6"], "verified")
        self.assertEqual(direct(doc, btime=NOW + 3600)[0]["MP6"], "verified")
        self.assertEqual(direct(doc, btime=NOW + 3601)[0]["MP6"], "failed:paid_after_mandate_expiry")
        doc, _ = scenario(open_kw={"nbf": NOW + 10})
        self.assertEqual(direct(doc, btime=NOW + 9)[0]["MP6"], "failed:paid_before_mandate_validity")
        self.assertEqual(direct(doc, btime=NOW + 10)[0]["MP6"], "verified")
        doc, _ = scenario(open_kw={"exp": "soon"})
        self.assertEqual(direct(doc, btime=NOW)[0]["MP6"], "failed:malformed")
        doc, _ = scenario(open_kw={"exp": True})
        self.assertEqual(direct(doc, btime=NOW)[0]["MP6"], "failed:malformed")
        doc, _ = scenario(open_kw={"exp": NOW + 100})
        self.assertEqual(direct(doc, btime=NOW + 101)[0]["MP6"], "failed:paid_after_mandate_expiry")

    def test_mp7_existence_is_not_knowledge(self):
        d = tempfile.mkdtemp(prefix="apc-tsa-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        tsa = LocalTSA(d)
        now = int(time.time())      # the TSA's genTime is the real clock, not NOW (the suite may run long)
        tight = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 1000}] + BASE[1:]
        narrow = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 2000}] + BASE[1:]
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, tight))], tsa=tsa)
        res, notes, rep = direct(doc, btime=now + 7200, tsa_cert=tsa.crt)
        self.assertEqual(rep["time_anchor"]["state"], "verified")
        self.assertEqual(res["MP5"], "failed:payment_outside_restriction")
        self.assertEqual(res["MP7"], "failed:paid_outside_restriction_that_existed_before")
        self.assertTrue(rep["restrictions"][0]["existed_before_payment"])
        self.assertTrue(any("not shown to have been received or known" in n for n in notes))
        # paid before the anchor's time: R not shown to exist before the payment
        res, notes, rep = direct(doc, btime=now - 7200, tsa_cert=tsa.crt)
        self.assertEqual(res["MP7"], "verified")
        self.assertFalse(rep["restrictions"][0]["existed_before_payment"])
        self.assertTrue(any("is not shown to exist before the payment" in n for n in notes))
        self.assertFalse(any("not shown to have been received or known" in n for n in notes))
        # without the TSA certificate the anchor is not verified
        res, _, _ = direct(doc, btime=now + 7200)
        self.assertEqual(res["MP7"], "not_evaluated:no_time_anchor")
        # no block time
        res, _, _ = direct(doc, btime=None, tsa_cert=tsa.crt)
        self.assertEqual(res["MP7"], "not_evaluated:absent:no_block_time")
        # within the restriction that existed before: verified
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, narrow))], tsa=tsa)
        res, _, rep = direct(doc, btime=now + 7200, tsa_cert=tsa.crt)
        self.assertEqual((res["MP5"], res["MP7"]), ("verified", "verified"))
        self.assertTrue(rep["restrictions"][0]["existed_before_payment"])
        # through the CLI flag
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(doc, fh)
        self.addCleanup(os.unlink, fh.name)
        out = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), fh.name, "--ap2-tsa-cert", tsa.crt],
                             capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
        self.assertEqual(json.loads(out.stdout)["mandate"]["time_anchor"]["state"], "verified")
        out = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), fh.name, "--ap2-tsa-cert"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 64)


class TestSyntheticBlock(unittest.TestCase):
    """SPEC 31.8: MP6 and MP7 on a header B1 verifies (tools/synth_mandate_block.py; a block on no chain)."""

    def test_four_cases_and_the_header_altered(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import synth_mandate_block as sb
        d = tempfile.mkdtemp(prefix="apc-synth-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        tsa = LocalTSA(d)
        av.AP2_TSA_CERT[0] = tsa.crt
        self.addCleanup(av.AP2_TSA_CERT.__setitem__, 0, None)
        now = int(time.time())      # the TSA stamps with the real clock: block times relative to it, not to NOW
        want = {"within_after": (now + 600, 2000, "verified", "verified", "verified", True),
                "outside_after": (now + 600, 1000, "failed:payment_outside_restriction", "verified",
                                  "failed:paid_outside_restriction_that_existed_before", True),
                "outside_before": (now - 600, 1000, "failed:payment_outside_restriction", "verified", "verified", False),
                "expired": (now + 600, 2000, "verified", "failed:paid_after_mandate_expiry", "verified", True)}
        for label, (bt, mx, mp5, mp6, mp7, before) in want.items():
            with open(sb.make(d, bt, mx, tsa, label, exp=bt - 100 if label == "expired" else None)) as fh:
                doc = av.strict_json(fh.read())
            r = run(doc)
            c = r["checks"]
            self.assertEqual([c[k] for k in ("B1", "B2", "B3", "B4", "L2.sig", "C1", "C2")], ["verified"] * 7, label)
            self.assertTrue(r["block_bound"], label)
            self.assertEqual((c["MP5"], c["MP6"], c["MP7"]), (mp5, mp6, mp7), label)
            self.assertEqual(r["mandate"]["restrictions"][0]["existed_before_payment"], before, label)
            if label == "outside_after":            # positive control: the header altered, B1 fails, no block time
                e = copy.deepcopy(doc)
                h = e["inclusion"]["block_header"]
                h["timestamp"] = hex(int(h["timestamp"], 16) - 7200)
                c = run(e)["checks"]
                self.assertEqual((c["B1"], c["MP7"]), ("failed:header_hash_mismatch", "not_evaluated:absent:no_block_time"))


class TestSolana(unittest.TestCase):
    """SPEC 31.9: apc-0.5 with the mandate member; real bundles from the payment of 2026-10-31 (Solana mainnet, signature
    4F6f2zy7…gxLWWX, throwaway mint, Memo = SHA-256 of the chain), and the binding rules on direct calls."""

    def test_real_payment(self):
        for f in ("s1_seller_no_memo.json", "s2_seller_memo_is_the_hash.json"):
            with open(os.path.join(ROOT, "bundles", "real_svm_mandate", f)) as fh:
                r = run(av.strict_json(fh.read()))
            c = r["checks"]
            self.assertEqual([c[k] for k in ("S1", "S2", "S3", "S4", "S5")], ["verified"] * 5, f)
            self.assertEqual([c[k] for k in am.CHECKS], ["verified", "verified", "verified",
                             "not_evaluated:asset_currency_unknown", "verified", "not_evaluated:no_block_time",
                             "verified"], f)
            self.assertEqual(r["mandate"]["x402"]["nonce"], "verified", f)
            self.assertEqual(r["verdict"], "chain_incomplete", f)

    def test_member_refused_outside_the_profile(self):
        with open(os.path.join(ROOT, "bundles", "real_svm_mandate", "s1_seller_no_memo.json")) as fh:
            d = av.strict_json(fh.read())
        for mut in (lambda m: m.update(profile="pulse-ap2-x402/0.3"), lambda m: m.update(x=1), lambda m: m.pop("pack")):
            e = copy.deepcopy(d)
            mut(e["mandate"])
            self.assertIn("refused", run(e))

    def test_binding_rules(self):
        doc, parts = scenario()
        want = hashlib.sha256(parts["chain"].encode("ascii")).hexdigest()
        acc = {"network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}
        pay = "7HrgiXR4dXkU9Bri9s2uFn9sHTK48KQ3PQaktdQeR82k"

        def mp4(memos, seller=None, amount=12500000, inst=None, doc=doc):
            res, _, rep = am.check(am.parse_member(copy.deepcopy(doc["mandate"])), None, acc, None, None,
                                   svm={"memos": memos, "seller_memo": seller, "amount": amount, "pay_to": pay})
            return rep["x402"]
        self.assertEqual(mp4([want.encode()])["nonce"], "verified")
        self.assertEqual(mp4([want.encode()])["amount"], "verified")          # USDC, 6 decimals, 1250 cents
        self.assertEqual(mp4([want.encode()], amount=12500001)["amount"], "failed:value_not_the_mandate_amount")
        self.assertEqual(mp4([])["nonce"], "failed:memo_count_0")
        self.assertEqual(mp4([want.encode(), b"x"])["nonce"], "failed:memo_count_2")
        self.assertEqual(mp4([want.upper().encode()])["nonce"], "failed:memo_not_the_chain_hash")
        self.assertEqual(mp4([b"invoice-42"], seller="invoice-42")["nonce"], "not_evaluated:seller_memo")
        self.assertEqual(mp4([want.encode()], seller=want)["nonce"], "verified")
        for pa, outcome in ((pay, "verified"), ("9" * 32, "failed:payee_address_not_the_authorization_to"),
                            ("0x" + "11" * 20, "failed:malformed"), ("O0Il" * 9, "failed:malformed")):
            d2, _ = scenario(closed_kw={"payment_instrument": dict(INSTRUMENT, payee_address=pa)})
            p2 = d2["mandate"]["chain"]
            w2 = hashlib.sha256(p2.encode("ascii")).hexdigest()
            self.assertEqual(mp4([w2.encode()], doc=d2)["payee"], outcome, pa)


class TestTimeAnchorState(unittest.TestCase):
    def test_existed_by_without_a_verified_anchor_state(self):
        """§11.2 of ap2-evidence-pack: existed_by can be set while time_anchor is not verified (another anchor of the
        pack failed). MP7 needs the state verified, not merely existed_by."""
        tight = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 1000}] + BASE[1:]
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, tight))])
        real = AP2.verify_restrictions

        def fake(path, tsa_cert=None):
            r = real(path, tsa_cert)
            r["time_anchor"] = {"state": "failed", "reasons": []}
            r["existed_by"] = "20000101000000Z"
            return r
        AP2.verify_restrictions = fake
        try:
            res, _, _ = direct(doc, btime=NOW)
        finally:
            AP2.verify_restrictions = real
        self.assertEqual(res["MP5"], "failed:payment_outside_restriction")
        self.assertEqual(res["MP7"], "not_evaluated:no_time_anchor")

    def test_gentime(self):
        self.assertEqual(am._gentime("20261031075823Z"), calendar_t("2026-10-31T07:58:23Z"))
        self.assertEqual(am._gentime("20261031075823.25Z"), calendar_t("2026-10-31T07:58:23Z") + 0.25)
        for bad in ("2026-10-31T07:58:23Z", "20261031075823", "20261331075823Z", "20261031075823.Z", None, 5):
            self.assertIsNone(am._gentime(bad), bad)


def calendar_t(s):
    import calendar
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


class TestPackAndLoader(unittest.TestCase):
    def test_pack_not_valid(self):
        doc, _ = scenario()
        d = copy.deepcopy(doc)
        d["mandate"]["pack"]["artifacts"][0]["resolved_claims"]["x"] = 1
        r = run(d)
        self.assertEqual(r["checks"]["MP1"], "failed:ap2_pack_not_valid")
        self.assertEqual({r["checks"][k] for k in am.CHECKS[1:]}, {"not_evaluated:ap2_pack_not_valid"})
        self.assertEqual(r["verdict"], "chain_failed")
        d = copy.deepcopy(doc)
        d["mandate"]["pack"] = {}
        self.assertEqual(run(d)["checks"]["MP1"], "failed:ap2_pack_not_valid")

    def test_loader_refuses_another_version(self):
        # SPEC 32.11 (a): with the variable unset the sibling ../ap2-evidence-pack is read at the hashes; the test patches
        # the sibling (never the machine's), and the variable always wins over it
        saved, saved_sib, pack = list(am._AP2EV), getattr(am, "AP2EV_SIBLING", None), os.environ["APC_AP2EV"]
        other = tempfile.mkdtemp(prefix="apc-other-pack-")
        os.mkdir(os.path.join(other, "pqcrypto"))
        for rel in ("ap2_evidence.py", os.path.join("pqcrypto", "sigsuite.py")):
            with open(os.path.join(other, rel), "w") as fh:
                fh.write("# not tag v1.7.1\n")
        try:
            for env, sib, want in ((None, other, "not_evaluated:ap2_evidence_pack_not_1.7.1"),
                                   (None, "/nonexistent-sibling", "not_evaluated:ap2_evidence_pack_unavailable"),
                                   (os.environ.get("APC_AP2EV_170", "/nonexistent"), pack, "not_evaluated:ap2_evidence_pack_not_1.7.1"),
                                   ("/nonexistent", pack, "not_evaluated:ap2_evidence_pack_not_1.7.1")):
                am._AP2EV.clear()
                am.AP2EV_SIBLING = sib
                old = os.environ.pop("APC_AP2EV", None)
                if env:
                    os.environ["APC_AP2EV"] = env
                try:
                    doc, _ = scenario()
                    r = run(doc)
                    self.assertEqual({r["checks"][k] for k in am.CHECKS}, {want}, (env, sib))
                    self.assertEqual(r["verdict"], "chain_incomplete")
                    self.assertIn("tag v1.7.1", am.cause())          # 32.11 (b): the note says how to get the pack
                finally:
                    os.environ["APC_AP2EV"] = old
        finally:
            shutil.rmtree(other, ignore_errors=True)
            am.AP2EV_SIBLING = saved_sib
            am._AP2EV[:] = saved

    def test_sibling_default_loads_the_pack(self):
        # SPEC 32.11 (a), review F1: APC_AP2EV unset and the pack beside the verifier: MP1 verified, as with the variable
        saved, saved_sib, pack = list(am._AP2EV), getattr(am, "AP2EV_SIBLING", None), os.environ.pop("APC_AP2EV")
        try:
            am._AP2EV.clear()
            am.AP2EV_SIBLING = pack
            doc, _ = scenario()
            r = run(doc)
            self.assertEqual(r["checks"]["MP1"], "verified", r.get("notes"))
            self.assertIsNone(am.cause())
        finally:
            os.environ["APC_AP2EV"] = pack
            am.AP2EV_SIBLING = saved_sib
            am._AP2EV[:] = saved

    def test_pack_equals_its_own_verifier(self):
        """Generative: a key added at every path of the pack, values changed at every leaf: MP1 is what
        ap2-evidence-pack's own verify_evidence says of the same pack, and nothing raises."""
        doc, _ = scenario()
        rnd = random.Random(20261031)

        def paths(node, p=()):
            yield p, node
            if isinstance(node, dict):
                for k, v in node.items():
                    yield from paths(v, p + (k,))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    yield from paths(v, p + (i,))
        allp = list(paths(doc["mandate"]["pack"]))
        n = 0
        for p, node in allp:
            variants = []
            if isinstance(node, dict):
                variants += [("add", k) for k in ("x", "", "__proto__", "Name", "valid ")]
            variants.append(("set", rnd.choice([None, 0, -1, 1.5, "", "x", [], {}, True])))
            for kind, v in variants:
                d = copy.deepcopy(doc)
                tgt = d["mandate"]["pack"]
                for k in p[:-1]:
                    tgt = tgt[k]
                if kind == "add":
                    (tgt[p[-1]] if p else tgt)[v] = 1
                elif p:
                    tgt[p[-1]] = v
                else:
                    continue
                if not isinstance(d["mandate"]["pack"], dict):
                    continue
                r = run(d)
                if "refused" in r:
                    self.fail("refused on %s %s: %s" % (kind, p, r["refused"]))
                own = own_verdict(d["mandate"]["pack"])
                self.assertEqual(r["checks"]["MP1"] == "verified", own, (kind, p, v))
                n += 1
        self.assertGreater(n, 200)


def own_verdict(p):
    d = tempfile.mkdtemp()
    try:
        f = os.path.join(d, "p.json")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(p, ensure_ascii=False, separators=(",", ":")))
        r = AP2.verify_evidence(f)
        return r.get("admission") == "admitted" and r.get("valid") is True
    finally:
        shutil.rmtree(d, ignore_errors=True)


class TestMemberGrammar(unittest.TestCase):
    def test_closed_member(self):
        doc, _ = scenario()
        for mut in (lambda m: m.update(x=1), lambda m: m.pop("pack"), lambda m: m.pop("chain"),
                    lambda m: m.update(pack=[]), lambda m: m.update(pack=None), lambda m: m.update(pack="{}"),
                    lambda m: m.update(chain=5), lambda m: m.update(chain=""), lambda m: m.update(chain=None),
                    lambda m: m.update(chain=m["chain"] + "é"), lambda m: m.update(chain="a" * (am.MAX_CHAIN + 1)),
                    lambda m: m.update(profile="ap2-evidence-pack/1.7.1 "), lambda m: m.update(Profile=am.PROFILE)):
            d = copy.deepcopy(doc)
            mut(d["mandate"])
            r = run(d)
            if d["mandate"].get("profile") == am.PROFILE:
                self.assertIn("refused", r, d["mandate"].keys())
                self.assertTrue(r["refused"].startswith("mandate"), r["refused"])
            else:
                self.assertEqual(r["checks"]["M1"], "not_evaluated:ap2_has_no_x402_binding")
        d = copy.deepcopy(doc)
        d["mandate"]["chain"] = "a" * am.MAX_CHAIN
        self.assertEqual(run(d)["checks"]["MP2"], "failed:chain_not_two_hops")

    def test_duplicate_keys_refused_by_the_parser(self):
        doc, _ = scenario()
        text = json.dumps(doc)
        bad = text.replace('"chain": ', '"chain": "x", "chain": ', 1)
        with self.assertRaises(av.Refusal):
            av.strict_json(bad)


class TestAdversarialReview(unittest.TestCase):
    """Adversarial review of 2026-10-31 (a second reviewer): each test failed on 77ce314 (positive control in the reviewer's report, not distributed)."""

    def test_restricts_type_in_the_open_hop_is_an_unknown_constraint(self):
        # SPEC 31.3: a type outside the list is not_evaluated:unknown_constraint; only R's own reference is left out
        doc, _ = scenario(cons=BASE + [{"type": am.RESTRICTS, "issuer_jwt_hash": "x"}])
        r = run(doc)
        self.assertEqual(r["checks"]["MP3"], "not_evaluated:unknown_constraint")
        self.assertIn(["constraints[3]", "not_evaluated:unknown_constraint"], r["mandate"]["constraints"])

    def test_mp7_not_verified_when_mp5_on_r_is_not_evaluated(self):
        # SPEC 31.7: C neither shown within R nor outside it -> MP7 cannot say verified
        d = tempfile.mkdtemp(prefix="apc-tsa-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        tsa = LocalTSA(d)
        for extra in ({"type": "payment.budget", "currency": "USD", "max": 20},
                      {"type": "payment.future_thing", "x": 1}):
            doc, _ = scenario(extra=[("r", lambda o: restriction(o, BASE + [extra]))], tsa=tsa)
            res, _, rep = direct(doc, btime=int(time.time()) + 7200, tsa_cert=tsa.crt)   # the TSA's clock, not NOW
            self.assertTrue(res["MP5"].startswith("not_evaluated:"), res["MP5"])
            self.assertEqual(res["MP7"], "not_evaluated:payment_within_restriction_not_shown", extra)
            self.assertTrue(rep["restrictions"][0]["existed_before_payment"])

    def test_unknown_member_of_a_known_constraint_is_not_failed(self):
        # SPEC 31.3: malformed = required keys and JSON types; the SDK (pydantic, extra ignored) evaluates it
        doc, _ = scenario(cons=[dict(BASE[0], note="x")] + BASE[1:])
        self.assertEqual(run(doc)["checks"]["MP3"], "not_evaluated:constraint_unknown_member")
        doc, _ = scenario(cons=[dict(BASE[0], max="5000")] + BASE[1:])          # a wrong type stays failed
        self.assertEqual(run(doc)["checks"]["MP3"], "failed:constraint_malformed")

    def test_pisp_match_needs_the_three_names(self):
        # types/pisp.json (SDK Pisp): legal_name, brand_name, domain_name required strings; absent == absent is no match
        for allowed, pisp in (([{}], {}), ([{"domain_name": "a.example"}], {"domain_name": "a.example"})):
            doc, _ = scenario(cons=BASE + [{"type": "payment.allowed_pisps", "allowed": allowed}], closed_kw={"pisp": pisp})
            # since 31.3a the schema stops it first (the closed pisp without the three names), never verified
            self.assertEqual(run(doc)["checks"]["MP3"], "failed:closed_mandate_schema:pisp", allowed)
        full = {"domain_name": "a.example", "legal_name": "A Ltd", "brand_name": "A"}
        doc, _ = scenario(cons=BASE + [{"type": "payment.allowed_pisps", "allowed": [full]}], closed_kw={"pisp": full})
        self.assertEqual(run(doc)["checks"]["MP3"], "verified")


class TestIndependentReview(unittest.TestCase):
    """Independent review of 2026-10-31: each test failed on 3df1e7d or killed a mutant that survived test_mandate there."""

    def test_open_hop_without_disclosures(self):
        # an SD-JWT with no disclosure ("h.p.s~"): the join strips the `~`, the pack holds it; failed on 3df1e7d
        o = issue(open_content(BASE), form="payload")
        hop, chain = present(o, closed_content())
        self.assertTrue(o.endswith("~") and o.count("~") == 1 and "~" not in chain.split("~~")[0])
        p = pack([("open_payment", o), ("closed_payment", hop)], {"open_payment": USER.jwk, "closed_payment": AGENT.jwk})
        doc = {"bundle_version": "apc-0.1", "payment_payload": payload(chain, 12500000),
               "mandate": {"profile": am.PROFILE, "pack": p, "chain": chain}}
        c = run(doc)["checks"]
        self.assertEqual((c["MP1"], c["MP2"], c["MP3"]), ("verified", "verified", "verified"))
        d = copy.deepcopy(doc)                      # the hop still has to be in the pack
        d["mandate"]["chain"] = chain.split("~~")[0] + "x~~" + hop
        d["payment_payload"] = payload(d["mandate"]["chain"], 12500000)
        c = run(d)["checks"]
        self.assertEqual(c["MP2"], "failed:chain_hop_not_in_pack")
        self.assertEqual({c[k] for k in am.CHECKS[2:]}, {"not_evaluated:chain_not_verified"})

    def test_open_hop_with_a_key_binding_jwt(self):
        # the segment as written (its last part a compact JWT, the SDK's rule: no `~` restored); mutant MD76
        o = issue(open_content(BASE))
        kb = AGENT.jws({"alg": "ES256", "typ": "kb+jwt"},
                       {"iat": NOW, "aud": "x", "nonce": "n", "sd_hash": b64u(hashlib.sha256(o.encode("ascii")).digest())})
        hop, _ = present(o + kb, closed_content())
        chain = o + kb + "~~" + hop
        p = pack([("open_payment", o + kb), ("closed_payment", hop)], {"open_payment": USER.jwk, "closed_payment": AGENT.jwk})
        doc = {"bundle_version": "apc-0.1", "payment_payload": payload(chain, 12500000),
               "mandate": {"profile": am.PROFILE, "pack": p, "chain": chain}}
        c = run(doc)["checks"]
        self.assertEqual((c["MP1"], c["MP2"], c["MP3"]), ("verified", "verified", "verified"))

    def test_pack_written_unescaped(self):
        # SPEC 31: the pack is written with ensure_ascii=False, never longer than it was read; at ap2-evidence-pack's
        # size limit an escaped copy (mutant N11) would be refused
        merch = dict(MERCHANT, name="Caf\u00e9 \u2615\u2615 \U0001f600")
        doc, _ = scenario(closed_kw={"payee": merch}, open_kw={"payee": merch})
        n = len(json.dumps(doc["mandate"]["pack"], ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        saved = AP2.MAX_EVIDENCE_BYTES
        AP2.MAX_EVIDENCE_BYTES = n
        try:
            c = run(doc)["checks"]
        finally:
            AP2.MAX_EVIDENCE_BYTES = saved
        self.assertEqual((c["MP1"], c["MP3"]), ("verified", "verified"))

    def test_loader_refuses_a_cached_module_from_elsewhere(self):
        # SPEC 31 (Implementation): only the ap2_evidence.py of APC_AP2EV; a module of that name already imported from
        # another place must not be taken (mutant N01: the realpath guard removed)
        import types
        saved_cache, saved_mod = list(am._AP2EV), sys.modules.get("ap2_evidence")
        fake = types.ModuleType("ap2_evidence")
        fake.__file__ = os.path.join(tempfile.gettempdir(), "elsewhere", "ap2_evidence.py")
        try:
            am._AP2EV.clear()
            sys.modules["ap2_evidence"] = fake
            mod, _, why = am._load()
            self.assertIsNone(mod)
            self.assertEqual(why, "not_evaluated:ap2_evidence_pack_unavailable")
        finally:
            am._AP2EV[:] = saved_cache
            if saved_mod is None:
                sys.modules.pop("ap2_evidence", None)
            else:
                sys.modules["ap2_evidence"] = saved_mod

    def test_verified_anchor_with_existed_by_of_another_shape(self):
        # SPEC 31.7: an existed_by of another shape is not_evaluated:no_time_anchor even with time_anchor verified
        # (mutant N09: the shape not checked -> None < int, an internal error)
        tight = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": 1000}] + BASE[1:]
        doc, _ = scenario(extra=[("r", lambda o: restriction(o, tight))])
        real = AP2.verify_restrictions

        def fake(path, tsa_cert=None):
            r = real(path, tsa_cert)
            r["time_anchor"] = {"state": "verified", "reasons": []}
            r["existed_by"] = "2026-10-31T00:00:00Z"
            return r
        AP2.verify_restrictions = fake
        try:
            res, _, rep = direct(doc, btime=NOW)
        finally:
            AP2.verify_restrictions = real
        self.assertEqual((res["MP5"], res["MP7"]), ("failed:payment_outside_restriction", "not_evaluated:no_time_anchor"))
        self.assertNotIn("existed_before_payment", rep["restrictions"][0])

    def test_check_not_run_is_not_evaluated(self):
        # a check ap2-evidence-pack could not run (its exit 74, e.g. a TSA certificate path that is a FIFO): every MP
        # check not_evaluated:ap2_evidence_pack_check_not_run (mutant N12: the exception not caught)
        doc, _ = scenario()
        real = AP2.verify_restrictions

        def fake(path, tsa_cert=None):
            raise AP2.Ap2WriteError("check not run here")
        AP2.verify_restrictions = fake
        try:
            r = run(doc)
        finally:
            AP2.verify_restrictions = real
        self.assertEqual({r["checks"][k] for k in am.CHECKS}, {"not_evaluated:ap2_evidence_pack_check_not_run"})
        self.assertEqual(r["verdict"], "chain_incomplete")

    def test_recurrence_needs_both_amount_range_and_budget(self):
        # SPEC 31.3, the SDK's check_payment_constraints: either one missing is a violation (mutant N14: `or`)
        rec = {"type": "payment.agent_recurrence", "frequency": "MONTHLY"}
        bud = {"type": "payment.budget", "currency": "USD", "max": 2000}     # both readings (200000, 2000) above 1250
        for cons, want in ((BASE + [rec], "failed:recurrence_without_amount_range_or_budget"),
                           (BASE[1:] + [bud, rec], "failed:recurrence_without_amount_range_or_budget"),
                           (BASE + [bud, rec], "not_evaluated:budget_needs_past_spend")):
            out, items = am.eval_terms(open_content(cons), closed_content(), AP2, [], None, None)
            self.assertEqual(out, want, cons)
        self.assertIn(["constraints[4]", "not_evaluated:recurrence_needs_past_uses"],
                      [list(x) for x in am.eval_terms(open_content(BASE + [bud, rec]), closed_content(), AP2, [], None,
                                                      None)[1]])

    def test_cli_ap2_tsa_cert_value(self):
        # the flag's value: missing, empty, or another option is usage (64), never a path (mutant N15)
        f = os.path.join(ROOT, "tests", "fixtures_mandate", "base.json")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        for args in (["--ap2-tsa-cert"], ["--ap2-tsa-cert", ""], ["--ap2-tsa-cert", "--json"], ["--ap2-tsa-cert", "-"]):
            p = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), f] + args, capture_output=True,
                               env=env, timeout=120)
            self.assertEqual(p.returncode, 64, args)
        p = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), f, "--ap2-tsa-cert", f], capture_output=True,
                           env=env, timeout=120)                    # positive control: a value is taken as a path
        self.assertEqual(p.returncode, 2, p.stdout[-300:])


if __name__ == "__main__":
    unittest.main()
