"""SPEC 0.17 (section 28.3, 28.5): Coinbase Smart Wallet passkey owners (apc_webauthn.py, L2.sig-1271).

Real data: oracle/passkey_20261026 (Base, read-only RPC, 2026-10-26): one EIP-3009 transfer of USDC signed by a
passkey owner (bundles/real_v02_passkey/b001) and 10 ERC-4337 operations that EntryPoint v0.6 executed with a passkey
signature (WebAuthn-layer oracles). Positive control: apc_verify 0.16.0 (6b2049d) does not verify the real bundle.
Generative cases re-sign the real bundle's WebAuthn assertion with a test P-256 key (owner reply replaced) to vary
clientDataJSON, authenticatorData, the indexes, s and the ABI form; Wycheproof's P-256 file runs through the ECDSA
step (p256_check)."""
import copy
import glob
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v02_passkey", "real_v02_wallet", oracle=("passkey_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_ap2  # noqa: E402
import apc_verify as av  # noqa: E402
import apc_webauthn as wa  # noqa: E402
import make_webauthn_oracle as mo  # noqa: E402

OLD = "6b2049d"
OR = os.path.join(ROOT, "oracle", "passkey_20261026")
REAL = os.path.join(ROOT, "bundles", "real_v02_passkey", "b001_indirect_envelope_reconstructed.json")
N, P = apc_ap2.P256_N, apc_ap2.P256_P
D_TEST = 0x1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201007    # a test key, not a wallet's


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Refusal as e:
        return {"verdict": "refused", "error": str(e)}


def p256_pub(d):
    j = apc_ap2._jmul(d, apc_ap2.P256_G)
    zi = pow(j[2], -1, P)
    return j[0] * zi * zi % P, j[1] * zi * zi * zi % P


def p256_sign(d, msg, k=None, low_s=True):
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    k = k or int.from_bytes(hashlib.sha256(b"k" + d.to_bytes(32, "big") + msg).digest(), "big") % (N - 1) + 1
    x = apc_ap2._affine_x(apc_ap2._jmul(k, apc_ap2.P256_G))
    r = x % N
    s = pow(k, -1, N) * (e + r * d) % N
    if low_s and s > N // 2:
        s = N - s
    return r, s


def w(v):
    return v.to_bytes(32, "big")


def tail(b):
    return w(len(b)) + b + bytes(-len(b) % 32)


def enc_auth(ad, cdj, ci, ti, r, s):
    """abi.encode(WebAuthnAuth) in the canonical form."""
    t1 = tail(ad)
    return w(32) + w(0xc0) + w(0xc0 + len(t1)) + w(ci) + w(ti) + w(r) + w(s) + t1 + tail(cdj)


def enc_wrapper(idx, data):
    return w(32) + w(idx) + w(64) + tail(data)


def parts(d):
    """(ownerIndex, signatureData) of the bundle's SignatureWrapper."""
    sig = bytes.fromhex(d["payment_payload"]["payload"]["signature"][2:])
    return mo.wrapper(sig)


def challenge_of(d):
    """replaySafeHash of the bundle's EIP-3009 digest, recomputed here from the bundle (CoinbaseSmartWallet ERC1271.sol)."""
    pp = d["payment_payload"]
    au, acc = pp["payload"]["authorization"], pp["accepted"]
    cid = int(acc["network"].split(":")[1])
    msg = {"from": au["from"].lower(), "to": au["to"].lower(), "value": int(au["value"]),
           "validAfter": int(au["validAfter"]), "validBefore": int(au["validBefore"]), "nonce": au["nonce"].lower()}
    dg = av.signing_digest({"name": acc["extra"]["name"], "version": acc["extra"]["version"], "chainId": cid,
                            "verifyingContract": acc["asset"].lower()}, "TransferWithAuthorization", av.TYPES, msg,
                           av.DOMAIN4)
    k = av.keccak256
    dom = k(k(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
            + k(b"Coinbase Smart Wallet") + k(b"1") + w(cid) + bytes(12) + bytes.fromhex(msg["from"][2:]))
    return k(b"\x19\x01" + dom + k(k(b"CoinbaseSmartWalletMessage(bytes32 hash)") + dg))


def resigned(cdj=None, ad=None, ci=None, ti=None, s_fn=None, key=D_TEST, sign_with=None, raw=None):
    """The real bundle with the owner replaced by `key`'s public key and a WebAuthn assertion built from the given
    parts; defaults: the real assertion's authenticatorData and the real clientDataJSON."""
    d = load(REAL)
    idx, data = parts(d)
    real = wa.decode_auth(data)
    ad = real["authenticatorData"] if ad is None else ad
    cdj = real["clientDataJSON"] if cdj is None else cdj
    ci = real["challengeIndex"] if ci is None else ci
    ti = real["typeIndex"] if ti is None else ti
    r, s = p256_sign(sign_with or key, ad + hashlib.sha256(cdj).digest())
    if s_fn:
        s = s_fn(s)
    x, y = p256_pub(key)
    d["payer_wallet"]["owner"]["result"] = "0x" + (w(32) + w(64) + w(x) + w(y)).hex()
    body = raw if raw is not None else enc_auth(ad, cdj, ci, ti, r, s)
    d["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, body).hex()
    return d


def cdj_with(ch, before=b'{"type":"webauthn.get","challenge":"', after=b'","origin":"https://keys.coinbase.com"}'):
    """(clientDataJSON, challengeIndex, typeIndex) with the challenge of ch."""
    c = before + wa.b64url(ch) + after
    return c, c.index(b'"challenge":"'), c.index(b'"type":"webauthn.get"')


class RealData(unittest.TestCase):
    def test_real_eip3009_passkey_payment_verifies(self):
        r = run(load(REAL))
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"]),
                         ("chain_verified", "verified (ERC-1271 CoinbaseSmartWallet, passkey)"))
        self.assertIn("WebAuthn origin 'https://keys.coinbase.com' (declared by the client; not checked by the contract, "
                      "WebAuthn.sol 77)", r["notes"])
        d = load(REAL)
        impl = d["payer_wallet"]["implementation"]["result"]
        self.assertEqual(impl[-40:], "00000110dcdedc9581cb5ecb8467282f2926534d")
        own = bytes.fromhex(d["payer_wallet"]["owner"]["result"][2:])
        self.assertEqual(int.from_bytes(own[32:64], "big"), 64)

    def test_real_assertion_altered_fails(self):
        d0 = load(REAL)
        idx, data = parts(d0)
        a = wa.decode_auth(data)
        cases = {"s_above_half_order": dict(a, s=N - a["s"]), "p256_signature_invalid": dict(a, r=a["r"] ^ 1),
                 "type_not_webauthn_get": dict(a, typeIndex=a["typeIndex"] + 1),
                 "challenge_not_at_index": dict(a, challengeIndex=a["challengeIndex"] + 1),
                 "user_present_flag_not_set": dict(a, authenticatorData=a["authenticatorData"][:32] + bytes(
                     [a["authenticatorData"][32] & 0xfe]) + a["authenticatorData"][33:])}
        for why, b in cases.items():
            d = copy.deepcopy(d0)
            d["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, enc_auth(
                b["authenticatorData"], b["clientDataJSON"], b["challengeIndex"], b["typeIndex"], b["r"], b["s"])).hex()
            r = run(d)
            self.assertEqual((r["verdict"], r["checks"]["L2.sig"]), ("chain_failed", "failed:webauthn_" + why), why)
        d = copy.deepcopy(d0)        # another amount: another digest, so another challenge
        d["payment_payload"]["payload"]["authorization"]["value"] = "15000001"
        d["payment_payload"]["accepted"]["amount"] = "15000001"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:webauthn_challenge_not_at_index")

    def test_positive_control_016_does_not_verify_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(["git", "-C", ROOT, "archive", OLD, "--", "*.py"], capture_output=True)
            if r.returncode != 0 or not r.stdout:
                raise unittest.SkipTest("needs the git history of ROOT")
            subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)
            out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), REAL],
                                 capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
        rep = json.loads(out.stdout)
        self.assertEqual((out.returncode, rep["checks"]["L2.sig"]), (2, "not_evaluated:wallet_implementation_not_known"))

    def test_user_operations_oracle(self):
        with open(os.path.join(OR, "webauthn_userops_53111319_300.json")) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["summary"]["entries"], 10)
        impls = {}
        for e in doc["entries"]:
            hit = doc["transactions"][e["tx_hash"]]
            op = mo.user_ops(bytes.fromhex(hit["tx"]["result"]["input"][2:]))[e["op_index"]]
            self.assertEqual("0x" + mo.user_op_hash(op, 8453).hex(), e["user_op_hash"])
            self.assertIn(e["user_op_hash"], [lg["topics"][1] for lg in hit["logs"]])
            idx, data = mo.wrapper(op["signature"])
            self.assertEqual(idx, e["owner_index"])
            auth = wa.decode_auth(data)
            own = bytes.fromhex(e["owner"]["result"][2:])
            self.assertEqual(int.from_bytes(own[32:64], "big"), 64)
            x, y = int.from_bytes(own[64:96], "big"), int.from_bytes(own[96:128], "big")
            ch = mo.challenge_of(op, 8453)
            self.assertIsNone(wa.verify(ch, auth, x, y), e["tx_hash"])
            self.assertEqual(av.keccak256(bytes.fromhex(e["code"]["result"][2:])).hex(), next(iter(av.WALLET_PROXY_CODE)))
            impl = "0x" + e["implementation"]["result"][-40:]
            self.assertIn(impl, av.WALLET_IMPL)
            impls[impl] = impls.get(impl, 0) + 1
            self.assertEqual(wa.verify(ch, dict(auth, s=auth["s"] ^ 2), x, y), "p256_signature_invalid")
            self.assertNotEqual(wa.verify(av.keccak256(ch), auth, x, y), None)
        self.assertEqual(impls, {"0x00000110dcdedc9581cb5ecb8467282f2926534d": 9,
                                 "0x000100abaad02f1cfc8bbe32bd5a564817339e72": 1})


class Generative(unittest.TestCase):
    CH = None

    @classmethod
    def setUpClass(cls):
        cls.CH = challenge_of(load(REAL))

    def check(self, d, want, note=None):
        r = run(d)
        self.assertEqual(r["checks"]["L2.sig"] if "checks" in r else r["verdict"], want, r.get("error"))
        if want.startswith("verified"):
            self.assertEqual(r["verdict"], "chain_verified")
        else:
            self.assertNotEqual(r["verdict"], "chain_verified")
        if note:
            self.assertTrue(any(note in n for n in r["notes"]), r["notes"])
        return r

    def test_resigned_baseline_and_other_key(self):
        self.check(resigned(), "verified (ERC-1271 CoinbaseSmartWallet, passkey)")
        self.check(resigned(sign_with=D_TEST + 1), "failed:webauthn_p256_signature_invalid")

    def test_client_data_json_forms_the_contract_accepts(self):
        """Member order, extra members, escapes, a JSON `type` other than webauthn.get with the substring elsewhere,
        duplicate members, text that is not JSON: the contract compares two substrings; the verdict follows it and the
        rest is noted."""
        ch = wa.b64url(self.CH)
        get, chal = b'"type":"webauthn.get"', b'"challenge":"' + ch
        ok = "verified (ERC-1271 CoinbaseSmartWallet, passkey)"
        forms = [
            (b'{"challenge":"' + ch + b'","type":"webauthn.get","origin":"x"}', ok, None),
            (b'{"type":"webauthn.get","challenge":"' + ch + b'","origin":"https://a.b","crossOrigin":true,"topOrigin":"t"}',
             ok, "crossOrigin true or carries topOrigin"),
            (b'{"type":"webauthn.get","challenge":"' + ch + b'","origin":"\\u0068ttps://a","other_keys_can_be_added_'
             b'here":"do not compare clientDataJSON against a template"}', ok, "other members"),
            (b'{"type":"webauthn.create","x":"' + get + b'","challenge":"' + ch + b'"}', ok, "not one JSON object"),
            (b'{"type":"webauthn.create","y":{' + get + b'},"challenge":"' + ch + b'"}', ok,
             "member `type` read as JSON is 'webauthn.create'"),
            (b'{"type":"webauthn.get","type":"webauthn.get","challenge":"' + ch + b'"}', ok, "not one JSON object"),
            (b'not json ' + get + b' "challenge":"' + ch + b'"', ok, "not one JSON object"),
            (b'{"type":"webauthn.get","challenge":"' + ch + b'","challenge":"x"}', ok, "not one JSON object"),
        ]
        for cdj, want, note in forms:
            self.check(resigned(cdj=cdj, ci=cdj.index(chal), ti=cdj.index(get)), want, note)
        # the escaped form \"type\":\"webauthn.get\" is not the substring: refused
        cdj = b'{"type":"webauthn.create","s":"\\"type\\":\\"webauthn.get\\"","challenge":"' + ch + b'"}'
        self.assertNotIn(get, cdj)
        self.check(resigned(cdj=cdj, ci=cdj.index(chal), ti=cdj.index(b'"type"')), "failed:webauthn_type_not_webauthn_get")
        cdj = b'{"type" : "webauthn.get","challenge":"' + ch + b'"}'           # a space: not the 21 bytes
        self.check(resigned(cdj=cdj, ci=cdj.index(chal), ti=1), "failed:webauthn_type_not_webauthn_get")

    def test_challenge_encodings(self):
        ch = self.CH
        for bad in (wa.b64url(ch) + b"=", hashlib.sha256(ch).digest().hex().encode(),
                    __import__("base64").b64encode(ch).rstrip(b"="), wa.b64url(ch)[:-1]):
            if bad == wa.b64url(ch):
                continue
            cdj = b'{"type":"webauthn.get","challenge":"' + bad + b'"}'
            self.check(resigned(cdj=cdj, ci=cdj.index(b'"challenge"'), ti=1), "failed:webauthn_challenge_not_at_index")

    def test_indexes(self):
        c, ci, ti = cdj_with(self.CH)
        for ci2, ti2, want in ((ci, ti, "verified (ERC-1271 CoinbaseSmartWallet, passkey)"),
                               (ci + 1, ti, "failed:webauthn_challenge_not_at_index"),
                               (ci, ti + 1, "failed:webauthn_type_not_webauthn_get"),
                               (ci, 2 ** 256 - 1, "failed:webauthn_type_not_webauthn_get"),
                               (ci, 2 ** 256 - 21, "failed:webauthn_type_not_webauthn_get"),
                               (2 ** 256 - 1, ti, "failed:webauthn_challenge_not_at_index"),
                               (len(c), ti, "failed:webauthn_challenge_not_at_index")):
            self.check(resigned(cdj=c, ci=ci2, ti=ti2), want)

    def test_authenticator_data_and_flags(self):
        base = load(REAL)
        ad = wa.decode_auth(parts(base)[1])["authenticatorData"]
        for flags, want, note in ((0x05, "verified (ERC-1271 CoinbaseSmartWallet, passkey)", None),
                                  (0x01, "verified (ERC-1271 CoinbaseSmartWallet, passkey)", "user-verified flag not set"),
                                  (0x04, "failed:webauthn_user_present_flag_not_set", None),
                                  (0x00, "failed:webauthn_user_present_flag_not_set", None)):
            self.check(resigned(ad=ad[:32] + bytes([flags]) + ad[33:]), want, note)
        self.check(resigned(ad=ad[:32]), "failed:webauthn_authenticator_data_shorter_than_33")
        self.check(resigned(ad=b""), "failed:webauthn_authenticator_data_shorter_than_33")
        self.check(resigned(ad=ad + b"\x00" * 40), "verified (ERC-1271 CoinbaseSmartWallet, passkey)")

    def test_s_and_owner_key(self):
        self.check(resigned(s_fn=lambda s: N - s), "failed:webauthn_s_above_half_order")
        # the contract's order: s first (WebAuthn.sol 110), before the type (117)
        self.check(resigned(s_fn=lambda s: N - s, ti=0), "failed:webauthn_s_above_half_order")
        self.check(resigned(s_fn=lambda s: 0), "failed:webauthn_r_or_s_out_of_range")
        d = resigned()
        own = bytes.fromhex(d["payer_wallet"]["owner"]["result"][2:])
        for x, y in ((int.from_bytes(own[64:96], "big") ^ 1, int.from_bytes(own[96:], "big")), (0, 0),
                     (int.from_bytes(own[64:96], "big") + P, int.from_bytes(own[96:], "big"))):
            if x >= 2 ** 256:
                continue
            e = copy.deepcopy(d)
            e["payer_wallet"]["owner"]["result"] = "0x" + (own[:64] + w(x) + w(y)).hex()
            self.check(e, "failed:webauthn_owner_key_not_on_p256")

    def test_non_canonical_abi_forms_are_not_evaluated(self):
        d = load(REAL)
        idx, data = parts(d)
        h = data[32:]
        n1 = int.from_bytes(h[0xc0:0xe0], "big")
        end1 = 0xc0 + 32 + (n1 + 31) // 32 * 32
        variants = [data + bytes(32),                                                # bytes after the encoding
                    w(64) + bytes(32) + h,                                           # outer offset not 0x20
                    w(33) + h,                                                       # only the outer word changed
                    data[:32] + w(0xc1) + h[32:],                                    # only the first offset
                    data[:64] + w(int.from_bytes(h[32:64], "big") + 32) + h[64:end1] + bytes(32) + h[end1:],
                    data[:32] + w(0xe0) + h[32:0xc0] + bytes(32) + h[0xc0:],         # gap before the first tail
                    data[:32 + end1 - 1] + b"\x01" + data[32 + end1:],               # padding byte not zero
                    data[:-32],                                                      # truncated
                    data[:64],
                    b""]
        for v in variants:
            e = copy.deepcopy(d)
            e["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, v).hex()
            r = run(e)
            self.assertTrue(r["checks"]["L2.sig"].startswith("not_evaluated:webauthn_auth_not_canonical_abi"),
                            r["checks"]["L2.sig"])
            self.assertEqual(r["verdict"], "chain_incomplete")

    def test_random_bytes_never_crash(self):
        rnd = random.Random(2717)
        d = load(REAL)
        idx, data = parts(d)
        seen = set()
        for i in range(300):
            v = bytearray(data)
            for _ in range(rnd.randrange(1, 4)):
                v[rnd.randrange(len(v))] = rnd.randrange(256)
            if rnd.random() < 0.2:
                v = v[:rnd.randrange(len(v))]
            e = copy.deepcopy(d)
            e["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, bytes(v)).hex()
            r = run(e)
            if bytes(v) == data:
                continue
            self.assertNotEqual(r["verdict"], "chain_verified", i)
            seen.add(r["checks"]["L2.sig"].split("(")[0])
        self.assertGreater(len(seen), 3, seen)

    def test_owner_shapes_and_grammar(self):
        d = load(REAL)
        own = bytes.fromhex(d["payer_wallet"]["owner"]["result"][2:])
        e = copy.deepcopy(d)
        e["payer_wallet"]["owner"]["result"] = "0x" + (own[:32] + w(65) + own[64:] + b"\x01" + bytes(31)).hex()
        self.assertEqual(run(e)["checks"]["L2.sig"], "failed:owner_not_an_address")
        for k in ("zz", "webauthn"):
            e = copy.deepcopy(d)
            e["payer_wallet"][k] = {}
            self.assertEqual(run(e)["verdict"], "refused")


class HostileClientDataJSON(unittest.TestCase):
    """SPEC 28.3 and 29.1 (0.18.1): clientDataJSON, read only for the notes, is read as the bundle's own JSON is. On the
    merge of 0.17 and 0.18 before this rule (json.loads in apc_webauthn.notes) a text nested 100000 deep made the
    verdict `error` (exit 3) and one nested 65 deep, or holding NaN, was read as a JSON object."""
    OK = "verified (ERC-1271 CoinbaseSmartWallet, passkey)"
    NOT = "clientDataJSON is not one JSON object with unique members"

    def cdj(self, val):
        c = b'{"type":"webauthn.get","challenge":"' + wa.b64url(challenge_of(load(REAL))) + b'","x":' + val + b"}"
        return resigned(cdj=c, ci=c.index(b'"challenge"'), ti=1)

    def notes_of(self, r):
        return [n for n in r["notes"] if "clientDataJSON" in n]

    def test_depth_at_and_past_the_bound(self):
        r = run(self.cdj(b"[" * 63 + b"]" * 63))                 # 64 deep with the outer object: read
        self.assertEqual(r["checks"]["L2.sig"], self.OK)
        self.assertEqual(self.notes_of(r), ["clientDataJSON other members ['x'] (not read by the contract)"])
        r = run(self.cdj(b"[" * 64 + b"]" * 64))                 # 65 deep: not read as JSON, verdict unchanged
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"]), ("chain_verified", self.OK))
        self.assertTrue(self.notes_of(r)[0].startswith(self.NOT), r["notes"])

    def test_past_the_parser_is_a_note_not_an_error(self):
        deep = b"[" * 100000 + b"]" * 100000
        r = run(self.cdj(deep))
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"]), ("chain_verified", self.OK))
        self.assertTrue(self.notes_of(r)[0].startswith(self.NOT), r["notes"])
        with tempfile.TemporaryDirectory() as tmp:               # the command line: exit 0, not 3
            f = os.path.join(tmp, "b.json")
            with open(f, "w") as fh:
                json.dump(self.cdj(deep), fh)
            p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), f], capture_output=True,
                               text=True, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
            self.assertEqual((p.returncode, json.loads(p.stdout)["verdict"]), (0, "chain_verified"), p.stderr[-300:])
        # the signature still decides: the same text with another key's signature fails, never `error`
        c = b'{"type":"webauthn.get","challenge":"' + wa.b64url(challenge_of(load(REAL))) + b'","x":' + deep + b"}"
        r = run(resigned(cdj=c, ci=c.index(b'"challenge"'), ti=1, sign_with=D_TEST + 1))
        self.assertEqual(r["checks"]["L2.sig"], "failed:webauthn_p256_signature_invalid")

    def test_constants_and_surrogates(self):
        for val in (b"NaN", b"Infinity", b"-Infinity", b'"\\ud800"'):
            r = run(self.cdj(val))
            self.assertEqual((r["verdict"], r["checks"]["L2.sig"]), ("chain_verified", self.OK), val)
            self.assertTrue(self.notes_of(r)[0].startswith(self.NOT), (val, r["notes"]))


class RequireUV(unittest.TestCase):
    def test_require_uv_reads_the_flag(self):
        """CoinbaseSmartWallet passes requireUV false; the function keeps the library's parameter (WebAuthn.sol 139)."""
        d = load(REAL)
        auth = wa.decode_auth(parts(d)[1])
        own = bytes.fromhex(d["payer_wallet"]["owner"]["result"][2:])
        x, y = int.from_bytes(own[64:96], "big"), int.from_bytes(own[96:128], "big")
        ch = challenge_of(d)
        self.assertIsNone(wa.verify(ch, auth, x, y))
        self.assertEqual(auth["authenticatorData"][32] & wa.FLAG_UV, wa.FLAG_UV)
        self.assertIsNone(wa.verify(ch, auth, x, y, require_uv=True))
        ad = auth["authenticatorData"]
        k = D_TEST
        tx, ty = p256_pub(k)
        for flags, want in ((0x01, "user_verified_flag_not_set"), (0x05, None)):
            a2 = dict(auth, authenticatorData=ad[:32] + bytes([flags]) + ad[33:])
            a2["r"], a2["s"] = p256_sign(k, a2["authenticatorData"] + hashlib.sha256(a2["clientDataJSON"]).digest())
            self.assertEqual(wa.verify(ch, a2, tx, ty, require_uv=True), want)
            self.assertIsNone(wa.verify(ch, a2, tx, ty))


class CompactOwnerSignature(unittest.TestCase):
    """EIP-2098 64-byte owner signatures (SignatureCheckerLib.sol 44-63), on the real address-owner wallet bundles."""
    PATHS = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_v02_wallet", "*.json")) if "MANIFEST" not in p)

    def test_compact_form_of_real_owner_signatures(self):
        self.assertEqual(len(self.PATHS), 2)
        for p in self.PATHS:
            d = load(p)
            idx, data = parts(d)
            self.assertEqual(len(data), 65)
            r, s, v = data[:32], int.from_bytes(data[32:64], "big"), data[64]
            vs = s | ((v - 27) << 255)
            e = copy.deepcopy(d)
            e["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, r + w(vs)).hex()
            got = run(e)
            self.assertEqual(got["checks"]["L2.sig"], "verified (ERC-1271 CoinbaseSmartWallet)", p)
            self.assertIn("owner signature in the 64-byte EIP-2098 form", got["notes"])
            e["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, r + w(vs ^ (1 << 255))).hex()
            self.assertTrue(run(e)["checks"]["L2.sig"].startswith("failed:"), p)
            e["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, r + w(vs)[:31]).hex()
            self.assertEqual(run(e)["checks"]["L2.sig"], "failed:owner_signature_not_65_bytes_v27_28")


    def test_compact_form_with_both_recovery_ids(self):
        """A test owner key signs the real bundle's replay-safe hash with k chosen to give each recovery id: the
        compact form carries v - 27 in the top bit of s (both real owner signatures have v 27)."""
        from lib.secp256k1 import public_key_to_address, recover_public_key, sign
        d = load(self.PATHS[0])
        idx, data = parts(d)
        h = challenge_of(d)
        key = 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318      # a test key
        r0, s0, _ = sign(h, key, 7)
        owner = public_key_to_address(recover_public_key(h, r0, s0, _), av.keccak256)
        d["payer_wallet"]["owner"]["result"] = "0x" + (w(32) + w(32) + bytes(12) + bytes.fromhex(owner[2:])).hex()
        seen = set()
        for k in range(2, 60):
            r, s, rec = sign(h, key, k)
            if rec in seen:
                continue
            seen.add(rec)
            for form in (w(r) + w(s) + bytes([27 + rec]), w(r) + w(s | rec << 255)):
                e = copy.deepcopy(d)
                e["payment_payload"]["payload"]["signature"] = "0x" + enc_wrapper(idx, form).hex()
                self.assertEqual(run(e)["checks"]["L2.sig"], "verified (ERC-1271 CoinbaseSmartWallet)", (rec, len(form)))
        self.assertEqual(seen, {0, 1})


class WycheproofP256(unittest.TestCase):
    def test_webauthn_ecdsa_step_differs_only_by_low_s(self):
        """p256_check on ecdsa_secp256r1_sha256_p1363_test.json (sources/wycheproof_d17cc89): valid signatures with
        s > n/2 refused by WebAuthn.sol 110 (the contract's rule), every other verdict equal to Wycheproof's."""
        with open(os.path.join(ROOT, "sources", "wycheproof_d17cc89", "ecdsa_secp256r1_sha256_p1363_test.json")) as fh:
            doc = json.load(fh)
        rows = []
        for g in doc["testGroups"]:
            u = bytes.fromhex(g["publicKey"]["uncompressed"])
            x, y = int.from_bytes(u[1:33], "big"), int.from_bytes(u[33:], "big")
            for t in g["tests"]:
                sig = bytes.fromhex(t["sig"])
                why = "length" if len(sig) != 64 else wa.p256_check(x, y, bytes.fromhex(t["msg"]),
                                                                     int.from_bytes(sig[:32], "big"),
                                                                     int.from_bytes(sig[32:], "big"))
                rows.append((t["result"], why, int.from_bytes(sig[32:], "big") if len(sig) == 64 else 0))
        self.assertEqual(len(rows), 262)
        self.assertEqual({r for r, why, s in rows}, {"valid", "invalid"})
        valid = [(why, s) for r, why, s in rows if r == "valid"]
        self.assertEqual(len(valid), 173)
        self.assertEqual(sum(s > N // 2 for why, s in valid), 70)
        self.assertTrue(all((why is None) == (s <= N // 2) for why, s in valid))
        self.assertTrue(all(why in (None, "s_above_half_order") for why, s in valid))
        self.assertEqual(sum(why is None for why, s in valid), WycheproofP256.LOW_S_VALID)
        self.assertTrue(all(why is not None for r, why, s in rows if r == "invalid"))

    LOW_S_VALID = 103          # measured 2026-10-26; the other 70 valid ones have s > n/2


if __name__ == "__main__":
    unittest.main()
