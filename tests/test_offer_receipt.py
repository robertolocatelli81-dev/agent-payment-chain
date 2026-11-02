"""SPEC 0.11 (section 13): x402 signed offers and receipts (OR1-OR3). Oracle: tests/data/offer_receipt_ref_vectors.json,
offers and receipts MADE and VERIFIED by the x402 reference implementation (4241d56, typescript/packages/extensions/src/
offer-receipt, tools/offer_receipt_oracle.ts) for the paid terms of two real bundles of the corpus (Base: real_v03 v002,
Solana: the mainnet payment of this work). Positive control: the same forged artifacts under apc_verify 0.8.0 (5cbe7c7)
leave the verdict chain_verified."""
import copy
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03", "real_svm", files=("tests/data/offer_receipt_ref_vectors.json",))   # not distributed (SPEC 33)
import apc_offer as ao  # noqa: E402
import apc_verify as av  # noqa: E402

VEC = json.load(open(os.path.join(ROOT, "tests", "data", "offer_receipt_ref_vectors.json")))["vectors"]
OLD = "5cbe7c7"           # apc_verify 0.8.0, before SPEC 0.11


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def bundle(v):
    """The real bundle of the vector, with the resource URL the artifact names and the artifact in its extension."""
    with open(os.path.join(ROOT, v["bundle"])) as fh:
        b = av.strict_json(fh.read())
    pl = v["artifact"].get("payload") or v["ref_payload"]
    url = pl["resourceUrl"]
    b["payment_payload"]["resource"] = {"url": url}
    b["payment_required"] = {"x402Version": 2, "resource": {"url": url}, "accepts": [copy.deepcopy(b["payment_payload"]["accepted"])]}
    if "_offer_" in v["id"]:
        b["payment_required"]["extensions"] = {"offer-receipt": {"info": {"offers": [copy.deepcopy(v["artifact"])]}}}
    else:
        b["settlement"]["extensions"] = {"offer-receipt": {"info": {"receipt": copy.deepcopy(v["artifact"])}}}
    return b


def trust_for(v):
    pl = v["artifact"].get("payload") or v["ref_payload"]
    u = urlsplit(pl["resourceUrl"])
    who = v["ref_signer"].lower() if "ref_signer" in v else v["kid"]
    t = {"apc_signer_trust": 1, "authorized": [{"origin": "%s://%s" % (u.scheme, u.netloc.lower()), "signers": [who]}]}
    if "kid" in v and v["kid"].startswith("did:web:"):
        t["keys"] = {v["kid"]: {"alg": v["alg"], "public_key": v["public_key"]}}
    return t


def run(b, trust=None):
    try:
        return av.verify_bundle(copy.deepcopy(b), signer_trust=trust)
    except av.Unsupported:
        return {"verdict": "unsupported", "checks": {}}
    except av.Refusal as e:
        return {"verdict": "refused", "checks": {}, "reason": str(e)}


def art(b):
    if "extensions" in b.get("payment_required", {}):
        return b["payment_required"]["extensions"]["offer-receipt"]["info"]["offers"][0]
    return b["settlement"]["extensions"]["offer-receipt"]["info"]["receipt"]


def or_check(b):
    return "OR1" if "extensions" in b.get("payment_required", {}) else "OR2"


def tamper_jws(a):
    """Flip one bit of the signature part (the header and payload unchanged)."""
    h, p, s = a["signature"].split(".")
    raw = bytearray(ao._b64u(s, "t"))
    raw[5] ^= 1
    a["signature"] = "%s.%s.%s" % (h, p, b64u(bytes(raw)))


def set_jws_part(a, i, obj, raw=None):
    parts = a["signature"].split(".")
    parts[i] = b64u(raw if raw is not None else json.dumps(obj, separators=(",", ":")).encode())
    a["signature"] = ".".join(parts)


class Curves(unittest.TestCase):
    def test_p256_rfc6979_a25(self):
        q = (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
             0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
        sig = (0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716).to_bytes(32, "big") + \
            (0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8).to_bytes(32, "big")
        self.assertTrue(ao.ecdsa_verify(ao.R1, q, b"sample", sig))
        self.assertFalse(ao.ecdsa_verify(ao.R1, q, b"samplf", sig))
        comp = bytes([2 + q[1] % 2]) + q[0].to_bytes(32, "big")
        self.assertEqual(ao._decompress(ao.R1, comp), q)
        self.assertIsNone(ao._decompress(ao.R1, bytes([2]) + (ao.R1[0]).to_bytes(32, "big")))

    def test_secp256k1_against_the_signing_library(self):
        import hashlib
        from lib.secp256k1 import sign, _mul, GX, GY, N
        rnd = random.Random(9)
        for _ in range(4):
            d, k = rnd.randrange(1, N), rnd.randrange(1, N)
            q = _mul(d, (GX, GY))
            m = rnd.randbytes(40)
            r, s, _ = sign(hashlib.sha256(m).digest(), d, k)
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            self.assertTrue(ao.ecdsa_verify(ao.K1, q, m, sig))
            self.assertFalse(ao.ecdsa_verify(ao.K1, q, m + b"x", sig))
            comp = bytes([2 + q[1] % 2]) + q[0].to_bytes(32, "big")
            self.assertEqual(ao._decompress(ao.K1, comp), q)


class Reference(unittest.TestCase):
    def test_every_reference_artifact(self):
        n = 0
        for v in VEC:
            b = bundle(v)
            r = run(b, trust_for(v))
            k = or_check(b)
            self.assertEqual(r["checks"][k], "verified", v["id"])
            self.assertEqual(r["checks"]["OR3"], "verified", v["id"])
            self.assertEqual(r["verdict"], run(av.strict_json(open(os.path.join(ROOT, v["bundle"])).read()))["verdict"], v["id"])
            m = r["offer_receipt"]
            got = (m["offers"][0] if k == "OR1" else m["receipt"])["signer"]
            self.assertEqual(got, v["ref_signer"].lower() if "ref_signer" in v else v["kid"], v["id"])
            n += 1
            # without the reader's trust: OR3 absent (signer not the payTo), did:web not resolvable offline
            r0 = run(b)
            if "kid" in v and v["kid"].startswith("did:web:"):
                self.assertTrue(r0["checks"][k].endswith("_key_not_resolvable_offline"), v["id"])
                self.assertEqual(r0["verdict"], "chain_incomplete")
            else:
                self.assertEqual(r0["checks"][k], "verified", v["id"])
                self.assertEqual(r0["checks"]["OR3"], "not_evaluated:absent:no_signer_trust", v["id"])
        self.assertEqual(n, 21)

    def test_the_reference_payload_is_what_we_read(self):
        for v in VEC:
            if v["artifact"]["format"] == "jws":
                info = ao._jws(v["artifact"], "offer" if "_offer_" in v["id"] else "receipt",
                               ao.parse_trust(trust_for(v)), [])
                self.assertEqual(info["payload"], v["ref_payload"], v["id"])


class Forged(unittest.TestCase):
    def cases(self):
        """(name, bundle, trust, expected result of the OR check or verdict 'refused')."""
        out = []
        for v in VEC:
            b0, t = bundle(v), trust_for(v)
            k = or_check(b0)
            if v["artifact"]["format"] == "jws":
                b = copy.deepcopy(b0)
                tamper_jws(art(b))
                out.append((v["id"] + ":sig", b, t, k, "_signature_invalid"))
                b = copy.deepcopy(b0)
                h = json.loads(ao._b64u(art(b)["signature"].split(".")[0], "h"))
                h["alg"] = {"EdDSA": "ES256", "ES256": "ES256K", "ES256K": "EdDSA"}[h["alg"]]
                set_jws_part(art(b), 0, h)
                out.append((v["id"] + ":alg", b, t, k, "_alg_not_the_key_algorithm"))
                b = copy.deepcopy(b0)
                h = json.loads(ao._b64u(art(b)["signature"].split(".")[0], "h"))
                h["crit"] = ["b64"]
                set_jws_part(art(b), 0, h)
                out.append((v["id"] + ":crit", b, t, k, "_jws_crit_not_understood"))
                b = copy.deepcopy(b0)
                p = json.loads(ao._b64u(art(b)["signature"].split(".")[1], "p"))
                set_jws_part(art(b), 1, None, json.dumps(p, indent=1).encode())
                out.append((v["id"] + ":notjcs", b, t, k, "_jws_payload_not_jcs"))
            else:   # eip712: a changed payload recovers ANOTHER signer, which the reader's trust does not list
                b = copy.deepcopy(b0)
                pl = art(b)["payload"]
                pl["issuedAt" if "issuedAt" in pl else "validUntil"] += 1
                out.append((v["id"] + ":payload", b, t, "OR3", "failed:signer_not_authorized"))
            if k == "OR2":
                b = copy.deepcopy(b0)
                b["settlement"]["success"] = False
                out.append((v["id"] + ":unsuccessful", b, t, k, "failed:receipt_on_unsuccessful_settlement"))
        return out

    def test_forged_fail(self):
        n = 0
        for name, b, t, k, want in self.cases():
            r = run(b, t)
            got = r["checks"].get(k, r["verdict"])
            self.assertTrue(got.endswith(want), (name, got))
            self.assertEqual(r["verdict"], "chain_failed", name)
            n += 1
        self.assertGreaterEqual(n, 60)

    def test_positive_control_old_verifier(self):
        """The forged bundles are chain_verified (or as the bundle alone) under apc_verify 0.8.0: the extension was
        carried and not read. A failing old verifier here would make the new test meaningless."""
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            seen = 0
            for name, b, t, k, want in [c for c in self.cases() if not c[0].endswith(":unsuccessful")][:24]:
                p = os.path.join(tmp, "b.json")
                with open(p, "w") as fh:
                    json.dump(b, fh)
                out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), p],
                                     capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
                rep = json.loads(out.stdout)
                self.assertEqual(rep["verifier"], "apc_verify 0.8.0")
                self.assertEqual(rep["verdict"], "chain_verified", name)
                self.assertFalse(any(c.startswith("OR") for c in rep["checks"]), name)
                seen += 1
            self.assertEqual(seen, 24)


class Bindings(unittest.TestCase):
    def v(self, ident):
        return next(v for v in VEC if v["id"] == ident)

    def test_receipt_mismatches(self):
        v = self.v("evm_receipt_eip712_None_None")
        t = trust_for(v)
        b = bundle(v)
        for field, val, want in (("transaction", "0x" + "11" * 32, "failed:receipt_transaction_mismatch"),
                                 ("payer", "0x" + "22" * 20, "failed:receipt_payer_mismatch"),
                                 ("network", "eip155:1", "failed:receipt_network_mismatch"),
                                 ("resourceUrl", "https://api.example.com/other", "failed:receipt_resource_url_mismatch")):
            bb = copy.deepcopy(b)
            bb["settlement"]["extensions"]["offer-receipt"]["info"]["receipt"]["payload"][field] = val
            r = run(bb, t)
            # the signature recovers another signer once the payload changes: OR2 binds, OR3 refuses the signer
            self.assertEqual(r["checks"]["OR2"], want, field)
            self.assertEqual(r["verdict"], "chain_failed")

    def test_offer_terms_and_accept_index(self):
        v = self.v("evm_offer_jws_EdDSA_key")
        t = trust_for(v)
        b = bundle(v)
        # the paid terms differ from the signed offer: no signed offer for them (not a failure: OR 4.1)
        bb = copy.deepcopy(b)
        acc = bb["payment_payload"]["accepted"]
        bb["payment_required"]["accepts"].insert(0, copy.deepcopy(acc))
        bb["payment_required"]["accepts"][1]["amount"] = "1"
        bb["payment_required"]["extensions"]["offer-receipt"]["info"]["offers"][0]["acceptIndex"] = 1
        r = run(bb, t)
        self.assertEqual(r["checks"]["OR1"], "failed:offer_accept_index_mismatch")
        bb["payment_required"]["extensions"]["offer-receipt"]["info"]["offers"][0]["acceptIndex"] = 7
        self.assertEqual(run(bb, t)["checks"]["OR1"], "failed:offer_accept_index_out_of_range")
        bb["payment_required"]["extensions"]["offer-receipt"]["info"]["offers"][0]["acceptIndex"] = 0
        self.assertEqual(run(bb, t)["checks"]["OR1"], "verified")
        bb = copy.deepcopy(b)
        bb["payment_payload"]["resource"]["url"] = bb["payment_required"]["resource"]["url"] = "https://api.example.com/x"
        r = run(bb, t)
        self.assertEqual(r["checks"]["OR1"], "not_evaluated:no_signed_offer_for_accepted")
        self.assertEqual(r["verdict"], "chain_incomplete")

    def test_untrusted_signer(self):
        v = self.v("evm_offer_jws_ES256K_key")
        t = trust_for(v)
        t["authorized"][0]["signers"] = ["0x" + "33" * 20]
        r = run(bundle(v), t)
        self.assertEqual(r["checks"]["OR3"], "failed:signer_not_authorized")
        t["authorized"][0]["origin"] = "https://elsewhere.example"
        t["authorized"][0]["signers"] = [v["kid"]]
        self.assertEqual(run(bundle(v), t)["checks"]["OR3"], "failed:signer_not_authorized")

    def test_payto_signing_needs_no_trust(self):
        """OR 4.5.1 first approach: on Solana an Ed25519 signer that IS payTo is authorized without signer_trust."""
        import apc_solana as sol
        v = self.v("svm_receipt_jws_EdDSA_key")
        b = bundle(v)
        key = ao.resolve(v["kid"], None, [])[1]
        b["payment_payload"]["accepted"]["payTo"] = sol.b58encode(key)
        info = ao._jws(art(b), "receipt", None, [])
        self.assertEqual(ao._authorized(info, sol.b58encode(key), "https://x", False, None), "verified")
        self.assertEqual(ao._authorized(info, "7HrgiXR4dXkU9Bri9s2uFn9sHTK48KQ3PQaktdQeR82k", "https://x", False, None),
                         "not_evaluated:absent:no_signer_trust")


class Closed(unittest.TestCase):
    """Generative: a new member at every level of the extension (OR 2: unsupported, so not evaluated, never verified),
    wrong types, other formats; any input is a verdict or a refusal, never a traceback."""

    def levels(self, b):
        if "extensions" in b.get("payment_required", {}):
            e = b["payment_required"]["extensions"]["offer-receipt"]
            yield e
            yield e["info"]
            yield e["info"]["offers"][0]
            if "payload" in e["info"]["offers"][0]:
                yield e["info"]["offers"][0]["payload"]
        else:
            e = b["settlement"]["extensions"]["offer-receipt"]
            yield e
            yield e["info"]
            yield e["info"]["receipt"]
            if "payload" in e["info"]["receipt"]:
                yield e["info"]["receipt"]["payload"]

    def test_new_member_each_level(self):
        rnd = random.Random(26)
        n = 0
        for v in VEC[::3]:          # every third vector: offers and receipts, each format and algorithm
            b0 = bundle(v)
            for i in range(len(list(self.levels(b0)))):
                for val in (None, 1, "x", [], {}, True):
                    b = copy.deepcopy(b0)
                    lvl = list(self.levels(b))[i]
                    lvl["z%d" % rnd.randrange(1000)] = val
                    r = run(b, trust_for(v))
                    # OR 2: unknown extension fields are "unsupported", not interpreted: the check is not evaluated
                    # and names the member; the bundle is never chain_verified with it
                    self.assertIn("member_not_supported", r["checks"][or_check(b0)], (v["id"], i, val))
                    self.assertEqual(r["verdict"], "chain_incomplete", (v["id"], i, val))
                    n += 1
        self.assertGreater(n, 120)

    def test_new_member_in_jws_payload(self):
        for v in VEC:
            if v["artifact"]["format"] != "jws":
                continue
            b = bundle(v)
            p = json.loads(ao._b64u(art(b)["signature"].split(".")[1], "p"))
            p["extra"] = 1
            import apc_ap2
            set_jws_part(art(b), 1, None, apc_ap2.canonical(p).encode())
            r = run(b, trust_for(v))
            self.assertIn("member_not_supported(payload.extra)", r["checks"][or_check(b)], v["id"])

    def test_wrong_types(self):
        rnd = random.Random(7)
        vals = [None, 0, -1, 2 ** 53, 1.5, "", "x" * 300, [], {}, True, "eip155:x", "\u00e9"]
        n = 0
        for v in VEC[1::3]:
            b0 = bundle(v)
            for lvl_i, lvl in enumerate(list(self.levels(b0))):
                for key in list(lvl):
                    for val in rnd.sample(vals, 4):
                        b = copy.deepcopy(b0)
                        list(self.levels(b))[lvl_i][key] = val
                        r = run(b, trust_for(v))
                        self.assertIn(r["verdict"], ("refused", "chain_failed", "chain_incomplete", "chain_verified"))
                        if r["verdict"] == "chain_verified":       # only a value read as absent may keep it verified
                            self.assertIn(key, ("acceptIndex", "transaction", "validUntil", "schema"), (v["id"], key, val))
                        n += 1
        self.assertGreater(n, 120)

    def test_other_format_and_versions(self):
        v = next(x for x in VEC if x["id"] == "evm_offer_jws_EdDSA_key")
        b = bundle(v)
        art(b)["format"] = "cose"
        self.assertEqual(run(b)["checks"]["OR1"], "not_evaluated:offer_0_format_not_supported")
        v = next(x for x in VEC if x["id"] == "evm_offer_eip712_None_None")
        b = bundle(v)
        art(b)["payload"]["version"] = 2
        self.assertEqual(run(b)["checks"]["OR1"], "not_evaluated:offer_0_version_not_supported")
        b = bundle(v)
        art(b)["payload"]["network"] = "base"
        self.assertEqual(run(b)["checks"]["OR1"], "failed:offer_0_network_not_caip2")

    def test_did_inputs(self):
        notes = []
        for kid, want in (("did:key:z" + "1" * 200, "did_key_too_long"), ("did:key:" + "x" * 5000, "kid_longer_than_4096"),
                          ("did:key:m123", "did_key_multibase_not_base58btc"), ("did:key:z0OIl", "did_key_not_base58"),
                          ("did:web:example.com", "key_not_resolvable_offline"), ("did:jwk:@@", "did_jwk_not_base64url"),
                          ("did:jwk:" + b64u(b'{"kty":"RSA","n":"x","e":"AQAB"}'), "did_jwk_key_type_not_supported")):
            with self.assertRaises((ao.Bad, ao.Open)) as cm:
                ao.resolve(kid, None, notes)
            self.assertEqual(str(cm.exception), want, kid)
        with self.assertRaises(av.Refusal):
            ao.resolve("did:jwk:" + b64u(b'{"kty":"OKP","crv":"Ed25519","x":"' + b"A" * 43 + b'","d":"x"}'), None, notes)

    def test_trust_document_closed(self):
        good = {"apc_signer_trust": 1, "authorized": [{"origin": "https://a.example", "signers": ["0x" + "11" * 20]}]}
        ao.parse_trust(good)
        for bad in ({**good, "x": 1}, {**good, "apc_signer_trust": True}, {**good, "authorized": []},
                    {**good, "authorized": [{"origin": "https://A.example", "signers": ["s"]}]},
                    {**good, "authorized": [{"origin": "https://a.example/path", "signers": ["s"]}]},
                    {**good, "keys": {"k": {"alg": "RS256", "public_key": "00"}}},
                    {**good, "keys": {"k": {"alg": "EdDSA", "public_key": "00" * 31}}},
                    {**good, "keys": {"k": {"alg": "ES256", "public_key": "04" + "00" * 64}}}):
            with self.assertRaises(av.Refusal):
                ao.parse_trust(bad)


if __name__ == "__main__":
    unittest.main()
