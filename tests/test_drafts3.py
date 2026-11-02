"""SPEC section 24: draft profiles of x402 PRs 3304, 3682, 3681, 2853 (apc_drafts3.py), only with --drafts, apart from
the verdict. Oracles: the normative vectors the PRs publish — PR 3304's worked vector and its seven query examples,
PR 3682's example receipt (its evidenceRef and Ed25519 signature verify), PR 2853's three recordDigest vectors."""
import base64
import copy
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_drafts3 as d3  # noqa: E402
import apc_verify as av  # noqa: E402

SRC = os.path.join(ROOT, "sources", "x402_prs_20261026")
V002 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def md_json(name, needle):
    with open(os.path.join(SRC, name)) as fh:
        return [json.loads(b) for b in re.findall(r"```json\n(.*?)```", fh.read(), re.S) if needle in b]


def with_exchange(d, target, body_obj, req_body=None):
    sig = base64.b64encode(json.dumps(d["payment_payload"]).encode()).decode()
    rq = {"method": "GET" if req_body is None else "POST", "target_uri": target,
          "fields": [["Host", target.split("/")[2]], ["PAYMENT-SIGNATURE", sig]]}
    if req_body is not None:
        rq["body"] = base64.b64encode(json.dumps(req_body).encode()).decode()
    d["exchange"] = {"request": rq, "response": {"status": 200, "fields": [["Content-Type", "application/json"]],
                                                 "body": base64.b64encode(json.dumps(body_obj).encode()).decode()}}
    return d


class Pr3304(unittest.TestCase):
    def test_normative_vectors(self):
        self.assertEqual(d3.provenance_hash("/v1/echo-sum", {"a": 2, "b": 3}, {"sum": 5}, "sum = a + b, integer addition",
                                            "2026-07"),
                         "sha256:81ea1f2227fd9df5b868954e6d26d091810352f148dade483b260844788ede03")
        for q, want in (("q=a+b", {"q": "a b"}), ("q=a%2Bb", {"q": "a+b"}), ("q=a%20b", {"q": "a b"}), ("flag", {"flag": ""}),
                        ("a=1&a=2", {"a": ["1", "2"]}), ("x=%ZZ", None), ("x=%FF", None), ("", {})):
            self.assertEqual(d3.query_inputs(q), want, q)

    def test_envelopes(self):
        env = md_json("response-provenance.md", '"response-provenance"')
        self.assertEqual(len(env), 2)                 # member carriage and body carriage of the same claim
        for body in env:
            d = with_exchange(load(V002), "https://api.example.com/v1/echo-sum", body, {"a": 2, "b": 3})
            r = av.verify_bundle(copy.deepcopy(d), drafts=True)
            self.assertEqual(r["drafts"][d3.P3304]["checks"], {"RP1": "verified", "RP2": "verified"})
            b2 = copy.deepcopy(body)
            (b2["result"] if "result" in b2 else b2)["sum"] = 6
            d = with_exchange(load(V002), "https://api.example.com/v1/echo-sum", b2, {"a": 2, "b": 3})
            self.assertEqual(av.verify_bundle(d, drafts=True)["drafts"][d3.P3304]["checks"]["RP2"], "failed:contradicted")
        b3 = copy.deepcopy(env[0])
        b3["extensions"]["response-provenance"]["fixedPointVersion"] = "GVP-FixedPoint/9"
        d = with_exchange(load(V002), "https://api.example.com/v1/echo-sum", b3, {"a": 2, "b": 3})
        self.assertEqual(av.verify_bundle(d, drafts=True)["drafts"][d3.P3304]["checks"]["RP1"],
                         "not_evaluated:unverifiable:fixed_point_version")


class Pr3682(unittest.TestCase):
    def example(self):
        return md_json("pr3682.md", '"signer"')[0]["extensions"]["execution-evidence"]

    def bundle(self):
        """A bundle with the example's payment terms (the x402 v1 specification example payer and payee)."""
        info = self.example()["info"]
        p = info["payment"]
        d = load(V002)
        d["payment_payload"]["accepted"]["payTo"] = p["payee"]
        d["payment_payload"]["payload"]["authorization"]["from"] = p["payer"]
        d["payment_payload"]["accepted"]["amount"] = p["amount"]
        d["settlement"] = {"success": True, "transaction": p["txHash"], "network": p["network"]}
        d.pop("chain_tx"), d.pop("inclusion")
        d["settlement"]["extensions"] = {"execution-evidence": copy.deepcopy(self.example())}
        return d

    def test_example_vector(self):
        r = av.verify_bundle(self.bundle(), drafts=True)
        ck = r["drafts"][d3.P3682]["checks"]
        for k in ("EE1", "EE2", "EE3", "EE4a", "EE4b", "EE4c", "EE4d", "EE4e", "EE4f"):
            self.assertEqual(ck[k], "verified", k)
        self.assertEqual(ck["EE5"], "not_evaluated:absent:no_response_body")
        self.assertEqual(ck["EE6"], "not_evaluated:absent:no_signer_trust")
        d = self.bundle()
        d["settlement"]["extensions"]["execution-evidence"]["info"]["payment"]["amount"] = "10001"
        ck = av.verify_bundle(d, drafts=True)["drafts"][d3.P3682]["checks"]
        self.assertEqual((ck["EE1"], ck["EE2"]), ("failed:evidence_ref_mismatch", "failed:evidence_signature_invalid"))


class Pr3681(unittest.TestCase):
    def test_refund(self):
        d = load(V002)
        st = d["settlement"]
        req = {"x402Version": 2, "paymentReference": {"txHash": st["transaction"], "network": st["network"]},
               "amount": "1000", "reason": "service_defective", "idempotencyKey": "9f3b1c2d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
               "payerSignature": "0x00"}
        rs = {"status": "executed", "amount": "1500", "refundTxHash": "0x" + "cd" * 32}
        req2 = dict(req, idempotencyKey="11111111-2222-3333-4444-555555555555")
        rs2 = dict(rs, refundTxHash="0x" + "ef" * 32)
        # the same key twice (one refund) and a second key: 1500 + 1500 > the 2000 settled
        d["draft_artifacts"] = [{"profile": d3.P3681, "artifact": {"request": req, "response": rs}}] * 2 + \
            [{"profile": d3.P3681, "artifact": {"request": req2, "response": rs2}}]
        ck = av.verify_bundle(copy.deepcopy(d), drafts=True)["drafts"][d3.P3681]["checks"]
        self.assertEqual((ck["RF2[0]"], ck["RF3[0]"], ck["RF5[0]"], ck["RF7"]),
                         ("verified", "verified", "not_evaluated:proposal_defines_no_signed_bytes",
                          "failed:refunded_total_above_settled_amount"))
        self.assertNotIn("RF8", ck)
        d["draft_artifacts"] = [{"profile": d3.P3681, "artifact": {"request": req, "response": rs}},
                                {"profile": d3.P3681, "artifact": {"request": req, "response": rs2}}]
        ck = av.verify_bundle(copy.deepcopy(d), drafts=True)["drafts"][d3.P3681]["checks"]
        self.assertEqual((ck["RF8"], ck["RF7"]), ("failed:idempotency_key_with_two_refunds", "verified"))


class Pr3783(unittest.TestCase):
    def vectors(self):
        with open(os.path.join(SRC, "delivery-receipt.vectors.json")) as fh:
            return json.load(fh)

    def test_session_path_expected_verdicts(self):
        import apc_dr3783 as dr
        d = self.vectors()
        n = 0
        for v in d["expectedVerdicts"]:
            if v["path"] != "session":
                continue
            levels, reason = dr.verify_session(dr.resolve(d, v["inputs"]))
            self.assertEqual((levels, reason), (v["levels"], v.get("reason")), v["id"])
            n += 1
        self.assertEqual(n, 8)
        s = d["stream"]
        self.assertEqual(dr.stream_digest([f.encode() for f in s["frames"]]), s["digest"])

    def test_breaks(self):
        import apc_dr3783 as dr
        d = self.vectors()
        v = next(x for x in d["expectedVerdicts"] if x["id"] == "endToEnd/body/session")
        inp = dr.resolve(d, v["inputs"])
        for mut, want in ((lambda i: i.__setitem__("responseBody", i["responseBody"] + " "), ("delivery", "BODY_DIGEST")),
                          (lambda i: i["settle"].__setitem__("payer", "0x" + "11" * 20), ("settlement", "SETTLEMENT_MISMATCH")),
                          (lambda i: i["receipt"]["payload"].__setitem__("amount", "1"), ("authentic", "SIGNATURE")),
                          (lambda i: i.__setitem__("pinnedGovernanceKeys", {}), ("trusted", "NO_PINNED_GOVERNANCE_KEY")),
                          (lambda i: i["directory"].__setitem__("epoch", 2), ("trusted", "DIRECTORY_ROOT")),
                          (lambda i: i["receipt"]["payload"].__setitem__("extra", 1), ("integrity", "PAYLOAD_MEMBERS"))):
            i2 = copy.deepcopy(inp)
            mut(i2)
            levels, reason = dr.verify_session(i2)
            self.assertEqual((reason["level"], reason["code"]), want)

    def test_bundle_profile(self):
        import apc_dr3783 as dr
        d = self.vectors()
        e = d["endToEnd"]
        b = load(V002)
        acc = b["payment_payload"]["accepted"]
        acc.update(payTo=e["requirements"]["payTo"], amount=e["requirements"]["amount"])
        b["payment_payload"]["payload"]["authorization"]["from"] = e["settle"]["payer"]
        b["settlement"] = dict(e["settle"], extensions={"delivery-receipt": {"info": {"receipt": e["receipt"]}}})
        b.pop("chain_tx"), b.pop("inclusion")
        sig = base64.b64encode(json.dumps(b["payment_payload"]).encode()).decode()
        b["exchange"] = {"request": {"method": "GET", "target_uri": e["resourceUrl"],
                                     "fields": [["Host", "api.example.com"], ["PAYMENT-SIGNATURE", sig]]},
                         "response": {"status": 200, "fields": [["Content-Type", "application/json"]],
                                      "body": base64.b64encode(e["body"].encode()).decode()}}
        b["draft_artifacts"] = [{"profile": dr.P3783, "artifact": {"directory": e["directory"]}}]
        gov = base64.b64decode(e["governanceKeys"]["ed25519"]).hex()
        trust = {"apc_signer_trust": 1, "keys": {"governance": {"alg": "EdDSA", "public_key": gov}},
                 "authorized": [{"origin": "https://api.example.com", "signers": ["governance"]}]}
        ck = av.verify_bundle(copy.deepcopy(b), drafts=True, signer_trust=trust)["drafts"][dr.P3783]["checks"]
        self.assertEqual([ck[k] for k in ("DR1_integrity", "DR2_authentic", "DR3_trusted", "DR4_settlement", "DR5_delivery")],
                         ["verified"] * 5)
        ck = av.verify_bundle(copy.deepcopy(b), drafts=True)["drafts"][dr.P3783]["checks"]
        self.assertEqual(ck["DR3_trusted"], "not_evaluated:absent:no_pinned_governance_key")


class Pr3220(unittest.TestCase):
    def vectors(self):
        with open(os.path.join(SRC, "authority-vectors.json")) as fh:
            return json.load(fh)

    def test_vectors(self):
        import apc_solana as sol
        v = self.vectors()
        a = v["modelA"]
        self.assertIsNone(d3.mandate_refusal(a["mandate"]))
        self.assertEqual(d3._jcs(a["mandate"]), a["jcs"])
        self.assertEqual(d3.mandate_digest(a["mandate"]), a["digest"])
        self.assertTrue(sol.ed25519_verify(d3._b64u(a["mandate"]["issuer"]),
                                           b"x402-mandate/1\n" + a["jcs"].encode(), d3._b64u(a["sig"])))
        b = d3.mandate_binding(a["digest"], a["binding"]["paymentId"])
        self.assertEqual((b, str(int(b, 16)), b[2:].upper()),
                         (a["binding"]["eip3009"], a["binding"]["permit2"], a["binding"]["xrpl"]))
        self.assertEqual(d3.mandate_digest(v["modelB"]["mandate"]), v["modelB"]["digest"])
        m = a["mandate"]
        for mut in (lambda x: x.__setitem__("notAfter", "2027-02-30T00:00:00Z"), lambda x: x.__setitem__("recipients", []),
                    lambda x: x.__setitem__("recipients", ["*", "merchant.example"]), lambda x: x.__setitem__("cap", "1.5"),
                    lambda x: x.__setitem__("perPayment", "2000000"), lambda x: x.__setitem__("extra", "x"),
                    lambda x: x.__setitem__("purpose", "\ud800"), lambda x: x.__setitem__("v", "x402-mandate/2")):
            x = copy.deepcopy(m)
            mut(x)
            self.assertIsNotNone(d3.mandate_refusal(x))
        with self.assertRaises(ValueError):
            d3.mandate_binding(a["digest"], "pay;001")

    def test_bundle(self):
        import hashlib
        import apc_solana as sol
        from lib.secp256k1 import sign, _mul, GX, GY
        import apc_offer as ao
        v = self.vectors()
        anvil = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
        payer = ao.evm_address(_mul(anvil, (GX, GY)))
        b = load(V002)
        acc = b["payment_payload"]["accepted"]
        m = dict(v["modelA"]["mandate"], subject=payer, asset=acc["asset"], recipients=[acc["payTo"]], cap="1000000",
                 perPayment="5000")
        seed = d3._b64u(v["keys"]["issuer"]["seedB64url"])
        sig = d3.base64.urlsafe_b64encode(sol.ed25519_sign(seed, b"x402-mandate/1\n" + d3._jcs(m).encode())).rstrip(b"=").decode()
        nonce = d3.mandate_binding(d3.mandate_digest(m), "pay-001")
        au = b["payment_payload"]["payload"]["authorization"]
        au.update({"from": payer, "nonce": nonce})
        dom = {"name": acc["extra"]["name"], "version": acc["extra"]["version"], "chainId": 8453, "verifyingContract": acc["asset"]}
        msg = dict(au, value=int(au["value"]), validAfter=int(au["validAfter"]), validBefore=int(au["validBefore"]))
        dg = av.signing_digest(dom, "TransferWithAuthorization", av.TYPES, msg, av.DOMAIN4)
        r, s_, rec = sign(dg, anvil, int.from_bytes(hashlib.sha256(dg).digest(), "big") % av.SECP_N)
        b["payment_payload"]["payload"]["signature"] = "0x" + r.to_bytes(32, "big").hex() + s_.to_bytes(32, "big").hex() + bytes([27 + rec]).hex()
        b["settlement"]["payer"] = payer
        b.pop("chain_tx")
        b.pop("inclusion")
        b["draft_artifacts"] = [{"profile": d3.P3220, "artifact": {"envelope": {"mandate": m, "alg": "Ed25519", "sig": sig},
                                                                  "paymentId": "pay-001"}}]
        r = av.verify_bundle(copy.deepcopy(b), drafts=True)
        self.assertEqual(r["checks"]["L2.sig"], "verified")
        ck = r["drafts"][d3.P3220]["checks"]
        self.assertEqual((ck["AU1[0]"], ck["AU2[0]"], ck["AU3[0]"], ck["AU4[0]"]), ("verified",) * 4)
        b["draft_artifacts"][0]["artifact"]["paymentId"] = "pay-002"
        self.assertEqual(av.verify_bundle(copy.deepcopy(b), drafts=True)["drafts"][d3.P3220]["checks"]["AU3[0]"],
                         "failed:nonce_not_the_mandate_binding")
        m2 = dict(m, perPayment="1000")                   # the settled 2000 above the per-payment bound (security fix)
        b["draft_artifacts"][0]["artifact"] = {"envelope": {"mandate": m2, "alg": "Ed25519", "sig": sig}, "paymentId": "pay-001"}
        ck = av.verify_bundle(copy.deepcopy(b), drafts=True)["drafts"][d3.P3220]["checks"]
        self.assertEqual((ck["AU2[0]"], ck["AU4[0]"]), ("failed:mandate_signature", "failed:amount_above_per_payment"))


class Pr3868(unittest.TestCase):
    def test_reference_kit_records(self):
        import hashlib
        kit = os.path.join(ROOT, "sources", "notary_x402_kit_e6e17a2")
        with open(os.path.join(kit, "dispute-extension-vectors.json")) as fh:
            vecs = json.load(fh)["vectors"]
        keys = {}
        for f in ("stillos-notary-ed25519-v1.pub", "stillos-notary-ed25519-retired-2026-07-31.pub"):
            with open(os.path.join(kit, f)) as fh:
                pem = fh.read()
            b64 = "".join(re.search(r"-----BEGIN PUBLIC KEY-----(.*?)-----END", pem, re.S).group(1).split())
            # the kit's fingerprint (keys/README.md) is the first 16 hex of SHA-256 over the .pub file text
            keys[hashlib.sha256(pem.encode()).hexdigest()[:16]] = {"alg": "EdDSA", "public_key": base64.b64decode(b64)[-32:].hex()}
        trust = {"apc_signer_trust": 1, "keys": keys, "authorized": [{"origin": "https://x.example", "signers": ["x"]}]}
        b = load(V002)
        b["draft_artifacts"] = [{"profile": d3.P3868, "artifact": {"preimage": v["preimage"], "receipt_hash": v["expected_receipt_hash"],
                                                                  "signature": v["signature"], "notary_fp": v["notary_fp"]}}
                                for v in vecs]
        ck = av.verify_bundle(copy.deepcopy(b), drafts=True, signer_trust=trust)["drafts"][d3.P3868]["checks"]
        self.assertEqual(len(vecs), 12)
        for i in range(12):
            self.assertEqual((ck["BV1[%d]" % i], ck["BV2[%d]" % i]), ("verified", "verified"), i)
            self.assertEqual(ck["BV3[%d]" % i], "not_evaluated:record_names_no_settlement_of_this_bundle")
        b["draft_artifacts"][0]["artifact"]["preimage"] += " "
        ck = av.verify_bundle(copy.deepcopy(b), drafts=True, signer_trust=trust)["drafts"][d3.P3868]["checks"]
        self.assertEqual(ck["BV1[0]"], "failed:record_hash_mismatch")


class Pr2853(unittest.TestCase):
    def test_record_digest_vectors(self):
        for inp, dg in (({"b": "x", "a": 1}, "0x84fc3d9faf736ddfdb9baab9973656bd8d9bd142f1dfff8aa513a774fddfdd04"),
                        ({"10": "a", "2": "b", "1": "c"}, "0x426b770f81b8ad5e307bcfb767deb02f8d32cd340d81a946be88bb184857e81b"),
                        ({"tax": {"amount": "1.10"}, "issuedAt": 1735689600},
                         "0x81086b5801b1bfd992e4d1e929f54907e0d3be0e8ede94f1da1a954b4e78b250")):
            self.assertEqual(d3.record_digest(inp), dg)
        self.assertFalse(d3._numbers_ok({"tax": {"amount": 1.1}}))
        self.assertFalse(d3._numbers_ok({"lines": [{"quantity": 2}]}))
        self.assertTrue(d3._numbers_ok({"issuedAt": 1735689600, "settlement": {"fiat": {"asOf": 1}}}))

    def test_attestation(self):
        from lib.secp256k1 import sign
        import hashlib
        d = load(V002)
        rec = {"version": 1, "canonicalizationVersion": 1, "receiptDigest": "0x" + "00" * 32, "issuedAt": 1790082990,
               "issuer": {"name": "Example GmbH", "jurisdiction": "DE-VAT"}, "supply": {"description": "API call"},
               "tax": {"scheme": "none", "currency": "EUR"}, "retentionYears": 10,
               "settlement": {"txHash": d["settlement"]["transaction"]}}
        pl = {"version": 1, "recordDigest": d3.record_digest(rec), "receiptDigest": rec["receiptDigest"], "issuedAt": rec["issuedAt"]}
        dig = av.signing_digest({"name": "compliance-fields", "version": "1", "chainId": 1}, "ComplianceAttestation",
                                d3.ATTEST_TYPES, pl)
        key = int.from_bytes(hashlib.sha256(b"pr2853 key").digest(), "big") % av.SECP_N
        r, s, rec_id = sign(dig, key, int.from_bytes(hashlib.sha256(dig).digest(), "big") % av.SECP_N)
        att = {"format": "eip712", "payload": pl,
               "signature": "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + rec_id]).hex()}
        d["settlement"]["extensions"] = {"compliance-fields": {"info": {"record": rec, "attestation": att}}}
        ck = av.verify_bundle(copy.deepcopy(d), drafts=True)["drafts"][d3.P2853]["checks"]
        self.assertEqual((ck["CF1"], ck["CF2"], ck["CF6"]), ("verified", "verified", "verified"))
        self.assertTrue(ck["CF4"].startswith("verified (signer 0x"))
        rec2 = dict(rec, retentionYears=5)
        d["settlement"]["extensions"]["compliance-fields"]["info"]["record"] = rec2
        self.assertEqual(av.verify_bundle(d, drafts=True)["drafts"][d3.P2853]["checks"]["CF2"],
                         "failed:attestation_digests_mismatch")


if __name__ == "__main__":
    unittest.main()
