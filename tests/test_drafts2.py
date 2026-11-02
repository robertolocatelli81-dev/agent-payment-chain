"""SPEC section 23: draft profiles of the second set (apc_drafts2.py), run only with --drafts, reported apart.
Oracles: four real Buyer Delivery Claims published as EAS attestations on Base, Optimism and Ethereum (PR 3604 9,
read by eth_call, sources/x402_prs_20261026/real_chain_reads.json); the PR 2666 settlement records and their real
Polygon transaction; PR 3186 receipts made and verified by that PR's own signing.ts and verify402 manifests signed as
its tests do (tests/data/drafts2_ref_vectors.json, tools/drafts2_oracle.ts); the PR 3830 worked example. The merged
verdict never changes."""
import base64
import copy
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm", "real_v03", files=("tests/data/drafts2_ref_vectors.json", "sources/x402_prs_20261026/real_chain_reads.json"))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_drafts2 as d2  # noqa: E402
import apc_verify as av  # noqa: E402

SRC = os.path.join(ROOT, "sources", "x402_prs_20261026")
with open(os.path.join(SRC, "real_chain_reads.json")) as _fh:
    READS = json.load(_fh)["calls"]
with open(os.path.join(ROOT, "tests", "data", "drafts2_ref_vectors.json")) as _fh:
    REF = json.load(_fh)
V002 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")
SVM = os.path.join(ROOT, "bundles", "real_svm", "m001_mainnet_payment_20261024.json")
KANON = os.path.join(ROOT, "sources", "kanon_3d49240", "x402-evm-eip3009-valid-baseline-001.json")
ANVIL0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def eas_claims():
    out = []
    for c in READS:
        if c["method"] != "eth_call":
            continue
        b = bytes.fromhex(c["result"][2:])
        t = b[int.from_bytes(b[:32], "big"):]
        doff = int.from_bytes(t[9 * 32:10 * 32], "big")
        data = t[doff + 32:doff + 32 + int.from_bytes(t[doff:doff + 32], "big")]
        so = int.from_bytes(data[32:64], "big")
        claim = data[so + 32:so + 32 + int.from_bytes(data[so:so + 32], "big")].decode("utf-8")
        out.append((data[:32].hex(), av.strict_json(claim)))
    return out


def run(doc, **kw):
    return av.verify_bundle(copy.deepcopy(doc), drafts=True, **kw)


def kanon_bundle():
    """The kanon valid baseline (payer = anvil account 0) with a settlement reply."""
    v = load(KANON)
    return {"bundle_version": "apc-0.1", "payment_payload": v["input"],
            "settlement": {"success": True, "transaction": "0x" + "ab" * 32, "network": "eip155:84532"}}


def eip191_sign(text):
    from lib.secp256k1 import sign
    m = text.encode()
    d = av.keccak256(b"\x19Ethereum Signed Message:\n" + str(len(m)).encode() + m)
    k = int.from_bytes(hashlib.sha256(d + b"k").digest(), "big") % av.SECP_N
    r, s, rec = sign(d, ANVIL0, k)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + rec]).hex()


class Pr3604(unittest.TestCase):
    def test_real_eas_claims(self):
        cl = eas_claims()
        self.assertEqual(len(cl), 4)
        for cid, c in cl:
            self.assertEqual("0x" + cid, c["claimId"])
            self.assertEqual(d2.claim_checks(c), {"DC1": "verified", "DC2": "verified", "DC3": "verified"})
        self.assertEqual(sorted(c["delivered"] for _, c in cl), ["no", "yes", "yes", "yes"])

    def test_tampered_and_bound(self):
        _, c = eas_claims()[0]
        t = dict(c, delivered="no")
        self.assertEqual(d2.claim_checks(t)["DC2"], "failed:claim_id_mismatch")
        d = load(V002)
        d["draft_artifacts"] = [{"profile": d2.P3604, "artifact": c}]
        r = run(d)
        ck = r["drafts"][d2.P3604]["checks"]
        self.assertEqual((ck["DC3[0]"], ck["DC4[0]"]), ("verified", "failed:buyer_not_the_payer"))
        self.assertEqual(r["verdict"], av.verify_bundle(load(V002))["verdict"])
        # a claim by the real payer of a bundle: built on the kanon baseline, whose payer is anvil account 0
        b = kanon_bundle()
        content = {"sellerAddress": b["payment_payload"]["accepted"]["payTo"].lower(),
                   "buyerAddress": b["payment_payload"]["payload"]["authorization"]["from"].lower(),
                   "assetType": "api-credits", "promisedSpec": "one call", "delivered": "yes",
                   "evidenceHash": "aa" * 32, "settlementRef": "0x" + "ab" * 32, "timestamp": "2026-10-26T08:00:00.000Z"}
        import apc_ap2
        cid = "0x" + hashlib.sha256(apc_ap2.canonical(content).encode()).hexdigest()
        claim = dict(content, claimId=cid, signature=eip191_sign(cid))
        b["draft_artifacts"] = [{"profile": d2.P3604, "artifact": claim}]
        r = run(b)
        self.assertEqual(r["drafts"][d2.P3604]["verdict"], "draft_met")
        self.assertEqual(r["notes"][-1][:22], "draft members carried,")


class Verify402(unittest.TestCase):
    def test_manifests(self):
        want = {"good": "draft_met", "other_payto": "draft_failed", "expired": "draft_failed", "other_chain": "draft_failed"}
        for m in REF["manifests"]:
            d = load(V002)
            d["draft_artifacts"] = [{"profile": d2.PV402, "artifact": m["artifact"]}]
            r = run(d)
            self.assertEqual(r["drafts"][d2.PV402]["verdict"], want[m["id"]], (m["id"], r["drafts"][d2.PV402]))
            self.assertEqual(r["drafts"][d2.PV402]["checks"]["VM2[0]"], "verified", m["id"])
        bad = copy.deepcopy(REF["manifests"][0]["artifact"])
        bad["seller"] = "attacker.example"
        d = load(V002)
        d["draft_artifacts"] = [{"profile": d2.PV402, "artifact": bad}]
        self.assertEqual(run(d)["drafts"][d2.PV402]["checks"]["VM2[0]"], "failed:manifest_signature_not_by_signer")


class Erc8004(unittest.TestCase):
    def test_proof_of_payment(self):
        d = load(V002)
        st = d["settlement"]
        f = {"agentRegistry": "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", "agentId": 22,
             "clientAddress": "eip155:8453:" + st["payer"], "createdAt": "2026-09-22T13:20:00Z", "value": 100,
             "valueDecimals": 0, "proofOfPayment": {"fromAddress": st["payer"], "toAddress": d["payment_payload"]["accepted"]["payTo"],
                                                   "chainId": "8453", "txHash": st["transaction"]}}
        d["draft_artifacts"] = [{"profile": d2.P8004, "artifact": f}]
        self.assertEqual(run(d)["drafts"][d2.P8004]["verdict"], "draft_met")
        f2 = copy.deepcopy(f)
        f2["proofOfPayment"]["txHash"] = "0x" + "00" * 32
        d["draft_artifacts"] = [{"profile": d2.P8004, "artifact": f2}]
        self.assertEqual(run(d)["drafts"][d2.P8004]["checks"]["FB5[0]"], "failed:tx_hash_not_the_settlement")


class Pr3741(unittest.TestCase):
    def test_method(self):
        d = load(V002)
        d["payment_payload"]["resource"] = {"url": "https://api.example.com/p", "method": "POST"}
        with self.assertRaises(av.Refusal):                 # the merged grammar does not know resource.method
            av.verify_bundle(copy.deepcopy(d))
        r = run(d)
        self.assertEqual(r["drafts"][d2.P3741]["checks"]["RM1"], "verified")
        self.assertEqual(r["drafts"][d2.P3741]["checks"]["RM2"], "not_evaluated:absent:no_exchange")
        d["payment_payload"]["resource"]["method"] = "post"
        self.assertEqual(run(d)["drafts"][d2.P3741]["checks"]["RM1"], "failed:method_not_an_uppercase_token")


class Pr3186(unittest.TestCase):
    def bundle(self, v):
        d = load(V002)
        d["payment_payload"]["resource"] = {"url": "https://api.example.com/premium-data"}
        d["settlement"]["extensions"] = {"offer-receipt": {"info": {"receipt": copy.deepcopy(v["artifact"])}}}
        body = base64.b64encode(v["body_raw"].encode()).decode()
        sig = base64.b64encode(json.dumps(d["payment_payload"]).encode()).decode()
        d["exchange"] = {"request": {"method": "GET", "target_uri": "https://api.example.com/premium-data",
                                     "fields": [["Host", "api.example.com"], ["PAYMENT-SIGNATURE", sig]]},
                         "response": {"status": 200, "fields": [["Content-Type", "application/json"]], "body": body}}
        return d

    def test_reference_receipts(self):
        for v in REF["receipts3186"]:
            kid = v.get("kid")
            trust = {"apc_signer_trust": 1, "authorized": [{"origin": "https://api.example.com",
                                                            "signers": [kid or v["ref_signer"].lower()]}]}
            d = self.bundle(v)
            r = run(d, signer_trust=trust)
            ck = r["drafts"][d2.P3186]["checks"]
            self.assertEqual(ck, {"DP1": "verified", "DP2": "verified", "DP3": "verified"}, v["id"])
            # the merged rules do not read version 2
            self.assertEqual(r["checks"]["OR2"], "not_evaluated:receipt_version_not_supported", v["id"])
            d["exchange"]["response"]["body"] = base64.b64encode(b'{"price":"1"}').decode()
            self.assertEqual(run(d, signer_trust=trust)["drafts"][d2.P3186]["checks"]["DP2"], "failed:response_hash_mismatch")


class Pr2666(unittest.TestCase):
    def records(self):
        with open(os.path.join(SRC, "pr2666.patch")) as fh:
            t = fh.read()
        import re
        blocks = re.findall(r"```json\n(.*?)```", "\n".join(l[1:] for l in t.split("\n") if l.startswith("+")), re.S)
        return [json.loads(b) for b in blocks if '"actionRef"' in b]

    def test_action_ref_and_chain(self):
        recs = self.records()
        self.assertEqual(len(recs), 3)                         # Sui example, Polygon merchant leg, Polygon fee leg
        for r in recs:
            self.assertEqual(d2.settlement_record_checks(r), {"SR1": "verified", "SR2": "verified"})
        bad = dict(recs[0], seq=2)
        self.assertEqual(d2.settlement_record_checks(bad)["SR2"], "failed:action_ref_mismatch")
        # the Polygon legs against the real transaction's JPYC Transfer logs
        rc = next(c["result"] for c in READS if c["method"] == "eth_getTransactionReceipt")
        topic = "0x" + av.keccak256(b"Transfer(address,address,uint256)").hex()
        legs = {("0x" + lg["topics"][2][-40:], int(lg["data"], 16)) for lg in rc["logs"]
                if lg["topics"][0] == topic and lg["address"].lower() == "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29"}
        for r in recs[1:]:
            self.assertIn((r["settlement"]["payTo"].lower(), int(r["settlement"]["amount"])), legs)


class Pr3830(unittest.TestCase):
    def test_worked_example(self):
        self.assertEqual(d2.svm_memo_commitment("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                                                "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", b"9f1c0b7a4e52d386",
                                                "0x8f2b1d4e6a0c93758e1fb2a4c6d80e5f3719ab42cd6e805f1a3b7c9d2e4f6081"),
                         "0xffb8966ec1d5565bd0580f4f007d99c0162a88476f69b3e79cb95246b4175c59")

    def test_real_solana_memo_link(self):
        import apc_solana as sol
        d = load(SVM)
        rep = av.verify_bundle(copy.deepcopy(d))
        salt = "0x" + hashlib.sha256(b"pr3830 test salt").hexdigest()
        memo = d["payment_payload"]["accepted"]["extra"]["memo"].encode()
        com = d2.svm_memo_commitment(d["payment_payload"]["accepted"]["asset"], rep["payer"], memo, salt)
        seed = hashlib.sha256(b"pr3830 key").digest()
        pub = sol.ed25519_public(seed)
        kid = "did:key:z" + sol.b58encode(b"\xed\x01" + pub)
        pl = {"authorizationCommitment": com, "authorizationMethod": "svm-memo", "issuedAt": 1792990000,
              "network": d["payment_payload"]["accepted"]["network"], "payer": rep["payer"],
              "resourceUrl": "https://api.example.com/sol", "version": 2}
        import apc_ap2
        h = apc_ap2.b64u(json.dumps({"alg": "EdDSA", "kid": kid}).encode())
        p = apc_ap2.b64u(apc_ap2.canonical(pl).encode())
        sig = apc_ap2.b64u(sol.ed25519_sign(seed, (h + "." + p).encode()))
        d["payment_payload"]["resource"] = {"url": "https://api.example.com/sol"}
        d["settlement"]["extensions"] = {"offer-receipt": {"info": {"receipt": {"format": "jws", "signature": h + "." + p + "." + sig},
                                                                    "authorizationSalt": salt}}}
        r = run(d)
        self.assertEqual(r["drafts"][d2.P3830]["checks"]["DM2"], "verified")
        d["settlement"]["extensions"]["offer-receipt"]["info"]["authorizationSalt"] = "0x" + "00" * 32
        self.assertEqual(run(d)["drafts"][d2.P3830]["checks"]["DM2"], "not_evaluated:incomplete:payload_memo_does_not_open_it")


class Apart(unittest.TestCase):
    def test_draft_artifacts_never_change_the_verdict(self):
        _, c = eas_claims()[0]
        for p in (V002, SVM):
            d = load(p)
            base = av.verify_bundle(copy.deepcopy(d))
            d["draft_artifacts"] = [{"profile": d2.P3604, "artifact": c}, {"profile": "unknown-profile", "artifact": 1}]
            for drafts in (False, True):
                r = av.verify_bundle(copy.deepcopy(d), drafts=drafts)
                self.assertEqual({k: v for k, v in r.items() if k not in ("drafts", "notes")},
                                 {k: v for k, v in base.items() if k != "notes"})
        for bad in ([], {}, [{"profile": 1, "artifact": 1}], [{"profile": "x"}]):
            d = load(V002)
            d["draft_artifacts"] = bad
            with self.assertRaises(av.Refusal):
                av.verify_bundle(d)


if __name__ == "__main__":
    unittest.main()
