"""SPEC section 17: draft profiles of proposed x402 rules (apc_verify --drafts). Oracles: the commit and link vectors of
x402 PR 3827 (babyblueviper1/preaction-governance-conformance 0a818e7, sources/x402_pr3827_20261026); the real
self-payment bundle v004 of bundles/real_v03. The drafts never change checks, verdict or exit code."""
import copy
import glob
import hashlib
import json
import os
import random
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_drafts as dr  # noqa: E402
import apc_offer as ao  # noqa: E402
import apc_verify as av  # noqa: E402

VEC_DIR = os.path.join(ROOT, "sources", "x402_pr3827_20261026")
with open(os.path.join(VEC_DIR, "vectors.json")) as _fh:
    VEC = json.load(_fh)["vectors"]
with open(os.path.join(VEC_DIR, "candidates_snapshot.json")) as _fh:
    SNAP = json.load(_fh)
V002 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")
V004 = os.path.join(ROOT, "bundles", "real_v03", "v004_b103_indirect_envelope_reconstructed.json")
KEY = int.from_bytes(hashlib.sha256(b"apc receipt v2 test key").digest(), "big") % av.SECP_N
SALT = "0x" + hashlib.sha256(b"fixed test salt, real salts are CSPRNG (PR 3827 5.6.3)").hexdigest()


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


class Pr3827Vectors(unittest.TestCase):
    def test_commit_vectors(self):
        n = 0
        for v in VEC:
            if v["kind"] != "commit":
                continue
            exp = v["expect"]
            if "commitment" in exp:
                self.assertEqual(dr.commitment(v["method"], v["asset"], v["authorizer"], v["nonce"], v["salt"]),
                                 exp["commitment"], v["id"])
            else:
                with self.assertRaises(ValueError) as cm:
                    dr.commitment(v["method"], v["asset"], v["authorizer"], v["nonce"], v["salt"])
                self.assertEqual(str(cm.exception), exp["malformed"], v["id"])
            n += 1
        self.assertEqual(n, 12)

    def test_link_vectors(self):
        cands = [c["nonce"] for c in SNAP["candidates"]]
        n = 0
        for v in VEC:
            if v["kind"] != "link":
                continue
            r, nonce = dr.link(v["commitment"], v["method"], v["asset"], v["authorizer"], v["salt"], cands)
            self.assertEqual(r, v["expect"]["result"], v["id"])
            if r == "linked":
                self.assertEqual(nonce, v["expect"]["nonce"])
            n += 1
        self.assertEqual(n, 5)


def sign_receipt_v2(pl):
    from lib.secp256k1 import sign
    msg = dict({"transaction": "", "authorizationMethod": "", "authorizationCommitment": ""}, **pl)
    d = av.signing_digest({"name": "x402 receipt", "version": "1", "chainId": 1}, "Receipt", dr.RECEIPT_V2_TYPES, msg)
    k = int.from_bytes(hashlib.sha256(d + b"k").digest(), "big") % av.SECP_N
    r, s, rec = sign(d, KEY, k)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + rec]).hex()


def signer():
    from lib.secp256k1 import _mul, GX, GY
    return ao.evm_address(_mul(KEY, (GX, GY)))


def v2_bundle(salt=SALT, commit=True, method="eip3009", tx=None, info_salt=True):
    d = load(V002)
    au = d["payment_payload"]["payload"]["authorization"]
    url = "https://api.example.com/premium-data"
    d["payment_payload"]["resource"] = {"url": url}
    pl = {"version": 2, "network": "eip155:8453", "resourceUrl": url, "payer": au["from"], "issuedAt": 1792990000,
          "transaction": tx or "", "authorizationMethod": method if commit else "",
          "authorizationCommitment": dr.commitment("eip3009", d["payment_payload"]["accepted"]["asset"], au["from"],
                                                   au["nonce"], salt) if commit else ""}
    info = {"receipt": {"format": "eip712", "payload": pl, "signature": sign_receipt_v2(pl)}}
    if info_salt:
        info["authorizationSalt"] = SALT
    d["settlement"]["extensions"] = {"offer-receipt": {"info": info}}
    return d


def trust():
    return {"apc_signer_trust": 1, "authorized": [{"origin": "https://api.example.com", "signers": [signer()]}]}


class Pr3827Bundles(unittest.TestCase):
    def dr2(self, d):
        r = av.verify_bundle(d, signer_trust=trust(), drafts=True)
        return r, r["drafts"][dr.P3827]["checks"]

    def test_linked_and_kept_apart(self):
        r, c = self.dr2(v2_bundle())
        self.assertEqual(c, {"DR1": "verified", "DR2": "verified", "DR3": "verified"})
        self.assertEqual(r["drafts"][dr.P3827]["verdict"], "draft_met")
        # the merged rules do not read version 2 nor authorizationSalt: not evaluated there, and the verdict says so
        self.assertEqual(r["checks"]["OR2"], "not_evaluated:receipt_member_not_supported(info.authorizationSalt)")
        self.assertEqual(r["verdict"], "chain_incomplete")
        r0 = av.verify_bundle(v2_bundle(), signer_trust=trust())
        self.assertEqual((r0["checks"], r0["verdict"]), (r["checks"], r["verdict"]))
        self.assertNotIn("drafts", r0)
        d = v2_bundle()
        del d["settlement"]["extensions"]["offer-receipt"]["info"]["authorizationSalt"]
        self.assertEqual(av.verify_bundle(d, signer_trust=trust())["checks"]["OR2"],
                         "not_evaluated:receipt_version_not_supported")

    def test_link_outcomes(self):
        tx = load(V002)["chain_tx"]["tx"]["hash"]
        for d, want in ((v2_bundle(tx=tx), "verified"),
                        (v2_bundle(tx="0x" + "11" * 32), "failed:inconsistent"),
                        (v2_bundle(salt="0x" + "22" * 32), "not_evaluated:incomplete:bundle_authorization_does_not_open_it"),
                        (v2_bundle(commit=False), "not_evaluated:not_attempted:no_commitment"),
                        (v2_bundle(method="svm-memo"), "not_evaluated:not_attempted:method_not_implemented"),
                        (v2_bundle(info_salt=False), "not_evaluated:not_attempted:no_salt")):
            self.assertEqual(self.dr2(d)[1]["DR2"], want)
        d = v2_bundle()
        pl = d["settlement"]["extensions"]["offer-receipt"]["info"]["receipt"]["payload"]
        pl["authorizationMethod"] = ""
        d["settlement"]["extensions"]["offer-receipt"]["info"]["receipt"]["signature"] = sign_receipt_v2(pl)
        self.assertEqual(self.dr2(d)[1]["DR2"], "failed:malformed:one_of_method_and_commitment")
        # a forged payload recovers another signer: the reader's trust does not list it, the profile fails
        d = v2_bundle()
        d["settlement"]["extensions"]["offer-receipt"]["info"]["receipt"]["payload"]["issuedAt"] += 1
        r, c = self.dr2(d)
        self.assertEqual(c["DR3"], "failed:signer_not_authorized")
        self.assertEqual(r["drafts"][dr.P3827]["verdict"], "draft_failed")


class Others(unittest.TestCase):
    def test_pr3910_real_self_payment(self):
        r = av.verify_bundle(load(V004), drafts=True)
        self.assertEqual(r["drafts"][dr.P3910]["checks"], {"DS1": "failed:invalid_self_payment"})
        self.assertEqual(r["verdict"], "chain_verified")         # the merged rules report it only (payer_is_payee)
        self.assertEqual(av.verify_bundle(load(V002), drafts=True)["drafts"][dr.P3910]["checks"], {"DS1": "verified"})

    def test_pr3925_low_s_every_token(self):
        d = load(V002)
        sig = bytes.fromhex(d["payment_payload"]["payload"]["signature"][2:])
        s = av.SECP_N - int.from_bytes(sig[32:64], "big")
        d["payment_payload"]["payload"]["signature"] = "0x" + (sig[:32] + s.to_bytes(32, "big") + bytes([27 + ((sig[64] - 27) ^ 1)])).hex()
        d.pop("chain_tx"), d.pop("inclusion")
        r = av.verify_bundle(d, drafts=True)
        self.assertEqual(r["drafts"][dr.P3925]["checks"]["DV1"], "failed:high_s")
        self.assertEqual(r["drafts"][dr.P3925]["checks"]["DV2"], "verified")
        r = av.verify_bundle(load(V002), drafts=True)
        self.assertEqual(r["drafts"][dr.P3925]["checks"]["DV1"], "verified")
        self.assertEqual(r["drafts"][dr.P3925]["verdict"], "draft_incomplete")     # DV5 is a set check

    def test_drafts_never_change_the_verdict(self):
        paths = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "*", "*.json")) if "MANIFEST" not in p)
        rnd = random.Random(15)
        for p in rnd.sample(paths, 25):
            d = load(p)
            try:
                a = av.verify_bundle(copy.deepcopy(d))
            except av.Refusal:
                continue
            b = av.verify_bundle(copy.deepcopy(d), drafts=True)
            self.assertEqual({k: v for k, v in b.items() if k != "drafts"}, a, p)

    def test_permit2_bundles_unchanged(self):
        """Independent review 27/10: the 6 real apc-0.10 bundles were `unsupported` (exit 3) with --drafts: the PR 3925 profile read
        them by the apc-0.1 parser and its Unsupported left the draft run (section 17: never the verdict)"""
        paths = sorted(p for p in glob.glob(os.path.join(ROOT, "bundles", "real_permit2", "*.json")) if "MANIFEST" not in p)
        self.assertEqual(len(paths), 6)
        for p in paths:
            a = av.verify_bundle(load(p))
            b = av.verify_bundle(load(p), drafts=True)
            self.assertEqual({k: v for k, v in b.items() if k != "drafts"}, a, p)
            self.assertTrue(b["drafts"][dr.P3925]["checks"]["bundle"].startswith("not_evaluated:not_read_by_the_profile("), p)

    def test_cli_exit_code_unchanged(self):
        env = dict(os.environ, PYTHONPATH="")
        for flags in ([], ["--drafts"]):
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), V004] + flags,
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, flags)
            self.assertEqual("drafts" in json.loads(r.stdout), bool(flags))


if __name__ == "__main__":
    unittest.main()
