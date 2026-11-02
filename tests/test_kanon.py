"""External oracle: the EIP-3009 vectors of iamonuwa/kanon @3d49240 (Apache-2.0; copies, reason-code registry 2.0.0 and
SHA256SUMS in sources/kanon_3d49240), a corpus written by others with expected verdicts. Each vector's `input` is an
x402 v2 PaymentPayload; it becomes the payment_payload of an apc-0.1 bundle. Mapping of their reason codes to our checks:
VALID -> L2.sig, K1, K2, K3 verified; SIG_MALLEABLE -> L2.sig failed:high_s_refused_by_token (USDC on Base Sepolia is
measured, Amendment 0.3.2); SIGNER_MISMATCH -> L2.sig failed:recovers_*; AMOUNT_INSUFFICIENT -> K2 failed (exact
equality, x402 scheme_exact.md); NETWORK_MISMATCH: their target network is the verifier's context, carried here as
settlement.network -> T2 failed. Not comparable, said and counted: NOT_YET_VALID and EXPIRED need their
context.verification_time and NONCE_REPLAY their context.seen_nonces, a verifier's clock and state that an evidence
bundle does not carry (B4 judges the window at the block time; D2/D3 judge replay across bundles)."""
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_verify as av  # noqa: E402

VECS = sorted(glob.glob(os.path.join(ROOT, "sources", "kanon_3d49240", "x402-evm-eip3009-*.json")))
NOT_COMPARABLE = {"NOT_YET_VALID", "EXPIRED", "NONCE_REPLAY"}


def bundle(v):
    d = {"bundle_version": "apc-0.1", "payment_payload": v["input"]}
    if v["network"] != v["input"]["accepted"]["network"]:
        d["settlement"] = {"success": True, "transaction": "0x" + "00" * 32, "network": v["network"]}
    return d


class Kanon(unittest.TestCase):
    def test_corpus(self):
        agree, skipped = [], []
        for p in VECS:
            with open(p) as fh:
                v = av.strict_json(fh.read())
            code = v["expected"]["reason_code"]
            if code in NOT_COMPARABLE:
                skipped.append(v["id"])
                continue
            c = av.verify_bundle(bundle(v))["checks"]
            got = {"VALID": all(c[k].startswith("verified") for k in ("L2.sig", "K1", "K2", "K3")),
                   "SIG_MALLEABLE": c["L2.sig"] == "failed:high_s_refused_by_token",
                   "SIGNER_MISMATCH": c["L2.sig"].startswith("failed:recovers_"),
                   "AMOUNT_INSUFFICIENT": c["K2"].startswith("failed") and c["L2.sig"] == "verified",
                   "NETWORK_MISMATCH": c.get("T2", "").startswith("failed")}[code]
            self.assertTrue(got, (v["id"], code, c))
            agree.append(v["id"])
        self.assertEqual((len(agree), len(skipped)), (7, 3))


if __name__ == "__main__":
    unittest.main()
