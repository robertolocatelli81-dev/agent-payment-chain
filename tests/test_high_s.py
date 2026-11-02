"""SPEC Amendment 0.3.2: an EOA signature with s > n/2 is refused by the deployed Base USDC (measured by eth_call,
tools/probe_lows_usdc.py), so L2.sig is not verified. Real data: every real bundle of the corpus with a 65-byte
signature, turned high-s (s' = n - s, v flipped: it still recovers to authorization.from)."""
import copy
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402
from test_apc03 import load, real_bundles, run  # noqa: E402

N = av.SECP_N
BASE_USDC = ("eip155:8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")     # measured, SPEC Amendment 0.3.2
# EVM bundles only: apc-0.5 (SPEC 0.5, Solana) carries no EIP-3009 signature
# settled EIP-3009 payments only: bundles/real_negatives_20261026 holds chain-reverted calls (tests/test_negatives reads
# them); apc-0.10 is Permit2, which verifies by ecrecover with no s rule (SPEC section 27, note [g]): no high-s rule
REAL = [p for p in real_bundles("evm") if "/real_negatives_" not in p and load(p)["bundle_version"] != "apc-0.10"]


def eoa_bundles():
    out = []
    for p in REAL:
        d = load(p)
        sig = d["payment_payload"]["payload"]["signature"]
        # a 65-byte signature of an account without code: not the ERC-6492 form, and not a contract wallet's (SPEC 32:
        # bundles/real_msca_20261101 carry payer_state; their high-s twin is failed:msca_high_s, tests/test_msca.py)
        if len(sig) == 132 and not sig.endswith("6492" * 16) and "payer_state" not in d:
            out.append((p, d))
    return out


def high_s(d):
    e = copy.deepcopy(d)
    pl = e["payment_payload"]["payload"]
    b = bytes.fromhex(pl["signature"][2:])
    s = int.from_bytes(b[32:64], "big")
    pl["signature"] = "0x" + (b[:32] + (N - s).to_bytes(32, "big") + bytes([55 - b[64]])).hex()
    return e


class HighS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = eoa_bundles()

    def test_corpus_is_real_and_low_s(self):
        """every real settled payment carries a low s (a high one could not have settled on USDC)"""
        self.assertGreater(len(self.cases), 100)
        for p, d in self.cases:
            s = int(d["payment_payload"]["payload"]["signature"][66:130], 16)
            self.assertLessEqual(s, N // 2, p)
            self.assertEqual(run(d)["checks"]["L2.sig"], "verified", p)

    def test_high_s_fails_on_base_usdc(self):
        for p, d in self.cases:
            acc = d["payment_payload"]["accepted"]
            r = run(high_s(d))
            if (acc["network"], acc["asset"].lower()) == BASE_USDC:
                self.assertEqual(r["checks"]["L2.sig"], "failed:high_s_refused_by_token", p)
                self.assertTrue(r["checks"]["K3"].startswith("failed"), p)
                self.assertNotIn(r["verdict"], ("verified", "chain_verified"), p)
            else:
                self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:high_s_token_rule_not_measured", p)
            self.assertTrue(any("upper half" in n and "low-s twin" in n for n in r["notes"]), p)

    def test_measured_list(self):
        # Amendment 0.3.2 measured these two; Amendment 0.11.5 (apc_assets.py, tests/test_world.py) added ten more
        self.assertTrue({BASE_USDC, ("eip155:84532", "0x036cbd53842c5426634e7929541ec2318f3dcf7e")} <= av.HIGH_S_REFUSED)
        self.assertEqual(len(av.HIGH_S_REFUSED), 12)

    def test_other_token_not_evaluated(self):
        """an asset outside the measured list: the rule is not known, so not verified and not failed"""
        p, d = self.cases[0]
        with mock.patch.object(av, "HIGH_S_REFUSED", set()):
            r = run(high_s(d))
        self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:high_s_token_rule_not_measured", p)

    def test_wrong_signer_still_fails_first(self):
        """a high-s signature that recovers to someone else is a wrong signer, as before"""
        p, d = self.cases[0]
        e = high_s(d)
        pl = e["payment_payload"]["payload"]
        pl["signature"] = pl["signature"][:4] + ("0" if pl["signature"][4] != "0" else "1") + pl["signature"][5:]
        self.assertTrue(run(e)["checks"]["L2.sig"].startswith(("failed:recovers_", "failed:no_recovery")), p)


if __name__ == "__main__":
    unittest.main()
