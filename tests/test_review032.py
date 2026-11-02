"""Independent review of SPEC Amendment 0.3.2 (2026-10-24): the cases the 0.3.2 tests did not pin (each kills a mutant of
the added lines that survived them) and the corrections: success not a boolean, settlement_pending, a high-s signature
the token accepted on chain."""
import copy
import glob
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from tests import real_corpus  # noqa: E402
real_corpus.need("real_issue1062", "real_v02", "real_v02_wallet")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402
from test_apc03 import load, run  # noqa: E402

N = av.SECP_N
ISSUE = os.path.join(ROOT, "bundles", "real_issue1062", "issue1062_envelope_reconstructed.json")
REASON = "failed:settlement_reported_failed_but_executed_on_chain"
V02_DIRECT = [p for p in sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02", "*.json"))) if "MANIFEST" not in p]


def t1_note(r):
    return [n for n in r["notes"] if n.startswith("T1:")]


def failed(d, tx, reason="settle_exact_node_failure"):
    e = copy.deepcopy(d)
    e["settlement"] = {"success": False, "errorReason": reason, "network": d["payment_payload"]["accepted"]["network"],
                       "transaction": tx}
    return e


def flip(h):
    b = bytes.fromhex(h[2:])
    s = int.from_bytes(b[32:64], "big")
    return "0x" + (b[:32] + (N - s).to_bytes(32, "big") + bytes([55 - b[64]])).hex()


def direct_v02():
    for p in V02_DIRECT:
        d = load(p)
        r = run(d)
        if "settlement" in d and r["checks"].get("C1") == "verified" and r["checks"].get("C3") == "verified":
            yield p, d


class HighSBoundary(unittest.TestCase):
    def test_s_exactly_half_is_low(self):
        """Circle ECRecover.sol 51-56 reverts on s > n/2 (0x7FFF...20A0 == n // 2): s == n // 2 is accepted"""
        self.assertEqual(N // 2, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
        d = load(ISSUE)
        frm = d["payment_payload"]["payload"]["authorization"]["from"].lower()
        sig = bytes.fromhex(d["payment_payload"]["payload"]["signature"][2:])
        for s, want in ((N // 2, "verified"), (N // 2 + 1, "failed:high_s_refused_by_token")):
            e = copy.deepcopy(d)
            del e["chain_tx"], e["settlement"]
            e["payment_payload"]["payload"]["signature"] = "0x" + (sig[:32] + s.to_bytes(32, "big") + sig[64:]).hex()
            with mock.patch.object(av, "recover_public_key", lambda *a: None), \
                    mock.patch.object(av, "public_key_to_address", lambda *a: frm):
                self.assertEqual(run(e)["checks"]["L2.sig"], want, hex(s))


class HighSAcceptedOnChain(unittest.TestCase):
    # the edited input no longer matches the transaction's own signature, so the sender check (SPEC Amendment 0.3.3)
    # is replaced by "verified" here to isolate the high-s rule; the sender check is tested in tests/test_sender.py
    @mock.patch.object(av, "_from_is_signer", lambda tx: "verified")
    def test_same_high_s_in_the_executed_transaction(self):
        """the transaction carries the very high-s signature and the token logged AuthorizationUsed: the token accepted
        it (payer with code, ERC-1271), so 'refused by the token' would be false"""
        d = load(ISSUE)
        d["settlement"] = {"success": True, "network": "eip155:8453", "transaction": d["settlement"]["transaction"]}
        pl = d["payment_payload"]["payload"]
        pl["signature"] = flip(pl["signature"])
        b = bytes.fromhex(d["chain_tx"]["tx"]["input"][2:])
        w = lambda i: b[4 + 32 * i: 4 + 32 * (i + 1)]  # noqa: E731
        v, s = int.from_bytes(w(6), "big"), int.from_bytes(w(8), "big")
        b = b[:4 + 32 * 6] + (55 - v).to_bytes(32, "big") + w(7) + (N - s).to_bytes(32, "big") + b[4 + 32 * 9:]
        tx = d["chain_tx"]["tx"]
        tx["input"] = "0x" + b.hex()
        tx["hash"] = d["chain_tx"]["log_authorization_used"]["transactionHash"] = d["settlement"]["transaction"] = \
            av.tx_hash_eip1559(tx)
        r = run(d)
        self.assertEqual((r["checks"]["C1"], r["checks"]["C2"]), ("verified", "verified"))
        self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:high_s_accepted_on_chain")
        self.assertEqual(r["checks"]["K3"], "not_evaluated:high_s_accepted_on_chain")
        self.assertEqual(r["verdict"], "chain_incomplete")
        e = copy.deepcopy(d)                                                   # the token's log not shown: no
        e["chain_tx"]["log_authorization_used"]["topics"][2] = "0x" + "00" * 32  # proof of acceptance
        r = run(e)
        self.assertEqual((r["checks"]["C1"], r["checks"]["C2"]), ("verified", "failed:log_nonce_mismatch"))
        self.assertEqual(r["checks"]["L2.sig"], "failed:high_s_refused_by_token")
        e = copy.deepcopy(d)                                                   # control: without the transaction
        del e["chain_tx"]
        e["settlement"]["transaction"] = load(ISSUE)["settlement"]["transaction"]
        self.assertEqual(run(e)["checks"]["L2.sig"], "failed:high_s_refused_by_token")


class SettlementReply(unittest.TestCase):
    def test_success_not_a_boolean_refused(self):
        for val in ("true", "false", 1, 0, None, [], {}, 1.0):
            d = load(ISSUE)
            d["settlement"]["success"] = val
            self.assertEqual(run(d)["verdict"], "refused", repr(val))

    def test_settlement_pending(self):
        """x402 v2 section 9: settlement_pending is non-terminal and MUST carry the broadcast hash"""
        d = failed(load(ISSUE), load(ISSUE)["settlement"]["transaction"], "settlement_pending")
        r = run(d)
        self.assertEqual(r["checks"]["T1"], "not_evaluated:settlement_pending_executed_on_chain")
        self.assertEqual(r["verdict"], "chain_incomplete")
        self.assertIn("non-terminal", t1_note(r)[0])
        e = copy.deepcopy(d)
        del e["chain_tx"]
        self.assertEqual(run(e)["checks"]["T1"], "not_evaluated:settlement_pending")
        e["settlement"]["transaction"] = ""
        self.assertEqual(run(e)["checks"]["T1"], "failed:settlement_pending_without_transaction_hash")

    def test_reply_with_no_hash_names_nothing(self):
        """x402 v2 5.3.2: transaction is the empty string when nothing was broadcast; not a hash, so no name"""
        for tx in ("", "0x12", "0x" + "ab" * 31):
            r = run(failed(load(ISSUE), tx))
            self.assertEqual(r["checks"]["T1"], REASON, tx)
            self.assertNotIn("names", t1_note(r)[0], tx)

    def test_hash_case_ignored(self):
        d = load(ISSUE)
        h = d["chain_tx"]["tx"]["hash"]
        up = "0x" + h[2:].upper()
        r = run(failed(d, up))
        self.assertIn("it is the transaction the reply names", t1_note(r)[0])
        e = failed(d, h)
        e["chain_tx"]["tx"]["hash"] = up
        e["chain_tx"]["log_authorization_used"]["transactionHash"] = up
        r = run(e)
        self.assertEqual(r["checks"]["C2"], "verified")
        self.assertIn("it is the transaction the reply names", t1_note(r)[0])

    def test_note_names_the_checks(self):
        self.assertIn("(C1-C2 verified)", t1_note(run(failed(load(ISSUE), "")))[0])
        p, d = next(direct_v02())
        self.assertIn("(C1-C2-C3 verified)", t1_note(run(failed(d, "")))[0], p)


class DirectV02(unittest.TestCase):
    def test_direct_c3_failed_not_executed(self):
        n = 0
        for p, d in direct_v02():
            e = failed(d, d["settlement"]["transaction"])
            lt = e["chain_tx"]["log_transfer"]
            lt["data"] = "0x" + "%064x" % (int(lt["data"], 16) + 1)
            r = run(e)
            self.assertEqual((r["checks"]["C1"], r["checks"]["C2"]), ("verified", "verified"), p)
            self.assertTrue(r["checks"]["C3"].startswith("failed"), p)
            self.assertEqual(r["checks"]["T1"], "failed:settlement_not_successful", p)
            n += 1
        self.assertGreater(n, 10)

    def test_direct_c3_absent_executed(self):
        """SPEC 0.3.2: C3 verified or absent"""
        p, d = next(direct_v02())
        e = failed(d, d["settlement"]["transaction"])
        del e["chain_tx"]["log_transfer"]
        r = run(e)
        self.assertEqual(r["checks"]["C3"], "not_evaluated:absent:no_log_transfer", p)
        self.assertEqual(r["checks"]["T1"], REASON, p)


class EmptyHexParam(unittest.TestCase):
    def test_0x_alone_is_hex_and_compared(self):
        """"0x" is 0x followed by (zero) hex digits: compared, not refused"""
        p = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02_wallet", "w_*.json")))[0]
        d = load(p)
        d["payer_wallet"]["owner"]["params"][0]["data"] = "0x"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:owner_params_0")


if __name__ == "__main__":
    unittest.main()
