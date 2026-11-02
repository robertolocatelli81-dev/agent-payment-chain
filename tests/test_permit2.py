"""SPEC 0.10 (section 12): x402 exact on EVM by Permit2 or ERC-7710, bundle apc-0.10. Real data: the 231 x402 Permit2
settlements on Base in blocks 52301786-53101785 (oracle/permit2_base_20261026, envelope reconstructed from the
calldata, tools/make_bundles_permit2.py) and one real MetaMask DelegationManager redemption (approve shape). Built here,
signed with a TEST key: the Permit2 cases absent from the real set (other spender, empty window, zero amount) and every
ERC-7710 bundle (no real x402 ERC-7710 payment was found, SPEC 12.3). Every rule is also broken one way at a time."""
import base64
import copy
import io
import json
import os
import random
import sys
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real", "real_permit2", oracle=("permit2_base_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402
import apc_permit2 as p2  # noqa: E402
import apc_batch  # noqa: E402
from tools.make_bundles_permit2 import build, load  # noqa: E402
from lib.eip712 import signing_digest  # noqa: E402
from lib.secp256k1 import sign  # noqa: E402

ORACLE = os.path.join(ROOT, "oracle", "permit2_base_20261026")
_REAL = None
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
TEST_KEY = 0x4646464646464646464646464646464646464646464646464646464646464646      # a TEST key, never a real one
TEST_ADDR = None


def real():
    global _REAL
    if _REAL is None:
        out, skipped = build(load(os.path.join(ORACLE, "proxy_txs.json.gz")))
        assert not skipped
        _REAL = out
    return _REAL


def real_one(name):
    return copy.deepcopy(dict(real())[name])


def run(d):
    try:
        return av.verify_bundle(d)
    except av.Unsupported as e:
        return {"verdict": "unsupported", "reason": str(e)}
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e)}


def chk(d, k):
    return run(d)["checks"][k]


def P(d):
    return d["payment_payload"]["payload"]["permit2Authorization"]


def w(n):
    return n.to_bytes(32, "big")


def a32(addr):
    return bytes(12) + bytes.fromhex(addr[2:])


def test_addr():
    global TEST_ADDR
    if TEST_ADDR is None:
        from lib.eip712 import keccak256
        from lib.secp256k1 import _mul, GX, GY, public_key_to_address
        TEST_ADDR = public_key_to_address(_mul(TEST_KEY, (GX, GY)), keccak256)
    return TEST_ADDR


def built_permit2(**over):
    """A permit2 payload signed by the TEST key (no chain_tx)."""
    au = {"token": USDC, "amount": 10000, "from": test_addr(), "spender": p2.EXACT_PROXY, "nonce": 7, "deadline": 2000,
          "to": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "validAfter": 1000}
    au.update(over)
    r, s, rec = sign(p2.permit2_digest(8453, au), TEST_KEY, 0x1234567)
    sig = "0x" + w(r).hex() + w(s).hex() + bytes([27 + rec]).hex()
    acc = {"scheme": "exact", "network": "eip155:8453", "amount": str(au["amount"]), "asset": au["token"],
           "payTo": au["to"], "maxTimeoutSeconds": 60, "extra": {"assetTransferMethod": "permit2"}}
    return {"bundle_version": "apc-0.10", "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
        "signature": sig, "permit2Authorization": {"permitted": {"token": au["token"], "amount": str(au["amount"])},
                                                   "from": au["from"], "spender": au["spender"], "nonce": str(au["nonce"]),
                                                   "deadline": str(au["deadline"]),
                                                   "witness": {"to": au["to"], "validAfter": str(au["validAfter"])}}}}}


# ---------------------------------------------------------------- ERC-7710, built (stated: no real x402 one exists)
MANAGER = "0xdb9b1e94b5b69df7e401ddbede43491141047db3"
DELEGATOR = "0x857b06519e91e3a54538791bdbb0e22373e36b66"
PAYTO = "0x209693bc6afc0c5328ba36faf03c514ef312287c"
CONTEXT = bytes(range(1, 70))


def ecd(target=USDC, value=0, to=PAYTO, amount=10000, sel=p2.SEL_TRANSFER):
    return bytes.fromhex(target[2:]) + w(value) + sel + a32(to) + w(amount)


def redeem_input(pc=CONTEXT, mode=bytes(32), e=None):
    e = ecd() if e is None else e
    return "0x" + (p2.SEL_REDEEM + p2._abi_canonical_redeem(pc, mode, e)).hex()


def built_7710(inp=None, transfer_from=DELEGATOR, to=None):
    acc = {"scheme": "exact", "network": "eip155:8453", "amount": "10000", "asset": USDC, "payTo": PAYTO,
           "maxTimeoutSeconds": 60, "extra": {"assetTransferMethod": "erc7710"}}
    tx = {"type": "0x2", "chainId": "0x2105", "nonce": "0x1", "maxPriorityFeePerGas": "0x1", "maxFeePerGas": "0x2",
          "gas": "0x30000", "to": to or MANAGER, "value": "0x0", "input": inp or redeem_input(), "accessList": [],
          "yParity": "0x0", "r": "0x1", "s": "0x1", "blockHash": "0x" + "ab" * 32, "blockNumber": "0x100"}
    tx["hash"] = av.tx_hash_eip1559(tx)
    pad = "0x" + "0" * 24
    lt = {"address": USDC, "topics": [p2.TRANSFER_TOPIC, pad + transfer_from[2:], pad + PAYTO[2:]],
          "data": "0x" + w(10000).hex(), "transactionHash": tx["hash"], "blockHash": tx["blockHash"],
          "blockNumber": tx["blockNumber"], "logIndex": "0x5", "removed": False}
    return {"bundle_version": "apc-0.10",
            "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
                "delegationManager": MANAGER, "permissionContext": "0x" + CONTEXT.hex(), "delegator": DELEGATOR}},
            "settlement": {"success": True, "transaction": tx["hash"], "network": "eip155:8453", "payer": DELEGATOR},
            "chain_tx": {"network": "eip155:8453", "tx": tx, "log_transfer": lt}}


class Constants(unittest.TestCase):
    def test_type_hash_and_domain(self):
        self.assertEqual(p2.PERMIT_WITNESS_TYPEHASH, p2.keccak256(
            b"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,"
            b"Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)"))
        with open(os.path.join(ORACLE, "onchain_constants_base.json")) as fh:
            on = {c.get("what"): c.get("result") for c in json.load(fh)["calls"]}
        dom = p2.keccak256(p2.DOMAIN3_TYPEHASH + p2.PERMIT2_NAME_HASH + w(8453) + a32(p2.PERMIT2))
        self.assertEqual("0x" + dom.hex(), on["DOMAIN_SEPARATOR()"])          # measured on Base
        self.assertEqual("0x" + p2.WITNESS_TYPEHASH.hex(), on["WITNESS_TYPEHASH()"])
        self.assertEqual(on["PERMIT2()"], "0x" + a32(p2.PERMIT2).hex())

    def test_digest_equals_generic_eip712(self):
        """An independent path: the generic EIP-712 encoder of x402-signature-vectors, nested types."""
        T = {"PermitWitnessTransferFrom": [{"name": "permitted", "type": "TokenPermissions"},
                                           {"name": "spender", "type": "address"}, {"name": "nonce", "type": "uint256"},
                                           {"name": "deadline", "type": "uint256"}, {"name": "witness", "type": "Witness"}],
             "TokenPermissions": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}],
             "Witness": [{"name": "to", "type": "address"}, {"name": "validAfter", "type": "uint256"}]}
        D3 = [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
              {"name": "verifyingContract", "type": "address"}]
        for name in ("p001_envelope_reconstructed.json", "p005_envelope_reconstructed.json"):
            au = p2.parse_payload(real_one(name)["payment_payload"])["auth"]
            msg = {"permitted": {"token": au["token"], "amount": str(au["amount"])}, "spender": au["spender"],
                   "nonce": str(au["nonce"]), "deadline": str(au["deadline"]),
                   "witness": {"to": au["to"], "validAfter": str(au["validAfter"])}}
            g = signing_digest({"name": "Permit2", "chainId": 8453, "verifyingContract": p2.PERMIT2},
                               "PermitWitnessTransferFrom", T, msg, D3)
            self.assertEqual(g, p2.permit2_digest(8453, au))


class Real(unittest.TestCase):
    def test_all_real_settlements(self):
        verdicts = {}
        for name, b in real():
            r = av.verify_bundle(copy.deepcopy(b))
            sig = b["payment_payload"]["payload"]["signature"]
            verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
            for k in ("C1", "C2", "C3", "K1", "K2", "K5", "K6", "K7", "T1", "T2"):
                self.assertTrue(r["checks"][k].startswith("verified"), (name, k, r["checks"][k]))
            if len(sig) == 132:
                self.assertEqual(r["checks"]["L2.sig"], "verified", name)
                self.assertEqual(r["verdict"], "chain_verified", name)
            else:       # 66 bytes: EIP-7702 payers, Permit2 asked them by ERC-1271 (measured: code 0xef0100...)
                self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:unsupported_signature_length_66", name)
                self.assertEqual(r["verdict"], "chain_incomplete", name)
        self.assertEqual(verdicts, {"chain_verified": 212, "chain_incomplete": 19})

    def test_cli(self):
        for name, code in (("p001_envelope_reconstructed.json", 0), ("p029_envelope_reconstructed.json", 2)):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(av.main(["apc_verify.py", os.path.join(ROOT, "bundles", "real_permit2", name)]), code)

    def test_spec_example_does_not_recover_from(self):
        """x402 scheme_exact_evm.md section 2 example (Base Sepolia): its signature is illustrative."""
        pp = {"x402Version": 2, "accepted": {"scheme": "exact", "network": "eip155:84532", "amount": "10000",
                                             "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                                             "maxTimeoutSeconds": 60,
                                             "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                                             "extra": {"assetTransferMethod": "permit2", "name": "USDC", "version": "2"}},
              "payload": {"signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce64966"
                                       "42e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
                          "permit2Authorization": {
                              "permitted": {"token": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "amount": "10000"},
                              "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                              "spender": "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
                              "nonce": "33247007178036348590600198031289925668252061821958005840077069883511451257277",
                              "deadline": "1740672154",
                              "witness": {"to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                                          "validAfter": "1740672089"}}}}
        r = run({"bundle_version": "apc-0.10", "payment_payload": pp})
        self.assertEqual(r["checks"]["L2.sig"], "failed:recovers_0x468d6ad86c21a78c0c1f4f1fdc6c67616b9beb6f_not_from")
        self.assertEqual(r["checks"]["K7"], "verified")


class Broken(unittest.TestCase):
    """One change at a time on real bundles: p001 (settle), p005 (settleWithPermit)."""
    S, W = "p001_envelope_reconstructed.json", "p005_envelope_reconstructed.json"

    def b(self, name=None):
        return real_one(name or self.S)

    def test_envelope_links(self):
        d = self.b()
        d["payment_payload"]["accepted"]["payTo"] = "0x" + "11" * 20
        self.assertEqual(chk(d, "K1"), "failed:witness_to_payTo_mismatch")
        d = self.b()
        d["payment_payload"]["accepted"]["amount"] = "1"
        self.assertEqual(chk(d, "K2"), "failed:permitted_amount_amount_mismatch")
        d = self.b()
        d["payment_payload"]["accepted"]["asset"] = "0x" + "11" * 20
        self.assertEqual(chk(d, "K3"), "failed:permitted_token_not_asset")
        d = self.b()
        d["payment_payload"]["accepted"]["network"] = "eip155:1"
        r = run(d)
        self.assertTrue(r["checks"]["L2.sig"].startswith("failed:recovers_"))
        self.assertEqual(r["checks"]["K3"], "failed:by_L2.sig")
        self.assertEqual(r["checks"]["C1"], "failed:chain_tx_network_mismatch")

    def test_signed_members(self):
        for k, v in (("nonce", None), ("deadline", None), ("spender", "0x" + "22" * 20)):
            d = self.b()
            P(d)[k] = v or str(int(P(d)[k]) + 1)
            r = run(d)
            self.assertTrue(r["checks"]["L2.sig"].startswith("failed:recovers_"), k)
            self.assertEqual(r["verdict"], "chain_failed", k)
        d = self.b()
        P(d)["spender"] = "0x" + "22" * 20
        self.assertEqual(chk(d, "K7"), "failed:spender_not_x402_exact_permit2_proxy")
        d = self.b()
        P(d)["nonce"] = str(int(P(d)["nonce"]) + 1)
        self.assertEqual(chk(d, "C1"), "failed:tx_arguments_differ_from_authorization")
        d = self.b()
        P(d)["witness"]["validAfter"] = "1"
        self.assertTrue(chk(d, "L2.sig").startswith("failed:recovers_"))
        d = self.b()
        P(d)["witness"]["to"] = d["payment_payload"]["accepted"]["payTo"] = "0x" + "33" * 20
        r = run(d)
        self.assertTrue(r["checks"]["L2.sig"].startswith("failed:recovers_"))
        self.assertEqual(r["checks"]["K1"], "verified")
        self.assertEqual(r["checks"]["C1"], "failed:tx_arguments_differ_from_authorization")

    def test_signature_forms(self):
        d = self.b()
        s = d["payment_payload"]["payload"]["signature"]
        d["payment_payload"]["payload"]["signature"] = s[:-2] + "1d"
        self.assertEqual(chk(d, "L2.sig"), "failed:v_not_27_or_28")
        d = self.b()
        s = d["payment_payload"]["payload"]["signature"]
        d["payment_payload"]["payload"]["signature"] = s[:70] + ("0" if s[70] != "0" else "1") + s[71:]
        r = run(d)
        self.assertTrue(r["checks"]["L2.sig"].startswith("failed:"), r["checks"]["L2.sig"])
        self.assertEqual(r["checks"]["C1"], "failed:tx_signature_differs_from_payload")
        # EIP-2098 compact and the high-s twin of the REAL signature: both accepted by Permit2 (no chain_tx: the
        # transaction carries the 65-byte form)
        seen = set()
        for name, _ in real():          # both v values, so the EIP-2098 parity bit is exercised
            d = real_one(name)
            sig = bytes.fromhex(d["payment_payload"]["payload"]["signature"][2:])
            if len(sig) != 65 or sig[64] in seen:
                continue
            seen.add(sig[64])
            del d["chain_tx"]
            del d["settlement"]
            r_, s_, v = sig[:32], int.from_bytes(sig[32:64], "big"), sig[64]
            compact = r_ + ((s_ | ((v - 27) << 255)).to_bytes(32, "big"))
            d["payment_payload"]["payload"]["signature"] = "0x" + compact.hex()
            self.assertEqual(chk(d, "L2.sig"), "verified", name)
            if len(seen) == 2:
                break
        self.assertEqual(seen, {27, 28})
        twin = r_ + (av.SECP_N - s_).to_bytes(32, "big") + bytes([55 - v])
        d["payment_payload"]["payload"]["signature"] = "0x" + twin.hex()
        r = run(d)
        self.assertEqual(r["checks"]["L2.sig"], "verified")
        self.assertTrue(any("upper half" in n for n in r["notes"]))
        for n in (63, 66, 130):
            d["payment_payload"]["payload"]["signature"] = "0x" + "01" * n
            self.assertEqual(chk(d, "L2.sig"), "not_evaluated:unsupported_signature_length_%d" % n)
        d["payment_payload"]["payload"]["signature"] = "0x" + "01" * 40 + "64926492" * 8
        self.assertEqual(chk(d, "L2.sig"), "not_evaluated:erc6492_counterfactual_signature")

    def test_settlement(self):
        d = self.b()
        d["settlement"]["transaction"] = "0x" + "44" * 32
        self.assertEqual(chk(d, "C2"), "failed:tx_hash_not_settlement_transaction")
        d = self.b()
        d["settlement"]["payer"] = "0x" + "44" * 20
        self.assertEqual(chk(d, "T2"), "failed:payer_mismatch")
        d = self.b()
        d["settlement"]["amount"] = "2"
        self.assertEqual(chk(d, "T2"), "failed:amount_mismatch")
        d = self.b()
        d["settlement"]["network"] = "eip155:1"
        self.assertEqual(chk(d, "T2"), "failed:network_mismatch")
        d = self.b()
        d["settlement"]["success"] = False
        self.assertEqual(chk(d, "T1"), "failed:settlement_reported_failed_but_executed_on_chain")
        d = self.b()
        d["settlement"].update(success=False, errorReason="settlement_pending")
        self.assertEqual(chk(d, "T1"), "not_evaluated:settlement_pending_executed_on_chain")
        d = self.b()
        d["settlement"].update(success=False, errorReason="settlement_pending", transaction="")
        self.assertEqual(chk(d, "T1"), "failed:settlement_pending_without_transaction_hash")
        d = self.b()
        del d["chain_tx"]
        d["settlement"]["success"] = False
        self.assertEqual(chk(d, "T1"), "failed:settlement_not_successful")
        d = self.b()
        d["settlement"]["transaction"] = "0x12"
        self.assertEqual(chk(d, "T1"), "failed:transaction_not_a_32_byte_hash")
        d = self.b()
        d["settlement"]["success"] = 1
        self.assertEqual(run(d)["verdict"], "refused")

    def test_log_settled(self):
        cases = [("topics", [p2.TOPIC_SETTLED_PERMIT], "failed:log_settled_not_the_settle_event"),
                 ("address", "0x" + "55" * 20, "failed:log_settled_not_from_proxy"),
                 ("data", "0x00", "failed:log_settled_data_not_empty"),
                 ("removed", True, "failed:log_settled_removed"),
                 ("blockHash", "0x" + "66" * 32, "failed:log_settled_block_not_tx_block"),
                 ("blockNumber", "0x1", "failed:log_settled_block_not_tx_block"),
                 ("transactionHash", "0x" + "66" * 32, "failed:log_settled_other_tx")]
        for k, v, want in cases:
            d = self.b()
            d["chain_tx"]["log_settled"][k] = v
            self.assertEqual(chk(d, "C2"), want, k)
        d = self.b(self.W)
        d["chain_tx"]["log_settled"]["topics"] = [p2.TOPIC_SETTLED]
        self.assertEqual(chk(d, "C2"), "failed:log_settled_not_the_settle_event")
        d = self.b()
        d["chain_tx"]["log_settled"]["removed"] = "no"
        self.assertEqual(run(d)["verdict"], "refused")
        for name in ("log_settled", "log_transfer"):    # read in every branch, also when C1 stops first
            d = self.b()
            d["chain_tx"][name]["removed"] = "no"
            d["chain_tx"]["tx"]["input"] = "0x12345678"
            self.assertEqual(run(d)["verdict"], "refused", name)
            d = self.b()
            d["chain_tx"][name]["topics"] = d["chain_tx"][name]["topics"] + ["0x" + "00" * 32]
            self.assertEqual(run(d)["verdict"], "refused", name)

    def test_log_transfer(self):
        lt = self.b()["chain_tx"]["log_transfer"]
        cases = [("address", "0x" + "55" * 20, "failed:log_transfer_not_from_asset"),
                 ("topics", ["0x" + "77" * 32] + lt["topics"][1:], "failed:log_transfer_not_Transfer"),
                 ("topics", lt["topics"][:1] + ["0x" + "0" * 24 + "88" * 20] + lt["topics"][2:],
                  "failed:log_transfer_from_mismatch"),
                 ("topics", lt["topics"][:2] + ["0x" + "0" * 24 + "88" * 20], "failed:log_transfer_to_mismatch"),
                 ("data", "0x" + "00" * 31 + "01", "failed:log_transfer_value_mismatch"),
                 ("data", "0x" + "00" * 33, "failed:log_transfer_value_mismatch"),
                 ("removed", True, "failed:log_transfer_removed"),
                 ("transactionHash", "0x" + "66" * 32, "failed:log_transfer_other_tx"),
                 ("blockHash", "0x" + "66" * 32, "failed:log_transfer_block_not_tx_block"),
                 ("logIndex", "0x0", "not_evaluated:log_transfer_not_next")]
        for k, v, want in cases:
            d = self.b()
            d["chain_tx"]["log_transfer"][k] = v
            self.assertEqual(chk(d, "C3"), want, (k, v))

    def test_calldata(self):
        def mod(d, f):
            b = bytearray(bytes.fromhex(d["chain_tx"]["tx"]["input"][2:]))
            f(b)
            d["chain_tx"]["tx"]["input"] = "0x" + b.hex()
            return chk(d, "C1")
        self.assertEqual(mod(self.b(), lambda b: b.__setitem__(0, b[0] ^ 1)), "failed:tx_not_settle")
        self.assertEqual(mod(self.b(), lambda b: b.__setitem__(4, 1)), "failed:tx_address_word_not_padded")
        self.assertEqual(mod(self.b(), lambda b: b.__setitem__(4 + 32 * 5, 1)), "failed:tx_address_word_not_padded")
        self.assertEqual(mod(self.b(), lambda b: b.__setitem__(4 + 32 * 7 + 31, 0x20)),
                         "failed:tx_signature_offset_not_canonical")
        self.assertEqual(mod(self.b(), lambda b: b.__setitem__(len(b) - 1, 1)), "failed:tx_signature_padding")
        self.assertEqual(mod(self.b(), lambda b: b.extend(b"\x01\x02")), "not_evaluated:unrecognized_trailing_calldata")
        self.assertEqual(mod(self.b(), lambda b: b.__setitem__(4 + 32 * 8 + 31, 0xff)), "failed:tx_signature_padding")
        self.assertEqual(mod(self.b(), lambda b: b.__delitem__(slice(40, None))), "failed:tx_calldata_short")
        self.assertEqual(mod(self.b(self.W), lambda b: b.__setitem__(4 + 32 * 4 + 30, 1)), "failed:tx_v_out_of_range")
        self.assertEqual(mod(self.b(self.W), lambda b: b.__setitem__(4 + 32 * 9, 1)), "failed:tx_address_word_not_padded")
        self.assertEqual(mod(self.b(self.W), lambda b: b.__setitem__(4 + 32 * 12 + 31, 0)),
                         "failed:tx_signature_offset_not_canonical")
        d = self.b()
        sfx = b"\x61\x62" + b"\x02\x00" + b"\x80\x21" * 8      # an ERC-8021 Schema 0 suffix "ab"
        self.assertEqual(mod(d, lambda b: b.extend(sfx)), "verified")

    def test_indirect(self):
        d = self.b()
        d["chain_tx"]["tx"]["to"] = "0x" + "99" * 20
        r = run(d)
        self.assertEqual(r["checks"]["C1"], "not_applicable:indirect_call")
        self.assertEqual(r["checks"]["C2"], "failed:tx_hash_not_its_rlp")      # the signed tx names the proxy
        self.assertEqual(r["verdict"], "chain_failed")
        d = self.b()
        d["chain_tx"]["network"] = "eip155:1"
        self.assertEqual(chk(d, "C1"), "failed:chain_tx_network_mismatch")

    def test_payment_required(self):
        d = self.b()
        acc = copy.deepcopy(d["payment_payload"]["accepted"])
        eip3009 = dict(copy.deepcopy(acc), extra={"name": "USD Coin", "version": "2"})
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "https://x.test/r"}, "accepts": [eip3009, acc,
                                 {"scheme": "upto", "network": "solana:x"}]}
        self.assertEqual(chk(d, "K4"), "verified")
        d["payment_required"]["accepts"] = [eip3009]
        self.assertEqual(chk(d, "K4"), "failed:accepted_not_offered")
        d["payment_required"]["accepts"] = [acc]
        d["payment_payload"]["resource"] = {"url": "https://x.test/other"}
        self.assertEqual(chk(d, "K4"), "failed:resource_url_mismatch")
        d = self.b()
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "u"},
                                               "accepts": [dict(copy.deepcopy(acc), extra={})]}
        self.assertEqual(run(d)["verdict"], "refused")          # an EIP-3009 offer without name and version

    def test_eip3009_bundle_offered_permit2(self):
        """Until 0.10 a permit2 entry in payment_required made an EIP-3009 bundle unsupported (SPEC 12.1)."""
        with open(os.path.join(ROOT, "bundles", "real", "real_001_envelope_reconstructed.json")) as fh:
            d = av.strict_json(fh.read())
        p2offer = dict(copy.deepcopy(d["payment_payload"]["accepted"]), extra={"assetTransferMethod": "permit2"})
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "u"},
                                 "accepts": [p2offer, d["payment_payload"]["accepted"]]}
        self.assertEqual(chk(d, "K4"), "verified")
        p2offer["extra"]["assetTransferMethod"] = "erc7710"
        self.assertEqual(chk(d, "K4"), "verified")
        p2offer["amount"] = "01"
        self.assertEqual(run(d)["verdict"], "refused")
        d["payment_payload"]["accepted"]["extra"] = {"assetTransferMethod": "permit2"}
        r = run(d)
        self.assertEqual(r["verdict"], "unsupported")
        self.assertIn("apc-0.10", r["reason"])


class Built(unittest.TestCase):
    """Signed with a TEST key: cases the real set does not hold."""
    def test_valid_and_limits(self):
        self.assertEqual(run(built_permit2())["verdict"], "chain_verified")
        r = run(built_permit2(spender="0x" + "ab" * 20))
        self.assertEqual(r["checks"]["L2.sig"], "verified")
        self.assertEqual(r["checks"]["K7"], "failed:spender_not_x402_exact_permit2_proxy")
        self.assertEqual(r["verdict"], "chain_failed")
        self.assertEqual(chk(built_permit2(validAfter=2001), "K5"), "failed:empty_validity_window")
        self.assertEqual(chk(built_permit2(validAfter=2000), "K5"), "verified")
        r = run(built_permit2(amount=0))
        self.assertEqual(r["checks"]["K6"], "failed:zero_amount")
        self.assertEqual(r["checks"]["L2.sig"], "verified")
        d = built_permit2()
        d["payment_payload"]["accepted"]["payTo"] = test_addr()
        P(d)["witness"]["to"] = test_addr()
        self.assertTrue(run(d)["payer_is_payee"])
        big = built_permit2(nonce=(1 << 256) - 1, deadline=(1 << 256) - 1)
        self.assertEqual(run(big)["verdict"], "chain_verified")

    def test_exchange_and_mandate(self):
        d = built_permit2()
        hdr = base64.b64encode(json.dumps(d["payment_payload"]).encode()).decode()
        d["exchange"] = {"request": {"method": "GET", "target_uri": "https://x.test/r",
                                     "fields": [["PAYMENT-SIGNATURE", hdr]]}}
        r = run(d)
        self.assertEqual(r["checks"]["X1"], "verified")
        d["mandate"] = {"profile": "other"}
        self.assertEqual(chk(d, "M1"), "not_evaluated:ap2_has_no_x402_binding")
        d["mandate"] = []
        self.assertEqual(run(d)["verdict"], "refused")


class Erc7710(unittest.TestCase):
    def test_valid(self):
        r = run(built_7710())
        self.assertEqual({k: r["checks"][k] for k in ("C1", "C2", "C3", "T1", "T2", "K6")},
                         dict.fromkeys(("C1", "C2", "C3", "T1", "T2", "K6"), "verified"))
        self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:erc7710_permission_context_opaque")
        self.assertEqual(r["verdict"], "chain_incomplete")
        self.assertEqual(r["method"], "erc7710")

    def test_execution(self):
        cases = [(redeem_input(pc=b"\x01"), "failed:tx_permission_context_differs_from_payload"),
                 (redeem_input(mode=b"\x01" + bytes(31)), "not_evaluated:erc7579_call_type_01_not_single"),
                 (redeem_input(mode=b"\x00\x02" + bytes(30)), "not_evaluated:erc7579_mode_not_default"),
                 (redeem_input(mode=bytes(31) + b"\x01"), "not_evaluated:erc7579_mode_not_default"),
                 (redeem_input(e=ecd(target="0x" + "12" * 20)), "failed:execution_target_not_asset"),
                 (redeem_input(e=ecd(value=1)), "failed:execution_sends_native_value"),
                 (redeem_input(e=ecd(to="0x" + "12" * 20)), "failed:execution_to_not_payTo"),
                 (redeem_input(e=ecd(amount=9999)), "failed:execution_amount_not_amount"),
                 (redeem_input(e=ecd(sel=b"\x09\x5e\xa7\xb3")), "failed:execution_not_a_transfer_call"),
                 (redeem_input(e=ecd() + b"\x00"), "failed:execution_not_a_transfer_call"),
                 (redeem_input(e=bytearray(ecd())[:56] + b"\x01" + ecd()[57:]),
                  "failed:execution_address_word_not_padded"),
                 (redeem_input() + "0102", "not_evaluated:unrecognized_trailing_calldata"),
                 ("0x" + (p2.SEL_REDEEM + w(0x60) + w(0x60)).hex(), "failed:tx_not_redeemDelegations_abi"),
                 ("0x12345678", "failed:tx_not_redeemDelegations"),
                 ("0x" + p2.SEL_REDEEM.hex(), "failed:tx_not_redeemDelegations_abi")]
        for inp, want in cases:
            self.assertEqual(chk(built_7710(inp=inp), "C1"), want, want)
        r = run(built_7710(inp=redeem_input(mode=b"\x00\x01" + bytes(30))))
        self.assertEqual(r["checks"]["C1"], "verified")
        self.assertTrue(any("execType 0x01" in n for n in r["notes"]))
        # non-canonical: the same values with a gap after the head
        enc = p2._abi_canonical_redeem(CONTEXT, bytes(32), ecd())
        shifted = b"".join(w(int.from_bytes(enc[i:i + 32], "big") + 32) for i in (0, 32, 64)) + bytes(32) + enc[96:]
        self.assertEqual(chk(built_7710(inp="0x" + (p2.SEL_REDEEM + shifted).hex()), "C1"),
                         "failed:tx_calldata_not_canonical_abi")      # same values, a gap after the head
        two = "0x" + (p2.SEL_REDEEM + w(0x60) + w(0xa0) + w(0xe0) + w(2) + bytes(64) + w(1) + bytes(32) + w(1)
                      + bytes(64)).hex()
        self.assertEqual(chk(built_7710(inp=two), "C1"), "failed:tx_not_one_delegation_redeemed")

    def test_logs_and_links(self):
        self.assertEqual(chk(built_7710(transfer_from="0x" + "77" * 20), "C3"), "failed:log_transfer_from_mismatch")
        r = run(built_7710(to="0x" + "88" * 20))
        self.assertEqual(r["checks"]["C1"], "not_applicable:indirect_call")
        self.assertEqual(r["checks"]["C3"], "verified")
        self.assertEqual(r["verdict"], "chain_incomplete")
        d = built_7710()
        d["settlement"]["payer"] = "0x" + "77" * 20
        self.assertEqual(chk(d, "T2"), "failed:payer_mismatch")
        d = built_7710()
        d["payment_payload"]["accepted"]["amount"] = "0"
        self.assertEqual(chk(d, "K6"), "failed:zero_amount")
        d = built_7710()
        del d["chain_tx"]["log_transfer"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_7710()
        d["chain_tx"]["log_settled"] = {}
        self.assertEqual(run(d)["verdict"], "refused")

    def test_real_redemption_not_x402_shape(self):
        """A real MetaMask DelegationManager redemption on Base (approve, not transfer): C1 refuses it as a payment."""
        with open(os.path.join(ORACLE, "dm_approve_tx.json")) as fh:
            tx = json.load(fh)["tx"]
        x = bytes.fromhex(tx["input"][10:])
        rd = lambda o: int.from_bytes(x[o:o + 32], "big")  # noqa: E731
        o = rd(0)
        inner = o + 32 + rd(o + 32)
        pc = x[inner + 32: inner + 32 + rd(inner)]
        oe = rd(64)
        ie = oe + 32 + rd(oe + 32)
        e = x[ie + 32: ie + 32 + rd(ie)]
        d = built_7710()
        d["payment_payload"]["payload"].update(delegationManager=tx["to"].lower(), permissionContext="0x" + pc.hex())
        d["payment_payload"]["accepted"].update(asset="0x" + e[:20].hex(), payTo="0x" + e[68:88].hex())
        d["chain_tx"]["tx"] = tx
        d["settlement"]["transaction"] = tx["hash"]
        self.assertEqual(chk(d, "C1"), "failed:execution_not_a_transfer_call")

    def test_batch(self):
        a = real_one("p001_envelope_reconstructed.json")
        b = copy.deepcopy(a)
        b["settlement"]["transaction"] = "0x" + "ee" * 32
        out = apc_batch.check_set([("a", a), ("b", b), ("c", built_7710())])
        self.assertEqual(out["D3"][0]["check"], "failed:same_authorization_two_settlements")
        self.assertEqual(out["D3"][0]["authorization"]["asset"], p2.PERMIT2)
        self.assertEqual([x["bundle"] for x in out["refused"]], ["c"])
        self.assertIn("multi-use", out["refused"][0]["reason"])
        c = copy.deepcopy(b)
        P(c)["nonce"] = str(int(P(c)["nonce"]) + 1)       # another authorization: no D3
        self.assertEqual(apc_batch.check_set([("a", a), ("c", c)])["D3"], "verified")


class Grammar(unittest.TestCase):
    """Closed at every level: an unknown member, a missing one, a wrong type is a refusal, never a traceback."""
    CLOSED = [(), ("payment_payload",), ("payment_payload", "accepted"), ("payment_payload", "payload"),
              ("payment_payload", "payload", "permit2Authorization"),
              ("payment_payload", "payload", "permit2Authorization", "permitted"),
              ("payment_payload", "payload", "permit2Authorization", "witness"), ("settlement",), ("chain_tx",)]
    OPTIONAL = {("settlement", "payer"), ("settlement", "amount"), ("settlement", "errorReason"),
                ("settlement", "extensions"), ("payment_payload", "resource"), ("payment_payload", "extensions"),
                ("payment_required",), ("settlement",), ("chain_tx",), ("mandate",), ("exchange",), ("provenance",)}

    def at(self, d, path):
        for k in path:
            d = d[k]
        return d

    def test_unknown_and_missing(self):
        base = real_one("p001_envelope_reconstructed.json")
        n = 0
        for path in self.CLOSED:
            d = copy.deepcopy(base)
            self.at(d, path)["zz_unknown"] = 1
            self.assertEqual(run(d)["verdict"], "refused", path)
            for k in list(self.at(base, path)):
                if path + (k,) in self.OPTIONAL:
                    continue
                d = copy.deepcopy(base)
                del self.at(d, path)[k]
                self.assertEqual(run(d)["verdict"], "refused", path + (k,))
                n += 1
        self.assertGreater(n, 25)
        d = built_7710()
        d["payment_payload"]["payload"]["zz"] = 1
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_7710()
        d["chain_tx"]["zz"] = 1
        self.assertEqual(run(d)["verdict"], "refused")
        for bad in (["inclusion", {}], ["acceptance", {}], ["payer_wallet", {}], ["canonical", {}]):
            d = copy.deepcopy(base)
            d[bad[0]] = bad[1]
            self.assertEqual(run(d)["verdict"], "refused", bad[0])

    def test_wrong_types_every_leaf(self):
        base = real_one("p005_envelope_reconstructed.json")
        bad = [None, True, 1, 1.5, [], {}, "", "0x", "9" * 5000, "0x" + "f" * 5001, "é", "-1", "01", "1e3"]
        leaves = []
        for path in self.CLOSED[1:7]:
            for k, v in self.at(base, path).items():
                if not isinstance(v, dict):
                    leaves.append(path + (k,))
        for path in leaves:
            for v in bad:
                d = copy.deepcopy(base)
                self.at(d, path[:-1])[path[-1]] = v
                r = run(d)          # a report or a refusal; any exception fails the test
                if path[-1] in ("amount", "nonce", "deadline", "validAfter", "from", "spender", "to", "token",
                                "signature", "payTo", "asset"):
                    self.assertIn(r["verdict"], ("refused", "chain_failed"), (path, v))
        self.assertGreater(len(leaves), 14)

    def test_method_values(self):
        d = built_permit2()
        d["payment_payload"]["accepted"]["extra"]["assetTransferMethod"] = "eip3009"
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_permit2()
        del d["payment_payload"]["accepted"]["extra"]["assetTransferMethod"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_permit2()
        del d["payment_payload"]["accepted"]["extra"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_permit2()
        d["payment_payload"]["accepted"]["extra"]["assetTransferMethod"] = "foo"
        self.assertEqual(run(d)["verdict"], "unsupported")
        d = built_permit2()
        d["payment_payload"]["accepted"]["extra"]["name"] = 3
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_permit2()
        d["payment_payload"]["accepted"]["extra"]["other"] = 3
        self.assertTrue(any("extra.other present" in n for n in run(d)["notes"]))
        d = built_permit2()
        d["payment_payload"]["accepted"]["network"] = "solana:abc"
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_permit2()
        d["payment_payload"]["accepted"]["scheme"] = "upto"
        self.assertEqual(run(d)["verdict"], "unsupported")
        d = built_permit2()
        d["payment_payload"]["x402Version"] = 1
        self.assertEqual(run(d)["verdict"], "unsupported")
        d = built_permit2()
        d["payment_payload"]["payload"]["signature"] = "0x123"
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_7710()
        d["payment_payload"]["payload"]["permissionContext"] = "0x"
        self.assertEqual(run(d)["verdict"], "refused")
        d = built_7710()
        d["payment_payload"]["accepted"]["extra"]["assetTransferMethod"] = "permit2"
        self.assertEqual(run(d)["verdict"], "refused")      # an erc7710 payload under the permit2 grammar
        self.assertEqual(run(dict(built_permit2(), bundle_version="apc-0.8"))["verdict"], "refused")

    def test_chain_members(self):
        for k in ("blockHash", "blockNumber", "hash", "to", "input"):
            d = real_one("p001_envelope_reconstructed.json")
            del d["chain_tx"]["tx"][k]
            self.assertEqual(run(d)["verdict"], "refused", k)
        for name in ("log_transfer", "log_settled"):
            for k in ("address", "topics", "data", "transactionHash", "blockHash", "blockNumber", "logIndex"):
                d = real_one("p001_envelope_reconstructed.json")
                del d["chain_tx"][name][k]
                self.assertEqual(run(d)["verdict"], "refused", (name, k))
            d = real_one("p001_envelope_reconstructed.json")
            d["chain_tx"][name]["topics"][0] = "0x12"
            self.assertEqual(run(d)["verdict"], "refused", name)
            d = real_one("p001_envelope_reconstructed.json")
            d["chain_tx"][name]["logIndex"] = "0x" + "f" * 65
            self.assertEqual(run(d)["verdict"], "refused", name)
        d = real_one("p001_envelope_reconstructed.json")
        d["chain_tx"]["tx"]["blockNumber"] = "0x01"
        self.assertEqual(run(d)["verdict"], "refused")

    def test_random_mutations_never_crash(self):
        """Seeded structural fuzz over real and built bundles: replace, delete or add at a random path."""
        rnd = random.Random(20261026)
        pool = [real_one("p001_envelope_reconstructed.json"), real_one("p005_envelope_reconstructed.json"),
                real_one("p029_envelope_reconstructed.json"), built_7710(), built_permit2()]
        vals = [None, True, False, 0, -1, 2 ** 70, 1e308, "", "0x", "0x00", "x" * 3, "9" * 80, [], {}, [1], {"a": 1}]
        counts = {}
        for i in range(600):
            d = copy.deepcopy(rnd.choice(pool))
            for _ in range(rnd.randint(1, 3)):
                paths, stack = [], [((), d)]
                while stack:
                    p, x = stack.pop()
                    paths.append(p)
                    if isinstance(x, dict):
                        stack.extend((p + (k,), v) for k, v in x.items())
                    elif isinstance(x, list):
                        stack.extend((p + (j,), v) for j, v in enumerate(x))
                path = rnd.choice(paths[1:])
                parent = self.at(d, path[:-1])
                op = rnd.random()
                if op < 0.6:
                    parent[path[-1]] = rnd.choice(vals)
                elif op < 0.8 and isinstance(parent, dict):
                    del parent[path[-1]]
                elif isinstance(parent, dict):
                    parent["k%d" % i] = rnd.choice(vals)
            r = run(d)
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        self.assertGreater(counts.get("refused", 0), 100)
        self.assertGreater(sum(v for k, v in counts.items() if k.startswith("chain_")), 50)


if __name__ == "__main__":
    unittest.main()
