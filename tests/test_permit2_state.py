"""SPEC 0.10 sections 12.5-12.7: payers with code (EIP-7702 delegates of a closed list), the declared ERC-1271 call, and
inclusion, canonical and acceptance in apc-0.10. Real data: the 19 Kernel payers and the 1 DeleGator payer of the
231 real Permit2 settlements, with their blocks, receipts, parent headers and eth_getProof replies
(oracle/permit2_7702_20261026, built by tools/make_bundles_permit2_state.py), and real isValidSignature eth_calls
(erc1271_calls.json). Built here with a TEST key: the replayable Kernel form and the synthetic state tries of the
proof-form failures that real data cannot show (a slot that changes inside the block, a delegate with other code)."""
import copy
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03_canonical", "real_permit2", oracle=("permit2_7702_20261026", "permit2_base_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_block as ab  # noqa: E402
import apc_verify as av  # noqa: E402
import apc_permit2 as p2  # noqa: E402
from make_bundles_permit2 import build, load  # noqa: E402
from make_bundles_permit2_state import with_state  # noqa: E402
from lib.secp256k1 import sign  # noqa: E402

ORACLE = os.path.join(ROOT, "oracle")
with open(os.path.join(ORACLE, "permit2_base_20261026", "payer_code_7702.json")) as fh:
    NAMES = sorted(json.load(fh)["replies"])
KERNEL1, DELEG = "p029_envelope_reconstructed.json", "p205_envelope_reconstructed.json"
_B = {}


def base(name):
    if not _B:
        _B.update(build(load(os.path.join(ORACLE, "permit2_base_20261026", "proxy_txs.json.gz")))[0])
    return copy.deepcopy(_B[name])


_S = {}


def state(name, form):
    if (name, form) not in _S:
        other = _S.get((name, "rpc" if form == "proof" else "proof"))
        _S[(name, form)] = with_state(name, base(name), form, other["inclusion"] if other else None)
    return copy.deepcopy(_S[(name, form)])


def run(d, **kw):
    try:
        return av.verify_bundle(d, **kw)
    except av.Refusal as e:
        return {"verdict": "unsupported" if isinstance(e, av.Unsupported) else "refused", "reason": str(e),
                "checks": {}}


def sig_of(d):
    return d["payment_payload"]["payload"]["signature"]


def offline(d):
    """The payload alone with its rpc payer_code (no chain_tx, no inclusion): L2.sig only."""
    for k in ("chain_tx", "inclusion", "settlement"):
        d.pop(k, None)
    return d


def w(n):
    return n.to_bytes(32, "big")


class RealState(unittest.TestCase):
    def test_all_twenty_both_forms(self):
        """Measured: 19 Kernel and 1 DeleGator payers verify in both forms, bound to their blocks."""
        got = {}
        for name in NAMES:
            for form in ("rpc", "proof"):
                r = run(state(name, form))
                got[r["checks"]["L2.sig"]] = got.get(r["checks"]["L2.sig"], 0) + 1
                self.assertEqual(r["verdict"], "chain_verified", (name, form, r.get("failed"), r.get("not_evaluated")))
                self.assertTrue(r["block_bound"], name)
                self.assertFalse([x for x in r["notes"] if x.startswith("E1:")], name)     # one Transfer each
                self.assertEqual(r["payer_state"], "declared_rpc" if form == "rpc" else "proven_at_parent_and_block")
                for k in ("B1", "B2", "B3", "B4", "C1", "C2", "C3", "K3"):
                    self.assertTrue(r["checks"][k].startswith("verified"), (name, form, k, r["checks"][k]))
        self.assertEqual(got, {"verified (ERC-1271 Kernel 0.3.3 by EIP-7702)": 38,
                               "verified (ERC-1271 EIP7702StatelessDeleGator by EIP-7702)": 2})
        self.assertEqual(len(NAMES), 20)

    def test_without_payer_code_unchanged(self):
        r = run(base(KERNEL1))
        self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:unsupported_signature_length_66")
        self.assertEqual(r["checks"]["B1"], "not_evaluated:absent:no_inclusion")


class KernelRule(unittest.TestCase):
    def d(self):
        return offline(state(KERNEL1, "rpc"))

    def test_signature_forms(self):
        d = self.d(); s = sig_of(d)
        d["payment_payload"]["payload"]["signature"] = s[:4] + ("0" if s[4] != "0" else "1") + s[5:]
        self.assertTrue(run(d)["checks"]["L2.sig"].startswith(("failed:kernel_signature_recovers_",
                                                                "failed:kernel_signature_invalid")))
        d = self.d(); d["payment_payload"]["payload"]["signature"] = "0x01" + sig_of(d)[4:]
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:kernel_validation_mode_01_not_evaluated")
        d = self.d(); raw = bytes.fromhex(sig_of(d)[2:])
        r_, s_, v = raw[1:33], int.from_bytes(raw[33:65], "big"), raw[65]
        d["payment_payload"]["payload"]["signature"] = "0x00" + (r_ + (s_ | ((v - 27) << 255)).to_bytes(32, "big")).hex()
        self.assertEqual(run(d)["checks"]["L2.sig"], "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)")   # 64-byte form
        d = self.d(); d["payment_payload"]["payload"]["signature"] = "0x00" + p2.KERNEL_REPLAYABLE.hex() + sig_of(d)[4:]
        self.assertTrue(run(d)["checks"]["L2.sig"].startswith("failed:kernel_signature_recovers_"))   # chainId 0
        d = self.d(); d["payment_payload"]["payload"]["signature"] = sig_of(d)[:-2] + "1d"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:kernel_signature_invalid")
        d = self.d(); d["payment_payload"]["payload"]["signature"] = sig_of(d) + "00"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:kernel_signature_length_66")

    def test_replayable_with_a_test_key(self):
        priv = 0x4646464646464646464646464646464646464646464646464646464646464646
        from lib.eip712 import keccak256
        from lib.secp256k1 import GX, GY, _mul, public_key_to_address
        me = public_key_to_address(_mul(priv, (GX, GY)), keccak256)
        d = self.d()
        P = d["payment_payload"]["payload"]["permit2Authorization"]
        P["from"] = me
        rp = d["payer_code"]["rpc"]
        rp["code"]["params"][0] = rp["storage"]["params"][0] = me
        pp = p2.parse_payload(d["payment_payload"])
        for chain, prefix in ((0, p2.KERNEL_REPLAYABLE), (8453, b"")):
            dom = p2.keccak256(p2.DOMAIN4_TYPEHASH + p2.keccak256(b"Kernel") + p2.keccak256(b"0.3.3") + w(chain)
                               + bytes(12) + bytes.fromhex(me[2:]))
            h = p2.keccak256(b"\x19\x01" + dom + p2.keccak256(p2.KERNEL_WRAPPER_TYPEHASH + p2.permit2_digest(8453, pp["auth"])))
            r, s, rec = sign(h, priv, 0x777)
            d["payment_payload"]["payload"]["signature"] = "0x00" + (prefix + w(r) + w(s) + bytes([27 + rec])).hex()
            self.assertEqual(run(d)["checks"]["L2.sig"], "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)", chain)

    def test_slot_and_code(self):
        d = self.d(); d["payer_code"]["rpc"]["storage"]["result"] = "0x" + "00" * 31 + "01"
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:kernel_root_validator_installed")
        d = self.d(); d["payer_code"]["rpc"]["storage"]["result"] = "0x" + "00" * 11 + "01" + "00" * 20
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:kernel_root_validator_installed")
        d = self.d(); d["payer_code"]["rpc"]["storage"]["result"] = "0x" + "ff" * 11 + "00" * 21    # nonces only
        self.assertEqual(run(d)["checks"]["L2.sig"], "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)")
        d = self.d(); del d["payer_code"]["rpc"]["storage"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = self.d(); d["payer_code"]["rpc"]["code"]["result"] = "0xef0100" + "12" * 20
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:payer_code_not_known")
        d = self.d(); d["payer_code"]["rpc"]["code"]["result"] = "0x6000"
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:payer_code_not_known")
        d = self.d(); d["payer_code"]["rpc"]["code"]["result"] = "0x"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:signature_length_66_for_a_payer_without_code")
        d = offline(base("p001_envelope_reconstructed.json"))      # an EOA payer, its code declared empty
        payer = d["payment_payload"]["payload"]["permit2Authorization"]["from"]
        d["payer_code"] = {"rpc": {"code": {"method": "eth_getCode", "params": [payer, "0x1"], "result": "0x"}}}
        self.assertEqual(run(d)["checks"]["L2.sig"], "verified")

    def test_rpc_grammar_and_params(self):
        d = self.d(); d["payer_code"]["rpc"]["code"]["params"][0] = "0x" + "12" * 20
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:code_params_0")
        d = self.d(); d["payer_code"]["rpc"]["storage"]["params"][1] = "0x" + "00" * 32
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:storage_params_1")
        d = self.d(); d["payer_code"]["rpc"]["storage"]["params"][2] = "0x5"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:storage_params_2")
        d = state(KERNEL1, "rpc"); rp = d["payer_code"]["rpc"]
        rp["code"]["params"][1] = rp["storage"]["params"][2] = "0x1"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:payer_code_block_not_tx_block")
        for bad in ({"rpc": {}, "proof": {}}, {}, {"rpc": {"code": {}, "zz": 1}}, {"zz": 1}, []):
            d = self.d(); d["payer_code"] = bad
            self.assertEqual(run(d)["verdict"], "refused", bad)
        d = self.d(); d["payer_code"]["rpc"]["code"]["method"] = "eth_call"
        self.assertEqual(run(d)["verdict"], "refused")
        d = self.d(); d["payer_code"]["rpc"]["storage"]["result"] = "0x00"
        self.assertEqual(run(d)["verdict"], "refused")
        d = self.d(); d["payer_code"]["rpc"]["code"]["params"][1] = "0x01"
        self.assertEqual(run(d)["verdict"], "refused")


class DelegatorRule(unittest.TestCase):
    def test_forms(self):
        d = offline(state(DELEG, "rpc"))
        self.assertEqual(run(d)["checks"]["L2.sig"], "verified (ERC-1271 EIP7702StatelessDeleGator by EIP-7702)")
        raw = bytes.fromhex(sig_of(d)[2:])
        r_, s_, v = raw[:32], int.from_bytes(raw[32:64], "big"), raw[64]
        twin = r_ + (av.SECP_N - s_).to_bytes(32, "big") + bytes([55 - v])
        d["payment_payload"]["payload"]["signature"] = "0x" + twin.hex()
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:high_s_refused_by_delegate")
        d["payment_payload"]["payload"]["signature"] = "0x" + (r_ + (s_ | ((v - 27) << 255)).to_bytes(32, "big")).hex()
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:delegate_signature_not_65_bytes")
        d["payment_payload"]["payload"]["signature"] = "0x" + (raw[:64] + b"\x1d").hex()
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:delegate_signature_invalid")
        d = offline(state(DELEG, "rpc")); P = d["payment_payload"]["payload"]["permit2Authorization"]
        P["deadline"] = str(int(P["deadline"]) + 1)
        self.assertTrue(run(d)["checks"]["L2.sig"].startswith("failed:recovers_"))


class ProofForm(unittest.TestCase):
    def test_real_tampered(self):
        d = state(KERNEL1, "proof"); d["payer_code"]["proof"]["code"] = "0xef0100" + "12" * 20
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:payer_state_code_not_proven")
        d = state(KERNEL1, "proof"); d["payer_code"]["proof"]["parent_header"]["gasUsed"] = "0x1"
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:payer_state_parent_header_not_parent")
        d = state(KERNEL1, "proof"); pr = d["payer_code"]["proof"]
        pr["at_parent"]["payer"], pr["at_block"]["payer"] = pr["at_block"]["payer"], pr["at_parent"]["payer"]
        self.assertTrue(run(d)["checks"]["L2.sig"].startswith("failed:payer_state_proof:"))
        d = state(KERNEL1, "proof"); del d["payer_code"]["proof"]["at_block"]["delegate"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = state(KERNEL1, "proof"); del d["payer_code"]["proof"]["at_block"]["payer"]["storageProof"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = state(KERNEL1, "proof"); pr = d["payer_code"]["proof"]
        pr["at_block"]["delegate"] = copy.deepcopy(pr["at_block"]["payer"]); del pr["at_block"]["delegate"]["storageProof"]
        self.assertTrue(run(d)["checks"]["L2.sig"].startswith("failed:payer_state_"))
        d = state(KERNEL1, "proof"); del d["inclusion"]
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:payer_code_proof_needs_inclusion")
        d = state(KERNEL1, "proof"); d["inclusion"]["block_header"]["gasUsed"] = "0x1"
        r = run(d)
        self.assertEqual(r["checks"]["B1"], "failed:header_hash_mismatch")
        self.assertEqual(r["checks"]["L2.sig"], "not_evaluated:payer_code_proof_block_not_bound")
        d = state(KERNEL1, "proof"); d["payer_code"]["proof"]["zz"] = 1
        self.assertEqual(run(d)["verdict"], "refused")
        d = state(KERNEL1, "proof"); d["payer_code"]["proof"]["at_parent"]["payer"]["accountProof"] = ["0x12"] * 65
        self.assertEqual(run(d)["verdict"], "refused")

    def synthetic(self, word_parent, word_block, delegate_hash=None):
        """Two state tries built here (apc_block.trie_root / trie_proof) under real header shapes."""
        d = state(KERNEL1, "proof")
        pr, inc = d["payer_code"]["proof"], d["inclusion"]
        payer = bytes.fromhex(d["payment_payload"]["payload"]["permit2Authorization"]["from"][2:])
        code = bytes.fromhex(pr["code"][2:])
        dkey = bytes.fromhex(p2.KERNEL[2:])
        out = {}
        for end, word in (("at_parent", word_parent), ("at_block", word_block)):
            skey = p2.keccak256(w(p2.KERNEL_SLOT))
            spairs = [(skey, ab.rlp(ab._int_bytes(word)))] if word else []
            sroot = ab.trie_root(spairs) if spairs else p2.apc_l1proof.EMPTY_TRIE
            sproof = ["0x" + n.hex() for n in ab.trie_proof(spairs, skey)] if spairs else []
            acct = ab.rlp([b"", b"", sroot, p2.keccak256(code)])
            dacct = ab.rlp([b"\x01", b"", p2.apc_l1proof.EMPTY_TRIE,
                            bytes.fromhex(delegate_hash or p2.DELEGATES[p2.KERNEL][1])])
            pairs = [(p2.keccak256(payer), acct), (p2.keccak256(dkey), dacct)]
            out[end] = (ab.trie_root(pairs), {"payer": {"accountProof": ["0x" + n.hex() for n in ab.trie_proof(pairs, pairs[0][0])],
                                                        "storageProof": sproof},
                                              "delegate": {"accountProof": ["0x" + n.hex() for n in ab.trie_proof(pairs, pairs[1][0])]}})
        ph = dict(pr["parent_header"], stateRoot="0x" + out["at_parent"][0].hex())
        ph["hash"] = ab.header_hash(ph)
        hdr = dict(inc["block_header"], stateRoot="0x" + out["at_block"][0].hex(), parentHash=ph["hash"])
        pc = {"proof": {"code": pr["code"], "parent_header": ph, "at_parent": out["at_parent"][1],
                        "at_block": out["at_block"][1]}}
        pp = p2.parse_payload(d["payment_payload"])
        return p2.payer_state(pc, pp, d["chain_tx"], {"block_header": hdr}, "verified"), pp

    def test_synthetic_tries(self):
        st, pp = self.synthetic(0, 0)
        self.assertEqual(st[2], "proven_at_parent_and_block")          # positive control of the construction
        self.assertEqual(p2.with_code(pp, st, "x"), "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)")
        st, pp = self.synthetic(0, 1 << 200)                            # nonces only, but changed inside the block
        self.assertEqual(st, "failed:payer_state_slot_changed_in_block")
        st, pp = self.synthetic(1, 1)
        self.assertEqual(p2.with_code(pp, st, "x"), "not_evaluated:kernel_root_validator_installed")
        st, pp = self.synthetic(0, 0, delegate_hash="11" * 32)
        self.assertEqual(st, "failed:payer_state_delegate_code_not_pinned")


class Erc1271Declared(unittest.TestCase):
    """Real isValidSignature eth_calls (base.drpc.org, 2026-10-26); the negative control is a real call too."""
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ORACLE, "permit2_7702_20261026", "erc1271_calls.json")) as fh:
            cls.calls = json.load(fh)

    def ec(self, name, end):
        n = int(base(name)["chain_tx"]["tx"]["blockNumber"], 16) - (1 if end == "parent" else 0)
        c = copy.deepcopy(self.calls["calls"]["%s@%d" % (name, n)])
        c.pop("raw_error")
        return c

    def test_declared(self):
        for name in (KERNEL1, DELEG):
            for end in ("parent", "block"):
                d = base(name); d["erc1271_call"] = self.ec(name, end)
                r = run(d)
                want = "not_evaluated:erc1271_declared_valid" if name == KERNEL1 else "verified"
                self.assertEqual(r["checks"]["L2.sig"], want, (name, end))
                self.assertTrue(r["erc1271"]["declared"])
                self.assertEqual(r["erc1271"]["returned"], "0x1626ba7e" + "00" * 28)
                if name == KERNEL1:
                    self.assertEqual(r["verdict"], "chain_incomplete")
        d = state(KERNEL1, "proof"); d["erc1271_call"] = self.ec(KERNEL1, "parent")
        self.assertEqual(run(d)["checks"]["L2.sig"], "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)")

    def test_negative_and_mismatch(self):
        neg = self.calls["negative_control"]["call"]["result"]
        self.assertEqual(neg, "0xffffffff" + "00" * 28)                # the endpoint can say invalid
        d = base(KERNEL1); d["erc1271_call"] = self.ec(KERNEL1, "block"); d["erc1271_call"]["call"]["result"] = neg
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:erc1271_declared_invalid")
        d = state(KERNEL1, "rpc"); d["erc1271_call"] = self.ec(KERNEL1, "block"); d["erc1271_call"]["call"]["result"] = neg
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:erc1271_declared_contradicts_offline_check")
        d = base(KERNEL1); ec = self.ec(KERNEL1, "block")
        ec["call"]["params"][0]["data"] = self.calls["negative_control"]["call"]["params"][0]["data"]
        d["erc1271_call"] = ec
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:call_params_0")
        d = base(KERNEL1); ec = self.ec(KERNEL1, "block"); ec["call"]["params"][1] = "0x1"; d["erc1271_call"] = ec
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:erc1271_call_block_not_tx_block_or_parent")
        d = state(KERNEL1, "rpc"); del d["payer_code"]; ec = self.ec(KERNEL1, "block"); ec["block_hash"] = "0x" + "ab" * 32
        d["erc1271_call"] = ec
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:erc1271_call_block_hash_not_header")
        for k, v in (("endpoint", "x" * 257), ("block_hash", "0x12"), ("zz", 1)):
            d = base(KERNEL1); d["erc1271_call"] = self.ec(KERNEL1, "block"); d["erc1271_call"][k] = v
            self.assertEqual(run(d)["verdict"], "refused", k)
        for bad in ("0x12", "0x1626ba7e", "0x1626ba7e" + "01" * 28, "0x1626ba7e" + "00" * 29):
            d = base(KERNEL1); d["erc1271_call"] = self.ec(KERNEL1, "block"); d["erc1271_call"]["call"]["result"] = bad
            self.assertEqual(run(d)["checks"]["L2.sig"], "failed:erc1271_declared_invalid", bad)   # a clean bytes4 only


class InclusionCanonicalAcceptance(unittest.TestCase):
    def test_inclusion_rules(self):
        d = state(KERNEL1, "rpc")
        other = state(NAMES[1], "rpc")["inclusion"]
        d["inclusion"]["receipt_proof"] = other["receipt_proof"]
        self.assertTrue(run(d)["checks"]["B3"].startswith("failed:receipt_proof:"))
        d = state(KERNEL1, "rpc"); d["inclusion"] = other
        r = run(d)
        self.assertEqual(r["checks"]["B1"], "failed:tx_block_not_header")
        self.assertFalse(r["block_bound"])
        d = state(KERNEL1, "rpc"); d["chain_tx"]["log_settled"]["data"] = "0x00"
        r = run(d)
        self.assertEqual(r["checks"]["B3"], "failed:settled_log_not_next_in_receipt")
        self.assertEqual((r["checks"]["B1"], r["checks"]["B2"], r["block_bound"]), ("verified", "verified", False))
        d = state(KERNEL1, "rpc"); d["chain_tx"]["log_transfer"]["data"] = "0x" + "00" * 32
        self.assertEqual(run(d)["checks"]["B3"], "failed:transfer_log_not_in_receipt")
        d = state(KERNEL1, "rpc"); del d["chain_tx"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = base(KERNEL1); d["canonical"] = {}
        self.assertEqual(run(d)["verdict"], "refused")

    def test_b4_window(self):
        d = state(KERNEL1, "rpc")
        ts = int(d["inclusion"]["block_header"]["timestamp"], 16)
        P = d["payment_payload"]["payload"]["permit2Authorization"]
        for va, dl, want in ((ts, ts, "verified"), (ts + 1, ts + 5, "failed:block_time_outside_authorization_window"),
                             (0, ts - 1, "failed:block_time_outside_authorization_window")):
            P["witness"]["validAfter"], P["deadline"] = str(va), str(dl)
            self.assertEqual(run(d)["checks"]["B4"], want, (va, dl))

    def test_erc7710_window_not_applicable(self):
        from tests import test_permit2 as t
        d = t.built_7710()
        d["chain_tx"]["tx"]["transactionIndex"] = d["chain_tx"]["log_transfer"]["transactionIndex"] = "0x0"
        d["inclusion"] = state(KERNEL1, "rpc")["inclusion"]
        r = run(d)
        self.assertEqual(r["checks"]["B4"], "not_applicable:erc7710_no_signed_window")
        self.assertEqual(r["checks"]["B1"], "failed:tx_block_not_header")

    def test_canonical_same_code(self):
        """The canonical member of a real apc-0.3 bundle gives the same O1-O4 under an apc-0.10 bundle."""
        import glob
        src = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v03_canonical", "*.json")))
        src = [p for p in src if "MANIFEST" not in p][0]
        with open(src) as fh:
            old = av.strict_json(fh.read())
        ro = av.verify_bundle(copy.deepcopy(old))
        d = base("p001_envelope_reconstructed.json")
        d["inclusion"], d["canonical"] = old["inclusion"], old["canonical"]
        r = run(d)
        for k in ("O1", "O2", "O3", "O4", "L1"):
            self.assertEqual(r["checks"][k], ro["checks"][k], k)
        self.assertEqual(r["checks"]["B1"], "failed:tx_block_not_header")
        self.assertFalse(r["block_bound"])

    def test_acceptance(self):
        d = base("p001_envelope_reconstructed.json")
        P = d["payment_payload"]["payload"]["permit2Authorization"]
        pm = {"protocol": "x402", "scheme": "exact", "network": "eip155:8453", "asset": P["permitted"]["token"],
              "payer": P["from"], "pay_to": P["witness"]["to"], "amount": P["permitted"]["amount"],
              "nonce": "0x%064x" % int(P["nonce"]), "settlement_tx": d["settlement"]["transaction"]}
        d["acceptance"] = {"receipt": {"payment": pm}}
        r = run(d)
        self.assertEqual((r["checks"]["A1"], r["checks"]["A2"]), ("verified", "verified"))
        for k, v, want in (("nonce", "0x%064x" % (int(P["nonce"]) + 1), "failed:nonce_mismatch"),
                           ("pay_to", "0x" + "12" * 20, "failed:pay_to_mismatch"),
                           ("amount", "1", "failed:amount_mismatch"), ("payer", "0x" + "12" * 20, "failed:payer_mismatch")):
            e = copy.deepcopy(d); e["acceptance"]["receipt"]["payment"][k] = v
            self.assertEqual(run(e)["checks"]["A1"], want, k)
        e = copy.deepcopy(d); e["acceptance"]["receipt"]["payment"]["settlement_tx"] = "0x" + "12" * 32
        self.assertEqual(run(e)["checks"]["A2"], "failed:settlement_tx_mismatch")
        from tests import test_permit2 as t
        d7 = t.built_7710()
        pm7 = dict(pm, asset=t.USDC, payer=t.DELEGATOR, pay_to=t.PAYTO, amount="10000",
                   settlement_tx=d7["settlement"]["transaction"])
        d7["acceptance"] = {"receipt": {"payment": pm7}}
        self.assertEqual(run(d7)["checks"]["A1"], "not_evaluated:erc7710_payment_has_no_nonce")
        d7["acceptance"]["receipt"]["payment"]["amount"] = "1"
        self.assertEqual(run(d7)["checks"]["A1"], "failed:amount_mismatch")
        d7["payer_code"] = {}
        self.assertEqual(run(d7)["verdict"], "refused")


if __name__ == "__main__":
    unittest.main()
