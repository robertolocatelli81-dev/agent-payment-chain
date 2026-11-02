"""SPEC 0.21 (section 32): a 65-byte signature of a payer with code (32.2), the member payer_state (32.4), the closed list
(32.5) and the rule of Circle_SingleOwnerMSCA 1.0.0 (32.6), the census (32.8); since 0.21.1 (32.10) the rule's `verified`
needs the block anchored, so on these bundles (no `canonical`) it is `not_evaluated:payer_state_block_not_anchored`. Real data: the 28 executed payments of
bundles/real_msca_20261101 (tools/make_bundles_msca.py), each as an apc-0.2 bundle with the rpc form and an apc-0.3 bundle
with inclusion and the proof form. Every negative case is a named alteration of a real one, or a synthetic state trie
under the real headers (apc_block.trie_root / trie_proof) for what real data cannot show. Everything goes through
apc_verify.verify_bundle, so that on a verifier without section 32 each test fails with an AssertionError (positive
control of the file), not with an import error."""
import copy
import glob
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from tests import real_corpus  # noqa: E402
real_corpus.need("real_msca_20261101", "real_v02", "real_v02_wallet", oracle=("coverage_20261022", "coverage_20261026", "msca_20261101", "census_base_*.json", "transfers_base_*.json",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_block as ab  # noqa: E402
import apc_verify as av  # noqa: E402
import coverage_census as cc  # noqa: E402
from apc_verify import keccak256  # noqa: E402

B = os.path.join(ROOT, "bundles", "real_msca_20261101")
RPC = sorted(glob.glob(os.path.join(B, "m*_rpc_*.json")))
PROOF = sorted(glob.glob(os.path.join(B, "m*_proof_*.json")))
WALLET02 = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02_wallet", "w_*.json")))
MSCA = "verified (ERC-1271 Circle_SingleOwnerMSCA 1.0.0)"
# SPEC 32.10 (0.21.1): the rule above ends in verified, but the block whose state decides it is not anchored (canonical
# final with l1_state proven, SPEC 30.1); the anchored case is tests/test_msca_anchor.py
NE = "not_evaluated:payer_state_block_not_anchored"
OWNER = "0x%040x" % ((int(json.load(open(RPC[0]))["payer_state"]["rpc"]["wallet"]["owner"]["result"], 16) >> 16)
                     & ((1 << 160) - 1))      # the owner key of the real payer, read from the first real bundle, not written here
IMPL = "0x9c6e09bc32d1e012dcaa2623e66d2cc9860c1aed"
IMPL_HASH = "60ecaaadc845f14626e77541b390bd36a7f5c35efdee5c30471f0eb08626019e"
SLOT1967 = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
OWNER_SLOT = 0xc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfc8 + 8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
EMPTY_TRIE = keccak256(ab.rlp(b""))
REPLIES = "oracle/msca_20261101/payer_state_replies.json"


def load(p):
    with open(p, "rb") as fh:
        return av.strict_json(fh.read().decode("utf-8"))


def run(d):
    try:
        return av.verify_bundle(d)
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e), "checks": {}}


def sig(d):
    return d["payment_payload"]["payload"]["signature"]


def set_sig(d, s):
    d["payment_payload"]["payload"]["signature"] = s


def hexflip(h, pos):
    """h with the hex digit at position pos (of the digits) changed."""
    i = 2 + pos
    return h[:i] + ("0" if h[i] != "0" else "1") + h[i + 1:]


def l2(d):
    r = run(d)
    return r["checks"].get("L2.sig", r.get("verdict"))


def c(r, k):
    """A check of the report, or the verdict when the report has none (a refusal): so that on a verifier without
    section 32 every test of this file fails with an AssertionError, not a KeyError."""
    return r["checks"].get(k, r.get("verdict"))


class Real(unittest.TestCase):
    def test_twenty_eight_in_both_forms(self):
        self.assertEqual((len(RPC), len(PROOF)), (28, 28))
        vs, payers = [], set()
        for p in RPC:
            r = run(load(p))
            self.assertEqual((r.get("verdict"), c(r, "L2.sig"), c(r, "K3"), r.get("payer_state"), r.get("evidence_level")),
                             ("chain_incomplete", NE, "not_evaluated:by_L2.sig", "declared_rpc", "none"), p)
            s = bytes.fromhex(sig(load(p))[2:])
            vs.append(s[64])
            self.assertLessEqual(int.from_bytes(s[32:64], "big"), N // 2)
            payers.add(load(p)["payment_payload"]["payload"]["authorization"]["from"])
        self.assertEqual((vs.count(27), vs.count(28), len(payers)), (16, 12, 1))
        for p in PROOF:
            r = run(load(p))
            self.assertEqual((r.get("verdict"), c(r, "L2.sig"), r.get("payer_state"), r.get("block_bound"), r.get("evidence_level")),
                             ("chain_incomplete", NE, "proven_at_parent_and_block", True, "none"), p)
            self.assertTrue(any("proven equal at the end of the parent block" in n for n in r["notes"]))

    def test_manifest_agrees(self):
        man = json.load(open(os.path.join(B, "MANIFEST.json")))["made"]
        self.assertEqual(len(man), 56)
        for m in man:
            r = run(load(os.path.join(B, m["file"])))
            self.assertEqual((r.get("verdict"), c(r, "L2.sig"), r.get("payer_state")), (m["verdict"], m["L2.sig"], m["payer_state"]))


class SignatureControls(unittest.TestCase):
    """Positive controls on the real signatures: each alteration must fail under the MSCA rule (32.6)."""

    def test_r_altered_every_payment(self):
        for p in RPC + PROOF:
            d = load(p)
            set_sig(d, hexflip(sig(d), 10))
            r = run(d)
            self.assertTrue(c(r, "L2.sig").startswith(("failed:msca_signature_recovers_", "failed:msca_signature_invalid")), p)
            self.assertEqual(r.get("verdict"), "chain_failed")

    def test_high_s_twin(self):
        d = load(RPC[0])
        s = bytes.fromhex(sig(d)[2:])
        twin = s[:32] + (N - int.from_bytes(s[32:64], "big")).to_bytes(32, "big") + bytes([55 - s[64]])
        set_sig(d, "0x" + twin.hex())
        self.assertEqual(l2(d), "failed:msca_high_s")

    def test_signature_of_another_payment(self):
        for i in range(28):
            d = load(RPC[i])
            set_sig(d, sig(load(RPC[(i + 1) % 28])))
            self.assertTrue(l2(d).startswith("failed:msca_signature_recovers_"), i)

    def test_length_and_v(self):
        d = load(RPC[0])
        set_sig(d, sig(d)[:-2])
        self.assertEqual(l2(d), "failed:msca_signature_length_64")
        d = load(RPC[0])
        set_sig(d, sig(d) + "00")
        self.assertEqual(l2(d), "failed:msca_signature_length_66")
        d = load(RPC[0])
        set_sig(d, sig(d)[:-2] + "1d")
        self.assertEqual(l2(d), "failed:msca_signature_invalid")
        d = load(RPC[0])
        set_sig(d, "0x" + "00" * 32 + sig(d)[66:])
        self.assertEqual(l2(d), "failed:msca_signature_invalid")
        d = load(RPC[0])                                    # v 29 with r = 2: ecrecover returns zero; the library alone
        set_sig(d, "0x" + "%064x" % 2 + sig(d)[66:-2] + "1d")   # would recover a point for recovery id 2 (x = r + n)
        self.assertEqual(l2(d), "failed:msca_signature_invalid")


class AcceptedOnChain(unittest.TestCase):
    """32.2: without payer_state, a 65-byte signature that does not recover `from` next to a chain_tx that executed it."""

    def bare(self, i=0):
        d = load(RPC[i])
        del d["payer_state"]
        return d

    def test_executed_is_not_evaluated_not_failed(self):
        for i in range(28):
            r = run(self.bare(i))
            self.assertEqual((r.get("verdict"), c(r, "L2.sig"), c(r, "K3"), r.get("evidence_level"), r.get("payer_state")),
                             ("chain_incomplete", "not_evaluated:signature_accepted_on_chain_needs_payer_state",
                              "not_evaluated:by_L2.sig", "none", None), i)
            self.assertEqual((c(r, "C1"), c(r, "C2"), c(r, "C3")), ("verified",) * 3)
        self.assertTrue(any("payer had code at that block" in n for n in run(self.bare())["notes"]))

    def test_every_version(self):
        d = self.bare()
        d["bundle_version"] = "apc-0.1"
        del d["chain_tx"]["log_transfer"]
        r = run(d)
        self.assertEqual((r.get("verdict"), c(r, "L2.sig")), ("chain_incomplete", "not_evaluated:signature_accepted_on_chain_needs_payer_state"))
        d = self.bare()
        d["bundle_version"] = "apc-0.3"
        self.assertEqual(run(d)["checks"]["L2.sig"], "not_evaluated:signature_accepted_on_chain_needs_payer_state")

    def test_positive_controls_stay_failed(self):
        self.assertEqual(l2(self.bare()), "not_evaluated:signature_accepted_on_chain_needs_payer_state")
        d = self.bare()
        del d["chain_tx"]                                   # nothing shows execution
        r = run(d)
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        self.assertEqual(r.get("verdict"), "chain_failed")
        d = self.bare()
        set_sig(d, hexflip(sig(d), 10))                    # not the signature the transaction carries
        r = run(d)
        self.assertEqual(c(r, "C1"), "failed:tx_signature_differs_from_payload")
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        d = self.bare()
        d["chain_tx"] = load(RPC[1])["chain_tx"]            # another payment's transaction
        r = run(d)
        self.assertEqual(c(r, "C1"), "failed:tx_arguments_differ_from_authorization")
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        d = self.bare()
        d["chain_tx"]["tx"]["to"] = "0x" + "11" * 20          # an indirect call: C1 does not bind the signature bytes
        r = run(d)
        self.assertEqual(c(r, "C1"), "not_applicable:indirect_call")
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        d = self.bare()
        d["payment_payload"]["accepted"]["extra"]["name"] = "USDC"       # not the token's measured domain (SPEC 0.11.5):
        r = run(d)                                                      # the digest is not the token's, the recovery says nothing
        self.assertEqual((c(r, "C1"), c(r, "C2")), ("verified", "verified"))
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        d = self.bare()
        d["payment_payload"]["accepted"]["extra"]["version"] = "1"
        self.assertTrue(l2(d).startswith("failed:recovers_"))
        d = self.bare()
        d["chain_tx"]["log_authorization_used"]["topics"][2] = "0x" + "22" * 32      # C2 fails: another nonce logged
        r = run(d)
        self.assertNotEqual(c(r, "C2"), "verified")
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))

    def test_eoa_forgery_stays_failed(self):
        # a real EOA payment whose signature is replaced: the token would not have executed it; C1 shows the mismatch
        self.assertEqual(l2(load(RPC[0])), NE)
        d = load(sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02", "b*.json")))[0])
        set_sig(d, sig(load(RPC[0])))
        r = run(d)
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        self.assertEqual(r.get("verdict"), "chain_failed")


class PayerWalletBeside65(unittest.TestCase):
    """32.3 point 3: payer_wallet is read beside a 65-byte signature."""

    def test_msca_code_in_payer_wallet_is_not_known(self):
        d = load(RPC[0])
        ps = d.pop("payer_state")["rpc"]
        frm, blk = d["payment_payload"]["payload"]["authorization"]["from"], d["chain_tx"]["tx"]["blockNumber"]
        d["payer_wallet"] = {"owner_index": "0", "code": ps["code"], "implementation": ps["wallet"]["implementation"],
                             "owner": {"method": "eth_call", "params": [{"to": frm, "data": "0x" + keccak256(b"ownerAtIndex(uint256)")[:4].hex() + "0" * 64}, blk],
                                       "result": "0x"}}
        r = run(d)
        self.assertEqual((r.get("verdict"), c(r, "L2.sig")), ("chain_incomplete", "not_evaluated:wallet_implementation_not_known"))
        d["payer_wallet"]["code"]["params"][0] = "0x" + "33" * 20          # the member names another payer: read, not skipped
        self.assertEqual(l2(d), "failed:code_params_0")
        d["payer_wallet"]["zz"] = 1
        self.assertEqual(run(d)["verdict"], "refused")

    def test_coinbase_code_with_65_bytes_stays_failed(self):
        d = load(WALLET02[0])
        d.pop("chain_tx", None)
        d.pop("settlement", None)
        set_sig(d, sig(load(RPC[0])))
        self.assertEqual(l2(d), "failed:payer_wallet_with_a_65_byte_signature")
        d["payer_wallet"]["code"]["result"] = "0x6001"                      # an unknown code, declared, no chain_tx:
        self.assertTrue(l2(d).startswith("failed:recovers_"))               # it does not lift the failed recovery (32.3)

    def test_both_members_refused(self):
        d = load(RPC[0])
        d["payer_wallet"] = load(WALLET02[0])["payer_wallet"]
        self.assertEqual(run(d)["verdict"], "refused")
        d = load(RPC[0])
        d["bundle_version"] = "apc-0.1"
        for k in ("log_transfer",):
            d["chain_tx"].pop(k, None)
        self.assertEqual(run(d)["verdict"], "refused")                      # payer_state is apc-0.2 and apc-0.3 only
        d = load(PROOF[0])
        del d["chain_tx"]["log_transfer"]
        d["bundle_version"] = "apc-0.2"
        del d["inclusion"]
        self.assertEqual(l2(d), "not_evaluated:payer_state_proof_needs_inclusion")


class RpcForm(unittest.TestCase):
    def w(self, d):
        return d["payer_state"]["rpc"]["wallet"]

    def test_block_and_params(self):
        d = load(RPC[0])
        for k in ("code",):
            d["payer_state"]["rpc"][k]["params"][1] = "0x1"
        self.assertEqual(l2(d), "failed:payer_state_block_not_tx_block")
        d = load(RPC[0])
        d["payer_state"]["rpc"]["code"]["params"][0] = "0x" + "44" * 20
        self.assertEqual(l2(d), "failed:code_params_0")
        d = load(RPC[0])
        self.w(d)["implementation"]["params"][1] = "0x" + "55" * 32
        self.assertEqual(l2(d), "failed:implementation_params_1")
        d = load(RPC[0])
        self.w(d)["owner"]["params"][1] = "0x%064x" % (OWNER_SLOT + 1)
        self.assertEqual(l2(d), "failed:owner_params_1")
        d = load(RPC[0])
        self.w(d)["implementation_code"]["params"][0] = OWNER
        self.assertEqual(l2(d), "failed:implementation_code_params_0")
        d = load(RPC[0])
        self.w(d)["owner_code"]["params"][0] = IMPL
        self.assertEqual(l2(d), "failed:owner_code_params_0")
        d = load(RPC[0])
        self.w(d)["owner_code"]["params"][1] = "0x2"
        self.assertEqual(l2(d), "failed:owner_code_params_1")
        d = load(RPC[0])
        del d["chain_tx"]                                   # without chain_tx the block is the replies' own
        del d["settlement"]
        r = run(d)                                          # declared, nothing executed: section 3 stands (32.3, review)
        self.assertEqual((r.get("verdict"), c(r, "L2.sig")[:16], r.get("evidence_level")), ("chain_failed", "failed:recovers_", "none"))

    def test_results(self):
        d = load(RPC[0])
        self.w(d)["implementation"]["result"] = "0x" + "00" * 12 + "66" * 20
        self.assertEqual(l2(d), "not_evaluated:wallet_implementation_not_known")
        d = load(RPC[0])
        self.w(d)["implementation"]["result"] = "0x" + "01" + "00" * 11 + IMPL[2:]       # not an address word
        self.assertEqual(l2(d), "not_evaluated:wallet_implementation_not_known")
        d = load(RPC[0])
        self.w(d)["implementation_code"]["result"] = self.w(d)["implementation_code"]["result"][:-2] + "ff"
        self.assertEqual(l2(d), "failed:payer_state_implementation_code_not_pinned")
        d = load(RPC[0])
        self.w(d)["owner"]["result"] = "0x" + "00" * 10 + OWNER[2:] + "0000"              # initialized 0
        self.assertEqual(l2(d), "failed:msca_not_initialized")
        d = load(RPC[0])
        self.w(d)["owner"]["result"] = "0x" + "00" * 10 + OWNER[2:] + "0101"              # initializing
        self.assertEqual(l2(d), "failed:msca_not_initialized")
        d = load(RPC[0])
        self.w(d)["owner"]["result"] = "0x" + "00" * 9 + "01" + OWNER[2:] + "0001"        # bits above 176
        self.assertEqual(l2(d), "failed:msca_owner_word_not_canonical")
        d = load(RPC[0])
        self.w(d)["owner"]["result"] = "0x" + "00" * 31 + "01"                            # owner zero: plugin path
        self.w(d)["owner_code"]["params"][0] = "0x" + "00" * 20
        self.assertEqual(l2(d), "not_evaluated:msca_owner_zero_plugin_path")
        d = load(RPC[0])
        self.w(d)["owner_code"]["result"] = "0xef0100" + "77" * 20                        # the owner has code
        self.assertEqual(l2(d), NE)            # OZ SignatureChecker 22-27: the recovery gives the owner (review 2026-11-01)
        d = load(RPC[0])                       # another owner, with code: its own ERC-1271 would decide
        self.w(d)["owner"]["result"] = "0x" + "00" * 10 + "88" * 20 + "0001"
        self.w(d)["owner_code"]["params"][0] = "0x" + "88" * 20
        self.w(d)["owner_code"]["result"] = "0x6001"
        self.assertEqual(l2(d), "not_evaluated:msca_owner_has_code")
        d = load(RPC[0])
        self.w(d)["owner"]["result"] = "0x" + "00" * 10 + "88" * 20 + "0001"              # another owner
        self.w(d)["owner_code"]["params"][0] = "0x" + "88" * 20
        self.assertTrue(l2(d).startswith("failed:msca_signature_recovers_"))
        self.assertTrue(l2(d).endswith("_not_owner"))

    def test_code_empty_or_unlisted(self):
        d = load(RPC[0])                                    # proven (declared) no code: the EOA rule, no 32.2 exception
        d["payer_state"]["rpc"]["code"]["result"] = "0x"
        del d["payer_state"]["rpc"]["wallet"]
        r = run(d)
        self.assertTrue(c(r, "L2.sig").startswith("failed:recovers_"))
        self.assertEqual((r.get("verdict"), r.get("payer_state")), ("chain_failed", "declared_rpc"))
        set_sig(d, sig(d) + "00")
        self.assertEqual(l2(d), "failed:signature_length_66_for_a_payer_without_code")
        d = load(RPC[0])
        d["payer_state"]["rpc"]["code"]["result"] = "0x6001"
        del d["payer_state"]["rpc"]["wallet"]
        r = run(d)
        self.assertEqual((c(r, "L2.sig"), r.get("verdict"), r.get("payer_state")),
                         ("not_evaluated:wallet_implementation_not_known", "chain_incomplete", "declared_rpc"))
        for w in WALLET02:                                  # both Coinbase forms: the ERC-1967 proxy and the EIP-7702 delegation
            d["payer_state"]["rpc"]["code"]["result"] = load(w)["payer_wallet"]["code"]["result"]
            r = run(d)
            self.assertEqual(c(r, "L2.sig"), "not_evaluated:wallet_implementation_not_known", w)
            self.assertTrue(any("is payer_wallet, not payer_state" in n for n in r["notes"]), w)
        self.assertEqual(len(WALLET02), 2)

    def test_grammar_closed(self):
        base = load(RPC[0])
        self.assertEqual(l2(base), NE)                       # the unaltered bundle reaches the rule's end: the alterations below are read
        for fn in (lambda d: d["payer_state"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["rpc"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["rpc"]["wallet"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["rpc"]["wallet"]["owner"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["rpc"]["code"].pop("result"),
                   lambda d: d["payer_state"]["rpc"]["wallet"].pop("owner_code"),
                   lambda d: d["payer_state"]["rpc"].pop("wallet"),                           # listed code: required
                   lambda d: (d["payer_state"]["rpc"]["code"].__setitem__("result", "0x")),   # empty code: refused
                   lambda d: d["payer_state"].__setitem__("proof", {}),                        # two forms
                   lambda d: d.__setitem__("payer_state", {}),
                   lambda d: d.__setitem__("payer_state", []),
                   lambda d: d["payer_state"]["rpc"]["code"].__setitem__("params", "0x"),
                   lambda d: d["payer_state"]["rpc"]["code"]["params"].__setitem__(1, 7),
                   lambda d: d["payer_state"]["rpc"]["code"]["params"].append("0x1"),
                   lambda d: d["payer_state"]["rpc"]["wallet"]["owner"].__setitem__("params", {}),
                   lambda d: d["payer_state"]["rpc"]["code"].__setitem__("result", "0X60"),   # SPEC 29.4
                   lambda d: d["payer_state"]["rpc"]["wallet"]["owner"].__setitem__("result", "0x" + "0" * 63),
                   lambda d: d["payer_state"]["rpc"]["code"].__setitem__("method", "eth_call")):
            d = copy.deepcopy(base)
            fn(d)
            r = run(d)
            self.assertIn(r.get("verdict"), ("refused",) if "params_" not in str(r.get("checks", {}).get("L2.sig", "")) else ("chain_failed",), r)
            self.assertNotEqual(r.get("verdict"), "chain_verified")
        d = copy.deepcopy(base)
        d["payer_state"]["rpc"]["code"]["result"] = "0X60"                 # SPEC 29.4: payer_state is a JSON-RPC member
        self.assertIn("SPEC 29.4", run(d).get("reason", ""))


class ProofForm(unittest.TestCase):
    def pr(self, d):
        return d["payer_state"]["proof"]

    def test_tampered(self):
        d = load(PROOF[0])
        self.pr(d)["code"] = self.pr(d)["code"][:-2] + "ff"            # no longer a listed code: the wallet members are refused
        self.assertEqual(run(d)["verdict"], "refused")
        d = load(PROOF[0])
        self.pr(d)["code"] = "0x6001"                                   # an unlisted code the account does not have
        for end in ("at_parent", "at_block"):
            del self.pr(d)[end]["payer"]["storageProof"], self.pr(d)[end]["implementation"], self.pr(d)[end]["owner"]
        self.assertEqual(l2(d), "failed:payer_state_code_not_proven")
        d = load(PROOF[0])
        self.pr(d)["parent_header"]["gasUsed"] = "0x1"
        self.assertEqual(l2(d), "failed:payer_state_parent_header_not_parent")
        d = load(PROOF[0])
        n = self.pr(d)["at_block"]["payer"]["accountProof"]
        n[0] = hexflip(n[0], 40)
        self.assertEqual(l2(d), "failed:payer_state_proof:proof_node_hash_mismatch")
        d = load(PROOF[0])
        n = self.pr(d)["at_parent"]["payer"]["storageProof"][1]
        n[-1] = hexflip(n[-1], 10)
        self.assertTrue(l2(d).startswith("failed:payer_state_proof:"))
        d = load(PROOF[0])
        n = self.pr(d)["at_block"]["owner"]["accountProof"]
        n[-1] = hexflip(n[-1], 10)
        self.assertTrue(l2(d).startswith("failed:payer_state_proof:"))
        d = load(PROOF[0])
        self.pr(d)["at_block"]["payer"], self.pr(d)["at_parent"]["payer"] = self.pr(d)["at_parent"]["payer"], self.pr(d)["at_block"]["payer"]
        self.assertTrue(l2(d).startswith("failed:payer_state_proof:"))
        d = load(PROOF[0])
        sp = self.pr(d)["at_block"]["payer"]["storageProof"]
        sp[0], sp[1] = sp[1], sp[0]                        # the two slot proofs in the other order
        self.assertTrue(l2(d).startswith(("failed:payer_state_proof:", "not_evaluated:wallet_implementation_not_known")))
        d = load(PROOF[0])
        d["inclusion"]["block_header"]["gasUsed"] = "0x1"
        r = run(d)
        self.assertEqual((c(r, "B1"), c(r, "L2.sig")), ("failed:header_hash_mismatch", "not_evaluated:payer_state_proof_block_not_bound"))
        d = load(PROOF[0])                                  # another stateRoot in a header chain that still hashes (B1 holds)
        ph, hdr = self.pr(d)["parent_header"], d["inclusion"]["block_header"]
        ph["stateRoot"] = "0x" + "ab" * 32
        ph["hash"] = ab.header_hash(ph)
        hdr["parentHash"] = ph["hash"]
        hdr["hash"] = ab.header_hash(hdr)
        for o in (d["chain_tx"]["tx"], d["chain_tx"]["log_authorization_used"], d["chain_tx"]["log_transfer"]):
            o["blockHash"] = hdr["hash"]
        r = run(d)
        self.assertEqual((c(r, "B1"), c(r, "L2.sig")), ("verified", "failed:payer_state_proof:proof_node_hash_mismatch"))
        d = load(PROOF[0])
        del d["inclusion"]
        r = run(d)
        self.assertEqual((c(r, "L2.sig"), r.get("verdict"), r.get("payer_state")), ("not_evaluated:payer_state_proof_needs_inclusion", "chain_incomplete", None))

    def test_grammar_closed(self):
        base = load(PROOF[0])
        self.assertEqual(l2(base), NE)
        for fn in (lambda d: d["payer_state"]["proof"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["proof"]["at_block"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["proof"]["at_block"]["payer"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["proof"]["at_block"]["owner"].__setitem__("zz", 1),
                   lambda d: d["payer_state"]["proof"]["parent_header"].__setitem__("zz", "0x1"),
                   lambda d: d["payer_state"]["proof"]["at_parent"].pop("owner"),
                   lambda d: d["payer_state"]["proof"]["at_parent"]["payer"].pop("storageProof"),
                   lambda d: d["payer_state"]["proof"]["at_parent"]["payer"]["storageProof"].pop(),
                   lambda d: d["payer_state"]["proof"]["at_parent"]["payer"]["storageProof"].append([]),
                   lambda d: d["payer_state"]["proof"]["at_parent"]["payer"]["storageProof"][0].__setitem__(0, "zz"),
                   lambda d: d["payer_state"]["proof"]["at_parent"]["payer"]["accountProof"].extend(["0x12"] * 64),
                   lambda d: d["payer_state"]["proof"]["at_parent"]["payer"].__setitem__("accountProof", []),
                   lambda d: d["payer_state"]["proof"].__setitem__("code", "0x" + "0"),
                   lambda d: d["payer_state"]["proof"].__setitem__("code", "0x"),           # empty code: nothing reads the rest
                   lambda d: d["payer_state"]["proof"].pop("parent_header"),
                   lambda d: d["payer_state"]["proof"]["at_block"]["implementation"].__setitem__("storageProof", []),
                   lambda d: d["payer_state"]["proof"]["at_block"]["payer"]["accountProof"].__setitem__(0, "0X12")):
            d = copy.deepcopy(base)
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused", fn)

    def synthetic(self, impl_hash=IMPL_HASH, word_parent=None, word_block=None, owner_code=False, owner=OWNER):
        """A real proof bundle whose two state tries are built here: the payer (code, two slots), the implementation
        and the owner under new stateRoots; the headers' hashes and the chain_tx block hashes follow, so B1-B4 hold."""
        d = load(PROOF[0])
        pr, inc = self.pr(d), d["inclusion"]
        payer = bytes.fromhex(d["payment_payload"]["payload"]["authorization"]["from"][2:])
        code = bytes.fromhex(pr["code"][2:])
        default = (int(owner, 16) << 16) | 1
        words = {"at_parent": default if word_parent is None else word_parent,
                 "at_block": default if word_block is None else word_block}
        roots = {}
        for end in ("at_parent", "at_block"):
            spairs = sorted([(keccak256(SLOT1967.to_bytes(32, "big")), ab.rlp(ab._int_bytes(int(IMPL, 16)))),
                             (keccak256(OWNER_SLOT.to_bytes(32, "big")), ab.rlp(ab._int_bytes(words[end])))])
            sroot = ab.trie_root(spairs)
            oaddr = bytes.fromhex(owner[2:])
            pairs = sorted([(keccak256(payer), ab.rlp([b"\x01", b"", sroot, keccak256(code)])),
                            (keccak256(bytes.fromhex(IMPL[2:])), ab.rlp([b"\x01", b"", EMPTY_TRIE, bytes.fromhex(impl_hash)])),
                            (keccak256(oaddr), ab.rlp([b"", b"", EMPTY_TRIE, keccak256(b"\x60" if owner_code else b"")]))])
            roots[end] = ab.trie_root(pairs)
            pr[end] = {"payer": {"accountProof": ["0x" + x.hex() for x in ab.trie_proof(pairs, keccak256(payer))],
                                 "storageProof": [["0x" + x.hex() for x in ab.trie_proof(spairs, keccak256(SLOT1967.to_bytes(32, "big")))],
                                                  ["0x" + x.hex() for x in ab.trie_proof(spairs, keccak256(OWNER_SLOT.to_bytes(32, "big")))]]},
                       "implementation": {"accountProof": ["0x" + x.hex() for x in ab.trie_proof(pairs, keccak256(bytes.fromhex(IMPL[2:])))]},
                       "owner": {"accountProof": ["0x" + x.hex() for x in ab.trie_proof(pairs, keccak256(oaddr))]}}
        pr["parent_header"]["stateRoot"] = "0x" + roots["at_parent"].hex()
        pr["parent_header"]["hash"] = ab.header_hash(pr["parent_header"])
        inc["block_header"]["stateRoot"] = "0x" + roots["at_block"].hex()
        inc["block_header"]["parentHash"] = pr["parent_header"]["hash"]
        inc["block_header"]["hash"] = ab.header_hash(inc["block_header"])
        for o in (d["chain_tx"]["tx"], d["chain_tx"]["log_authorization_used"], d["chain_tx"]["log_transfer"]):
            o["blockHash"] = inc["block_header"]["hash"]
        return d

    def test_synthetic_tries(self):
        r = run(self.synthetic())                            # positive control of the construction
        self.assertEqual((r.get("verdict"), c(r, "L2.sig"), r.get("block_bound"), r.get("payer_state")),
                         ("chain_incomplete", NE, True, "proven_at_parent_and_block"))
        self.assertEqual(l2(self.synthetic(impl_hash="11" * 32)), "failed:payer_state_implementation_code_not_pinned")
        self.assertEqual(l2(self.synthetic(word_block=(int(OWNER, 16) << 16) | 0)), "failed:payer_state_slot_changed_in_block")
        self.assertEqual(l2(self.synthetic(word_parent=(int(OWNER, 16) << 16), word_block=(int(OWNER, 16) << 16))), "failed:msca_not_initialized")
        self.assertEqual(l2(self.synthetic(word_parent=(int(OWNER, 16) << 16) | 0x101, word_block=(int(OWNER, 16) << 16) | 0x101)), "failed:msca_not_initialized")
        self.assertEqual(l2(self.synthetic(word_parent=1, word_block=1, owner="0x" + "00" * 20)), "not_evaluated:msca_owner_zero_plugin_path")
        # OZ SignatureChecker 22-27 (review 2026-11-01): the recovery decides first; the owner's ERC-1271 only otherwise
        self.assertEqual(l2(self.synthetic(owner_code=True)), NE)
        other = "0x" + "99" * 20
        w = (int(other, 16) << 16) | 1
        self.assertEqual(l2(self.synthetic(word_parent=w, word_block=w, owner=other, owner_code=True)), "not_evaluated:msca_owner_has_code")
        self.assertTrue(l2(self.synthetic(word_parent=w, word_block=w, owner=other)).startswith("failed:msca_signature_recovers_"))
        w = (1 << 176) | (int(OWNER, 16) << 16) | 1
        self.assertEqual(l2(self.synthetic(word_parent=w, word_block=w)), "failed:msca_owner_word_not_canonical")


class Census(unittest.TestCase):
    """32.8: tools/coverage_census.py builds the bundle with payer_state from the saved replies."""
    E = {"kind": "evm_eip3009", "network": "eip155:8453", "asset": "USDC", "label": "w52338016_100",
         "files": {"census": "oracle/census_base_52338016_100.json",
                   "transfers": "oracle/transfers_base_52338016_100.json",
                   "wallets": ["oracle/coverage_20261022/payer_wallet_replies.json",
                               "oracle/coverage_20261026/payer_wallets_base_20261022_windows.json", REPLIES]}}
    TXS = {m["tx"] for m in json.load(open(os.path.join(B, "MANIFEST.json")))["made"] if m["window"] == "52338016_100"}

    def recs(self, entry, disable=()):
        out, _, wal = cc.classify_eip3009(entry, cc.facilitators(), cc.load_routes(), disable, self.TXS)
        return {r["tx"]: r for r in out}, wal

    def test_built_and_verified(self):
        recs, _ = self.recs(self.E)
        self.assertEqual(len(recs), 9)                       # the 9 payments of this window
        for h, r in recs.items():
            # 32.10: the rpc form is declared state, never anchored: built, chain_incomplete (L2.sig not_evaluated)
            self.assertEqual((r["built"], r.get("extraction"), r.get("verdict"), r.get("l2_sig")),
                             (True, "msca_1271", "chain_incomplete", NE), h)

    def test_positive_controls(self):
        recs, _ = self.recs(self.E, ("msca_1271",))
        for h, r in recs.items():
            self.assertEqual((r["built"], r["reason"], r["payer"]), (False, "direct_not_decoded", "code_not_known"), h)
        files = dict(self.E["files"], wallets=self.E["files"]["wallets"][:2])
        recs, wal = self.recs(dict(self.E, files=files))
        for h, r in recs.items():
            self.assertEqual((r["built"], r["payer"]), (False, "not_read"), h)
        self.assertEqual(len(wal.not_read), 9)             # one (payer, block) pair per payment

    def test_calldata_must_name_the_logged_authorization(self):
        """The rule reads the direct call only when its decoded `from` and `nonce` are the log's: a census copy whose
        log names another nonce for one payment leaves that payment unbuilt (and the other eight built)."""
        import tempfile
        c = json.load(open(os.path.join(ROOT, self.E["files"]["census"])))
        hit = 0
        for x in c["calls"]:
            if x["method"] == "eth_getLogs":
                for lg in x["result"]:
                    if lg["transactionHash"] in self.TXS and hit == 0:
                        lg["topics"][2] = "0x" + "ab" * 32
                        hit, victim = 1, lg["transactionHash"]
        self.assertEqual(hit, 1)
        tmp = tempfile.mkdtemp(prefix="apcmsca_", dir=ROOT)
        try:
            with open(os.path.join(tmp, "census.json"), "w") as fh:
                json.dump(c, fh)
            e = dict(self.E, files=dict(self.E["files"], census=os.path.relpath(os.path.join(tmp, "census.json"), ROOT)))
            recs, _ = self.recs(e)
        finally:
            import shutil
            shutil.rmtree(tmp)
        self.assertEqual((recs[victim]["built"], recs[victim]["reason"], recs[victim]["payer"]), (False, "direct_not_decoded", "code_not_known"))
        self.assertEqual(sum(r["built"] for r in recs.values()), 8)


if __name__ == "__main__":
    unittest.main()
