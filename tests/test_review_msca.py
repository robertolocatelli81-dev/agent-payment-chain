"""Review 2026-11-01 of 19b0ecd (SPEC 0.21, section 32): R1 declared state members, R2 reverted receipts, R3 the made-up-block
limit (closed by 32.10, Amendment 0.21.1: tests/test_msca_anchor.py)."""
import unittest

import copy, glob, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_msca_20261101")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_block as ab, apc_verify as av, apc_msca as am
from apc_verify import keccak256
from lib.secp256k1 import sign, public_key_to_address, _mul, GX, GY
from lib.eip712 import signing_digest

def addr(priv):
    return public_key_to_address(_mul(priv, (GX, GY)), keccak256)
ATT, FAC = 0xA11CE, 0xFACC
A, F = addr(ATT), addr(FAC)
SLOT1967 = am.ERC1967_SLOT; OWNER_SLOT = am.MSCA_OWNER_SLOT
EMPTY_TRIE = keccak256(ab.rlp(b""))
IMPL = am.WALLETS[next(iter(am.WALLETS))][0]; IMPL_HASH = am.WALLETS[next(iter(am.WALLETS))][1]

def q(n): return ab._int_bytes(n)
def hx(b): return "0x" + b.hex()

def forge(owner_priv=ATT, new_to=None, new_value=None, mode="ok", vbyte=None):
    d = json.load(open(sorted(glob.glob(os.path.join(ROOT, "bundles/real_msca_20261101/m001_proof_*.json")))[0]))
    pp = d["payment_payload"]; au = pp["payload"]["authorization"]; acc = pp["accepted"]
    if new_to: au["to"] = acc["payTo"] = new_to
    if new_value: au["value"] = acc["amount"] = str(new_value)
    dom = {"name": acc["extra"]["name"], "version": acc["extra"]["version"], "chainId": 8453, "verifyingContract": acc["asset"]}
    msg = {"from": au["from"], "to": au["to"], "value": int(au["value"]), "validAfter": int(au["validAfter"]),
           "validBefore": int(au["validBefore"]), "nonce": au["nonce"]}
    h = signing_digest(dom, "TransferWithAuthorization", av.TYPES, msg, av.DOMAIN4)
    rs = am.replay_safe_hash(8453, au["from"], h)
    r, s, rec = sign(rs, owner_priv, 0x5EED + owner_priv)
    vv = 27 + rec if vbyte is None else vbyte
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([vv])
    pp["payload"]["signature"] = hx(sig)
    tx = d["chain_tx"]["tx"]
    w = lambda x: x.to_bytes(32, "big")
    inp = bytes.fromhex(tx["input"][2:10]) + bytes(12) + bytes.fromhex(au["from"][2:]) + bytes(12) + bytes.fromhex(au["to"][2:]) \
        + w(int(au["value"])) + w(int(au["validAfter"])) + w(int(au["validBefore"])) + bytes.fromhex(au["nonce"][2:]) \
        + w(vv) + w(r) + w(s)
    tx["input"] = hx(inp)
    I = lambda k: int(tx[k], 16)
    fields = [q(I("chainId")), q(I("nonce")), q(I("maxPriorityFeePerGas")), q(I("maxFeePerGas")), q(I("gas")),
              bytes.fromhex(tx["to"][2:]), q(I("value")), inp, []]
    th = keccak256(b"\x02" + ab.rlp(fields))
    tr, ts_, trec = sign(th, FAC, 0xBEEF)
    tx.update({"from": F, "r": hex(tr), "s": hex(ts_), "yParity": hex(trec), "v": hex(trec)})
    raw_tx = b"\x02" + ab.rlp(fields + [q(trec), q(tr), q(ts_)])
    tx["hash"] = hx(keccak256(raw_tx))
    inc = d["inclusion"]; idx = int(inc["transaction_index"], 16); key = ab.rlp(ab._int_bytes(idx))
    raw_rc = ab.verify_proof(bytes.fromhex(inc["block_header"]["receiptsRoot"][2:]), key,
                             [bytes.fromhex(n[2:]) for n in inc["receipt_proof"]])
    rc = ab.rlp_decode(raw_rc[1:])
    tt = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()
    for lg in rc[3]:
        if hx(lg[1][0]) == tt and hx(lg[0]) == acc["asset"]:
            lg[1][2] = bytes(12) + bytes.fromhex(au["to"][2:]); lg[2] = w(int(au["value"]))
    if mode == "reverted":
        rc[0] = b""
    raw_rc2 = raw_rc[:1] + ab.rlp(rc)
    tp = [(key, raw_tx)]; rp = [(key, raw_rc2)]
    inc["tx_proof"] = [hx(x) for x in ab.trie_proof(tp, key)]
    inc["receipt_proof"] = [hx(x) for x in ab.trie_proof(rp, key)]
    hdr = inc["block_header"]; pr = d["payer_state"]["proof"]
    hdr["transactionsRoot"] = hx(ab.trie_root(tp)); hdr["receiptsRoot"] = hx(ab.trie_root(rp))
    payer = bytes.fromhex(au["from"][2:]); code = bytes.fromhex(pr["code"][2:])
    owner = addr(owner_priv); word = (int(owner, 16) << 16) | 1
    roots = {}
    for end in ("at_parent", "at_block"):
        spairs = sorted([(keccak256(SLOT1967.to_bytes(32, "big")), ab.rlp(ab._int_bytes(int(IMPL, 16)))),
                         (keccak256(OWNER_SLOT.to_bytes(32, "big")), ab.rlp(ab._int_bytes(word)))])
        sroot = ab.trie_root(spairs); oaddr = bytes.fromhex(owner[2:])
        pairs = sorted([(keccak256(payer), ab.rlp([b"\x01", b"", sroot, keccak256(code)])),
                        (keccak256(bytes.fromhex(IMPL[2:])), ab.rlp([b"\x01", b"", EMPTY_TRIE, bytes.fromhex(IMPL_HASH)])),
                        (keccak256(oaddr), ab.rlp([b"", b"", EMPTY_TRIE, keccak256(b"")]))])
        roots[end] = ab.trie_root(pairs)
        P = lambda prs, k: [hx(x) for x in ab.trie_proof(prs, k)]
        pr[end] = {"payer": {"accountProof": P(pairs, keccak256(payer)),
                             "storageProof": [P(spairs, keccak256(SLOT1967.to_bytes(32, "big"))), P(spairs, keccak256(OWNER_SLOT.to_bytes(32, "big")))]},
                   "implementation": {"accountProof": P(pairs, keccak256(bytes.fromhex(IMPL[2:])))},
                   "owner": {"accountProof": P(pairs, keccak256(oaddr))}}
    pr["parent_header"]["stateRoot"] = hx(roots["at_parent"]); pr["parent_header"]["hash"] = ab.header_hash(pr["parent_header"])
    hdr["stateRoot"] = hx(roots["at_block"]); hdr["parentHash"] = pr["parent_header"]["hash"]; hdr["hash"] = ab.header_hash(hdr)
    ct = d["chain_tx"]
    for o in (tx, ct["log_authorization_used"], ct["log_transfer"]):
        o["blockHash"] = hdr["hash"]
    for o in (ct["log_authorization_used"], ct["log_transfer"]):
        o["transactionHash"] = tx["hash"]
    ct["log_transfer"]["topics"][2] = "0x" + "00" * 12 + au["to"][2:]
    ct["log_transfer"]["data"] = hx(w(int(au["value"])))
    d["settlement"]["transaction"] = tx["hash"]
    if mode == "reverted":
        pass
    return d



def run(d):
    try:
        r = av.verify_bundle(d)
        return r["verdict"], r["checks"]["L2.sig"], r.get("evidence_level"), r.get("reverted")
    except av.Refusal as e:
        return "refused", str(e)


def eoa_v02():
    for p in sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02", "*.json"))):
        d = json.load(open(p))
        if d.get("bundle_version") == "apc-0.2" and len(d["payment_payload"]["payload"]["signature"]) == 132 \
                and "payer_wallet" not in d and run(d)[1] == "verified":
            return d


def forged_eoa(keep_chain=False):
    d = eoa_v02()
    s = d["payment_payload"]["payload"]["signature"]
    d["payment_payload"]["payload"]["signature"] = s[:70] + ("1" if s[70] != "1" else "2") + s[71:]
    if not keep_chain:
        for k in ("chain_tx", "settlement"):
            d.pop(k, None)
    return d


class DeclaredMemberDoesNotLiftFailed(unittest.TestCase):
    """Review 2026-11-01, R1: a declared payer_state / payer_wallet beside a 65-byte signature whose recovery fails."""
    def test_control_without_member(self):
        self.assertTrue(run(forged_eoa())[1].startswith("failed:recovers_"))

    def test_payer_state_rpc_unlisted_code(self):
        d = forged_eoa()
        au = d["payment_payload"]["payload"]["authorization"]
        d["payer_state"] = {"rpc": {"code": {"method": "eth_getCode", "params": [au["from"], "0x10"], "result": "0x6001"}}}
        v, l2 = run(d)[:2]
        self.assertTrue(l2.startswith("failed:recovers_"), l2)
        self.assertEqual(v, "chain_failed")

    def test_payer_state_proof_in_v02(self):
        d = forged_eoa()
        d["payer_state"] = {"proof": {"code": "0x6001", "parent_header": {"hash": "0x00"},
                                      "at_parent": {"payer": {"accountProof": ["0x00"]}},
                                      "at_block": {"payer": {"accountProof": ["0x00"]}}}}
        self.assertTrue(run(d)[1].startswith("failed:recovers_"))

    def test_payer_wallet_unknown_code(self):
        d = forged_eoa()
        au = d["payment_payload"]["payload"]["authorization"]
        blk = "0x10"
        sel = "0x" + keccak256(b"ownerAtIndex(uint256)")[:4].hex() + "%064x" % 0
        d["payer_wallet"] = {"owner_index": "0",
                             "code": {"method": "eth_getCode", "params": [au["from"], blk], "result": "0x6001"},
                             "implementation": {"method": "eth_getStorageAt", "params": [au["from"], av.ERC1967_SLOT, blk], "result": "0x" + "00" * 32},
                             "owner": {"method": "eth_call", "params": [{"to": au["from"], "data": sel}, blk], "result": "0x" + "00" * 32}}
        self.assertTrue(run(d)[1].startswith("failed:recovers_"))

    def test_every_section3_failure_stays_failed(self):
        # review 2 (2026-11-01): the clause keeps every `failed:` of section 3 for 65 bytes, not only failed:recovers_
        # (v outside 27/28; a high-s twin that recovers `from`, which USDC refuses: Amendment 0.3.2)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        base = eoa_v02()
        for k in ("chain_tx", "settlement"):
            base.pop(k, None)
        s = base["payment_payload"]["payload"]["signature"]
        v26 = s[:130] + "1a"
        sv = int(s[66:130], 16)
        twin = s[:66] + "%064x" % (n - sv) + ("1c" if s[130:] == "1b" else "1b")
        au = base["payment_payload"]["payload"]["authorization"]
        for sig, want in ((v26, "failed:v_not_27_or_28"), (twin, "failed:high_s_refused_by_token")):
            d = copy.deepcopy(base)
            d["payment_payload"]["payload"]["signature"] = sig
            self.assertEqual(run(d)[1], want)                                   # control: no member
            d["payer_state"] = {"rpc": {"code": {"method": "eth_getCode", "params": [au["from"], "0x10"], "result": "0x6001"}}}
            self.assertEqual(run(d)[1], want)

    def test_real_msca_unchanged(self):
        p = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_msca_20261101", "m001_rpc_*.json")))[0]
        d = json.load(open(p))         # 32.10: the rule ends in verified, the declared state is not anchored
        self.assertEqual(run(d)[1], "not_evaluated:payer_state_block_not_anchored")
        for k in ("chain_tx", "settlement"):
            d.pop(k)
        self.assertTrue(run(d)[1].startswith("failed:recovers_"))      # declared, nothing executed: section 3 stands
        d = json.load(open(p))         # executed and measured: the state's own reason stays
        d["payer_state"]["rpc"]["wallet"]["implementation"]["result"] = "0x" + "00" * 12 + "11" * 20
        self.assertEqual(run(d)[1], "not_evaluated:wallet_implementation_not_known")
        for k in ("chain_tx", "settlement"):
            d.pop(k)
        self.assertTrue(run(d)[1].startswith("failed:recovers_"))


class RevertedIsNotExecuted(unittest.TestCase):
    """Review 2026-11-01, R2: a receipt proven reverted (B3) is not 'the token executed it' for 32.2."""
    def test_reverted(self):
        d = forge(mode="reverted")
        del d["payer_state"]
        v, l2, _, rev = run(d)
        self.assertTrue(rev)
        self.assertTrue(l2.startswith("failed:recovers_"), l2)

    def test_executed_control(self):
        d = forge()
        del d["payer_state"]
        self.assertEqual(run(d)[1], "not_evaluated:signature_accepted_on_chain_needs_payer_state")


class MadeUpBlockLimit(unittest.TestCase):
    """Review 2026-11-01, R3: a made-up block with made-up state tries gives the owner the bundle chooses; on 19b0ecd
    verified, chain_verified, inclusion_proof, no key of the payer. SPEC 32.10 (0.21.1) closes it: the block is not
    anchored (no canonical final with l1_state proven), so not_evaluated, chain_incomplete, level none."""
    def test_made_up_block(self):
        r = av.verify_bundle(forge(new_to=A, new_value=10 ** 12))
        self.assertEqual((r["verdict"], r["checks"]["L2.sig"], r["evidence_level"], r["block_bound"]),
                         ("chain_incomplete", "not_evaluated:payer_state_block_not_anchored", "none", True))

    def test_control_other_key(self):
        d = forge()
        d["payment_payload"]["payload"]["signature"] = forge(owner_priv=0xB0B)["payment_payload"]["payload"]["signature"]
        self.assertTrue(av.verify_bundle(d)["checks"]["L2.sig"].startswith("failed:msca_signature_recovers_"))


REAL_OWNER = "0x%040x" % ((int(json.load(open(sorted(glob.glob(os.path.join(ROOT, "bundles", "real_msca_20261101", "m*_rpc_*.json")))[0]))
                              ["payer_state"]["rpc"]["wallet"]["owner"]["result"], 16) >> 16) & ((1 << 160) - 1))   # from the first real bundle


def proof_bundle():
    return json.load(open(sorted(glob.glob(os.path.join(ROOT, "bundles", "real_msca_20261101", "m001_proof_*.json")))[0]))


class MutantGaps(unittest.TestCase):
    """Review 2026-11-01: tests for the mutants N02, N05, N07, N08 that test_msca let live."""
    def test_parent_header_not_linked(self):          # N02: a parent header that hashes, numbered N-1, not the parent
        d = proof_bundle()
        pr = d["payer_state"]["proof"]
        au = d["payment_payload"]["payload"]["authorization"]
        payer = bytes.fromhex(au["from"][2:]); code = bytes.fromhex(pr["code"][2:])
        word = (int(REAL_OWNER, 16) << 16) | 1
        spairs = sorted([(keccak256(SLOT1967.to_bytes(32, "big")), ab.rlp(ab._int_bytes(int(IMPL, 16)))),
                         (keccak256(OWNER_SLOT.to_bytes(32, "big")), ab.rlp(ab._int_bytes(word)))])
        oaddr = bytes.fromhex(REAL_OWNER[2:])
        pairs = sorted([(keccak256(payer), ab.rlp([b"\x01", b"", ab.trie_root(spairs), keccak256(code)])),
                        (keccak256(bytes.fromhex(IMPL[2:])), ab.rlp([b"\x01", b"", EMPTY_TRIE, bytes.fromhex(IMPL_HASH)])),
                        (keccak256(oaddr), ab.rlp([b"", b"", EMPTY_TRIE, keccak256(b"")]))])
        P = lambda prs, k: [hx(x) for x in ab.trie_proof(prs, k)]
        pr["at_parent"] = {"payer": {"accountProof": P(pairs, keccak256(payer)),
                                     "storageProof": [P(spairs, keccak256(SLOT1967.to_bytes(32, "big"))),
                                                      P(spairs, keccak256(OWNER_SLOT.to_bytes(32, "big")))]},
                           "implementation": {"accountProof": P(pairs, keccak256(bytes.fromhex(IMPL[2:])))},
                           "owner": {"accountProof": P(pairs, keccak256(oaddr))}}
        pr["parent_header"]["stateRoot"] = hx(ab.trie_root(pairs))
        pr["parent_header"]["hash"] = ab.header_hash(pr["parent_header"])
        self.assertEqual(run(d)[1], "failed:payer_state_parent_header_not_parent")

    def test_unlisted_code_one_extra_member(self):      # N05: one wallet member beside an unlisted code is refused
        d = proof_bundle()
        pr = d["payer_state"]["proof"]
        pr["code"] = "0x6001"
        for end in ("at_parent", "at_block"):
            del pr[end]["payer"]["storageProof"], pr[end]["owner"]
            if end == "at_parent":
                del pr[end]["implementation"]
        self.assertEqual(run(d)[0], "refused")

    def test_32_2_only_on_a_recovery_to_another_address(self):     # N07: v 29 executed stays failed:v_not_27_or_28
        d = forge(vbyte=29)
        del d["payer_state"]
        self.assertEqual(run(d)[1], "failed:v_not_27_or_28")

    def test_replay_safe_domain_reads_the_chain(self):  # N08: chainId of accepted.network in the replay-safe domain
        d = json.load(open(sorted(glob.glob(os.path.join(ROOT, "bundles", "real_msca_20261101", "m001_rpc_*.json")))[0]))
        for k in ("chain_tx", "settlement"):
            d.pop(k)
        acc = d["payment_payload"]["accepted"]
        acc["network"] = "eip155:1"
        au = d["payment_payload"]["payload"]["authorization"]
        w = d["payer_state"]["rpc"]["wallet"]
        w["owner"]["result"] = "0x" + "%064x" % ((int(A, 16) << 16) | 1)
        w["owner_code"]["params"][0] = A
        dom = {"name": acc["extra"]["name"], "version": acc["extra"]["version"], "chainId": 1, "verifyingContract": acc["asset"]}
        msg = {"from": au["from"], "to": au["to"], "value": int(au["value"]), "validAfter": int(au["validAfter"]),
               "validBefore": int(au["validBefore"]), "nonce": au["nonce"]}
        h = signing_digest(dom, "TransferWithAuthorization", av.TYPES, msg, av.DOMAIN4)
        # the replay-safe hash written here from the sources (BaseERC712CompliantAccount.sol 34-42), not taken from apc_msca
        ds = keccak256(keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
                       + keccak256(b"Circle_SingleOwnerMSCA") + keccak256(b"1.0.0") + (1).to_bytes(32, "big")
                       + bytes(12) + bytes.fromhex(au["from"][2:]))
        rs = keccak256(b"\x19\x01" + ds + keccak256(keccak256(b"CircleSingleOwnerMSCAMessage(bytes32 hash)") + h))
        r, s_, rec = sign(rs, ATT, 0x77)
        d["payment_payload"]["payload"]["signature"] = hx(r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([27 + rec]))
        res = av.verify_bundle(d)
        # 32.10: the rule ends in verified only with chainId 1 in the domain (the note says so), then the declared state is
        # not anchored and, without chain_tx, section 3 stands: failed:recovers_…_not_from. With a constant 8453 the
        # recovery gives another address: failed:msca_signature_recovers_…_not_owner, and no such note
        self.assertEqual((res["checks"]["L2.sig"][:16], res["payer_state"]), ("failed:recovers_", "declared_rpc"))
        self.assertTrue(any("payer_state says not_evaluated:payer_state_block_not_anchored" in x for x in res["notes"]))


if __name__ == "__main__":
    unittest.main()
