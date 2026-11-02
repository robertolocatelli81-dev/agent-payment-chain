"""apc_l1proof prototype: account and storage proofs (present and absent keys), code hash, L1 header chain.
Tries are built here with apc_block.trie_root (the same builder that recomputes the real receipts roots of
bundles/real_v03); the proofs are the paths eth_getProof returns (root first)."""
import copy
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests import real_corpus  # noqa: E402
# only test_header_chain reads the corpus (a local_only set): it names it itself
import apc_block as ab  # noqa: E402
import apc_l1proof as lp  # noqa: E402
from apc_block import BlockRefusal, keccak256  # noqa: E402


def path(pairs, key):
    """Nodes on the path to `key`, also when `key` is absent (then the path ends where it diverges)."""
    items = sorted((ab._nibbles(k), v) for k, v in pairs)
    target, out, depth = ab._nibbles(key), [], 0
    while True:
        node = ab._node(items, depth)
        out.append(ab.rlp(node))
        if len(node) == 2:
            pre = ab._hp_decode(node[0])[0]
            if node[0][0] >> 4 >= 2 or target[depth:depth + len(pre)] != pre:
                return out
            depth += len(pre)
        else:
            depth += 1
        items = [it for it in items if it[0][:depth] == target[:depth]]
        if not items or len(ab.rlp(ab._node(items, depth))) < 32:
            return out


def word(v):
    return ab.rlp(ab._int_bytes(v))


SLOTS = {0: 1, 1: 0xdead, 7: 2 ** 255, 0x51: 5}          # slot -> value (nonzero; zero slots are absent)
STORE = [(keccak256(s.to_bytes(32, "big")), word(v)) for s, v in SLOTS.items()]
SROOT = ab.trie_root(STORE)
CODE = bytes.fromhex("6080604052") + b"\x01" * 40
ADDR = bytes.fromhex("909f6cf47ed12f010a796527f562bfc26c7f4e72")
OTHERS = [bytes([i]) * 20 for i in range(1, 30)]
ACCTS = [(keccak256(ADDR), ab.rlp([ab._int_bytes(1), ab._int_bytes(0), SROOT, keccak256(CODE)]))] + \
        [(keccak256(a), ab.rlp([ab._int_bytes(i), ab._int_bytes(10 ** 18), lp.EMPTY_TRIE, lp.EMPTY_CODE]))
         for i, a in enumerate(OTHERS)]
STATE = ab.trie_root(ACCTS)


class L1Proof(unittest.TestCase):
    def test_account_and_storage(self):
        n, bal, sr, ch = lp.account(STATE, ADDR, path(ACCTS, keccak256(ADDR)))
        self.assertEqual((n, bal, sr), (1, 0, SROOT))
        lp.code(ch, CODE)
        for s, v in SLOTS.items():
            self.assertEqual(lp.storage(sr, s, path(STORE, keccak256(s.to_bytes(32, "big")))), v)

    def test_absent_slot_is_zero(self):
        for s in (2, 3, 0x52, 10 ** 9):
            k = keccak256(s.to_bytes(32, "big"))
            self.assertEqual(lp.storage(SROOT, s, path(STORE, k)), 0)

    def test_absent_account(self):
        a = b"\x77" * 20
        self.assertEqual(lp.account(STATE, a, path(ACCTS, keccak256(a))), (0, 0, lp.EMPTY_TRIE, lp.EMPTY_CODE))

    def test_present_slot_cannot_be_shown_absent(self):
        # the proof of slot 2 (absent) offered for slot 1: the walk follows slot 1's key and does not end absent
        p = path(STORE, keccak256((2).to_bytes(32, "big")))
        try:
            v = lp.storage(SROOT, 1, p)
        except BlockRefusal:
            return
        self.assertEqual(v, SLOTS[1])

    def test_truncated_or_padded_proof_refused(self):
        p = path(STORE, keccak256((7).to_bytes(32, "big")))
        with self.assertRaises(BlockRefusal):
            lp.storage(SROOT, 7, p[:-1])
        with self.assertRaises(BlockRefusal):
            lp.storage(SROOT, 7, p + [p[-1]])
        absent = path(STORE, keccak256((3).to_bytes(32, "big")))
        with self.assertRaises(BlockRefusal):
            lp.storage(SROOT, 3, absent + [p[-1]])

    def test_forged_node_refused(self):
        p = path(ACCTS, keccak256(ADDR))
        bad = list(p)
        bad[-1] = bad[-1][:-1] + bytes([bad[-1][-1] ^ 1])
        with self.assertRaises(BlockRefusal):
            lp.account(STATE, ADDR, bad)

    def test_coherent_forgery_needs_another_root(self):
        # rebuild the whole trie with slot 0 = 0 (a blacklist entry erased): the proof is valid, but for another root
        store2 = [x for x in STORE if x[0] != keccak256(bytes(32))]
        root2 = ab.trie_root(store2)
        p = path(store2, keccak256(bytes(32)))
        self.assertEqual(lp.storage(root2, 0, p), 0)
        with self.assertRaises(BlockRefusal):
            lp.storage(SROOT, 0, p)

    def test_empty_proof_is_not_an_absence(self):
        with self.assertRaises(BlockRefusal):
            lp.storage(SROOT, 2, [])
        with self.assertRaises(BlockRefusal):
            lp.account(STATE, b"\x77" * 20, [])
        self.assertEqual(lp.storage(lp.EMPTY_TRIE, 2, []), 0)          # the empty trie needs no node

    def test_absence_by_divergence_with_a_node_more_refused(self):
        # a key whose path ends at a leaf of another key (shared first nibbles): absent, and nothing may follow
        pairs = [(bytes([0x12]) + bytes(31), word(1)), (bytes([0x34]) + bytes(31), word(2))]
        root = ab.trie_root(pairs)
        key = bytes([0x12]) + b"\x01" + bytes(30)
        p = path(pairs, key)
        self.assertIsNone(lp.proof_get(root, key, p))
        self.assertEqual(ab.rlp_decode(p[-1])[0][0] >> 4 in (2, 3), True)       # it ends on a leaf: divergence
        with self.assertRaises(BlockRefusal):
            lp.proof_get(root, key, p + [p[0]])

    def test_storage_word_canonical(self):
        for raw in (b"", b"\x00", b"\x00\x05", b"\x01" * 33):
            pairs = [(keccak256((9).to_bytes(32, "big")), ab.rlp(raw))]
            root = ab.trie_root(pairs)
            with self.assertRaises(BlockRefusal, msg=raw):
                lp.storage(root, 9, path(pairs, keccak256((9).to_bytes(32, "big"))))

    def test_account_fields_sized(self):
        a = b"\x66" * 20
        for acct in ([b"\x01", b"", SROOT[:31], lp.EMPTY_CODE], [b"\x01", b"", SROOT, lp.EMPTY_CODE[:31]],
                     [b"\x01", b"", SROOT], [b"\x01", b"", [SROOT], lp.EMPTY_CODE], [[b"\x01"], b"", SROOT, lp.EMPTY_CODE]):
            pairs = [(keccak256(a), ab.rlp(acct))]
            with self.assertRaises(BlockRefusal, msg=repr(acct)[:40]):
                lp.account(ab.trie_root(pairs), a, path(pairs, keccak256(a)))

    def test_proof_nodes_must_be_bytes(self):
        p = path(STORE, keccak256((7).to_bytes(32, "big")))
        with self.assertRaises(BlockRefusal):
            lp.storage(SROOT, 7, ["0x" + x.hex() for x in p])          # eth_getProof hex strings, not decoded

    def test_leaf_value_must_be_bytes(self):
        k = keccak256((4).to_bytes(32, "big"))
        node = [ab._hp(ab._nibbles(k), True), [b"\x05"]]             # a leaf whose value is a list
        enc = ab.rlp(node)
        with self.assertRaises(BlockRefusal):
            lp.proof_get(keccak256(enc), k, [enc])

    def test_code_hash(self):
        with self.assertRaises(BlockRefusal):
            lp.code(keccak256(CODE), CODE + b"\x00")

    def test_mapping_slot(self):
        # Solidity: keccak256(h(k) . p); a value-type key is left-padded to 32 bytes
        k = bytes(12) + ADDR
        self.assertEqual(lp.mapping_slot(k, 3), int.from_bytes(keccak256(k + (3).to_bytes(32, "big")), "big"))

    @real_corpus.unless("real_v03_canonical")
    def test_header_chain(self):
        f = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "bundles", "real_v03_canonical", "*.json")))[0]
        with open(f) as fh:
            h0 = json.load(fh)["inclusion"]["block_header"]
        h0 = {k: v for k, v in h0.items() if k != "hash"}
        chain, parent = [], h0
        for i in range(3):        # three children of a real header, built here: newest first
            c = copy.deepcopy(parent)
            c["parentHash"] = ab.header_hash(parent)
            c["number"] = hex(int(parent["number"], 16) + 1)
            chain.insert(0, parent)
            parent = c
        chain.insert(0, parent)
        top = ab.header_hash(chain[0])
        self.assertIs(lp.header_chain(top, chain), chain[-1])
        with self.assertRaises(BlockRefusal):
            lp.header_chain("0x" + "00" * 32, chain)
        bad = copy.deepcopy(chain)
        bad[2]["stateRoot"] = "0x" + "11" * 32           # another state under the same checkpoint
        with self.assertRaises(BlockRefusal):
            lp.header_chain(top, bad)
        with self.assertRaises(BlockRefusal):
            lp.header_chain(top, chain[:1] + chain[2:])   # a gap
        skip = copy.deepcopy(chain[1:])
        skip.insert(0, dict(copy.deepcopy(chain[0]), parentHash=ab.header_hash(skip[0]),
                            number=hex(int(skip[0]["number"], 16) + 2)))
        with self.assertRaises(BlockRefusal):              # hash-linked, but the numbers jump
            lp.header_chain(ab.header_hash(skip[0]), skip)


if __name__ == "__main__":
    unittest.main()
