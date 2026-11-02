"""agent-payment-chain, block inclusion (SPEC 0.3 draft, rule B1-B3). Standard library only, plus the keccak256 of
x402-signature-vectors tag v1.4.0 at its hashes (apc_siglib, SPEC 32.12; same APC_SIGLIB as apc_verify).

Given the JSON-RPC replies for one block (eth_getBlockByNumber with hashes only, eth_getBlockReceipts), it recomputes
  - the block hash = keccak256(rlp(header)) from the header fields, and
  - the receipts root = root of the ordered Merkle-Patricia trie with key rlp(index) and value = encoded receipt,
and compares both with what the replies state. When both match, every receipt (status, logs) is bound to that block
hash. Whether that block hash is on the canonical chain is NOT decided here: it is an input the reader must trust or
check elsewhere (two independent RPC providers, an L1 output root). The report says so.

  python3 apc_block.py BLOCK.json RECEIPTS.json
"""
import json
import re
import sys

import apc_siglib  # noqa: E402

# SPEC 32.12 (f): x402-signature-vectors v1.4.0 run from the bytes hashed, never by name; without it, as the program run,
# one line on standard error and exit 64 (apc_siglib.guard; SPEC 32.11 (c)), as a module a SiglibError (an ImportError)
_eip712 = apc_siglib.guard("apc_block", __name__ == "__main__").eip712

# SPEC 29.2: Keccak-256 here is pure Python (about 3 s of CPU per MiB, measured 2026-10-26), so the bytes one
# verification may hash are bounded. apc_verify.verify_bundle opens the count (KECCAK_SPENT = 0) and closes it; outside a
# verification nothing is counted. lib.eip712.keccak256 is replaced so that its signing_digest counts too.
KECCAK_BUDGET = 1 << 20
KECCAK_SPENT = None
_KECCAK = getattr(_eip712, "_apc_raw_keccak256", _eip712.keccak256)


class HashBudget(Exception):
    """More bytes to hash than KECCAK_BUDGET in one verification (apc_verify turns it into a refusal)."""


def keccak256(data):
    global KECCAK_SPENT
    if KECCAK_SPENT is not None:
        KECCAK_SPENT += len(data)
        if KECCAK_SPENT > KECCAK_BUDGET:
            raise HashBudget("more than %d bytes to hash with Keccak-256 (SPEC 29.2)" % KECCAK_BUDGET)
    return _KECCAK(data)


_eip712._apc_raw_keccak256 = _KECCAK
_eip712.keccak256 = keccak256


class BlockRefusal(Exception):
    pass


# Header fields in consensus order. The fields after baseFeePerGas were added by later forks (London, Shanghai,
# Cancun, Prague); a header carries a PREFIX of the optional list and never a gap. Closed list: anything else refused.
HEADER_BASE = ("parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
               "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce")
HEADER_OPT = ("baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot",
              "requestsHash")
HEADER_SIZES = {"parentHash": 32, "sha3Uncles": 32, "miner": 20, "stateRoot": 32, "transactionsRoot": 32,
                "receiptsRoot": 32, "logsBloom": 256, "mixHash": 32, "nonce": 8, "withdrawalsRoot": 32,
                "parentBeaconBlockRoot": 32, "requestsHash": 32}
HEADER_QTY = ("difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas", "blobGasUsed",
              "excessBlobGas")
# Reply members that are not header fields but are allowed in an eth_getBlockByNumber reply (closed list).
BLOCK_EXTRA = ("hash", "size", "uncles", "transactions", "withdrawals", "totalDifficulty")
RECEIPT_TYPES = (0x00, 0x01, 0x02, 0x03, 0x04, 0x7E)


_HEXDATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_QTY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,63})\Z")


def _hexbytes(v, what, size=None):
    # ASCII hex digit pairs only: bytes.fromhex alone would also take spaces
    if not isinstance(v, str) or not _HEXDATA.match(v):
        raise BlockRefusal("not_hex_bytes:" + what)
    b = bytes.fromhex(v[2:])
    if size is not None and len(b) != size:
        raise BlockRefusal("wrong_size:%s:%d" % (what, len(b)))
    return b


def _qty(v, what):
    """JSON-RPC quantity: 0x0 or 0x without leading zeros, lower-case ASCII hex, at most 256 bits (Ethereum JSON-RPC
    spec, 'quantity'). int() alone would also take a sign, '_', spaces and non-ASCII digits."""
    if not isinstance(v, str) or not _QTY.match(v):
        raise BlockRefusal("not_quantity:" + what)
    return int(v[2:], 16)


def _int_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def rlp(x):
    if isinstance(x, bytes):
        if len(x) == 1 and x[0] < 0x80:
            return x
        return _len(len(x), 0x80) + x
    if isinstance(x, list):
        body = b"".join(rlp(i) for i in x)
        return _len(len(body), 0xC0) + body
    raise TypeError(type(x))


def _len(n, off):
    if n < 56:
        return bytes([off + n])
    b = _int_bytes(n)
    return bytes([off + 55 + len(b)]) + b


def header_hash(block):
    if not isinstance(block, dict):
        raise BlockRefusal("block_not_object")
    allowed = set(HEADER_BASE) | set(HEADER_OPT) | set(BLOCK_EXTRA)
    extra = sorted(set(block) - allowed)
    if extra:
        raise BlockRefusal("unknown_block_member:" + extra[0])
    missing = [k for k in HEADER_BASE if k not in block]
    if missing:
        raise BlockRefusal("missing_header_field:" + missing[0])
    present = [k for k in HEADER_OPT if k in block]
    if present != list(HEADER_OPT[:len(present)]):
        raise BlockRefusal("header_fields_not_a_fork_prefix")
    items = []
    for k in HEADER_BASE + tuple(present):
        if k in HEADER_QTY:
            items.append(_int_bytes(_qty(block[k], k)))
        elif k == "extraData":
            items.append(_hexbytes(block[k], k))
        else:
            items.append(_hexbytes(block[k], k, HEADER_SIZES[k]))
    return "0x" + keccak256(rlp(items)).hex()


def encode_receipt(r, i):
    w = "receipt[%d]" % i
    if not isinstance(r, dict):
        raise BlockRefusal("receipt_not_object:" + w)
    t = _qty(r.get("type", "0x"), w + ".type") if "type" in r else 0
    if t not in RECEIPT_TYPES:
        raise BlockRefusal("unknown_receipt_type:%s:%d" % (w, t))
    if "status" not in r:
        raise BlockRefusal("receipt_without_status:" + w)   # pre-Byzantium root receipts are out of scope
    st = _qty(r["status"], w + ".status")
    if st not in (0, 1):
        raise BlockRefusal("bad_status:" + w)
    logs = r.get("logs")
    if not isinstance(logs, list):
        raise BlockRefusal("logs_not_list:" + w)
    enc_logs = []
    for j, lg in enumerate(logs):
        p = "%s.logs[%d]" % (w, j)
        if not isinstance(lg, dict) or not isinstance(lg.get("topics"), list) or len(lg["topics"]) > 4:
            raise BlockRefusal("bad_log:" + p)
        enc_logs.append([_hexbytes(lg.get("address"), p + ".address", 20),
                         [_hexbytes(tp, p + ".topic", 32) for tp in lg["topics"]],
                         _hexbytes(lg.get("data"), p + ".data")])
    body = [_int_bytes(st), _int_bytes(_qty(r.get("cumulativeGasUsed"), w + ".cumulativeGasUsed")),
            _hexbytes(r.get("logsBloom"), w + ".logsBloom", 256), enc_logs]
    if t == 0x7E:
        # OP Stack deposit receipt (Canyon): depositNonce and depositReceiptVersion appended when present.
        if "depositNonce" in r:
            body.append(_int_bytes(_qty(r["depositNonce"], w + ".depositNonce")))
            if "depositReceiptVersion" in r:
                body.append(_int_bytes(_qty(r["depositReceiptVersion"], w + ".depositReceiptVersion")))
        elif "depositReceiptVersion" in r:
            raise BlockRefusal("deposit_version_without_nonce:" + w)
    elif "depositNonce" in r or "depositReceiptVersion" in r:
        raise BlockRefusal("deposit_fields_on_non_deposit:" + w)
    enc = rlp(body)
    return enc if t == 0 else bytes([t]) + enc


# Ordered Merkle-Patricia trie (Ethereum Yellow Paper, appendix D), computed from scratch over all (key, value) pairs.
def _nibbles(b):
    out = []
    for c in b:
        out += [c >> 4, c & 15]
    return out


def _hp(nibs, leaf):
    f = 2 if leaf else 0
    if len(nibs) % 2:
        return bytes([(f + 1) << 4 | nibs[0]]) + bytes(nibs[i] << 4 | nibs[i + 1] for i in range(1, len(nibs), 2))
    return bytes([f << 4]) + bytes(nibs[i] << 4 | nibs[i + 1] for i in range(0, len(nibs), 2))


def _ref(node):
    e = rlp(node)
    return e if len(e) < 32 else keccak256(e)


def _node(items, depth):
    """items: list of (nibbles, value), keys unique and sorted. Returns the node structure (list)."""
    if len(items) == 1:
        k, v = items[0]
        return [_hp(k[depth:], True), v]
    # common prefix beyond depth
    first, last = items[0][0], items[-1][0]
    n = depth
    while n < len(first) and n < len(last) and first[n] == last[n]:
        n += 1
    if n > depth:
        child = _node(items, n)
        return [_hp(first[depth:n], False), _child(child)]
    branch = [b""] * 17
    for d in range(16):
        sub = [it for it in items if len(it[0]) > depth and it[0][depth] == d]
        if sub:
            branch[d] = _child(_node(sub, depth + 1))
    term = [it for it in items if len(it[0]) == depth]
    if term:
        branch[16] = term[0][1]
    return branch


def _child(node):
    e = rlp(node)
    return node if len(e) < 32 else keccak256(e)


def trie_root(pairs):
    if not pairs:
        return keccak256(rlp(b""))
    items = sorted((_nibbles(k), v) for k, v in pairs)
    for a, b in zip(items, items[1:]):
        if a[0] == b[0]:
            raise BlockRefusal("duplicate_trie_key")
    return keccak256(rlp(_node(items, 0)))


def trie_proof(pairs, key):
    """The nodes on the path from the root to `key` (each RLP-encoded), as eth_getProof gives them for accounts."""
    items = sorted((_nibbles(k), v) for k, v in pairs)
    target, out, depth = _nibbles(key), [], 0
    while True:
        node = _node(items, depth)
        out.append(rlp(node))
        if len(node) == 2:
            pre = _hp_decode(node[0])[0]
            if node[0][0] >> 4 >= 2:          # leaf: done
                return out
            depth += len(pre)                  # extension: the child is the next node
        elif depth == len(target):
            return out                         # value held in the branch's 17th slot
        else:
            depth += 1
        items = [it for it in items if it[0][:depth] == target[:depth]]
        if not items:
            raise BlockRefusal("proof_key_absent")
        if len(rlp(_node(items, depth))) < 32:   # embedded child: it is inside the parent, not a separate node
            return out


def _hp_decode(b):
    if not b:
        raise BlockRefusal("proof_bad_path")
    f = b[0] >> 4
    if f > 3:
        raise BlockRefusal("proof_bad_path_flag")
    nibs = ([b[0] & 15] if f & 1 else []) + [n for c in b[1:] for n in (c >> 4, c & 15)]
    if not f & 1 and b[0] & 15:
        raise BlockRefusal("proof_bad_path_padding")
    return nibs, f >= 2


RLP_MAX_DEPTH = 16          # SPEC 29.2: lists nested at most 16 deep (a receipt is 4, a trie node with embedded nodes less)


def rlp_decode(b):
    item, end = _rlp_item(b, 0)
    if end != len(b):
        raise BlockRefusal("rlp_trailing_bytes")
    return item


def _rlp_item(b, i, depth=0):
    if i >= len(b):
        raise BlockRefusal("rlp_truncated")
    p = b[i]
    if p < 0x80:
        return b[i:i + 1], i + 1
    if p < 0xB8:
        n = p - 0x80
        s = b[i + 1:i + 1 + n]
        if len(s) != n or (n == 1 and s[0] < 0x80):
            raise BlockRefusal("rlp_bad_short_string")
        return s, i + 1 + n
    if p < 0xC0:
        ll = p - 0xB7
        n = _rlp_long(b, i + 1, ll)
        s = b[i + 1 + ll:i + 1 + ll + n]
        if len(s) != n:
            raise BlockRefusal("rlp_truncated")
        return s, i + 1 + ll + n
    if p < 0xF8:
        n, j = p - 0xC0, i + 1
    else:
        ll = p - 0xF7
        n = _rlp_long(b, i + 1, ll)
        j = i + 1 + ll
    if depth >= RLP_MAX_DEPTH:      # SPEC 29.2: this list would be the 17th nested (an empty one too, independent review 27/10)
        raise BlockRefusal("rlp_nested_too_deep")
    end, out = j + n, []
    if end > len(b):
        raise BlockRefusal("rlp_truncated")
    while j < end:
        it, j = _rlp_item(b, j, depth + 1)
        out.append(it)
    if j != end:
        raise BlockRefusal("rlp_list_overrun")
    return out, end


def _rlp_long(b, i, ll):
    s = b[i:i + ll]
    if len(s) != ll or s[0] == 0:
        raise BlockRefusal("rlp_bad_length")
    n = int.from_bytes(s, "big")
    if n < 56:
        raise BlockRefusal("rlp_non_canonical_length")
    return n


def verify_proof(root, key, proof):
    """Walk `proof` (list of RLP-encoded nodes) from `root` (32 bytes) along `key`; return the value or refuse."""
    if not isinstance(proof, list) or not proof or len(proof) > 64:
        raise BlockRefusal("proof_not_a_node_list")
    nibs, want, i, k = _nibbles(key), root, 0, 0
    node_b = None
    while True:
        if isinstance(want, bytes) and len(want) == 32:
            if i >= len(proof):
                raise BlockRefusal("proof_too_short")
            node_b = proof[i]
            i += 1
            if keccak256(node_b) != want:
                raise BlockRefusal("proof_node_hash_mismatch")
            node = rlp_decode(node_b)
        elif isinstance(want, list):
            node = want                         # embedded node (its RLP is shorter than 32 bytes)
        else:
            raise BlockRefusal("proof_bad_reference")
        if not isinstance(node, list):
            raise BlockRefusal("proof_node_not_list")
        if len(node) == 17:
            if k == len(nibs):
                if i != len(proof) or not isinstance(node[16], bytes) or not node[16]:
                    raise BlockRefusal("proof_value_absent")
                return node[16]
            want, k = node[nibs[k]], k + 1
            if want == b"":
                raise BlockRefusal("proof_key_absent")
        elif len(node) == 2:
            if not isinstance(node[0], bytes):
                raise BlockRefusal("proof_bad_path")
            pre, leaf = _hp_decode(node[0])
            if not leaf and not pre:            # an extension carries at least one nibble (Yellow Paper, appendix D)
                raise BlockRefusal("proof_empty_extension")
            if nibs[k:k + len(pre)] != pre:
                raise BlockRefusal("proof_key_absent")
            k += len(pre)
            if leaf:
                if k != len(nibs) or i != len(proof) or not isinstance(node[1], bytes):
                    raise BlockRefusal("proof_leaf_mismatch")
                return node[1]
            want = node[1]
            if isinstance(want, bytes) and len(want) != 32:
                raise BlockRefusal("proof_bad_reference")
        else:
            raise BlockRefusal("proof_node_bad_arity")


def receipts_root(receipts):
    if not isinstance(receipts, list):
        raise BlockRefusal("receipts_not_list")
    return "0x" + trie_root([(rlp(_int_bytes(i)), encode_receipt(r, i)) for i, r in enumerate(receipts)]).hex()


def check_block(block, receipts):
    """B1 header hash, B2 receipts root, B3 receipts belong to this block (hash, number, index order, count)."""
    res = {}
    try:
        h = header_hash(block)
        res["B1"] = "verified" if h == str(block.get("hash", "")).lower() else "failed:header_hash_mismatch"
        rr = receipts_root(receipts)
        res["B2"] = ("verified" if rr == str(block["receiptsRoot"]).lower() else "failed:receipts_root_mismatch")
        b3 = "verified"
        txs = block.get("transactions")
        if isinstance(txs, list) and len(txs) != len(receipts):
            b3 = "failed:receipt_count_not_transaction_count"
        for i, r in enumerate(receipts):
            if (str(r.get("blockHash", "")).lower() != h or r.get("blockNumber") != block["number"]
                    or r.get("transactionIndex") != hex(i)):
                b3 = "failed:receipt_not_in_this_block_position:%d" % i
                break
            if isinstance(txs, list) and isinstance(txs[i], str) and str(r.get("transactionHash", "")).lower() != txs[i].lower():
                b3 = "failed:receipt_tx_hash_not_block_tx:%d" % i
                break
        res["B3"] = b3
    except BlockRefusal as e:
        return {"verdict": "refused", "reason": str(e)}
    res["verdict"] = "block_bound" if all(v == "verified" for v in res.values()) else "block_failed"
    res["block_hash"] = h
    res["note"] = "receipts bound to this block hash; whether the hash is canonical is not decided here"
    return res


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 64
    try:
        with open(argv[1]) as fb, open(argv[2]) as fr:
            b, r = json.load(fb), json.load(fr)
        b = b.get("result", b) if isinstance(b, dict) and "jsonrpc" in b else b
        r = r.get("result", r) if isinstance(r, dict) and "jsonrpc" in r else r
    except (OSError, ValueError) as e:
        print(json.dumps({"verdict": "refused", "reason": "unreadable:%s" % type(e).__name__}))
        return 3
    out = check_block(b, r)
    print(json.dumps(out, indent=1))
    return {"block_bound": 0, "block_failed": 1}.get(out["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
