"""Build the `inclusion` member of an apc-0.3 bundle from the JSON-RPC replies of one block (read-only; no network here).

  python3 tools/inclusion.py BLOCK_FULL.json RECEIPTS.json TX_HASH > inclusion.json

BLOCK_FULL.json = eth_getBlockByNumber(n, true); RECEIPTS.json = eth_getBlockReceipts(n). The tool encodes every
transaction (EIP-2718 types 0, 1, 2, 3, 4 and the OP Stack deposit 0x7e) and every receipt, checks that each encoded
transaction hashes to the hash the RPC states, that the two trie roots and the header hash recompute, and only then
emits the header and the two Merkle proofs for TX_HASH. Any mismatch stops it: a proof is never built on a root it
could not recompute.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/inclusion", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_block as ab  # noqa: E402
from apc_block import BlockRefusal, _int_bytes, keccak256, rlp  # noqa: E402

HEADER_KEYS = ab.HEADER_BASE + ab.HEADER_OPT + ("hash",)


def _q(v):
    return _int_bytes(ab._qty(v, "tx"))


def _b(v, size=None):
    return ab._hexbytes(v, "tx", size)


def _to(v):
    return b"" if v is None else _b(v, 20)


def _al(v):
    return [[_b(e["address"], 20), [_b(k, 32) for k in e["storageKeys"]]] for e in v]


def _sig(t):
    yp = t.get("yParity", t.get("v"))
    return [_q(yp), _q(t["r"]), _q(t["s"])]


def encode_tx(t):
    ty = ab._qty(t["type"], "type")
    if ty == 0:
        return rlp([_q(t["nonce"]), _q(t["gasPrice"]), _q(t["gas"]), _to(t["to"]), _q(t["value"]), _b(t["input"]),
                    _q(t["v"]), _q(t["r"]), _q(t["s"])])
    if ty == 1:
        body = [_q(t["chainId"]), _q(t["nonce"]), _q(t["gasPrice"]), _q(t["gas"]), _to(t["to"]), _q(t["value"]),
                _b(t["input"]), _al(t["accessList"])] + _sig(t)
    elif ty in (2, 3, 4):
        body = [_q(t["chainId"]), _q(t["nonce"]), _q(t["maxPriorityFeePerGas"]), _q(t["maxFeePerGas"]), _q(t["gas"]),
                _to(t["to"]), _q(t["value"]), _b(t["input"]), _al(t["accessList"])]
        if ty == 3:
            body += [_q(t["maxFeePerBlobGas"]), [_b(h, 32) for h in t["blobVersionedHashes"]]]
        if ty == 4:
            body += [[[_q(a["chainId"]), _b(a["address"], 20), _q(a["nonce"]), _q(a["yParity"]), _q(a["r"]),
                       _q(a["s"])] for a in t["authorizationList"]]]
        body += _sig(t)
    elif ty == 0x7E:
        body = [_b(t["sourceHash"], 32), _b(t["from"], 20), _to(t["to"]), _q(t.get("mint", "0x0")), _q(t["value"]),
                _q(t["gas"]), b"\x01" if t.get("isSystemTx") else b"", _b(t["input"])]
    else:
        raise BlockRefusal("unknown_tx_type:%d" % ty)
    return bytes([ty]) + rlp(body)


def build(block, receipts, tx_hash):
    txs = block["transactions"]
    if len(txs) != len(receipts):
        raise BlockRefusal("receipt_count_not_transaction_count")
    keys = [rlp(_int_bytes(i)) for i in range(len(txs))]
    enc_tx = []
    for i, t in enumerate(txs):
        e = encode_tx(t)
        if "0x" + keccak256(e).hex() != t["hash"].lower():
            raise BlockRefusal("tx_encoding_does_not_hash_to_rpc_hash:%d" % i)
        enc_tx.append(e)
    enc_rc = [ab.encode_receipt(r, i) for i, r in enumerate(receipts)]
    tx_pairs, rc_pairs = list(zip(keys, enc_tx)), list(zip(keys, enc_rc))
    if "0x" + ab.trie_root(tx_pairs).hex() != block["transactionsRoot"].lower():
        raise BlockRefusal("transactions_root_mismatch")
    if "0x" + ab.trie_root(rc_pairs).hex() != block["receiptsRoot"].lower():
        raise BlockRefusal("receipts_root_mismatch")
    header = {k: block[k] for k in HEADER_KEYS if k in block}
    if ab.header_hash(header) != block["hash"].lower():
        raise BlockRefusal("header_hash_mismatch")
    idx = next((i for i, t in enumerate(txs) if t["hash"].lower() == tx_hash.lower()), None)
    if idx is None:
        raise BlockRefusal("tx_not_in_block")
    return {"block_header": header, "transaction_index": hex(idx),
            "tx_proof": ["0x" + n.hex() for n in ab.trie_proof(tx_pairs, keys[idx])],
            "receipt_proof": ["0x" + n.hex() for n in ab.trie_proof(rc_pairs, keys[idx])]}


def _result(path):
    with open(path) as fh:
        d = json.load(fh)
    return d["result"] if isinstance(d, dict) and "jsonrpc" in d else d


def main(argv):
    if len(argv) != 4:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 64
    try:
        out = build(_result(argv[1]), _result(argv[2]), argv[3])
    except BlockRefusal as e:
        print("refused:", e, file=sys.stderr)
        return 3
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
