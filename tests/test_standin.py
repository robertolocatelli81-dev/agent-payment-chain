"""The stand-in of tools/siglib_standin: a second implementation of keccak256, EIP-712 and the recovery, written from the
references, checked here against the real data. Since apc_verify 0.21.3 (SPEC 32.12 (f)) the verifier runs only the bytes
of x402-signature-vectors v1.4.0 at their hashes: APC_SIGLIB=tools/siglib_standin is exit 64, the stand-in is never the
verifier's library. Its modules are loaded here by file path under their own names: `from lib...` would return the real
library, which apc_siglib registers under those names. keccak256 on known digests and real block headers; recovery of the payer of real payments."""
import glob
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(HERE, "tools", "siglib_standin", "lib")
sys.path.insert(0, HERE)
from tests import real_corpus  # noqa: E402
real_corpus.need("real")   # the real corpus is not distributed (SPEC 33): skip with the reason; test_real_headers names its set


def _load(name):
    spec = importlib.util.spec_from_file_location("standin_" + name, os.path.join(LIB, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


E712, SECP = _load("eip712"), _load("secp256k1")
keccak256 = E712.keccak256
TYPES = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"}, {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"}]}
DOMAIN4 = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
           {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]


class StandIn(unittest.TestCase):
    def test_it_is_the_stand_in(self):
        self.assertEqual(os.path.dirname(E712.__file__), LIB)

    def test_known_digests(self):
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"Transfer(address,address,uint256)").hex(),
                         "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

    @real_corpus.unless("real_v03_canonical")
    def test_real_headers(self):
        import sys
        sys.path.insert(0, HERE)
        import apc_block
        for f in sorted(glob.glob(os.path.join(HERE, "bundles", "real_v03_canonical", "v*.json")))[:5]:
            with open(f) as fh:
                h = json.load(fh)["inclusion"]["block_header"]
            self.assertEqual("0x" + keccak256(apc_block.rlp(_items(apc_block, h))).hex(), h["hash"].lower())

    def test_recovers_the_payer_of_real_payments(self):
        n = 0
        for f in sorted(glob.glob(os.path.join(HERE, "bundles", "real", "real_*.json")))[:6]:
            with open(f) as fh:
                pp = json.load(fh)["payment_payload"]
            acc, au = pp["accepted"], pp["payload"]["authorization"]
            dom = {"name": acc["extra"]["name"], "version": acc["extra"]["version"],
                   "chainId": int(acc["network"].split(":")[1]), "verifyingContract": acc["asset"].lower()}
            msg = dict(au, value=int(au["value"]), validAfter=int(au["validAfter"]), validBefore=int(au["validBefore"]),
                       nonce=au["nonce"].lower())
            sig = bytes.fromhex(pp["payload"]["signature"][2:])
            d = E712.signing_digest(dom, "TransferWithAuthorization", TYPES, msg, DOMAIN4)
            who = SECP.public_key_to_address(SECP.recover_public_key(
                d, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64] - 27), keccak256)
            self.assertEqual(who, au["from"].lower(), f)
            n += 1
        self.assertEqual(n, 6)


def _items(ab, block):
    """the header fields as apc_block.header_hash encodes them (same order and types)"""
    present = [k for k in ab.HEADER_OPT if k in block]
    out = []
    for k in ab.HEADER_BASE + tuple(present):
        if k in ab.HEADER_QTY:
            out.append(ab._int_bytes(ab._qty(block[k], k)))
        elif k == "extraData":
            out.append(ab._hexbytes(block[k], k))
        else:
            out.append(ab._hexbytes(block[k], k, ab.HEADER_SIZES[k]))
    return out


if __name__ == "__main__":
    unittest.main()
