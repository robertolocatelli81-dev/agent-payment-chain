"""Re-derive, offline, each executed EIP-3009 authorization in an oracle file written by fetch_base_eip3009.py and
check that our stdlib EIP-712 + secp256k1 recover the authorization's `from` (the chain accepted every one).

  python3 tools/check_eip3009_oracle.py ORACLE.json [--domain3]

--domain3 uses the 3-member domain (no verifyingContract): the negative control, it must recover nobody right.
Exit 0 only if every EOA signature recovers `from`; contract-wallet signatures (not 65 bytes) are counted apart."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.load()      # SPEC 32.12 (f): x402-signature-vectors v1.4.0 run from the bytes hashed, never by name from a path
from lib.eip712 import keccak256, signing_digest  # noqa: E402
from lib.secp256k1 import public_key_to_address, recover_public_key  # noqa: E402

TYPES = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"}, {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"}]}
DOMAIN4 = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
           {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]


def words(data: bytes, i):
    return data[4 + 32 * i: 4 + 32 * (i + 1)]


def decode(form, inp):
    b = bytes.fromhex(inp[2:])
    addr = lambda w: "0x" + w[12:].hex()          # noqa: E731
    msg = {"from": addr(words(b, 0)), "to": addr(words(b, 1)), "value": int.from_bytes(words(b, 2), "big"),
           "validAfter": int.from_bytes(words(b, 3), "big"), "validBefore": int.from_bytes(words(b, 4), "big"),
           "nonce": "0x" + words(b, 5).hex()}
    if form == "vrs":
        v = int.from_bytes(words(b, 6), "big")
        r, s = int.from_bytes(words(b, 7), "big"), int.from_bytes(words(b, 8), "big")
        return msg, (v, r, s)
    off = int.from_bytes(words(b, 6), "big")
    n = int.from_bytes(b[4 + off: 4 + off + 32], "big")
    sig = b[4 + off + 32: 4 + off + 32 + n]
    if len(sig) != 65:
        return msg, ("contract", len(sig))
    return msg, (sig[64], int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"))


def main(argv):
    doc = json.load(open(argv[1]))
    d3 = "--domain3" in argv
    s = doc["summary"]
    txs = {c["params"][0]: c["result"] for c in doc["calls"] if c["method"] == "eth_getTransactionByHash"}
    dom = {"name": s["token_name"], "version": s["token_version"], "chainId": s["chain_id"]}
    if not d3:
        dom["verifyingContract"] = s["token"]
    ok = bad = contract = failed_tx = 0
    for k in doc["kept"]:
        if k["status"] != "0x1":
            failed_tx += 1
            continue
        msg, sig = decode(k["form"], txs[k["tx"]]["input"])
        if sig[0] == "contract":
            contract += 1
            continue
        v, r, sv = sig
        digest = signing_digest(dom, "TransferWithAuthorization", TYPES, msg, None if d3 else DOMAIN4)
        try:
            who = public_key_to_address(recover_public_key(digest, r, sv, v - 27), keccak256)
        except ValueError:
            who = None
        if who == msg["from"].lower():
            ok += 1
        else:
            bad += 1
    print(json.dumps({"domain": "3 members" if d3 else "4 members", "eoa_recovered_from": ok, "eoa_mismatch": bad,
                      "contract_wallet_signatures": contract, "reverted_tx_skipped": failed_tx,
                      "token": s["token_name"] + " v" + s["token_version"], "chain_id": s["chain_id"],
                      "head_block": s["head_block"]}))
    return 0 if bad == 0 and ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
