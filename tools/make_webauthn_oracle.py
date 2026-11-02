"""Real WebAuthn assertions of Coinbase Smart Wallet passkey owners, from ERC-4337 operations that EntryPoint v0.6
executed on Base (SPEC 0.17, section 28). The chain accepted each one: an operation whose validateUserOp returns 1
(signature invalid) makes handleOps revert (AA24), and a reverted transaction emits no UserOperationEvent.

  python3 tools/make_webauthn_oracle.py SCAN.json OUT.json

SCAN.json is the output of tools/scan_webauthn.py on EntryPoint v0.6 UserOperationEvent. For each operation of each
hit whose signature is a SignatureWrapper around an abi.encode(WebAuthnAuth): the userOpHash is recomputed from the
raw calldata (EntryPoint v0.6 getUserOpHash; CoinbaseSmartWallet.sol 158-160 and 242-244 for
executeWithoutChainIdValidation) and must equal the event's topic 1; then the wallet's code, implementation and
ownerAtIndex(ownerIndex) are read at the transaction's block (public RPC, read-only) and saved as raw replies."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_webauthn_oracle", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_webauthn  # noqa: E402
import apc_verify  # noqa: E402
from apc_verify import keccak256  # noqa: E402

EP06 = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
HANDLE_OPS = keccak256(b"handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],"
                       b"address)")[:4]
EVENT = "0x" + keccak256(b"UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)").hex()
NO_CHAIN = keccak256(b"executeWithoutChainIdValidation(bytes[])")[:4]
OWNER_AT = keccak256(b"ownerAtIndex(uint256)")[:4]


def w(b, i):
    return int.from_bytes(b[i:i + 32], "big")


def dyn(b, base, off_word):
    o = base + w(b, off_word)
    n = w(b, o)
    return b[o + 32:o + 32 + n]


def user_ops(inp):
    """handleOps(UserOperation[] ops, address beneficiary) of EntryPoint v0.6, read from the raw calldata."""
    if inp[:4] != HANDLE_OPS:
        return []
    a = inp[4:]
    arr = w(a, 0)
    n = w(a, arr)
    out = []
    for i in range(n):
        t = arr + 32 + w(a, arr + 32 + 32 * i)
        out.append({"sender": "0x" + a[t + 12:t + 32].hex(), "nonce": w(a, t + 32), "initCode": dyn(a, t, t + 64),
                    "callData": dyn(a, t, t + 96), "callGasLimit": w(a, t + 128),
                    "verificationGasLimit": w(a, t + 160), "preVerificationGas": w(a, t + 192),
                    "maxFeePerGas": w(a, t + 224), "maxPriorityFeePerGas": w(a, t + 256),
                    "paymasterAndData": dyn(a, t, t + 288), "signature": dyn(a, t, t + 320)})
    return out


def user_op_hash(op, chain_id, with_chain=True):
    """EntryPoint v0.6 UserOperationLib.hash + getUserOpHash; without the chain id: CoinbaseSmartWallet.sol 242-244."""
    def u(x):
        return x.to_bytes(32, "big")
    packed = (bytes(12) + bytes.fromhex(op["sender"][2:]) + u(op["nonce"]) + keccak256(op["initCode"])
              + keccak256(op["callData"]) + u(op["callGasLimit"]) + u(op["verificationGasLimit"])
              + u(op["preVerificationGas"]) + u(op["maxFeePerGas"]) + u(op["maxPriorityFeePerGas"])
              + keccak256(op["paymasterAndData"]))
    inner = keccak256(packed) + bytes(12) + bytes.fromhex(EP06[2:])
    return keccak256(inner + (u(chain_id) if with_chain else b""))


def wrapper(sig):
    """abi.encode(SignatureWrapper{ownerIndex, signatureData}) in the canonical form, else None."""
    if len(sig) < 128 or w(sig, 0) != 32 or w(sig, 64) != 64:
        return None
    n = w(sig, 96)
    end = 128 + (n + 31) // 32 * 32
    if end != len(sig) or any(sig[128 + n:end]):
        return None
    return w(sig, 32), sig[128:128 + n]


def challenge_of(op, chain_id):
    return user_op_hash(op, chain_id, op["callData"][:4] != NO_CHAIN)


def main(argv):
    import scan_webauthn
    scan = json.load(open(argv[1]))
    out = argv[2]
    if os.path.exists(out):
        raise SystemExit("%s exists" % out)
    chain = scan_webauthn.batch([("eth_chainId", [])])[0]
    cid = int(chain["result"], 16)
    entries, skipped = [], {}
    for hit in scan["hits"]:
        tx = hit["tx"]["result"]
        if (tx["to"] or "").lower() != EP06:
            skipped["not_a_direct_handleOps"] = skipped.get("not_a_direct_handleOps", 0) + 1
            continue
        ev = {(lg["topics"][1], "0x" + lg["topics"][2][26:]) for lg in hit["logs"] if lg["topics"][0] == EVENT}
        for k, op in enumerate(user_ops(bytes.fromhex(tx["input"][2:]))):
            wr = wrapper(op["signature"])
            if wr is None:
                skipped["signature_not_a_wrapper"] = skipped.get("signature_not_a_wrapper", 0) + 1
                continue
            try:
                apc_webauthn.decode_auth(wr[1])
            except apc_webauthn.NotCanonical:
                skipped["signature_data_not_webauthn"] = skipped.get("signature_data_not_webauthn", 0) + 1
                continue
            h = "0x" + user_op_hash(op, cid).hex()
            if (h, op["sender"]) not in ev:
                skipped["userophash_not_in_event"] = skipped.get("userophash_not_in_event", 0) + 1
                continue
            blk = tx["blockNumber"]
            replies = scan_webauthn.batch([
                ("eth_getCode", [op["sender"], blk]),
                ("eth_getStorageAt", [op["sender"], apc_verify.ERC1967_SLOT, blk]),
                ("eth_call", [{"to": op["sender"], "data": "0x" + (OWNER_AT + wr[0].to_bytes(32, "big")).hex()}, blk])])
            entries.append({"tx_hash": tx["hash"], "block": blk, "op_index": k, "sender": op["sender"],
                            "user_op_hash": h, "owner_index": wr[0], "code": replies[0],
                            "implementation": replies[1], "owner": replies[2]})
            print(tx["hash"], k, op["sender"], len(entries), flush=True)
    doc = {"summary": {"scan": scan["summary"], "chain_id": cid, "entries": len(entries), "skipped": skipped},
           "chain_id_reply": chain, "transactions": {hit["tx"]["result"]["hash"]: hit for hit in scan["hits"]},
           "entries": entries}
    with open(out, "x") as fh:
        json.dump(doc, fh, indent=1)
    print(json.dumps(doc["summary"], indent=1))


if __name__ == "__main__":
    main(sys.argv)
