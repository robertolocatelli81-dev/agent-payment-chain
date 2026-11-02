"""agent-payment-chain, SPEC 0.21 (SPEC.md section 32): a payer with code that pays USDC by a 65-byte signature on the
(v,r,s) path, and the ERC-1271 of Circle_SingleOwnerMSCA 1.0.0 reduced to the values the chain state gives — the member
`payer_state` (32.4, forms rpc and proof), the closed list WALLETS (32.5) and the rule (32.6). Offline; standard library
plus the keccak256 and secp256k1 of APC_SIGLIB, as apc_verify (which imports this module when the member is carried).
"""
import apc_block
import apc_l1proof
from apc_block import keccak256
from lib.secp256k1 import public_key_to_address, recover_public_key

SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ERC1967_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
# keccak256(abi.encode(uint256(keccak256(abi.encode("circle.msca.v1.storage"))) - 1)), WalletStorageV1Lib.sol 32; the
# Layout packs `uint8 initialized | bool initializing | address owner` in the word at +8 (three slots of AddressDLL,
# five mappings, then that word; Structs.sol 37-41)
MSCA_OWNER_SLOT = 0xc6a0cc20c824c4eecc4b0fbb7fb297d07492a7bd12c83d4fa4d27b4249f9bfc8 + 8
# SPEC 32.5, closed list: proxy code keccak256 -> (implementation address, implementation code keccak256, owner slot,
# name). Measured on Base 2026-11-01; sources in sources/circle_msca_v1_3c8cd8fb_20261101.
WALLETS = {
    "d09e34b2e51f09092e73e3ba1d520a42972496bf2a3bfdb22bb50b9729a9fd66": (
        "0x9c6e09bc32d1e012dcaa2623e66d2cc9860c1aed",
        "60ecaaadc845f14626e77541b390bd36a7f5c35efdee5c30471f0eb08626019e",
        MSCA_OWNER_SLOT, "Circle_SingleOwnerMSCA 1.0.0"),
}
DOMAIN4_TYPEHASH = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
MSCA_TYPEHASH = keccak256(b"CircleSingleOwnerMSCAMessage(bytes32 hash)")     # SingleOwnerMSCA.sol 83
NAME_HASH, VERSION_HASH = keccak256(b"Circle_SingleOwnerMSCA"), keccak256(b"1.0.0")   # SingleOwnerMSCA.sol 80-82


def _av():
    import apc_verify      # the verifier imports this module: its helpers are taken when a function runs
    return apc_verify


def replay_safe_hash(chain_id, payer, h):
    """BaseERC712CompliantAccount.sol 34-42: keccak256(0x1901 || DS || keccak256(TYPEHASH || h)), DS the EIP-712 domain
    {name Circle_SingleOwnerMSCA, version 1.0.0, chainId, verifyingContract = the payer}."""
    ds = keccak256(DOMAIN4_TYPEHASH + NAME_HASH + VERSION_HASH + chain_id.to_bytes(32, "big")
                   + bytes(12) + bytes.fromhex(payer[2:]))
    return keccak256(b"\x19\x01" + ds + keccak256(MSCA_TYPEHASH + h))


def _word_addr(word, what):
    """A 32-byte storage word that holds an address: 12 zero bytes then the address; None otherwise."""
    return None if word >> 160 else "0x%040x" % word


def _owner_addr(word):
    """The owner of the packed word (SPEC 32.5), or a failed result when bits above 176 are set."""
    if word >> 176:
        return "failed:msca_owner_word_not_canonical"
    return "0x%040x" % (word >> 16)


def _nodes(v, path):
    av = _av()
    if not isinstance(v, list) or not 1 <= len(v) <= 64:
        raise av.Refusal("%s: not a list of 1..64 nodes" % path)
    return [av._d(n, path + "[]") for n in v]


def payer_state(ps, pp, tx_block, inc, b1):
    """SPEC 32.4: (code bytes, wallet or None, how) or a check result string. wallet (only for a code of the list) is
    {"pin", "impl_hash", "word", "owner_has_code"}; how is "declared_rpc" or "proven_at_parent_and_block"."""
    av = _av()
    payer = pp["auth"]["from"]
    av._obj(ps, "payer_state", (), ("rpc", "proof"))
    if len(ps) != 1:
        raise av.Refusal("payer_state: exactly one of rpc and proof")
    if "rpc" in ps:
        return _rpc_state(av, ps["rpc"], payer, tx_block)
    pr = av._obj(ps["proof"], "payer_state.proof", ("code", "parent_header", "at_parent", "at_block"))
    code = av._d(pr["code"], "payer_state.proof.code")
    pin = WALLETS.get(keccak256(code).hex())
    ph = av._header_obj(pr["parent_header"], "payer_state.proof.parent_header")
    ends = {}
    for end in ("at_parent", "at_block"):
        p = "payer_state.proof." + end
        e = av._obj(pr[end], p, ("payer",), ("implementation", "owner"))
        w = av._obj(e["payer"], p + ".payer", ("accountProof",), ("storageProof",))
        if (pin is not None) != ("storageProof" in w and "implementation" in e and "owner" in e) \
                or (pin is None and len(e) + len(w) > 2):
            raise av.Refusal("%s: storageProof, implementation and owner are required for a listed wallet code and "
                             "refused otherwise (SPEC 32.4)" % p)
        parts = {"payer": _nodes(w["accountProof"], p + ".payer.accountProof")}
        if pin is not None:
            if not isinstance(w["storageProof"], list) or len(w["storageProof"]) != 2:
                raise av.Refusal("%s.payer.storageProof: not two proofs (ERC-1967 slot, owner slot)" % p)
            parts["slots"] = [_nodes(x, p + ".payer.storageProof[%d]" % i) for i, x in enumerate(w["storageProof"])]
            for who in ("implementation", "owner"):
                a = av._obj(e[who], "%s.%s" % (p, who), ("accountProof",))
                parts[who] = _nodes(a["accountProof"], "%s.%s.accountProof" % (p, who))
        ends[end] = parts
    if inc is None:
        return "not_evaluated:payer_state_proof_needs_inclusion"
    if b1 != "verified":
        return "not_evaluated:payer_state_proof_block_not_bound"
    hdr = inc["block_header"]
    try:
        if apc_block.header_hash(ph) != str(ph["hash"]).lower() or ph["hash"].lower() != str(hdr["parentHash"]).lower() \
                or apc_block._qty(ph["number"], "n") + 1 != apc_block._qty(hdr["number"], "n"):
            return "failed:payer_state_parent_header_not_parent"
        words, wallet = [], None
        for end, h in (("at_parent", ph), ("at_block", hdr)):
            root = apc_block._hexbytes(h["stateRoot"], "stateRoot", 32)
            _, _, sroot, chash = apc_l1proof.account(root, bytes.fromhex(payer[2:]), ends[end]["payer"])
            if chash != keccak256(code):
                return "failed:payer_state_code_not_proven"
            if pin is None:
                continue
            iw = apc_l1proof.storage(sroot, ERC1967_SLOT, ends[end]["slots"][0])
            ow = apc_l1proof.storage(sroot, pin[2], ends[end]["slots"][1])
            words.append((iw, ow))
            if _word_addr(iw, "implementation") != pin[0]:
                return "not_evaluated:wallet_implementation_not_known"
            owner = _owner_addr(ow)
            if owner.startswith("failed:"):
                return owner
            ih = apc_l1proof.account(root, bytes.fromhex(pin[0][2:]), ends[end]["implementation"])[3]
            oh = apc_l1proof.account(root, bytes.fromhex(owner[2:]), ends[end]["owner"])[3]
            # SPEC 32.6 (0.21.1): the owner HAS code when its codeHash is not keccak256("") at EITHER end; an owner
            # deployed inside block N may have decided the signature (review 2026-11-01, N04)
            wallet = {"pin": pin, "impl_hash": ih.hex(), "word": ow,
                      "owner_has_code": (wallet is not None and wallet["owner_has_code"]) or oh != apc_l1proof.EMPTY_CODE}
    except apc_block.BlockRefusal as e:
        return "failed:payer_state_proof:%s" % e
    if words and words[0] != words[1]:
        return "failed:payer_state_slot_changed_in_block"
    return code, wallet, "proven_at_parent_and_block"


def _rpc_state(av, rp, payer, tx_block):
    rp = av._obj(rp, "payer_state.rpc", ("code",), ("wallet",))
    av._obj(rp["code"], "payer_state.rpc.code", ("method", "params", "result"))
    if not isinstance(rp["code"]["params"], list) or len(rp["code"]["params"]) != 2 \
            or not isinstance(rp["code"]["params"][1], str):
        raise av.Refusal("payer_state.rpc.code.params: not [address, block]")
    blk = rp["code"]["params"][1]
    av._q(blk, "payer_state.rpc.code.params[1]")
    if tx_block is not None:
        av._q(tx_block, "chain_tx.tx.blockNumber")
        if blk.lower() != str(tx_block).lower():
            return "failed:payer_state_block_not_tx_block"
    blk = blk.lower()
    code = av._reply(rp["code"], "payer_state.rpc.code", "eth_getCode", [payer, blk])
    if code.startswith("failed:"):
        return code
    code = av._d(code, "payer_state.rpc.code.result")
    pin = WALLETS.get(keccak256(code).hex())
    if (pin is not None) != ("wallet" in rp):
        raise av.Refusal("payer_state.rpc.wallet: required for a listed wallet code and refused otherwise (SPEC 32.4)")
    if pin is None:
        return code, None, "declared_rpc"
    w = av._obj(rp["wallet"], "payer_state.rpc.wallet", ("implementation", "owner", "implementation_code", "owner_code"))
    for k in w:
        av._obj(w[k], "payer_state.rpc.wallet." + k, ("method", "params", "result"))
        if not isinstance(w[k]["params"], list):
            raise av.Refusal("payer_state.rpc.wallet.%s.params: not a list" % k)
    got = []
    for k, slot in (("implementation", ERC1967_SLOT), ("owner", pin[2])):
        r = av._reply(w[k], "payer_state.rpc.wallet." + k, "eth_getStorageAt", [payer, "0x%064x" % slot, blk])
        if r.startswith("failed:"):
            return r
        got.append(int.from_bytes(av._d(r, "payer_state.rpc.wallet.%s.result" % k, 32), "big"))
    iw, ow = got
    if _word_addr(iw, "implementation") != pin[0]:
        return "not_evaluated:wallet_implementation_not_known"
    owner = _owner_addr(ow)
    if owner.startswith("failed:"):
        return owner
    ic = av._reply(w["implementation_code"], "payer_state.rpc.wallet.implementation_code", "eth_getCode", [pin[0], blk])
    if ic.startswith("failed:"):
        return ic
    oc = av._reply(w["owner_code"], "payer_state.rpc.wallet.owner_code", "eth_getCode", [owner, blk])
    if oc.startswith("failed:"):
        return oc
    wallet = {"pin": pin, "impl_hash": keccak256(av._d(ic, "payer_state.rpc.wallet.implementation_code.result")).hex(),
              "word": ow, "owner_has_code": av._d(oc, "payer_state.rpc.wallet.owner_code.result") != b""}
    return code, wallet, "declared_rpc"


def check(pp, st):
    """SPEC 32.6: L2.sig once the payer's state is known. Returns (result, notes)."""
    av = _av()
    code, wallet, how = st
    sig = pp["signature"]
    if code == b"":
        if len(sig) == 65:
            return av.check_signature(pp)
        return "failed:signature_length_%d_for_a_payer_without_code" % len(sig), []
    if wallet is None:
        n = []
        if keccak256(code).hex() in av.WALLET_PROXY_CODE or (len(code) == 23 and code[:3] == b"\xef\x01\x00"
                                                             and "0x" + code[3:].hex() in av.WALLET_7702):
            n.append("L2.sig: the payer's code is a Coinbase Smart Wallet proxy or delegation of section 3: its member "
                     "is payer_wallet, not payer_state (SPEC 32.5)")
        return "not_evaluated:wallet_implementation_not_known", n
    pin = wallet["pin"]
    notes = ["payer is a %s (ERC-1271, SPEC 32.6); its implementation and owner are chain state %s" % (
        pin[3], "read by RPC at the transaction's block, declared" if how == "declared_rpc" else
        "proven equal at the end of the parent block and of the transaction's block (the proof binds the owner to the "
        "block, not the payment to the chain); a transaction earlier in the block could change them and change them "
        "back, which is not excluded")]
    if wallet["impl_hash"] != pin[1]:
        return "failed:payer_state_implementation_code_not_pinned", notes
    word = wallet["word"]
    if word & 0xff != 1 or (word >> 8) & 0xff != 0:
        return "failed:msca_not_initialized", notes
    owner = word >> 16
    if owner == 0:
        return "not_evaluated:msca_owner_zero_plugin_path", notes
    # OZ 5.0.0 SignatureChecker 22-27: ECDSA.tryRecover first, the owner's own ERC-1271 only when that does not give
    # the owner; so an owner with code is decided by the recovery when it gives the owner, else not evaluated
    oc = wallet["owner_has_code"]
    if len(sig) != 65:
        if oc:
            return "not_evaluated:msca_owner_has_code", notes
        return "failed:msca_signature_length_%d" % len(sig), notes
    r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    if s > SECP_N // 2 or v not in (27, 28) or not 0 < r < SECP_N or s == 0:
        if oc:
            return "not_evaluated:msca_owner_has_code", notes
        return "failed:msca_high_s" if s > SECP_N // 2 else "failed:msca_signature_invalid", notes
    acc = pp["accepted"]
    h = av.signing_digest({"name": acc["domain_name"], "version": acc["domain_version"], "chainId": acc["chain_id"],
                           "verifyingContract": acc["asset"]}, "TransferWithAuthorization", av.TYPES, dict(pp["auth"]),
                          av.DOMAIN4)
    try:
        who = public_key_to_address(recover_public_key(replay_safe_hash(acc["chain_id"], pp["auth"]["from"], h), r, s,
                                                       v - 27), keccak256)
    except ValueError:
        return ("not_evaluated:msca_owner_has_code" if oc else "failed:msca_signature_invalid"), notes
    if who != "0x%040x" % owner:
        if oc:
            return "not_evaluated:msca_owner_has_code", notes
        return "failed:msca_signature_recovers_%s_not_owner" % who, notes
    return "verified (ERC-1271 %s)" % pin[3], notes
