"""agent-payment-chain, L1 state proof of the eight canonical replies (SPEC 0.4, section 6, canonical.l1_state).
Standard library plus the keccak256 of APC_SIGLIB, as apc_block.

What it proves, from an L1 header whose hash the reader trusts (a checkpoint):
  - L1H  a chain of L1 headers, each keccak256(rlp(header)) and parentHash-linked, from the checkpoint down to block b;
  - L1A  an account (nonce, balance, storageRoot, codeHash) in the state trie under block b's stateRoot, key
         keccak256(address) (eth_getProof accountProof; Yellow Paper 4.1, "secure trie");
  - L1S  a storage word under that account's storageRoot, key keccak256(slot), value rlp(uint) (eth_getProof
         storageProof), including the proof that a slot is ABSENT, i.e. zero, which is what an unset mapping entry
         (a game not blacklisted) looks like;
  - L1C  the account's code hashes to codeHash (code-held values: clone arguments and immutables).
"""
import apc_block as ab
from apc_block import BlockRefusal, keccak256

EMPTY_TRIE = keccak256(ab.rlp(b""))
EMPTY_CODE = keccak256(b"")


def proof_get(root, key, proof):
    """Walk an eth_getProof path. Returns the value (bytes) or None when the proof shows the key is absent. Every node
    must be used; a path that stops early or carries more nodes is refused (an absence proof is a proof too)."""
    if not isinstance(proof, list) or len(proof) > 64:
        raise BlockRefusal("proof_not_a_node_list")
    if root == EMPTY_TRIE and not proof:
        return None
    nibs, want, i, k = ab._nibbles(key), root, 0, 0

    def done(v):
        if i != len(proof):
            raise BlockRefusal("proof_extra_nodes")
        return v
    while True:
        if isinstance(want, bytes) and len(want) == 32:
            if i >= len(proof):
                raise BlockRefusal("proof_too_short")
            if not isinstance(proof[i], bytes) or keccak256(proof[i]) != want:
                raise BlockRefusal("proof_node_hash_mismatch")
            node = ab.rlp_decode(proof[i])
            i += 1
        elif isinstance(want, list):
            node = want
        else:
            raise BlockRefusal("proof_bad_reference")
        if not isinstance(node, list):
            raise BlockRefusal("proof_node_not_list")
        if len(node) == 17:
            if k == len(nibs):
                return done(node[16] or None)
            want, k = node[nibs[k]], k + 1
            if want == b"":
                return done(None)
        elif len(node) == 2 and isinstance(node[0], bytes):
            pre, leaf = ab._hp_decode(node[0])
            if not leaf and not pre:
                raise BlockRefusal("proof_empty_extension")
            if nibs[k:k + len(pre)] != pre or (leaf and k + len(pre) != len(nibs)):
                return done(None)                       # the path diverges here: the key is not in the trie
            k += len(pre)
            if leaf:
                if not isinstance(node[1], bytes):
                    raise BlockRefusal("proof_leaf_mismatch")
                return done(node[1])
            want = node[1]
        else:
            raise BlockRefusal("proof_node_bad_arity")


def account(state_root, address, proof):
    """L1A: (nonce, balance, storageRoot, codeHash); an absent account is (0, 0, EMPTY_TRIE, EMPTY_CODE)."""
    v = proof_get(state_root, keccak256(address), proof)
    if v is None:
        return 0, 0, EMPTY_TRIE, EMPTY_CODE
    a = ab.rlp_decode(v)
    if not isinstance(a, list) or len(a) != 4 or not all(isinstance(x, bytes) for x in a) \
            or len(a[2]) != 32 or len(a[3]) != 32:
        raise BlockRefusal("account_not_4_fields")
    return int.from_bytes(a[0], "big"), int.from_bytes(a[1], "big"), a[2], a[3]


def storage(storage_root, slot, proof):
    """L1S: the 32-byte word at `slot` (int); absent = 0."""
    v = proof_get(storage_root, keccak256(slot.to_bytes(32, "big")), proof)
    if v is None:
        return 0
    w = ab.rlp_decode(v)
    if not isinstance(w, bytes) or not w or w[0] == 0 or len(w) > 32:
        raise BlockRefusal("storage_value_not_a_canonical_word")
    return int.from_bytes(w, "big")


def code(code_hash, code_bytes):
    """L1C"""
    if keccak256(code_bytes) != code_hash:
        raise BlockRefusal("code_not_code_hash")
    return code_bytes


def header_chain(checkpoint_hash, headers):
    """L1H: headers[0] hashes to checkpoint_hash, each next one is the parent of the previous. Returns the last header
    (the block whose stateRoot the account proofs use)."""
    if not isinstance(headers, list) or not headers or len(headers) > 8192:
        raise BlockRefusal("header_chain_not_a_list")
    want = checkpoint_hash.lower()
    prev = None
    for h in headers:
        hh = ab.header_hash(h)
        if hh != want:
            raise BlockRefusal("header_chain_broken")
        n = ab._qty(h["number"], "number")
        if prev is not None and n != prev - 1:
            raise BlockRefusal("header_chain_numbers")
        prev, want = n, str(h["parentHash"]).lower()
    return headers[-1]


def mapping_slot(key32, base_slot):
    """Solidity layout of mapping(k => v) at `base_slot`: keccak256(k ‖ base_slot) (Solidity docs, storage layout)."""
    return int.from_bytes(keccak256(key32 + base_slot.to_bytes(32, "big")), "big")


# ------------------------------------------------------------------ SPEC 0.4: the eight replies from proofs
# Base mainnet, measured 2026-10-24 (eth_call at L1 blocks 26259631 and 26259645, ethereum-rpc.publicnode.com; the same
# header hash, codeHash and storageHash for the 10 accounts on eth.drpc.org). Values held in code (immutables, clone
# layout) are keyed by the proven codeHash: the same code gives the same values; another code is not read (NotPinned).
ASR = bytes.fromhex("909f6cf47ed12f010a796527f562bfc26c7f4e72")            # AnchorStateRegistry proxy
DGF = bytes.fromhex("43edb88c4b80fdd2adff2412a7bebf9df42cb40e")            # DisputeGameFactory proxy
IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc   # EIP-1967
PORTAL_SLOT = 0x4b6c74f9e688cb39801f2112c14a8c57232a3fc5202e1444126d4bce86eb19ac  # keccak("systemconfig.optimismportal")-1
PROXY_CODEHASH = {"fa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998",    # ASR, DisputeGameFactory
                  "7d1cd19d713c8d64bf663f4168250abfbf690dbb6214c25bf757fee383816914",    # SystemConfig
                  "33920c8270353487e486debc0d8ddbb187fa86727f2daf412d794589e6f26cb5"}    # SuperchainConfig
PINS = {
    "game_impl": {   # AggregateVerifier 0.1.0 (base/contracts a27edbf3), 0.2.0 (a879bfe4)
        "5033d9882dccce7a394bc34cc02f8620afe0a5e172eab70f830de2e7a61fa3c4": {"game_type": 621, "roots": 20, "asr": ASR},
        "9a495e781a85f550788618de994b6d38b6f216ea0b5c50943b0e4c75323842e5": {"game_type": 621, "roots": 20, "asr": ASR}},
    "asr_impl": {    # AnchorStateRegistry 3.7.0 (affa48e2)
        "d01ffe5bb9bdf9cb1e42b2dd12188f9bc2a163e8301b24451d7d8485280148b7": {"finality_delay": 0}},
    "dgf_impl": {    # DisputeGameFactory 1.5.0 (eaa7729)
        "910d7bf9e11f1a95aab4e3fceb71f647c8db0431b4510e2155c54dca2b50e444": {}},
    "sysconf_impl": {  # SystemConfig 3.14.0 (4951105b)
        "8f2f3085ef0b85c764a113b72dc3845fbfe7652562634d4e3f6983be8399d78a": {}},
    "supc_impl": {   # SuperchainConfig 2.5.0 (415a6a8c); PAUSE_EXPIRY, SystemConfig.sol 106
        "4027ad2266b7a6238263e5ce5943e25037bffacfb4c68905b271d3fef65f15cb": {"pause_expiry": 7_884_000}},
}
# Solady LibClone 502cc1e, clone with immutable args: prefix, uint16 args length, mid, implementation, suffix, args
CLONE_PRE = bytes.fromhex("36602c57343d527f9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff593da1005b"
                          "363d3d373d3d3d3d61")
CLONE_MID = bytes.fromhex("806062363936013d73")
CLONE_SUF = bytes.fromhex("5af43d3d93803e606057fd5bf3")
MASK64, MASK160 = 2 ** 64 - 1, 2 ** 160 - 1


class NotPinned(BlockRefusal):
    """A proven code that is not in the table: an upgrade is never read blindly."""


def clone_args(code_bytes):
    """(implementation, args without the trailing length) of a Solady CWIA clone; anything else is refused."""
    n = len(CLONE_PRE)
    if code_bytes[:n] != CLONE_PRE:
        raise BlockRefusal("game_code_not_a_clone")
    argc = int.from_bytes(code_bytes[n:n + 2], "big")
    rest = code_bytes[n + 2:]
    if rest[:len(CLONE_MID)] != CLONE_MID or rest[len(CLONE_MID) + 20:len(CLONE_MID) + 20 + len(CLONE_SUF)] != CLONE_SUF:
        raise BlockRefusal("game_code_not_a_clone")
    impl = rest[len(CLONE_MID):len(CLONE_MID) + 20]
    args = rest[len(CLONE_MID) + 20 + len(CLONE_SUF):]
    if argc != len(args) or len(args) < 2 or int.from_bytes(args[-2:], "big") != argc:
        raise BlockRefusal("game_clone_length")
    return impl, args[:-2]


def _addr_of(word, shift=0):
    return ((word >> shift) & MASK160).to_bytes(20, "big")


def replies(header, accounts, game_code, game, used=None):
    """The eight replies of SPEC O1 (ABI words; extraData as ABI bytes) recomputed from proofs under header's stateRoot.
    accounts: {20-byte address: (accountProof nodes, {slot int: storage proof nodes})}; game: 20-byte address. used: a
    set that receives every (address, slot or None) read, so that a caller can refuse a proof nothing reads."""
    sr, ts = bytes.fromhex(header["stateRoot"][2:]), ab._qty(header["timestamp"], "timestamp")
    used = set() if used is None else used

    def acc(addr):
        if addr not in accounts:
            raise BlockRefusal("account_proof_missing_0x" + addr.hex())
        used.add((addr, None))
        return account(sr, addr, accounts[addr][0])

    def word(addr, a, slot):
        sp = accounts[addr][1]
        if slot not in sp:
            raise BlockRefusal("storage_proof_missing")
        used.add((addr, slot))
        return storage(a[2], slot, sp[slot])

    def impl_of(addr, kind):
        a = acc(addr)
        if a[3].hex() not in PROXY_CODEHASH:
            raise NotPinned(kind + "_proxy_code_not_pinned")
        ia = acc(_addr_of(word(addr, a, IMPL_SLOT)))
        pin = PINS[kind].get(ia[3].hex())
        if pin is None:
            raise NotPinned(kind + "_not_pinned")
        return a, pin

    g = acc(game)
    impl, args = clone_args(code(g[3], game_code))
    gpin = PINS["game_impl"].get(acc(impl)[3].hex())
    if gpin is None:
        raise NotPinned("game_impl_not_pinned")
    root_claim = args[20:52]
    xlen = 0x34 + 0x20 * gpin["roots"]
    if len(args) < 0x54 + xlen:
        raise BlockRefusal("game_args_short")
    extra = args[0x54:0x54 + xlen]
    s0 = word(game, g, 0)
    created, resolved = s0 & MASK64, (s0 >> 64) & MASK64
    status, respected = (s0 >> 128) & 0xff, (s0 >> 144) & 0xff
    start_block = word(game, g, 2)
    asr, asr_pin = impl_of(ASR, "asr_impl")
    sysconf, dgf = _addr_of(word(ASR, asr, 0), 16), _addr_of(word(ASR, asr, 1))
    retirement = (word(ASR, asr, 6) >> 32) & MASK64
    blacklisted = word(ASR, asr, mapping_slot(bytes(12) + game, 5)) & 0xff
    if dgf != DGF:
        raise BlockRefusal("asr_factory_not_the_pinned_factory")
    f, _ = impl_of(dgf, "dgf_impl")
    enc = gpin["game_type"].to_bytes(32, "big") + root_claim + (96).to_bytes(32, "big") \
        + len(extra).to_bytes(32, "big") + extra + b"\0" * (-len(extra) % 32)
    registered = _addr_of(word(dgf, f, mapping_slot(keccak256(enc), 103))) == game and gpin["asr"] == ASR
    sc, _ = impl_of(sysconf, "sysconf_impl")
    supc, portal = _addr_of(word(sysconf, sc, 108)), _addr_of(word(sysconf, sc, PORTAL_SLOT))
    su, su_pin = impl_of(supc, "supc_impl")

    def paused(ident):
        t = word(supc, su, mapping_slot(bytes(12) + ident, 0))
        return t != 0 and ts < t + su_pin["pause_expiry"]
    # every condition is read, none short-circuited: the set of proofs a bundle must carry is the same for every game
    pause_any, pause_portal = paused(bytes(20)), paused(portal)
    proper = registered and not blacklisted and created > retirement and not (pause_any or pause_portal)
    if resolved > ts:
        raise BlockRefusal("game_resolved_after_block")
    finalized = resolved != 0 and status in (1, 2) and ts - resolved > asr_pin["finality_delay"]
    valid = proper and respected == 1 and finalized and status == 2

    def w(n):
        return n.to_bytes(32, "big")
    return [w(gpin["game_type"]), root_claim, w(32) + w(len(extra)) + extra + b"\0" * (-len(extra) % 32),
            w(start_block), w(status), w(int(proper)), w(respected), w(int(valid))]
