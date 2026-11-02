"""Stellar primitives for SPEC section 20 (x402 `exact` on Stellar): a strict reader of the XDR the scheme carries
(stellar/stellar-xdr @4f524bb, copies in sources/stellar_xdr_4f524bb), StrKey (SEP-23), the network id, the
transaction hash and the Soroban authorization preimage. Standard library only; Ed25519 from apc_solana (RFC 8032).
Anything outside the subset read here is refused (StellarRefusal), never skipped."""
import base64
import hashlib

PASSPHRASE = {"stellar:pubnet": "Public Global Stellar Network ; September 2015",
              "stellar:testnet": "Test SDF Network ; September 2015"}
MAX_DEPTH = 32


class StellarRefusal(ValueError):
    pass


def network_id(network):
    return hashlib.sha256(PASSPHRASE[network].encode("ascii")).digest()


# ------------------------------------------------------------------ StrKey (SEP-23)
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
VERSION = {"G": 6 << 3, "C": 2 << 3, "M": 12 << 3}


def _crc16(b):
    crc = 0
    for x in b:
        crc ^= x << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def strkey_encode(kind, payload):
    raw = bytes([VERSION[kind]]) + payload
    raw += _crc16(raw).to_bytes(2, "little")
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def strkey_decode(s, kind):
    """32-byte payload of a G (account) or C (contract) StrKey; canonical form only."""
    if not isinstance(s, str) or len(s) != 56 or s[0] != kind or any(c not in B32 for c in s):
        raise StellarRefusal("not_a_%s_strkey" % kind)
    raw = base64.b32decode(s)
    if raw[0] != VERSION[kind] or _crc16(raw[:-2]).to_bytes(2, "little") != raw[-2:]:
        raise StellarRefusal("strkey_checksum")
    if strkey_encode(kind, raw[1:-2]) != s:
        raise StellarRefusal("strkey_not_canonical")
    return raw[1:-2]


# ------------------------------------------------------------------ XDR reader
class R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if n < 0 or self.i + n > len(self.b):
            raise StellarRefusal("xdr_truncated")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def u32(self):
        return int.from_bytes(self.take(4), "big")

    def i32(self):
        return int.from_bytes(self.take(4), "big", signed=True)

    def u64(self):
        return int.from_bytes(self.take(8), "big")

    def i64(self):
        return int.from_bytes(self.take(8), "big", signed=True)

    def bool(self):
        v = self.u32()
        if v > 1:
            raise StellarRefusal("xdr_bool_not_0_or_1")
        return v == 1

    def opaque(self, maxlen=None, fixed=None):
        n = fixed if fixed is not None else self.u32()
        if maxlen is not None and n > maxlen:
            raise StellarRefusal("xdr_length_above_limit")
        v = self.take(n)
        pad = self.take((4 - n % 4) % 4)
        if any(pad):
            raise StellarRefusal("xdr_padding_not_zero")
        return v

    def string(self, maxlen=None):
        return self.opaque(maxlen)

    def count(self, maxn=None):
        n = self.u32()
        if (maxn is not None and n > maxn) or n * 4 > len(self.b) - self.i:
            raise StellarRefusal("xdr_array_length")
        return n

    def optional(self):
        return self.bool()

    def end(self):
        if self.i != len(self.b):
            raise StellarRefusal("xdr_trailing_bytes")


def _enum(v, allowed, what):
    if v not in allowed:
        raise StellarRefusal("%s_%d_not_supported" % (what, v))
    return v


def muxed_account(r):
    t = _enum(r.u32(), (0, 0x100), "muxed_account_type")
    if t == 0:
        return {"kind": "G", "key": r.take(32)}
    mid = r.u64()
    return {"kind": "M", "id": mid, "key": r.take(32)}


def account_id(r):
    _enum(r.u32(), (0,), "public_key_type")
    return r.take(32)


def sc_address(r):
    t = _enum(r.u32(), (0, 1, 2, 3, 4, 5), "sc_address_type")
    if t == 0:
        return ("G", account_id(r))
    if t == 1:
        return ("C", r.take(32))
    if t == 2:
        return ("M", r.u64(), r.take(32))
    if t == 3:
        _enum(r.u32(), (0,), "claimable_balance_id_type")
        return ("B", r.take(32))
    if t == 4:
        return ("L", r.take(32))
    return ("MC", r.u64(), r.take(32))


def sc_val(r, depth=0):
    if depth > MAX_DEPTH:
        raise StellarRefusal("scval_nested_too_deep")
    t = r.u32()
    if t == 0:
        return ("bool", r.bool())
    if t in (1, 20):
        return ("void" if t == 1 else "ledger_key_contract_instance", None)
    if t == 3:
        return ("u32", r.u32())
    if t == 4:
        return ("i32", r.i32())
    if t in (5, 7, 8):
        return ({5: "u64", 7: "timepoint", 8: "duration"}[t], r.u64())
    if t == 6:
        return ("i64", r.i64())
    if t == 9:
        hi, lo = r.u64(), r.u64()
        return ("u128", (hi << 64) | lo)
    if t == 10:
        hi, lo = r.i64(), r.u64()
        return ("i128", (hi << 64) | lo)
    if t in (11, 12):
        parts = [r.i64() if (t == 12 and k == 0) else r.u64() for k in range(4)]
        v = 0
        for p in parts:
            v = (v << 64) | (p & ((1 << 64) - 1))
        if t == 12 and parts[0] < 0:
            v -= 1 << 256
        return ("u256" if t == 11 else "i256", v)
    if t == 13:
        return ("bytes", r.opaque())
    if t == 14:
        return ("string", r.string())
    if t == 15:
        return ("symbol", r.string(32))
    if t == 16:
        if not r.optional():
            return ("vec", None)
        return ("vec", [sc_val(r, depth + 1) for _ in range(r.count())])
    if t == 17:
        if not r.optional():
            return ("map", None)
        return ("map", [(sc_val(r, depth + 1), sc_val(r, depth + 1)) for _ in range(r.count())])
    if t == 18:
        return ("address", sc_address(r))
    if t == 21:
        return ("ledger_key_nonce", r.i64())
    raise StellarRefusal("scval_type_%d_not_supported" % t)


def invoke_contract_args(r):
    addr = sc_address(r)
    fn = r.string(32)
    args = [sc_val(r) for _ in range(r.count())]
    return {"contract": addr, "function": fn, "args": args}


def authorized_invocation(r, depth=0):
    if depth > MAX_DEPTH:
        raise StellarRefusal("invocation_nested_too_deep")
    s = r.i
    t = _enum(r.u32(), (0,), "authorized_function_type")    # create-contract functions are not a transfer
    fn = invoke_contract_args(r)
    subs = [authorized_invocation(r, depth + 1) for _ in range(r.count())]
    return {"type": t, "fn": fn, "subs": subs, "raw": r.b[s:r.i]}


def auth_entry(r):
    s = r.i
    ct = _enum(r.u32(), (0, 1, 2, 3), "soroban_credentials_type")
    cred = {"type": ct}
    if ct in (1, 2, 3):
        cred["address"] = sc_address(r)
        cred["nonce"] = r.i64()
        cred["expiration"] = r.u32()
        cred["signature"] = sc_val(r)
        if ct == 3:
            raise StellarRefusal("credentials_with_delegates_not_read")
    inv = authorized_invocation(r)
    return {"credentials": cred, "invocation": inv, "raw": r.b[s:r.i]}


def _ledger_key(r):
    t = _enum(r.u32(), tuple(range(10)), "ledger_key_type")
    if t == 0:
        account_id(r)
    elif t == 1:
        account_id(r)
        at = _enum(r.u32(), (0, 1, 2, 3), "asset_type")
        if at in (1, 2):
            r.take(4 if at == 1 else 12)
            account_id(r)
        elif at == 3:
            r.take(32)
    elif t == 2:
        account_id(r)
        r.i64()
    elif t == 3:
        account_id(r)
        r.string(64)
    elif t == 4:
        _enum(r.u32(), (0,), "claimable_balance_id_type")
        r.take(32)
    elif t in (5, 7, 9):
        r.take(32)
    elif t == 6:
        sc_address(r)
        sc_val(r)
        _enum(r.u32(), (0, 1), "contract_data_durability")
    else:
        r.i32()


def _soroban_data(r):
    v = _enum(r.u32(), (0, 1), "soroban_data_ext")
    if v == 1:
        for _ in range(r.count()):
            r.u32()
    for _ in range(2):
        for _ in range(r.count()):
            _ledger_key(r)
    r.u32(), r.u32(), r.u32()
    return r.i64()


def _preconditions(r):
    t = _enum(r.u32(), (0, 1, 2), "precondition_type")
    if t == 1:
        r.u64(), r.u64()
    elif t == 2:
        if r.optional():
            r.u64(), r.u64()
        if r.optional():
            r.u32(), r.u32()
        if r.optional():
            r.i64()
        r.u64(), r.u32()
        for _ in range(r.count(2)):
            st = _enum(r.u32(), (0, 1, 2, 3), "signer_key_type")
            r.take(32)
            if st == 3:
                r.opaque(64)


def _memo(r):
    t = _enum(r.u32(), (0, 1, 2, 3, 4), "memo_type")
    if t == 1:
        return r.string(28)
    if t == 2:
        return r.u64()
    if t in (3, 4):
        return r.take(32)
    return None


def operation(r):
    s = r.i
    src = muxed_account(r) if r.optional() else None
    ot = r.u32()
    if ot != 24:                                     # INVOKE_HOST_FUNCTION
        return {"source": src, "type": ot, "raw": None}
    ht = _enum(r.u32(), (0, 1, 2, 3), "host_function_type")
    if ht != 0:
        raise StellarRefusal("host_function_not_invoke_contract")
    fn = invoke_contract_args(r)
    auth = [auth_entry(r) for _ in range(r.count())]
    return {"source": src, "type": ot, "fn": fn, "auth": auth, "body_raw": r.b[s:r.i]}


def transaction(r):
    s = r.i
    src = muxed_account(r)
    fee = r.u32()
    seq = r.i64()
    _preconditions(r)
    memo = _memo(r)
    n = r.count(100)
    ops = []
    for _ in range(n):
        op = operation(r)
        if op["type"] != 24:
            raise StellarRefusal("operation_type_%d_not_read" % op["type"])
        ops.append(op)
    e0 = r.i
    ext = _enum(r.u32(), (0, 1), "transaction_ext")
    resource_fee = _soroban_data(r) if ext == 1 else None
    return {"source": src, "fee": fee, "seq": seq, "memo": memo, "ops": ops, "resource_fee": resource_fee,
            "raw": r.b[s:r.i], "ext_raw": r.b[e0:r.i]}


def _signatures(r):
    out = []
    for _ in range(r.count(20)):
        out.append((r.take(4), r.opaque(64)))
    return out


def envelope(b64):
    """TransactionEnvelope (ENVELOPE_TYPE_TX or _FEE_BUMP) from strict base64: dict with tx, signatures, and the
    TransactionSignaturePayload tag and bytes for the hash."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        raise StellarRefusal("not_base64")
    if base64.b64encode(raw).decode("ascii") != b64:
        raise StellarRefusal("base64_not_canonical")
    r = R(raw)
    t = _enum(r.u32(), (2, 5), "envelope_type")
    if t == 2:
        tx = transaction(r)
        sigs = _signatures(r)
        r.end()
        return {"type": 2, "tx": tx, "signatures": sigs, "tagged": (2).to_bytes(4, "big") + tx["raw"]}
    s = r.i
    fee_source = muxed_account(r)
    r.i64()
    _enum(r.u32(), (2,), "inner_envelope_type")
    tx = transaction(r)
    inner_sigs = _signatures(r)
    _enum(r.u32(), (0,), "fee_bump_ext")
    fb_raw = r.b[s:r.i]
    sigs = _signatures(r)
    r.end()
    return {"type": 5, "tx": tx, "inner_signatures": inner_sigs, "signatures": sigs, "fee_source": fee_source,
            "tagged": (5).to_bytes(4, "big") + fb_raw}


def tx_hash(env, network):
    """SHA-256 of the TransactionSignaturePayload: the transaction id Stellar reports."""
    return hashlib.sha256(network_id(network) + env["tagged"]).hexdigest()


def auth_preimage(entry, network):
    """SHA-256 of HashIDPreimage ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9) or ..._WITH_ADDRESS (10, credentials V2)."""
    c = entry["credentials"]
    head = network_id(network) + c["nonce"].to_bytes(8, "big", signed=True) + c["expiration"].to_bytes(4, "big")
    if c["type"] == 1:
        return hashlib.sha256((9).to_bytes(4, "big") + head + entry["invocation"]["raw"]).digest()
    # V2 (CAP-71): the address the credentials name is bound into the preimage, between expiration and invocation
    return hashlib.sha256((10).to_bytes(4, "big") + head + _encode_sc_address(c["address"])
                          + entry["invocation"]["raw"]).digest()


def _encode_sc_address(a):
    if a[0] == "G":
        return (0).to_bytes(4, "big") + (0).to_bytes(4, "big") + a[1]
    if a[0] == "C":
        return (1).to_bytes(4, "big") + a[1]
    raise StellarRefusal("address_kind_not_encoded")


def address_str(a):
    """G.../C... StrKey of an SCAddress tuple, or None for the kinds a payer or payee cannot be in this profile."""
    if a[0] in ("G", "C"):
        return strkey_encode(a[0], a[1])
    return None


def sac_contract_id(network, code, issuer_g):
    """Contract id of the Stellar Asset Contract of a classic credit asset (ContractIDPreimage FROM_ASSET)."""
    issuer = strkey_decode(issuer_g, "G")
    c = code.encode("ascii")
    if 1 <= len(c) <= 4:
        asset = (1).to_bytes(4, "big") + c.ljust(4, b"\0") + (0).to_bytes(4, "big") + issuer
    elif 5 <= len(c) <= 12:
        asset = (2).to_bytes(4, "big") + c.ljust(12, b"\0") + (0).to_bytes(4, "big") + issuer
    else:
        raise StellarRefusal("asset_code_length")
    pre = (8).to_bytes(4, "big") + network_id(network) + (1).to_bytes(4, "big") + asset   # ENVELOPE_TYPE_CONTRACT_ID
    return strkey_encode("C", hashlib.sha256(pre).digest())
