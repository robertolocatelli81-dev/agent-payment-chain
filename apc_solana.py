"""agent-payment-chain, Solana prototype (x402 `exact` on SVM, x402-foundation/x402@4241d56 scheme_exact_svm.md).
Standard library only: base58, the transaction wire format (legacy and v0 messages), Ed25519 verification and the
on-curve test of RFC 8032 5.1, program-derived addresses and the associated token account, TransferChecked decoding.
"""
import hashlib

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"


class SolRefusal(Exception):
    pass


B58_MAX_BYTES = 1232           # SPEC 29.2: without a fixed size, at most a packet (PACKET_DATA_SIZE) of bytes


def b58decode(s, size=None):
    if not isinstance(s, str) or not s or any(c not in B58 for c in s):
        raise SolRefusal("not_base58")
    # SPEC 29.2: n bytes are at most ceil(n log 256 / log 58) characters; a longer text is refused before the
    # quadratic big-integer conversion below (a 1 MiB string took over 20 s of CPU: tests/fuzz_cases)
    if len(s) > -(-(size if size is not None else B58_MAX_BYTES) * 136566 // 100000):
        raise SolRefusal("base58_too_long")
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    out = b"\0" * (len(s) - len(s.lstrip("1"))) + body
    if size is not None and len(out) != size:
        raise SolRefusal("base58_wrong_length")
    if b58encode(out) != s:
        raise SolRefusal("base58_not_canonical")
    return out


def b58encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


# ------------------------------------------------------------------ Ed25519, RFC 8032 5.1 (edwards25519)
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _decompress(b):
    """RFC 8032 5.1.3; None when the 32 bytes are not a point (that is the PDA 'off curve' test)."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x - u) % P:
        if (v * x * x + u) % P:
            return None
        x = x * SQRT_M1 % P
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a, b = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    c, dd = t1 * 2 * D * t2 % P, z1 * 2 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


_GY = 4 * pow(5, P - 2, P) % P
G = _decompress(_GY.to_bytes(32, "little"))


def on_curve(b):
    return _decompress(b) is not None


def _decompress_lax(b):
    """The decoding the chains use (SPEC 28.1): curve25519-dalek 4.1.3 CompressedEdwardsY::decompress (edwards.rs
    194-240; field.rs 326-338: the high bit is masked and y is not required below p) and ed25519-donna
    ge25519_unpack_negative_vartime (ed25519-donna-impl-base.h 192-239): y is the low 255 bits taken mod p, and the
    sign bit with x = 0 gives x = 0. None when y is not the y of a curve point."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y = (y & ((1 << 255) - 1)) % P
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x - u) % P:
        if (v * x * x + u) % P:
            return None
        x = x * SQRT_M1 % P
    if x & 1 != sign:
        x = (P - x) % P
    return (x, y, 1, x * y % P)


def _small_order(p):
    """[8]p is the identity (curve25519-dalek is_small_order, edwards.rs 1227-1229)."""
    q = _mul(8, p)
    return q[0] % P == 0 and (q[1] - q[2]) % P == 0


ED25519_RULES = ("rfc8032", "dalek_strict", "donna")


def ed25519_verify(pub, msg, sig, rule="rfc8032"):
    """rule "rfc8032": RFC 8032 5.1.7 (cofactorless equation [S]B = R + [k]A, S < L, A and R decodable with canonical
    encodings), for our own formats. The chains' rules (SPEC 28.1):
    "dalek_strict": Solana transaction signatures (solana-ed25519 0.2.4 verify_dalek, ed_sigs/verification_key.rs
    205-227 and 391-428) and Soroban (ed25519-dalek 2.1.1 verify_strict, verifying.rs 161-169 and 402-425): A and R
    decoded as _decompress_lax, A or R of small order refused, S < L, then [S]B - [k]A encoded must be the bytes of R;
    "donna": rippled (PublicKey.cpp 154-170 S < L and 280-289, ed25519-donna ed25519.c 94-116): A decoded as
    _decompress_lax, no order test, [S]B - [k]A encoded must be the bytes of R. k = SHA-512(R || A || M) over the bytes
    as given (dalek verifying.rs 194-214, donna ed25519.c 35-42)."""
    if rule not in ED25519_RULES:
        raise ValueError("unknown Ed25519 rule %r" % (rule,))
    if len(pub) != 32 or len(sig) != 64:
        return False
    if rule != "rfc8032":
        s = int.from_bytes(sig[32:], "little")
        a = _decompress_lax(pub)
        if a is None or s >= L:
            return False
        if rule == "dalek_strict":
            r = _decompress_lax(sig[:32])
            if r is None or _small_order(a) or _small_order(r):
                return False
        k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
        neg_a = ((P - a[0]) % P, a[1], a[2], (P - a[3]) % P)
        return _encode(_add(_mul(s, G), _mul(k, neg_a))) == sig[:32]
    a, r = _decompress(pub), _decompress(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    return _eq(_mul(s, G), _add(r, _mul(k, a)))


def _encode(p):
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _expand(seed):
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = hashlib.sha512(seed).digest()
    return int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254), h[32:]


def ed25519_public(seed):
    """RFC 8032 5.1.5"""
    return _encode(_mul(_expand(seed)[0], G))


def ed25519_sign(seed, msg):
    """RFC 8032 5.1.6"""
    a, prefix = _expand(seed)
    pub = _encode(_mul(a, G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    rb = _encode(_mul(r, G))
    k = int.from_bytes(hashlib.sha512(rb + pub + msg).digest(), "little") % L
    return rb + ((r + k * a) % L).to_bytes(32, "little")


# ------------------------------------------------------------------ addresses
def pda(seeds, program):
    """find_program_address: the first bump from 255 down whose hash is off the curve."""
    prog = b58decode(program, 32)
    for bump in range(255, -1, -1):
        h = hashlib.sha256(b"".join(seeds) + bytes([bump]) + prog + b"ProgramDerivedAddress").digest()
        if not on_curve(h):
            return b58encode(h), bump
    raise SolRefusal("no_pda")


def ata(owner, mint, token_program):
    return pda([b58decode(owner, 32), b58decode(token_program, 32), b58decode(mint, 32)], ATA_PROGRAM)[0]


# ------------------------------------------------------------------ wire format
def _shortvec(b, i):
    n = s = 0
    for k in range(3):
        if i >= len(b):
            raise SolRefusal("shortvec_truncated")
        c = b[i]
        i += 1
        n |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            if k and c == 0:
                raise SolRefusal("shortvec_not_minimal")
            if n > 0xFFFF:                      # ShortU16: Overflow above u16 (solana-sdk @6437e43 short-vec/src/lib.rs)
                raise SolRefusal("shortvec_above_u16")
            return n, i
    raise SolRefusal("shortvec_too_long")


def parse_tx(raw):
    """-> dict(signatures, message bytes, version, header, keys, blockhash, instructions, lookups)."""
    if len(raw) > 1232:                         # PACKET_DATA_SIZE = 1232 (solana-sdk @6437e43 packet/src/lib.rs)
        raise SolRefusal("transaction_larger_than_1232_bytes")
    n, i = _shortvec(raw, 0)
    sigs = []
    for _ in range(n):
        if i + 64 > len(raw):
            raise SolRefusal("signature_truncated")
        sigs.append(raw[i:i + 64])
        i += 64
    msg = raw[i:]
    j = 0
    version = "legacy"
    if msg and msg[0] & 0x80:
        if msg[0] != 0x80:
            raise SolRefusal("message_version_not_0")
        version, j = 0, 1
    if j + 3 > len(msg):
        raise SolRefusal("message_truncated")
    hdr = tuple(msg[j:j + 3])
    j += 3
    nk, j = _shortvec(msg, j)
    keys = []
    for _ in range(nk):
        if j + 32 > len(msg):
            raise SolRefusal("key_truncated")
        keys.append(b58encode(msg[j:j + 32]))
        j += 32
    if j + 32 > len(msg):
        raise SolRefusal("blockhash_truncated")
    blockhash = b58encode(msg[j:j + 32])
    j += 32
    ni, j = _shortvec(msg, j)
    ixs = []
    for _ in range(ni):
        if j >= len(msg):
            raise SolRefusal("instruction_truncated")
        prog = msg[j]
        j += 1
        na, j = _shortvec(msg, j)
        accs = list(msg[j:j + na])
        if len(accs) != na:
            raise SolRefusal("instruction_truncated")
        j += na
        nd, j = _shortvec(msg, j)
        data = msg[j:j + nd]
        if len(data) != nd:
            raise SolRefusal("instruction_truncated")
        j += nd
        ixs.append({"program": prog, "accounts": accs, "data": data})
    lookups = []
    if version == 0:
        nl, j = _shortvec(msg, j)
        for _ in range(nl):
            if j + 32 > len(msg):
                raise SolRefusal("lookup_truncated")
            table = b58encode(msg[j:j + 32])
            j += 32
            nw, j = _shortvec(msg, j)
            w = list(msg[j:j + nw])
            j += nw
            nr, j = _shortvec(msg, j)
            r = list(msg[j:j + nr])
            j += nr
            if len(w) != nw or len(r) != nr:
                raise SolRefusal("lookup_truncated")
            lookups.append({"table": table, "writable": w, "readonly": r})
    if j != len(msg):
        raise SolRefusal("message_trailing_bytes")
    if n != hdr[0]:
        raise SolRefusal("signature_count_not_header")
    nlook = sum(len(x["writable"]) + len(x["readonly"]) for x in lookups)
    for ix in ixs:
        if ix["program"] >= nk:                 # a program id must be a static key (runtime rule)
            raise SolRefusal("program_index_out_of_range")
        if any(a >= nk + nlook for a in ix["accounts"]):
            raise SolRefusal("account_index_out_of_range")
    return {"signatures": sigs, "message": msg, "version": version, "header": hdr, "keys": keys,
            "blockhash": blockhash, "instructions": ixs, "lookups": lookups}


def transfer_checked(tx, ix):
    """spl-token / token-2022 TransferChecked (instruction 12): accounts [source, mint, destination, authority, ...],
    data = 12 ‖ amount u64 LE ‖ decimals u8. None when the instruction is not that."""
    prog = tx["keys"][ix["program"]]
    if prog not in (SPL_TOKEN, TOKEN_2022) or len(ix["data"]) != 10 or ix["data"][0] != 12:
        return None
    if len(ix["accounts"]) < 4:
        raise SolRefusal("transfer_checked_accounts")
    k = tx["keys"]
    acc = [k[a] if a < len(k) else None for a in ix["accounts"][:4]]
    return {"program": prog, "source": acc[0], "mint": acc[1], "destination": acc[2], "authority": acc[3],
            "amount": int.from_bytes(ix["data"][1:9], "little"), "decimals": ix["data"][9]}
