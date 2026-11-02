"""XRP Ledger primitives for SPEC 0.16 (section 26), standard library only, offline:
  the binary codec (fields from XRPLF/xrpl.js f8c5c72 packages/ripple-binary-codec/src/enums/definitions.json, local
  copy sources/xrpl_js_f8c5c72), canonical field order, single-signature verification (secp256k1 ECDSA over
  SHA-512Half("STX\\0" || signing fields), fully canonical low-s; Ed25519 over the same bytes unhashed), the
  transaction id SHA-512Half("TXN\\0" || blob), classic addresses (RIPEMD-160(SHA-256(key)), base58 with the XRPL
  alphabet), the transaction SHAMap root and the ledger header hash ("LWR\\0").
Every decoder is closed: an unknown field, type or a trailing byte raises XrplError, never a silent skip."""
import hashlib
import json
import os

import apc_solana as sol

HERE = os.path.dirname(os.path.abspath(__file__))
DEFS_PATH = os.path.join(HERE, "sources", "xrpl_js_f8c5c72", "definitions.json")
ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIXED = {"UInt8": 1, "UInt16": 2, "UInt32": 4, "UInt64": 8, "Hash128": 16, "Hash160": 20, "Hash192": 24,
         "Hash256": 32, "Hash384": 48, "Hash512": 64, "UInt96": 12, "Int32": 4, "Int64": 8, "Currency": 20,
         "Number": 12}
NO_ACCOUNT = bytes(19) + b"\x01"


class XrplError(ValueError):
    pass


def _load_defs():
    with open(DEFS_PATH) as fh:
        d = json.load(fh)
    types = d["TYPES"]
    by_code, by_name = {}, {}
    for name, f in d["FIELDS"]:
        if not f["isSerialized"] or f["nth"] < 1 or types[f["type"]] < 1:
            continue
        key = (types[f["type"]], f["nth"])
        by_code[key] = dict(f, name=name, code=types[f["type"]])
        by_name[name] = by_code[key]
    return by_code, by_name, d["TRANSACTION_TYPES"], {v: k for k, v in d["TRANSACTION_RESULTS"].items()}


FIELDS, BY_NAME, TX_TYPES, RESULTS = _load_defs()
TX_TYPE_NAME = {v: k for k, v in TX_TYPES.items()}


def sha512half(b):
    return hashlib.sha512(b).digest()[:32]


# ------------------------------------------------------------------ RIPEMD-160 (pure; hashlib may lack it)
_RL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _f(j, x, y, z):
    return [x ^ y ^ z, (x & y) | (~x & z), (x | ~y) ^ z, (x & z) | (y & ~z), x ^ (y | ~z)][j] & 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ripemd160(msg):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    m = msg + b"\x80" + bytes((55 - len(msg)) % 64) + (8 * len(msg)).to_bytes(8, "little")
    for i in range(0, len(m), 64):
        X = [int.from_bytes(m[i + 4 * k:i + 4 * k + 4], "little") for k in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = (_rol((al + _f(r, bl, cl, dl) + X[_RL[j]] + _KL[r]) & 0xFFFFFFFF, _SL[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            t = (_rol((ar + _f(4 - r, br, cr, dr) + X[_RR[j]] + _KR[r]) & 0xFFFFFFFF, _SR[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b"".join(x.to_bytes(4, "little") for x in h)


# ------------------------------------------------------------------ addresses
def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return ALPHABET[0] * (len(data) - len(data.lstrip(b"\0"))) + out


def b58check_decode(s):
    if not isinstance(s, str) or not 25 <= len(s) <= 35 or any(c not in ALPHABET for c in s):
        raise XrplError("not an XRPL base58 string")
    n = 0
    for c in s:
        n = n * 58 + ALPHABET.index(c)
    lead = len(s) - len(s.lstrip(ALPHABET[0]))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    data = bytes(lead) + body
    if len(data) < 5 or hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4] != data[-4:]:
        raise XrplError("base58 checksum")
    return data[:-4]


def classic_address(account_id):
    return b58check(b"\x00" + account_id)


def account_id(address):
    """Classic address -> 20-byte AccountID; the round trip must give the same string (no alternative spellings)."""
    d = b58check_decode(address)
    if len(d) != 21 or d[0] != 0 or classic_address(d[1:]) != address:
        raise XrplError("not a classic address")
    return d[1:]


def key_account(pubkey):
    return ripemd160(hashlib.sha256(pubkey).digest())


# ------------------------------------------------------------------ binary codec
MAX_DEPTH = 10              # SPEC 29.2: STObjects nested at most 10 deep, STArrays not counted (the corpus: 4 at most)
VL_MAX = 918744             # the largest length the VL prefix encodes (xrpl.js BinarySerializer, rippled: 3 bytes up to 918744)


class _P:
    def __init__(self, b):
        self.b, self.i, self.depth = b, 0, 0

    def take(self, n):
        if n < 0 or self.i + n > len(self.b):
            raise XrplError("truncated")
        r = self.b[self.i:self.i + n]
        self.i += n
        return r

    def done(self):
        return self.i >= len(self.b)


def _field_id(p):
    b = p.take(1)[0]
    t, f = b >> 4, b & 15
    if t == 0:
        t = p.take(1)[0]
        if t < 16:
            raise XrplError("non-canonical field id")
    if f == 0:
        f = p.take(1)[0]
        if f < 16:
            raise XrplError("non-canonical field id")
    return t, f


def _vl(p):
    b1 = p.take(1)[0]
    if b1 <= 192:
        return b1
    if b1 <= 240:
        return 193 + (b1 - 193) * 256 + p.take(1)[0]
    if b1 <= 254:
        b2, b3 = p.take(2)
        return 12481 + (b1 - 241) * 65536 + b2 * 256 + b3
    raise XrplError("vl prefix 255")


def _amount(p):
    b0 = p.take(1)[0]
    if b0 & 0x80:                         # issued currency: 8-byte value, 20-byte currency, 20-byte issuer
        raw = bytes([b0]) + p.take(7)
        return ("iou", raw, p.take(20), p.take(20))
    if b0 & 0x20:                         # MPT amount: flag byte, 8-byte value, 24-byte issuance id
        return ("mpt", bytes([b0]) + p.take(8), p.take(24))
    raw = bytes([b0]) + p.take(7)
    if not b0 & 0x40:
        raise XrplError("XRP amount without the positive bit")
    return ("xrp", int.from_bytes(raw, "big") & ((1 << 62) - 1))


def _pathset(p):
    paths, cur = [], []
    while True:
        t = p.take(1)[0]
        if t in (0x00, 0xFF):
            paths.append(cur)
            if t == 0x00:
                return paths
            cur = []
            continue
        if t & ~0x31 or not t:
            raise XrplError("path step type")
        step = {}
        if t & 0x01:
            step["account"] = p.take(20)
        if t & 0x10:
            step["currency"] = p.take(20)
        if t & 0x20:
            step["issuer"] = p.take(20)
        cur.append(step)


def _issue(p):
    cur = p.take(20)
    if cur == bytes(20):
        return ("xrp",)
    iss = p.take(20)
    if iss == NO_ACCOUNT:
        return ("mpt", cur + p.take(4))
    return ("iou", cur, iss)


def _value(p, f):
    t = f["type"]
    if t in FIXED:
        return p.take(FIXED[t])
    if t == "Amount":
        return _amount(p)
    if t in ("Blob", "AccountID", "Vector256"):
        n = _vl(p)
        v = p.take(n)
        if t == "AccountID" and n != 20 or t == "Vector256" and n % 32:
            raise XrplError("%s length" % t)
        return v
    if t == "STObject":
        return _object(p, inner=True)
    if t == "STArray":
        out = []
        while True:
            tf = _field_id(p)
            if tf == (15, 1):                 # ArrayEndMarker
                return out
            g = FIELDS.get(tf)
            if g is None or g["type"] != "STObject":
                raise XrplError("array element not an object")
            out.append((g["name"], _object(p, inner=True)))
    if t == "PathSet":
        return _pathset(p)
    if t == "Issue":
        return _issue(p)
    if t == "XChainBridge":
        return (_vl_acc(p), _issue(p), _vl_acc(p), _issue(p))
    raise XrplError("field type %s not decoded" % t)


def _vl_acc(p):
    if _vl(p) != 20:
        raise XrplError("account length")
    return p.take(20)


def _object(p, inner=False):
    """Fields in order with their raw bytes: [(name, value, start, end, (type, nth))]; canonical order enforced."""
    p.depth += 1
    if p.depth > MAX_DEPTH:
        raise XrplError("objects nested deeper than %d" % MAX_DEPTH)
    try:
        return _fields(p, inner)
    finally:
        p.depth -= 1


def _fields(p, inner):
    out, last = [], None
    while not p.done():
        start = p.i
        tf = _field_id(p)
        if inner and tf == (14, 1):           # ObjectEndMarker
            return out
        f = FIELDS.get(tf)
        if f is None:
            raise XrplError("unknown field %r" % (tf,))
        if last is not None and tf <= last:
            raise XrplError("fields not in canonical order or repeated (%s)" % f["name"])
        last = tf
        out.append((f["name"], _value(p, f), start, p.i, tf))
    if inner:
        raise XrplError("object without end marker")
    return out


def decode(blob):
    """Top-level STObject (transaction or metadata) -> (fields list, dict name -> value)."""
    p = _P(blob)
    fields = _object(p)
    return fields, {n: v for n, v, *_ in fields}


def signing_bytes(blob, fields, prefix=b"STX\0"):
    return prefix + b"".join(blob[s:e] for n, v, s, e, tf in fields if FIELDS[tf]["isSigningField"])


def tx_id(blob):
    return sha512half(b"TXN\0" + blob).hex().upper()


def _der(sig):
    """Strict DER ECDSA -> (r, s) or None."""
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        return None
    out, i = [], 2
    for _ in range(2):
        if i + 2 > len(sig) or sig[i] != 0x02:
            return None
        n = sig[i + 1]
        v = sig[i + 2:i + 2 + n]
        if n == 0 or len(v) != n or v[0] & 0x80 or (n > 1 and v[0] == 0 and not v[1] & 0x80) or n > 33:
            return None
        out.append(int.from_bytes(v, "big"))
        i += 2 + n
    return tuple(out) if i == len(sig) else None


def verify_signature(blob, fields, vals):
    """Single signature: 'verified', or 'failed:<reason>' / 'not_evaluated:<reason>'."""
    pk, sig = vals.get("SigningPubKey"), vals.get("TxnSignature")
    if "Signers" in vals or pk == b"":
        return "not_evaluated:multisigned"
    if pk is None or sig is None:
        return "failed:no_signature"
    data = signing_bytes(blob, fields)
    if len(pk) == 33 and pk[0] == 0xED:
        ok = len(sig) == 64 and sol.ed25519_verify(pk[1:], data, sig, "donna")      # rippled's rule, SPEC 28.1
        return "verified" if ok else "failed:ed25519_signature"
    if len(pk) != 33 or pk[0] not in (2, 3):
        return "failed:signing_key_not_secp256k1_or_ed25519"
    return secp256k1_verify(pk, sha512half(data), sig)


def secp256k1_verify(pk, dg, sig):
    """rippled verifyDigest with mustBeFullyCanonical (PublicKey.cpp 224-269, PublicKey.h 240): strict DER, r and s
    in [1, n-1], s <= n/2, then the ECDSA check against the 33-byte compressed key, made here by recovery."""
    rs = _der(sig)
    if rs is None:
        return "failed:signature_not_strict_der"
    r, s = rs
    if not (0 < r < SECP_N and 0 < s < SECP_N):
        return "failed:signature_out_of_range"
    if s > SECP_N // 2:
        return "failed:signature_not_fully_canonical"     # rippled: tfFullyCanonicalSig is required (low s)
    from lib.secp256k1 import recover_public_key
    for rec in range(4):
        try:
            x, y = recover_public_key(dg, r, s, rec)
        except ValueError:
            continue
        if bytes([2 + (y & 1)]) + x.to_bytes(32, "big") == pk:
            return "verified"
    return "failed:secp256k1_signature"


# ------------------------------------------------------------------ amounts
def iou_value(raw):
    """8-byte issued-currency value -> (mantissa signed int, exponent); zero -> (0, 0)."""
    v = int.from_bytes(raw, "big")
    if v == 0x8000000000000000:
        return 0, 0
    m = v & ((1 << 54) - 1)
    e = ((v >> 54) & 0xFF) - 97
    if not 10 ** 15 <= m < 10 ** 16 or not -96 <= e <= 80:
        raise XrplError("issued amount not normalized")
    return (m if v >> 62 & 1 else -m), e


def decimal_parts(s):
    """A decimal string as (integer, exponent) exactly, no float, no Decimal context; None outside the grammar."""
    import re
    # the XRPL range: a 16-digit mantissa with exponents -96..80, so at most 97 integer and 111 fraction digits
    m = re.fullmatch(r"(0|[1-9][0-9]{0,96})(?:\.([0-9]{1,111}))?", s) if isinstance(s, str) else None
    if not m:
        return None
    frac = m.group(2) or ""
    return int(m.group(1) + frac), -len(frac)


def same_value(a, b):
    """(m, e) == (m', e') as numbers."""
    (m1, e1), (m2, e2) = a, b
    if m1 == 0 or m2 == 0:
        return m1 == m2
    k = min(e1, e2)
    if max(e1, e2) - k > 200:
        return False
    return m1 * 10 ** (e1 - k) == m2 * 10 ** (e2 - k)


def compare_value(a, b):
    (m1, e1), (m2, e2) = a, b
    k = min(e1, e2)
    if max(e1, e2) - k > 200:
        return (abs(m1) > 0) - (abs(m2) > 0) if e1 > e2 else -((abs(m2) > 0) - (abs(m1) > 0))
    x, y = m1 * 10 ** (e1 - k), m2 * 10 ** (e2 - k)
    return (x > y) - (x < y)


def currency_bytes(code):
    """x402 asset field (3-character code or 40 hex) -> 20 bytes; None outside the grammar."""
    import re
    if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9?!@#$%^&*<>(){}\[\]|]{3}", code) and code != "XRP":
        return bytes(12) + code.encode("ascii") + bytes(5)
    if isinstance(code, str) and re.fullmatch(r"[0-9A-Fa-f]{40}", code) and code[:2] != "00":
        return bytes.fromhex(code)
    return None


# ------------------------------------------------------------------ ledger
def shamap_root(leaves):
    """Transaction SHAMap root: leaves = {txid bytes: leaf hash bytes}."""
    def node(keys, depth):
        if not keys:
            return bytes(32)
        if len(keys) == 1 and depth > 0:
            return leaves[keys[0]]
        kids = []
        for nib in range(16):
            sub = [k for k in keys if (k[depth // 2] >> (4 * (1 - depth % 2))) & 15 == nib]
            kids.append(node(sub, depth + 1))
        return sha512half(b"MIN\0" + b"".join(kids))
    return node(sorted(leaves), 0)


def tx_leaf(tx_blob, meta_blob):
    def vl(b):
        n = len(b)
        if n > VL_MAX:
            raise XrplError("blob of %d bytes: longer than the VL prefix encodes (%d)" % (n, VL_MAX))
        if n <= 192:
            h = bytes([n])
        elif n <= 12480:
            n -= 193
            h = bytes([193 + n // 256, n % 256])
        else:
            n -= 12481
            h = bytes([241 + n // 65536, (n // 256) % 256, n % 256])
        return h + b
    tid = sha512half(b"TXN\0" + tx_blob)
    return tid, sha512half(b"SND\0" + vl(tx_blob) + vl(meta_blob) + tid)


def ledger_header(data):
    if len(data) != 118:
        raise XrplError("ledger header not 118 bytes")
    return {"ledger_index": int.from_bytes(data[0:4], "big"), "total_coins": int.from_bytes(data[4:12], "big"),
            "parent_hash": data[12:44], "transaction_hash": data[44:76], "account_hash": data[76:108],
            "parent_close_time": int.from_bytes(data[108:112], "big"), "close_time": int.from_bytes(data[112:116], "big"),
            "close_time_resolution": data[116], "close_flags": data[117],
            "hash": sha512half(b"LWR\0" + data).hex().upper()}
