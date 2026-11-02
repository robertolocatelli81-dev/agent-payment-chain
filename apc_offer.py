"""SPEC 0.11 (section 13): the x402 `offer-receipt` extension — signed offers in PaymentRequired, a signed receipt in the
SettlementResponse (x402 4241d56 specs/extensions/extension-offer-and-receipt.md, cited OR §n). Checks OR1 (offers),
OR2 (receipt), OR3 (signer authorization). Offline, standard library only: EIP-712 over secp256k1 (x402-signature-
vectors lib), JWS ES256K / EdDSA / ES256 with keys from did:key, did:jwk or the reader's signer_trust document."""
import base64
import hashlib
import re

import apc_verify as av
from apc_verify import Refusal, _obj, _str

EXT = "offer-receipt"
SAFE = 2 ** 53
CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\Z")         # CAIP-2 namespace:reference
EIP155 = re.compile(r"eip155:(0|[1-9][0-9]{0,77})\Z")
ORIGIN = re.compile(r"https?://[^/?#@\s]+\Z")
OFFER_TYPES = {"Offer": [{"name": n, "type": t} for n, t in (
    ("version", "uint256"), ("resourceUrl", "string"), ("scheme", "string"), ("network", "string"),
    ("asset", "string"), ("payTo", "string"), ("amount", "string"), ("validUntil", "uint256"))]}
RECEIPT_TYPES = {"Receipt": [{"name": n, "type": t} for n, t in (
    ("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
    ("issuedAt", "uint256"), ("transaction", "string"))]}
OFFER_MEMBERS = (("version", "resourceUrl", "scheme", "network", "asset", "payTo", "amount"), ("validUntil",))
RECEIPT_MEMBERS = (("version", "network", "resourceUrl", "payer", "issuedAt"), ("transaction",))
# the merged extension (OR at 4241d56): payload version -> (members, EIP-712 types)
SPEC_MERGED = {"offer": {1: (OFFER_MEMBERS, OFFER_TYPES)}, "receipt": {1: (RECEIPT_MEMBERS, RECEIPT_TYPES)}}
ALGS = ("EdDSA", "ES256K", "ES256")
# secp256k1 and P-256: (p, a, b, n, G)
K1 = (2 ** 256 - 2 ** 32 - 977, 0, 7, av.SECP_N,
      (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))
R1 = (2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1, -3,
      0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
      0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
      (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
       0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5))


class Bad(Exception):
    """An artifact that does not hold: becomes failed:<artifact>_<reason>."""


class Open(Exception):
    """An artifact that cannot be evaluated: becomes not_evaluated:<artifact>_<reason>."""


# ------------------------------------------------------------------ curve arithmetic (affine; verification only)
def _on(c, pt):
    p, a, b = c[0], c[1], c[2]
    x, y = pt
    return 0 <= x < p and 0 <= y < p and (y * y - x * x * x - a * x - b) % p == 0


def _add(c, P, Q):
    p, a = c[0], c[1]
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return x, (lam * (P[0] - x) - P[1]) % p


def _mul(c, k, P):
    R = None
    while k:
        if k & 1:
            R = _add(c, R, P)
        P = _add(c, P, P)
        k >>= 1
    return R


def _decompress(c, b):
    """SEC 1 2.3.3 point: 0x02/0x03 || x (33 bytes) or 0x04 || x || y (65 bytes); both p are 3 mod 4."""
    p, a, bb = c[0], c[1], c[2]
    if len(b) == 65 and b[0] == 4:
        pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
    elif len(b) == 33 and b[0] in (2, 3):
        x = int.from_bytes(b[1:], "big")
        if x >= p:
            return None
        y2 = (x * x * x + a * x + bb) % p
        y = pow(y2, (p + 1) // 4, p)
        if y * y % p != y2:
            return None
        pt = (x, y if y % 2 == b[0] % 2 else p - y)
    else:
        return None
    return pt if _on(c, pt) else None


def ecdsa_verify(c, pub, msg, sig):
    """ECDSA with SHA-256 over msg, sig = r || s (64 bytes, RFC 7518 3.4 / RFC 8812); low or high s both accepted."""
    n, G = c[3], c[4]
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, n)
    X = _add(c, _mul(c, e * w % n, G), _mul(c, r * w % n, pub))
    return X is not None and X[0] % n == r


def evm_address(pt):
    return "0x" + av.keccak256(pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big"))[-20:].hex()


# ------------------------------------------------------------------ keys
def _b64u(s, what):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise Bad(what + "_not_base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(b).rstrip(b"=").decode() != s:
        raise Bad(what + "_not_base64url")
    return b


def _key(alg, raw):
    """(alg, key) with key the public point (EC) or the 32 bytes (Ed25519), or None if not a valid key."""
    if alg == "EdDSA":
        import apc_solana as sol
        return (alg, raw) if len(raw) == 32 and sol.on_curve(raw) else None
    pt = _decompress(K1 if alg == "ES256K" else R1, raw)
    return (alg, pt) if pt is not None else None


def _jwk_key(jwk, notes):
    if not isinstance(jwk, dict):
        raise Bad("did_jwk_not_an_object")
    if "d" in jwk:
        raise Refusal("did:jwk carries a private key member d")
    extra = sorted(set(jwk) - {"kty", "crv", "x", "y"})
    if extra:           # RFC 7517 4: members not understood MUST be ignored
        notes.append("did:jwk members ignored (RFC 7517 4): %s" % ", ".join(extra))
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519" and "y" not in jwk:
        k = _key("EdDSA", _b64u(jwk.get("x"), "did_jwk_x"))
    elif kty == "EC" and crv in ("secp256k1", "P-256"):
        x, y = _b64u(jwk.get("x"), "did_jwk_x"), _b64u(jwk.get("y"), "did_jwk_y")
        if len(x) != 32 or len(y) != 32:
            raise Bad("did_jwk_coordinate_not_32_bytes")
        k = _key("ES256K" if crv == "secp256k1" else "ES256", b"\x04" + x + y)
    else:
        raise Open("did_jwk_key_type_not_supported")
    if k is None:
        raise Bad("did_jwk_not_a_valid_key")
    return k


def resolve(kid, trust, notes):
    """kid -> (alg, key): did:key and did:jwk offline; any kid listed in the reader's trust keys."""
    if trust is not None and kid in trust["keys"]:
        return trust["keys"][kid]
    if len(kid) > 4096:                 # bounds the base58 / base64url decoding below
        raise Bad("kid_longer_than_4096")
    if kid.startswith("did:key:"):
        ident = kid[8:].split("#", 1)[0]
        if len(ident) > 128:            # a multibase key of this profile is at most 50 characters
            raise Bad("did_key_too_long")
        if not ident.startswith("z"):
            raise Open("did_key_multibase_not_base58btc")
        import apc_solana as sol
        try:
            raw = sol.b58decode(ident[1:])
        except Exception:       # noqa: BLE001 — any decoding error of the multibase string
            raise Bad("did_key_not_base58")
        for prefix, alg, size in ((b"\xed\x01", "EdDSA", 32), (b"\xe7\x01", "ES256K", 33), (b"\x80\x24", "ES256", 33)):
            if raw.startswith(prefix):
                if len(raw) != len(prefix) + size:
                    raise Bad("did_key_wrong_length")
                k = _key(alg, raw[len(prefix):])
                if k is None:
                    raise Bad("did_key_not_a_valid_key")
                return k
        raise Open("did_key_type_not_supported")
    if kid.startswith("did:jwk:"):
        raw = _b64u(kid[8:].split("#", 1)[0], "did_jwk")
        try:
            jwk = av.strict_json(raw.decode("utf-8"))
        except (Refusal, UnicodeDecodeError):
            raise Bad("did_jwk_not_json")
        return _jwk_key(jwk, notes)
    raise Open("key_not_resolvable_offline")


def parse_trust(doc):
    """SPEC 0.11 signer_trust: {"apc_signer_trust": 1, "keys"?: {kid: {alg, public_key}}, "authorized": [...]}, closed."""
    _obj(doc, "signer_trust", ("apc_signer_trust", "authorized"), ("keys",))
    if doc["apc_signer_trust"] != 1 or isinstance(doc["apc_signer_trust"], bool):
        raise Refusal("signer_trust.apc_signer_trust: not 1")
    keys = {}
    if "keys" in doc:
        if not isinstance(doc["keys"], dict):
            raise Refusal("signer_trust.keys: not an object")
        for kid, k in doc["keys"].items():
            q = "signer_trust.keys[%r]" % kid
            _obj(k, q, ("alg", "public_key"))
            if k["alg"] not in ALGS:
                raise Refusal("%s.alg: not one of %s" % (q, ", ".join(ALGS)))
            if not isinstance(k["public_key"], str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", k["public_key"]):
                raise Refusal("%s.public_key: not lowercase hex" % q)
            b = bytes.fromhex(k["public_key"])
            if (k["alg"] == "EdDSA") != (len(b) == 32) or (k["alg"] != "EdDSA" and (len(b) != 65 or b[0] != 4)):
                raise Refusal("%s.public_key: Ed25519 is 32 bytes, an EC key 0x04 || x || y" % q)
            kk = _key(k["alg"], b)
            if kk is None:
                raise Refusal("%s.public_key: not a point of the curve" % q)
            keys[kid] = kk
    if not isinstance(doc["authorized"], list) or not 1 <= len(doc["authorized"]) <= 256:
        raise Refusal("signer_trust.authorized: not a list of 1..256 entries")
    auth = {}
    for i, e in enumerate(doc["authorized"]):
        q = "signer_trust.authorized[%d]" % i
        _obj(e, q, ("origin", "signers"))
        o = _str(e["origin"], q + ".origin")
        import apc_intl                             # SPEC 0.11.4: an IDN origin is read as its A-label form
        if not ORIGIN.match(o) or apc_intl.origin(o) is None or (o.isascii() and o != o.lower()):
            raise Refusal("%s.origin: not an https?://host[:port] (lower case, or an IDN host)" % q)
        o = apc_intl.origin(o)
        if not isinstance(e["signers"], list) or not 1 <= len(e["signers"]) <= 64:
            raise Refusal("%s.signers: not a list of 1..64" % q)
        for s in e["signers"]:
            s = _str(s, q + ".signers[]")
            auth.setdefault(o, set()).add(s.lower() if av.ADDR.match(s) else s)
    return {"keys": keys, "authorized": auth}


# ------------------------------------------------------------------ artifacts
def _int53(v, what, path):
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < SAFE:
        raise Refusal("%s.%s: not a JSON integer in [0, 2^53)" % (path, what))
    return v


def _closed(v, path, req, opt=()):
    """OR §2: "treat unknown extension-specific fields as unsupported": a member outside req + opt is Open (the check is
    not evaluated, with its name), never ignored; a missing member or a non-object is outside the grammar (Refusal)."""
    if not isinstance(v, dict):
        raise Refusal("%s: not an object" % path)
    for k in req:
        if k not in v:
            raise Refusal("%s: missing member %s" % (path, k))
    extra = sorted(k for k in v if k not in req and k not in opt)
    if extra:
        raise Open("member_not_supported(%s.%s)" % (path.rsplit(".", 1)[-1], extra[0][:40]))
    return v


def _payload(v, kind, path, spec=None):
    spec = spec or SPEC_MERGED
    if isinstance(v, dict) and isinstance(v.get("version"), int) and not isinstance(v.get("version"), bool) \
            and v["version"] not in spec[kind]:
        raise Open("version_not_supported")
    if not isinstance(v, dict) or "version" not in v:
        raise Refusal("%s: not an object with a version" % path)
    _int53(v["version"], "version", path)
    req, opt = spec[kind][v["version"]][0]
    _closed(v, path, req, opt)
    for k in req + opt:
        if k not in v:
            continue
        if k in ("version", "validUntil", "issuedAt"):
            _int53(v[k], k, path)
        elif k in opt:              # OR §4.3, §5.3: an optional string may be "", read as absent
            if not isinstance(v[k], str):
                raise Refusal("%s.%s: not a string" % (path, k))
        else:
            _str(v[k], "%s.%s" % (path, k))
    return v


def _eip712(art, kind, notes, spec=None):
    pl = art["payload"]
    if not EIP155.match(pl["network"]) or (kind == "offer" and not av.ADDR.match(pl["payTo"])):
        raise Bad("eip712_needs_evm")
    sig = art["signature"]
    if not isinstance(sig, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", sig):
        raise Bad("signature_not_65_bytes_hex")
    b = bytes.fromhex(sig[2:])
    v = b[64]
    if v in (0, 1):
        notes.append("%s: v %d read as %d (as the reference implementation's viem)" % (kind, v, v + 27))
        v += 27
    if v not in (27, 28):
        raise Bad("v_not_27_or_28")
    spec = spec or SPEC_MERGED
    types = spec[kind][pl["version"]][1]
    _, opt = spec[kind][pl["version"]][0]
    # OR §4.3, §5.3: an absent optional member is 0 (uint256) or "" (string) in the signed message
    msg = dict({k: (0 if k == "validUntil" else "") for k in opt}, **pl)
    if kind == "offer":
        dom, primary = {"name": "x402 offer", "version": "1", "chainId": 1}, "Offer"
    else:
        dom, primary = {"name": "x402 receipt", "version": "1", "chainId": 1}, "Receipt"
    try:
        d = av.signing_digest(dom, primary, types, msg)
        pt = av.recover_public_key(d, int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big"), v - 27)
    except ValueError:
        raise Bad("no_recovery")
    if int.from_bytes(b[32:64], "big") > av.SECP_N // 2:
        notes.append("%s: EIP-712 signature with s in the upper half (accepted off chain, as the reference)" % kind)
    return {"format": "eip712", "alg": "secp256k1-recover", "kid": None, "signer": evm_address(pt), "key": ("ES256K", pt)}


def _jws(art, kind, trust, notes, spec=None):
    s = art["signature"]
    if not isinstance(s, str) or s.count(".") != 2:
        raise Bad("jws_not_compact")
    h64, p64, s64 = s.split(".")
    try:
        hdr = av.strict_json(_b64u(h64, "jws_header").decode("utf-8"))
    except (Refusal, UnicodeDecodeError):
        raise Bad("jws_header_not_json")
    if not isinstance(hdr, dict) or not isinstance(hdr.get("alg"), str) or not isinstance(hdr.get("kid"), str):
        raise Bad("jws_header_needs_alg_and_kid")
    if "crit" in hdr:                   # RFC 7515 4.1.11: extensions not understood -> the JWS is invalid
        raise Bad("jws_crit_not_understood")
    extra = sorted(set(hdr) - {"alg", "kid"})
    if extra:                           # RFC 7515 4: header parameters not understood MUST be ignored
        notes.append("%s: JWS header members ignored (RFC 7515 4): %s" % (kind, ", ".join(extra)))
    raw = _b64u(p64, "jws_payload")
    try:
        pl = av.strict_json(raw.decode("utf-8"))
    except (Refusal, UnicodeDecodeError):
        raise Bad("jws_payload_not_json")
    import apc_ap2
    try:
        if not isinstance(pl, dict) or apc_ap2.canonical(pl).encode("utf-8") != raw:
            raise Bad("jws_payload_not_jcs")            # OR §10: JCS for JWS payloads
    except (TypeError, ValueError):
        raise Bad("jws_payload_not_jcs")
    try:
        _payload(pl, kind, "payload", spec)
    except Refusal as e:                # the signed bytes are not a payload of OR §4.2 / §5.2
        raise Bad("jws_payload_outside_grammar(%s)" % e)
    alg, key = resolve(hdr["kid"], trust, notes)
    if hdr["alg"] != alg:
        raise Bad("alg_not_the_key_algorithm")
    sig = _b64u(s64, "jws_signature")
    data = (h64 + "." + p64).encode("ascii")
    if alg == "EdDSA":
        import apc_solana as sol
        ok = len(sig) == 64 and sol.ed25519_verify(key, data, sig)
    else:
        ok = ecdsa_verify(K1 if alg == "ES256K" else R1, key, data, sig)
    if not ok:
        raise Bad("signature_invalid")
    return {"format": "jws", "alg": alg, "kid": hdr["kid"], "payload": pl, "key": (alg, key),
            "signer": hdr["kid"]}


def _artifact(art, kind, path, trust, notes, spec=None):
    """(info, None) for a verified signature, (None, check result) otherwise. Grammar errors raise Refusal."""
    spec = spec or SPEC_MERGED
    keys_opt = ("payload", "acceptIndex") if kind == "offer" else ("payload",)
    if not isinstance(art, dict):
        raise Refusal("%s: not an object" % path)
    fmt = _str(art.get("format"), path + ".format")
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", fmt):
        raise Refusal("%s.format: not a format name" % path)
    _str(art.get("signature"), path + ".signature")
    if fmt == "eip712" and "payload" not in art:
        raise Refusal("%s: eip712 needs payload (OR 3.1.1)" % path)
    if fmt == "jws" and "payload" in art:
        raise Refusal("%s: jws must not carry payload (OR 3.1.1)" % path)
    if "acceptIndex" in art:
        if kind != "offer":
            return None, "not_evaluated:%s_member_not_supported(acceptIndex)" % kind
        _int53(art["acceptIndex"], "acceptIndex", path)
    if fmt not in ("eip712", "jws"):
        return None, "not_evaluated:%s_format_not_supported" % kind
    try:
        _closed(art, path, ("format", "signature"), keys_opt)
        if fmt == "eip712":
            pl = _payload(art["payload"], kind, path + ".payload", spec)
            if not CAIP2.match(pl["network"]):
                raise Bad("network_not_caip2")
            info = _eip712(art, kind, notes, spec)
            info["payload"] = pl
        else:
            info = _jws(art, kind, trust, notes, spec)
            pl = info["payload"]
            if not CAIP2.match(pl["network"]):
                raise Bad("network_not_caip2")
    except Bad as e:
        return None, "failed:%s_%s" % (kind, e)
    except Open as e:
        return None, "not_evaluated:%s_%s" % (kind, e)
    return info, None


def _same_addr(a, b, evm):
    return isinstance(a, str) and isinstance(b, str) and ((a.lower() == b.lower() and bool(av.ADDR.match(a)))
                                                          if evm else a == b)


def key_address(alg, key, family):
    """The payTo a signing key controls on the payment's network family (SPEC 0.11, 0.16.1), or None where a key does
    not name an address: EVM secp256k1 -> keccak address; Solana Ed25519 -> base58 of the key; Stellar Ed25519 -> the
    G StrKey (SEP-23); XRPL Ed25519 (0xED || key) or secp256k1 (compressed) -> the classic address of
    RIPEMD-160(SHA-256(key))."""
    if family == "evm":
        return evm_address(key) if alg == "ES256K" else None
    if family == "solana" and alg == "EdDSA":
        import apc_solana as sol
        return sol.b58encode(key)
    if family == "stellar" and alg == "EdDSA":
        import apc_stellar as xs
        return xs.strkey_encode("G", key)
    if family == "xrpl" and alg in ("EdDSA", "ES256K"):
        import apc_xrpl as xr
        pub = b"\xed" + key if alg == "EdDSA" else bytes([2 + (key[1] & 1)]) + key[0].to_bytes(32, "big")
        return xr.classic_address(xr.key_account(pub))
    return None


def _authorized(info, pay_to, resource_url, evm, trust, family=None):
    """OR3 for one verified artifact: 'verified', 'failed:signer_not_authorized' or the absent result."""
    alg, key = info["key"]
    family = family or ("evm" if evm else "solana")
    if info["format"] == "eip712":
        if _same_addr(info["signer"], pay_to, True):
            return "verified"
    elif evm and alg == "ES256K" and _same_addr(key_address(alg, key, family), pay_to, True):
        return "verified"
    elif not evm and key_address(alg, key, family) == pay_to:
        return "verified"
    if trust is None:
        return "not_evaluated:absent:no_signer_trust"
    import apc_intl
    origin = apc_intl.origin(resource_url) if isinstance(resource_url, str) else None
    who = info["signer"].lower() if info["format"] == "eip712" else info["signer"]
    return "verified" if origin and who in trust["authorized"].get(origin, ()) else "failed:signer_not_authorized"


def _ext(container, path, member, extra_info=()):
    """(info, None) for the extension's info object {member: ...}, (None, reason) for an unsupported member, or
    (None, None) when the container does not carry the extension."""
    ext = container.get("extensions") if isinstance(container, dict) else None
    if not isinstance(ext, dict) or EXT not in ext:
        return None, None
    q = "%s.extensions[%r]" % (path, EXT)
    try:
        e = _closed(ext[EXT], q, ("info",), ("schema",))
        if "schema" in e and not isinstance(e["schema"], dict):
            raise Refusal("%s.schema: not an object" % q)
        return _closed(e["info"], q + ".info", (member,), extra_info), None
    except Open as x:
        return None, str(x)


def check(doc, ctx, trust, spec=None, extra_info=()):
    """ctx: evm, network, scheme, asset, pay_to, amount, resource_url, payer, transaction (str or None), success
    (bool or None), block_time (int or None), accepts (list or None), and optionally family ("evm", "solana",
    "stellar", "xrpl"; default evm or solana by ctx["evm"]: how a key names a payTo, and on XRPL the transaction id
    compared without case, as T1 does). Returns (checks, notes, report member); ({}, [], None) without the extension."""
    pr_info, pr_open = _ext(doc.get("payment_required"), "payment_required", "offers")
    st_info, st_open = _ext(doc.get("settlement"), "settlement", "receipt", extra_info)
    notes = []
    pl_ext = doc.get("payment_payload", {}).get("extensions") if isinstance(doc.get("payment_payload"), dict) else None
    if isinstance(pl_ext, dict) and EXT in pl_ext:
        notes.append("payment_payload.extensions carries offer-receipt: carried, not interpreted (the extension places "
                     "offers in PaymentRequired and the receipt in the SettlementResponse)")
    if pr_info is None and st_info is None and pr_open is None and st_open is None:
        return {}, notes, None
    evm = ctx["evm"]
    res, member, verified = {}, {"offers": [], "receipt": None}, []
    if pr_open is not None:
        res["OR1"] = "not_evaluated:offer_" + pr_open
    if st_open is not None:
        res["OR2"] = "not_evaluated:receipt_" + st_open
    # OR1 offers
    if pr_info is not None:
        offers = pr_info["offers"]
        if not isinstance(offers, list) or not 1 <= len(offers) <= 64:
            raise Refusal("payment_required.extensions[%r].info.offers: not a list of 1..64" % EXT)
        first_bad = first_open = None
        match = None
        for i, art in enumerate(offers):
            path = "payment_required.extensions[%r].info.offers[%d]" % (EXT, i)
            info, r = _artifact(art, "offer", path, trust, notes, spec)
            if info is None:
                r = r.replace(":offer_", ":offer_%d_" % i, 1)
                if r.startswith("failed"):
                    first_bad = first_bad or r
                else:
                    first_open = first_open or r
                member["offers"].append({"index": i, "format": art["format"], "result": r})
                continue
            pl = info["payload"]
            terms = (pl["scheme"] == ctx["scheme"] and pl["network"] == ctx["network"] and pl["amount"] == ctx["amount"]
                     and _same_addr(pl["asset"], ctx["asset"], evm) and _same_addr(pl["payTo"], ctx["pay_to"], evm))
            if "acceptIndex" in art and ctx["accepts"] is not None:
                j = art["acceptIndex"]
                if j >= len(ctx["accepts"]):
                    first_bad = first_bad or "failed:offer_accept_index_out_of_range"
                else:
                    a = ctx["accepts"][j]
                    if not (isinstance(a, dict) and a.get("scheme") == pl["scheme"] and a.get("network") == pl["network"]
                            and a.get("amount") == pl["amount"] and _same_addr(a.get("asset"), pl["asset"], evm)
                            and _same_addr(a.get("payTo"), pl["payTo"], evm)):
                        first_bad = first_bad or "failed:offer_accept_index_mismatch"
            ok = terms and pl["resourceUrl"] == ctx["resource_url"]
            if ok and match is None:
                match = (i, info)
            vu = pl.get("validUntil", 0)
            if ok and vu and ctx["block_time"] is not None and ctx["block_time"] > vu:
                notes.append("OR1: offer %d validUntil %d is before the settlement's block time %d: the server MAY "
                             "reject such a payment (OR 4.6)" % (i, vu, ctx["block_time"]))
            member["offers"].append({"index": i, "format": info["format"], "alg": info["alg"], "kid": info["kid"],
                                     "signer": info["signer"], "matches": ok, "result": "verified"})
        if first_bad:
            res["OR1"] = first_bad
        elif match is None:
            res["OR1"] = first_open or "not_evaluated:no_signed_offer_for_accepted"
            if first_open is None:
                notes.append("OR1: no signed offer carries the paid terms (resource URL, scheme, network, asset, payTo, "
                             "amount); a server may sign only some of its options")
        else:
            res["OR1"] = first_open or "verified"
            verified.append(match[1])
    # OR2 receipt
    if st_info is not None:
        info, r = _artifact(st_info["receipt"], "receipt", "settlement.extensions[%r].info.receipt" % EXT, trust, notes,
                            spec)
        if ctx["success"] is not True:
            res["OR2"] = "failed:receipt_on_unsuccessful_settlement"
        elif info is None:
            res["OR2"] = r
        else:
            pl = info["payload"]
            tx = pl.get("transaction", "")
            if pl["network"] != ctx["network"]:
                res["OR2"] = "failed:receipt_network_mismatch"
            elif not _same_addr(pl["payer"], ctx["payer"], evm):
                res["OR2"] = "failed:receipt_payer_mismatch"
            elif tx and not (tx.lower() == (ctx["transaction"] or "").lower() if evm or ctx.get("family") == "xrpl"
                             else tx == ctx["transaction"]):
                res["OR2"] = "failed:receipt_transaction_mismatch"
            elif ctx["resource_url"] is None:
                res["OR2"] = "not_evaluated:no_resource_url"
            elif pl["resourceUrl"] != ctx["resource_url"]:
                res["OR2"] = "failed:receipt_resource_url_mismatch"
            else:
                res["OR2"] = "verified"
                verified.append(info)
            if ctx["block_time"] is not None and pl["issuedAt"] < ctx["block_time"]:
                notes.append("OR2: receipt issuedAt %d is before the settlement's block time %d (no source says this "
                             "is an inconsistency)" % (pl["issuedAt"], ctx["block_time"]))
            if not tx:
                notes.append("OR2: privacy-minimal receipt (no transaction, OR 5.2): it names the payer and the "
                             "resource, not this settlement")
            member["receipt"] = {"format": info["format"], "alg": info["alg"], "kid": info["kid"],
                                 "signer": info["signer"], "issued_at": pl["issuedAt"], "transaction": tx or None}
    # OR3 who signed, per artifact verified above
    if verified:
        rs = [_authorized(i, ctx["pay_to"], i["payload"]["resourceUrl"], evm, trust, ctx.get("family")) for i in verified]
        res["OR3"] = next((x for x in rs if x.startswith("failed")), None) or \
            next((x for x in rs if x.startswith("not_evaluated")), "verified")
        if res["OR3"].startswith("not_evaluated"):
            notes.append("OR3: a valid signature is not authorization (OR 4.5.1); the signer is not the payTo and no "
                         "signer_trust names it")
    else:
        res["OR3"] = "not_evaluated:no_verified_artifact"
    return res, notes, member
