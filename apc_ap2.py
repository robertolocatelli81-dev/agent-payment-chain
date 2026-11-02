"""agent-payment-chain, AP2 Payment Mandate -> x402 exact/EIP-3009 binding (SPEC 0.7, section 9; census G1).
An independent offline evaluator of the Pulse AP2-x402 conformance profile (shibutatsu/pulse-ap2-x402-conformance,
fixture format ap2-x402-conformance/0.3, read at e06a6cbf): it derives the decision and the failure codes from the
signed artifacts and never reads a case's `expected`. Standard library only: ES256 (ECDSA P-256, FIPS 186-5, written
here), SD-JWT disclosures (RFC 9901 shape as the profile uses it), RFC 8785 canonical JSON, and the EIP-712 recovery of
x402-signature-vectors (APC_SIGLIB) for the EIP-3009 signature.

  python3 apc_ap2.py CASES.json      -> one line per case: id, consistent, failure codes; exit 0 when every case's
                                        computed result equals its recorded expectation (the comparison is made after
                                        the evaluation, from the file, as the profile's bundle check does)
"""
import base64
import hashlib
import json
import math
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_siglib  # noqa: E402
apc_siglib.guard("apc_ap2", __name__ == "__main__")  # SPEC 32.11 (c), 32.12 (f): without the library one line, exit 64, no traceback
from apc_block import keccak256  # noqa: E402,F401  (counted inside a verification, SPEC 29.2; apc_block loads the library of SPEC 32.12)
from lib.eip712 import signing_digest  # noqa: E402
from lib.secp256k1 import public_key_to_address, recover_public_key  # noqa: E402

CODES = (   # the profile's failure codes, in its report order (src/failures.ts)
    "INPUT_SCHEMA_INVALID", "INPUT_HASH_MISMATCH", "AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID", "AP2_CLOSED_MANDATE_UNVERIFIED",
    "AP2_OPEN_MANDATE_UNVERIFIED", "AP2_KEY_BINDING_UNVERIFIED", "AP2_CHECKOUT_BINDING_UNVERIFIED",
    "AP2_RECEIPT_UNVERIFIED", "AP2_CLOSED_MANDATE_REFERENCE_MISMATCH", "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
    "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH", "AP2_PAYMENT_REFERENCE_MISMATCH", "AP2_CLOSED_TRANSACTION_ID_MISMATCH",
    "AP2_CONSTRAINT_VIOLATION", "AP2_UNSUPPORTED_CONSTRAINT", "AP2_OPEN_PRESET_MISMATCH",
    "AP2_VERIFICATION_CONTEXT_MISMATCH", "AP2_MANDATE_TIME_INVALID", "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED",
    "AP2_RECEIPT_NOT_SUCCESSFUL", "AP2_RECEIPT_REFERENCE_MISMATCH", "AP2_RECEIPT_TRANSACTION_MISMATCH",
    "AP2_X402_SCHEME_MISMATCH", "AP2_X402_NETWORK_MISMATCH", "AP2_X402_ASSET_MISMATCH", "AP2_X402_AMOUNT_MISMATCH",
    "AP2_X402_PAYEE_MISMATCH", "AP2_X402_COMMERCE_BINDING_MISMATCH", "AP2_X402_TIMEOUT_MISMATCH",
    "AP2_X402_EIP712_DOMAIN_MISMATCH", "X402_MANDATE_REFERENCE_MISMATCH", "X402_ACCEPTED_REQUIREMENTS_MISMATCH",
    "X402_UNSUPPORTED_EXTENSION", "EIP3009_PAYER_MISMATCH", "EIP3009_RECIPIENT_MISMATCH", "EIP3009_VALUE_MISMATCH",
    "EIP3009_VALID_AFTER_IN_FUTURE", "EIP3009_VALID_BEFORE_EXPIRED", "EIP3009_VALIDITY_EXCEEDS_TIMEOUT",
    "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY", "EIP3009_NONCE_BINDING_MISMATCH", "EIP3009_SIGNATURE_INVALID",
    "SETTLEMENT_FAILED", "SETTLEMENT_NETWORK_MISMATCH", "SETTLEMENT_PAYER_MISMATCH", "SETTLEMENT_AMOUNT_MISMATCH",
    "SETTLEMENT_TRANSACTION_INVALID")
SAFE = 2 ** 53 - 1
SECP_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
UNSAFE_KEYS = {"__proto__", "prototype", "constructor"}


# ------------------------------------------------------------------ ECDSA P-256 (FIPS 186-5, SEC 2 secp256r1)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def p256_on_curve(pt):
    x, y = pt
    return 0 <= x < P256_P and 0 <= y < P256_P and (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def _jadd(p, q):
    """Jacobian addition on y^2 = x^3 - 3x + b; None is the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1, z2z2 = z1 * z1 % P256_P, z2 * z2 % P256_P
    u1, u2 = x1 * z2z2 % P256_P, x2 * z1z1 % P256_P
    s1, s2 = y1 * z2 * z2z2 % P256_P, y2 * z1 * z1z1 % P256_P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else None
    h, r = (u2 - u1) % P256_P, (s2 - s1) % P256_P
    hh = h * h % P256_P
    hhh = h * hh % P256_P
    v = u1 * hh % P256_P
    x3 = (r * r - hhh - 2 * v) % P256_P
    return x3, (r * (v - x3) - s1 * hhh) % P256_P, h * z1 * z2 % P256_P


def _jdouble(p):
    if p is None or p[1] == 0:
        return None
    x, y, z = p
    zz = z * z % P256_P
    m = 3 * (x - zz) * (x + zz) % P256_P                    # a = -3
    yy = y * y % P256_P
    s = 4 * x * yy % P256_P
    x3 = (m * m - 2 * s) % P256_P
    return x3, (m * (s - x3) - 8 * yy * yy) % P256_P, 2 * y * z % P256_P


def _jmul(k, pt):
    acc, add = None, (pt[0], pt[1], 1)
    while k:
        if k & 1:
            acc = _jadd(acc, add)
        add = _jdouble(add)
        k >>= 1
    return acc


def _affine_x(p):
    if p is None:
        return None
    return p[0] * pow(p[2] * p[2], -1, P256_P) % P256_P


def es256_verify(pub, msg, sig):
    """ECDSA P-256 with SHA-256 over msg; sig = r || s (64 bytes, JWS RFC 7518 3.4). pub = (x, y) on the curve."""
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, P256_N)
    x = _affine_x(_jadd(_jmul(e * w % P256_N, P256_G), _jmul(r * w % P256_N, pub)))
    return x is not None and x % P256_N == r


# ------------------------------------------------------------------ RFC 8785 canonical JSON
def _num(v):
    if isinstance(v, bool):
        raise TypeError("bool")
    if isinstance(v, int):
        return str(v)
    if not math.isfinite(v):
        raise TypeError("a non-finite number")
    if v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    r = repr(v)                                                  # shortest round-trip digits, as ECMAScript
    if "e" in r:
        mant, ex = r.split("e")
        r = "%se%s%d" % (mant, "+" if int(ex) > 0 else "-", abs(int(ex)))
    return r


def canonical(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):                                      # member names ordered by UTF-16 code units
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k])
                              for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise TypeError("not a JSON value")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s):
    """canonical unpadded base64url (the encoding of the decoded bytes is s again), else ValueError"""
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(b) != s:
        raise ValueError("not canonical base64url")
    return b


def sha_b64u(text, alg="sha256"):
    return b64u(hashlib.new(alg, text.encode("ascii") if isinstance(text, str) else text).digest())


def canon_sha(v):
    return b64u(hashlib.sha256(canonical(v).encode("utf-8")).digest())


def canon_eq(a, b):
    try:
        return canonical(a) == canonical(b)
    except TypeError:
        return False


# ------------------------------------------------------------------ the profile's closed schema (src/types.ts)
class SchemaError(Exception):
    pass


def _need(cond, what):
    if not cond:
        raise SchemaError(what)


def _strict(v, path, req, opt=()):
    _need(isinstance(v, dict), path + ": not an object")
    _need(not set(v) - set(req) - set(opt), "%s: unknown keys %s" % (path, sorted(set(v) - set(req) - set(opt))))
    _need(not set(req) - set(v), "%s: missing %s" % (path, sorted(set(req) - set(v))))
    return v


def _is_int(v):
    return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())


def _int(v, path, lo=None, hi=None, safe=False):
    _need(_is_int(v), path + ": not an integer")
    _need((lo is None or v >= lo) and (hi is None or v <= hi), path + ": out of range")
    _need(not safe or abs(v) <= SAFE, path + ": not a safe integer")


def _s(v, path, rx=None, min1=True):
    _need(isinstance(v, str) and (not min1 or v), path + ": not a string")
    _need(rx is None or re.fullmatch(rx, v) is not None, path + ": format")


ADDR, B32, SIG, UINT = r"0x[0-9a-fA-F]{40}", r"0x[0-9a-fA-F]{64}", r"0x[0-9a-fA-F]{130}", r"(0|[1-9][0-9]*)"
# The profile's date-time: src/types.ts z.string().datetime({ offset: true }), zod 4.4.3 (package.json), whose regex
# (v4/core/regexes.js dateSource/timeSource/datetime) is copied here with ASCII digits: calendar dates only, hour
# 00-23, seconds optional, any number of fraction digits, Z or an offset of hour 00-23.
DT = (r"(?:(?:[0-9][0-9][2468][048]|[0-9][0-9][13579][26]|[0-9][0-9]0[48]|[02468][048]00|[13579][26]00)-02-29|"
      r"[0-9]{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)|"
      r"02-(?:0[1-9]|1[0-9]|2[0-8])))"
      r"T(?:[01][0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9](?:\.[0-9]+)?)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])")


def _b64sha(v, path):
    _s(v, path, r"[A-Za-z0-9_-]{43}")
    try:
        _need(len(b64u_decode(v)) == 32, path + ": not 32 bytes")
    except ValueError:
        raise SchemaError(path + ": not canonical base64url")


def _caip2(v, path):
    _s(v, path)
    m = re.fullmatch(r"eip155:([1-9][0-9]*)", v)
    _need(m is not None and len(m.group(1)) <= 16 and int(m.group(1)) <= SAFE, path + ": not a safe eip155 CAIP-2 id")


def _iso(s):
    """A date-time of DT -> milliseconds since 1970 as the profile reads it (Date.parse: the fraction cut after 3 digits,
    the year 0000 included); computed here, not by datetime.fromisoformat, whose reach changes with the Python version."""
    if not isinstance(s, str) or re.fullmatch(DT, s) is None:
        raise ValueError("not a date-time")
    m = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?"
                     r"(?:Z|([+-])([0-9]{2}):([0-9]{2}))", s)
    y, mo, d, hh, mi = (int(m.group(k)) for k in range(1, 6))
    sec, ms = int(m.group(6) or 0), int(((m.group(7) or "") + "000")[:3])
    y -= mo <= 2                                         # days from 1970-01-01 (proleptic Gregorian, H. Hinnant)
    era = y // 400
    doy = (153 * (mo + (-3 if mo > 2 else 9)) + 2) // 5 + d - 1
    days = era * 146097 + (y - era * 400) * 365 + (y - era * 400) // 4 - (y - era * 400) // 100 + doy - 719468
    off = 0 if m.group(8) is None else (1 if m.group(8) == "+" else -1) * (int(m.group(9)) * 60 + int(m.group(10)))
    return (((days * 24 + hh) * 60 + mi - off) * 60 + sec) * 1000 + ms


def _datetime(v, path):
    _s(v, path, DT)
    try:
        _iso(v)
    except ValueError:
        raise SchemaError(path + ": not a date-time")


def _url(v, path):
    _s(v, path)
    try:
        u = urlsplit(v)
    except ValueError:                                  # e.g. "http://[bad" (an unparsable host)
        raise SchemaError(path + ": not a URL")
    _need(bool(u.scheme) and bool(u.netloc or u.path), path + ": not a URL")


def _json_value(v, path):
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, float):
            _need(math.isfinite(x), path + ": a non-finite number")
        else:
            _need(x is None or isinstance(x, (str, int, bool)), path + ": not JSON")


def _amount(v, path):
    _strict(v, path, ("amount", "currency"))
    _int(v["amount"], path + ".amount", 0, safe=True)
    _s(v["currency"], path + ".currency", r"[A-Z]{3}")


def _jwk(v, path):
    _strict(v, path, ("kty", "crv", "alg", "kid", "x", "y"))
    _need(v["kty"] == "EC" and v["crv"] == "P-256" and v["alg"] == "ES256", path + ": not a P-256 ES256 key")
    _s(v["kid"], path + ".kid")
    _s(v["x"], path + ".x", r"[A-Za-z0-9_-]{43}")
    _s(v["y"], path + ".y", r"[A-Za-z0-9_-]{43}")


def _merchant(v, path):
    _strict(v, path, ("id", "name"), ("website",))
    _s(v["id"], path + ".id")
    _s(v["name"], path + ".name")
    if "website" in v:
        _url(v["website"], path + ".website")


def _pisp(v, path):
    _strict(v, path, ("legal_name", "brand_name", "domain_name"))
    for k in v:
        _s(v[k], path + "." + k)


def _instrument(v, path):
    _strict(v, path, ("id", "type", "x402"), ("description",))
    _s(v["id"], path + ".id")
    _need(v["type"] == "x402", path + ".type")
    if "description" in v:
        _s(v["description"], path + ".description", min1=False)
    x = _strict(v["x402"], path + ".x402", ("version", "scheme", "network", "asset", "amount", "payTo", "payer",
                                            "ap2PayeeId", "ap2PaymentAmount", "maxTimeoutSeconds", "eip712Domain",
                                            "nonceBinding"))
    _need(x["version"] == 2 and _is_int(x["version"]) and x["scheme"] == "exact", path + ".x402 version/scheme")
    _caip2(x["network"], path + ".x402.network")
    for k in ("asset", "payTo", "payer"):
        _s(x[k], path + ".x402." + k, ADDR)
    _s(x["amount"], path + ".x402.amount", UINT)
    _s(x["ap2PayeeId"], path + ".x402.ap2PayeeId")
    _amount(x["ap2PaymentAmount"], path + ".x402.ap2PaymentAmount")
    _int(x["maxTimeoutSeconds"], path + ".x402.maxTimeoutSeconds", 1, safe=True)
    d = _strict(x["eip712Domain"], path + ".x402.eip712Domain", ("name", "version"))
    _s(d["name"], path + "..name")
    _s(d["version"], path + "..version")
    _need(x["nonceBinding"] == "base64url-decode-ap2-mandate-reference", path + ".x402.nonceBinding")


def _closed(v, path):
    _strict(v, path, ("vct", "transaction_id", "payee", "payment_amount", "payment_instrument", "iat", "exp"),
            ("pisp", "execution_date", "risk_data"))
    _need(v["vct"] == "mandate.payment.1", path + ".vct")
    _b64sha(v["transaction_id"], path + ".transaction_id")
    _merchant(v["payee"], path + ".payee")
    _amount(v["payment_amount"], path + ".payment_amount")
    _instrument(v["payment_instrument"], path + ".payment_instrument")
    if "pisp" in v:
        _pisp(v["pisp"], path + ".pisp")
    if "execution_date" in v:
        _datetime(v["execution_date"], path + ".execution_date")
    if "risk_data" in v:
        _need(isinstance(v["risk_data"], dict), path + ".risk_data")
        _json_value(v["risk_data"], path + ".risk_data")
    _int(v["iat"], path + ".iat", 0)
    _int(v["exp"], path + ".exp", 1)


AGENT_FREQ = {"ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"}


def _constraint(c, path):
    def ok(fn):
        try:
            fn()
            return True
        except SchemaError:
            return False

    def reference():
        _strict(c, path, ("type", "conditional_transaction_id"))
        _need(c["type"] == "payment.reference", "t")
        _b64sha(c["conditional_transaction_id"], path)

    def instruments():
        _strict(c, path, ("type", "allowed"))
        _need(c["type"] == "payment.allowed_payment_instruments", "t")
        _need(isinstance(c["allowed"], list) and c["allowed"], "allowed")
        for a in c["allowed"]:
            _strict(a, path, ("id", "type"), ("description", "x402"))
            _s(a["id"], path)
            _s(a["type"], path)
            if "description" in a:
                _s(a["description"], path, min1=False)
            if "x402" in a:
                _json_value(a["x402"], path)

    def amount_range():
        _strict(c, path, ("type", "currency", "max"), ("min",))
        _need(c["type"] == "payment.amount_range", "t")
        _s(c["currency"], path, r"[A-Z]{3}")
        _int(c["max"], path, 0, safe=True)
        if "min" in c:
            _int(c["min"], path, 0, safe=True)

    def payees():
        _strict(c, path, ("type", "allowed"))
        _need(c["type"] == "payment.allowed_payees", "t")
        _need(isinstance(c["allowed"], list) and c["allowed"], "allowed")
        for m in c["allowed"]:
            _merchant(m, path)

    def unsupported():
        t = c.get("type") if isinstance(c, dict) else None
        if t == "payment.agent_recurrence":
            _strict(c, path, ("type", "frequency"), ("max_occurrences",))
            _need(isinstance(c["frequency"], str) and c["frequency"] in AGENT_FREQ, "frequency")
            if "max_occurrences" in c:
                _int(c["max_occurrences"], path, 0)
        elif t == "payment.allowed_pisps":
            _strict(c, path, ("type", "allowed"))
            _need(isinstance(c["allowed"], list) and c["allowed"], "allowed")
            for x in c["allowed"]:
                _pisp(x, path)
        elif t == "payment.budget":
            _strict(c, path, ("type", "max", "currency"))
            _need(isinstance(c["max"], (int, float)) and not isinstance(c["max"], bool) and c["max"] >= 0, "max")
            _s(c["currency"], path, r"[A-Z]{3}")
        elif t == "payment.execution_date":
            _strict(c, path, ("type",), ("not_before", "not_after"))
            for k in ("not_before", "not_after"):
                if k in c:
                    _datetime(c[k], path)
            if "not_before" in c and "not_after" in c:
                _need(_ts(c["not_before"]) <= _ts(c["not_after"]), "not_after before not_before")
        else:
            raise SchemaError(path + ": unknown constraint type")
    _need(any(ok(f) for f in (reference, instruments, amount_range, payees, unsupported)), path + ": no constraint form")


def _open(v, path):
    _strict(v, path, ("vct", "constraints", "cnf", "iat", "exp"),
            ("payee", "payment_amount", "payment_instrument", "execution_date", "pisp", "risk_data"))
    _need(v["vct"] == "mandate.payment.open.1", path + ".vct")
    _need(isinstance(v["constraints"], list) and v["constraints"], path + ".constraints")
    for i, c in enumerate(v["constraints"]):
        _constraint(c, "%s.constraints.%d" % (path, i))
    _jwk(_strict(v["cnf"], path + ".cnf", ("jwk",))["jwk"], path + ".cnf.jwk")
    if "payee" in v:
        _merchant(v["payee"], path + ".payee")
    if "payment_amount" in v:
        _amount(v["payment_amount"], path + ".payment_amount")
    if "payment_instrument" in v:
        _instrument(v["payment_instrument"], path + ".payment_instrument")
    if "execution_date" in v:
        _datetime(v["execution_date"], path + ".execution_date")
    if "pisp" in v:
        _pisp(v["pisp"], path + ".pisp")
    if "risk_data" in v:
        _need(isinstance(v["risk_data"], dict), path + ".risk_data")
        _json_value(v["risk_data"], path + ".risk_data")
    _int(v["iat"], path + ".iat", 0)
    _int(v["exp"], path + ".exp", 1)
    _need(any(c.get("type") == "payment.reference" for c in v["constraints"]), path + ": no payment.reference")


def _receipt(v, path):
    _need(isinstance(v, dict) and v.get("status") in ("Success", "Error"), path + ".status")
    if v["status"] == "Success":
        _strict(v, path, ("status", "iss", "iat", "reference", "payment_id", "psp_confirmation_id",
                          "network_confirmation_id"), ("error", "error_description"))
        _s(v["psp_confirmation_id"], path)
        _s(v["network_confirmation_id"], path, B32)
        _need(v.get("error") is None and v.get("error_description") is None, path + ": error on success")
    else:
        _strict(v, path, ("status", "iss", "iat", "reference", "payment_id", "error", "error_description"),
                ("psp_confirmation_id", "network_confirmation_id"))
        _s(v["error"], path)
        _s(v["error_description"], path)
        _need(v.get("psp_confirmation_id") is None and v.get("network_confirmation_id") is None, path)
    _s(v["iss"], path + ".iss")
    _int(v["iat"], path + ".iat", 0)
    _b64sha(v["reference"], path + ".reference")
    _s(v["payment_id"], path + ".payment_id")


def _requirements(v, path):
    _strict(v, path, ("scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"))
    _s(v["scheme"], path + ".scheme")
    _caip2(v["network"], path + ".network")
    _s(v["asset"], path + ".asset", ADDR)
    _s(v["amount"], path + ".amount", UINT)
    _s(v["payTo"], path + ".payTo", ADDR)
    _int(v["maxTimeoutSeconds"], path + ".maxTimeoutSeconds", 1, safe=True)
    e = _strict(v["extra"], path + ".extra", ("name", "version", "assetTransferMethod", "ap2MandateReference",
                                             "ap2NonceDerivation"))
    _s(e["name"], path + ".extra.name")
    _s(e["version"], path + ".extra.version")
    _need(e["assetTransferMethod"] == "eip3009", path + ".extra.assetTransferMethod")
    _b64sha(e["ap2MandateReference"], path + ".extra.ap2MandateReference")
    _need(e["ap2NonceDerivation"] == "base64url-decode-ap2-mandate-reference", path + ".extra.ap2NonceDerivation")


PRINTABLE = r"[\x20-\x7e]+"


def _x402(v, path):
    _strict(v, path, ("requirements", "payload", "settlement"))
    _requirements(v["requirements"], path + ".requirements")
    p = _strict(v["payload"], path + ".payload", ("x402Version", "resource", "accepted", "payload"), ("extensions",))
    _need(p["x402Version"] == 2 and _is_int(p["x402Version"]), path + ".payload.x402Version")
    r = _strict(p["resource"], path + ".payload.resource", ("url",),
                ("description", "mimeType", "serviceName", "tags", "iconUrl"))
    _s(r["url"], path + ".payload.resource.url")
    for k in ("description", "mimeType"):
        if r.get(k) is not None:
            _s(r[k], path, min1=False)
    if r.get("serviceName") is not None:
        _s(r["serviceName"], path, PRINTABLE)
        _need(len(r["serviceName"]) <= 32, path + ".serviceName")
    if r.get("tags") is not None:
        _need(isinstance(r["tags"], list) and len(r["tags"]) <= 5, path + ".tags")
        for t in r["tags"]:
            _s(t, path, PRINTABLE)
            _need(len(t) <= 32, path + ".tags")
    if r.get("iconUrl") is not None:
        _s(r["iconUrl"], path, min1=False)
        _need(len(r["iconUrl"]) <= 2048, path + ".iconUrl")
    _requirements(p["accepted"], path + ".payload.accepted")
    a = _strict(p["payload"], path + ".payload.payload", ("signature", "authorization"))
    _s(a["signature"], path + ".payload.payload.signature", SIG)
    au = _strict(a["authorization"], path + ".payload.payload.authorization",
                 ("from", "to", "value", "validAfter", "validBefore", "nonce"))
    _s(au["from"], path, ADDR)
    _s(au["to"], path, ADDR)
    for k in ("value", "validAfter", "validBefore"):
        _s(au[k], path, UINT)
    _s(au["nonce"], path, B32)
    if "extensions" in p:
        _need(isinstance(p["extensions"], dict), path + ".payload.extensions")
        _json_value(p["extensions"], path)
    st = _strict(v["settlement"], path + ".settlement", ("success", "payer", "transaction", "network"),
                 ("errorReason", "errorMessage", "amount", "extensions", "extra"))
    _need(isinstance(st["success"], bool), path + ".settlement.success")
    for k in ("errorReason", "errorMessage"):
        if k in st:
            _s(st[k], path, min1=False)
    _s(st["payer"], path + ".settlement.payer", ADDR)
    _need(isinstance(st["transaction"], str), path + ".settlement.transaction")
    _caip2(st["network"], path + ".settlement.network")
    if "amount" in st:
        _s(st["amount"], path + ".settlement.amount", UINT)
    for k in ("extensions", "extra"):
        if k in st:
            _need(isinstance(st[k], dict), path + "." + k)
            _json_value(st[k], path)


PINS = {"ap2-x402-conformance/0.1": ("67b1ba0a7abbd7907a28fa624670872532e0eae9", "2.19.0"),
        "ap2-x402-conformance/0.2": ("c8247c4cd15f29498474404d94636e7dbb894e86", "2.22.0"),
        "ap2-x402-conformance/0.3": ("17d319fab5c17a6b4873eb41197894db924f59ed", "2.23.0")}
AP2_PIN = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"


def check_schema(c):
    _need(isinstance(c, dict) and isinstance(c.get("caseVersion"), str) and c["caseVersion"] in PINS, "caseVersion")
    _strict(c, "<root>", ("caseVersion", "sourcePins", "id", "description", "nowEpochSeconds", "ap2", "x402",
                          "inputHash", "expected"))
    sp = _strict(c["sourcePins"], "sourcePins", ("ap2Commit", "x402Commit", "x402PackageVersion"))
    _need((sp["ap2Commit"], sp["x402Commit"], sp["x402PackageVersion"]) == (AP2_PIN,) + PINS[c["caseVersion"]],
          "sourcePins")
    _s(c["id"], "id", r"[a-z0-9][a-z0-9-]*")
    _s(c["description"], "description")
    _int(c["nowEpochSeconds"], "nowEpochSeconds", 1)
    ap2 = _strict(c["ap2"], "ap2", ("closedMandate", "openMandate", "paymentReceipt", "verification"))
    _closed(ap2["closedMandate"], "ap2.closedMandate")
    _open(ap2["openMandate"], "ap2.openMandate")
    _receipt(ap2["paymentReceipt"], "ap2.paymentReceipt")
    v = _strict(ap2["verification"], "ap2.verification", ("verifier", "verifiedAtEpochSeconds", "clockSkewSeconds",
                                                          "openCheckoutReference", "closedMandateClaimsHash",
                                                          "openMandateClaimsHash", "closedMandateReference",
                                                          "cryptographicEvidence"))
    _s(v["verifier"], "verifier")
    _int(v["verifiedAtEpochSeconds"], "verifiedAtEpochSeconds", 1)
    _int(v["clockSkewSeconds"], "clockSkewSeconds", 0, 300)
    for k in ("openCheckoutReference", "closedMandateClaimsHash", "openMandateClaimsHash", "closedMandateReference"):
        _b64sha(v[k], "ap2.verification." + k)
    ev = _strict(v["cryptographicEvidence"], "cryptographicEvidence",
                 ("mandateChain", "paymentReceiptJwt", "trustedRootPublicJwk", "trustedReceiptPublicJwk",
                  "expectedAudience", "expectedNonce"))
    for k in ("mandateChain", "paymentReceiptJwt", "expectedAudience", "expectedNonce"):
        _s(ev[k], k)
    _jwk(ev["trustedRootPublicJwk"], "trustedRootPublicJwk")
    _jwk(ev["trustedReceiptPublicJwk"], "trustedReceiptPublicJwk")
    _x402(c["x402"], "x402")
    _b64sha(c["inputHash"], "inputHash")
    e = _strict(c["expected"], "expected", ("consistent", "failureCodes"))
    _need(isinstance(e["consistent"], bool) and isinstance(e["failureCodes"], list)
          and all(x in CODES for x in e["failureCodes"]), "expected")


def _ts(s):
    return _iso(s)                      # milliseconds, compared only with each other


# ------------------------------------------------------------------ AP2 mandate chain and receipt (src/ap2-crypto.ts)
class CryptoFail(Exception):
    def __init__(self, stage, code):
        super().__init__("%s %s" % (stage, code))
        self.stage, self.code = stage, code


def _rec(v):
    return isinstance(v, dict)


def _safe_int(v):
    return _is_int(v) and abs(v) <= SAFE


def _parse_sd(seg, stage):
    seg = seg if seg.endswith("~") else seg + "~"
    parts = seg.split("~")
    iss, disc = parts[0], parts[1:-1]
    if parts[-1] != "" or len(iss.split(".")) != 3 or any(d == "" for d in disc):
        raise CryptoFail(stage, "DISCLOSURE_INVALID")
    return {"jwt": iss, "disc": disc, "sd": iss + "~" + "~".join(disc) + ("~" if disc else "")}


def _jwk_key(jwk, stage):
    if not _rec(jwk) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not isinstance(jwk.get("x"), str) \
            or not isinstance(jwk.get("y"), str) or "d" in jwk or ("alg" in jwk and jwk["alg"] != "ES256"):
        raise CryptoFail(stage, "JWK_INVALID")
    try:
        x, y = (b64u_decode(jwk[k]) for k in ("x", "y"))
    except ValueError:
        raise CryptoFail(stage, "JWK_INVALID")
    pt = (int.from_bytes(x, "big"), int.from_bytes(y, "big"))
    if len(x) != 32 or len(y) != 32 or not p256_on_curve(pt):
        raise CryptoFail(stage, "JWK_INVALID")
    return pt


MAX_JSON_DEPTH = 64         # SPEC 29.1 (apc_verify.MAX_JSON_DEPTH): every JSON text read, the embedded ones too


def _json(text):
    """json.loads with the nesting bound of SPEC 29.1: deeper (or past the parser's own recursion) is a ValueError,
    which the callers turn into their failure code, never an exception out of the evaluator"""
    try:
        v = json.loads(text)
    except RecursionError:
        raise ValueError("JSON nested too deep")
    stack = [(v, 0)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, (dict, list)):
            if d >= MAX_JSON_DEPTH:
                raise ValueError("JSON nested deeper than %d" % MAX_JSON_DEPTH)
            stack.extend((y, d + 1) for y in (x.values() if isinstance(x, dict) else x))
    return v


def _verify_jws(jwt, key, stage):
    """compact JWS with ES256 -> (protected header, payload object)"""
    try:
        h64, p64, s64 = jwt.split(".")
        header = _json(b64u_decode(h64))
        sig = b64u_decode(s64)
        payload_bytes = b64u_decode(p64)
    except (ValueError, UnicodeDecodeError):
        raise CryptoFail(stage, "SIGNATURE_INVALID")
    if not _rec(header) or header.get("alg") != "ES256" or "crit" in header or header.get("b64", True) is not True \
            or not es256_verify(key, (h64 + "." + p64).encode("ascii"), sig):
        raise CryptoFail(stage, "SIGNATURE_INVALID")
    try:
        payload = _json(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise CryptoFail(stage, "SIGNATURE_INVALID")
    if not _rec(payload):
        raise CryptoFail(stage, "SIGNATURE_INVALID")
    return header, payload


def _sd_alg(claim, stage):
    name = "sha-256" if claim is None else claim
    if not isinstance(name, str):
        raise CryptoFail(stage, "DISCLOSURE_INVALID")
    alg = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}.get(name)
    if alg is None:
        raise CryptoFail(stage, "DISCLOSURE_INVALID")
    return alg


def _decode_disclosure(enc, stage):
    try:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", enc) or len(enc) % 4 == 1:
            raise ValueError
        d = _json(b64u_decode(enc).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise CryptoFail(stage, "DISCLOSURE_INVALID")
    if not isinstance(d, list) or len(d) not in (2, 3) or not isinstance(d[0], str) \
            or (len(d) == 3 and not isinstance(d[1], str)):
        raise CryptoFail(stage, "DISCLOSURE_INVALID")
    return d


def _resolve_disclosures(env, tok, stage):
    alg = _sd_alg(env.get("_sd_alg"), stage)
    by = {}
    for enc in tok["disc"]:
        d = _decode_disclosure(enc, stage)
        dig = sha_b64u(enc, alg)
        if dig in by:
            raise CryptoFail(stage, "DISCLOSURE_INVALID")
        by[dig] = d
    used, resolving = set(), set()

    def digest(dg, n, depth):
        d = by.get(dg)
        if d is None or len(d) != n:
            raise CryptoFail(stage, "DISCLOSURE_INVALID")
        if dg in resolving:
            raise CryptoFail(stage, "DISCLOSURE_INVALID")
        used.add(dg)
        resolving.add(dg)
        try:
            return value(d[1], False, depth) if n == 2 else (d[1], value(d[2], False, depth))
        finally:
            resolving.discard(dg)

    def value(v, allow_digest, depth=0):
        if depth > MAX_JSON_DEPTH:              # SPEC 29.1: the resolved claims nest at most as deep as one JSON text
            raise CryptoFail(stage, "DISCLOSURE_INVALID")
        depth += 1
        if allow_digest and isinstance(v, str) and v in by:
            return digest(v, 2, depth)
        if isinstance(v, list):
            return [value(x, allow_digest, depth) for x in v]
        if not _rec(v):
            return v
        if len(v) == 1 and isinstance(v.get("..."), str):
            return dict(v) if v["..."] not in by else digest(v["..."], 2, depth)
        out = {}
        for k, child in v.items():
            if k == "_sd":
                continue
            if k in UNSAFE_KEYS:
                raise CryptoFail(stage, "DISCLOSURE_INVALID")
            out[k] = value(child, k == "delegate_payload", depth)
        if "_sd" in v:
            sd = v["_sd"]
            if not isinstance(sd, list) or any(not isinstance(x, str) for x in sd):
                raise CryptoFail(stage, "DISCLOSURE_INVALID")
            for dg in sd:
                if dg not in by:
                    continue
                name, val = digest(dg, 3, depth)
                if name in UNSAFE_KEYS or name in out:
                    raise CryptoFail(stage, "DISCLOSURE_INVALID")
                out[name] = val
        return out
    res = value(env, False)
    if not _rec(res) or len(used) != len(by):
        raise CryptoFail(stage, "DISCLOSURE_INVALID")
    return res


def _times(claims, now, skew, stage):
    if "iat" in claims and (not _safe_int(claims["iat"]) or claims["iat"] > now + skew):
        raise CryptoFail(stage, "IAT_INVALID")
    if "exp" in claims and (not _safe_int(claims["exp"]) or now > claims["exp"] + skew):
        raise CryptoFail(stage, "EXP_INVALID")


def _single_payload(env, stage):
    p = env.get("delegate_payload")
    if not isinstance(p, list) or len(p) != 1 or not _rec(p[0]):
        raise CryptoFail(stage, "DELEGATE_PAYLOAD_INVALID")
    return p[0]


def verify_ap2(ev, now, skew, ref):
    """-> (open mandate, closed mandate, receipt, closed-mandate reference); CryptoFail(stage, code) otherwise."""
    chain = ev["mandateChain"]
    for k in ("mandateChain", "paymentReceiptJwt", "expectedAudience", "expectedNonce"):
        if not isinstance(ev[k], str) or not ev[k]:
            raise CryptoFail("input", "CHAIN_MALFORMED")
    if not isinstance(ref, str) or not ref or not _safe_int(now) or now < 0 or not _safe_int(skew) or skew < 0:
        raise CryptoFail("input", "CHAIN_MALFORMED")
    i = chain.find("~~")
    if i <= 0 or i != chain.rfind("~~") or i + 2 >= len(chain):
        raise CryptoFail("input", "CHAIN_MALFORMED")
    root, leaf = _parse_sd(chain[:i], "root-disclosures"), _parse_sd(chain[i + 2:], "leaf-disclosures")
    rk = _jwk_key(ev["trustedRootPublicJwk"], "root-signature")
    rh, renv = _verify_jws(root["jwt"], rk, "root-signature")
    typ = rh.get("typ")
    if typ is not None and (not isinstance(typ, str) or not typ.endswith("+sd-jwt") or typ in ("kb+sd-jwt", "kb-sd-jwt")
                            or typ.endswith("+sd-jwt+kb")):
        raise CryptoFail("root-header", "TYP_INVALID")
    rres = _resolve_disclosures(renv, root, "root-disclosures")
    _times(rres, now, skew, "root-claims")
    opn = _single_payload(rres, "root-claims")
    _times(opn, now, skew, "root-claims")
    if opn.get("vct") != "mandate.payment.open.1" or not isinstance(opn.get("constraints"), list):
        raise CryptoFail("root-claims", "MANDATE_TYPE_INVALID")
    refs = [c for c in opn["constraints"] if _rec(c) and c.get("type") == "payment.reference"]
    if not refs or any(c.get("conditional_transaction_id") != ref for c in refs):
        raise CryptoFail("root-claims", "CHECKOUT_REFERENCE_MISMATCH")
    cnf = opn.get("cnf")
    if not _rec(cnf) or not _rec(cnf.get("jwk")):
        raise CryptoFail("key-binding", "CNF_INVALID")
    hk = _jwk_key(cnf["jwk"], "key-binding")
    lh, lenv = _verify_jws(leaf["jwt"], hk, "leaf-signature")
    if lh.get("typ") not in ("kb+sd-jwt", "kb-sd-jwt"):
        raise CryptoFail("leaf-header", "TYP_INVALID")
    if "issuer_jwt_hash" in lenv or not isinstance(lenv.get("sd_hash"), str):
        raise CryptoFail("leaf-binding", "SD_HASH_INVALID")
    if lenv["sd_hash"] != sha_b64u(root["sd"], _sd_alg(renv.get("_sd_alg"), "leaf-disclosures")):
        raise CryptoFail("leaf-binding", "SD_HASH_INVALID")
    if lenv.get("aud") != ev["expectedAudience"]:
        raise CryptoFail("leaf-binding", "AUD_MISMATCH")
    if lenv.get("nonce") != ev["expectedNonce"]:
        raise CryptoFail("leaf-binding", "NONCE_MISMATCH")
    if "iat" not in lenv:
        raise CryptoFail("leaf-claims", "IAT_INVALID")
    _times(lenv, now, skew, "leaf-claims")
    lres = _resolve_disclosures(lenv, leaf, "leaf-disclosures")
    closed = _single_payload(lres, "leaf-claims")
    _times(closed, now, skew, "leaf-claims")
    pa, pi = closed.get("payment_amount"), closed.get("payment_instrument")
    if closed.get("vct") != "mandate.payment.1" or not isinstance(closed.get("transaction_id"), str) \
            or not closed["transaction_id"] or not _rec(closed.get("payee")) or not _rec(pa) \
            or not _safe_int(pa.get("amount")) or not isinstance(pa.get("currency"), str) or not _rec(pi) \
            or not isinstance(pi.get("id"), str) or not isinstance(pi.get("type"), str) or "cnf" in closed:
        raise CryptoFail("leaf-claims", "MANDATE_TYPE_INVALID")
    if closed["transaction_id"] != ref:
        raise CryptoFail("leaf-claims", "CLOSED_TRANSACTION_ID_MISMATCH")
    cref = sha_b64u(leaf["jwt"])
    kk = _jwk_key(ev["trustedReceiptPublicJwk"], "receipt-signature")
    _, rc = _verify_jws(ev["paymentReceiptJwt"], kk, "receipt-signature")
    _times(rc, now, skew, "receipt-claims")
    common = rc.get("status") in ("Success", "Error") and isinstance(rc.get("iss"), str) and _safe_int(rc.get("iat")) \
        and isinstance(rc.get("reference"), str) and isinstance(rc.get("payment_id"), str) and rc["payment_id"] != ""
    if rc.get("status") == "Success":
        variant = all(isinstance(rc.get(k), str) and rc[k] for k in ("psp_confirmation_id", "network_confirmation_id"))
    else:
        variant = all(isinstance(rc.get(k), str) and rc[k] for k in ("error", "error_description"))
    if not common or not variant:
        raise CryptoFail("receipt-claims", "RECEIPT_CLAIMS_INVALID")
    if rc["reference"] != cref:
        raise CryptoFail("receipt-claims", "RECEIPT_REFERENCE_MISMATCH")
    return opn, closed, rc, cref


def _crypto_code(e):
    if e.code == "CHECKOUT_REFERENCE_MISMATCH":
        return "AP2_CHECKOUT_BINDING_UNVERIFIED"
    if e.code == "CLOSED_TRANSACTION_ID_MISMATCH":
        return "AP2_CLOSED_TRANSACTION_ID_MISMATCH"
    if e.code == "RECEIPT_REFERENCE_MISMATCH":
        return "AP2_RECEIPT_REFERENCE_MISMATCH"
    if e.code in ("AUD_MISMATCH", "NONCE_MISMATCH", "SD_HASH_INVALID", "CNF_INVALID"):
        return "AP2_KEY_BINDING_UNVERIFIED"
    if e.code in ("IAT_INVALID", "EXP_INVALID"):
        return "AP2_RECEIPT_UNVERIFIED" if e.stage.startswith("receipt") else "AP2_MANDATE_TIME_INVALID"
    if e.stage.startswith("root"):
        return "AP2_OPEN_MANDATE_UNVERIFIED"
    if e.stage in ("key-binding", "leaf-binding"):
        return "AP2_KEY_BINDING_UNVERIFIED"
    if e.stage.startswith("leaf"):
        return "AP2_CLOSED_MANDATE_UNVERIFIED"
    if e.stage.startswith("receipt"):
        return "AP2_RECEIPT_UNVERIFIED"
    return "AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID"


# ------------------------------------------------------------------ the case (src/verifier.ts)
def _has_unsafe_key(v):
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            if UNSAFE_KEYS & set(x):
                return True
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return False


def _eq_addr(a, b):
    return str(a).lower() == str(b).lower()


def _big(s):
    """A decimal string (UINT) as an int; more than 78 digits is above uint256 and stays out of int()'s digit limit."""
    return int(s) if len(s) <= 78 else 1 << 256


def _nonce_of(ref):
    b = b64u_decode(ref)
    if len(b) != 32:
        raise ValueError("not 32 bytes")
    return "0x" + b.hex()


def verify_case(c):
    """-> {"consistent": bool, "failureCodes": [...], "computed": {...}}"""
    if _has_unsafe_key(c):
        return {"consistent": False, "failureCodes": ["INPUT_SCHEMA_INVALID"], "computed": {}}
    try:
        check_schema(c)
    except SchemaError as e:
        return {"consistent": False, "failureCodes": ["INPUT_SCHEMA_INVALID"], "computed": {}, "schema": str(e)}
    ap2, x, now = c["ap2"], c["x402"], c["nowEpochSeconds"]
    closed, opn, ver, rcp = ap2["closedMandate"], ap2["openMandate"], ap2["verification"], ap2["paymentReceipt"]
    ins, req = closed["payment_instrument"]["x402"], x["requirements"]
    au, st = x["payload"]["payload"]["authorization"], x["settlement"]
    f = []

    def add(code):
        f.append(code)

    def once(code):
        if code not in f:
            f.append(code)
    input_hash = canon_sha({k: c[k] for k in ("caseVersion", "sourcePins", "nowEpochSeconds", "ap2", "x402")})
    if input_hash != c["inputHash"]:
        add("INPUT_HASH_MISMATCH")
    cref = None
    ev = ver["cryptographicEvidence"]
    try:
        vo, vc, vr, cref = verify_ap2(ev, ver["verifiedAtEpochSeconds"], ver["clockSkewSeconds"],
                                      ver["openCheckoutReference"])
        if not canon_eq(vc, closed):
            add("AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH")
        if not canon_eq(vo, opn):
            add("AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH")
        if not canon_eq(vr, rcp):
            add("AP2_RECEIPT_UNVERIFIED")
        if cref != ver["closedMandateReference"]:
            add("AP2_CLOSED_MANDATE_REFERENCE_MISMATCH")
    except CryptoFail as e:
        once(_crypto_code(e))
    except (ValueError, TypeError, KeyError, AttributeError):
        once("AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID")
    ref = cref if cref is not None else ver["closedMandateReference"]
    nonce = _nonce_of(ref)
    va = ver["verifiedAtEpochSeconds"]
    if va < now:
        add("AP2_VERIFICATION_CONTEXT_MISMATCH")
    sk = ver["clockSkewSeconds"]
    if opn["iat"] > va + sk or closed["iat"] > va + sk or opn["exp"] < va - sk or closed["exp"] < va - sk:
        once("AP2_MANDATE_TIME_INVALID")
    if canon_sha(closed) != ver["closedMandateClaimsHash"]:
        once("AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH")
    if canon_sha(opn) != ver["openMandateClaimsHash"]:
        once("AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH")
    # open-mandate constraints
    ci = closed["payment_instrument"]
    n_instr = 0
    for k in opn["constraints"]:
        t = k["type"]
        if t == "payment.reference":
            if k["conditional_transaction_id"] != ver["openCheckoutReference"]:
                once("AP2_PAYMENT_REFERENCE_MISMATCH")
        elif t == "payment.allowed_payment_instruments":
            n_instr += 1
            if not any(a["id"] == ci["id"] and a["type"] == ci["type"] and "x402" in a and canon_eq(a["x402"], ci["x402"])
                       for a in k["allowed"]):
                once("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED")
        elif t == "payment.amount_range":
            am = closed["payment_amount"]
            if am["currency"] != k["currency"] or am["amount"] > k["max"] or ("min" in k and am["amount"] < k["min"]):
                once("AP2_CONSTRAINT_VIOLATION")
        elif t == "payment.allowed_payees":
            if not any(m["id"] == closed["payee"]["id"] for m in k["allowed"]):
                once("AP2_CONSTRAINT_VIOLATION")
        elif t == "payment.execution_date":
            ed = closed.get("execution_date")
            et = _ts(ed) if ed else None
            if et is None or ("not_before" in k and et < _ts(k["not_before"])) \
                    or ("not_after" in k and et > _ts(k["not_after"])):
                once("AP2_CONSTRAINT_VIOLATION")
        elif t in ("payment.agent_recurrence", "payment.allowed_pisps", "payment.budget"):
            once("AP2_UNSUPPORTED_CONSTRAINT")
    if n_instr == 0:
        once("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED")
    if ("payee" in opn and not canon_eq(opn["payee"], closed["payee"])) \
            or ("payment_amount" in opn and not canon_eq(opn["payment_amount"], closed["payment_amount"])) \
            or ("payment_instrument" in opn and not canon_eq(opn["payment_instrument"], ci)) \
            or ("execution_date" in opn and opn["execution_date"] != closed.get("execution_date")):
        once("AP2_OPEN_PRESET_MISMATCH")
    if "pisp" in opn or "risk_data" in opn:
        once("AP2_UNSUPPORTED_CONSTRAINT")
    if "pisp" in closed or "risk_data" in closed:
        once("AP2_UNSUPPORTED_CONSTRAINT")
    if closed["transaction_id"] != ver["openCheckoutReference"]:
        once("AP2_CLOSED_TRANSACTION_ID_MISMATCH")
    if rcp["status"] != "Success":
        add("AP2_RECEIPT_NOT_SUCCESSFUL")
    if ref != rcp["reference"]:
        once("AP2_RECEIPT_REFERENCE_MISMATCH")
    if ins["ap2PayeeId"] != closed["payee"]["id"] or not canon_eq(ins["ap2PaymentAmount"], closed["payment_amount"]):
        add("AP2_X402_COMMERCE_BINDING_MISMATCH")
    if rcp["status"] == "Success" and str(st["transaction"]).lower() != str(rcp["network_confirmation_id"]).lower():
        add("AP2_RECEIPT_TRANSACTION_MISMATCH")
    if ins["scheme"] != req["scheme"]:
        add("AP2_X402_SCHEME_MISMATCH")
    if ins["network"] != req["network"]:
        add("AP2_X402_NETWORK_MISMATCH")
    if not _eq_addr(ins["asset"], req["asset"]):
        add("AP2_X402_ASSET_MISMATCH")
    if ins["amount"] != req["amount"]:
        add("AP2_X402_AMOUNT_MISMATCH")
    if not _eq_addr(ins["payTo"], req["payTo"]):
        add("AP2_X402_PAYEE_MISMATCH")
    if ins["maxTimeoutSeconds"] != req["maxTimeoutSeconds"]:
        add("AP2_X402_TIMEOUT_MISMATCH")
    if ins["eip712Domain"]["name"] != req["extra"]["name"] or ins["eip712Domain"]["version"] != req["extra"]["version"]:
        add("AP2_X402_EIP712_DOMAIN_MISMATCH")
    if ref != req["extra"]["ap2MandateReference"]:
        add("X402_MANDATE_REFERENCE_MISMATCH")
    if not canon_eq(req, x["payload"]["accepted"]):
        add("X402_ACCEPTED_REQUIREMENTS_MISMATCH")
    if x["payload"].get("extensions"):
        add("X402_UNSUPPORTED_EXTENSION")
    if not _eq_addr(ins["payer"], au["from"]):
        add("EIP3009_PAYER_MISMATCH")
    if not _eq_addr(req["payTo"], au["to"]):
        add("EIP3009_RECIPIENT_MISMATCH")
    if req["amount"] != au["value"]:
        add("EIP3009_VALUE_MISMATCH")
    va_, vb = _big(au["validAfter"]), _big(au["validBefore"])
    if va_ >= now:
        add("EIP3009_VALID_AFTER_IN_FUTURE")
    if vb < now + 6:
        add("EIP3009_VALID_BEFORE_EXPIRED")
    if vb > now + req["maxTimeoutSeconds"]:
        add("EIP3009_VALIDITY_EXCEEDS_TIMEOUT")
    if vb > min(opn["exp"], closed["exp"]):
        add("EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY")
    if nonce.lower() != au["nonce"].lower():
        add("EIP3009_NONCE_BINDING_MISMATCH")
    sig = bytes.fromhex(x["payload"]["payload"]["signature"][2:])
    s = int.from_bytes(sig[32:64], "big")
    signer = None
    if not 0 < s <= SECP_HALF_N or sig[64] not in (27, 28) or max(va_, vb, _big(au["value"])) >= 1 << 256:
        add("EIP3009_SIGNATURE_INVALID")
    else:
        dom = {"name": req["extra"]["name"], "version": req["extra"]["version"],
               "chainId": int(req["network"].split(":")[1]), "verifyingContract": req["asset"].lower()}
        msg = {"from": au["from"].lower(), "to": au["to"].lower(), "value": int(au["value"]),
               "validAfter": va_, "validBefore": vb, "nonce": au["nonce"].lower()}
        types = {"TransferWithAuthorization": [
            {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]}
        domain_types = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                        {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
        try:
            digest = signing_digest(dom, "TransferWithAuthorization", types, msg, domain_types)
            pub = recover_public_key(digest, int.from_bytes(sig[:32], "big"), s, sig[64] - 27)
            signer = public_key_to_address(pub, keccak256)
        except (ValueError, TypeError, AssertionError):
            signer = None
        if signer is None or not _eq_addr(signer, au["from"]):
            add("EIP3009_SIGNATURE_INVALID")
    if not st["success"]:
        add("SETTLEMENT_FAILED")
    if req["network"] != st["network"]:
        add("SETTLEMENT_NETWORK_MISMATCH")
    if not _eq_addr(au["from"], st["payer"]):
        add("SETTLEMENT_PAYER_MISMATCH")
    if "amount" in st and req["amount"] != st["amount"]:
        add("SETTLEMENT_AMOUNT_MISMATCH")
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", st["transaction"]):
        add("SETTLEMENT_TRANSACTION_INVALID")
    f.sort(key=CODES.index)
    return {"consistent": not f, "failureCodes": f,
            "computed": {"closedMandateReference": ref, "inputHash": input_hash, "expectedNonce": nonce,
                         **({"recoveredSigner": signer} if signer else {})}}


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 64
    with open(argv[1]) as fh:
        bundle = json.load(fh, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    ok = 0
    for case in bundle["cases"]:
        r = verify_case(case)
        exp = case.get("expected") if isinstance(case, dict) else None
        match = isinstance(exp, dict) and r["consistent"] == exp.get("consistent") \
            and r["failureCodes"] == exp.get("failureCodes")
        ok += match
        print("%-4s %-45s %-5s %s" % ("ok" if match else "DIFF", case.get("id"), r["consistent"],
                                       ",".join(r["failureCodes"]) or "-"))
    print("%d/%d cases equal their recorded expectation" % (ok, len(bundle["cases"])))
    return 0 if ok == len(bundle["cases"]) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
