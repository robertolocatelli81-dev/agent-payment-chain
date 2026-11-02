"""SPEC 0.8 (section 10): the HTTP exchange that carried the payment, checks X1-X7. Offline, standard library only.

Sources (sources/http_20261025): x402 specs/transports-v2/http.md @0aee759, RFC 9421 (HTTP Message Signatures), RFC 9530
(Digest Fields), RFC 9651 (Structured Field Values). Signatures: Ed25519 of apc_solana.py (RFC 8032 5.1.7) and ECDSA
P-256 of apc_ap2.py (FIPS 186-5); RFC 8785 equality of apc_ap2.py."""
import base64
import hashlib
import re
from urllib.parse import urlsplit

import apc_verify as av
from apc_verify import Refusal, _obj, _str

MAX_BODY = 8 * 1024 * 1024
MAX_FIELDS = 256
MAX_LABELS = 64             # SPEC 29.2: signature labels per message (each one an ECDSA or Ed25519 verification)
TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")                       # RFC 9110 5.6.2
FIELD_VALUE = re.compile(r"(?:[\x21-\x7e](?:[\x20-\x7e\t]*[\x21-\x7e])?)?\Z")  # RFC 9110 5.5, ASCII, no obs-fold
B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")
DEFAULT_PORT = {"http": "80", "https": "443"}
ALGS = ("ed25519", "ecdsa-p256-sha256")


class SFError(ValueError):
    """a field value that is not the Structured Field it must be (RFC 9651 4.2: parsing fails)"""


def b64decode(s):
    """standard base64 with padding (RFC 4648 4), canonical, else ValueError"""
    if not isinstance(s, str) or not B64.match(s):
        raise ValueError("not base64")
    b = base64.b64decode(s, validate=True)
    if base64.b64encode(b).decode() != s:
        raise ValueError("not canonical base64")
    return b


# ------------------------------------------------------------------ RFC 9651 4.2 parsing (the types these fields use)
class _P:
    def __init__(self, s):
        if not isinstance(s, str) or any(ord(c) > 0x7e or (ord(c) < 0x20 and c != "\t") for c in s):
            raise SFError("not ASCII")
        self.s, self.i = s, 0

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def sp(self):
        while self.peek() == " ":
            self.i += 1

    def ows(self):
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1


def parse_dictionary(s, unique=False):
    """RFC 9651 4.2.2; returns a list of (key, (value, params)) in order, a later duplicate key replacing the earlier
    one in place of its value (4.2.2: "overwrite"), with value an item or an inner list (a list of items). unique: a
    repeated key fails (RFC 9421 4.1, 4.2: signature labels MUST be unique)."""
    p = _P(s)
    p.sp()
    out, keys = [], {}
    while p.peek():
        k = _key(p)
        if p.peek() == "=":
            p.i += 1
            m = _item_or_inner(p)
        else:
            m = (True, _params(p))
        if k in keys:
            if unique:
                raise SFError("key %s repeated" % k)
            out[keys[k]] = (k, m)
        else:
            keys[k] = len(out)
            out.append((k, m))
        p.ows()
        if not p.peek():
            return out
        if p.peek() != ",":
            raise SFError("expected ','")
        p.i += 1
        p.ows()
        if not p.peek():
            raise SFError("trailing ','")
    return out


def _item_or_inner(p):
    if p.peek() == "(":
        return _inner(p)
    return (_bare(p), _params(p))


def _inner(p):
    p.i += 1
    items = []
    while p.peek():
        p.sp()
        if p.peek() == ")":
            p.i += 1
            return (items, _params(p))
        items.append((_bare(p), _params(p)))
        if p.peek() not in (" ", ")"):
            raise SFError("inner list: expected ' ' or ')'")
    raise SFError("inner list not closed")


def _params(p):
    out, keys = [], {}
    while p.peek() == ";":
        p.i += 1
        p.sp()
        k = _key(p)
        v = True
        if p.peek() == "=":
            p.i += 1
            v = _bare(p)
        if k in keys:
            out[keys[k]] = (k, v)
        else:
            keys[k] = len(out)
            out.append((k, v))
    return out


def _key(p):
    c = p.peek()
    if not (c.islower() and c.isascii() or c == "*"):
        raise SFError("key")
    j = p.i
    while p.peek() and (p.peek().islower() and p.peek().isascii() or p.peek().isdigit() or p.peek() in "_-.*"):
        p.i += 1
    return p.s[j:p.i]


class Token(str):
    pass


def _bare(p):
    c = p.peek()
    if c == "-" or c.isdigit():
        return _number(p)
    if c == '"':
        return _string(p)
    if c == ":":
        p.i += 1
        j = p.s.find(":", p.i)
        if j < 0:
            raise SFError("byte sequence not closed")
        b = p.s[p.i:j]
        p.i = j + 1
        try:                                            # validate: outside the base64 alphabet fails
            return base64.b64decode(b + "=" * (-len(b) % 4), validate=True)
        except ValueError:
            raise SFError("byte sequence")
    if c == "?":
        p.i += 1
        d = p.peek()
        p.i += 1
        if d not in ("0", "1"):
            raise SFError("boolean")
        return d == "1"
    if c == "@":
        p.i += 1
        v = _number(p)
        if not isinstance(v, int):
            raise SFError("date")
        return ("date", v)
    if c == "%":
        return _display(p)
    if c.isalpha() and c.isascii() or c == "*":
        j = p.i
        p.i += 1
        while p.peek() and (TOKEN.match(p.peek()) or p.peek() in ":/"):
            p.i += 1
        return Token(p.s[j:p.i])
    raise SFError("item")


def _number(p):
    m = re.compile(r"-?[0-9]+(\.[0-9]+)?").match(p.s, p.i)
    if not m:
        raise SFError("number")
    t = m.group(0)
    p.i = m.end()
    if m.group(1) is None:
        if len(t.lstrip("-")) > 15:
            raise SFError("integer too long")
        return int(t)
    ip, fp = t.lstrip("-").split(".")
    if len(ip) > 12 or len(fp) > 3:
        raise SFError("decimal too long")
    return ("decimal", t)


class Display(str):
    pass


def _display(p):
    """RFC 9651 4.2.10"""
    if p.s[p.i:p.i + 2] != '%"':
        raise SFError("display string")
    p.i += 2
    out = bytearray()
    while p.i < len(p.s):
        c = p.s[p.i]
        p.i += 1
        if c == "%":
            h = p.s[p.i:p.i + 2]
            if not re.fullmatch(r"[0-9a-f]{2}", h):
                raise SFError("display string escape")
            out.append(int(h, 16))
            p.i += 2
        elif c == '"':
            try:
                return Display(out.decode("utf-8"))
            except UnicodeDecodeError:
                raise SFError("display string not UTF-8")
        elif c == "\t" or not 0x20 <= ord(c) <= 0x7e:
            raise SFError("display string character")
        else:
            out.append(ord(c))
    raise SFError("display string not closed")


def _string(p):
    p.i += 1
    out = []
    while p.i < len(p.s):
        c = p.s[p.i]
        p.i += 1
        if c == "\\":
            if p.i >= len(p.s) or p.s[p.i] not in '"\\':
                raise SFError("string escape")
            out.append(p.s[p.i])
            p.i += 1
        elif c == '"':
            return "".join(out)
        elif c == "\t":
            raise SFError("string character")
        else:
            out.append(c)
    raise SFError("string not closed")


# ------------------------------------------------------------------ RFC 9651 4.1 serialization (component identifiers)
def ser_bare(v):
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, Token):
        return str(v)
    if isinstance(v, Display):
        return '%"' + "".join(c if 0x20 <= ord(c) <= 0x7e and c not in '%"' else
                              "".join("%%%02x" % x for x in c.encode("utf-8")) for c in v) + '"'
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, bytes):
        return ":" + base64.b64encode(v).decode() + ":"
    if isinstance(v, tuple) and v[0] == "decimal":
        ip, fp = v[1].split(".")
        return ip + "." + (fp.rstrip("0") or "0")
    if isinstance(v, tuple) and v[0] == "date":
        return "@" + str(v[1])
    raise SFError("not serializable")


def ser_params(ps):
    return "".join(";" + k + ("" if v is True else "=" + ser_bare(v)) for k, v in ps)


def ser_inner(items, ps):
    return "(" + " ".join(ser_bare(v) + ser_params(q) for v, q in items) + ")" + ser_params(ps)


# ------------------------------------------------------------------ the exchange member (grammar, section 10)
def _fields(v, path, least):
    if not isinstance(v, list) or not least <= len(v) <= MAX_FIELDS:
        raise Refusal("%s: not a list of %d to %d fields" % (path, least, MAX_FIELDS))
    for i, f in enumerate(v):
        q = "%s[%d]" % (path, i)
        if not isinstance(f, list) or len(f) != 2 or not all(isinstance(x, str) for x in f):
            raise Refusal("%s: not a [name, value] pair of strings" % q)
        if not TOKEN.match(f[0]):
            raise Refusal("%s: field name not an RFC 9110 token" % q)
        if not FIELD_VALUE.match(f[1]):
            raise Refusal("%s: field value not visible ASCII, space and tab without leading or trailing whitespace" % q)
    return v


def _body(m, path):
    if "body" not in m:
        return None
    try:
        b = b64decode(m["body"])
    except ValueError:
        raise Refusal("%s.body: not canonical standard base64 with padding" % path)
    if len(b) > MAX_BODY:
        raise Refusal("%s.body: more than %d bytes" % (path, MAX_BODY))
    return b


def parse_exchange(ex):
    _obj(ex, "exchange", ("request",), ("response",))
    rq = _obj(ex["request"], "exchange.request", ("method", "target_uri", "fields"), ("body",))
    if not isinstance(rq["method"], str) or not TOKEN.match(rq["method"]):
        raise Refusal("exchange.request.method: not an RFC 9110 token")
    uri = _str(rq["target_uri"], "exchange.request.target_uri")
    if not re.fullmatch(r"https?://[\x21-\x7e]+", uri) or "#" in uri:
        raise Refusal("exchange.request.target_uri: not an http or https URI of visible ASCII without a fragment")
    u = urlsplit(uri)
    if not u.netloc or "@" in u.netloc or not u.hostname:
        raise Refusal("exchange.request.target_uri: no host, or user information present")
    try:
        u.port
    except ValueError:
        raise Refusal("exchange.request.target_uri: port not a number in range")
    out = {"method": rq["method"], "uri": uri, "split": u,
           "fields": _fields(rq["fields"], "exchange.request.fields", 1),
           "body": _body(rq, "exchange.request"), "response": None}
    if "response" in ex:
        rs = _obj(ex["response"], "exchange.response", ("status", "fields"), ("body",))
        st = rs["status"]
        if isinstance(st, bool) or not isinstance(st, int) or not 100 <= st <= 599:
            raise Refusal("exchange.response.status: not an integer from 100 to 599")
        out["response"] = {"status": st, "fields": _fields(rs["fields"], "exchange.response.fields", 0),
                           "body": _body(rs, "exchange.response")}
    return out


def field(fields, name):
    """the values of a field by name with case ignored, in message order"""
    n = name.lower()
    return [v for k, v in fields if k.lower() == n]


def combined(fields, name):
    vs = field(fields, name)
    return None if not vs else ", ".join(vs)          # RFC 9421 2.1, RFC 9110 5.2


def parse_keys(doc):
    """SPEC 0.8 http_keys: {"apc_http_keys": 1, "keys": {keyid: {"alg", "public_key"}}}, closed."""
    _obj(doc, "http_keys", ("apc_http_keys", "keys"))
    if doc["apc_http_keys"] != 1 or isinstance(doc["apc_http_keys"], bool):
        raise Refusal("http_keys.apc_http_keys: not 1")
    if not isinstance(doc["keys"], dict) or not doc["keys"]:
        raise Refusal("http_keys.keys: not a non-empty object")
    import apc_ap2
    keys = {}
    for kid, k in doc["keys"].items():
        q = "http_keys.keys[%r]" % kid
        _obj(k, q, ("alg", "public_key"))
        if k["alg"] not in ALGS:
            raise Refusal("%s.alg: not one of %s" % (q, ", ".join(ALGS)))
        if not isinstance(k["public_key"], str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", k["public_key"]):
            raise Refusal("%s.public_key: not lowercase hex" % q)
        b = bytes.fromhex(k["public_key"])
        if k["alg"] == "ed25519":
            if len(b) != 32:
                raise Refusal("%s.public_key: an Ed25519 key is 32 bytes" % q)
            keys[kid] = ("ed25519", b)
        else:
            pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
            if len(b) != 65 or b[0] != 4 or not apc_ap2.p256_on_curve(pt):
                raise Refusal("%s.public_key: not 0x04 || x || y of a P-256 point" % q)
            keys[kid] = ("ecdsa-p256-sha256", pt)
    return keys


# ------------------------------------------------------------------ RFC 9421 signature base (2.5) and verification (3.2)
def _derived(name, msg, ex, is_request):
    u = ex["split"]
    if name == "@status":
        if is_request:
            raise SFError("@status in a request")
        return str(msg["status"])
    if not is_request:
        raise SFError("%s targets a request" % name)
    if name == "@method":
        return ex["method"]
    if name == "@target-uri":
        return ex["uri"]
    if name == "@scheme":
        return u.scheme.lower()
    if name == "@authority":
        host = u.hostname.lower()
        port = u.port
        if ":" in host:
            host = "[" + host + "]"
        return host if port is None or str(port) == DEFAULT_PORT[u.scheme.lower()] else "%s:%d" % (host, port)
    path = u.path or "/"
    if name == "@path":
        return path
    has_q = "?" in ex["uri"]
    if name == "@query":
        return "?" + u.query if has_q else "?"
    if name == "@request-target":
        return path + ("?" + u.query if has_q else "")
    raise SFError("derived component %s not supported" % name)


SUPPORTED_DERIVED = ("@method", "@target-uri", "@authority", "@scheme", "@request-target", "@path", "@query", "@status")


class NotSupported(Exception):
    pass


class Missing(Exception):
    pass


def signature_base(components, params_ser, msg, ex, is_request):
    """RFC 9421 2.5 for the supported components. Raises NotSupported, Missing or SFError."""
    lines, seen = [], set()
    for name, ps in components:
        if not isinstance(name, str) or isinstance(name, Token):
            raise SFError("a component identifier is not a String")
        ident = ser_bare(name) + ser_params(ps)
        if ident in seen:
            raise SFError("component repeated")
        seen.add(ident)
        pk = [k for k, _ in ps]
        if any(k != "req" for k in pk) or name == "@query-param":
            raise NotSupported(ident)
        if any(v is not True for k, v in ps):
            raise SFError("req is a Boolean flag")
        target, target_req = msg, is_request
        if pk:                                              # req (2.4)
            if is_request:
                raise SFError("req in a request signature")
            target, target_req = ex["request"], True
        if name.startswith("@"):
            if name not in SUPPORTED_DERIVED:
                raise NotSupported(ident)
            val = _derived(name, target, ex, target_req)
        else:
            if name != name.lower() or not TOKEN.match(name):
                raise SFError("a field component name must be a lowercase field name")
            val = combined(target["fields"], name)
            if val is None:
                raise Missing(ident)
        lines.append("%s: %s" % (ident, val))
    lines.append('"@signature-params": ' + params_ser)
    base = "\n".join(lines)
    if any(ord(c) > 0x7e for c in base):
        raise SFError("signature base not ASCII")
    return base.encode("ascii")


def _verify_sig(alg, key, base, sig):
    if alg == "ed25519":
        import apc_solana
        return apc_solana.ed25519_verify(key, base, sig)
    import apc_ap2
    return apc_ap2.es256_verify(key, base, sig)


def _is_string(v):
    return isinstance(v, str) and not isinstance(v, (Token, Display))


def signatures(msg, ex, is_request, keys):
    """X7 results for the labels of one message, in field order: a list of report entries, then one entry per label
    of the Signature field that has no Signature-Input (RFC 9421 3.2 step 1.2: an error). Without keys no label is
    judged (each not_evaluated:absent:no_http_keys)."""
    where = "request" if is_request else "response"
    si_raw, s_raw = combined(msg["fields"], "signature-input"), combined(msg["fields"], "signature")
    if si_raw is None and s_raw is None:
        return []
    try:
        si = parse_dictionary(si_raw, unique=True) if si_raw is not None else []
        sg = dict(parse_dictionary(s_raw, unique=True)) if s_raw is not None else {}
    except SFError as e:
        return [{"where": where, "label": None, "result": "not_evaluated:absent:no_http_keys" if keys is None
                 else "failed:signature_input_malformed", "why": str(e)}]
    if len(si) > MAX_LABELS or len(sg) > MAX_LABELS:
        raise av.Refusal("exchange.%s: more than %d signature labels (SPEC 29.2)" % (where, MAX_LABELS))
    out = []
    for label, (val, ps) in si:
        e = {"where": where, "label": label, "keyid": None, "alg": None, "covered": None, "created": None,
             "expires": None}
        out.append(e)
        pd = dict(ps)
        if isinstance(val, list):
            e["covered"] = [ser_bare(n) + ser_params(q) for n, q in val]
        for k in ("keyid", "alg", "created", "expires"):
            if k in pd:
                e[k] = ser_bare(pd[k]) if isinstance(pd[k], (bytes, tuple)) else pd[k]
        if keys is None:
            e["result"] = "not_evaluated:absent:no_http_keys"
            continue
        typed = all(_is_string(pd[k]) for k in ("keyid", "alg", "nonce", "tag") if k in pd) and \
            all(isinstance(pd[k], int) and not isinstance(pd[k], bool) for k in ("created", "expires") if k in pd)
        if not isinstance(val, list) or not typed:
            e["result"] = "failed:signature_input_malformed"
            continue
        if label not in sg or not isinstance(sg[label][0], bytes):
            e["result"] = "failed:signature_missing"
            continue
        kid = pd.get("keyid")
        if kid not in keys:
            e["result"] = "failed:unknown_keyid"
            continue
        alg, key = keys[kid]
        if "alg" in pd and pd["alg"] != alg:
            e["result"] = "failed:alg_not_the_key_algorithm"
            continue
        try:
            base = signature_base(val, ser_inner(val, ps), msg, ex, is_request)
        except NotSupported as x:
            e["result"] = "not_evaluated:component_not_supported:%s" % x
            continue
        except Missing as x:
            e["result"] = "failed:component_not_in_message:%s" % x
            continue
        except SFError:
            e["result"] = "failed:signature_input_malformed"
            continue
        e["result"] = "verified" if _verify_sig(alg, key, base, sg[label][0]) else "failed:signature_invalid"
    inputs = {label for label, _ in si}
    for label in sg:
        if label not in inputs:
            out.append({"where": where, "label": label, "keyid": None, "alg": None, "covered": None, "created": None,
                        "expires": None, "result": "not_evaluated:absent:no_http_keys" if keys is None
                        else "failed:signature_without_input"})
    return out


# ------------------------------------------------------------------ X1-X7
def _one_json(fields, name, what):
    vs = field(fields, name)
    if not vs:
        return None, "absent"
    if len(vs) > 1:
        return None, "failed:%s_repeated" % what
    try:
        text = b64decode(vs[0]).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None, "failed:%s_not_base64" % what
    try:
        return av.strict_json(text), None
    except Refusal:
        return None, "failed:%s_not_json" % what


def _digest(msg):
    raw = combined(msg["fields"], "content-digest")
    if raw is None:
        return "not_evaluated:absent:no_content_digest", []
    try:
        d = parse_dictionary(raw)
    except SFError:
        return "failed:content_digest_malformed", []
    body = msg["body"]
    if body is None:
        if combined(msg["fields"], "content-length") == "0":
            body = b""
        else:
            return "not_evaluated:absent:no_body", []
    seen, ignored = 0, []
    for alg, (v, _ps) in d:
        if alg in ("sha-256", "sha-512"):
            if not isinstance(v, bytes):
                return "failed:content_digest_malformed", []
            seen += 1
            if hashlib.new(alg.replace("-", ""), body).digest() != v:
                return "failed:content_digest_mismatch", []
        else:
            ignored.append(alg)
    notes = ["Content-Digest algorithm(s) ignored (RFC 9530 2): %s" % ", ".join(ignored)] if ignored else []
    return ("verified" if seen else "not_evaluated:no_supported_digest"), notes


def _media(v):
    return v.split(";", 1)[0].strip().lower()


def check(doc, keys=None):
    """SPEC 0.8 X1-X7 for a bundle with `exchange`: (checks, notes, report member); (None, [], None) without one.
    keys: parse_keys() output (the reader's trust) or None."""
    if "exchange" not in doc:
        return None, [], None
    ex = parse_exchange(doc["exchange"])
    rq, rs = {"fields": ex["fields"], "body": ex["body"]}, ex["response"]
    ex["request"] = rq
    res, notes = {}, []
    pay, err = _one_json(rq["fields"], "payment-signature", "payment_signature")
    if err == "absent":
        res["X1"] = "failed:request_without_payment_signature"
    elif err:
        res["X1"] = err
    else:
        import apc_ap2
        res["X1"] = ("verified" if apc_ap2.canon_eq(pay, doc["payment_payload"])
                     else "failed:request_carries_another_payment")
    url = None
    for m in ("payment_payload", "payment_required"):
        r = doc.get(m, {}).get("resource") if isinstance(doc.get(m), dict) else None
        if isinstance(r, dict) and isinstance(r.get("url"), str):
            url = r["url"]
            break
    res["X2"] = ("not_evaluated:absent:no_resource_url" if url is None else
                 "verified" if ex["uri"] == url else "failed:request_not_for_the_resource")
    if res["X2"] == "failed:request_not_for_the_resource" and not url.isascii():
        # SPEC 0.11.4: resource.url may be an IRI; a request target is a URI (RFC 3987 3.1 maps one to the other)
        import apc_intl
        try:
            if apc_intl.iri_to_uri(url) == ex["uri"]:
                res["X2"] = "verified"
                notes.append("X2: resource.url is an IRI; equal to the request target after the RFC 3987 3.1 mapping "
                             "(IDNA A-labels, %%-escaped UTF-8): %s" % ex["uri"])
        except apc_intl.NotComparable as e:
            notes.append("X2: resource.url is an IRI that cannot be mapped to a URI for comparison (%s)" % e)
    st = doc.get("settlement")
    if rs is None:
        res["X3"] = "not_evaluated:absent:no_response"
        res["X4"] = "not_evaluated:absent:no_response"
    else:
        sr, err = _one_json(rs["fields"], "payment-response", "payment_response")
        if err == "absent":
            res["X3"] = ("failed:response_without_payment_response" if st is not None
                         else "not_evaluated:absent:no_payment_response")
        elif err:
            res["X3"] = err
        elif st is None:
            res["X3"] = "failed:settlement_not_in_bundle"
        else:
            import apc_ap2
            res["X3"] = "verified" if apc_ap2.canon_eq(sr, st) else "failed:response_carries_another_settlement"
        if st is None:
            res["X4"] = "not_evaluated:absent:no_settlement"
        else:
            ok2 = 200 <= rs["status"] <= 299
            res["X4"] = "verified" if ok2 == (st.get("success") is True) else "failed:status_contradicts_settlement"
    res["X5q"], n = _digest(rq)
    notes += ["X5q: " + x for x in n]
    if rs is None:
        res["X5r"] = "not_evaluated:absent:no_response"
    else:
        res["X5r"], n = _digest(rs)
        notes += ["X5r: " + x for x in n]
    mime = None
    for m in ("payment_payload", "payment_required"):
        r = doc.get(m, {}).get("resource") if isinstance(doc.get(m), dict) else None
        if isinstance(r, dict) and isinstance(r.get("mimeType"), str):
            mime = r["mimeType"]
            break
    if rs is None:
        res["X6"] = "not_evaluated:absent:no_response"
    elif mime is None:
        res["X6"] = "not_evaluated:absent:no_mime_type"
    else:
        ct = combined(rs["fields"], "content-type")
        res["X6"] = ("not_evaluated:absent:no_content_type" if ct is None else
                     "verified" if _media(ct) == _media(mime) else "failed:content_type_not_the_declared_mime_type")
    sigs = signatures(rq, ex, True, keys) + (signatures(rs, ex, False, keys) if rs is not None else [])
    if not sigs:
        res["X7"] = "not_evaluated:absent:no_signature"
    else:
        rr = [s["result"] for s in sigs]
        res["X7"] = next((x for x in rr if x.startswith("failed")), None) or \
            next((x for x in rr if x.startswith("not_evaluated")), None) or "verified"
    notes.append("exchange (declared): X1-X6 show that the recorded HTTP exchange agrees with this payment, not that "
                 "it took place; only an X7 signature binds the parts it covers to a key the reader trusts")
    member = {"status": rs["status"] if rs is not None else None,
              "request_body_sha256": hashlib.sha256(rq["body"]).hexdigest() if rq["body"] is not None else None,
              "response_body_sha256": (hashlib.sha256(rs["body"]).hexdigest()
                                       if rs is not None and rs["body"] is not None else None),
              "signatures": sigs}
    return res, notes, member
