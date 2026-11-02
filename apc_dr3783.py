"""Draft profile of x402 PR 3783 `delivery-receipt` v0.2.1 (head 737243dc), the SESSION path (ed25519) of its section 8:
levels integrity, authentic, trusted, settlement, delivery, for body, reference and stream (sse) delivery. The archival
path needs ML-DSA-65 (FIPS 204), which this verifier does not implement: it reports `not_evaluated`. Standard library
only. Section references are to the PR's delivery-receipt.md (copy in sources/x402_prs_20261026)."""
import base64
import hashlib
import re

import apc_ap2
import apc_solana as sol

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
KID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
SKEW = 300
PAYLOAD = {"version": int, "issuer": str, "resourceUrl": str, "method": str, "scheme": str, "network": str, "asset": str,
           "payTo": str, "amount": str, "payer": str, "transaction": str, "logIndex": (int, type(None)),
           "paymentId": (str, type(None)), "responseStatus": (int, type(None)), "responseContentType": (str, type(None)),
           "delivery": dict, "keyDirectoryEpoch": int, "keyDirectoryDigest": str, "issuedAt": int}
DIR_MEMBERS = ("spec", "issuer", "epoch", "prevRoot", "publishedAt", "governanceKeys", "keys", "root", "signatures")


class Fail(Exception):
    def __init__(self, level, code):
        super().__init__(code)
        self.level, self.code = level, code


def _b64(s):
    if not isinstance(s, str):
        raise ValueError
    b = base64.b64decode(s, validate=True)
    if base64.b64encode(b).decode() != s:
        raise ValueError
    return b


def _jcs(v):
    return apc_ap2.canonical(v)


def receipt_id(payload):
    return hashlib.sha256(_jcs(payload).encode("utf-8")).hexdigest()


def stream_digest(frames):
    d = hashlib.sha256(b"x402-delivery-stream/1").digest()
    for f in frames:
        d = hashlib.sha256(d + len(f).to_bytes(8, "big") + f).digest()
    return d.hex()


def sse_events(text):
    """Events as an EventSource dispatches them (HTML 'Server-sent events', interpreting an event stream): lines end
    at CRLF, CR or LF; a blank line dispatches; comments start with ':'; a pending event at the end is discarded."""
    lines = re.split(r"\r\n|\r|\n", text)
    events, data, etype = [], [], ""
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        if line == "":
            if last:
                break
            if data:
                events.append((etype or "message", "\n".join(data)))
            data, etype = [], ""
            continue
        if last:                      # no line end after it: the event is still pending and is discarded
            break
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "data":
            data.append(value)
        elif name == "event":
            etype = value
    return events


def _payload_integrity(p):
    if not isinstance(p, dict) or set(p) != set(PAYLOAD):
        raise Fail("integrity", "PAYLOAD_MEMBERS")
    for k, t in PAYLOAD.items():
        if isinstance(p[k], bool) or not isinstance(p[k], t):
            raise Fail("integrity", "PAYLOAD_TYPE")
    if p["version"] != 1 or not p["transaction"] or not HEX64.match(p["keyDirectoryDigest"]) or p["keyDirectoryEpoch"] < 1:
        raise Fail("integrity", "PAYLOAD_VALUE")
    dv = p["delivery"]
    if dv.get("mode") == "body":
        if set(dv) != {"mode", "sha256"} or not isinstance(dv["sha256"], str) or not HEX64.match(dv["sha256"]):
            raise Fail("integrity", "DELIVERY")
    elif dv.get("mode") == "stream":
        if set(dv) != {"mode", "framing", "frameCount", "digest"} or dv["framing"] != "sse" or \
                not isinstance(dv["frameCount"], int) or isinstance(dv["frameCount"], bool) or \
                not isinstance(dv["digest"], str) or not HEX64.match(dv["digest"]):
            raise Fail("integrity", "DELIVERY")
    else:
        raise Fail("integrity", "DELIVERY")
    try:
        _jcs(p)
    except (TypeError, ValueError):
        raise Fail("integrity", "NOT_I_JSON")


def _receipt_integrity(rc):
    if not isinstance(rc, dict) or set(rc) != {"payload", "signatures"}:
        raise Fail("integrity", "RECEIPT_MEMBERS")
    _payload_integrity(rc["payload"])
    sigs = rc["signatures"]
    if not isinstance(sigs, list) or not 2 <= len(sigs) <= 4:
        raise Fail("integrity", "SIGNATURES")
    algs = []
    for s in sigs:
        if not isinstance(s, dict) or set(s) != {"alg", "kid", "signature"} or not isinstance(s["kid"], str) or \
                not KID.match(s["kid"]):
            raise Fail("integrity", "SIGNATURES")
        try:
            _b64(s["signature"])
        except ValueError:
            raise Fail("integrity", "SIGNATURE_ENCODING")
        algs.append(s["alg"])
    if len(set(algs)) != len(algs) or "ed25519" not in algs or "ml-dsa-65" not in algs:
        raise Fail("integrity", "BASELINE_ALGORITHMS")


def directory_root(d):
    body = {k: d[k] for k in ("spec", "issuer", "epoch", "prevRoot", "publishedAt")}
    body["governanceKeys"] = sorted(d["governanceKeys"], key=lambda k: k["alg"])
    body["keys"] = sorted(d["keys"], key=lambda k: k["kid"])
    return hashlib.sha256(_jcs(body).encode("utf-8")).hexdigest()


def _directory(d, pinned_ed25519):
    """Section 7.3 for one epoch on the session path; returns the trust basis."""
    if not isinstance(d, dict) or set(d) != set(DIR_MEMBERS) or d["spec"] != "x402-receipt-key-directory/1":
        raise Fail("trusted", "DIRECTORY_FORMAT")
    if directory_root(d) != d["root"]:
        raise Fail("trusted", "DIRECTORY_ROOT")
    if (d["epoch"] == 1) != (d["prevRoot"] == "0" * 64):
        raise Fail("trusted", "DIRECTORY_PREV_ROOT")
    gov = {g["alg"]: g["publicKey"] for g in d["governanceKeys"]}
    sig = next((s["signature"] for s in d["signatures"] if s.get("alg") == "ed25519"), None)
    try:
        pk, sg = _b64(gov["ed25519"]), _b64(sig)
    except (KeyError, ValueError):
        raise Fail("trusted", "DIRECTORY_SIGNATURE")
    if len(pk) != 32 or len(sg) != 64 or not sol.ed25519_verify(pk, ("x402-receipt-key-directory/1\n" + d["root"]).encode(), sg):
        raise Fail("trusted", "DIRECTORY_SIGNATURE")
    if pinned_ed25519 is None:
        raise Fail("trusted", "NO_PINNED_GOVERNANCE_KEY")
    if pinned_ed25519 != gov["ed25519"]:
        raise Fail("trusted", "GOVERNANCE_KEY_NOT_PINNED")
    return "pinned"


def _key_authorizes(k, alg, t):
    if k.get("use") != "x402-delivery-receipt" or k.get("alg") != alg:
        return False
    st, nb, na = k.get("status"), k.get("notBefore"), k.get("notAfter")
    if st == "active":
        return isinstance(nb, int) and nb <= t and (na is None or t <= na)
    if st in ("retiring", "retired"):
        return isinstance(nb, int) and isinstance(na, int) and nb <= t <= na
    return False


def verify_session(inp):
    """inp: receipt (wire object) or receiptDocument + reference; directory; pinnedGovernanceKeys {"ed25519": b64};
    now; settle; requirements; resourceUrl; method; responseBody (text) or eventStream (text); responseStatus.
    Returns (levels, reason)."""
    levels = {k: "not-evaluated" for k in ("integrity", "authentic", "trusted", "settlement", "delivery")}
    terminal = None
    try:
        rc = inp.get("receipt")
        if "eventStream" in inp:
            evs = sse_events(inp["eventStream"])
            term = [i for i, (t, _) in enumerate(evs) if t == "x402-delivery-receipt"]
            if len(term) != 1:
                raise Fail("delivery", "NO_TERMINAL_EVENT")
            terminal = apc_ap2._json(evs[term[0]][1])         # SPEC 29.1: nested at most 64 deep
            frames = [d.encode("utf-8") for t, d in evs[:term[0]]]
            after = len(evs) - term[0] - 1
            rc = terminal.get("receipt", rc)
        if rc is None:
            ref, doc = inp.get("reference"), inp.get("receiptDocument")
            if terminal is not None and "reference" in terminal:
                ref = {"info": terminal["reference"]}
            info = ref["info"] if isinstance(ref, dict) and "info" in ref else ref
            octets = doc.encode("utf-8") if isinstance(doc, str) else _jcs(doc).encode("utf-8")
            if hashlib.sha256(octets).hexdigest() != info["digest"]:
                raise Fail("integrity", "REFERENCE_DIGEST")
            rc = apc_ap2._json(octets)                        # SPEC 29.1
            if _jcs(rc).encode("utf-8") != octets:
                raise Fail("integrity", "REFERENCE_NOT_JCS")
            if receipt_id(rc["payload"]) != info["receiptId"] or not info["receiptUrl"].endswith("/" + info["receiptId"]):
                raise Fail("integrity", "REFERENCE_RECEIPT_ID")
        _receipt_integrity(rc)
        levels["integrity"] = "pass"
        p = rc["payload"]
        msg = ("x402-delivery-receipt/1\n" + receipt_id(p)).encode("utf-8")
        d = inp["directory"]
        ed = next(s for s in rc["signatures"] if s["alg"] == "ed25519")
        key = next((k for k in d.get("keys", []) if k.get("kid") == ed["kid"]), None)
        if key is None or key.get("alg") != "ed25519":
            raise Fail("authentic", "UNKNOWN_KID")
        pk = _b64(key["publicKey"])
        if len(pk) != 32 or not sol.ed25519_verify(pk, msg, _b64(ed["signature"])):
            raise Fail("authentic", "SIGNATURE")
        levels["authentic"] = "pass"
        _directory(d, (inp.get("pinnedGovernanceKeys") or {}).get("ed25519"))
        if d["root"] != p["keyDirectoryDigest"]:
            raise Fail("trusted", "KEY_DIRECTORY_DIGEST_MISMATCH")
        if d["epoch"] != p["keyDirectoryEpoch"] or d["publishedAt"] > p["issuedAt"] + SKEW:
            raise Fail("trusted", "EPOCH_NOT_IN_FORCE")
        if not _key_authorizes(key, "ed25519", p["issuedAt"]):
            raise Fail("trusted", "KEY_NOT_AUTHORIZED")
        if inp.get("now") is not None and p["issuedAt"] > inp["now"] + SKEW:
            raise Fail("trusted", "ISSUED_IN_FUTURE")
        from urllib.parse import urlsplit
        o = lambda u: "%s://%s" % (urlsplit(u).scheme, urlsplit(u).netloc)      # noqa: E731
        if d["issuer"] != p["issuer"] or o(p["resourceUrl"]) != p["issuer"]:
            raise Fail("trusted", "ISSUER_NOT_AUTHORIZED")
        levels["trusted"] = "pass"
        st, rq = inp["settle"], inp["requirements"]
        evm = str(p["network"]).startswith("eip155:")
        same = (lambda a, b: isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()) if evm else \
            (lambda a, b: a == b)
        ok = (p["transaction"] == st.get("transaction") and p["network"] == st.get("network") and same(p["payer"], st.get("payer"))
              and p["scheme"] == rq.get("scheme") and same(p["asset"], rq.get("asset")) and same(p["payTo"], rq.get("payTo"))
              and p["amount"] == (st.get("amount") if st.get("amount") is not None else rq.get("amount"))
              and p["resourceUrl"] == inp.get("resourceUrl") and p["method"] == inp.get("method")
              and (inp.get("paymentId") is None or p["paymentId"] == inp.get("paymentId")))
        if not ok:
            raise Fail("settlement", "SETTLEMENT_MISMATCH")
        levels["settlement"] = "pass"
        dv = p["delivery"]
        if inp.get("responseStatus") is not None and p["responseStatus"] is not None and p["responseStatus"] != inp["responseStatus"]:
            raise Fail("delivery", "STATUS_MISMATCH")
        if dv["mode"] == "body":
            if inp.get("responseBody") is None:
                return levels, {"level": "delivery", "code": "DELIVERY_UNCONFIRMED"}
            body = inp["responseBody"].encode("utf-8") if isinstance(inp["responseBody"], str) else inp["responseBody"]
            if hashlib.sha256(body).hexdigest() != dv["sha256"]:
                raise Fail("delivery", "BODY_DIGEST")
        else:
            if terminal is None:
                return levels, {"level": "delivery", "code": "DELIVERY_UNCONFIRMED"}
            dg = stream_digest(frames)
            if after or terminal.get("frameCount") != len(frames) or terminal.get("digest") != dg or \
                    dv["frameCount"] != len(frames) or dv["digest"] != dg:
                raise Fail("delivery", "STREAM_DIGEST")
        levels["delivery"] = "pass"
        return levels, None
    except Fail as f:
        levels[f.level] = "fail"
        return levels, {"level": f.level, "code": f.code}
    except (KeyError, TypeError, ValueError, AttributeError, StopIteration, RecursionError) as e:
        # RecursionError: an embedded JSON text (SSE event, reference document) nested past the parser (SPEC 29.1)
        lv = next(k for k, v in levels.items() if v == "not-evaluated")
        levels[lv] = "fail"
        return levels, {"level": lv, "code": "VERIFIER_INPUT_%s" % type(e).__name__}


def resolve(doc, node):
    """Resolve {"$ref": "/a/b"} JSON pointers of the PR's vectors file."""
    if isinstance(node, dict) and set(node) == {"$ref"}:
        cur = doc
        for part in node["$ref"].lstrip("/").split("/"):
            cur = cur[int(part)] if isinstance(cur, list) else cur[part.replace("~1", "/").replace("~0", "~")]
        return resolve(doc, cur)
    if isinstance(node, dict):
        return {k: resolve(doc, v) for k, v in node.items()}
    if isinstance(node, list):
        return [resolve(doc, v) for v in node]
    return node


P3783 = "x402-pr3783@737243d"
SOURCE = ("x402-foundation/x402 PR 3783 head 737243dc5928db2fe6c202e09490c9deddf3835c (open): delivery-receipt v0.2.1, "
          "session path (ed25519) only")


def profile(doc, rep, trust, taken):
    """The bundle's settlement extension `delivery-receipt` (inline receipt or reference) with, in draft_artifacts
    under this profile, {"directory": <epoch document>, "receiptDocument"?: <JCS text>}; the reader pins the
    governance key through signer_trust keys (the ed25519 key equal to the directory's)."""
    st = doc.get("settlement")
    ext = (st.get("extensions") or {}).get("delivery-receipt") if isinstance(st, dict) and isinstance(st.get("extensions"), dict) else None
    arts = [e["artifact"] for e in taken.get("draft_artifacts", []) if e["profile"] == P3783]
    if not isinstance(ext, dict) or not arts or not isinstance(arts[0], dict):
        return None
    a = arts[0]
    info = ext.get("info") if isinstance(ext.get("info"), dict) else {}
    ex = doc.get("exchange") if isinstance(doc.get("exchange"), dict) else {}
    rq, rs = ex.get("request") or {}, ex.get("response") or {}
    from apc_drafts2 import terms
    t = terms(doc, rep)
    pinned = None
    gov = [g.get("publicKey") for g in (a.get("directory") or {}).get("governanceKeys", []) if isinstance(g, dict) and g.get("alg") == "ed25519"]
    if trust is not None and gov:
        try:
            g = _b64(gov[0])
            pinned = gov[0] if any(k == ("EdDSA", g) for k in trust["keys"].values()) else None
        except ValueError:
            pinned = None
    inp = {"directory": a.get("directory"), "pinnedGovernanceKeys": {"ed25519": pinned} if pinned else {},
           "now": None, "settle": dict(st, payer=st.get("payer") or t["payer"]),
           "requirements": doc.get("payment_payload", {}).get("accepted", {}),
           "resourceUrl": rq.get("target_uri", t["resource_url"]), "method": rq.get("method"),
           "responseStatus": rs.get("status")}
    if "body" in rs:
        inp["responseBody"] = base64.b64decode(rs["body"])
    if "receipt" in info:
        inp["receipt"] = info["receipt"]
    else:
        inp["reference"], inp["receiptDocument"] = info, a.get("receiptDocument")
    levels, reason = verify_session(inp)
    m = {"pass": "verified", "fail": "failed:%s" % (reason or {}).get("code", "fail").lower()}
    out = {"DR%d_%s" % (i + 1, k): m.get(v, "not_evaluated:%s" % ((reason or {}).get("code", "not_evaluated").lower()
                                                                 if reason and reason["level"] == k else "after_a_failure"))
           for i, (k, v) in enumerate(levels.items())}
    if reason and reason["code"] == "NO_PINNED_GOVERNANCE_KEY":     # the reader's pin is absent, not contradicted
        out["DR3_trusted"] = "not_evaluated:absent:no_pinned_governance_key"
    out["DR6_archival"] = "not_evaluated:ml_dsa_65_not_implemented"
    return out
