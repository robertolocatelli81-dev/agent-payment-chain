"""SPEC section 24 (draft profiles, third set): x402 PRs 3304 (response-provenance), 3682 (execution-evidence),
3681 (refund) and 2853 (compliance-fields), read only with --drafts and reported apart, as sections 17 and 23."""
import base64
import hashlib
import re

import apc_verify as av
from apc_drafts2 import _bind, _jcs, _same, _verdict, terms

P3304 = "x402-pr3304@7f7489b"
P3682 = "x402-pr3682@23b5c21"
P3681 = "x402-pr3681@4acdd1f"
P2853 = "x402-pr2853@30a6be4"
SOURCES = {
    P3304: "x402-foundation/x402 PR 3304 head 7f7489ba8978a3b6eea0eb9c6a2ccb6c099eb883 (open): response-provenance",
    P3682: "x402-foundation/x402 PR 3682 head 23b5c21125982961a2d4c13faf3cb5a6d6d7c03b (open): execution-evidence x402ev/1",
    P3681: "x402-foundation/x402 PR 3681 head 4acdd1f6cbf14308cddaa399fe3285616ada38e5 (open): refund",
    P2853: "x402-foundation/x402 PR 2853 head 30a6be4fada8a57d6c46b772f2746bc637435a3e (open): compliance-fields",
}
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
VINTAGE = re.compile(r"[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?\Z")


def _response_json(doc):
    ex = doc.get("exchange")
    rs = ex.get("response") if isinstance(ex, dict) else None
    if not isinstance(rs, dict) or "body" not in rs:
        return None, None
    raw = base64.b64decode(rs["body"])
    try:
        return raw, av.strict_json(raw.decode("utf-8"))
    except (av.Refusal, UnicodeDecodeError):
        return raw, None


# ------------------------------------------------------------------ PR 3304 response-provenance
def query_inputs(query):
    """PR 3304 'Request -> inputs mapping' for a body-less request: WHATWG urlencoded with the two tightenings
    (a bad %-escape and non-UTF-8 are malformed). Returns the object, or None when malformed."""
    out = {}
    if query == "":
        return out
    for pair in query.split("&"):
        if pair == "":
            continue
        name, _, value = pair.partition("=")
        dec = []
        for part in (name, value):
            b, i, s = bytearray(), 0, part.replace("+", " ")
            while i < len(s):
                if s[i] == "%":
                    if not re.fullmatch(r"[0-9A-Fa-f]{2}", s[i + 1:i + 3]):
                        return None
                    b.append(int(s[i + 1:i + 3], 16))
                    i += 3
                else:
                    b += s[i].encode("utf-8")
                    i += 1
            try:
                dec.append(b.decode("utf-8"))
            except UnicodeDecodeError:
                return None
        k, v = dec
        if k in out:
            out[k] = (out[k] if isinstance(out[k], list) else [out[k]]) + [v]
        else:
            out[k] = v
    return out


def provenance_hash(endpoint, inputs, result, method, vintage):
    fp = {"endpoint": endpoint, "inputs": inputs, "result": result, "method": method, "dataVintage": vintage}
    return "sha256:" + hashlib.sha256(_jcs(fp).encode("utf-8")).hexdigest()


def p3304(doc, rep, trust, taken):
    raw, body = _response_json(doc)
    if not isinstance(body, dict) or not isinstance(body.get("extensions"), dict) or \
            "response-provenance" not in body["extensions"]:
        return None                                          # "no_claim": not a failure (PR 3304 outcomes)
    e = body["extensions"]["response-provenance"]
    req, opt = {"responseHash", "fixedPointVersion", "method", "dataVintage"}, {"resultCarriage", "spec"}
    if not isinstance(e, dict) or not req <= set(e) or set(e) - req - opt or not isinstance(e["responseHash"], str) \
            or not SHA.match(e["responseHash"]):
        return {"RP1": "not_evaluated:unverifiable:extension_shape"}
    if e["fixedPointVersion"] not in ("GVP-FixedPoint/1", "GVP-FixedPoint/2"):
        return {"RP1": "not_evaluated:unverifiable:fixed_point_version"}
    if e["fixedPointVersion"] == "GVP-FixedPoint/2" and not (isinstance(e["dataVintage"], str) and VINTAGE.match(e["dataVintage"])):
        return {"RP1": "not_evaluated:unverifiable:data_vintage_grammar"}
    carriage = e.get("resultCarriage", "member")
    if carriage == "member" and "result" in body:
        result = body["result"]
    elif carriage == "body":
        result = {k: v for k, v in body.items() if k != "extensions"}
    else:
        return {"RP1": "not_evaluated:unverifiable:result_not_recoverable"}
    rq = doc["exchange"]["request"]
    from urllib.parse import urlsplit
    u = urlsplit(rq["target_uri"])
    if "body" in rq:
        try:
            inputs = av.strict_json(base64.b64decode(rq["body"]).decode("utf-8"))
        except (av.Refusal, UnicodeDecodeError):
            return {"RP1": "not_evaluated:unverifiable:request_body_not_json"}
    else:
        inputs = query_inputs(u.query)
        if inputs is None:
            return {"RP1": "not_evaluated:unverifiable:malformed_query"}
    try:
        h = provenance_hash(u.path, inputs, result, e["method"], e["dataVintage"])
    except (TypeError, ValueError):
        return {"RP1": "not_evaluated:unverifiable:not_canonicalizable"}
    return {"RP1": "verified", "RP2": "verified" if h == e["responseHash"] else "failed:contradicted"}


# ------------------------------------------------------------------ PR 3682 execution-evidence
def evidence_body(info):
    body = {k: v for k, v in info.items() if k not in ("evidenceRef", "transparency")}
    if isinstance(info.get("signer"), dict):
        body["signer"] = {k: v for k, v in info["signer"].items() if k != "signature"}
    return body


def p3682(doc, rep, trust, taken):
    st = doc.get("settlement")
    ext = (st.get("extensions") or {}).get("execution-evidence") if isinstance(st, dict) and isinstance(st.get("extensions"), dict) else None
    if not isinstance(ext, dict) or not isinstance(ext.get("info"), dict):
        return None
    info = ext["info"]
    out = {}
    need = ("evidenceRef", "scheme", "canonicalization", "payment", "request", "delivery", "signer")
    if any(k not in info for k in need) or info.get("scheme") != "x402ev/1" or info.get("canonicalization") != "RFC8785" \
            or not isinstance(info["payment"], dict) or not isinstance(info["signer"], dict) or not isinstance(info["delivery"], dict):
        return {"EE1": "failed:evidence_outside_grammar"}
    body = evidence_body(info)
    try:
        j = _jcs(body).encode("utf-8")
    except (TypeError, ValueError):
        return {"EE1": "failed:evidence_not_canonicalizable"}
    out["EE1"] = "verified" if info["evidenceRef"] == "x402ev/1:sha256:" + hashlib.sha256(j).hexdigest() \
        else "failed:evidence_ref_mismatch"
    sg = info["signer"]
    if sg.get("keyType") != "Ed25519":
        out["EE2"] = "not_evaluated:key_type_not_supported"
    else:
        import apc_solana as sol
        try:
            pk = base64.urlsafe_b64decode(sg["publicKey"] + "=" * (-len(sg["publicKey"]) % 4))
            s = sg["signature"]
            sig = base64.urlsafe_b64decode(s.split(":", 1)[1] + "=" * (-len(s.split(":", 1)[1]) % 4)) \
                if isinstance(s, str) and s.startswith("base64url:") else b""
        except (ValueError, TypeError, KeyError, IndexError):
            pk, sig = b"", b""
        out["EE2"] = "verified" if len(pk) == 32 and len(sig) == 64 and sol.on_curve(pk) and sol.ed25519_verify(pk, j, sig) \
            else "failed:evidence_signature_invalid"
        # the key's authorization needs an explicit external trust input (PR 3682 rule 1)
        auth = trust is not None and any(k == ("EdDSA", pk) for k in trust["keys"].values())
        out["EE6"] = "verified" if auth else "not_evaluated:absent:no_signer_trust"
    p, t = info["payment"], terms(doc, rep)
    out["EE3"] = "failed:payer_equals_payee" if _same(p.get("payer"), p.get("payee"), t["evm"]) else "verified"
    for key, field, mine, why in (("EE4a", "payer", t["payer"], "payer_mismatch"),
                                  ("EE4b", "payee", t["pay_to"], "payee_mismatch"),
                                  ("EE4d", "asset", t["asset"], "asset_mismatch")):
        _bind(out, key, None if mine is None else _same(p.get(field), mine, t["evm"]), "no_" + field, why)
    _bind(out, "EE4c", None if t["amount"] is None else p.get("amount") == str(t["amount"]), "no_amount", "amount_mismatch")
    _bind(out, "EE4e", None if t["network"] is None else p.get("network") == t["network"], "no_network", "network_mismatch")
    if "txHash" in p:
        _bind(out, "EE4f", None if t["transaction"] is None else _same(p["txHash"], t["transaction"], t["evm"]),
              "no_settlement_transaction", "tx_hash_mismatch")
    raw, _ = _response_json(doc)
    cd = info["delivery"].get("contentDigest")
    out["EE5"] = "not_evaluated:absent:no_response_body" if raw is None else \
        "verified" if cd == "sha256:" + hashlib.sha256(raw).hexdigest() else "failed:content_digest_mismatch"
    return out


# ------------------------------------------------------------------ PR 3681 refund (request / response in draft_artifacts)
REASONS = ("service_not_delivered", "service_defective", "duplicate_payment", "overcharge", "customer_request", "other")


def p3681(doc, rep, trust, taken):
    arts = [e["artifact"] for e in taken.get("draft_artifacts", []) if e["profile"] == P3681]
    if not arts:
        return None
    t = terms(doc, rep)
    out, by_key = {}, {}
    for i, a in enumerate(arts):
        r = {}
        rq, rs = (a.get("request"), a.get("response")) if isinstance(a, dict) else (None, None)
        if not isinstance(rq, dict) or any(k not in rq for k in ("x402Version", "paymentReference", "amount", "reason",
                                                                  "idempotencyKey", "payerSignature")) \
                or rq["reason"] not in REASONS or not isinstance(rq["amount"], str) or not re.fullmatch(r"0|[1-9][0-9]*", rq["amount"]):
            r["RF1"] = "failed:refund_request_outside_grammar"
        else:
            r["RF1"] = "verified"
            ref = rq["paymentReference"] if isinstance(rq["paymentReference"], dict) else {}
            _bind(r, "RF2", None if t["transaction"] is None else _same(ref.get("txHash"), t["transaction"], t["evm"]),
                  "no_settlement_transaction", "refund_names_another_payment")
            _bind(r, "RF3", None if t["amount"] is None else int(rq["amount"]) <= int(t["amount"]), "no_amount",
                  "refund_above_settled_amount")
            if "refundTo" in rq:
                r["RF4"] = "verified" if _same(rq["refundTo"], t["payer"], t["evm"]) else "not_evaluated:refund_to_another_address"
            # PR 3681: "Signature over the canonical request bytes ... same format rules as the Offer and Receipt
            # extension" — it defines neither the bytes nor EIP-712 types for a request
            r["RF5"] = "not_evaluated:proposal_defines_no_signed_bytes"
        if isinstance(rs, dict):
            st = rs.get("status")
            if st not in ("executed", "pending", "denied"):
                r["RF6"] = "failed:refund_response_status"
            elif st == "executed":
                r["RF6"] = "verified" if isinstance(rs.get("refundTxHash"), str) else "failed:executed_without_refund_tx"
                if isinstance(rs.get("amount"), str) and rs["amount"].isdigit() and isinstance(rq, dict):
                    # PR 3681: "a repeated key MUST return the original response, never a second transfer"
                    by_key.setdefault(rq.get("idempotencyKey"), set()).add((rs.get("refundTxHash"), int(rs["amount"])))
            else:
                r["RF6"] = "verified"
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    if any(len(v) > 1 for v in by_key.values()):
        out["RF8"] = "failed:idempotency_key_with_two_refunds"
    executed = sum(max(a for _, a in v) for v in by_key.values())
    if t["amount"] is not None:
        out["RF7"] = "verified" if executed <= int(t["amount"]) else "failed:refunded_total_above_settled_amount"
    return out


# ------------------------------------------------------------------ PR 2853 compliance-fields
INT_MEMBERS = {("version",), ("canonicalizationVersion",), ("issuedAt",), ("seq",), ("correctionSeq",), ("retentionYears",),
               ("settlement", "fiat", "asOf")}
ATTEST_TYPES = {"ComplianceAttestation": [{"name": n, "type": t} for n, t in (
    ("version", "uint256"), ("recordDigest", "bytes32"), ("receiptDigest", "bytes32"), ("issuedAt", "uint256"))]}


def _numbers_ok(v, path=()):
    """PR 2853 'Numbers': only the declared int members may be JSON numbers, and they are exact integers."""
    if isinstance(v, bool):
        return True
    if isinstance(v, (int, float)):
        return isinstance(v, int) and path in INT_MEMBERS and abs(v) < 2 ** 53
    if isinstance(v, dict):
        return all(_numbers_ok(x, path + (k,)) for k, x in v.items())
    if isinstance(v, list):
        return all(_numbers_ok(x, path + ("[]",)) for x in v)
    return True


def record_digest(record):
    return "0x" + av.keccak256(_jcs(record).encode("utf-8")).hex()


def p2853(doc, rep, trust, taken):
    st = doc.get("settlement")
    ext = (st.get("extensions") or {}).get("compliance-fields") if isinstance(st, dict) and isinstance(st.get("extensions"), dict) else None
    if not isinstance(ext, dict) or not isinstance(ext.get("info"), dict):
        return None
    rec, att = ext["info"].get("record"), ext["info"].get("attestation")
    if not isinstance(rec, dict) or not _numbers_ok(rec) or rec.get("version") != 1 or rec.get("canonicalizationVersion") != 1:
        return {"CF1": "failed:record_outside_grammar"}
    out = {"CF1": "verified"}
    rd = record_digest(rec)
    base = ((st.get("extensions") or {}).get("offer-receipt") or {}).get("info", {}).get("receipt")
    if base is None:
        out["CF3"] = "not_evaluated:absent:no_offer_receipt_receipt"
    else:
        out["CF3"] = "verified" if rec.get("receiptDigest") == "0x" + av.keccak256(_jcs(base).encode()).hex() \
            else "failed:receipt_digest_mismatch"
    if not isinstance(att, dict) or att.get("format") != "eip712" or not isinstance(att.get("payload"), dict):
        out["CF2"] = "not_evaluated:attestation_format_not_read"
    else:
        pl = att["payload"]
        out["CF2"] = "verified" if pl.get("recordDigest") == rd and pl.get("receiptDigest") == rec.get("receiptDigest") \
            and pl.get("issuedAt") == rec.get("issuedAt") else "failed:attestation_digests_mismatch"
        try:
            d = av.signing_digest({"name": "compliance-fields", "version": "1", "chainId": 1}, "ComplianceAttestation",
                                  ATTEST_TYPES, pl)
            s = bytes.fromhex(att["signature"][2:])
            import apc_offer as ao
            who = ao.evm_address(av.recover_public_key(d, int.from_bytes(s[:32], "big"), int.from_bytes(s[32:64], "big"),
                                                       s[64] - 27))
            out["CF4"] = "verified (signer %s)" % who
            t = terms(doc, rep)
            out["CF5"] = "verified" if t["pay_to"] and who == str(t["pay_to"]).lower() else \
                "not_evaluated:absent:no_signer_trust"
        except (ValueError, KeyError, TypeError, IndexError):
            out["CF4"] = "failed:attestation_signature_invalid"
    tx = (rec.get("settlement") or {}).get("txHash") if isinstance(rec.get("settlement"), dict) else None
    if tx is not None:
        t = terms(doc, rep)
        _bind(out, "CF6", None if t["transaction"] is None else _same(tx, t["transaction"], t["evm"]),
              "no_settlement_transaction", "record_names_another_transaction")
    return out


# ------------------------------------------------------------------ PR 3220 authority mandate (single payment, sections 3-7)
P3220 = "x402-pr3220@72c3704"
SOURCES[P3220] = ("x402-foundation/x402 PR 3220 head 72c3704dfb89851fb7b1f0dca4d327b804faee5c (open): authority "
                  "mandates x402-mandate/1, single payment (sections 3-7); spend log, heads, Model B, delegation not read")
B64U43 = re.compile(r"[A-Za-z0-9_-]{43}\Z")
B64U86 = re.compile(r"[A-Za-z0-9_-]{86}\Z")
DEC = re.compile(r"(0|[1-9][0-9]*)\Z")
RFC3339Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z\Z")
MANDATE_REQ = ("v", "issuer", "subject", "asset", "cap", "recipients", "accountant", "purpose", "notAfter", "nonce")
MANDATE_OPT = ("perPayment", "parent")


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mandate_refusal(m):
    """PR 3220 section 3 validation (every rule a MUST), None when valid, else the reason."""
    import datetime
    if not isinstance(m, dict) or any(k not in m for k in MANDATE_REQ):
        return "missing_member"
    if set(m) - set(MANDATE_REQ) - set(MANDATE_OPT):
        return "unknown_member"                       # the object is closed (PR 3220 securityFixes)
    for k, v in m.items():
        vals = v if k == "recipients" else [v]
        if not isinstance(vals, list) or not all(isinstance(x, str) for x in vals):
            return "not_a_string:" + k
        try:
            [x.encode("utf-8") for x in vals]
        except UnicodeEncodeError:
            return "not_well_formed_utf16:" + k
    if m["v"] != "x402-mandate/1" or not B64U43.match(m["issuer"]):
        return "version_or_issuer"
    if not DEC.match(m["cap"]) or ("perPayment" in m and (not DEC.match(m["perPayment"]) or int(m["perPayment"]) > int(m["cap"]))):
        return "cap_or_per_payment"
    r = m["recipients"]
    if not r or ("*" in r and r != ["*"]):
        return "recipient_scope"
    if m["accountant"] != "payees" and not B64U43.match(m["accountant"]):
        return "accountant"
    if m["accountant"] == "payees" and r != ["*"] and not all(B64U43.match(x) for x in r):
        return "payees_recipients_not_keys"
    if not RFC3339Z.match(m["notAfter"]):
        return "not_after"
    try:
        t = datetime.datetime.strptime(m["notAfter"][:19], "%Y-%m-%dT%H:%M:%S")
        if t.strftime("%Y-%m-%dT%H:%M:%S") != m["notAfter"][:19]:
            return "not_after"
    except ValueError:
        return "not_after"
    if "parent" in m and not re.fullmatch(r"sha256:[0-9a-f]{64}", m["parent"]):
        return "parent"
    return None


def mandate_digest(m):
    return "sha256:" + hashlib.sha256(b"x402-mandate/1\n" + _jcs(m).encode("utf-8")).hexdigest()


def mandate_binding(digest, payment_id):
    """PR 3220 section 7, EIP-3009 encoding: 0x + lower-case hex of B."""
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,64}", payment_id or ""):
        raise ValueError("payment_id_outside_grammar")
    return "0x" + hashlib.sha256(b"x402-mandate-binding/1\n" + (digest + "\n" + payment_id).encode("utf-8")).hexdigest()


def p3220(doc, rep, trust, taken):
    arts = [e["artifact"] for e in taken.get("draft_artifacts", []) if e["profile"] == P3220]
    if not arts:
        return None
    import apc_solana as sol
    import time
    t = terms(doc, rep)
    out = {}
    for i, a in enumerate(arts):
        r = {}
        env = a.get("envelope") if isinstance(a, dict) else None
        if not isinstance(env, dict) or set(env) != {"mandate", "alg", "sig"} or not isinstance(a.get("paymentId"), str):
            r["AU1"] = "failed:not_a_mandate_envelope_with_payment_id"
        else:
            why = mandate_refusal(env["mandate"])
            if why:
                r["AU1"] = "failed:mandate_invalid:" + why
            else:
                m = env["mandate"]
                r["AU1"] = "verified"
                ok = env["alg"] == "Ed25519" and isinstance(env["sig"], str) and B64U86.match(env["sig"]) and \
                    sol.ed25519_verify(_b64u(m["issuer"]), b"x402-mandate/1\n" + _jcs(m).encode("utf-8"), _b64u(env["sig"]))
                r["AU2"] = "verified" if ok else "failed:mandate_signature"
                dg = mandate_digest(m)
                pp = doc.get("payment_payload", {})
                nonce = ((pp.get("payload") or {}).get("authorization") or {}).get("nonce")
                try:
                    b = mandate_binding(dg, a["paymentId"])
                    r["AU3"] = "not_evaluated:not_eip3009" if nonce is None else \
                        "verified" if str(nonce).lower() == b else "failed:nonce_not_the_mandate_binding"
                except ValueError:
                    r["AU3"] = "failed:payment_id_outside_grammar"
                # section 6, from the settled artifact: payer = subject, recipient in scope, asset, amount bounds
                rc = m["recipients"]
                r["AU4"] = ("failed:payer_not_subject" if not _same(t["payer"], m["subject"], t["evm"]) else
                            "failed:recipient_out_of_scope" if rc != ["*"] and not any(_same(t["pay_to"], x, t["evm"]) for x in rc) else
                            "failed:asset_not_the_mandate_asset" if not _same(t["asset"], m["asset"], t["evm"]) else
                            "failed:amount_above_per_payment" if "perPayment" in m and int(t["amount"]) > int(m["perPayment"]) else
                            "failed:amount_above_cap" if int(t["amount"]) > int(m["cap"]) else "verified")
                inc = doc.get("inclusion")
                if isinstance(inc, dict):
                    bt = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(inc["block_header"]["timestamp"], 16)))
                    r["AU5"] = "verified" if bt < m["notAfter"][:19] + "Z" else "failed:expired_at_settlement"
                else:
                    r["AU5"] = "not_evaluated:absent:no_block_time"
                r["AU6"] = "not_evaluated:spend_log_not_read"
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    return out


# ------------------------------------------------------------------ PR 3868 correctness and dispute (hash/signature set)
P3868 = "x402-pr3868@aeb0389"
SOURCES[P3868] = ("x402-foundation/x402 PR 3868 head aeb038998b677d8197ab4aeac66886e57c56fa85 (open): bonded verdicts; "
                  "only the record hash and signature (its reference kit stillmarcus24/notary-x402-reference-kit e6e17a2)")


def p3868(doc, rep, trust, taken):
    arts = [e["artifact"] for e in taken.get("draft_artifacts", []) if e["profile"] == P3868]
    if not arts:
        return None
    import apc_solana as sol
    t = terms(doc, rep)
    out = {}
    for i, a in enumerate(arts):
        r = {}
        if not isinstance(a, dict) or set(a) != {"preimage", "receipt_hash", "signature", "notary_fp"} or \
                not all(isinstance(a[k], str) for k in a):
            r["BV1"] = "failed:record_outside_grammar"
        else:
            # kit: "sha256(utf8(preimage)) must equal expected_receipt_hash", the preimage published verbatim
            r["BV1"] = "verified" if hashlib.sha256(a["preimage"].encode("utf-8")).hexdigest() == a["receipt_hash"] \
                else "failed:record_hash_mismatch"
            key = trust["keys"].get(a["notary_fp"]) if trust is not None else None
            try:
                sig = base64.b64decode(a["signature"], validate=True)
            except ValueError:
                sig = b""
            if key is None:
                r["BV2"] = "not_evaluated:absent:no_signer_trust"
            elif key[0] != "EdDSA":
                r["BV2"] = "failed:alg_not_the_key_algorithm"
            else:
                r["BV2"] = "verified" if len(sig) == 64 and sol.ed25519_verify(key[1], a["receipt_hash"].encode(), sig) \
                    else "failed:record_signature_invalid"
            # PR 3868 rule 5: the record MUST link the exact verified settlement evidence it was issued against
            try:
                pre = av.strict_json(a["preimage"])
            except av.Refusal:
                pre = None
            vals = [v for v in pre.values() if isinstance(v, str)] if isinstance(pre, dict) else []
            r["BV3"] = "verified" if t["transaction"] and any(_same(v, t["transaction"], t["evm"]) for v in vals) else \
                "not_evaluated:record_names_no_settlement_of_this_bundle"
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    return out


def run(doc, rep, trust, taken):
    import apc_dr3783
    SOURCES[apc_dr3783.P3783] = apc_dr3783.SOURCE
    out = {}
    for pid, fn in ((P3304, p3304), (P3682, p3682), (P3681, p3681), (P2853, p2853), (apc_dr3783.P3783, apc_dr3783.profile), (P3220, p3220), (P3868, p3868)):
        try:
            checks = fn(doc, rep, trust, taken)
        except av.Refusal as e:
            checks = {"grammar": "failed:outside_the_proposal_grammar(%s)" % str(e)[:120]}
        except av.apc_block.HashBudget:         # SPEC 29.2: past the drafts' own budget, never the verdict
            checks = dict(av.DRAFT_BUDGET_CHECKS)
        out[pid] = {"source": SOURCES[pid], "checks": checks or {},
                    "verdict": _verdict(checks) if checks else "draft_not_applicable"}
    return out
