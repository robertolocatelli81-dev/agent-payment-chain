"""SPEC section 23 (draft profiles, second set): proposals read only with --drafts, each under its own profile id, in
the report member `drafts`; never the verdict. Artifacts a proposal defines outside the x402 messages travel in the
bundle member `draft_artifacts` [{"profile", "artifact"}]; a resource member a proposal adds (PR 3741 `method`) is
taken out of the bundle before the merged rules read it (apc_verify._split_drafts)."""
import base64
import hashlib
import re

import apc_verify as av
from apc_verify import Refusal

P3604 = "x402-pr3604@4726ab0"
PV402 = "verify402-seller-payout@2b0faea"
P8004 = "erc8004-feedback@4891ba3"
P3741 = "x402-pr3741@1f5a05a"
P3186 = "x402-pr3186@3dcef3c"
P2666 = "x402-pr2666@76b8ccc"
P3830 = "x402-pr3830@f2cf798"
SOURCES = {
    P3604: "x402-foundation/x402 PR 3604 head 4726ab0ddcab98243036f0fb6a2ed5384923e010 (open): Buyer Delivery Claim",
    PV402: "a32116150-ctrl/verify402 2b0faeaf95a5205f3972003033c3a5844919de93 src/preflight.mjs 985-1230: seller payout "
           "manifest verify402/seller-payout@1 (one implementer's own format)",
    P8004: "ethereum/ERCs 4891ba3b ERCS/erc-8004.md (Draft): off-chain feedback file, proofOfPayment",
    P3741: "x402-foundation/x402 PR 3741 head 1f5a05a751bb9c9306d7f1694efb08a397c24544 (open): resource.method",
    P3186: "x402-foundation/x402 PR 3186 head 3dcef3c3dd1f172826247a131b083959d1447fcd (open): offer-receipt receipt "
           "version 2 with responseHash (another version 2 than PR 3827's)",
    P2666: "x402-foundation/x402 PR 2666 head 76b8cccdc065f3699fb5cdfaa6492aaaadd6db13 (open): settlement record, actionRef",
    P3830: "x402-foundation/x402 PR 3830 head f2cf79802d0bb192b1d5cddf671a8a155d56a9d6 (open, draft): svm-memo "
           "authorization commitment",
}
ADDR = re.compile(r"0x[0-9a-fA-F]{40}\Z")
HEX32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")
ISO_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")


def _verdict(checks):
    v = list(checks.values())
    if any(x.startswith("failed") for x in v):
        return "draft_failed"
    if v and all(x.startswith("verified") for x in v):
        return "draft_met"
    return "draft_incomplete"


def _jcs(v):
    import apc_ap2
    return apc_ap2.canonical(v)


def terms(doc, rep):
    """The paid terms as the merged rules read them: network, asset, pay_to, amount, payer, transaction, resource
    URL, evm (bool)."""
    v = doc.get("bundle_version")
    pp = doc.get("payment_payload", {})
    acc = pp.get("accepted", {})
    st = doc.get("settlement") if isinstance(doc.get("settlement"), dict) else {}
    res = (pp.get("resource") or {}).get("url") or ((doc.get("payment_required") or {}).get("resource") or {}).get("url")
    t = {"network": acc.get("network"), "asset": acc.get("asset"), "pay_to": acc.get("payTo"),
         "amount": acc.get("amount"), "transaction": st.get("transaction") if st.get("success") is True else None,
         "resource_url": res, "evm": v not in ("apc-0.5", "apc-0.12", "apc-0.16")}
    if t["evm"]:
        t["payer"] = (pp.get("payload", {}).get("authorization") or {}).get("from")
    else:
        t["payer"] = rep.get("payer")
    return t


def _same(a, b, evm):
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return a.lower() == b.lower() if evm else a == b


def _eip191(msg_text, sig_hex):
    """Recover the EVM address of an EIP-191 personal_sign over the UTF-8 text, or None."""
    import apc_offer as ao
    if not isinstance(sig_hex, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", sig_hex):
        return None
    m = msg_text.encode("utf-8")
    d = av.keccak256(b"\x19Ethereum Signed Message:\n" + str(len(m)).encode() + m)
    s = bytes.fromhex(sig_hex[2:])
    v = s[64] - 27 if s[64] >= 27 else s[64]
    try:
        return ao.evm_address(av.recover_public_key(d, int.from_bytes(s[:32], "big"), int.from_bytes(s[32:64], "big"), v))
    except ValueError:
        return None


def _artifacts(taken, profile):
    return [e["artifact"] for e in taken.get("draft_artifacts", []) if e["profile"] == profile]


def _bind(out, key, ok, absent, reason):
    out[key] = "not_evaluated:absent:%s" % absent if ok is None else ("verified" if ok else "failed:" + reason)


# ------------------------------------------------------------------ PR 3604 Buyer Delivery Claim
CLAIM_REQ = ("sellerAddress", "buyerAddress", "assetType", "promisedSpec", "delivered", "evidenceHash", "settlementRef",
             "timestamp", "claimId", "signature")
CLAIM_OPT = ("measured", "externalRefs", "priorClaimId")


def claim_checks(c):
    """DC1 grammar (PR 3604 4), DC2 claimId (5), DC3 the buyer's EIP-191 signature (5, 10 step 2)."""
    if not isinstance(c, dict) or any(k not in c for k in CLAIM_REQ):
        return {"DC1": "failed:claim_missing_member"}
    extra = sorted(set(c) - set(CLAIM_REQ) - set(CLAIM_OPT))
    if extra:
        return {"DC1": "not_evaluated:claim_member_not_in_proposal(%s)" % extra[0][:40]}
    bad = (not (isinstance(c["sellerAddress"], str) and ADDR.match(c["sellerAddress"]))
           or not (isinstance(c["buyerAddress"], str) and ADDR.match(c["buyerAddress"]))
           or c["assetType"] not in ("gpu-hours", "storage", "api-credits", "bandwidth")
           or c["delivered"] not in ("yes", "no", "partial")
           or not (isinstance(c["evidenceHash"], str) and re.fullmatch(r"[0-9a-f]{64}", c["evidenceHash"]))
           or not isinstance(c["settlementRef"], str) or not (isinstance(c["timestamp"], str) and ISO_MS.match(c["timestamp"]))
           or not isinstance(c["promisedSpec"], (str, dict)))
    if bad:
        return {"DC1": "failed:claim_outside_grammar"}
    out = {"DC1": "verified"}
    # PR 3604 5: "sellerAddress and buyerAddress MUST be lowercased before serialization" (two of the four live claims
    # carry EIP-55 forms: their claimId is over the lower-case form)
    content = {k: (v.lower() if k in ("sellerAddress", "buyerAddress") else v) for k, v in c.items()
               if k not in ("claimId", "signature")}
    try:
        cid = "0x" + hashlib.sha256(_jcs(content).encode("utf-8")).hexdigest()
    except (TypeError, ValueError):
        return dict(out, DC2="failed:claim_not_canonicalizable")
    out["DC2"] = "verified" if cid == c["claimId"] else "failed:claim_id_mismatch"
    who = _eip191(c["claimId"], c["signature"])
    out["DC3"] = "verified" if who == c["buyerAddress"].lower() else "failed:claim_signature_not_by_buyer"
    return out


def p3604(doc, rep, taken):
    arts = _artifacts(taken, P3604)
    if not arts:
        return None
    t = terms(doc, rep)
    out = {}
    for i, c in enumerate(arts):
        r = claim_checks(c)
        if all(x == "verified" for x in r.values()):
            # PR 3604 6: "a verifier MUST confirm that claim.buyerAddress matches the payer of the settlement"
            _bind(r, "DC4", None if t["payer"] is None else _same(c["buyerAddress"], t["payer"], True), "no_payer", "buyer_not_the_payer")
            _bind(r, "DC5", None if t["pay_to"] is None else _same(c["sellerAddress"], t["pay_to"], True), "no_payTo", "seller_not_payTo")
            _bind(r, "DC6", None if t["transaction"] is None else _same(c["settlementRef"], t["transaction"], True),
                  "no_settlement_transaction", "settlement_ref_not_the_transaction")
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    return out


# ------------------------------------------------------------------ verify402 seller payout manifest
def p_v402(doc, rep, taken):
    arts = _artifacts(taken, PV402)
    if not arts:
        return None
    t = terms(doc, rep)
    out = {}
    for i, m in enumerate(arts):
        r = {}
        req, opt = ("spec", "chainId", "payTo", "expiresAt", "signer", "signature"), ("seller", "issuedAt")
        if not isinstance(m, dict) or any(k not in m for k in req):
            r["VM1"] = "failed:manifest_missing_member"
        elif set(m) - set(req) - set(opt):
            r["VM1"] = "not_evaluated:manifest_member_not_in_format(%s)" % sorted(set(m) - set(req) - set(opt))[0][:40]
        elif m["spec"] != "verify402/seller-payout@1" or isinstance(m["chainId"], bool) or not isinstance(m["chainId"], int) \
                or m["chainId"] <= 0 or not isinstance(m["signer"], str) or not ADDR.match(m["signer"].strip()) \
                or not isinstance(m["expiresAt"], str) or not ISO.match(m["expiresAt"]) \
                or ("issuedAt" in m and m["issuedAt"] is not None and not (isinstance(m["issuedAt"], str) and ISO.match(m["issuedAt"]))):
            r["VM1"] = "failed:manifest_outside_format"
        else:
            pay = m["payTo"] if isinstance(m["payTo"], list) else [m["payTo"]]
            pay = [x.strip() for x in pay if isinstance(x, str) and x.strip()]
            if not 1 <= len(pay) <= 200:
                r["VM1"] = "failed:manifest_payto_count"
            else:
                r["VM1"] = "verified"
                # preflight.mjs 1156-1166: the signed payload, canonicalStable (sorted keys, JSON.stringify values)
                payload = {"spec": m["spec"], "seller": m["seller"] if isinstance(m.get("seller"), str) else None,
                           "chainId": m["chainId"], "payTo": pay, "issuedAt": m.get("issuedAt"),
                           "expiresAt": m["expiresAt"], "signer": m["signer"].strip()}
                who = _eip191(_jcs(payload), m["signature"])
                r["VM2"] = "verified" if who is not None and who == m["signer"].strip().lower() else \
                    "failed:manifest_signature_not_by_signer"
                net = "eip155:%d" % m["chainId"]
                _bind(r, "VM3", None if t["network"] is None else net == t["network"], "no_network", "manifest_for_another_chain")
                _bind(r, "VM4", None if t["pay_to"] is None else any(_same(x, t["pay_to"], True) for x in pay), "no_payTo", "payTo_not_in_manifest")
                bt = _block_time_iso(doc)
                if bt is None:
                    r["VM5"] = "not_evaluated:absent:no_block_time"
                else:
                    r["VM5"] = "verified" if m["expiresAt"] > bt else "failed:manifest_expired_at_settlement"
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    return out


def _block_time_iso(doc):
    import time
    inc = doc.get("inclusion")
    if isinstance(inc, dict) and isinstance(inc.get("block_header"), dict):
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(inc["block_header"]["timestamp"], 16)))
        except (TypeError, ValueError, KeyError, OverflowError):
            return None
    return None


# ------------------------------------------------------------------ ERC-8004 feedback file
def p8004(doc, rep, taken):
    arts = _artifacts(taken, P8004)
    if not arts:
        return None
    t = terms(doc, rep)
    out = {}
    for i, f in enumerate(arts):
        r = {}
        must = ("agentRegistry", "agentId", "clientAddress", "createdAt", "value", "valueDecimals")
        if not isinstance(f, dict) or any(k not in f for k in must):
            r["FB1"] = "failed:feedback_missing_must_field"
        elif not isinstance(f.get("proofOfPayment"), dict):
            r["FB1"] = "not_evaluated:no_proof_of_payment"
        else:
            p = f["proofOfPayment"]
            if set(p) != {"fromAddress", "toAddress", "chainId", "txHash"} or not all(isinstance(p[k], str) for k in p):
                r["FB1"] = "failed:proof_of_payment_not_the_four_strings"
            else:
                r["FB1"] = "verified"
                _bind(r, "FB2", None if t["payer"] is None else _same(p["fromAddress"], t["payer"], t["evm"]), "no_payer", "from_not_the_payer")
                _bind(r, "FB3", None if t["pay_to"] is None else _same(p["toAddress"], t["pay_to"], t["evm"]), "no_payTo", "to_not_payTo")
                net = t["network"] or ""
                _bind(r, "FB4", None if not net.startswith("eip155:") else p["chainId"] == net.split(":", 1)[1], "not_evm", "chain_id_not_the_network")
                _bind(r, "FB5", None if t["transaction"] is None else _same(p["txHash"], t["transaction"], t["evm"]),
                      "no_settlement_transaction", "tx_hash_not_the_settlement")
                cl = f["clientAddress"] if isinstance(f["clientAddress"], str) else ""
                _bind(r, "FB6", None if t["payer"] is None or not cl.startswith("eip155:") else
                      _same(cl.rsplit(":", 1)[-1], t["payer"], True), "no_payer", "client_not_the_payer")
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    return out


# ------------------------------------------------------------------ PR 3741 resource.method
def p3741(doc, rep, taken):
    res = taken.get("resource")
    if not res:
        return None
    out = {}
    methods = {m: v.get("method") for m, v in res.items()}
    for m, v in methods.items():
        if not isinstance(v, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Z-]+", v):
            out["RM1"] = "failed:method_not_an_uppercase_token"
    out.setdefault("RM1", "verified")
    srv = methods.get("payment_required")
    ex = doc.get("exchange")
    if out["RM1"] != "verified":
        return out
    # PR 3741: the server's own rendering is authoritative; the client's echo is client-controlled
    declared = srv if srv is not None else methods.get("payment_payload")
    if isinstance(ex, dict) and isinstance(ex.get("request"), dict):
        out["RM2"] = "verified" if ex["request"].get("method") == declared else "failed:payment_not_on_the_declared_method"
        rs = ex.get("response")
        if ex["request"].get("method") == "HEAD" and isinstance(rs, dict) and 200 <= rs.get("status", 0) <= 299:
            # RFC 9110 9.3.2: a HEAD response carries no content; a body resource paid on HEAD is paid for nothing
            mt = ((doc.get("payment_payload", {}).get("resource") or {}).get("mimeType"))
            out["RM3"] = "failed:settled_on_head_for_a_body_resource" if mt else "not_evaluated:resource_kind_unknown"
    else:
        out["RM2"] = "not_evaluated:absent:no_exchange"
    bz = ((doc.get("payment_required") or {}).get("extensions") or {}).get("bazaar") if isinstance(doc.get("payment_required"), dict) else None
    bm = (((bz or {}).get("info") or {}).get("input") or {}).get("method") if isinstance(bz, dict) else None
    if bm is not None and srv is not None:
        out["RM4"] = "verified" if bm == srv else "failed:bazaar_method_differs"
    return out


# ------------------------------------------------------------------ PR 3186 receipt version 2 responseHash
RECEIPT_3186_TYPES = {"Receipt": [{"name": n, "type": t} for n, t in (
    ("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
    ("issuedAt", "uint256"), ("transaction", "string"), ("responseHash", "string"), ("responseHashAlg", "string"),
    ("responseHashEncoding", "string"))]}


def p3186(doc, rep, trust):
    st = doc.get("settlement")
    ext = (st.get("extensions") or {}).get("offer-receipt") if isinstance(st, dict) and isinstance(st.get("extensions"), dict) else None
    if not isinstance(ext, dict):
        return None
    import apc_offer as ao
    v2 = (("version", "network", "resourceUrl", "payer", "issuedAt"),
          ("transaction", "responseHash", "responseHashAlg", "responseHashEncoding"))
    spec = {"offer": ao.SPEC_MERGED["offer"], "receipt": {**ao.SPEC_MERGED["receipt"], 2: (v2, RECEIPT_3186_TYPES)}}
    t = terms(doc, rep)
    ctx = {"evm": t["evm"], "network": t["network"], "scheme": "exact", "asset": t["asset"], "pay_to": t["pay_to"],
           "amount": t["amount"], "resource_url": t["resource_url"], "payer": t["payer"],
           "transaction": st.get("transaction"), "success": st.get("success"), "block_time": None, "accepts": None}
    res, _, member = ao.check({"settlement": st, "payment_payload": {}}, ctx, trust, spec)
    out = {"DP1": res.get("OR2", "not_evaluated:no_receipt"), "DP3": res.get("OR3", "not_evaluated:no_receipt")}
    if member is None or member["receipt"] is None:
        out["DP2"] = "not_evaluated:receipt_not_verified"
        return out
    rc = ext["info"]["receipt"]
    pl = rc["payload"] if rc.get("format") == "eip712" else ao._jws(rc, "receipt", trust, [], spec)["payload"]
    h, alg, enc = pl.get("responseHash", ""), pl.get("responseHashAlg", ""), pl.get("responseHashEncoding", "")
    if pl["version"] != 2 or not h:
        out["DP2"] = "not_evaluated:no_response_hash"
        return out
    if alg != "sha256" or enc not in ("raw", "jcs") or not HEX32.match(h):
        out["DP2"] = "failed:response_hash_fields_outside_proposal"
        return out
    body = ((doc.get("exchange") or {}).get("response") or {}).get("body") if isinstance(doc.get("exchange"), dict) else None
    if body is None:
        out["DP2"] = "not_evaluated:absent:no_response_body"
        return out
    raw = base64.b64decode(body)
    if enc == "jcs":
        try:
            raw = _jcs(av.strict_json(raw.decode("utf-8"))).encode("utf-8")
        except (Refusal, UnicodeDecodeError, TypeError, ValueError):
            out["DP2"] = "failed:response_body_not_json_for_jcs"
            return out
    # the exchange body is the content as transferred (section 10); with a content coding "raw" needs it removed
    ce = [v for n, v in (doc["exchange"]["response"].get("fields") or []) if n.lower() == "content-encoding"]
    if enc == "raw" and ce and ce != ["identity"]:
        out["DP2"] = "not_evaluated:content_coding_not_removed"
        return out
    out["DP2"] = "verified" if "0x" + hashlib.sha256(raw).hexdigest() == h.lower() else "failed:response_hash_mismatch"
    return out


# ------------------------------------------------------------------ PR 2666 settlement record
def action_ref(rec):
    tup = {k: rec[k] for k in ("agentId", "actionType", "scope", "timestampMs", "seq", "terminal")}
    return "sha256:" + hashlib.sha256(_jcs(tup).encode("utf-8")).hexdigest()


def settlement_record_checks(rec):
    common = ("agentId", "actionType", "scope", "timestampMs", "seq", "terminal", "actionRef", "schema")
    if not isinstance(rec, dict) or any(k not in rec for k in common):
        return {"SR1": "failed:record_missing_member"}
    if ("paymentHash" in rec) == ("settlement" in rec):
        return {"SR1": "failed:record_needs_one_settlement_binding"}
    extra = sorted(set(rec) - set(common) - {"paymentHash", "settlement"})
    if extra:                               # PR 2666 2: "MUST treat unknown top-level ..." is not read further here
        return {"SR1": "not_evaluated:record_member_not_in_proposal(%s)" % extra[0][:40]}
    ok = all(isinstance(rec[k], str) for k in ("agentId", "actionType", "scope", "actionRef", "schema")) and \
        all(isinstance(rec[k], int) and not isinstance(rec[k], bool) and abs(rec[k]) < 2 ** 53 for k in ("timestampMs", "seq")) \
        and isinstance(rec["terminal"], bool)
    if ok and "settlement" in rec:
        s = rec["settlement"]
        keys = ("txDigest", "payTo", "asset", "amount", "decimals", "network", "scheme", "assertedFrom", "verifiedBy", "rail")
        ok = isinstance(s, dict) and set(s) == set(keys) and isinstance(s["decimals"], int) and \
            not isinstance(s["decimals"], bool) and isinstance(s["amount"], str) and re.fullmatch(r"0|[1-9][0-9]*", s["amount"]) \
            is not None and s["assertedFrom"] == "net-balance-change-to-payTo" and s["scheme"] == "exact" and \
            all(isinstance(s[k], str) for k in keys if k != "decimals")
    if not ok:
        return {"SR1": "failed:record_outside_grammar"}
    out = {"SR1": "verified", "SR2": "verified" if action_ref(rec) == rec["actionRef"] else "failed:action_ref_mismatch"}
    return out


def p2666(doc, rep, taken):
    arts = _artifacts(taken, P2666)
    if not arts:
        return None
    t = terms(doc, rep)
    out = {}
    for i, rec in enumerate(arts):
        r = settlement_record_checks(rec)
        if r.get("SR1") == "verified" and "settlement" in rec:
            s = rec["settlement"]
            _bind(r, "SR3", None if t["transaction"] is None else _same(s["txDigest"], t["transaction"], t["evm"]),
                  "no_settlement_transaction", "tx_digest_not_the_settlement")
            _bind(r, "SR4", None if t["pay_to"] is None else _same(s["payTo"], t["pay_to"], t["evm"]), "no_payTo", "payTo_mismatch")
            _bind(r, "SR5", None if t["asset"] is None else _same(s["asset"], t["asset"], t["evm"]), "no_asset", "asset_mismatch")
            _bind(r, "SR6", None if t["amount"] is None else s["amount"] == str(t["amount"]), "no_amount", "amount_mismatch")
            _bind(r, "SR7", None if t["network"] is None else s["network"] == t["network"], "no_network", "network_mismatch")
            import apc_assets
            a = apc_assets.ASSETS.get((t["network"], str(t["asset"]).lower())) if t["evm"] else None
            if a is not None:
                r["SR8"] = "verified" if s["decimals"] == a[1] else "failed:decimals_not_the_measured_ones"
            r["SR9"] = "not_evaluated:vaara_receipt_not_read"
        out.update({"%s[%d]" % (k, i): v for k, v in r.items()})
    return out


# ------------------------------------------------------------------ PR 3830 svm-memo commitment
def svm_memo_commitment(mint_b58, payer_b58, memo_bytes, salt_hex):
    import apc_solana as sol
    if not isinstance(salt_hex, str) or not HEX32.match(salt_hex):
        raise ValueError("salt_not_bytes32")
    try:
        mint, payer = sol.b58decode(mint_b58, 32), sol.b58decode(payer_b58, 32)
    except sol.SolRefusal:
        raise ValueError("address_not_32_bytes_base58")
    pre = b"x402-receipt-authorization/0\x00svm-memo\x00" + mint + payer + hashlib.sha256(memo_bytes).digest() + \
        bytes.fromhex(salt_hex[2:])
    return "0x" + hashlib.sha256(pre).hexdigest()


def p3830(doc, rep, trust):
    if doc.get("bundle_version") != "apc-0.5":
        return None
    st = doc.get("settlement")
    ext = (st.get("extensions") or {}).get("offer-receipt") if isinstance(st, dict) and isinstance(st.get("extensions"), dict) else None
    if not isinstance(ext, dict):
        return None
    import apc_drafts
    import apc_offer as ao
    t = terms(doc, rep)
    ctx = {"evm": False, "network": t["network"], "scheme": "exact", "asset": t["asset"], "pay_to": t["pay_to"],
           "amount": str(t["amount"]), "resource_url": t["resource_url"], "payer": t["payer"],
           "transaction": st.get("transaction"), "success": st.get("success"), "block_time": None, "accepts": None}
    res, _, member = ao.check({"settlement": st, "payment_payload": {}}, ctx, trust, apc_drafts._spec3827(),
                              extra_info=("authorizationSalt",))
    out = {"DM1": res.get("OR2", "not_evaluated:no_receipt"), "DM3": res.get("OR3", "not_evaluated:no_receipt")}
    if member is None or member["receipt"] is None:
        out["DM2"] = "not_evaluated:receipt_not_verified"
        return out
    rc = ext["info"]["receipt"]
    pl = rc["payload"] if rc.get("format") == "eip712" else ao._jws(rc, "receipt", trust, [], apc_drafts._spec3827())["payload"]
    m, c = pl.get("authorizationMethod", ""), pl.get("authorizationCommitment", "")
    if pl["version"] != 2 or (not m and not c):
        out["DM2"] = "not_evaluated:not_attempted:no_commitment"
    elif m != "svm-memo":
        out["DM2"] = "not_evaluated:not_attempted:method_not_svm_memo"
    elif "authorizationSalt" not in ext["info"]:
        out["DM2"] = "not_evaluated:not_attempted:no_salt"
    else:
        memos = _payload_memos(doc)
        try:
            hits = [x for x in memos if svm_memo_commitment(t["asset"], pl["payer"], x, ext["info"]["authorizationSalt"])
                    == str(c).lower()]
        except ValueError as e:
            out["DM2"] = "failed:malformed:%s" % e
            return out
        out["DM2"] = "verified" if len(hits) == 1 else "not_evaluated:incomplete:payload_memo_does_not_open_it"
    return out


def _payload_memos(doc):
    import apc_solana as sol
    import apc_svm
    raw = apc_svm._b64(doc["payment_payload"]["payload"]["transaction"], "t")
    tx = apc_svm._parse(raw, "t")
    return [ix["data"] for ix in tx["instructions"] if tx["keys"][ix["program"]] == sol.MEMO_PROGRAM]


def run(doc, rep, trust, taken):
    out = {}
    for pid, fn in ((P3604, lambda: p3604(doc, rep, taken)), (PV402, lambda: p_v402(doc, rep, taken)),
                    (P8004, lambda: p8004(doc, rep, taken)), (P3741, lambda: p3741(doc, rep, taken)),
                    (P3186, lambda: p3186(doc, rep, trust)), (P2666, lambda: p2666(doc, rep, taken)),
                    (P3830, lambda: p3830(doc, rep, trust))):
        try:
            checks = fn()
        except Refusal as e:                    # a draft artifact outside its own grammar: the draft says so
            checks = {"grammar": "failed:outside_the_proposal_grammar(%s)" % str(e)[:120]}
        except av.apc_block.HashBudget:         # SPEC 29.2: past the drafts' own budget, never the verdict
            checks = dict(av.DRAFT_BUDGET_CHECKS)
        out[pid] = {"source": SOURCES[pid], "checks": checks or {},
                    "verdict": _verdict(checks) if checks else "draft_not_applicable"}
    return out

