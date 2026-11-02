"""SPEC section 17 (draft profiles): x402 rules that are proposed, not merged, each checked under its own profile id
(the PR and its head commit). Run only on request (apc_verify --drafts); the result is the report member `drafts`,
{profile: {"source", "checks", "verdict": draft_met | draft_failed | draft_incomplete | draft_not_applicable}}, kept
apart from `checks` and the verdict, which follow merged specifications only. When a proposal changes, only its
profile here changes."""
import hashlib
import re

import apc_verify as av

P3910 = "x402-pr3910@2e9e6aa"
P3925 = "x402-pr3925@8d08156"
P3827 = "x402-pr3827@fe777a4"
SOURCES = {
    P3910: "x402-foundation/x402 PR 3910 head 2e9e6aa179845ebeb1e6314476bda0ad140b8aec (open 2026-10-26): "
           "self-payment prohibition, scheme_exact.md and x402-specification-v2.md 10.3",
    P3925: "x402-foundation/x402 PR 3925 head 8d0815651fe53400f4835f0952af3c74724d7a22 (open 2026-10-26): "
           "scheme_exact_evm.md 'Facilitator Verification Rules (MUST)' 1-5",
    P3827: "x402-foundation/x402 PR 3827 head fe777a4e02f3b55e76a246f17bc3ddc616ba3a9c (open 2026-10-26): "
           "offer-receipt receipt payload version 2, authorizationCommitment (5.6); vectors "
           "babyblueviper1/preaction-governance-conformance 0a818e7",
}
HEX32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")
ADDR = re.compile(r"0x[0-9a-fA-F]{40}\Z")
DOMAIN_TAG = b"x402-receipt-authorization/0"


def _verdict(checks):
    v = list(checks.values())
    if any(x.startswith("failed") for x in v):
        return "draft_failed"
    if all(x.startswith("verified") for x in v):
        return "draft_met"
    return "draft_incomplete"


# ------------------------------------------------------------------ PR 3910
def p3910(doc, rep):
    """scheme_exact.md (PR): "the resolved payer address MUST NOT equal paymentRequirements.payTo
    (invalid_self_payment)", case-insensitively normalized (x402-specification-v2 10.3 of the PR)."""
    acc = doc["payment_payload"]["accepted"]
    if doc["bundle_version"] in ("apc-0.5", "apc-0.12", "apc-0.16"):   # Solana, Stellar, XRPL: the report's payer
        payer = rep.get("payer")
        if payer is None:
            return {"DS1": "not_evaluated:no_resolved_payer"}
        same = payer == acc["payTo"]
    else:
        same = rep.get("payer_is_payee") is True
    return {"DS1": "failed:invalid_self_payment" if same else "verified"}


# ------------------------------------------------------------------ PR 3925
def p3925(doc, rep):
    """The five "Facilitator Verification Rules (MUST)" of the PR, read after the fact from the bundle (EVM only)."""
    if doc["bundle_version"] in ("apc-0.5", "apc-0.12", "apc-0.16"):
        return None
    ck = rep["checks"]
    pp = av.parse_payload(doc["payment_payload"])
    sig = pp["signature"]
    out = {}
    # 1 signature canonicality: s > n/2 rejected, for every token (merged rule, Amendment 0.3.2: the measured tokens)
    if len(sig) != 65:
        out["DV1"] = "not_evaluated:not_a_65_byte_signature"
    else:
        out["DV1"] = "failed:high_s" if int.from_bytes(sig[32:64], "big") > av.SECP_N // 2 else "verified"
    # 2 signer binding over the token's EIP-712 domain = L2.sig (high-s aside, rule 1)
    l2 = ck["L2.sig"]
    out["DV2"] = ("verified" if l2.startswith("verified") or l2 in ("failed:high_s_refused_by_token",
                                                                    "not_evaluated:high_s_token_rule_not_measured")
                  else l2 if l2.startswith("failed") else "not_evaluated:by_L2.sig")
    # 3 validity window, "evaluated at verification time": the bundle has no verification time; the block time (B4)
    b4 = ck.get("B4")
    out["DV3"] = (b4 if b4 is not None and not b4.startswith("not_evaluated") else
                  "not_evaluated:verification_time_not_in_bundle")
    # 4 exact value = K2
    out["DV4"] = ck["K2"]
    # 5 replay: stateful, across verifications: the set checks D2/D3 of apc_batch read it
    out["DV5"] = "not_evaluated:set_check_apc_batch_D2_D3"
    return out


# ------------------------------------------------------------------ PR 3827
def commitment(method, asset, authorizer, identifier, salt):
    """PR 3827 5.6.2. Raises ValueError(<malformed code of the PR's vectors>)."""
    if method != "eip3009":
        raise ValueError("unsupported_method")
    if not isinstance(asset, str) or not ADDR.match(asset):
        raise ValueError("asset_not_address")
    if not isinstance(authorizer, str) or not ADDR.match(authorizer):
        raise ValueError("authorizer_not_address")
    if not isinstance(identifier, str) or not HEX32.match(identifier):
        raise ValueError("nonce_not_bytes32")
    if not isinstance(salt, str) or not HEX32.match(salt):
        raise ValueError("salt_not_bytes32")
    pre = DOMAIN_TAG + b"\x00" + method.encode("ascii") + b"\x00" + bytes.fromhex(asset[2:]) + \
        bytes.fromhex(authorizer[2:]) + bytes.fromhex(identifier[2:]) + bytes.fromhex(salt[2:])
    return "0x" + hashlib.sha256(pre).hexdigest()


def link(com, method, asset, authorizer, salt, candidates):
    """PR 3827 5.6.4 step 3 over the given candidate nonces: 'linked' (exactly one matches, returned too) or
    'no_match'. Inputs as commitment()."""
    hits = [n for n in candidates if commitment(method, asset, authorizer, n, salt) == com.lower()]
    return ("linked", hits[0]) if len(hits) == 1 else ("no_match", None)


RECEIPT_V2_TYPES = {"Receipt": [{"name": n, "type": t} for n, t in (
    ("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
    ("issuedAt", "uint256"), ("transaction", "string"), ("authorizationMethod", "string"),
    ("authorizationCommitment", "string"))]}


def _spec3827():
    import apc_offer as ao
    v2 = (("version", "network", "resourceUrl", "payer", "issuedAt"),
          ("transaction", "authorizationMethod", "authorizationCommitment"))
    return {"offer": ao.SPEC_MERGED["offer"], "receipt": {**ao.SPEC_MERGED["receipt"], 2: (v2, RECEIPT_V2_TYPES)}}


def p3827(doc, rep, trust):
    st = doc.get("settlement")
    ext = st.get("extensions", {}).get("offer-receipt") if isinstance(st, dict) and \
        isinstance(st.get("extensions"), dict) else None
    if not isinstance(ext, dict):
        return None
    import apc_offer as ao
    evm = doc["bundle_version"] not in ("apc-0.5", "apc-0.12", "apc-0.16")
    if not evm:
        return {"DR1": "not_evaluated:eip3009_method_only"}
    pp = av.parse_payload(doc["payment_payload"])
    acc, au = pp["accepted"], pp["auth"]
    ctx = {"evm": True, "network": acc["network"], "scheme": "exact", "asset": acc["asset"], "pay_to": acc["pay_to"],
           "amount": str(acc["amount"]), "resource_url": pp["resource_url"] if pp["resource_url"] is not None else
           ((doc.get("payment_required") or {}).get("resource") or {}).get("url"),
           "payer": au["from"], "transaction": st.get("transaction"), "success": st.get("success"),
           "block_time": None, "accepts": None}
    res, _, member = ao.check({"settlement": st, "payment_payload": {}}, ctx, trust, _spec3827(),
                              extra_info=("authorizationSalt",))
    # DR1 the receipt and its bindings (OR2 of section 13 under the PR's grammar), DR3 who signed it (OR3)
    out = {"DR1": res.get("OR2", "not_evaluated:no_receipt"), "DR3": res.get("OR3", "not_evaluated:no_receipt")}
    if member is None or member["receipt"] is None:      # the signature did not hold: nothing to link
        out["DR2"] = "not_evaluated:receipt_not_verified"
        return out
    info = ext["info"]
    rc = info["receipt"]
    pl = rc.get("payload") if rc.get("format") == "eip712" else None
    if pl is None:                      # jws: the verified payload is in the signature
        pl = ao._jws(rc, "receipt", trust, [], _spec3827())["payload"]
    m, c = pl.get("authorizationMethod", ""), pl.get("authorizationCommitment", "")
    if pl["version"] != 2 or (m == "" and c == ""):
        out["DR2"] = "not_evaluated:not_attempted:no_commitment"
    elif (m == "") != (c == ""):
        out["DR2"] = "failed:malformed:one_of_method_and_commitment"          # 5.3 of the PR: MUST report malformed
    elif m != "eip3009":
        out["DR2"] = "not_evaluated:not_attempted:method_not_implemented"
    elif "authorizationSalt" not in info:
        out["DR2"] = "not_evaluated:not_attempted:no_salt"
    elif not isinstance(c, str) or not HEX32.match(c):
        out["DR2"] = "failed:malformed:commitment_not_bytes32"
    else:
        # 5.6.4 step 1: the authorizer is the receipt's signed payer; the asset is the accepted one; the candidate is
        # the authorization this bundle carries and its chain_tx shows consumed (C2), which is one of the set that
        # step 2 queries; a match there is the unique match (one nonce per authorizer and token executes once)
        executed = rep["checks"].get("C2") == "verified"
        try:
            r, _ = link(c, m, acc["asset"], pl["payer"], info["authorizationSalt"], [au["nonce"]])
        except ValueError as e:
            out["DR2"] = "failed:malformed:%s" % e
            return out
        tx = pl.get("transaction", "")
        if r == "linked" and not executed:
            out["DR2"] = "not_evaluated:incomplete:authorization_not_shown_consumed"
        elif r == "linked" and tx and tx.lower() != str(doc["chain_tx"]["tx"]["hash"]).lower():
            out["DR2"] = "failed:inconsistent"
        elif r == "linked":
            out["DR2"] = "verified"
        else:
            # the bundle holds one candidate, not the authorizer's whole set: a miss here is incomplete, not no_match
            out["DR2"] = "not_evaluated:incomplete:bundle_authorization_does_not_open_it"
    return out


def run(doc, rep, trust=None):
    if doc.get("bundle_version") == "apc-0.13":               # x402 v1: the profiles read the apc-0.3 bundle it maps to
        import apc_v1
        doc = apc_v1.to_v2(doc)[0]
    if doc.get("bundle_version") == "apc-0.15":               # auth-capture: these three PRs amend scheme exact
        return {pid: {"source": SOURCES[pid], "checks": {}, "verdict": "draft_not_applicable"}
                for pid in (P3910, P3925, P3827)}
    out = {}
    for pid, fn in ((P3910, lambda: p3910(doc, rep)), (P3925, lambda: p3925(doc, rep)),
                    (P3827, lambda: p3827(doc, rep, trust))):
        try:
            checks = fn()
        except av.Refusal as e:                 # section 17: a draft never changes the verdict (independent review 27/10: the
            # real apc-0.10 bundles were `unsupported` with --drafts, p3925 reading them by the apc-0.1 parser)
            checks = {"bundle": "not_evaluated:not_read_by_the_profile(%s)" % str(e)[:120]}
        except av.apc_block.HashBudget:         # SPEC 29.2: past the drafts' own budget, never the verdict (independent review 2
            checks = dict(av.DRAFT_BUDGET_CHECKS)   # 27/10: a 1.2 MB receipt `transaction` of PR 3827 turned it refused)
        out[pid] = {"source": SOURCES[pid], "checks": checks or {},
                    "verdict": _verdict(checks) if checks else "draft_not_applicable"}
    return out
