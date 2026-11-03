"""agent-payment-chain, SPEC 0.12 (SPEC.md section 20): the x402 `exact` scheme on Stellar (x402 4241d56
specs/schemes/exact/scheme_exact_stellar.md, cited XLM §), bundle apc-0.12. Called by apc_verify.verify_bundle;
standard library only (primitives in apc_stellar.py, Ed25519 in apc_solana.py)."""
import base64
import binascii
import math
import re

import apc_solana as sol
import apc_stellar as xs
from apc_verify import (Refusal, Unsupported, _int_json, _json_eq, _obj, _str, exchange_checks, payment_required_obj,
                        provenance, resource_info)

UINT = re.compile(r"(0|[1-9][0-9]*)\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
I128_MAX = (1 << 127) - 1
LEDGER_SECONDS = 5          # XLM §3: the fallback estimate of a ledger's duration
ZERO_SOURCE = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"


def _addr(v, path, kinds=("G", "C")):
    s = _str(v, path)
    for k in kinds:
        if s[:1] == k:
            try:
                xs.strkey_decode(s, k)
                return s
            except xs.StellarRefusal as e:
                raise Refusal("%s: not a canonical StrKey (%s)" % (path, e))
    raise Refusal("%s: not a %s StrKey" % (path, "/".join(kinds)))


def _amount(v, path):
    if not isinstance(v, str) or not UINT.match(v) or len(v) > 39 or int(v) > I128_MAX:
        raise Refusal("%s: not a decimal i128 without sign or leading zeros" % path)
    return int(v)


def _b64(v, path):
    s = _str(v, path)
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise Refusal("%s: not base64 (RFC 4648, padded)" % path)
    if base64.b64encode(b).decode() != s:
        raise Refusal("%s: not canonical base64" % path)
    return s


def parse_requirements(v, path):
    _obj(v, path, ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"))
    if _str(v["scheme"], path + ".scheme") != "exact":
        raise Unsupported("%s.scheme %r (exact only)" % (path, v["scheme"]))
    if _str(v["network"], path + ".network") not in xs.PASSPHRASE:
        raise Unsupported("%s.network %r (apc-0.12: stellar:pubnet, stellar:testnet)" % (path, v["network"]))
    ex = _obj(v["extra"], path + ".extra", ("areFeesSponsored",))
    if not isinstance(ex["areFeesSponsored"], bool):
        raise Refusal("%s.extra.areFeesSponsored: not a boolean" % path)
    mt = _int_json(v["maxTimeoutSeconds"], path + ".maxTimeoutSeconds")
    if mt <= 0 or mt > 1 << 31:
        raise Refusal("%s.maxTimeoutSeconds: not a positive integer" % path)
    return {"network": v["network"], "amount": _amount(v["amount"], path + ".amount"),
            "asset": _addr(v["asset"], path + ".asset", ("C",)), "pay_to": _addr(v["payTo"], path + ".payTo"),
            "max_timeout": mt, "sponsored": ex["areFeesSponsored"]}


def _envelope(b64, path):
    try:
        return xs.envelope(b64)
    except xs.StellarRefusal as e:
        if str(e).startswith("operation_type_"):
            return {"not_invoke": str(e)}
        raise Refusal("%s: not a Stellar transaction envelope this profile reads (%s)" % (path, e))


def _g1(env, acc):
    """XLM §2 transaction structure."""
    if "not_invoke" in env or len(env["tx"]["ops"]) != 1:
        return "failed:not_one_invoke_host_function", None
    op = env["tx"]["ops"][0]
    fn = op["fn"]
    if xs.address_str(fn["contract"]) != acc["asset"]:
        return "failed:contract_not_the_asset", None
    if fn["function"] != b"transfer" or len(fn["args"]) != 3:
        return "failed:not_transfer_with_3_arguments", None
    a0, a1, a2 = fn["args"]
    if a0[0] != "address" or xs.address_str(a0[1]) is None:
        return "failed:from_not_an_account_or_contract", None
    if a1[0] != "address" or xs.address_str(a1[1]) != acc["pay_to"]:
        return "failed:to_not_payTo", xs.address_str(a0[1])
    if a2[0] != "i128" or a2[1] != acc["amount"]:
        return "failed:amount_not_the_requirement", xs.address_str(a0[1])
    return "verified", xs.address_str(a0[1])


def _sig_g(entry, network, frm):
    """Ed25519 by the account's own key over the authorization preimage; other signer sets need ledger state."""
    sig = entry["credentials"]["signature"]
    if sig[0] != "vec" or not sig[1]:
        return "failed:auth_signature_not_a_signature_vector"
    maps = []
    for el in sig[1]:
        if el[0] != "map" or el[1] is None:
            return "failed:auth_signature_entry_not_a_map"
        m = {k[1]: v for k, v in el[1] if k[0] == "symbol"}
        if set(m) != {b"public_key", b"signature"} or len(el[1]) != 2 or m[b"public_key"][0] != "bytes" or \
                m[b"signature"][0] != "bytes":
            return "failed:auth_signature_entry_not_public_key_and_signature"
        maps.append((m[b"public_key"][1], m[b"signature"][1]))
    key = xs.strkey_decode(frm, "G")
    if len(maps) != 1 or maps[0][0] != key:
        return "not_evaluated:account_signers_need_ledger_state"
    pk, s = maps[0]
    if len(s) != 64 or not sol.ed25519_verify(pk, xs.auth_preimage(entry, network), s, "dalek_strict"):   # SPEC 28.1
        return "failed:auth_signature_invalid"
    return "verified"


def _g2(env, acc, frm, network):
    """XLM §3 authorization entries."""
    op = env["tx"]["ops"][0]
    if not op["auth"]:
        return "failed:no_auth_entries"
    out, mine = [], 0
    for e in op["auth"]:
        c = e["credentials"]
        if c["type"] == 0:
            return "failed:source_account_credentials"
        inv = e["invocation"]
        if inv["subs"]:
            return "failed:auth_has_subinvocations"
        if inv["fn"] != op["fn"]:
            return "failed:auth_root_not_the_transfer"
        who = xs.address_str(c["address"])
        if who != frm:
            return "failed:auth_entry_for_another_address"
        mine += 1
        out.append(_sig_g(e, network, frm) if frm.startswith("G") else "not_evaluated:contract_account_check_auth")
    if mine == 0:
        return "failed:no_auth_entry_for_from"
    return next((x for x in out if x.startswith("failed")), None) or \
        next((x for x in out if x.startswith("not_evaluated")), "verified")


def _events(ct, path):
    ev = ct["contractEventsXdr"]
    if not isinstance(ev, list) or len(ev) != 1 or not isinstance(ev[0], list):
        raise Refusal("%s.contractEventsXdr: not one list of events (one operation)" % path)
    out = []
    for i, e in enumerate(ev[0]):
        try:
            r = xs.R(base64.b64decode(_b64(e, "%s.contractEventsXdr[0][%d]" % (path, i))))
            xs._enum(r.u32(), (0,), "event_ext")
            cid = r.take(32) if r.optional() else None
            t = xs._enum(r.u32(), (0, 1, 2), "contract_event_type")
            xs._enum(r.u32(), (0,), "event_body")
            topics = [xs.sc_val(r) for _ in range(r.count())]
            data = xs.sc_val(r)
            r.end()
        except xs.StellarRefusal as x:
            raise Refusal("%s.contractEventsXdr[0][%d]: %s" % (path, i, x))
        out.append({"contract": xs.strkey_encode("C", cid) if cid else None, "type": t, "topics": topics, "data": data})
    return out


def _amount_of(data):
    if data[0] == "i128":
        return data[1]
    if data[0] == "map" and data[1]:       # CAP-67: {amount, to_muxed_id}
        m = {k[1]: v for k, v in data[1] if k[0] == "symbol"}
        if b"amount" in m and m[b"amount"][0] == "i128":
            return m[b"amount"][1]
    return None


def _result_ok(b64, path):
    try:
        r = xs.R(base64.b64decode(_b64(b64, path)))
        r.i64()
        code = r.i32()
        if code == 1:                       # txFEE_BUMP_INNER_SUCCESS: InnerTransactionResultPair
            r.take(32)
            r.i64()
            return r.i32() == 0
        return code == 0
    except xs.StellarRefusal as e:
        raise Refusal("%s: %s" % (path, e))


def verify(doc, http_keys=None, signer_trust=None):
    _obj(doc, "bundle", ("bundle_version", "payment_payload"), ("payment_required", "settlement", "chain_tx",
                                                                 "facilitator", "provenance", "exchange",
                                                                 "exchange_mcp", "exchange_a2a"))
    p = "payment_payload"
    pp = _obj(doc[p], p, ("x402Version", "accepted", "payload"), ("resource", "extensions"))
    if _int_json(pp["x402Version"], p + ".x402Version") != 2:
        raise Unsupported("%s.x402Version %r (XLM: v2 only)" % (p, pp["x402Version"]))
    if "extensions" in pp and not isinstance(pp["extensions"], dict):
        raise Refusal("%s.extensions: not an object" % p)
    resource_url = None
    if "resource" in pp:
        resource_url = _str(resource_info(pp["resource"], p + ".resource")["url"],
                            p + ".resource.url")
    acc = parse_requirements(pp["accepted"], p + ".accepted")
    net = acc["network"]
    env = _envelope(_b64(_obj(pp["payload"], p + ".payload", ("transaction",))["transaction"], p + ".payload.transaction"),
                    p + ".payload.transaction")
    res, notes = {}, []
    res["G1"], frm = _g1(env, acc)
    res["G2"] = _g2(env, acc, frm, net) if res["G1"] == "verified" else "not_evaluated:after_G1"
    res["K6"] = "verified" if acc["amount"] > 0 else "failed:zero_amount"         # SPEC section 6, our rule
    if not acc["sponsored"]:
        notes.append("extra.areFeesSponsored is false: XLM § says the non-sponsored flow 'will be added later'; "
                     "the checks below are the sponsored ones")
    # K4 offered in payment_required
    if "payment_required" in doc:
        pr, prn = payment_required_obj(doc["payment_required"], "payment_required", ("x402Version", "resource", "accepts"),
                                       ("error", "extensions"))
        notes += prn   # SPEC 32.14
        if _int_json(pr["x402Version"], "payment_required.x402Version") != 2:
            raise Unsupported("payment_required.x402Version %r (2 only)" % (pr["x402Version"],))
        if not isinstance(pr["accepts"], list) or not pr["accepts"] or not all(isinstance(a, dict) for a in pr["accepts"]):
            raise Refusal("payment_required.accepts: not a non-empty array of objects")
        resource_info(pr["resource"], "payment_required.resource")
        if "extensions" in pr and not isinstance(pr["extensions"], dict):
            raise Refusal("payment_required.extensions: not an object")
        if "error" in pr and not isinstance(pr["error"], str):
            raise Refusal("payment_required.error: not a string")
        res["K4"] = "verified" if any(_json_eq(pp["accepted"], a) for a in pr["accepts"]) else "failed:accepted_not_offered"
        if resource_url is not None and resource_url != _str(pr["resource"]["url"], "payment_required.resource.url"):
            res["K4"] = "failed:resource_url_mismatch"
    else:
        res["K4"] = "not_evaluated:absent:no_payment_required"
    # T1 settlement reply (x402 v2 5.3.2; XLM Phase 3: transaction = 64-character hex)
    st_id = None
    if "settlement" in doc:
        st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network"),
                  ("errorReason", "payer", "amount", "extensions"))
        if not isinstance(st["success"], bool):
            raise Refusal("settlement.success: not a boolean")
        for k in ("errorReason",):
            if k in st and not isinstance(st[k], str):
                raise Refusal("settlement.%s: not a string" % k)
        if "extensions" in st and not isinstance(st["extensions"], dict):
            raise Refusal("settlement.extensions: not an object")
        tx = _str(st["transaction"], "settlement.transaction") if st["transaction"] != "" else ""
        if st["success"] is not True:
            res["T1"] = ("not_evaluated:settlement_pending" if st.get("errorReason") == "settlement_pending"
                         else "failed:settlement_not_successful")
        elif st["network"] != net:
            res["T1"] = "failed:settlement_network_not_accepted"
        elif not HEX64.match(tx):
            res["T1"] = "failed:transaction_not_64_hex"
        elif "payer" in st and st["payer"] != frm:
            res["T1"] = "failed:settlement_payer_mismatch"
        elif "amount" in st and _amount(st["amount"], "settlement.amount") != acc["amount"]:
            res["T1"] = "failed:settlement_amount_mismatch"
        else:
            res["T1"] = "verified"
        st_id = tx if HEX64.match(tx) else None
    else:
        res["T1"] = "not_evaluated:absent:no_settlement"
    # chain: the settled transaction (declared RPC data: getTransaction)
    settled_by, tx_id = [], None
    if "chain_tx" in doc:
        q = "chain_tx"
        ct = _obj(doc[q], q, ("ledger", "status", "envelopeXdr", "resultXdr", "contractEventsXdr"))
        ledger = _int_json(ct["ledger"], q + ".ledger")
        if ledger <= 0 or ledger >= 1 << 32:
            raise Refusal("%s.ledger: not a ledger number" % q)
        if ct["status"] not in ("SUCCESS", "FAILED"):
            raise Refusal("%s.status: not SUCCESS or FAILED" % q)
        cenv = _envelope(_b64(ct["envelopeXdr"], q + ".envelopeXdr"), q + ".envelopeXdr")
        if "not_invoke" in cenv:
            raise Refusal("%s.envelopeXdr: not one invokeHostFunction" % q)
        ok = _result_ok(ct["resultXdr"], q + ".resultXdr")
        events = _events(ct, q)
        tx_id = xs.tx_hash(cenv, net)
        csrc = [xs.strkey_encode("G", cenv["tx"]["source"]["key"])]
        if cenv["type"] == 5:
            csrc.append(xs.strkey_encode("G", cenv["fee_source"]["key"]))
        cop = cenv["tx"]["ops"][0]
        if cop["source"] is not None:
            csrc.append(xs.strkey_encode("G", cop["source"]["key"]))
        settled_by = sorted(set(csrc))
        # C1 the facilitator copies the operation and its auth entries (XLM Settlement Phase 1)
        res["C1"] = ("not_evaluated:after_G1" if res["G1"] != "verified" else
                     "verified" if [o["fn"] for o in cenv["tx"]["ops"]] == [env["tx"]["ops"][0]["fn"]] and
                     [a["raw"] for a in cop["auth"]] == [a["raw"] for a in env["tx"]["ops"][0]["auth"]]
                     and len(cenv["tx"]["ops"]) == 1 else "failed:chain_tx_not_the_payload")
        # C2 the transaction id and its outcome
        if st_id is not None and st_id != tx_id:
            res["C2"] = "failed:settlement_names_another_transaction"
        elif ct["status"] != "SUCCESS" or not ok:
            res["C2"] = "failed:transaction_failed"
            if res["T1"] == "verified":
                res["T1"] = "failed:settlement_reported_success_but_failed"
        else:
            res["C2"] = "verified"
        # C3 the asset's transfer events: exactly the payment, no other balance change (XLM §4, §5)
        tr = [e for e in events if e["topics"] and e["topics"][0] == ("symbol", b"transfer")]
        mine = [e for e in tr if e["contract"] == acc["asset"] and len(e["topics"]) >= 3
                and e["topics"][1][0] == "address" and xs.address_str(e["topics"][1][1]) == frm
                and e["topics"][2][0] == "address" and xs.address_str(e["topics"][2][1]) == acc["pay_to"]
                and _amount_of(e["data"]) == acc["amount"]]
        res["C3"] = ("not_evaluated:after_G1" if frm is None else
                     "failed:no_matching_transfer_event" if not mine else
                     "failed:more_than_one_matching_transfer_event" if len(mine) > 1 else
                     "failed:other_transfer_events" if len(tr) != 1 else "verified")
        # G3 expiration (XLM §3), at the settlement ledger: the verify-time ledger is not in the bundle
        if res["G1"] == "verified":
            bound = math.ceil(acc["max_timeout"] / LEDGER_SECONDS)
            g3 = "verified"
            for e in env["tx"]["ops"][0]["auth"]:
                x = e["credentials"].get("expiration")
                if x is not None and x < ledger:
                    g3 = "failed:auth_expired_before_settlement"
                elif x is not None and x > ledger + bound:
                    g3 = "failed:expiration_too_far"
            res["G3"] = g3
            # G4 facilitator safety (XLM §4)
            auth_addrs = {xs.address_str(e["credentials"]["address"]) for e in cop["auth"] if "address" in e["credentials"]}
            psrc = {xs.strkey_encode("G", env["tx"]["source"]["key"])}
            if env["tx"]["ops"][0]["source"] is not None:
                psrc.add(xs.strkey_encode("G", env["tx"]["ops"][0]["source"]["key"]))
            res["G4"] = ("failed:facilitator_is_payer" if frm in settled_by else
                         "failed:facilitator_in_auth" if auth_addrs & set(settled_by) else
                         "failed:unsafe_tx_or_op_source" if psrc & set(settled_by) else "verified")
        else:
            res["G3"] = res["G4"] = "not_evaluated:after_G1"
        notes.append("chain_tx is the RPC's getTransaction reply (declared): the transaction id is recomputed from its "
                     "envelope; no ledger header binds it here (block_bound false)")
    else:
        for k in ("C1", "C2", "C3", "G3", "G4"):
            res[k] = "not_evaluated:absent:no_chain_tx"
    # F2 the declared facilitator's signers (as SPEC Amendment 0.3.3 part 3)
    if "facilitator" in doc:
        fc = _obj(doc["facilitator"], "facilitator", ("signers", "source", "fetched"))
        if not isinstance(fc["signers"], list) or not 1 <= len(fc["signers"]) <= 256:
            raise Refusal("facilitator.signers: not a list of 1..256 accounts")
        signers = {_addr(a, "facilitator.signers[]", ("G",)) for a in fc["signers"]}
        _str(fc["source"], "facilitator.source")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", _str(fc["fetched"], "facilitator.fetched")):
            raise Refusal("facilitator.fetched: not YYYY-MM-DDTHH:MM:SSZ")
        res["F2"] = ("not_evaluated:absent:no_chain_tx" if not settled_by else
                     "verified" if set(settled_by) <= signers else "failed:settled_by_not_a_facilitator_signer")
    else:
        res["F2"] = "not_evaluated:absent:no_facilitator"
    xr, xn, xm = exchange_checks(doc, http_keys)
    if xr:
        res.update(xr)
        notes += xn
    import apc_transport
    tr2, tn, tm = apc_transport.check(doc)
    res.update(tr2)
    notes += tn
    from apc_verify import offer_receipt_checks          # SPEC 0.11: signed offers and receipts, any network
    pr_doc, st_doc = doc.get("payment_required"), doc.get("settlement")
    orr, orn, orm = offer_receipt_checks(doc, {
        "evm": False, "family": "stellar", "network": net, "scheme": "exact", "asset": acc["asset"], "pay_to": acc["pay_to"],
        "amount": str(acc["amount"]), "resource_url": resource_url if resource_url is not None else
        (pr_doc["resource"]["url"] if isinstance(pr_doc, dict) else None), "payer": frm, "transaction": st_id,
        "success": st_doc["success"] if isinstance(st_doc, dict) else None, "block_time": None,
        "accepts": pr_doc["accepts"] if isinstance(pr_doc, dict) else None}, signer_trust)
    res.update(orr)
    notes += orn
    if orm is not None:
        tm = dict(tm, offer_receipt=orm)
    import apc_payid
    pir, pin = apc_payid.check(doc)
    res.update(pir)
    notes += pin
    from apc_verify import builder_code_checks          # SPEC 0.16.1: BC1 declarations (no ERC-8021 calldata here)
    bcr, bcn, bcm = builder_code_checks(doc, None, evm=False)
    res.update(bcr)
    notes += bcn
    if bcm is not None:
        tm = dict(tm, builder_code=bcm)
    failed = sorted(k for k, x in res.items() if x.startswith("failed"))
    absent = sorted(k for k, x in res.items() if x.startswith("not_evaluated:absent:"))
    open_ = sorted(k for k, x in res.items() if x.startswith("not_evaluated") and k not in absent)
    verdict = "chain_failed" if failed else ("chain_incomplete" if open_ else "chain_verified")
    pv, pn = provenance(doc)
    if pn:
        notes.append(pn)
    return {"verdict": verdict, "checks": res, "failed": failed, "not_evaluated": open_, "absent": absent,
            "notes": notes, "payer": frm, "transaction_id": tx_id, "settled_by": settled_by or None,
            "block_bound": False, "provenance": pv, "exchange": xm, **tm}
