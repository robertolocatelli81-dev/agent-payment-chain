"""SPEC 0.16 (section 26): x402 `exact` on the XRP Ledger, bundle apc-0.16. Source: x402-foundation/x402
specs/schemes/exact/scheme_exact_xrpl.md (local copy sources/x402_schemes_20261026). The facilitator verification
rules (MUST) 1-10 that need no live ledger state, the settled transaction, and (optional) the transaction's place in a
validated ledger: SHAMap root = the header's transaction_hash, header hash = a ledger hash the reader trusts."""
import hashlib
import re

import apc_xrpl as xr
from apc_verify import (Refusal, Unsupported, _int_json, _json_eq, _obj, _str, builder_code_checks, exchange_checks,
                        offer_receipt_checks, provenance, resource_info)

NETWORK = re.compile(r"xrpl:(0|[1-9][0-9]{0,9})\Z")
HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
EXTRA = ("areFeesSponsored", "assetTransferMethod", "invoiceId", "destinationTag", "issuer")
TF_PARTIAL_PAYMENT = 0x00020000
TES_SUCCESS = 0


def _blob(v, path):
    _str(v, path)
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", v):
        raise Refusal("%s: not hex" % path)
    return bytes.fromhex(v)


def _decode(b, path):
    try:
        return xr.decode(b)
    except xr.XrplError as e:
        raise Refusal("%s: not a canonical XRPL object (%s)" % (path, e))


def parse_requirements(v, path):
    _obj(v, path, ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"))
    if _str(v["scheme"], path + ".scheme") != "exact":
        raise Unsupported("%s.scheme %r (apc-0.16: exact only)" % (path, v["scheme"]))
    m = NETWORK.match(_str(v["network"], path + ".network"))
    if not m or int(m.group(1)) >= 1 << 32:
        raise Unsupported("%s.network %r (apc-0.16: xrpl:<uint32>)" % (path, v["network"]))
    ex = _obj(v["extra"], path + ".extra", ("areFeesSponsored",), EXTRA[1:])
    if ex["areFeesSponsored"] is not False:
        raise Refusal("%s.extra.areFeesSponsored: must be false (XRPL exact)" % path)
    method = ex.get("assetTransferMethod")
    if method is not None and method not in ("sequence", "ticketSequence"):
        raise Refusal("%s.extra.assetTransferMethod %r: not sequence or ticketSequence" % (path, method))
    for k in ("invoiceId",):
        if k in ex:
            _str(ex[k], "%s.extra.%s" % (path, k))
    if "destinationTag" in ex and not 0 <= _int_json(ex["destinationTag"], path + ".extra.destinationTag") < 1 << 32:
        raise Refusal("%s.extra.destinationTag: not a uint32" % path)
    mt = _int_json(v["maxTimeoutSeconds"], path + ".maxTimeoutSeconds")
    if mt <= 0 or mt > 1 << 31:
        raise Refusal("%s.maxTimeoutSeconds: not a positive integer" % path)
    try:
        pay_to = xr.account_id(_str(v["payTo"], path + ".payTo"))
    except xr.XrplError:
        raise Refusal("%s.payTo: not an XRPL classic address" % path)
    r = {"network": v["network"], "network_id": int(m.group(1)), "pay_to": pay_to, "pay_to_s": v["payTo"],
         "max_timeout": mt, "method": method, "extra": ex}
    asset = _str(v["asset"], path + ".asset")
    if asset == "XRP":
        if not re.fullmatch(r"(0|[1-9][0-9]{0,18})", _str(v["amount"], path + ".amount")) or int(v["amount"]) > 10 ** 17:
            raise Refusal("%s.amount: not integer drops" % path)
        if "issuer" in ex:
            raise Refusal("%s.extra.issuer: present for XRP" % path)
        r.update(kind="xrp", drops=int(v["amount"]))
    else:
        cur = xr.currency_bytes(asset)
        val = xr.decimal_parts(_str(v["amount"], path + ".amount"))
        if cur is None or val is None:
            raise Refusal("%s.asset / amount: not a 3-character or 160-bit currency and a decimal value" % path)
        if "issuer" not in ex:
            raise Refusal("%s.extra.issuer: required for an issued currency" % path)
        try:
            iss = xr.account_id(_str(ex["issuer"], path + ".extra.issuer"))
        except xr.XrplError:
            raise Refusal("%s.extra.issuer: not an XRPL classic address" % path)
        r.update(kind="iou", currency=cur, issuer=iss, value=val)
    return r


def _u(vals, name):
    v = vals.get(name)
    return int.from_bytes(v, "big") if isinstance(v, bytes) else None


def rules(acc, blob):
    """scheme_exact_xrpl.md Facilitator Verification Rules 2-10 on the signed blob."""
    res, notes = {}, []
    fields, vals = _decode(blob, "payment_payload.payload.signedTxBlob")
    acct = vals.get("Account")
    payer = xr.classic_address(acct) if isinstance(acct, bytes) else None
    # R3 transaction type (rule 3), R4 destination (rule 4)
    res["R3"] = "verified" if _u(vals, "TransactionType") == xr.TX_TYPES["Payment"] else "failed:not_a_payment"
    dt = acc["extra"].get("destinationTag")
    res["R4"] = ("failed:destination_not_payTo" if vals.get("Destination") != acc["pay_to"] else
                 "failed:destination_tag_mismatch" if dt is not None and _u(vals, "DestinationTag") != dt else "verified")
    # R5 network binding (rule 5)
    nid = _u(vals, "NetworkID")
    res["R5"] = (("failed:network_id_present_for_a_standard_network" if nid is not None else "verified")
                 if acc["network_id"] <= 1024 else
                 ("verified" if nid == acc["network_id"] else "failed:network_id_mismatch"))
    # R6 amount (rule 6): the binary form carries Amount (DeliverMax is its API v2 JSON name)
    am, flags = vals.get("Amount"), _u(vals, "Flags") or 0
    if am is None:
        res["R6"] = "failed:no_amount"
    elif acc["kind"] == "xrp":
        res["R6"] = ("failed:amount_not_xrp" if am[0] != "xrp" else
                     "failed:amount_mismatch" if am[1] != acc["drops"] else
                     "failed:send_max_for_xrp" if "SendMax" in vals else
                     "failed:paths_present" if "Paths" in vals else
                     "failed:deliver_min_present" if "DeliverMin" in vals else "verified")
    else:
        sm = vals.get("SendMax")
        try:
            ok = am[0] == "iou" and am[2] == acc["currency"] and am[3] == acc["issuer"] and \
                xr.same_value(xr.iou_value(am[1]), acc["value"])
            smok = sm is not None and sm[0] == "iou" and sm[2] == acc["currency"] and sm[3] == acc["issuer"] and \
                xr.compare_value(xr.iou_value(sm[1]), xr.iou_value(am[1])) >= 0
        except xr.XrplError:
            ok = smok = False
        res["R6"] = ("failed:amount_mismatch" if not ok else
                     "failed:send_max_policy" if not smok else
                     "failed:paths_present" if "Paths" in vals else
                     "failed:deliver_min_present" if "DeliverMin" in vals else "verified")
    if res["R6"] == "verified" and flags & TF_PARTIAL_PAYMENT:
        res["R6"] = "failed:partial_payment_flag"
    # R7 expiry and sequencing (rule 7): the bounds against the current ledger and account state are live
    method = acc["method"] or "sequence"
    seq, tick = _u(vals, "Sequence"), _u(vals, "TicketSequence")
    res["R7"] = ("failed:no_last_ledger_sequence" if "LastLedgerSequence" not in vals else
                 "failed:ticket_sequence_with_sequence_method" if method == "sequence" and tick is not None else
                 "failed:ticket_method_needs_sequence_0_and_a_ticket" if method == "ticketSequence" and
                 (seq != 0 or tick is None) else "verified")
    notes.append("XRPL rule 7: Sequence = the account's current one, an available ticket, and LastLedgerSequence <= "
                 "the current validated ledger + ceil(maxTimeoutSeconds / 5) + 2 need the live ledger at verification")
    # R8 invoice binding (rule 8)
    inv = acc["extra"].get("invoiceId")
    res["R8"] = ("verified" if inv is None else                      # nothing to bind
                 "failed:invoice_id_missing" if vals.get("InvoiceID") is None else
                 "verified" if vals["InvoiceID"] == hashlib.sha256(inv.encode("utf-8")).digest() else
                 "failed:invoice_id_mismatch")
    if inv is None and "InvoiceID" in vals:
        notes.append("the transaction carries an InvoiceID and the requirements name no invoiceId")
    # R9 safety (rule 9): Delegate, Memos; the Fee bound is the facilitator's policy
    res["R9"] = ("failed:delegate_present" if "Delegate" in vals else
                 "failed:memos_present" if "Memos" in vals else "verified")
    notes.append("XRPL rule 9: the Fee bound is the facilitator's policy (fee in the blob: %s drops)" %
                 (vals["Fee"][1] if isinstance(vals.get("Fee"), tuple) and vals["Fee"][0] == "xrp" else "?"))
    # R10 signature (rule 10), and the signer is the account's master key
    sig = xr.verify_signature(blob, fields, vals)
    if sig == "verified" and xr.key_account(vals["SigningPubKey"]) != acct:
        sig = "not_evaluated:regular_key_needs_account_state"
    res["R10"] = sig
    return res, notes, payer, vals


def verify(doc, l1_checkpoint=None, http_keys=None, signer_trust=None):
    _obj(doc, "bundle", ("bundle_version", "payment_payload"), ("payment_required", "settlement", "chain_tx",
                                                                 "inclusion", "provenance", "exchange"))
    p = "payment_payload"
    pp = _obj(doc[p], p, ("x402Version", "accepted", "payload"), ("resource", "extensions"))
    if _int_json(pp["x402Version"], p + ".x402Version") != 2:
        raise Unsupported("%s.x402Version %r (XRPL: v2 only)" % (p, pp["x402Version"]))
    if "extensions" in pp and not isinstance(pp["extensions"], dict):
        raise Refusal("%s.extensions: not an object" % p)
    resource_url = None
    if "resource" in pp:
        resource_url = _str(resource_info(pp["resource"], p + ".resource")["url"],
                            p + ".resource.url")
    acc = parse_requirements(pp["accepted"], p + ".accepted")
    blob = _blob(_obj(pp["payload"], p + ".payload", ("signedTxBlob",))["signedTxBlob"], p + ".payload.signedTxBlob")
    res, notes, payer, vals = rules(acc, blob)
    tid = xr.tx_id(blob)
    if "payment_required" in doc:
        pr = _obj(doc["payment_required"], "payment_required", ("x402Version", "resource", "accepts"), ("error", "extensions"))
        if _int_json(pr["x402Version"], "payment_required.x402Version") != 2:
            raise Unsupported("payment_required.x402Version %r (2 only)" % (pr["x402Version"],))
        if not isinstance(pr["accepts"], list) or not pr["accepts"] or not all(isinstance(a, dict) for a in pr["accepts"]):
            raise Refusal("payment_required.accepts: not a non-empty array of objects")
        purl = _str(resource_info(pr["resource"], "payment_required.resource")["url"],
                    "payment_required.resource.url")
        if "extensions" in pr and not isinstance(pr["extensions"], dict) or "error" in pr and not isinstance(pr["error"], str):
            raise Refusal("payment_required.error / extensions: not a string / an object")
        # rule 1: accepted matches the requirements
        res["K4"] = ("failed:accepted_not_offered" if not any(_json_eq(pp["accepted"], a) for a in pr["accepts"]) else
                     "failed:resource_url_mismatch" if resource_url is not None and resource_url != purl else "verified")
    else:
        res["K4"] = "not_evaluated:absent:no_payment_required"
    st_id = None
    if "settlement" in doc:
        st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network"),
                  ("errorReason", "payer", "amount", "extensions"))
        if not isinstance(st["success"], bool) or "errorReason" in st and not isinstance(st["errorReason"], str) or \
                "extensions" in st and not isinstance(st["extensions"], dict):
            raise Refusal("settlement: success / errorReason / extensions outside the grammar")
        tx = _str(st["transaction"], "settlement.transaction") if st["transaction"] != "" else ""
        res["T1"] = ("failed:settlement_not_successful" if st["success"] is not True else
                     "failed:settlement_network_not_accepted" if st["network"] != acc["network"] else
                     "failed:transaction_not_64_hex" if not HEX64.match(tx) else
                     "failed:settlement_names_another_transaction" if tx.upper() != tid else
                     "failed:settlement_payer_mismatch" if "payer" in st and st["payer"] != payer else "verified")
        st_id = tx.upper() if HEX64.match(tx) else None
    else:
        res["T1"] = "not_evaluated:absent:no_settlement"
    meta_blob, ledger_seen = None, None
    if "chain_tx" in doc:
        ct = _obj(doc["chain_tx"], "chain_tx", ("tx_blob", "meta", "ledger_index"))
        cblob, meta_blob = _blob(ct["tx_blob"], "chain_tx.tx_blob"), _blob(ct["meta"], "chain_tx.meta")
        ledger_seen = _int_json(ct["ledger_index"], "chain_tx.ledger_index")
        _, mv = _decode(meta_blob, "chain_tx.meta")
        res["C1"] = "verified" if cblob == blob else "failed:settled_blob_not_the_payload"   # the facilitator submits it as signed
        code = _u(mv, "TransactionResult")
        res["C2"] = ("failed:no_transaction_result" if code is None else "verified" if code == TES_SUCCESS else
                     "failed:transaction_result_%s" % xr.RESULTS.get(code, code))
        if res["C2"] != "verified" and res["T1"] == "verified":
            res["T1"] = "failed:settlement_reported_success_but_failed"
        da = mv.get("DeliveredAmount")
        if da is None and not (_u(vals, "Flags") or 0) & TF_PARTIAL_PAYMENT and res["C2"] == "verified":
            # the binary metadata carries DeliveredAmount only when the server stores it; "if the transaction was
            # successful, then the destination received [Amount] -- except if the transaction was a partial payment"
            # (xrpl-dev-portal 94abc77 metadata.md 269)
            da = vals.get("Amount")
            notes.append("chain_tx.meta has no DeliveredAmount: the delivered amount is the Amount of a successful "
                         "payment without tfPartialPayment (xrpl-dev-portal metadata.md); for tokens the docs say it "
                         "'may be slightly different ... due to rounding' (partial-payments.md 64)")
        try:
            res["C3"] = ("failed:no_delivered_amount" if da is None else
                         ("verified" if da == ("xrp", acc["drops"]) else "failed:delivered_amount_mismatch") if acc["kind"] == "xrp"
                         else ("verified" if da[0] == "iou" and da[2:] == (acc["currency"], acc["issuer"]) and
                               xr.same_value(xr.iou_value(da[1]), acc["value"]) else "failed:delivered_amount_mismatch"))
        except xr.XrplError:
            res["C3"] = "failed:delivered_amount_mismatch"
        lls = _u(vals, "LastLedgerSequence")
        res["C4"] = ("not_evaluated:after_R7" if lls is None else
                     "verified" if ledger_seen <= lls else "failed:validated_after_last_ledger_sequence")
    else:
        for k in ("C1", "C2", "C3", "C4"):
            res[k] = "not_evaluated:absent:no_chain_tx"
    block_bound = False
    if "inclusion" in doc:
        inc = _obj(doc["inclusion"], "inclusion", ("ledger_data", "transactions"))
        try:
            hdr = xr.ledger_header(_blob(inc["ledger_data"], "inclusion.ledger_data"))
        except xr.XrplError as e:
            raise Refusal("inclusion.ledger_data: %s" % e)
        if not isinstance(inc["transactions"], list) or not 1 <= len(inc["transactions"]) <= 100000:
            raise Refusal("inclusion.transactions: not a list of 1..100000 entries")
        leaves = {}
        for i, t in enumerate(inc["transactions"]):
            t = _obj(t, "inclusion.transactions[%d]" % i, ("tx_blob", "meta"))
            try:
                k, lf = xr.tx_leaf(_blob(t["tx_blob"], "inclusion.tx_blob"), _blob(t["meta"], "inclusion.meta"))
            except xr.XrplError as e:
                raise Refusal("inclusion.transactions[%d]: %s" % (i, e))
            if k in leaves:
                raise Refusal("inclusion.transactions: a transaction twice")
            leaves[k] = lf
        try:
            me = xr.tx_leaf(blob, meta_blob) if meta_blob is not None else None
        except xr.XrplError as e:
            raise Refusal("chain_tx: %s" % e)
        res["I1"] = ("not_evaluated:absent:no_chain_tx" if me is None else
                     "failed:transaction_not_in_the_set" if leaves.get(me[0]) != me[1] else
                     "failed:set_not_the_ledger_transaction_hash" if xr.shamap_root(leaves) != hdr["transaction_hash"] else
                     "failed:ledger_index_not_chain_tx" if hdr["ledger_index"] != ledger_seen else "verified")
        if l1_checkpoint is None:
            res["I2"] = "not_evaluated:absent:no_trusted_ledger_hash"
        else:
            cp = str(l1_checkpoint).upper()
            cp = cp[2:] if cp.startswith("0X") else cp
            res["I2"] = "verified" if cp == hdr["hash"] else "failed:ledger_hash_not_the_trusted_one"
            block_bound = res["I1"] == res["I2"] == "verified"
        notes.append("inclusion: the transaction set hashes to the header's transaction_hash and the header to %s; "
                     "that a validator quorum validated this ledger is the reader's trusted hash, not checked here" % hdr["hash"])
    else:
        res["I1"] = res["I2"] = "not_evaluated:absent:no_inclusion"
    xr_, xn, xm = exchange_checks(doc, http_keys)
    if xr_:
        res.update(xr_)
        notes += xn
    # SPEC 0.16.1: the amendments that hold for every bundle version, by the code of apc-0.1 to apc-0.3
    bcr, bcn, bcm = builder_code_checks(doc, None, evm=False)          # BC1 declarations, no ERC-8021 calldata
    res.update(bcr)
    notes += bcn
    import apc_payid                                                    # PI1, section 15
    pir, pin = apc_payid.check(doc)
    res.update(pir)
    notes += pin
    pr_doc, st_doc = doc.get("payment_required"), doc.get("settlement")
    orr, orn, orm = offer_receipt_checks(doc, {                       # OR1-OR3, section 13
        "evm": False, "family": "xrpl", "network": acc["network"], "scheme": "exact", "asset": pp["accepted"]["asset"],
        "pay_to": pp["accepted"]["payTo"], "amount": pp["accepted"]["amount"],
        "resource_url": resource_url if resource_url is not None else
        (pr_doc["resource"]["url"] if isinstance(pr_doc, dict) else None), "payer": payer,
        "transaction": st_id, "success": st_doc["success"] if isinstance(st_doc, dict) else None, "block_time": None,
        "accepts": pr_doc["accepts"] if isinstance(pr_doc, dict) else None}, signer_trust)
    res.update(orr)
    notes += orn
    failed = sorted(k for k, x in res.items() if x.startswith("failed"))
    absent = sorted(k for k, x in res.items() if x.startswith("not_evaluated:absent:"))
    open_ = sorted(k for k, x in res.items() if x.startswith("not_evaluated") and k not in absent)
    verdict = "chain_failed" if failed else ("chain_incomplete" if open_ else "chain_verified")
    pv, pn = provenance(doc)
    if pn:
        notes.append(pn)
    return {"verdict": verdict, "checks": res, "failed": failed, "not_evaluated": open_, "absent": absent, "notes": notes,
            "payer": payer, "transaction_id": tid, "settlement_transaction": st_id, "block_bound": block_bound,
            "provenance": pv, "exchange": xm, **({"builder_code": bcm} if bcm is not None else {}),
            **({"offer_receipt": orm} if orm is not None else {})}
