"""agent-payment-chain, SPEC 0.5 (SPEC.md section 7): the x402 `exact` scheme on Solana, bundle apc-0.5. Called by
apc_verify.verify_bundle; standard library only (the primitives are in apc_solana.py)."""
import base64
import binascii
import json
import re

import apc_solana as sol
from apc_verify import (Refusal, Unsupported, _int_json, _json_eq, _obj, _str, exchange_checks, payment_required_obj,
                        provenance, resource_info)

NETWORK = re.compile(r"solana:[1-9A-HJ-NP-Za-km-z]{32}\Z")
UINT = re.compile(r"(0|[1-9][0-9]*)\Z")
LIGHTHOUSE = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
KNOWN_TOP = {sol.COMPUTE_BUDGET, sol.SPL_TOKEN, sol.TOKEN_2022, sol.MEMO_PROGRAM, LIGHTHOUSE}
ZERO_SIG = bytes(64)


def _key(v, path):
    try:
        sol.b58decode(_str(v, path), 32)
    except sol.SolRefusal as e:
        raise Refusal("%s: not a canonical base58 address of 32 bytes (%s)" % (path, e))
    return v


def _u64(v, path):
    # the digit bound keeps int() under its own limit (4300 digits, CPython >= 3.9.14 / 3.11): refused, not a crash
    if not isinstance(v, str) or not UINT.match(v) or len(v) > 20 or int(v) >= 1 << 64:
        raise Refusal("%s: not a decimal u64 without leading zeros" % path)
    return int(v)


def _uint_json(v, path):
    if _int_json(v, path) < 0:
        raise Refusal("%s: negative" % path)
    return v


def _b64(v, path):
    s = _str(v, path)
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise Refusal("%s: not base64 (RFC 4648, padded)" % path)
    if base64.b64encode(b).decode() != s:
        raise Refusal("%s: not canonical base64" % path)
    return b


def _parse(raw, path):
    try:
        tx = sol.parse_tx(raw)
    except sol.SolRefusal as e:
        raise Refusal("%s: not a Solana transaction (%s)" % (path, e))
    # runtime rules on the header: account 0 is a writable signer (the fee payer), the counts fit the keys
    nsig, ro_signed, ro_unsigned = tx["header"]
    # nsig 0 fails the first condition; nsig above the key count makes the right side of the second negative
    if ro_signed >= nsig or ro_unsigned > len(tx["keys"]) - nsig:
        raise Refusal("%s: header %s does not fit %d keys (account 0 must be a writable signer)"
                      % (path, list(tx["header"]), len(tx["keys"])))
    if len(set(tx["keys"])) != len(tx["keys"]):
        raise Refusal("%s: a key appears twice" % path)
    return tx


def parse_requirements(v, path):
    _obj(v, path, ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"))
    if _str(v["scheme"], path + ".scheme") != "exact":
        raise Unsupported("%s.scheme %r (exact only)" % (path, v["scheme"]))
    if not NETWORK.match(_str(v["network"], path + ".network")):
        if v["network"].startswith("solana:"):
            raise Refusal("%s.network %r: not solana:<32 base58 characters>" % (path, v["network"]))
        raise Unsupported("%s.network %r (apc-0.5: solana only)" % (path, v["network"]))
    ex = v["extra"]
    if not isinstance(ex, dict):
        raise Refusal("%s.extra: not an object" % path)
    if "feePayer" not in ex:
        raise Refusal("%s.extra.feePayer missing (SVM: required)" % path)
    r = {"network": v["network"], "amount": _u64(v["amount"], path + ".amount"), "asset": _key(v["asset"], path + ".asset"),
         "pay_to": _key(v["payTo"], path + ".payTo"), "fee_payer": _key(ex["feePayer"], path + ".extra.feePayer"),
         "max_timeout": _int_json(v["maxTimeoutSeconds"], path + ".maxTimeoutSeconds"), "memo": None, "notes": []}
    if "memo" in ex:
        m = _str(ex["memo"], path + ".extra.memo")
        if len(m.encode("utf-8")) > 256:
            raise Refusal("%s.extra.memo: more than 256 UTF-8 bytes (SVM)" % path)
        r["memo"] = m
    if "recentBlockhash" in ex:
        _key(ex["recentBlockhash"], path + ".extra.recentBlockhash")
    if "lastValidBlockHeight" in ex:
        _u64(ex["lastValidBlockHeight"], path + ".extra.lastValidBlockHeight")
    for k in sorted(set(ex) - {"feePayer", "memo", "recentBlockhash", "lastValidBlockHeight"}):
        r["notes"].append("%s.extra.%s present (scheme-specific, not interpreted)" % (path, k))
    return r


def _inner(meta, path):
    """meta.innerInstructions of an encoding=base64 getTransaction reply -> [(top index, {program, accounts, data})]."""
    out = []
    if not isinstance(meta["innerInstructions"], list):
        raise Refusal("%s.innerInstructions: not an array" % path)
    for i, g in enumerate(meta["innerInstructions"]):
        q = "%s.innerInstructions[%d]" % (path, i)
        _obj(g, q, ("index", "instructions"))
        _uint_json(g["index"], q + ".index")
        if not isinstance(g["instructions"], list):
            raise Refusal("%s.instructions: not an array" % q)
        for j, ix in enumerate(g["instructions"]):
            p = "%s.instructions[%d]" % (q, j)
            _obj(ix, p, ("programIdIndex", "accounts", "data"), ("stackHeight",))
            if not isinstance(ix["accounts"], list):
                raise Refusal("%s.accounts: not an array" % p)
            for a in [ix["programIdIndex"]] + ix["accounts"]:
                _uint_json(a, p)
            if "stackHeight" in ix and ix["stackHeight"] is not None:
                _uint_json(ix["stackHeight"], p + ".stackHeight")
            try:
                data = sol.b58decode(ix["data"]) if ix["data"] != "" else b""
            except sol.SolRefusal:
                raise Refusal("%s.data: not base58" % p)
            out.append((g["index"], {"program": ix["programIdIndex"], "accounts": list(ix["accounts"]), "data": data}))
    return out


def _balances(v, path, nkeys):
    if not isinstance(v, list):
        raise Refusal("%s: not an array" % path)
    out = {}
    for i, b in enumerate(v):
        p = "%s[%d]" % (path, i)
        _obj(b, p, ("accountIndex", "mint", "uiTokenAmount"), ("owner", "programId"))
        if _uint_json(b["accountIndex"], p + ".accountIndex") >= nkeys:
            raise Refusal("%s.accountIndex: out of range" % p)
        u = _obj(b["uiTokenAmount"], p + ".uiTokenAmount", ("amount", "decimals"), ("uiAmount", "uiAmountString"))
        if b["accountIndex"] in out:
            raise Refusal("%s.accountIndex: duplicate" % p)
        # SPEC 29.4: the members read for nothing are still checked to their type (a closed grammar types every member)
        for k in ("owner", "programId"):
            if k in b:
                _key(b[k], "%s.%s" % (p, k))
        if _uint_json(u["decimals"], p + ".uiTokenAmount.decimals") > 255:      # u8 in the SPL Mint account
            raise Refusal("%s.uiTokenAmount.decimals: above 255" % p)
        if "uiAmount" in u and u["uiAmount"] is not None and (isinstance(u["uiAmount"], bool)
                                                             or not isinstance(u["uiAmount"], (int, float))):
            raise Refusal("%s.uiTokenAmount.uiAmount: not a number or null" % p)
        if "uiAmountString" in u and not isinstance(u["uiAmountString"], str):
            raise Refusal("%s.uiTokenAmount.uiAmountString: not a string" % p)
        out[b["accountIndex"]] = (_key(b["mint"], p + ".mint"), _u64(u["amount"], p + ".uiTokenAmount.amount"))
    return out


def verify(doc, http_keys=None, signer_trust=None):
    _obj(doc, "bundle", ("bundle_version", "payment_payload"), ("payment_required", "settlement", "chain_tx",
                                                                 "provenance", "exchange", "exchange_mcp",
                                                                 "exchange_a2a", "mandate"))
    import apc_mandate
    mandate = None
    if "mandate" in doc:                                 # SPEC 31.9: only the ap2-evidence-pack profile, closed
        try:
            mandate = apc_mandate.parse_member(doc["mandate"])
        except ValueError as e:
            raise Refusal(str(e))
    p = "payment_payload"
    pp = _obj(doc[p], p, ("x402Version", "accepted", "payload"), ("resource", "extensions"))
    if _int_json(pp["x402Version"], p + ".x402Version") != 2:
        raise Unsupported("%s.x402Version %r (2 only)" % (p, pp["x402Version"]))
    if "extensions" in pp and not isinstance(pp["extensions"], dict):
        raise Refusal("%s.extensions: not an object" % p)
    resource_url = None
    if "resource" in pp:
        resource_url = _str(resource_info(pp["resource"], p + ".resource")["url"],
                            p + ".resource.url")
    acc = parse_requirements(pp["accepted"], p + ".accepted")
    raw = _b64(_obj(pp["payload"], p + ".payload", ("transaction",))["transaction"], p + ".payload.transaction")
    tx = _parse(raw, p + ".payload.transaction")
    res, notes = {}, list(acc["notes"])
    keys, hdr, ixs = tx["keys"], tx["header"], tx["instructions"]

    # chain_tx first: its lookup tables and inner instructions are read by S2/S3
    ct = ctx = None
    inner, loaded = [], None
    if "chain_tx" in doc:
        q = "chain_tx"
        ct = _obj(doc[q], q, ("slot", "blockTime", "transaction", "meta"))
        _uint_json(ct["slot"], q + ".slot")
        if ct["blockTime"] is not None:
            _uint_json(ct["blockTime"], q + ".blockTime")
        ctx = _parse(_b64(ct["transaction"], q + ".transaction"), q + ".transaction")
        meta = _obj(ct["meta"], q + ".meta", ("err", "fee", "preTokenBalances", "postTokenBalances", "innerInstructions",
                                              "loadedAddresses"))
        _uint_json(meta["fee"], q + ".meta.fee")
        la = _obj(meta["loadedAddresses"], q + ".meta.loadedAddresses", ("writable", "readonly"))
        for k in ("writable", "readonly"):
            if not isinstance(la[k], list):
                raise Refusal("%s.meta.loadedAddresses.%s: not an array" % (q, k))
            for a in la[k]:
                _key(a, "%s.meta.loadedAddresses.%s[]" % (q, k))
        if [len(la["writable"]), len(la["readonly"])] != [sum(len(x["writable"]) for x in ctx["lookups"]),
                                                            sum(len(x["readonly"]) for x in ctx["lookups"])]:
            raise Refusal("%s.meta.loadedAddresses: not the size of the transaction's lookups" % q)
        loaded = la["writable"] + la["readonly"]
        inner = _inner(meta, q + ".meta")
    all_keys = keys + (loaded or [])
    nall = len(keys) + sum(len(x["writable"]) + len(x["readonly"]) for x in tx["lookups"])
    for _, ix in inner:
        if ix["program"] >= nall or any(a >= nall for a in ix["accounts"]):
            raise Refusal("chain_tx.meta.innerInstructions: account index out of range")
    resolved = loaded is not None or not tx["lookups"]

    def name(i):
        return all_keys[i] if i < len(all_keys) else None

    # S1 fee payer and signatures
    s1 = []
    if keys[0] != acc["fee_payer"]:
        s1.append("failed:fee_payer_not_account_0")
    for i in range(hdr[0]):
        sig = tx["signatures"][i]
        if i == 0 and sig == ZERO_SIG:
            continue
        if not sol.ed25519_verify(sol.b58decode(keys[i], 32), tx["message"], sig, "dalek_strict"):      # SPEC 28.1
            s1.append("failed:signer_%d_signature_invalid" % i)
    res["S1"] = next(iter(s1), "verified")

    # S2 exactly one matching TransferChecked (top level from the payload, inner from chain_tx)
    def tc(ix):
        prog = name(ix["program"])
        if prog not in (sol.SPL_TOKEN, sol.TOKEN_2022) or len(ix["data"]) != 10 or ix["data"][0] != 12:
            return None
        if len(ix["accounts"]) < 4:
            raise Refusal("a TransferChecked with fewer than 4 accounts")
        a = [name(k) for k in ix["accounts"][:4]]
        return {"program": prog, "mint": a[1], "destination": a[2], "authority": a[3],
                "amount": int.from_bytes(ix["data"][1:9], "little"), "decimals": ix["data"][9]}

    transfers = [t for t in (tc(ix) for ix in ixs + [x for _, x in inner]) if t]
    atas = {prog: sol.ata(acc["pay_to"], acc["asset"], prog) for prog in (sol.SPL_TOKEN, sol.TOKEN_2022)}
    match = [t for t in transfers if t["mint"] == acc["asset"] and t["destination"] == atas[t["program"]]
             and t["amount"] >= acc["amount"]]
    unknown_top = sorted({keys[ix["program"]] for ix in ixs} - KNOWN_TOP)
    if len(match) == 1:
        res["S2"] = "verified"
        if match[0]["amount"] > acc["amount"]:
            notes.append("S2: the transfer pays %d, more than the %d required (tolerated, SVM 1.4)"
                         % (match[0]["amount"], acc["amount"]))
    elif match:
        res["S2"] = "failed:more_than_one_matching_transfer"
    elif unknown_top and ct is None:
        res["S2"] = "not_evaluated:transfer_may_be_inside_a_program_call"
        notes.append("S2: top-level program(s) %s outside the known set; the transfer may be inside their calls (a smart "
                     "wallet, SVM 3.2): the CPI trace of chain_tx would show it" % ", ".join(unknown_top))
    else:
        res["S2"] = "failed:no_matching_transfer"
    payer = match[0]["authority"] if len(match) == 1 else None

    # S3 fee payer isolation
    every = ixs + [x for _, x in inner]
    if any(ix["program"] == 0 or 0 in ix["accounts"] for ix in every):     # an authority is one of the accounts
        res["S3"] = "failed:fee_payer_in_an_instruction"
    elif not resolved:
        res["S3"] = "not_evaluated:lookup_tables_not_resolved"
    elif keys[0] in (loaded or []):
        res["S3"] = "failed:fee_payer_in_a_lookup_table"
    else:
        res["S3"] = "verified"

    # S4 signer set
    res["S4"] = "verified" if hdr[0] <= 2 else "failed:more_than_two_required_signers"

    # S5 memo
    memos = [ix for ix in ixs if keys[ix["program"]] == sol.MEMO_PROGRAM]
    if acc["memo"] is not None:
        if len(memos) != 1:
            res["S5"] = "failed:memo_count_%d" % len(memos)
        else:
            res["S5"] = "verified" if memos[0]["data"] == acc["memo"].encode("utf-8") else "failed:memo_mismatch"
    else:
        res["S5"] = "verified"
        if not memos:
            notes.append("S5: no Memo instruction (SVM 3.1: a client MUST add one, the facilitator checks it only "
                         "with extra.memo)")

    # S6 cost: notes only (SVM 2.2.1 is a SHOULD)
    limit = price = None
    for ix in ixs:
        if keys[ix["program"]] != sol.COMPUTE_BUDGET:
            continue
        d = ix["data"]
        if d[:1] == b"\x02" and len(d) == 5:
            limit = int.from_bytes(d[1:5], "little")
        elif d[:1] == b"\x03" and len(d) == 9:
            price = int.from_bytes(d[1:9], "little")
        else:
            notes.append("S6: a ComputeBudget instruction other than SetComputeUnitLimit/Price (SVM 2.2.1: SHOULD be "
                         "rejected by a sponsor)")
    if limit is not None and limit > 400000:
        notes.append("S6: compute unit limit %d above the reference 400 000" % limit)
    if price is not None and price > 50000:
        notes.append("S6: compute unit price %d micro-lamports above the reference 50 000" % price)
    if limit is not None:
        notes.append("S6: fee bound %d lamports (5 000 x %d signatures + ceil(price x limit / 10^6))"
                     % (5000 * hdr[0] + -(-(price or 0) * limit // 10 ** 6), hdr[0]))

    # K4 payment_required
    if "payment_required" in doc:
        pr, prn = payment_required_obj(doc["payment_required"], "payment_required", ("x402Version", "resource", "accepts"),
                                       ("error", "extensions"))
        notes += prn   # SPEC 32.14
        if _int_json(pr["x402Version"], "payment_required.x402Version") != 2:     # SPEC 0.5 grammar: 2
            raise Unsupported("payment_required.x402Version %r (2 only)" % (pr["x402Version"],))
        if "error" in pr and not isinstance(pr["error"], str):
            raise Refusal("payment_required.error: not a string")
        if not isinstance(pr["accepts"], list) or not pr["accepts"]:
            raise Refusal("payment_required.accepts: not a non-empty array")
        for i, a in enumerate(pr["accepts"]):
            if not isinstance(a, dict):
                raise Refusal("payment_required.accepts[%d]: not an object" % i)
            if a.get("scheme") == "exact" and str(a.get("network", "")).startswith("solana:"):
                parse_requirements(a, "payment_required.accepts[%d]" % i)
        resource_info(pr["resource"], "payment_required.resource")
        if "extensions" in pr and not isinstance(pr["extensions"], dict):
            raise Refusal("payment_required.extensions: not an object")
        res["K4"] = ("verified" if any(_json_eq(pp["accepted"], a) for a in pr["accepts"])
                     else "failed:accepted_not_offered")
        if resource_url is not None and resource_url != _str(pr["resource"]["url"], "payment_required.resource.url"):
            res["K4"] = "failed:resource_url_mismatch"
    else:
        res["K4"] = "not_evaluated:absent:no_payment_required"

    # T1 settlement reply
    st_id = None
    if "settlement" in doc:
        st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network"),
                  ("payer", "errorReason", "amount", "extensions"))
        if not isinstance(st["success"], bool):
            raise Refusal("settlement.success: not a boolean")
        if "extensions" in st and not isinstance(st["extensions"], dict):
            raise Refusal("settlement.extensions: not an object")
        if "errorReason" in st and not isinstance(st["errorReason"], str):
            raise Refusal("settlement.errorReason: not a string")
        st_payer = _key(st["payer"], "settlement.payer") if "payer" in st else None
        st_amount = _u64(st["amount"], "settlement.amount") if "amount" in st else None
        if st["transaction"] != "":
            try:
                sol.b58decode(_str(st["transaction"], "settlement.transaction"), 64)
            except sol.SolRefusal:
                raise Refusal("settlement.transaction: not base58 of a 64-byte signature")
            st_id = st["transaction"]
        if st["success"] is not True:
            if st.get("errorReason") == "settlement_pending":
                res["T1"] = "not_evaluated:settlement_pending"
            else:
                res["T1"] = "failed:settlement_not_successful"
        elif st["network"] != acc["network"]:
            res["T1"] = "failed:settlement_network_not_accepted"
        elif st_id is None:
            res["T1"] = "failed:settlement_without_transaction"
        else:
            res["T1"] = "verified"
        # payer: x402 v2 5.3.2 says the payer's wallet, the SVM SettlementResponse the fee payer; either is accepted,
        # anything else contradicts the transaction. amount: "the actual amount settled" = the matching transfer's.
        if res["T1"] == "verified" and st_payer is not None and st_payer not in (keys[0], payer):
            res["T1"] = "failed:settlement_payer_mismatch"
        elif res["T1"] == "verified" and st_amount is not None and len(match) == 1 and st_amount != match[0]["amount"]:
            res["T1"] = "failed:settlement_amount_mismatch"
        if st_amount is not None and len(match) != 1:
            notes.append("T1: settlement.amount not compared (no single matching transfer)")
    else:
        res["T1"] = "not_evaluated:absent:no_settlement"

    # C1-C3 the confirmed transaction (declared RPC data)
    tx_id = None
    if ct is None:
        for k in ("C1", "C2", "C3"):
            res[k] = "not_evaluated:absent:no_chain_tx"
    else:
        if ctx["message"] != tx["message"] or ctx["signatures"][1:] != tx["signatures"][1:]:
            res["C1"] = "failed:chain_tx_not_the_payload"
        elif not sol.ed25519_verify(sol.b58decode(keys[0], 32), ctx["message"], ctx["signatures"][0], "dalek_strict"):
            res["C1"] = "failed:fee_payer_signature_invalid"
        else:
            res["C1"] = "verified"
        tx_id = sol.b58encode(ctx["signatures"][0])
        if st_id is not None and st_id != tx_id:
            res["C2"] = "failed:settlement_names_another_transaction"
        elif meta["err"] is not None:
            res["C2"] = "failed:transaction_error"
            notes.append("C2: the transaction failed on chain (meta.err %s): the transfer did not happen"
                         % json.dumps(meta["err"], sort_keys=True))
            if res["T1"] == "verified":         # a verified T1 names a transaction, and this branch has st_id == tx_id
                res["T1"] = "failed:settlement_reported_success_but_failed"
        else:
            res["C2"] = "verified"
        pre = _balances(meta["preTokenBalances"], "chain_tx.meta.preTokenBalances", nall)
        post = _balances(meta["postTokenBalances"], "chain_tx.meta.postTokenBalances", nall)
        if len(match) != 1:
            res["C3"] = "not_evaluated:no_single_matching_transfer"
        else:
            dest = all_keys.index(match[0]["destination"])
            b0, b1 = pre.get(dest, (acc["asset"], 0)), post.get(dest)
            ok = b1 is not None and b0[0] == b1[0] == acc["asset"] and b1[1] - b0[1] >= acc["amount"]
            res["C3"] = "verified" if ok else "failed:balance_delta_short"
        notes.append("chain_tx is the RPC's getTransaction reply (declared): no Solana block header binds a transaction, "
                     "so the execution it shows is not bound to a block (block_bound false)")
    xr, xn, xm = exchange_checks(doc, http_keys)        # SPEC 0.8: the HTTP exchange (X1-X7)
    if xr:
        res.update(xr)
        notes += xn
    import apc_transport                                 # SPEC 0.11.3: the payment over MCP or A2A
    tr, tn, tm = apc_transport.check(doc)
    res.update(tr)
    notes += tn
    import apc_payid                                     # SPEC 0.11.2: payment-identifier
    pir, pin = apc_payid.check(doc)
    res.update(pir)
    notes += pin
    # SPEC 0.11: signed offers and receipts (OR1-OR3)
    from apc_verify import offer_receipt_checks
    pr_doc, st_doc = doc.get("payment_required"), doc.get("settlement")
    orr, orn, orm = offer_receipt_checks(doc, {
        "evm": False, "network": acc["network"], "scheme": "exact", "asset": acc["asset"], "pay_to": acc["pay_to"],
        "amount": str(acc["amount"]),
        "resource_url": resource_url if resource_url is not None else
        (pr_doc["resource"]["url"] if isinstance(pr_doc, dict) else None),
        "payer": payer, "transaction": st_id, "success": st_doc["success"] if isinstance(st_doc, dict) else None,
        "block_time": ct["blockTime"] if ct is not None else None,
        "accepts": pr_doc["accepts"] if isinstance(pr_doc, dict) else None}, signer_trust)
    res.update(orr)
    notes += orn
    from apc_verify import builder_code_checks          # SPEC 0.16.1: BC1 declarations (no ERC-8021 calldata here)
    bcr, bcn, bcm = builder_code_checks(doc, None, evm=False)
    res.update(bcr)
    notes += bcn
    mandate_rep = None
    if mandate is not None:                              # SPEC 31.9: MP1-MP7 with the Memo binding; no proven block time
        from apc_verify import AP2_TSA_CERT
        mr, mn, mandate_rep = apc_mandate.check(mandate, None, acc, None, AP2_TSA_CERT[0], svm={
            "memos": [ix["data"] for ix in memos], "seller_memo": acc["memo"], "amount": acc["amount"],
            "pay_to": acc["pay_to"]})
        res.update(mr)
        notes += mn
    failed = sorted(k for k, x in res.items() if x.startswith("failed"))
    absent = sorted(k for k, x in res.items() if x.startswith("not_evaluated:absent:"))
    open_ = sorted(k for k, x in res.items() if x.startswith("not_evaluated") and k not in absent)
    # S1-S5 are each verified, failed or not_evaluated, so failed and open_ decide (section 5)
    verdict = "chain_failed" if failed else ("chain_incomplete" if open_ else "chain_verified")
    pv, pn = provenance(doc)                             # SPEC 0.6 G6
    if pn:
        notes.append(pn)
    return {"verdict": verdict, "checks": res, "failed": failed, "not_evaluated": open_, "absent": absent,
            "notes": notes, "payer": payer, "fee_payer": keys[0], "transaction_id": tx_id, "block_bound": False,
            "provenance": pv, "exchange": xm, **({"offer_receipt": orm} if orm is not None else {}),
            **({"builder_code": bcm} if bcm is not None else {}), **tm,
            **({"mandate": mandate_rep} if mandate_rep is not None else {})}
