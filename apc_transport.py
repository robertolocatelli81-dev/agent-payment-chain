"""Amendment 0.11.3 (SPEC section 16): the x402 payment carried over MCP or A2A (x402 4241d56 specs/transports-v2/mcp.md
and a2a.md, cited MCP-T and A2A-T). Members `exchange_mcp` and `exchange_a2a` of an apc-0.3 or apc-0.5 bundle: the
JSON-RPC request that carried the PaymentPayload and the reply that carried the SettlementResponse, as recorded.
DECLARED data: XM1-XM4 / XA1-XA4 show the recording agrees with the payment, not that the exchange happened."""
from apc_verify import Refusal, _obj, _str

A2A_STATUS = ("payment-required", "payment-rejected", "payment-submitted", "payment-verified", "payment-completed",
              "payment-failed")


def _id(v, path):
    # JSON-RPC 2.0 section 4: "a String, Number, or NULL value"; a fraction or null is allowed there but SHOULD NOT be
    # used, so only a string or an integer is read here
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        raise Refusal("%s.id: not a string or an integer" % path)
    return v


def _request(v, path):
    _obj(v, path, ("jsonrpc", "id", "method", "params"))         # JSON-RPC 2.0 section 4: these members only
    if v["jsonrpc"] != "2.0":
        raise Refusal(path + ".jsonrpc: not \"2.0\"")
    _id(v["id"], path)
    _str(v["method"], path + ".method")
    if not isinstance(v["params"], dict):
        raise Refusal(path + ".params: not an object")
    return v


def _response(v, path):
    if not isinstance(v, dict) or ("result" in v) == ("error" in v):
        raise Refusal(path + ": a JSON-RPC response has exactly one of result and error")
    _obj(v, path, ("jsonrpc", "id"), ("result", "error"))
    if v["jsonrpc"] != "2.0":
        raise Refusal(path + ".jsonrpc: not \"2.0\"")
    _id(v["id"], path)
    if "result" in v and not isinstance(v["result"], dict):
        raise Refusal(path + ".result: not an object")
    return v


def _eq(a, b):
    import apc_ap2
    return apc_ap2.canon_eq(a, b)


def _meta(obj, path):
    m = obj.get("_meta") if isinstance(obj, dict) else None
    if m is not None and not isinstance(m, dict):
        raise Refusal(path + "._meta: not an object")
    return m or {}


def check_mcp(doc):
    ex = _obj(doc["exchange_mcp"], "exchange_mcp", ("request",), ("response",))
    rq = _request(ex["request"], "exchange_mcp.request")
    res, notes = {}, []
    meta = _meta(rq["params"], "exchange_mcp.request.params")
    if rq["method"] != "tools/call":
        res["XM1"] = "failed:mcp_request_not_tools_call"
    elif "x402/payment" not in meta:
        res["XM1"] = "failed:mcp_request_without_payment"
    else:
        res["XM1"] = "verified" if _eq(meta["x402/payment"], doc["payment_payload"]) else \
            "failed:mcp_request_carries_another_payment"
    st = doc.get("settlement")
    if "response" not in ex:
        res["XM2"] = res["XM3"] = res["XM4"] = "not_evaluated:absent:no_response"
        return res, notes, {"tool": rq["params"].get("name"), "response": False}
    rs = _response(ex["response"], "exchange_mcp.response")
    res["XM2"] = "verified" if rs["id"] == rq["id"] and type(rs["id"]) is type(rq["id"]) else "failed:mcp_response_id_mismatch"
    result = rs.get("result")
    if result is None:
        res["XM3"] = "not_evaluated:mcp_response_is_a_jsonrpc_error"
        res["XM4"] = ("verified" if st is None or st["success"] is not True else "failed:mcp_status_contradicts_settlement")
        return res, notes, {"tool": rq["params"].get("name"), "response": True}
    rmeta = _meta(result, "exchange_mcp.response.result")
    is_error = result.get("isError", False)
    if not isinstance(is_error, bool):
        raise Refusal("exchange_mcp.response.result.isError: not a boolean")
    if "x402/payment-response" in rmeta:
        res["XM3"] = ("failed:settlement_not_in_bundle" if st is None else
                      "verified" if _eq(rmeta["x402/payment-response"], st) else
                      "failed:mcp_response_carries_another_settlement")
    elif st is not None and st["success"] is True:
        res["XM3"] = "failed:mcp_response_without_payment_response"
    else:
        # MCP-T "Settlement Failure": a failed settlement is a tool result with isError and the PaymentRequired
        res["XM3"] = "not_evaluated:absent:no_payment_response"
    if st is None:
        res["XM4"] = "not_evaluated:absent:no_settlement"
    elif (st["success"] is True) == is_error:
        res["XM4"] = "failed:mcp_status_contradicts_settlement"
    elif is_error:
        # MCP-T "Server Requirements": PaymentRequired in structuredContent AND as JSON text in content[0].text
        sc, ct = result.get("structuredContent"), result.get("content")
        txt = ct[0].get("text") if isinstance(ct, list) and ct and isinstance(ct[0], dict) else None
        if not isinstance(sc, dict) or not isinstance(txt, str):
            res["XM4"] = "failed:mcp_payment_required_not_in_both_forms"
        else:
            import apc_verify as av
            try:
                same = _eq(av.strict_json(txt), sc)
            except Refusal:
                same = False
            res["XM4"] = "verified" if same else "failed:mcp_payment_required_text_differs"
    else:
        res["XM4"] = "verified"
    return res, notes, {"tool": rq["params"].get("name"), "response": True, "is_error": is_error}


def check_a2a(doc):
    ex = _obj(doc["exchange_a2a"], "exchange_a2a", ("request",), ("response",))
    rq = _request(ex["request"], "exchange_a2a.request")
    res, notes = {}, []
    msg = rq["params"].get("message")
    md = msg.get("metadata") if isinstance(msg, dict) else None
    if md is not None and not isinstance(md, dict):
        raise Refusal("exchange_a2a.request.params.message.metadata: not an object")
    md = md or {}
    for k in ("x402.payment.status",):
        if k in md and md[k] not in A2A_STATUS:
            raise Refusal("exchange_a2a.request.params.message.metadata[%r]: not an A2A-T status" % k)
    task = msg.get("taskId") if isinstance(msg, dict) else None
    if rq["method"] != "message/send":
        res["XA1"] = "failed:a2a_request_not_message_send"
    elif "x402.payment.payload" not in md:
        res["XA1"] = "failed:a2a_request_without_payment"
    elif md.get("x402.payment.status") != "payment-submitted":
        res["XA1"] = "failed:a2a_request_status_not_payment_submitted"
    elif not isinstance(task, str):
        res["XA1"] = "failed:a2a_request_without_task_id"
    else:
        res["XA1"] = "verified" if _eq(md["x402.payment.payload"], doc["payment_payload"]) else \
            "failed:a2a_request_carries_another_payment"
    st = doc.get("settlement")
    if "response" not in ex:
        res["XA2"] = res["XA3"] = res["XA4"] = "not_evaluated:absent:no_response"
        return res, notes, {"task": task, "response": False}
    rs = _response(ex["response"], "exchange_a2a.response")
    result = rs.get("result")
    if result is None:
        res["XA2"] = "verified" if rs["id"] == rq["id"] else "failed:a2a_response_id_mismatch"
        res["XA3"] = res["XA4"] = "not_evaluated:a2a_response_is_a_jsonrpc_error"
        return res, notes, {"task": task, "response": True}
    status = result.get("status") if isinstance(result.get("status"), dict) else {}
    rmsg = status.get("message") if isinstance(status.get("message"), dict) else {}
    rmd = rmsg.get("metadata") if isinstance(rmsg.get("metadata"), dict) else {}
    pst = rmd.get("x402.payment.status")
    if pst is not None and pst not in A2A_STATUS:
        raise Refusal("exchange_a2a.response.result.status.message.metadata['x402.payment.status']: not an A2A-T status")
    if rs["id"] != rq["id"]:
        res["XA2"] = "failed:a2a_response_id_mismatch"
    elif result.get("kind") != "task" or result.get("id") != task:
        res["XA2"] = "failed:a2a_task_id_mismatch"          # A2A-T: taskId correlates the payment with the task
    else:
        res["XA2"] = "verified"
    receipts = rmd.get("x402.payment.receipts")
    if receipts is not None and not isinstance(receipts, list):
        raise Refusal("exchange_a2a.response...metadata['x402.payment.receipts']: not an array")
    if receipts is None:
        res["XA3"] = "failed:a2a_response_without_receipts" if st is not None else "not_evaluated:absent:no_receipts"
    elif st is None:
        res["XA3"] = "failed:settlement_not_in_bundle"
    else:
        res["XA3"] = "verified" if any(_eq(r, st) for r in receipts) else "failed:a2a_receipts_without_the_settlement"
    state = status.get("state")
    if st is None:
        res["XA4"] = "not_evaluated:absent:no_settlement"
    elif st["success"] is True:
        res["XA4"] = ("verified" if pst == "payment-completed" and state == "completed"
                      else "failed:a2a_status_contradicts_settlement")
    else:
        res["XA4"] = ("verified" if pst == "payment-failed" and state == "failed"
                      else "failed:a2a_status_contradicts_settlement")
    return res, notes, {"task": task, "response": True, "state": state, "payment_status": pst}


def check(doc):
    """(checks, notes, {member: report}) for the transports the bundle carries; ({}, [], {}) without any."""
    res, notes, members = {}, [], {}
    for name, fn in (("exchange_mcp", check_mcp), ("exchange_a2a", check_a2a)):
        if name in doc:
            r, n, m = fn(doc)
            res.update(r)
            notes += n
            members[name] = m
    if members:
        notes.append("exchange over MCP / A2A is a recording (declared): it shows the recording agrees with the payment, "
                     "not that the exchange happened (SPEC 0.11.3)")
    return res, notes, members
