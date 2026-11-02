"""SPEC 0.15 (section 25): x402 scheme `auth-capture` on EVM, the client's collect payload on the EIP-3009 path
(bundle apc-0.15). Sources, local copies with SHA256SUMS:
  x402-foundation/x402 main 2ff672c, specs/schemes/auth-capture/scheme_auth_capture{,_evm}.md (v1.1, 2026-08-26)
  base/commerce-payments v1.1.0 6b0a5ef and v1.0.0 d33b5d5: PaymentInfo typehash, AuthCaptureEscrow.getHash,
  ERC3009PaymentCollector (receiveWithAuthorization with nonce = the payer-agnostic hash).
The Permit2 collect path (SPEC 0.16.1, section 25.1): Permit2PaymentCollector of the same two commits
(permitTransferFrom without a witness, nonce = the payer-agnostic hash as uint256, deadline = preApprovalExpiry).
Not here: lifecycle payloads (capture, void, refund need the escrow's paymentState), the facilitator's operator
allowlist and its clock, and the step 15 simulation."""
import re

import apc_assets
from apc_verify import (ADDR, HASH32, HEXDATA, HIGH_S_REFUSED, REQ_MEMBERS, SECP_N, ERC6492_MAGIC, Refusal,
                        Unsupported, _addr, _int_json, _json_eq, _obj, _str, _uint, builder_code_checks, exchange_checks,
                        _q, keccak256, offer_receipt_checks, provenance, public_key_to_address, recover_public_key,
                        tx_hash_eip1559)

ZERO = "0x" + "00" * 20
# Commerce-payments deployments (scheme_auth_capture_evm.md): escrow -> (set, EIP-3009 collector, fee field)
DEPLOY = {"0xf96815976523e00e65be8f34ca5e64b4f41eb19c": ("v1.1", "0x8612dfdc421f80336cd14e8ef9cb1e765db5ab88", "feeAmount"),
          "0xbdea0d1bcc5966192b070fdf62ab4ef5b4420cff": ("v1.0", "0x0e3df9510de65469c4518d7843919c0b8c7a7757", "feeBps")}
DEFAULT_ESCROW = "0xf96815976523e00e65be8f34ca5e64b4f41eb19c"
# PERMIT2_TOKEN_COLLECTOR_ADDRESS of each set (scheme_auth_capture_evm.md "Commerce-payments deployments"; on Base
# 2026-10-26 both have 4049 bytes of code, oracle/authcap_permit2_20261026/code_base.json)
P2_COLLECTOR = {"0xf96815976523e00e65be8f34ca5e64b4f41eb19c": "0xd69831aed5bfe262067ec4c751f4f830ecdd446e",
                "0xbdea0d1bcc5966192b070fdf62ab4ef5b4420cff": "0x992476b9ee81d52a5bda0622c333938d0af0ab26"}
EV_TRANSFER = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()
PAYMENT_INFO_TYPE = (b"PaymentInfo(address operator,address payer,address receiver,address token,uint120 maxAmount,"
                     b"uint48 preApprovalExpiry,uint48 authorizationExpiry,uint48 refundExpiry,uint16 minFeeBps,"
                     b"uint16 maxFeeBps,address feeReceiver,uint256 salt)")
SALT_BINDING_TYPE = b"x402AuthCaptureSaltBinding(address receiverAuthorizer,address policy,uint256 saltNonce)"
RECEIVE_TYPE = (b"ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,"
                b"bytes32 nonce)")
DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
CHARGE_TYPE = {"feeAmount": b"Charge(bytes32 paymentInfoHash,uint256 amount,address tokenCollector,bytes32 collectorDataHash,"
                            b"uint256 feeAmount,address feeReceiver)",
               "feeBps": b"Charge(bytes32 paymentInfoHash,uint256 amount,address tokenCollector,bytes32 collectorDataHash,"
                         b"uint16 feeBps,address feeReceiver)"}
PI_TUPLE = "(address,address,address,address,uint120,uint48,uint48,uint48,uint16,uint16,address,uint256)"
EV_AUTHORIZED = "0x" + keccak256(("PaymentAuthorized(bytes32,%s,uint256,address)" % PI_TUPLE).encode()).hex()
EV_CHARGED = {"feeAmount": "0x" + keccak256(("PaymentCharged(bytes32,%s,uint256,address,uint256,address)" % PI_TUPLE).encode()).hex(),
              "feeBps": "0x" + keccak256(("PaymentCharged(bytes32,%s,uint256,address,uint16,address)" % PI_TUPLE).encode()).hex()}
EV_AUTH_USED = "0x" + keccak256(b"AuthorizationUsed(address,bytes32)").hex()
CAIP2 = re.compile(r"eip155:([1-9][0-9]{0,31})\Z")
EXTRA_KNOWN = ("name", "version", "authCaptureEscrow", "captureAuthorizer", "operatorType", "receiverAuthorizer", "policy",
               "paymentFlow", "captureDeadline", "refundDeadline", "minFeeBps", "maxFeeBps", "feeRecipient",
               "assetTransferMethod", "captureMode", "autoCapture")
EXTRA_REQUIRED = ("captureAuthorizer", "captureDeadline", "refundDeadline", "feeRecipient", "minFeeBps", "maxFeeBps",
                  "name", "version")
PAYLOAD_KEYS = ("authorization", "signature", "salt", "saltNonce", "amount", "feeAmount", "feeBps", "feeReceiver",
                "authorizerSignature")
COMPLETION = ("amount", "feeReceiver", "authorizerSignature")


def _wa(a):
    return bytes(12) + bytes.fromhex(a[2:])


def _wu(n):
    return n.to_bytes(32, "big")


def encode_pi(pi):
    """abi.encode of the PaymentInfo struct (all members static, one word each)."""
    return b"".join(_wa(v) if isinstance(v, str) else _wu(v) for v in pi)


def get_hash(chain_id, escrow, pi):
    """AuthCaptureEscrow.getHash: keccak256(abi.encode(chainid, escrow, keccak256(abi.encode(TYPEHASH, paymentInfo))))."""
    inner = keccak256(keccak256(PAYMENT_INFO_TYPE) + encode_pi(pi))
    return keccak256(_wu(chain_id) + _wa(escrow) + inner)


def signature_nonce(chain_id, escrow, pi):
    """The payer-agnostic hash (TokenCollector._getHashPayerAgnostic): getHash with payer = address(0)."""
    return get_hash(chain_id, escrow, [pi[0], ZERO] + list(pi[2:]))


def salt_binding(receiver_authorizer, policy, salt_nonce):
    return int.from_bytes(keccak256(keccak256(SALT_BINDING_TYPE) + _wa(receiver_authorizer) + _wa(policy) + _wu(salt_nonce)), "big")


def _domain(name, version, chain_id, contract):
    return keccak256(keccak256(DOMAIN_TYPE) + keccak256(name.encode("utf-8")) + keccak256(version.encode("utf-8"))
                     + _wu(chain_id) + _wa(contract))


def receive_digest(name, version, chain_id, token, au):
    sm = keccak256(keccak256(RECEIVE_TYPE) + _wa(au["from"]) + _wa(au["to"]) + _wu(au["value"]) + _wu(au["validAfter"])
                   + _wu(au["validBefore"]) + au["nonce"])
    return keccak256(b"\x19\x01" + _domain(name, version, chain_id, token) + sm)


def charge_digest(chain_id, operator, fee_field, pi_hash, amount, collector, collector_data, fee, fee_receiver):
    sm = keccak256(keccak256(CHARGE_TYPE[fee_field]) + pi_hash + _wu(amount) + _wa(collector) + keccak256(collector_data)
                   + _wu(fee) + _wa(fee_receiver))
    return keccak256(b"\x19\x01" + _domain("x402 Auth Capture Operator", "1", chain_id, operator) + sm)


def _recover(digest, sig):
    """65-byte ECDSA (v 27/28) -> lower-case address, or None."""
    if len(sig) != 65 or sig[64] not in (27, 28):
        return None
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    try:
        return public_key_to_address(recover_public_key(digest, r, s, sig[64] - 27), keccak256).lower()
    except ValueError:
        return None


def _hex(v, path, size=None):
    _str(v, path)
    if not HEXDATA.match(v) or (size is not None and len(v) != 2 + 2 * size):
        raise Refusal("%s: not %s hex" % (path, "%d-byte" % size if size else "0x-prefixed"))
    return bytes.fromhex(v[2:])


def _uint_json(v, path, bits):
    n = _int_json(v, path)
    if not 0 <= n < 1 << bits:
        raise Refusal("%s: not a uint%d" % (path, bits))
    return n


def parse(pp_doc):
    """The payment payload and its accepted requirements; structure errors raise Refusal, scope errors Unsupported."""
    p = "payment_payload"
    pp = _obj(pp_doc, p, ("x402Version", "accepted", "payload"), ("resource", "extensions"))
    if _int_json(pp["x402Version"], p + ".x402Version") != 2:
        raise Unsupported("%s.x402Version %r (auth-capture: v2 only)" % (p, pp["x402Version"]))
    if "extensions" in pp and not isinstance(pp["extensions"], dict):
        raise Refusal("%s.extensions: not an object" % p)
    q = p + ".accepted"
    a = _obj(pp["accepted"], q, REQ_MEMBERS + ("extra",))
    if _str(a["scheme"], q + ".scheme") != "auth-capture":
        raise Unsupported("%s.scheme %r (apc-0.15: auth-capture only)" % (q, a["scheme"]))
    m = CAIP2.match(_str(a["network"], q + ".network"))
    if not m:
        raise Unsupported("%s.network %r (auth-capture on EVM: eip155 only)" % (q, a["network"]))
    ex = a["extra"]
    if not isinstance(ex, dict):
        raise Refusal("%s.extra: not an object" % q)
    for k in EXTRA_REQUIRED:
        if k not in ex:
            raise Refusal("%s.extra.%s missing (required, scheme_auth_capture_evm.md extra fields)" % (q, k))
    r = {"chain_id": int(m.group(1)), "network": a["network"], "amount": _uint(a["amount"], q + ".amount", 120),
         "asset": _addr(a["asset"], q + ".asset"), "pay_to": _addr(a["payTo"], q + ".payTo"),
         "max_timeout": _int_json(a["maxTimeoutSeconds"], q + ".maxTimeoutSeconds"), "notes": []}
    for k in sorted(set(ex) - set(EXTRA_KNOWN)):     # Compatibility: "Clients MUST ignore unrecognized extra keys"
        r["notes"].append("%s.extra.%s: not a member of auth-capture v1.1 (the scheme says to ignore it; reported)" % (q, k))
    for k in ("name", "version"):
        r[k] = _str(ex[k], "%s.extra.%s" % (q, k))
    for k in ("captureAuthorizer", "feeRecipient"):
        r[k] = _addr(ex[k], "%s.extra.%s" % (q, k))
    for k in ("receiverAuthorizer", "policy"):
        r[k] = _addr(ex[k], "%s.extra.%s" % (q, k)) if k in ex else ZERO
    r["escrow"] = _addr(ex["authCaptureEscrow"], q + ".extra.authCaptureEscrow") if "authCaptureEscrow" in ex else DEFAULT_ESCROW
    r["captureDeadline"] = _uint_json(ex["captureDeadline"], q + ".extra.captureDeadline", 48)
    r["refundDeadline"] = _uint_json(ex["refundDeadline"], q + ".extra.refundDeadline", 48)
    r["minFeeBps"] = _uint_json(ex["minFeeBps"], q + ".extra.minFeeBps", 16)
    r["maxFeeBps"] = _uint_json(ex["maxFeeBps"], q + ".extra.maxFeeBps", 16)
    for k, dflt in (("paymentFlow", "escrow"), ("operatorType", "delegated"), ("assetTransferMethod", "eip3009")):
        r[k] = _str(ex[k], "%s.extra.%s" % (q, k)) if k in ex else dflt
    r["captureMode"] = _str(ex["captureMode"], q + ".extra.captureMode") if "captureMode" in ex else None
    if "autoCapture" in ex and not isinstance(ex["autoCapture"], bool):
        raise Refusal("%s.extra.autoCapture: not a boolean" % q)
    r["autoCapture"] = ex.get("autoCapture")
    if r["assetTransferMethod"] not in ("eip3009", "permit2"):
        raise Refusal("%s.extra.assetTransferMethod %r: not eip3009 or permit2" % (q, r["assetTransferMethod"]))
    q = p + ".payload"
    pl = pp["payload"]
    if r["assetTransferMethod"] == "permit2":      # SPEC 0.16.1, section 25.1: the Permit2 payload shape
        if not isinstance(pl, dict) or "authorization" in pl:
            raise Refusal("%s: not the Permit2 payload shape (permit2 selected)" % q)
        _obj(pl, q, ("permit2Authorization", "signature", "salt"),
             tuple(k for k in PAYLOAD_KEYS if k not in ("authorization", "signature", "salt")))
        a2 = q + ".permit2Authorization"
        au = _obj(pl["permit2Authorization"], a2, ("from", "permitted", "spender", "nonce", "deadline"))
        pm = _obj(au["permitted"], a2 + ".permitted", ("token", "amount"))
        u = {"from": _addr(au["from"], a2 + ".from"), "token": _addr(pm["token"], a2 + ".permitted.token"),
             "amount": _uint(pm["amount"], a2 + ".permitted.amount"), "spender": _addr(au["spender"], a2 + ".spender"),
             "nonce": _uint(au["nonce"], a2 + ".nonce"), "deadline": _uint(au["deadline"], a2 + ".deadline")}
    else:
        if not isinstance(pl, dict) or "permit2Authorization" in pl:
            raise Refusal("%s: not the EIP-3009 payload shape (eip3009 selected)" % q)
        _obj(pl, q, ("authorization", "signature", "salt"), tuple(k for k in PAYLOAD_KEYS if k not in ("authorization", "signature", "salt")))
        au = _obj(pl["authorization"], q + ".authorization", ("from", "to", "value", "validAfter", "validBefore", "nonce"))
        u = {"from": _addr(au["from"], q + ".authorization.from"), "to": _addr(au["to"], q + ".authorization.to"),
             "value": _uint(au["value"], q + ".authorization.value"),
             "validAfter": _uint(au["validAfter"], q + ".authorization.validAfter"),
             "validBefore": _uint(au["validBefore"], q + ".authorization.validBefore"),
             "nonce": _hex(au["nonce"], q + ".authorization.nonce", 32)}
    w = {"method": r["assetTransferMethod"], "auth": u, "signature": _hex(pl["signature"], q + ".signature"),
         "salt": int.from_bytes(_hex(pl["salt"], q + ".salt", 32), "big"),
         "saltNonce": int.from_bytes(_hex(pl["saltNonce"], q + ".saltNonce", 32), "big") if "saltNonce" in pl else None,
         "completion": {k: pl[k] for k in COMPLETION + ("feeAmount", "feeBps") if k in pl}}
    c = w["completion"]
    if "amount" in c:
        c["amount"] = _uint(c["amount"], q + ".amount", 120)
    if "feeAmount" in c:
        c["feeAmount"] = _uint(c["feeAmount"], q + ".feeAmount")
    if "feeBps" in c:
        c["feeBps"] = _uint_json(c["feeBps"], q + ".feeBps", 16) if not isinstance(c["feeBps"], str) else _uint(c["feeBps"], q + ".feeBps", 16)
    if "feeReceiver" in c:
        c["feeReceiver"] = _addr(c["feeReceiver"], q + ".feeReceiver")
    if "authorizerSignature" in c:
        c["authorizerSignature"] = _hex(c["authorizerSignature"], q + ".authorizerSignature")
    resource_url = None
    if "resource" in pp:
        resource_url = _str(_obj(pp["resource"], p + ".resource", ("url",), ("description", "mimeType", "method"))["url"],
                            p + ".resource.url")
    return pp, r, w, resource_url


def expiry(w):
    """PaymentInfo.preApprovalExpiry: EIP-3009 validBefore, Permit2 deadline (scheme_auth_capture_evm.md payload tables)."""
    return w["auth"]["deadline"] if w["method"] == "permit2" else w["auth"]["validBefore"]


def payment_info(r, w):
    """PaymentInfo reconstructed field by field (scheme_auth_capture_evm.md appendix)."""
    return [r["captureAuthorizer"], w["auth"]["from"], r["pay_to"], r["asset"], r["amount"], expiry(w),
            r["captureDeadline"], r["refundDeadline"], r["minFeeBps"], r["maxFeeBps"], r["feeRecipient"], w["salt"]]


def client_checks(r, w):
    """Verification steps 1-14 of scheme_auth_capture_evm.md that need no chain state and no clock."""
    res, notes = {}, []
    dep = DEPLOY.get(r["escrow"])
    bound = r["receiverAuthorizer"] != ZERO or r["policy"] != ZERO
    flow = r["paymentFlow"]
    c = w["completion"]
    # AC1 extra validation (step 4)
    res["AC1"] = ("failed:invalid_auth_capture_evm_extra:escrow_not_canonical" if dep is None else
                  "failed:invalid_auth_capture_evm_unsupported_payment_flow" if flow not in ("escrow", "authorization")
                  or r["autoCapture"] is True else
                  "failed:invalid_auth_capture_evm_extra:capture_mode" if r["captureMode"] is not None and
                  (flow == "authorization" or r["captureMode"] not in ("sync", "deferred")) else
                  "failed:invalid_auth_capture_evm_extra:fee_bps" if r["maxFeeBps"] > 10000 or r["minFeeBps"] > r["maxFeeBps"] else
                  "failed:invalid_auth_capture_evm_extra:zero_fee_recipient_with_fee" if r["feeRecipient"] == ZERO and
                  r["maxFeeBps"] != 0 else "verified")
    # AC2 operator model (step 5, the offline part: the allowlist and "controls and submits from" are the facilitator's)
    res["AC2"] = ("failed:invalid_auth_capture_evm_unsupported_operator_type" if r["operatorType"] not in ("delegated", "custom") else
                  "failed:invalid_auth_capture_evm_operator:policy_not_zero" if r["policy"] != ZERO else
                  "failed:invalid_auth_capture_evm_operator:charge_without_receiver_authorizer"
                  if flow == "authorization" and r["receiverAuthorizer"] == ZERO else "verified")
    notes.append("auth-capture step 5: whether extra.captureAuthorizer is admitted (allowlist, or an address the "
                 "facilitator submits from) is the facilitator's own state, not in the bundle")
    # AC3 shape of the bind and of the completion (step 1)
    full = all(k in c for k in COMPLETION) and (dep is not None and dep[2] in c)
    res["AC3"] = ("failed:invalid_auth_capture_evm_payload_format:salt_nonce" if bound != (w["saltNonce"] is not None) else
                  "failed:invalid_auth_capture_evm_payload_format:completion_on_authorize" if flow == "escrow" and c else
                  "failed:invalid_auth_capture_evm_payload_format:partial_completion" if c and not full else
                  "failed:invalid_auth_capture_evm_payload_format:wrong_fee_field" if dep is not None and
                  ({"feeAmount", "feeBps"} - {dep[2]}) & set(c) else "verified")
    # AC4 deadline ordering (step 7, static part) and validAfter (the collector hardcodes 0)
    au, p2 = w["auth"], w["method"] == "permit2"
    exp, exn = expiry(w), "deadline" if p2 else "valid_before"
    res["AC4"] = ("failed:invalid_auth_capture_evm_deadlines:refund_before_capture" if r["refundDeadline"] < r["captureDeadline"] else
                  "failed:invalid_auth_capture_evm_deadlines:%s_after_capture" % exn if exp > r["captureDeadline"] else
                  "failed:invalid_auth_capture_evm_deadlines:%s_not_uint48" % exn if exp >= 1 << 48 else
                  "failed:invalid_auth_capture_evm_deadlines:valid_after_not_zero" if not p2 and au["validAfter"] != 0 else
                  "verified")
    notes.append("auth-capture steps 7-8: the checks against now (captureDeadline > now + 6 s, validBefore > now + 6 s, "
                 "now + maxTimeoutSeconds <= captureDeadline) need the facilitator's clock at verification")
    # AC5 collector (step 9) and amount (step 12)
    if p2:      # section 25.1: spender the Permit2 collector (step 9), permitted.token the asset (step 10), the amount
        res["AC5"] = ("not_evaluated:after_AC1" if dep is None else
                      "failed:invalid_auth_capture_evm_collector_mismatch" if au["spender"] != P2_COLLECTOR[r["escrow"]] else
                      "failed:invalid_auth_capture_evm_token_mismatch" if au["token"] != r["asset"] else
                      "failed:invalid_auth_capture_evm_amount_mismatch" if au["amount"] != r["amount"] else "verified")
    else:
        res["AC5"] = ("not_evaluated:after_AC1" if dep is None else
                      "failed:invalid_auth_capture_evm_collector_mismatch" if au["to"] != dep[1] else
                      "failed:invalid_auth_capture_evm_amount_mismatch" if au["value"] != r["amount"] else "verified")
    # AC6 nonce (step 13): signatureNonce over the reconstructed PaymentInfo, and the salt commitment when bound
    pi = payment_info(r, w)
    if dep is None or exp >= 1 << 48:
        res["AC6"] = "not_evaluated:after_AC1"
    elif bound and w["saltNonce"] is not None and w["salt"] != salt_binding(r["receiverAuthorizer"], r["policy"], w["saltNonce"]):
        res["AC6"] = "failed:invalid_auth_capture_evm_nonce_mismatch:salt_not_the_binding"
    elif signature_nonce(r["chain_id"], r["escrow"], pi) != (au["nonce"].to_bytes(32, "big") if p2 else au["nonce"]):
        res["AC6"] = "failed:invalid_auth_capture_evm_nonce_mismatch"
    else:
        res["AC6"] = "verified"
    # AC7 client signature (step 11): ReceiveWithAuthorization under the token's domain
    sig = w["signature"]
    if sig.endswith(ERC6492_MAGIC):
        res["AC7"] = "not_evaluated:erc6492_counterfactual_signature"
    elif p2:    # section 25.1: PermitTransferFrom under the canonical Permit2 domain, msg.sender = the Permit2 collector
        import apc_permit2
        if dep is None:
            res["AC7"] = "not_evaluated:after_AC1"
        elif len(sig) not in (64, 65):
            res["AC7"] = "not_evaluated:erc1271_needs_chain_state"
        else:
            r7, n7 = apc_permit2.signature_verification(sig, apc_permit2.permit_transfer_digest(
                r["chain_id"], au["token"], au["amount"], P2_COLLECTOR[r["escrow"]], au["nonce"], au["deadline"]), au["from"])
            res["AC7"] = ("failed:signature_does_not_recover_the_payer" if r7.startswith("failed:recovers_") else r7)
            notes += n7
    elif len(sig) != 65:
        res["AC7"] = "not_evaluated:erc1271_needs_chain_state"
    else:
        who = _recover(receive_digest(r["name"], r["version"], r["chain_id"], r["asset"], au), sig)
        high = int.from_bytes(sig[32:64], "big") > SECP_N // 2
        res["AC7"] = ("failed:signature_does_not_recover_the_payer" if who != au["from"] else
                      "failed:high_s_refused_by_token" if high and (r["network"], r["asset"]) in HIGH_S_REFUSED else
                      "not_evaluated:high_s_token_rule_not_measured" if high else "verified")
    # AC8 charge: amount and fee (step 12) and the receiver authorizer's Charge signature (step 14)
    if flow != "authorization":
        pass                                         # authorize: no server-authored fields, nothing to check here
    elif not c:
        res["AC8"] = "not_evaluated:raw_verify_form_without_completion"
    elif not full:
        res["AC8"] = "not_evaluated:after_AC3"
    else:
        amt, fee, fr = c["amount"], c[dep[2]], c["feeReceiver"]
        if dep[2] == "feeAmount":
            fee_ok = amt * r["minFeeBps"] // 10000 <= fee <= amt * r["maxFeeBps"] // 10000
        else:
            fee_ok = r["minFeeBps"] <= fee <= r["maxFeeBps"]
        who = _recover(charge_digest(r["chain_id"], r["captureAuthorizer"], dep[2], get_hash(r["chain_id"], r["escrow"], pi),
                                     amt, collector(r, w), sig, fee, fr), c["authorizerSignature"])
        res["AC8"] = ("failed:invalid_auth_capture_evm_amount:charge_amount" if not 0 < amt <= r["amount"] else
                      "failed:invalid_auth_capture_evm_fee:out_of_range" if not fee_ok else
                      "failed:invalid_auth_capture_evm_fee:fee_receiver" if (r["feeRecipient"] != ZERO and fr != r["feeRecipient"])
                      or (fr == ZERO and fee != 0) else
                      "failed:invalid_auth_capture_evm_authorizer_signature" if who != r["receiverAuthorizer"] else "verified")
    return res, notes, pi, dep


def _logs(rc, path):
    if not isinstance(rc.get("logs"), list):
        raise Refusal(path + ".logs: not a list")
    out = []
    for i, lg in enumerate(rc["logs"]):
        q = "%s.logs[%d]" % (path, i)
        if not isinstance(lg, dict):
            raise Refusal(q + ": not an object")
        a = _str(lg.get("address"), q + ".address")
        if not ADDR.match(a) or not isinstance(lg.get("topics"), list) or \
                not all(isinstance(t, str) and HASH32.match(t) for t in lg["topics"]):
            raise Refusal(q + ": address or topics outside the grammar")
        if not isinstance(lg.get("data"), str) or not HEXDATA.match(lg["data"]):
            raise Refusal(q + ".data: not hex")
        if "removed" in lg and not isinstance(lg["removed"], bool):
            raise Refusal(q + ".removed: not a boolean")
        out.append({"address": a.lower(), "topics": [t.lower() for t in lg["topics"]], "data": bytes.fromhex(lg["data"][2:]),
                    "removed": lg.get("removed", False), "tx": str(lg.get("transactionHash", "")).lower(),
                    "block": _block(lg, q)})
    return out


def _block(obj, path):
    """(blockHash, blockNumber) of an RPC object, both required (SPEC 0.18.2, section 25 C1, block): blockHash 32 bytes of
    hex, compared without case; blockNumber a JSON-RPC quantity as apc_verify._q reads it everywhere else (0x0 or
    lower-case hex without leading zeros, at most 256 bits), compared as an integer."""
    h = obj.get("blockHash")
    if not isinstance(h, str) or not HASH32.match(h):
        raise Refusal(path + ".blockHash: not 32 bytes of hex")
    return h.lower(), int.from_bytes(_q(obj.get("blockNumber"), path + ".blockNumber"), "big")


def collector(r, w):
    """The tokenCollector of the deployment for the client's method (step 9)."""
    return P2_COLLECTOR[r["escrow"]] if w["method"] == "permit2" else DEPLOY[r["escrow"]][1]


def chain_checks(ct, r, w, pi, dep, amount, tx_id):
    """C1 transaction hash, C2 status, C3 the escrow's event for this PaymentInfo, C4 the token's AuthorizationUsed."""
    res = {}
    ct = _obj(ct, "chain_tx", ("tx", "receipt"))
    tx, rc = ct["tx"], ct["receipt"]
    if not isinstance(tx, dict) or not isinstance(rc, dict):
        raise Refusal("chain_tx.tx / chain_tx.receipt: not objects")
    h = tx_hash_eip1559(tx)
    th = _hex(rc.get("transactionHash"), "chain_tx.receipt.transactionHash", 32)
    res["C1"] = ("not_evaluated:tx_type_not_eip1559" if h is None else
                 "failed:tx_hash_not_the_transaction" if h != "0x" + th.hex() or str(tx.get("hash", "")).lower() != h else
                 "failed:settlement_names_another_transaction" if tx_id is not None and tx_id != h else "verified")
    res["C2"] = "verified" if rc.get("status") == "0x1" else "failed:transaction_reverted"
    logs = _logs(rc, "chain_tx.receipt")
    if any(lg["tx"] and lg["tx"] != "0x" + th.hex() for lg in logs):
        raise Refusal("chain_tx.receipt.logs: a log of another transaction")
    # SPEC 0.18.2 (section 25, C1, block): the receipt and every log claim the transaction's block (hash and number);
    # both blocks are read whatever C1 is (a missing or malformed one is a refusal), and a C1 not verified keeps its reason
    blk, rblk = _block(tx, "chain_tx.tx"), _block(rc, "chain_tx.receipt")
    if res["C1"] == "verified" and (rblk != blk or any(lg["block"] != blk for lg in logs)):
        res["C1"] = "failed:log_block_not_tx_block"
    if dep is None:
        res["C3"] = res["C4"] = "not_evaluated:after_AC1"
        return res
    pih = "0x" + get_hash(r["chain_id"], r["escrow"], pi).hex()
    flow = r["paymentFlow"]
    topic0 = EV_AUTHORIZED if flow == "escrow" else EV_CHARGED[dep[2]]
    # SPEC 29.4: PaymentAuthorized and PaymentCharged have one indexed parameter: exactly two topics
    mine = [lg for lg in logs if lg["address"] == r["escrow"] and lg["topics"] == [topic0, pih]]
    want = encode_pi(pi) + _wu(amount) + _wa(collector(r, w))
    if flow == "authorization" and "feeReceiver" in w["completion"]:
        want += _wu(w["completion"].get(dep[2], 0)) + _wa(w["completion"]["feeReceiver"])
    res["C3"] = ("failed:no_escrow_event_for_this_payment_info" if not mine else
                 "failed:more_than_one_escrow_event" if len(mine) > 1 else
                 "failed:removed_log" if mine[0]["removed"] else
                 "failed:escrow_event_data_mismatch" if (flow == "escrow" and mine[0]["data"] != want) or
                 (flow == "authorization" and mine[0]["data"][:len(want)] != want) else "verified")
    if w["method"] == "permit2":
        # section 25.1: Permit2 emits no event for a signature transfer (SignatureTransfer.sol); the evidence is the
        # token's Transfer of the collected amount from the payer (to the operator's token store, not recomputed here)
        used = [lg for lg in logs if lg["address"] == r["asset"] and lg["topics"][:2] ==
                [EV_TRANSFER, "0x" + _wa(w["auth"]["from"]).hex()] and len(lg["topics"]) == 3]
        mine = [lg for lg in used if lg["data"] == _wu(amount)]
        res["C4"] = ("failed:no_transfer_of_the_amount_from_the_payer" if not mine else
                     "not_evaluated:more_than_one_transfer_from_the_payer" if len(used) > 1 else
                     "failed:removed_log" if mine[0]["removed"] else "verified")
        return res
    used = [lg for lg in logs if lg["address"] == r["asset"] and lg["topics"] ==
            [EV_AUTH_USED, "0x" + _wa(w["auth"]["from"]).hex(), "0x" + w["auth"]["nonce"].hex()]]
    res["C4"] = ("failed:no_authorization_used_for_the_nonce" if not used else
                 "failed:more_than_one_authorization_used" if len(used) > 1 else
                 "failed:removed_log" if used[0]["removed"] else "verified")
    return res


def verify(doc, http_keys=None, signer_trust=None):
    _obj(doc, "bundle", ("bundle_version", "payment_payload"), ("payment_required", "settlement", "chain_tx",
                                                                 "provenance", "exchange"))
    pp, r, w, resource_url = parse(doc["payment_payload"])
    res, notes, pi, dep = client_checks(r, w)
    notes = r["notes"] + notes
    flow = r["paymentFlow"]
    amount = w["completion"].get("amount", r["amount"]) if flow == "authorization" else r["amount"]
    if "payment_required" in doc:
        pr = _obj(doc["payment_required"], "payment_required", ("x402Version", "resource", "accepts"), ("error", "extensions"))
        if _int_json(pr["x402Version"], "payment_required.x402Version") != 2:
            raise Unsupported("payment_required.x402Version %r (2 only)" % (pr["x402Version"],))
        if not isinstance(pr["accepts"], list) or not pr["accepts"] or not all(isinstance(a, dict) for a in pr["accepts"]):
            raise Refusal("payment_required.accepts: not a non-empty array of objects")
        _str(_obj(pr["resource"], "payment_required.resource", ("url",), ("description", "mimeType"))["url"],
             "payment_required.resource.url")
        if "extensions" in pr and not isinstance(pr["extensions"], dict):
            raise Refusal("payment_required.extensions: not an object")
        if "error" in pr and not isinstance(pr["error"], str):
            raise Refusal("payment_required.error: not a string")
        res["K4"] = "verified" if any(_json_eq(pp["accepted"], a) for a in pr["accepts"]) else "failed:accepted_not_offered"
        if resource_url is not None and resource_url != pr["resource"]["url"]:
            res["K4"] = "failed:resource_url_mismatch"
    else:
        res["K4"] = "not_evaluated:absent:no_payment_required"
    tx_id = None
    if "settlement" in doc:
        st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network"),
                  ("errorReason", "payer", "amount", "extensions"))
        if not isinstance(st["success"], bool):
            raise Refusal("settlement.success: not a boolean")
        if "errorReason" in st and not isinstance(st["errorReason"], str) or \
                "extensions" in st and not isinstance(st["extensions"], dict):
            raise Refusal("settlement.errorReason / extensions: not a string / an object")
        _str(st["network"], "settlement.network")
        tx_id = "0x" + _hex(st["transaction"], "settlement.transaction", 32).hex() if st["success"] else None
        res["T1"] = ("failed:settlement_not_successful" if st["success"] is not True else
                     "failed:settlement_network_not_accepted" if st["network"] != r["network"] else
                     "failed:settlement_payer_mismatch" if "payer" in st and _addr(st["payer"], "settlement.payer") != w["auth"]["from"] else
                     "failed:settlement_amount_mismatch" if "amount" in st and _uint(st["amount"], "settlement.amount") != amount
                     else "verified")
    else:
        res["T1"] = "not_evaluated:absent:no_settlement"
    if "chain_tx" in doc:
        res.update(chain_checks(doc["chain_tx"], r, w, pi, dep, amount, tx_id))
        notes.append("chain_tx is the RPC's transaction and receipt (declared): the hash is recomputed, the escrow and "
                     "token events are read; no block header binds the receipt here (block_bound false), and the call "
                     "path to the escrow (operator, account abstraction) is not decoded")
    else:
        for k in ("C1", "C2", "C3", "C4"):
            res[k] = "not_evaluated:absent:no_chain_tx"
    xr, xn, xm = exchange_checks(doc, http_keys)
    if xr:
        res.update(xr)
        notes += xn
    # SPEC 0.16.1: the amendments that hold for every bundle version, by the code of apc-0.1 to apc-0.3. BC1: the call
    # path to the escrow is not decoded (C1-C4 note), so no settlement calldata suffix is read (as an indirect call)
    bcr, bcn, bcm = builder_code_checks(doc, None)
    res.update(bcr)
    notes += bcn
    import apc_payid                                     # PI1, section 15
    pir, pin = apc_payid.check(doc)
    res.update(pir)
    notes += pin
    pr_doc, st_doc = doc.get("payment_required"), doc.get("settlement")
    orr, orn, orm = offer_receipt_checks(doc, {        # OR1-OR3, section 13: an offer names its scheme
        "evm": True, "network": r["network"], "scheme": "auth-capture", "asset": r["asset"], "pay_to": r["pay_to"],
        "amount": str(r["amount"]), "resource_url": resource_url if resource_url is not None else
        (pr_doc["resource"]["url"] if isinstance(pr_doc, dict) else None), "payer": w["auth"]["from"],
        "transaction": st_doc["transaction"] if isinstance(st_doc, dict) and isinstance(st_doc.get("transaction"), str)
        else None, "success": st_doc["success"] if isinstance(st_doc, dict) else None, "block_time": None,
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
    out = {"verdict": verdict, "checks": res, "failed": failed, "not_evaluated": open_, "absent": absent, "notes": notes,
           "payer": w["auth"]["from"], "transaction_id": tx_id, "payment_info_hash":
           "0x" + get_hash(r["chain_id"], r["escrow"], pi).hex() if r["captureDeadline"] < 1 << 48 else None,
           "deployment": dep[0] if dep else None, "asset_transfer_method": w["method"], "block_bound": False,
           "provenance": pv, "exchange": xm}
    if bcm is not None:
        out["builder_code"] = bcm
    if orm is not None:
        out["offer_receipt"] = orm
    ai = apc_assets.info(r["network"], r["asset"], r["amount"])         # section 19: measured assets only
    if ai is not None:
        out["asset"] = ai
        if (r["name"], r["version"]) != (ai["eip712"]["name"], ai["eip712"]["version"]):
            notes.append("accepted.extra names the EIP-712 domain (%r, %r); the measured domain of this asset is (%r, "
                         "%r) (SPEC 0.11.5): %s" % (r["name"], r["version"], ai["eip712"]["name"], ai["eip712"]["version"],
                                                   "AC7 decides" if w["method"] == "eip3009" else
                                                   "the Permit2 signature does not use it"))
    return out
