"""agent-payment-chain, SPEC 0.10 (SPEC.md section 12): the x402 `exact` scheme on EVM without EIP-3009, bundle apc-0.10.
Two asset transfer methods of x402 scheme_exact_evm.md (x402-foundation/x402 @ 4241d56): `permit2` (Permit2
permitWitnessTransferFrom through the x402ExactPermit2Proxy) and `erc7710` (a delegation redeemed at an ERC-7710
Delegation Manager). Called by apc_verify.verify_bundle; standard library plus the keccak256 and secp256k1 of
APC_SIGLIB. Every type string, domain and address below is a constant of the pinned sources, never read from the input."""
import json
import re

import apc_block
import apc_l1proof
import apc_assets
from apc_verify import (CAIP2_EIP155, ERC6492_MAGIC, HASH32, SECP_N, TRANSFER_TOPIC, Refusal, Unsupported, _addr, _d,
                        _from_is_signer, _header_obj, _int_json, _json_eq, _obj, _q, _removed, _reply, _str, _uint,
                        bound_report, builder_code_checks, check_acceptance, check_canonical, check_inclusion,
                        check_mandate, eip55_ok, eq, resource_info,
                        erc8021_schema0, erc8021_schema2, exchange_checks, keccak256, offer_receipt_checks, provenance,
                        public_key_to_address,
                        recover_public_key, tx_hash_eip1559, tx_sender_eip1559)

METHODS = ("permit2", "erc7710")
# Uniswap permit2 @ cc56ad0: the canonical address (x402BasePermit2Proxy.sol, measured as PERMIT2() of the proxy on
# Base), EIP712.sol (3-member domain, name "Permit2", no version), PermitHash.sol (the witness stub)
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
DOMAIN3_TYPEHASH = keccak256(b"EIP712Domain(string name,uint256 chainId,address verifyingContract)")
PERMIT2_NAME_HASH = keccak256(b"Permit2")
WITNESS_STUB = b"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,"
TOKEN_PERMISSIONS_TYPEHASH = keccak256(b"TokenPermissions(address token,uint256 amount)")
# x402 contracts/evm/src/x402ExactPermit2Proxy.sol @ 4241d56: canonical address (scheme_exact_evm.md), witness type
EXACT_PROXY = "0x402085c248eea27d92e8b30b2c58ed07f9e20001"
WITNESS_TYPE_STRING = b"Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)"
WITNESS_TYPEHASH = keccak256(b"Witness(address to,uint256 validAfter)")
PERMIT_WITNESS_TYPEHASH = keccak256(WITNESS_STUB + WITNESS_TYPE_STRING)
_sel = lambda s: keccak256(s.encode())[:4]  # noqa: E731
SEL_SETTLE = _sel("settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)")
SEL_SETTLE_PERMIT = _sel("settleWithPermit((uint256,uint256,bytes32,bytes32,uint8),((address,uint256),uint256,uint256),"
                         "address,(address,uint256),bytes)")
TOPIC_SETTLED = "0x" + keccak256(b"Settled()").hex()
TOPIC_SETTLED_PERMIT = "0x" + keccak256(b"SettledWithPermit()").hex()
# ERC-7710 (ethereum/ERCs be46db7, Draft): ERC7710Manager.redeemDelegations; ERC-7579 (3f5f41b, Draft) single call
SEL_REDEEM = _sel("redeemDelegations(bytes[],bytes32[],bytes[])")
SEL_TRANSFER = _sel("transfer(address,uint256)")
NOTES = []
BUILDER = []                # SPEC 0.16.1: the decoded Schema 2 map of the settle calldata (as apc_verify.BUILDER)


def _w(n):
    return n.to_bytes(32, "big")


def _a(addr):
    return bytes(12) + bytes.fromhex(addr[2:])


# ------------------------------------------------------------------ grammar (SPEC 12.1)
def parse_requirements(v, path):
    """An x402 PaymentRequirements of the exact scheme on eip155 whose extra.assetTransferMethod is permit2 or erc7710."""
    _obj(v, path, ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds"), ("extra",))
    if _str(v["scheme"], path + ".scheme") != "exact":
        raise Unsupported("%s.scheme %r (exact only)" % (path, v["scheme"]))
    m = CAIP2_EIP155.match(_str(v["network"], path + ".network"))
    if not m:
        raise Refusal("%s.network %r: not eip155:<decimal chain id without leading zeros>" % (path, v["network"]))
    extra = v.get("extra")
    if not isinstance(extra, dict):
        raise Refusal("%s.extra: required, an object with assetTransferMethod (apc-0.10)" % path)
    method = extra.get("assetTransferMethod")
    if method not in METHODS:
        if method is None or method == "eip3009":
            raise Refusal("%s.extra.assetTransferMethod %r: an apc-0.10 bundle carries permit2 or erc7710 (EIP-3009: "
                          "apc-0.1 to apc-0.3)" % (path, method))
        raise Unsupported("%s.extra.assetTransferMethod %r (permit2 or erc7710)" % (path, method))
    r = {"chain_id": int(m.group(1)), "network": v["network"], "amount": _uint(v["amount"], path + ".amount"),
         "asset": _addr(v["asset"], path + ".asset"), "pay_to": _addr(v["payTo"], path + ".payTo"),
         "max_timeout": _int_json(v["maxTimeoutSeconds"], path + ".maxTimeoutSeconds"), "method": method, "notes": []}
    for k in ("name", "version"):        # conditional (permit2: EIP-2612 sponsoring) or optional (erc7710): strings
        r["domain_" + k] = _str(extra[k], "%s.extra.%s" % (path, k)) if k in extra else None
    for k in sorted(set(extra) - {"name", "version", "assetTransferMethod"}):
        r["notes"].append("%s.extra.%s present (scheme-specific, not interpreted)" % (path, k))
    for k, a in (("asset", v["asset"]), ("payTo", v["payTo"])):
        if not eip55_ok(a):
            r["notes"].append("%s.%s: mixed case with a wrong EIP-55 checksum" % (path, k))
    return r


def _hexdata(v, path):
    if not isinstance(v, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", v):
        raise Refusal("%s: not non-empty even-length hex" % path)
    return bytes.fromhex(v[2:])


def parse_payload(v):
    p = "payment_payload"
    _obj(v, p, ("x402Version", "accepted", "payload"), ("resource", "extensions"))
    if "extensions" in v and not isinstance(v["extensions"], dict):
        raise Refusal("%s.extensions: not an object" % p)
    if _int_json(v["x402Version"], p + ".x402Version") != 2:
        raise Unsupported("%s.x402Version %r (2 only)" % (p, v["x402Version"]))
    acc = parse_requirements(v["accepted"], p + ".accepted")
    resource_url = None
    if "resource" in v:
        res = resource_info(v["resource"], p + ".resource")
        resource_url = _str(res["url"], p + ".resource.url")
    out = {"accepted": acc, "raw_accepted": v["accepted"], "resource_url": resource_url, "method": acc["method"]}
    q = p + ".payload"
    if acc["method"] == "permit2":
        pl = _obj(v["payload"], q, ("signature", "permit2Authorization"))
        au = _obj(pl["permit2Authorization"], q + ".permit2Authorization",
                  ("permitted", "from", "spender", "nonce", "deadline", "witness"))
        a = q + ".permit2Authorization"
        pm = _obj(au["permitted"], a + ".permitted", ("token", "amount"))
        wt = _obj(au["witness"], a + ".witness", ("to", "validAfter"))
        out["signature"] = _hexdata(pl["signature"], q + ".signature")
        out["auth"] = {"token": _addr(pm["token"], a + ".permitted.token"),
                       "amount": _uint(pm["amount"], a + ".permitted.amount"),
                       "from": _addr(au["from"], a + ".from"), "spender": _addr(au["spender"], a + ".spender"),
                       "nonce": _uint(au["nonce"], a + ".nonce"), "deadline": _uint(au["deadline"], a + ".deadline"),
                       "to": _addr(wt["to"], a + ".witness.to"),
                       "validAfter": _uint(wt["validAfter"], a + ".witness.validAfter")}
        out["payer"] = out["auth"]["from"]
    else:
        pl = _obj(v["payload"], q, ("delegationManager", "permissionContext", "delegator"))
        out["auth"] = {"manager": _addr(pl["delegationManager"], q + ".delegationManager"),
                       "context": _hexdata(pl["permissionContext"], q + ".permissionContext"),
                       "delegator": _addr(pl["delegator"], q + ".delegator")}
        out["payer"] = out["auth"]["delegator"]
    return out


# ------------------------------------------------------------------ L2.sig for permit2 (SPEC 12.2)
def permit2_digest(chain_id, au):
    """EIP-712 digest Permit2 checks in permitWitnessTransferFrom (PermitHash.hashWithWitness, EIP712._hashTypedData),
    with msg.sender = au["spender"] and the witness hash of x402ExactPermit2Proxy.settle."""
    dom = keccak256(DOMAIN3_TYPEHASH + PERMIT2_NAME_HASH + _w(chain_id) + _a(PERMIT2))
    witness = keccak256(WITNESS_TYPEHASH + _a(au["to"]) + _w(au["validAfter"]))
    tp = keccak256(TOKEN_PERMISSIONS_TYPEHASH + _a(au["token"]) + _w(au["amount"]))
    st = keccak256(PERMIT_WITNESS_TYPEHASH + tp + _a(au["spender"]) + _w(au["nonce"]) + _w(au["deadline"]) + witness)
    return keccak256(b"\x19\x01" + dom + st)


PERMIT_TRANSFER_TYPEHASH = keccak256(b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,"
                                     b"uint256 deadline)TokenPermissions(address token,uint256 amount)")


def permit_transfer_digest(chain_id, token, amount, spender, nonce, deadline):
    """EIP-712 digest Permit2 checks in permitTransferFrom without a witness (PermitHash.hash(PermitTransferFrom),
    cc56ad0), spender = msg.sender: the commerce-payments Permit2 collector (SPEC 0.16.1)."""
    dom = keccak256(DOMAIN3_TYPEHASH + PERMIT2_NAME_HASH + _w(chain_id) + _a(PERMIT2))
    tp = keccak256(TOKEN_PERMISSIONS_TYPEHASH + _a(token) + _w(amount))
    st = keccak256(PERMIT_TRANSFER_TYPEHASH + tp + _a(spender) + _w(nonce) + _w(deadline))
    return keccak256(b"\x19\x01" + dom + st)


def check_signature(pp):
    """Permit2 SignatureVerification.verify (cc56ad0) for a payer without code: 65 bytes r||s||v, or 64 bytes EIP-2098
    r||vs; ecrecover, no low-s rule; the recovered address must be permit2Authorization.from."""
    sig, au, acc = pp["signature"], pp["auth"], pp["accepted"]
    if sig.endswith(ERC6492_MAGIC):
        return "not_evaluated:erc6492_counterfactual_signature", []
    return signature_verification(sig, permit2_digest(acc["chain_id"], au), au["from"])


def signature_verification(sig, digest, owner):
    """SignatureVerification.verify for an owner without code, over digest: (result, notes)."""
    if len(sig) == 65:
        r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
        if v not in (27, 28):
            return "failed:v_not_27_or_28", []
    elif len(sig) == 64:
        vs = int.from_bytes(sig[32:], "big")
        r, s, v = int.from_bytes(sig[:32], "big"), vs & ((1 << 255) - 1), (vs >> 255) + 27
    else:
        return "not_evaluated:unsupported_signature_length_%d" % len(sig), []
    notes = []
    if s > SECP_N // 2:
        notes.append("signature s in the upper half of the order: Permit2 accepts it (SignatureVerification.sol calls "
                     "ecrecover with no s rule)")
    try:
        who = public_key_to_address(recover_public_key(digest, r, s, v - 27), keccak256)
    except ValueError as e:
        return "failed:no_recovery(%s)" % e, notes
    return ("verified" if who == owner else "failed:recovers_%s_not_from" % who), notes


# ------------------------------------------------------------------ chain evidence (SPEC 12.3)
def _word(b, i):
    return b[4 + 32 * i: 4 + 32 * (i + 1)]


def _tail(tail):
    """The calldata tail rule of SPEC 4 (nothing, an ERC-8021 Schema 2 or Schema 0 suffix); None if accepted."""
    if not tail:
        return None
    suffix = erc8021_schema2(tail)
    if suffix is not None:
        import apc_builder      # SPEC 0.16.1: read under x402 builder_code.md (section 14), as in apc-0.1 to apc-0.3
        fields, why = apc_builder.decode(bytes.fromhex(suffix))
        BUILDER.append(fields if fields is not None else {"malformed": why, "cbor": suffix})
        NOTES.append("calldata carries an ERC-8021 Schema 2 suffix (x402 builder-code extension): %s"
                     % (json.dumps(fields, sort_keys=True) if fields is not None else
                        "not an x402 builder-code map (%s), CBOR %s" % (why, suffix)))
        return None
    codes = erc8021_schema0(tail)
    if codes is not None:
        NOTES.append("calldata carries an ERC-8021 Schema 0 suffix (draft ERC, ethereum/ERCs PR #1209), codes %r, not "
                     "interpreted" % codes)
        return None
    NOTES.append("%d bytes of calldata after the ABI arguments, not an ERC-8021 suffix" % len(tail))
    return "not_evaluated:unrecognized_trailing_calldata"


def _c1_permit2(tx, pp):
    """settle / settleWithPermit of x402ExactPermit2Proxy, strict ABI: the arguments equal the payload."""
    b = _d(tx["input"], "chain_tx.tx.input")
    sel = b[:4]
    if sel == SEL_SETTLE:
        base, head, kind = 0, 8, "settle"
    elif sel == SEL_SETTLE_PERMIT:
        base, head, kind = 5, 13, "settleWithPermit"
    else:
        return "failed:tx_not_settle", None
    if len(b) < 4 + 32 * (head + 1):
        return "failed:tx_calldata_short", None
    if base and int.from_bytes(_word(b, 4), "big") > 255:
        return "failed:tx_v_out_of_range", None
    if any(_word(b, base + i)[:12] != bytes(12) for i in (0, 4, 5)):
        return "failed:tx_address_word_not_padded", None
    off = int.from_bytes(_word(b, base + 7), "big")
    if off != 32 * head:
        return "failed:tx_signature_offset_not_canonical", None
    n = int.from_bytes(b[4 + off: 4 + off + 32], "big")
    if n > len(b):
        return "failed:tx_signature_padding", None
    end = 4 + off + 32 + (n + 31) // 32 * 32
    if len(b) < end or any(b[4 + off + 32 + n: end]):
        return "failed:tx_signature_padding", None
    w = lambda i: int.from_bytes(_word(b, base + i), "big")  # noqa: E731
    got = {"token": "0x" + _word(b, base)[12:].hex(), "amount": w(1), "nonce": w(2), "deadline": w(3),
           "from": "0x" + _word(b, base + 4)[12:].hex(), "to": "0x" + _word(b, base + 5)[12:].hex(),
           "validAfter": w(6)}
    t = _tail(b[end:])
    if t is not None:
        return t, kind
    want = {k: v for k, v in pp["auth"].items() if k != "spender"}
    if got != want:
        return "failed:tx_arguments_differ_from_authorization", kind
    if b[4 + off + 32: 4 + off + 32 + n] != pp["signature"]:
        return "failed:tx_signature_differs_from_payload", kind
    if base:
        NOTES.append("settleWithPermit: the transaction also carries an EIP-2612 permit of value %d to Permit2 (deadline "
                     "%d), the approval only; x402BasePermit2Proxy requires its value to equal permitted.amount; its "
                     "signature is not checked here" % (w(-5), w(-4)))
    return "verified", kind


def _abi_canonical_redeem(pc, mode, ecd):
    """abi.encode(bytes[] [pc], bytes32[] [mode], bytes[] [ecd]), the standard head/tail layout."""
    def bytes_arr(x):
        pad = x + bytes(-len(x) % 32)
        return _w(1) + _w(32) + _w(len(x)) + pad
    a, c = bytes_arr(pc), bytes_arr(ecd)
    m = _w(1) + mode
    return _w(96) + _w(96 + len(a)) + _w(96 + len(a) + len(m)) + a + m + c


def _c1_erc7710(tx, pp):
    """redeemDelegations([permissionContext], [mode], [executionCallData]) at the delegation manager (x402
    scheme_exact_evm.md ERC-7710 phases 3-4); executionCallData = ERC-7579 single call (target, value, callData) of
    transfer(payTo, amount) on the asset."""
    b = _d(tx["input"], "chain_tx.tx.input")
    if b[:4] != SEL_REDEEM:
        return "failed:tx_not_redeemDelegations"
    try:
        x = b[4:]
        rd = lambda o: int.from_bytes(x[o:o + 32], "big") if o + 32 <= len(x) else -1  # noqa: E731
        o_pc, o_m, o_e = rd(0), rd(32), rd(64)
        if min(o_pc, o_m, o_e) < 0 or max(o_pc, o_m, o_e) > len(x):
            raise IndexError
        if rd(o_pc) != 1 or rd(o_m) != 1 or rd(o_e) != 1:
            return "failed:tx_not_one_delegation_redeemed"

        def one_bytes(o):
            inner = o + 32 + rd(o + 32)
            ln = rd(inner)
            if rd(o + 32) < 0 or ln < 0 or ln > len(x):
                raise IndexError
            return x[inner + 32: inner + 32 + ln]
        pc, mode, ecd = one_bytes(o_pc), x[o_m + 32: o_m + 64], one_bytes(o_e)
        if len(mode) != 32:
            raise IndexError
    except IndexError:
        return "failed:tx_not_redeemDelegations_abi"
    enc = _abi_canonical_redeem(pc, mode, ecd)
    if x[:len(enc)] != enc:
        return "failed:tx_calldata_not_canonical_abi"
    t = _tail(x[len(enc):])
    if t is not None:
        return t
    if pc != pp["auth"]["context"]:
        return "failed:tx_permission_context_differs_from_payload"
    if mode[0] != 0:
        return "not_evaluated:erc7579_call_type_%02x_not_single" % mode[0]
    if mode[1] not in (0, 1) or any(mode[2:]):
        return "not_evaluated:erc7579_mode_not_default"
    if mode[1] == 1:
        NOTES.append("ERC-7579 execType 0x01 (try): a failed transfer does not revert the redemption; C3 decides")
    acc = pp["accepted"]
    if len(ecd) != 20 + 32 + 68 or ecd[52:56] != SEL_TRANSFER:
        return "failed:execution_not_a_transfer_call"
    if "0x" + ecd[:20].hex() != acc["asset"]:
        return "failed:execution_target_not_asset"
    if any(ecd[20:52]):
        return "failed:execution_sends_native_value"
    if ecd[56:68] != bytes(12):
        return "failed:execution_address_word_not_padded"
    if "0x" + ecd[68:88].hex() != acc["pay_to"]:
        return "failed:execution_to_not_payTo"
    if int.from_bytes(ecd[88:120], "big") != acc["amount"]:
        return "failed:execution_amount_not_amount"
    return "verified"


def _log(lg, name, n_topics):
    if not isinstance(lg, dict) or not isinstance(lg.get("topics"), list) or len(lg["topics"]) != n_topics \
            or not all(isinstance(t, str) for t in lg["topics"]) or not isinstance(lg.get("data"), str):
        raise Refusal("chain_tx.%s: needs topics[%d] of strings and data" % (name, n_topics))
    for k in ("address", "transactionHash", "blockHash", "blockNumber", "logIndex"):
        if not isinstance(lg.get(k), str):
            raise Refusal("chain_tx.%s: needs string %s" % (name, k))
    for i, t in enumerate(lg["topics"]):
        _d(t, "chain_tx.%s.topics[%d]" % (name, i), 32)
    _d(lg["address"], "chain_tx.%s.address" % name, 20)
    _d(lg["transactionHash"], "chain_tx.%s.transactionHash" % name, 32)
    _d(lg["blockHash"], "chain_tx.%s.blockHash" % name, 32)
    return int(_q(lg["logIndex"], "chain_tx.%s.logIndex" % name).hex() or "0", 16), \
        _d(lg["data"], "chain_tx.%s.data" % name)


def _c2(acc, tx, tx_hash):
    """The transaction alone: its hash recomputed (EIP-1559), equal to the settlement's, its chainId, its sender."""
    c2 = []
    if tx_hash is not None:
        c2.append("verified" if tx["hash"].lower() == tx_hash else "failed:tx_hash_not_settlement_transaction")
    h = tx_hash_eip1559(tx)
    if h is None:
        c2.append("not_evaluated:tx_type_%s_hash_not_recomputed" % tx.get("type"))
    else:
        c2.append("verified" if h == tx["hash"].lower() else "failed:tx_hash_not_its_rlp")
        if int(_q(tx["chainId"], "chain_tx.tx.chainId").hex() or "0", 16) != acc["chain_id"]:
            c2.append("failed:tx_chainId_not_network")
        c2.append(_from_is_signer(tx))
    return c2


def _same_tx(lg, tx, name):
    out = [lg["transactionHash"].lower() == tx["hash"].lower() or "failed:%s_other_tx" % name]
    for k in ("blockHash", "blockNumber"):
        out.append(lg[k].lower() == tx[k].lower() or "failed:%s_block_not_tx_block" % name)
    return out


def _transfer(lt, acc, frm, to, amount, tx):
    """C3: the Transfer(from, to, amount) of the asset in this transaction (Permit2 safeTransferFrom; the delegator's
    transfer for ERC-7710)."""
    i, data = _log(lt, "log_transfer", 3)
    pad = "0x" + "0" * 24
    checks = [_removed(lt, "log_transfer"),
              lt["address"].lower() == acc["asset"] or "failed:log_transfer_not_from_asset",
              lt["topics"][0].lower() == TRANSFER_TOPIC or "failed:log_transfer_not_Transfer"] + \
        _same_tx(lt, tx, "log_transfer") + [
              lt["topics"][1].lower() == pad + frm[2:] or "failed:log_transfer_from_mismatch",
              lt["topics"][2].lower() == pad + to[2:] or "failed:log_transfer_to_mismatch",
              (len(data) == 32 and int.from_bytes(data, "big") == amount) or "failed:log_transfer_value_mismatch"]
    return i, next((x for x in checks if x is not True), "verified")


def check_chain(ct, pp, tx_hash):
    """(C1, C2, C3) of SPEC 12.3."""
    acc, au, permit2 = pp["accepted"], pp["auth"], pp["method"] == "permit2"
    _obj(ct, "chain_tx", ("network", "tx", "log_transfer") + (("log_settled",) if permit2 else ()))
    for name in ("log_transfer", "log_settled"):
        if isinstance(ct.get(name), dict) and "removed" in ct[name] and not isinstance(ct[name]["removed"], bool):
            raise Refusal("chain_tx.%s.removed: not a boolean" % name)
    tx = ct["tx"]
    if not isinstance(tx, dict) or not all(isinstance(tx.get(k), str) for k in ("to", "input", "hash", "blockHash",
                                                                             "blockNumber")):
        raise Refusal("chain_tx.tx: needs string members to, input, hash, blockHash, blockNumber")
    _d(tx["hash"], "chain_tx.tx.hash", 32)
    _d(tx["blockHash"], "chain_tx.tx.blockHash", 32)
    _q(tx["blockNumber"], "chain_tx.tx.blockNumber")
    if ct["network"] != acc["network"]:
        return "failed:chain_tx_network_mismatch", "not_evaluated:after_C1", "not_evaluated:after_C1"
    target = EXACT_PROXY if permit2 else au["manager"]
    kind = None
    if tx["to"].lower() != target:
        c1 = "not_applicable:indirect_call"
        NOTES.append("indirect call through %s: the calldata is the caller's and is not compared (C1); the logs are "
                     "(C2, C3)" % tx["to"].lower())
    elif permit2:
        c1, kind = _c1_permit2(tx, pp)
    else:
        c1 = _c1_erc7710(tx, pp)
    if not (c1 == "verified" or c1.startswith("not_applicable:")):
        return c1, "not_evaluated:after_C1", "not_evaluated:after_C1"
    c2 = _c2(acc, tx, tx_hash)
    i_tr, c3 = _transfer(ct["log_transfer"], acc, pp["payer"], au["to"] if permit2 else acc["pay_to"],
                         au["amount"] if permit2 else acc["amount"], tx)
    if permit2:     # the proxy's own event, emitted after Permit2's transfer (x402ExactPermit2Proxy.sol)
        ls = ct["log_settled"]
        i_st, data = _log(ls, "log_settled", 1)
        topics = {"settle": (TOPIC_SETTLED,), "settleWithPermit": (TOPIC_SETTLED_PERMIT,),
                  None: (TOPIC_SETTLED, TOPIC_SETTLED_PERMIT)}[kind]
        c2 += [_removed(ls, "log_settled"),
               ls["address"].lower() == EXACT_PROXY or "failed:log_settled_not_from_proxy",
               ls["topics"][0].lower() in topics or "failed:log_settled_not_the_settle_event",
               data == b"" or "failed:log_settled_data_not_empty"] + _same_tx(ls, tx, "log_settled")
        if c3 == "verified" and i_tr + 1 != i_st:
            c3 = "not_evaluated:log_transfer_not_next"
    c2r = next((x for x in c2 if x not in (True, "verified")), "verified")
    return c1, c2r, c3


# ------------------------------------------------------------------ payers with code (SPEC 12.5, 12.6)
# Closed list: EIP-7702 delegate address -> (name, keccak256 of its runtime code measured on Base 2026-10-26; the code of
# an existing account cannot change since EIP-6780). Sources pinned in sources/kernel_7702_d6cedde8_20261026 and
# sources/metamask_7702_63c0c19a_20261026.
KERNEL = "0xd6cedde84be40893d153be9d467cd6ad37875b28"
DELEGATOR = "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b"
DELEGATES = {KERNEL: ("Kernel 0.3.3", "e5b56d82025d2358308f77833fe29c3856b1a7a0f7a4b9f86b1fd77da3e3b4fb"),
             DELEGATOR: ("EIP7702StatelessDeleGator",
                         "6af675ac126c441bec5d5013da3331a52e7465fc0d5a662a8708a9f33ce497ba")}
KERNEL_SLOT = 0x7bcaa2ced2a71450ed5a9a1b4848e8e5206dbc3f06011e595f7f55428cc6f84f    # kernel.v3.validation - 1
KERNEL_WRAPPER_TYPEHASH = keccak256(b"Kernel(bytes32 hash)")
KERNEL_REPLAYABLE = keccak256(b"kernel.replayable.signature")
DOMAIN4_TYPEHASH = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
ERC1271_MAGIC = bytes.fromhex("1626ba7e")


def _rec(digest, r, s, v):
    """ecrecover: v 27 or 28, r and s in range; None when the precompile returns nothing."""
    if v not in (27, 28) or not 0 < r < SECP_N or not 0 < s < SECP_N:
        return None
    try:
        return public_key_to_address(recover_public_key(digest, r, s, v - 27), keccak256)
    except ValueError:
        return None


def kernel_check(pp, slot_word):
    """Kernel 0.3.3 isValidSignature (ValidationManager._verifySignature, ValidatorLib.decodeSignature): a first byte
    0x00 is the root mode; with no root validator installed (the low 21 bytes of the validation slot zero) the type is
    VALIDATION_TYPE_7702 and the check is solady ECDSA.recover over _toWrappedHash(hash) == the account itself."""
    sig, payer = pp["signature"], pp["auth"]["from"]
    if not sig or sig[0] != 0:
        return "not_evaluated:kernel_validation_mode_%02x_not_evaluated" % (sig[0] if sig else 0)
    if slot_word & ((1 << 168) - 1):
        return "not_evaluated:kernel_root_validator_installed"
    inner, chain = sig[1:], pp["accepted"]["chain_id"]
    if len(inner) >= 32 and inner[:32] == KERNEL_REPLAYABLE:
        inner, chain = inner[32:], 0        # _chainAgnosticHashTypedData: chainId 0
    if len(inner) == 65:
        r, s, v = int.from_bytes(inner[:32], "big"), int.from_bytes(inner[32:64], "big"), inner[64]
    elif len(inner) == 64:
        vs = int.from_bytes(inner[32:], "big")
        r, s, v = int.from_bytes(inner[:32], "big"), vs & ((1 << 255) - 1), (vs >> 255) + 27
    else:
        return "failed:kernel_signature_length_%d" % len(inner)
    dom = keccak256(DOMAIN4_TYPEHASH + keccak256(b"Kernel") + keccak256(b"0.3.3") + _w(chain) + _a(payer))
    digest = keccak256(b"\x19\x01" + dom + keccak256(KERNEL_WRAPPER_TYPEHASH + permit2_digest(pp["accepted"]["chain_id"],
                                                                                         pp["auth"])))
    who = _rec(digest, r, s, v)
    if who is None:
        return "failed:kernel_signature_invalid"
    return "verified (ERC-1271 Kernel 0.3.3 by EIP-7702)" if who == payer else "failed:kernel_signature_recovers_%s" % who


def delegator_check(pp):
    """EIP7702StatelessDeleGator._isValidSignature: OpenZeppelin ECDSA.recover (65 bytes, v 27 or 28, low s) over the
    hash itself == the account."""
    sig = pp["signature"]
    if len(sig) != 65:
        return "failed:delegate_signature_not_65_bytes"
    r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    if s > SECP_N // 2:
        return "failed:high_s_refused_by_delegate"
    who = _rec(permit2_digest(pp["accepted"]["chain_id"], pp["auth"]), r, s, v)
    if who is None:
        return "failed:delegate_signature_invalid"
    return ("verified (ERC-1271 EIP7702StatelessDeleGator by EIP-7702)" if who == pp["auth"]["from"]
            else "failed:recovers_%s_not_from" % who)


def _storage_rpc_word(r, path, payer, blk):
    got = _reply(r, path, "eth_getStorageAt", [payer, "0x%064x" % KERNEL_SLOT, blk])
    return got if got.startswith("failed:") else int.from_bytes(_d(got, path + ".result", 32), "big")


def payer_state(pc, pp, ct, inc, b1):
    """SPEC 12.5: (code bytes, Kernel slot word or None, how the state is known) or a check result string."""
    payer = pp["auth"]["from"]
    _obj(pc, "payer_code", (), ("rpc", "proof"))
    if len(pc) != 1:
        raise Refusal("payer_code: exactly one of rpc and proof")
    if "rpc" in pc:
        rp = _obj(pc["rpc"], "payer_code.rpc", ("code",), ("storage",))
        for k in rp:
            _obj(rp[k], "payer_code.rpc." + k, ("method", "params", "result"))
            if not isinstance(rp[k]["params"], list) or not rp[k]["params"] or not isinstance(rp[k]["params"][-1], str):
                raise Refusal("payer_code.rpc.%s.params: not a list ending in a block" % k)
        blk = rp["code"]["params"][-1]
        _q(blk, "payer_code.rpc.code.params[1]")
        if ct is not None and blk.lower() != ct["tx"]["blockNumber"].lower():
            return "failed:payer_code_block_not_tx_block"
        code = _reply(rp["code"], "payer_code.rpc.code", "eth_getCode", [payer, blk.lower()])
        if code.startswith("failed:"):
            return code
        word = None
        if "storage" in rp:
            word = _storage_rpc_word(rp["storage"], "payer_code.rpc.storage", payer, blk.lower())
            if isinstance(word, str):
                return word
        return _d(code, "payer_code.rpc.code.result"), word, "declared_rpc"
    pr = _obj(pc["proof"], "payer_code.proof", ("code", "parent_header", "at_parent", "at_block"))
    code = _d(pr["code"], "payer_code.proof.code")
    ph = _header_obj(pr["parent_header"], "payer_code.proof.parent_header")
    ends = {}
    for end in ("at_parent", "at_block"):
        e = _obj(pr[end], "payer_code.proof." + end, ("payer",), ("delegate",))
        parts = {}
        for who in e:
            w = _obj(e[who], "payer_code.proof.%s.%s" % (end, who), ("accountProof",),
                     ("storageProof",) if who == "payer" else ())
            nodes = {}
            for k in w:
                if not isinstance(w[k], list) or len(w[k]) > 64:
                    raise Refusal("payer_code.proof.%s.%s.%s: not a list of at most 64 nodes" % (end, who, k))
                nodes[k] = [_d(n, "payer_code.proof.%s.%s.%s[]" % (end, who, k)) for n in w[k]]
            parts[who] = nodes
        ends[end] = parts
    if inc is None:
        return "not_evaluated:payer_code_proof_needs_inclusion"
    if b1 != "verified":
        return "not_evaluated:payer_code_proof_block_not_bound"
    hdr = inc["block_header"]
    try:
        if apc_block.header_hash(ph) != str(ph["hash"]).lower() or ph["hash"].lower() != str(hdr["parentHash"]).lower() \
                or apc_block._qty(ph["number"], "n") + 1 != apc_block._qty(hdr["number"], "n"):
            return "failed:payer_state_parent_header_not_parent"
        delegate = "0x" + code[3:].hex() if len(code) == 23 and code[:3] == b"\xef\x01\x00" else None
        words = []
        for end, h in (("at_parent", ph), ("at_block", hdr)):
            root = apc_block._hexbytes(h["stateRoot"], "stateRoot", 32)
            _, _, sroot, chash = apc_l1proof.account(root, bytes.fromhex(payer[2:]), ends[end]["payer"]["accountProof"])
            if chash != keccak256(code):
                return "failed:payer_state_code_not_proven"
            if "storageProof" in ends[end]["payer"]:
                words.append(apc_l1proof.storage(sroot, KERNEL_SLOT, ends[end]["payer"]["storageProof"]))
            if delegate in DELEGATES:
                if "delegate" not in ends[end]:
                    raise Refusal("payer_code.proof.%s: the listed delegate needs its account proof" % end)
                dh = apc_l1proof.account(root, bytes.fromhex(delegate[2:]), ends[end]["delegate"]["accountProof"])[3]
                if dh.hex() != DELEGATES[delegate][1]:
                    return "failed:payer_state_delegate_code_not_pinned"
    except apc_block.BlockRefusal as e:
        return "failed:payer_state_proof:%s" % e
    if len(words) not in (0, 2):
        raise Refusal("payer_code.proof: storageProof at both ends or at neither")
    if words and words[0] != words[1]:
        return "failed:payer_state_slot_changed_in_block"
    return code, (words[0] if words else None), "proven_at_parent_and_block"


def with_code(pp, st, eoa):
    """SPEC 12.5: L2.sig once the payer's code is known. eoa = the result of 12.2 for a payer without code."""
    code, word, _ = st
    n = len(pp["signature"])
    if code == b"":
        return eoa if n in (64, 65) else "failed:signature_length_%d_for_a_payer_without_code" % n
    delegate = "0x" + code[3:].hex() if len(code) == 23 and code[:3] == b"\xef\x01\x00" else None
    if delegate == KERNEL:
        if word is None:
            raise Refusal("payer_code: a Kernel delegate needs the validation slot (storage)")
        return kernel_check(pp, word)
    if delegate == DELEGATOR:
        return delegator_check(pp)
    return "not_evaluated:payer_code_not_known"


def erc1271_declared(ec, pp, ct, inc):
    """SPEC 12.6: a declared eth_call of isValidSignature(digest, signature) on the payer. Returns (result, report)."""
    _obj(ec, "erc1271_call", ("call", "block_hash", "endpoint"))
    _obj(ec["call"], "erc1271_call.call", ("method", "params", "result"))
    if not isinstance(ec["call"]["params"], list) or len(ec["call"]["params"]) != 2:
        raise Refusal("erc1271_call.call.params: not [call, block]")
    blk = ec["call"]["params"][1]
    _q(blk, "erc1271_call.call.params[1]")
    bh = _str(ec["block_hash"], "erc1271_call.block_hash")
    _d(bh, "erc1271_call.block_hash", 32)
    if len(_str(ec["endpoint"], "erc1271_call.endpoint")) > 256:
        raise Refusal("erc1271_call.endpoint: longer than 256 characters")
    sig = pp["signature"]
    data = "0x" + (ERC1271_MAGIC + permit2_digest(pp["accepted"]["chain_id"], pp["auth"]) + _w(64) + _w(len(sig))
                   + sig + bytes(-len(sig) % 32)).hex()
    got = _reply(ec["call"], "erc1271_call.call", "eth_call", [{"to": pp["auth"]["from"], "data": data}, blk.lower()])
    rep = {"declared": True, "block": blk.lower(), "block_hash": bh.lower(), "endpoint": ec["endpoint"]}
    if got.startswith("failed:"):
        return got, rep
    n = int(blk, 16)
    if ct is not None:
        tb = int(ct["tx"]["blockNumber"], 16)
        if n not in (tb, tb - 1):
            return "failed:erc1271_call_block_not_tx_block_or_parent", rep
        if inc is not None:
            want = (inc["block_header"]["hash"] if n == tb else inc["block_header"]["parentHash"]).lower()
            if bh.lower() != want:
                return "failed:erc1271_call_block_hash_not_header", rep
    ret = _d(got, "erc1271_call.call.result")
    rep["returned"] = "0x" + ret.hex()
    if len(ret) == 32 and ret == ERC1271_MAGIC + bytes(28):
        return "not_evaluated:erc1271_declared_valid", rep
    return "failed:erc1271_declared_invalid", rep


# ------------------------------------------------------------------ the bundle (SPEC 12.4)
def _settlement(doc, acc, payer, res):
    if "settlement" not in doc:
        res["T1"] = res["T2"] = "not_evaluated:absent:no_settlement"
        return None
    st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network"),
              ("errorReason", "payer", "amount", "extensions"))
    if not isinstance(st["success"], bool):
        raise Refusal("settlement.success: not a boolean")
    if "extensions" in st and not isinstance(st["extensions"], dict):
        raise Refusal("settlement.extensions: not an object")
    tx_hash = None
    if st["success"] is not True:
        named = isinstance(st["transaction"], str) and HASH32.match(st["transaction"])
        res["T1"] = "failed:settlement_not_successful"
        if st.get("errorReason") == "settlement_pending":
            res["T1"] = ("not_evaluated:settlement_pending" if named
                         else "failed:settlement_pending_without_transaction_hash")
    elif not isinstance(st["transaction"], str) or not HASH32.match(st["transaction"]):
        res["T1"] = "failed:transaction_not_a_32_byte_hash"
    else:
        res["T1"] = "verified"
        tx_hash = st["transaction"].lower()
    t2 = [eq(_str(st["network"], "settlement.network"), acc["network"], "network")]
    if "payer" in st:
        t2.append(eq(_addr(st["payer"], "settlement.payer"), payer, "payer"))
    if "amount" in st:
        t2.append(eq(_uint(st["amount"], "settlement.amount"), acc["amount"], "amount"))
    res["T2"] = next((x for x in t2 if x != "verified"), "verified")
    return tx_hash


def _k4(doc, pp, res):
    import apc_verify
    if "payment_required" not in doc:
        res["K4"] = "not_evaluated:absent:no_payment_required"
        return
    pr = _obj(doc["payment_required"], "payment_required", ("x402Version", "resource", "accepts"), ("error", "extensions"))
    if _int_json(pr["x402Version"], "payment_required.x402Version") != 2:
        raise Unsupported("payment_required.x402Version %r (2 only)" % (pr["x402Version"],))
    if "error" in pr and not isinstance(pr["error"], str):
        raise Refusal("payment_required.error: not a string")
    if not isinstance(pr["accepts"], list) or not pr["accepts"]:
        raise Refusal("payment_required.accepts: not a non-empty array")
    for i, a in enumerate(pr["accepts"]):
        if not isinstance(a, dict):
            raise Refusal("payment_required.accepts[%d]: not an object" % i)
        apc_verify.parse_offer(a, "payment_required.accepts[%d]" % i)
    resource_info(pr["resource"], "payment_required.resource")
    if "extensions" in pr and not isinstance(pr["extensions"], dict):
        raise Refusal("payment_required.extensions: not an object")
    res["K4"] = "verified" if any(_json_eq(pp["raw_accepted"], a) for a in pr["accepts"]) else "failed:accepted_not_offered"
    if pp["resource_url"] is not None and pp["resource_url"] != _str(pr["resource"]["url"], "payment_required.resource.url"):
        res["K4"] = "failed:resource_url_mismatch"


def _k3(au, acc, sig):
    return ("failed:permitted_token_not_asset" if au["token"] != acc["asset"] else
            "verified (token; chainId by L2.sig)" if sig.startswith("verified") else
            "failed:by_L2.sig" if sig.startswith("failed") else "not_evaluated:by_L2.sig")


B3_NAMES = {"failed:authorization_log_not_in_receipt": "failed:transfer_log_not_in_receipt",
            "failed:transfer_log_not_next_in_receipt": "failed:settled_log_not_next_in_receipt"}


def _inclusion(doc, pp, res, notes, l1_checkpoint):
    """SPEC 12.7: section 6 B1-B4, E1 and O1-O4/L1 on an apc-0.10 bundle, by the same code."""
    acc, au, permit2 = pp["accepted"], pp["auth"], pp["method"] == "permit2"
    if "canonical" in doc and "inclusion" not in doc:
        raise Refusal("canonical without inclusion")
    if "inclusion" not in doc:
        why = "not_evaluated:absent:no_inclusion" if "chain_tx" in doc else "not_evaluated:absent:no_chain_tx"
        for k in ("B1", "B2", "B3", "B4", "O1", "O2", "O3", "O4", "L1"):
            res[k] = why
        return
    if "chain_tx" not in doc:
        raise Refusal("inclusion or canonical without chain_tx")
    # B4 reads a strict window (validAfter < t < validBefore); Permit2's is inclusive at both ends
    view = ({"from": pp["payer"], "validAfter": au["validAfter"] - 1, "validBefore": au["deadline"] + 1} if permit2
            else {"from": pp["payer"], "validAfter": 0, "validBefore": 0})
    b, e1 = check_inclusion(doc["inclusion"], doc["chain_tx"], view, anchor="log_transfer",
                            nxt="log_settled" if permit2 else None, anchor_is_payment=True)
    b["B3"] = B3_NAMES.get(b["B3"], b["B3"])
    if not permit2:
        b["B4"] = "not_applicable:erc7710_no_signed_window"
    res.update(b)
    notes += e1
    if "canonical" in doc:
        o, on = check_canonical(doc["canonical"], doc["inclusion"]["block_header"], acc["network"], l1_checkpoint)
        res.update(o)
        notes += on
    else:
        res["O1"] = res["O2"] = res["O3"] = res["O4"] = res["L1"] = "not_evaluated:absent:no_canonical"


def verify(doc, http_keys=None, l1_checkpoint=None, signer_trust=None):
    _obj(doc, "bundle", ("bundle_version", "payment_payload"),
         ("payment_required", "settlement", "chain_tx", "mandate", "exchange", "provenance", "payer_code",
          "erc1271_call", "inclusion", "canonical", "acceptance"))
    pp = parse_payload(doc["payment_payload"])
    acc, au, permit2 = pp["accepted"], pp["auth"], pp["method"] == "permit2"
    if not permit2 and ("payer_code" in doc or "erc1271_call" in doc):
        raise Refusal("payer_code and erc1271_call: permit2 only (an erc7710 payload carries no signature)")
    res, notes = {}, list(acc["notes"])
    del NOTES[:]
    del BUILDER[:]
    if permit2:
        res["L2.sig"], n = check_signature(pp)
        notes += n
        res["K1"] = eq(au["to"], acc["pay_to"], "witness_to_payTo")
        res["K2"] = eq(au["amount"], acc["amount"], "permitted_amount_amount")
        res["K7"] = "verified" if au["spender"] == EXACT_PROXY else "failed:spender_not_x402_exact_permit2_proxy"
        if au["validAfter"] > au["deadline"]:
            res["K5"] = "failed:empty_validity_window"
        else:
            res["K5"] = "verified"
            notes.append("validity window %d s (witness.validAfter to deadline, both inclusive); "
                         "accepted.maxTimeoutSeconds %d (relation not stated by the spec)"
                         % (au["deadline"] - au["validAfter"], acc["max_timeout"]))
        res["K6"] = "verified" if au["amount"] > 0 else "failed:zero_amount"
    else:
        opaque = "not_evaluated:erc7710_permission_context_opaque"
        res["L2.sig"] = res["K1"] = res["K2"] = res["K3"] = opaque
        res["K6"] = "verified" if acc["amount"] > 0 else "failed:zero_amount"
        notes.append("erc7710: the permissionContext is opaque (x402 scheme_exact_evm.md: its structure is the "
                     "Delegation Manager's, verification is by simulation); nothing in the payload is a signature this "
                     "verifier can check offline, so the bundle is at best chain_incomplete")
    _k4(doc, pp, res)
    tx_hash = _settlement(doc, acc, pp["payer"], res)
    settled_by = None
    if "chain_tx" in doc:
        res["C1"], res["C2"], res["C3"] = check_chain(doc["chain_tx"], pp, tx_hash)
        notes += NOTES
        notes.append("chain_tx is RPC data carried by the bundle: C2 recomputes the transaction hash from its fields; "
                     "nothing here shows that the transaction or its logs are in a block of the canonical chain")
        if res["C2"] == "verified":
            settled_by = tx_sender_eip1559(doc["chain_tx"]["tx"])
        executed = res["C2"] == "verified" and res["C3"] == "verified" and (
            res["C1"] == "verified" or res["C1"].startswith("not_applicable:"))
        if executed and res["T1"] in ("failed:settlement_not_successful", "not_evaluated:settlement_pending"):
            pending = res["T1"] == "not_evaluated:settlement_pending"
            res["T1"] = ("not_evaluated:settlement_pending_executed_on_chain" if pending
                         else "failed:settlement_reported_failed_but_executed_on_chain")
            # SPEC 29.6 (Amendment 0.3.2 in apc-0.10): whether the transaction the failed reply names is this one
            named = doc["settlement"]["transaction"]
            named = named.lower() if isinstance(named, str) and HASH32.match(named) else None
            ran = str(doc["chain_tx"]["tx"]["hash"]).lower()
            notes.append("T1: the settlement reply says the payment did not (yet) succeed, and the chain_tx the bundle "
                         "carries shows the transfer executed (C1-C3)%s"
                         % ("" if named is None else "; it is the transaction the reply names" if named == ran else
                            "; the reply names %s, another transaction executed it (the preemption pattern of arXiv "
                            "2605.11781 I-B)" % named))
    else:
        res["C1"] = res["C2"] = res["C3"] = "not_evaluated:absent:no_chain_tx"
    _inclusion(doc, pp, res, notes, l1_checkpoint)
    state = erc1271 = None
    if permit2:
        ct, inc = doc.get("chain_tx"), doc.get("inclusion")
        if "payer_code" in doc:         # SPEC 12.5
            st = payer_state(doc["payer_code"], pp, ct, inc, res.get("B1"))
            if isinstance(st, str):
                res["L2.sig"] = st
            else:
                state = st[2]
                res["L2.sig"] = with_code(pp, st, res["L2.sig"])
                notes.append("L2.sig: the payer's code%s %s (SPEC 12.5)" % (
                    " and validation slot" if st[1] is not None else "",
                    "are RPC replies carried by the bundle (declared) at the transaction's block" if state == "declared_rpc"
                    else "are proven equal at the end of the parent block and of the transaction's block; a transaction "
                         "earlier in the block could change them and change them back, which is not excluded"))
        if "erc1271_call" in doc:       # SPEC 12.6
            r, erc1271 = erc1271_declared(doc["erc1271_call"], pp, ct, inc)
            decided = res["L2.sig"].startswith(("verified", "failed"))
            if r not in ("not_evaluated:erc1271_declared_valid", "failed:erc1271_declared_invalid"):
                res["L2.sig"] = r           # the call is not for this payer, digest, signature or block
            elif r == "failed:erc1271_declared_invalid" and res["L2.sig"].startswith("verified"):
                res["L2.sig"] = "failed:erc1271_declared_contradicts_offline_check"
            elif not decided:
                res["L2.sig"] = r
            notes.append("erc1271_call: a DECLARED eth_call of isValidSignature on the payer at block %s from %s, "
                         "returned %s; reported as declared, never as verified (SPEC 12.6)"
                         % (erc1271["block"], erc1271["endpoint"], erc1271.get("returned", "-")))
        res["K3"] = _k3(au, acc, res["L2.sig"])
    if "acceptance" in doc:             # SPEC 12.7: A1-A2 of section 4 on the apc-0.10 terms
        view = {"accepted": acc, "auth": {"from": pp["payer"], "to": au["to"] if permit2 else acc["pay_to"],
                                          "value": au["amount"] if permit2 else acc["amount"],
                                          "nonce": "0x%064x" % au["nonce"] if permit2 else None}}
        res["A1"], res["A2"] = check_acceptance(doc["acceptance"], view, tx_hash)
        if not permit2 and res["A1"] == "failed:nonce_mismatch":
            res["A1"] = "not_evaluated:erc7710_payment_has_no_nonce"
    else:
        res["A1"] = res["A2"] = "not_evaluated:absent:no_acceptance"
    if "mandate" in doc:
        if not isinstance(doc["mandate"], dict):
            raise Refusal("mandate: not an object")
        if doc["mandate"].get("profile") == "pulse-ap2-x402/0.3":
            res["M1"], mn = check_mandate(doc["mandate"], doc["payment_payload"])
            notes += mn
        else:
            res["M1"] = "not_evaluated:ap2_has_no_x402_binding"
    else:
        res["M1"] = "not_evaluated:absent:no_mandate"
    xr, xn, xm = exchange_checks(doc, http_keys)
    if xr:
        res.update(xr)
        notes += xn
    # SPEC 0.16.1: the amendments that hold for every bundle version, by the code of apc-0.1 to apc-0.3
    bcr, bcn, bcm = builder_code_checks(doc, BUILDER[0] if BUILDER and res.get("C1") == "verified" else None)
    res.update(bcr)                                      # BC1, section 14
    notes += bcn
    import apc_payid                                     # PI1, section 15
    pir, pin = apc_payid.check(doc)
    res.update(pir)
    notes += pin
    pr_doc, st_doc = doc.get("payment_required"), doc.get("settlement")
    btime = int(doc["inclusion"]["block_header"]["timestamp"], 16) if res.get("B1") == "verified" else None
    orr, orn, orm = offer_receipt_checks(doc, {        # OR1-OR3, section 13
        "evm": True, "network": acc["network"], "scheme": "exact", "asset": acc["asset"], "pay_to": acc["pay_to"],
        "amount": str(acc["amount"]),
        "resource_url": pp["resource_url"] if pp["resource_url"] is not None else
        (pr_doc["resource"]["url"] if isinstance(pr_doc, dict) else None),
        "payer": pp["payer"], "transaction": st_doc["transaction"] if isinstance(st_doc, dict) and
        isinstance(st_doc.get("transaction"), str) else None,
        "success": st_doc["success"] if isinstance(st_doc, dict) else None, "block_time": btime,
        "accepts": pr_doc["accepts"] if isinstance(pr_doc, dict) else None}, signer_trust)
    res.update(orr)
    notes += orn
    failed = sorted(k for k, x in res.items() if x.startswith("failed"))
    absent = sorted(k for k, x in res.items() if x.startswith("not_evaluated:absent:"))
    open_ = sorted(k for k, x in res.items() if x.startswith("not_evaluated") and k not in absent)
    core = all(res[k].startswith("verified") for k in ("L2.sig", "K1", "K2", "K3") + (("K7",) if permit2 else ()))
    if res.get("C1", "").startswith("not_applicable:"):
        core = core and res.get("C3") == "verified"
    verdict = "chain_failed" if failed else ("chain_verified" if core and not open_ else "chain_incomplete")
    out = {"verdict": verdict, "method": pp["method"], "checks": res, "failed": failed, "not_evaluated": open_,
           "absent": absent, "notes": notes, "payer_is_payee": pp["payer"] == acc["pay_to"], "settled_by": settled_by,
           "exchange": xm, "payer_state": state, "erc1271": erc1271}
    out["block_bound"] = all(res.get(k) == "verified" for k in ("B1", "B2", "B3")) and (
        res.get("B4") in ("verified", "not_applicable:erc7710_no_signed_window"))
    bound_report(res, out)
    if bcm is not None:
        out["builder_code"] = bcm
    if orm is not None:
        out["offer_receipt"] = orm
    ai = apc_assets.info(acc["network"], acc["asset"], acc["amount"])       # section 19: measured assets only
    if ai is not None:
        out["asset"] = ai
        dom = (acc["domain_name"], acc["domain_version"])
        if dom != (None, None) and dom != (ai["eip712"]["name"], ai["eip712"]["version"]):
            notes.append("accepted.extra names the EIP-712 domain (%r, %r); the measured domain of this asset is (%r, "
                         "%r) (SPEC 0.11.5): Permit2 signs under its own domain, the token's is the EIP-2612 permit's"
                         % (dom + (ai["eip712"]["name"], ai["eip712"]["version"])))
    if out["payer_is_payee"]:
        notes.append("the payer is the payee (%s): the transfer moves no value to anyone else" % pp["payer"])
    out["provenance"], pn = provenance(doc)
    if pn:
        notes.append(pn)
    return out
