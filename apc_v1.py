"""SPEC 0.13 (SPEC.md section 21): x402 version 1 payments (x402 4241d56 specs/x402-specification-v1.md, cited V1 §),
bundle apc-0.13, EVM `exact` with EIP-3009. Version 1 differs from 2 where the evidence is concerned: the payload
names only scheme and network (the requirement it pays is found in the PaymentRequired it answers), networks are
names ("base"), the amount is `maxAmountRequired` and the payment "meets or exceeds" it (V1 6.1.2 step 3), the resource
is a member of the requirement. The bundle is read as the apc-0.3 bundle these objects map to, then the v1 rules
replace the v2 ones where they differ. Standard library only."""
import copy

from apc_verify import Refusal, Unsupported, _int_json, _obj, _str

# x402 4241d56 typescript/packages/legacy/x402/src/types/shared/network.ts EvmNetworkToChainId (the v1 SDK's table)
V1_EVM = {"abstract": 2741, "abstract-testnet": 11124, "base-sepolia": 84532, "base": 8453, "avalanche-fuji": 43113,
          "avalanche": 43114, "iotex": 4689, "sei": 1329, "sei-testnet": 1328, "polygon": 137, "polygon-amoy": 80002,
          "peaq": 3338, "story": 1514, "educhain": 41923, "skale-base-sepolia": 324705682}
REQ_REQ = ("scheme", "network", "maxAmountRequired", "asset", "payTo", "resource", "description", "maxTimeoutSeconds")
REQ_OPT = ("mimeType", "outputSchema", "extra")


def _net(v, path):
    n = _str(v, path)
    if n not in V1_EVM:
        raise Unsupported("%s %r: not an EVM network of the x402 v1 table (solana and others not read)" % (path, n))
    return "eip155:%d" % V1_EVM[n]


def _req(a, path):
    _obj(a, path, REQ_REQ, REQ_OPT)
    if "outputSchema" in a and a["outputSchema"] is not None and not isinstance(a["outputSchema"], dict):
        raise Refusal(path + ".outputSchema: not an object or null")
    for k in ("resource", "description") + (("mimeType",) if "mimeType" in a else ()):
        if not isinstance(a[k], str):
            raise Refusal("%s.%s: not a string" % (path, k))
    v2 = {"scheme": a["scheme"], "network": _net(a["network"], path + ".network"), "amount": a["maxAmountRequired"],
          "asset": a["asset"], "payTo": a["payTo"], "maxTimeoutSeconds": a["maxTimeoutSeconds"]}
    if "extra" in a:
        v2["extra"] = a["extra"]
    res = {"url": a["resource"], "description": a["description"]}
    if "mimeType" in a:
        res["mimeType"] = a["mimeType"]
    return v2, res


def to_v2(doc):
    """(apc-0.3 document, notes, the index of the requirement paid) or Refusal / Unsupported."""
    _obj(doc, "bundle", ("bundle_version", "payment_payload", "payment_required"),
         ("settlement", "chain_tx", "inclusion", "canonical", "facilitator", "provenance", "acceptance", "mandate",
          "payer_wallet"))
    pp = _obj(doc["payment_payload"], "payment_payload", ("x402Version", "scheme", "network", "payload"))
    if _int_json(pp["x402Version"], "payment_payload.x402Version") != 1:
        raise Unsupported("payment_payload.x402Version %r (apc-0.13: 1)" % (pp["x402Version"],))
    if _str(pp["scheme"], "payment_payload.scheme") != "exact":
        raise Unsupported("payment_payload.scheme %r (exact only)" % pp["scheme"])
    net = _net(pp["network"], "payment_payload.network")
    pr = _obj(doc["payment_required"], "payment_required", ("x402Version", "error", "accepts"))
    if _int_json(pr["x402Version"], "payment_required.x402Version") != 1:
        raise Unsupported("payment_required.x402Version %r (apc-0.13: 1)" % (pr["x402Version"],))
    if not isinstance(pr["error"], str):
        raise Refusal("payment_required.error: not a string")
    if not isinstance(pr["accepts"], list) or not pr["accepts"]:
        raise Refusal("payment_required.accepts: not a non-empty array")
    conv, chosen = [], []
    for i, a in enumerate(pr["accepts"]):
        if not isinstance(a, dict):
            raise Refusal("payment_required.accepts[%d]: not an object" % i)
        if a.get("scheme") == "exact" and a.get("network") in V1_EVM:
            v2, res = _req(a, "payment_required.accepts[%d]" % i)
            conv.append((v2, res))
            if a["network"] == pp["network"]:
                chosen.append(len(conv) - 1)
    notes = []
    if not chosen:
        raise Refusal("payment_required.accepts: no exact requirement on the payload's network %r: the payment "
                      "answers no requirement the bundle carries" % pp["network"])
    if len(chosen) > 1:
        # V1 names no field that says which of several requirements on one network was paid: the first one whose payTo
        # is the authorization's recipient and whose amount the value meets (V1 6.1.2 steps 3 and 5)
        au = pp["payload"].get("authorization") if isinstance(pp["payload"], dict) else None
        to = str(au.get("to", "")).lower() if isinstance(au, dict) else ""
        fit = [c for c in chosen if str(conv[c][0]["payTo"]).lower() == to]
        if len(fit) != 1:
            raise Refusal("payment_required.accepts: %d exact requirements on %r and the authorization's recipient does "
                          "not single one out" % (len(chosen), pp["network"]))
        chosen = fit
        notes.append("V1: several requirements on %s; the one whose payTo is the authorization's recipient is read"
                     % pp["network"])
    acc, res = conv[chosen[0]]
    v2 = {"bundle_version": "apc-0.3",
          "payment_payload": {"x402Version": 2, "accepted": acc, "payload": pp["payload"], "resource": res},
          "payment_required": {"x402Version": 2, "resource": res, "accepts": [c[0] for c in conv]}}
    if pr["error"]:
        v2["payment_required"]["error"] = pr["error"]
    if "settlement" in doc:
        st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network", "payer"), ("errorReason",))
        s2 = {"success": st["success"], "transaction": st["transaction"],
              "network": _net(st["network"], "settlement.network"), "payer": st["payer"]}
        if "errorReason" in st:
            s2["errorReason"] = st["errorReason"]
        v2["settlement"] = s2
    for k in ("chain_tx", "inclusion", "canonical", "facilitator", "provenance", "acceptance", "mandate", "payer_wallet"):
        if k in doc:
            v2[k] = copy.deepcopy(doc[k])
    if "chain_tx" in v2 and isinstance(v2["chain_tx"], dict) and v2["chain_tx"].get("network") != net:
        raise Refusal("chain_tx.network: not the CAIP-2 form %s of the payload's network %r" % (net, pp["network"]))
    return v2, notes, chosen[0]


def verify(doc, l1_checkpoint=None, signer_trust=None):
    import apc_verify as av
    v2, notes, _ = to_v2(doc)
    rep = av._verify_bundle(v2, l1_checkpoint, None, signer_trust)
    ck = rep["checks"]
    au = v2["payment_payload"]["payload"]["authorization"]
    need = int(v2["payment_payload"]["accepted"]["amount"])
    # V1 6.1.2 step 3: the value "meets or exceeds" maxAmountRequired; v2's exact equality is not the v1 rule
    if ck["K2"].startswith("failed") and isinstance(au.get("value"), str) and au["value"].isdigit() and \
            int(au["value"]) > need:
        ck["K2"] = "verified (v1: value %s exceeds maxAmountRequired %d)" % (au["value"], need)
        rep["notes"].append("K2: x402 v1 accepts a value that meets or exceeds maxAmountRequired (V1 6.1.2 step 3)")
    # K4: the requirement is chosen from payment_required, so accepted is offered by construction
    ck["K4"] = "verified (v1: the requirement is read from payment_required)"
    failed = sorted(k for k, x in ck.items() if x.startswith("failed"))
    absent = sorted(k for k, x in ck.items() if x.startswith("not_evaluated:absent:"))
    open_ = sorted(k for k, x in ck.items() if x.startswith("not_evaluated") and k not in absent)
    core = all(ck[k].startswith("verified") for k in ("L2.sig", "K1", "K2", "K3"))
    if ck.get("C1", "").startswith("not_applicable:"):
        core = core and ck.get("C3") == "verified"
    rep.update(verdict="chain_failed" if failed else ("chain_verified" if core and not open_ else "chain_incomplete"),
               failed=failed, not_evaluated=open_, absent=absent, notes=notes + rep["notes"] +
               ["x402 v1 bundle read as the apc-0.3 bundle its objects map to (SPEC section 21)"], x402_version=1)
    return rep
