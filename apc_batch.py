"""agent-payment-chain, checks across a SET of bundles (SPEC 0.3 rules D1-D2). Offline.

One EIP-3009 authorization can settle on chain once (the token marks its nonce used), but nothing on chain stops the
same settled payment from being shown to unlock two different things. Across the bundles given:
  D1  one authorization (network, asset, payer, nonce; on Solana, SPEC 0.5: network, asset and the transaction
      message) appears in two bundles that name different resources or
      different acceptance receipts -> failed:same_payment_for_two_deliveries (the "free shopping" class of
      arXiv 2607.19545 seen from the evidence side)
  D2  the same authorization in several bundles with the same delivery -> reported as a duplicate bundle
  D3  one authorization in two bundles whose settlements name different transactions -> failed:
      same_authorization_two_settlements (the token executes one (from, nonce) once: at most one of them is true)
  D4  one payment-identifier (SPEC 0.11.2, x402 payment_identifier.md) in two bundles of one merchant (network, payTo and the
      resource URL's origin) with different request fingerprints (scheme, asset, amount, resource: PI "Request Binding") -> failed:payment_identifier_reused (PI: 409 Conflict); the same id and
      fingerprint with two different authorizations whose settlements (T1 verified) name transactions ->
      failed:payment_identifier_two_settled_payments (an idempotent operation paid twice)
Each bundle is first checked alone by apc_verify; a bundle refused there is listed and kept out of D1-D4.

  python3 apc_batch.py BUNDLE.json [BUNDLE.json ...]      exit 0 no failure, 1 a D1, D3 or D4 failure, 64 usage (or the
                                                          signature library absent: one line on standard error, SPEC 32.12 (f))
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_siglib  # noqa: E402
apc_siglib.guard("apc_batch", __name__ == "__main__")  # SPEC 32.11 (c), 32.12 (f): without the library one line, exit 64 (1 would read as a failure)
import apc_payid  # noqa: E402
import apc_verify as av  # noqa: E402


def _key(doc):
    if doc["bundle_version"] == "apc-0.5":
        # SPEC 0.5: on Solana the payment is its transaction message (the fee payer's signature, the transaction id,
        # is deterministic Ed25519 over it); called after verify_bundle accepted the bundle
        import apc_svm
        pl = doc["payment_payload"]
        acc = apc_svm.parse_requirements(pl["accepted"], "payment_payload.accepted")
        tx = apc_svm._parse(apc_svm._b64(pl["payload"]["transaction"], "t"), "t")
        pp = {"resource_url": (pl.get("resource") or {}).get("url")}
        return (acc["network"], acc["asset"], "message", hashlib.sha256(tx["message"]).hexdigest()), pp
    if doc["bundle_version"] == "apc-0.10":
        # SPEC 0.10: Permit2's unordered nonce is per owner across tokens; an ERC-7710 delegation may be multi-use
        import apc_permit2
        pp = apc_permit2.parse_payload(doc["payment_payload"])
        if pp["method"] != "permit2":
            raise av.Refusal("kept out of D1-D4: an erc7710 payment has no one-time authorization key (a delegation "
                             "may be multi-use, SPEC 0.10)")
        return (pp["accepted"]["network"], apc_permit2.PERMIT2, pp["auth"]["from"], str(pp["auth"]["nonce"])), pp
    if doc["bundle_version"] == "apc-0.12":
        # SPEC 0.12: on Stellar one authorization is (network, asset, payer, the Soroban nonce of its entry), which the
        # host consumes once; called after verify_bundle accepted the bundle
        import apc_stellar as xs
        pl = doc["payment_payload"]
        env = xs.envelope(pl["payload"]["transaction"])
        op = env["tx"]["ops"][0]
        frm = xs.address_str(op["fn"]["args"][0][1])
        nonces = sorted(e["credentials"]["nonce"] for e in op["auth"] if e["credentials"]["type"] in (1, 2))
        pp = {"resource_url": (pl.get("resource") or {}).get("url")}
        return (pl["accepted"]["network"], pl["accepted"]["asset"], frm, "nonce:%s" % ",".join(map(str, nonces))), pp
    if doc["bundle_version"] == "apc-0.16":
        # SPEC 0.16: an XRPL account consumes each Sequence (or Ticket) once; the key is that slot
        import apc_xrp
        import apc_xrpl as xr
        pl = doc["payment_payload"]
        acc = apc_xrp.parse_requirements(pl["accepted"], "payment_payload.accepted")
        _, v = xr.decode(bytes.fromhex(pl["payload"]["signedTxBlob"]))
        tick = v.get("TicketSequence")
        slot = "ticket:%d" % int.from_bytes(tick, "big") if tick is not None else "seq:%d" % int.from_bytes(v["Sequence"], "big")
        return (acc["network"], pl["accepted"]["asset"], xr.classic_address(v["Account"]), slot), \
            {"resource_url": (pl.get("resource") or {}).get("url")}
    if doc["bundle_version"] == "apc-0.15":
        # SPEC 0.15: auth-capture collects through receiveWithAuthorization, whose nonce the token consumes once per payer;
        # the token's one nonce space (authorizationState) is shared with transferWithAuthorization (apc-0.3, apc-0.13),
        # and the tuple is written as theirs: CAIP-2 network, lower-case addresses, nonce as 0x and 64 lower-case digits
        import apc_authcap as ac
        pl, r, w, url = ac.parse(doc["payment_payload"])
        if w["method"] == "permit2":
            # SPEC 0.16.1: the Permit2 collector consumes Permit2's unordered nonce of the payer, the space apc-0.10
            # keys by (network, Permit2, owner, nonce): the same tuple, so one nonce used by both is seen
            import apc_permit2
            return (r["network"], apc_permit2.PERMIT2, w["auth"]["from"], str(w["auth"]["nonce"])), {"resource_url": url}
        return (r["network"], r["asset"], w["auth"]["from"], "0x" + w["auth"]["nonce"].hex()), {"resource_url": url}
    if doc["bundle_version"] == "apc-0.13":            # SPEC 0.13: x402 v1, read as the apc-0.3 bundle it maps to
        import apc_v1
        doc = apc_v1.to_v2(doc)[0]
    pp = av.parse_payload(doc["payment_payload"])
    acc, au = pp["accepted"], pp["auth"]
    return (acc["network"], acc["asset"], au["from"], au["nonce"]), pp


def _delivery(doc, pp):
    """What the payment unlocked, as the bundle names it: the resource URL and the acceptance receipt (if any)."""
    url = pp["resource_url"]
    if url is None and isinstance(doc.get("payment_required"), dict):
        url = (doc["payment_required"].get("resource") or {}).get("url")
    rec = doc.get("acceptance")
    rec_h = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if rec else None
    return url, rec_h


def check_set(docs):
    """docs: list of (name, parsed JSON). Returns the report."""
    refused, groups, ids = [], {}, {}
    for name, doc in docs:
        try:
            rep = av.verify_bundle(doc)
            k, pp = _key(doc)
        except av.Refusal as e:
            refused.append({"bundle": name, "reason": str(e)})
            continue
        tx = None
        if rep["checks"].get("T1") == "verified":           # a 32-byte transaction hash (SPEC T1), or base58 (0.5)
            tx = doc["settlement"]["transaction"]
            tx = tx if doc["bundle_version"] in ("apc-0.5", "apc-0.12") else tx.upper() if doc["bundle_version"] == "apc-0.16" else tx.lower()
        groups.setdefault(k, []).append({"bundle": name, "verdict": rep["verdict"], "tx": tx,
                                         "delivery": _delivery(doc, pp)})
        pid = apc_payid.payment_id(doc)
        if pid is not None:
            acc = doc["payment_payload"]["accepted"]
            url = _delivery(doc, pp)[0]
            import apc_intl                         # SPEC 0.11.4: an IDN host and its A-label are one merchant
            origin = apc_intl.origin(url) if isinstance(url, str) else None
            low = (lambda a: a.lower()) if doc["bundle_version"] not in ("apc-0.5", "apc-0.12", "apc-0.16") else (lambda a: a)
            merchant = (str(acc.get("network")), low(str(acc.get("payTo"))), origin)
            # PI "Request Binding": the fingerprint is scheme, network, asset, amount, payTo, resource (not the nonce)
            fp = (acc.get("scheme"), str(acc.get("amount")), low(str(acc.get("asset"))), url)
            ids.setdefault((pid, merchant), {}).setdefault(fp, []).append((name, k, tx))
    d1, d2, d3 = [], [], []
    for k, g in sorted(groups.items()):
        if len(g) < 2:
            continue
        deliveries = {x["delivery"] for x in g}
        entry = {"authorization": {"network": k[0], "asset": k[1], "payer": k[2], "nonce": k[3]},
                 "bundles": [x["bundle"] for x in g]}
        txs = sorted({x["tx"] for x in g if x["tx"] is not None})
        if len(txs) > 1:
            d3.append(dict(entry, check="failed:same_authorization_two_settlements", transactions=txs))
        if len(deliveries) > 1:
            d1.append(dict(entry, check="failed:same_payment_for_two_deliveries",
                           deliveries=sorted([list(map(str, d)) for d in deliveries])))
        else:
            d2.append(dict(entry, check="duplicate_bundle"))
    d4 = []
    for (pid, m), fps in sorted(ids.items(), key=lambda x: str(x[0])):
        entry = {"payment_identifier": pid, "merchant": list(map(str, m)),
                 "bundles": sorted(b[0] for v in fps.values() for b in v)}
        if len(fps) > 1:
            d4.append(dict(entry, check="failed:payment_identifier_reused"))
            continue
        settled = {(b[1], b[2]) for v in fps.values() for b in v if b[2] is not None}
        if len({a for a, _ in settled}) > 1:
            # one idempotent operation, two authorizations each with a settlement reply naming its transaction
            d4.append(dict(entry, check="failed:payment_identifier_two_settled_payments",
                           transactions=sorted(t for _, t in settled)))
    return {"bundles": len(docs), "refused": refused, "authorizations": len(groups),
            "D1": d1 or "verified", "D2": d2 or "none", "D3": d3 or "verified", "D4": d4 or "verified",
            "verdict": "set_failed" if d1 or d3 or d4 else "set_consistent"}


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 64
    docs = []
    for p in argv[1:]:
        try:
            docs.append((p, av.strict_json(av.read_bundle_bytes(p).decode("utf-8"))))
        except (OSError, UnicodeDecodeError, av.Refusal) as e:
            docs.append((p, {"unreadable": type(e).__name__}))
    out = check_set(docs)
    print(json.dumps(out, indent=1))
    return 1 if out["verdict"] == "set_failed" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
