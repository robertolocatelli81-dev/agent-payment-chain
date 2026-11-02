"""Amendment 0.11.2 (SPEC section 15): the x402 `payment-identifier` extension (x402 4241d56
specs/extensions/payment_identifier.md, cited PI). PI1 for one bundle, D4 across a set (apc_batch.py). Offline,
standard library only."""
import re

from apc_verify import Refusal, _obj

EXT = "payment-identifier"
ID = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")      # PI "id Format": 16-128 characters, alphanumeric, hyphens, underscores


def _decl(container, path):
    """{required: bool, id?: str} of the extension in a PaymentRequired or PaymentPayload, closed; None without it."""
    ext = container.get("extensions") if isinstance(container, dict) else None
    if not isinstance(ext, dict) or EXT not in ext:
        return None
    q = "%s.extensions[%r]" % (path, EXT)
    e = _obj(ext[EXT], q, ("info",), ("schema",))
    if "schema" in e and not isinstance(e["schema"], dict):
        raise Refusal(q + ".schema: not an object")
    info = _obj(e["info"], q + ".info", ("required",), ("id",))
    if not isinstance(info["required"], bool):
        raise Refusal(q + ".info.required: not a boolean")
    if "id" in info and not isinstance(info["id"], str):
        raise Refusal(q + ".info.id: not a string")
    return info


def payment_id(doc):
    """The id the payload carries when it is well formed, else None (PI1 says why)."""
    cli = _decl(doc.get("payment_payload"), "payment_payload")
    return cli["id"] if cli and "id" in cli and ID.match(cli["id"]) else None


def check(doc):
    """PI1: ({"PI1": result}, notes) or ({}, []) when neither PaymentRequired nor PaymentPayload carries the extension."""
    srv = _decl(doc.get("payment_required"), "payment_required")
    cli = _decl(doc.get("payment_payload"), "payment_payload")
    if srv is None and cli is None:
        return {}, []
    if cli is not None and "id" in cli and not ID.match(cli["id"]):
        return {"PI1": "failed:payment_identifier_malformed"}, []
    if srv is not None and srv["required"] and (cli is None or "id" not in cli):
        # PI "Idempotency Behavior": required true and no id -> 400 Bad Request; a settled payment should not exist
        return {"PI1": "failed:payment_identifier_required_but_absent"}, []
    if cli is None or "id" not in cli:
        return {"PI1": "not_evaluated:absent:no_payment_identifier"}, []
    return {"PI1": "verified"}, ["payment-identifier %s (an idempotency key chosen by the client; D4 compares it across a "
                                 "set of bundles)" % cli["id"]]
