"""agent-payment-chain report tools (SPEC 0.6, section 8), offline, standard library only:

  python3 apc_report.py sign SEED_FILE REPORT.json [--signed-at YYYY-MM-DDTHH:MM:SSZ]
                                                          -> a signed report (Ed25519 over the canonical report;
                                                             with --signed-at, version 2 signing the time too)
  python3 apc_report.py verify SIGNED.json [PUBLIC_KEY] [--keys KEYS.json]
                                                          -> exit 0 when the signature holds (and is by that key,
                                                             valid at signed_at in KEYS, SPEC 0.14)
  python3 apc_report.py sarif BUNDLE.json [...]           -> a SARIF 2.1.0 log of the failed and not evaluated checks
  python3 apc_report.py policy POLICY.json BUNDLE.json    -> the report with the policy checks P1-P5
  python3 apc_report.py merkle REPORT.json [...]          -> the RFC 6962 Merkle root over the canonical reports

SEED_FILE holds one line, the 32-byte Ed25519 seed in hex; it is read and never printed. A report is apc_verify's JSON
output. Exit 0 done, 1 a signature that does not hold or a policy failure, 3 an input outside the grammar, 64 usage (or
the signature library absent: one line on standard error, no report, SPEC 32.12 (f)).
"""
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_siglib  # noqa: E402
apc_siglib.guard("apc_report", __name__ == "__main__")  # SPEC 32.11 (c), 32.12 (f): without the library one line, exit 64, no partial report
import apc_solana as sol  # noqa: E402

DOMAIN = b"apc-report-v1\n"          # domain separation: a report signature is not a signature of anything else
HEX32 = re.compile(r"[0-9a-f]{64}\Z")


class Bad(Exception):
    pass


def canonical(v):
    """RFC 8785 (JCS) for the values a report holds: objects with ASCII member names, strings, integers, booleans and
    null. A float or a non-ASCII member name is refused rather than serialised by another rule."""
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            for k in x:
                if not isinstance(k, str) or not k.isascii():
                    raise Bad("a member name that is not ASCII")
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
        elif x is not None and not isinstance(x, (str, int, bool)):
            raise Bad("a value outside strings, integers, booleans and null")
        elif isinstance(x, int) and not isinstance(x, bool) and abs(x) >= 2 ** 53:
            raise Bad("an integer beyond 2^53 (RFC 8785 writes numbers as IEEE 754 doubles)")
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_seed(path):
    with open(path) as fh:
        line = fh.read().strip().lower()
    if not HEX32.match(line):
        raise Bad("the seed file is not one 32-byte hex line")
    return bytes.fromhex(line)


DOMAIN2 = b"apc-report-v2\n"         # SPEC 0.14: the signed object is {report, signed_at}
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _utc(v, what):
    import datetime
    if not isinstance(v, str) or not UTC.match(v):
        raise Bad("%s: not YYYY-MM-DDTHH:MM:SSZ" % what)
    try:
        datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Bad("%s: not a calendar time" % what)
    return v


def sign(report, seed, signed_at=None):
    """Version 1 without signed_at; version 2 (SPEC 0.14) signs {report, signed_at} so a key validity window can be
    checked against the signing time."""
    pub = sol.ed25519_public(seed)
    out = {"report": report, "public_key": pub.hex(), "key_id": hashlib.sha256(pub).hexdigest()[:16]}
    if signed_at is None:
        return dict(out, apc_signed_report=1, signature=sol.ed25519_sign(seed, DOMAIN + canonical(report)).hex())
    _utc(signed_at, "signed_at")
    msg = DOMAIN2 + canonical({"report": report, "signed_at": signed_at})
    return dict(out, apc_signed_report=2, signed_at=signed_at, signature=sol.ed25519_sign(seed, msg).hex())


def parse_keys(doc):
    """SPEC 0.14 report keyset: {"apc_report_keys": 1, "keys": [{"public_key", "valid_from", "valid_to": UTC or null}]},
    closed; one entry per key."""
    if not isinstance(doc, dict) or set(doc) != {"apc_report_keys", "keys"} or type(doc["apc_report_keys"]) is not int \
            or doc["apc_report_keys"] != 1 or not isinstance(doc["keys"], list) or not doc["keys"]:
        raise Bad("report keys: {apc_report_keys: 1, keys: [1.. entries]}")
    out = {}
    for i, k in enumerate(doc["keys"]):
        if not isinstance(k, dict) or set(k) != {"public_key", "valid_from", "valid_to"}:
            raise Bad("keys[%d]: exactly public_key, valid_from, valid_to" % i)
        if not isinstance(k["public_key"], str) or not HEX32.match(k["public_key"]) or k["public_key"] in out:
            raise Bad("keys[%d].public_key: not 32 bytes lowercase hex, or listed twice" % i)
        vf = _utc(k["valid_from"], "keys[%d].valid_from" % i)
        vt = None if k["valid_to"] is None else _utc(k["valid_to"], "keys[%d].valid_to" % i)
        if vt is not None and vt < vf:
            raise Bad("keys[%d]: valid_to before valid_from" % i)
        out[k["public_key"]] = (vf, vt)
    return out


def verify(signed, want_key=None, keys=None):
    """-> 'verified' or 'failed:<reason>' (or 'not_evaluated:<reason>'); Bad for a document outside the grammar.
    keys: parse_keys() output, the reader's keys with their validity windows (SPEC 0.14)."""
    v = signed.get("apc_signed_report") if isinstance(signed, dict) else None
    members = {"apc_signed_report", "report", "public_key", "key_id", "signature"} | ({"signed_at"} if v == 2 else set())
    if not isinstance(signed, dict) or set(signed) != members:
        raise Bad("not a signed report (closed members)")
    if type(v) is not int or v not in (1, 2):
        raise Bad("apc_signed_report: not 1 or 2")
    if not isinstance(signed["public_key"], str) or not HEX32.match(signed["public_key"]):
        raise Bad("public_key: not 32 bytes lowercase hex")
    if not isinstance(signed["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", signed["signature"]):
        raise Bad("signature: not 64 bytes lowercase hex")
    if v == 2:
        _utc(signed["signed_at"], "signed_at")
    pub = bytes.fromhex(signed["public_key"])
    if signed["key_id"] != hashlib.sha256(pub).hexdigest()[:16]:
        return "failed:key_id_not_the_key"
    if want_key is not None and want_key.lower() != signed["public_key"]:
        return "failed:signed_by_another_key"
    msg = DOMAIN + canonical(signed["report"]) if v == 1 else \
        DOMAIN2 + canonical({"report": signed["report"], "signed_at": signed["signed_at"]})
    if not sol.ed25519_verify(pub, msg, bytes.fromhex(signed["signature"])):
        return "failed:signature_invalid"
    if keys is not None:
        if signed["public_key"] not in keys:
            return "failed:signed_by_another_key"
        if v == 1:
            return "not_evaluated:v1_has_no_signed_at"
        vf, vt = keys[signed["public_key"]]
        if signed["signed_at"] < vf:
            return "failed:key_not_valid_before_valid_from"
        if vt is not None and signed["signed_at"] > vt:
            return "failed:key_not_valid_after_valid_to"
    return "verified"


def sarif(items):
    """items: [(bundle path, report)] -> a SARIF 2.1.0 log (OASIS SARIF v2.1.0): one result per failed check (error)
    and per not evaluated check (warning); absent artifacts are not results."""
    rules, results = {}, []
    for path, rep in items:
        if rep.get("verdict") in ("refused", "unsupported"):
            rules.setdefault("bundle", {"id": "bundle", "shortDescription": {"text": "bundle grammar (SPEC 1)"}})
            results.append({"ruleId": "bundle", "level": "error", "message": {"text": rep.get("reason", rep["verdict"])},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}]})
            continue
        for k in rep["failed"] + rep["not_evaluated"]:
            rules.setdefault(k, {"id": k, "shortDescription": {"text": "SPEC check " + k}})
            results.append({"ruleId": k, "level": "error" if k in rep["failed"] else "warning",
                            "message": {"text": "%s: %s (verdict %s)" % (k, rep["checks"][k], rep["verdict"])},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "apc_verify", "informationUri": "SPEC.md",
                                          "rules": [rules[k] for k in sorted(rules)]}},
                      "results": results}]}


def merkle_root(leaves):
    """RFC 6962 2.1: MTH of the leaves (bytes): leaf hash SHA-256(0x00 || d), node SHA-256(0x01 || l || r), the split at
    the largest power of two below n."""
    if not leaves:
        return hashlib.sha256(b"").digest()

    def mth(xs):
        if len(xs) == 1:
            return hashlib.sha256(b"\0" + xs[0]).digest()
        k = 1 << (len(xs) - 1).bit_length() - 1
        return hashlib.sha256(b"\1" + mth(xs[:k]) + mth(xs[k:])).digest()
    return mth(leaves)


# ------------------------------------------------------------------ policy (G4): a closed grammar, offline
POLICY_MEMBERS = ("apc_policy", "networks", "assets", "pay_to", "max_amount", "hosts")


def parse_policy(p):
    if not isinstance(p, dict) or set(p) - set(POLICY_MEMBERS) or type(p.get("apc_policy")) is not int \
            or p["apc_policy"] != 1:
        raise Bad("policy: an object with apc_policy 1 and only %s" % ", ".join(POLICY_MEMBERS[1:]))
    for k in ("networks", "assets", "pay_to", "hosts"):
        if k in p and (not isinstance(p[k], list) or not p[k] or not all(isinstance(x, str) and x for x in p[k])
                       or len(set(p[k])) != len(p[k])):
            raise Bad("policy.%s: not a non-empty list of distinct strings" % k)
    if "hosts" in p:                                    # SPEC 0.11.4: each host must have one A-label form
        import apc_intl
        for h in p["hosts"]:
            try:
                apc_intl.host_ascii(h)
            except apc_intl.NotComparable as e:
                raise Bad("policy.hosts: %r is not a comparable host name (%s)" % (h, e))
    if "max_amount" in p:
        m = p["max_amount"]
        if not isinstance(m, dict) or not m or not all(isinstance(v, str) and re.fullmatch(r"(0|[1-9][0-9]{0,77})", v)
                                                       for v in m.values()):
            raise Bad("policy.max_amount: not an object of asset -> decimal string")
    return p


def _norm(network, a):
    return a.lower() if network.startswith("eip155:") else a       # EVM addresses: case ignored; base58: exact


def apply_policy(policy, doc, report):
    """P1 network, P2 asset, P3 amount at most max_amount[asset], P4 payTo, P5 resource host: 'verified',
    'failed:<reason>', or 'not_evaluated:absent:no_rule' when the policy has no such rule."""
    from urllib.parse import urlsplit
    if isinstance(doc, dict) and doc.get("bundle_version") == "apc-0.13":    # x402 v1: the bundle it maps to (SPEC 21)
        import apc_v1
        doc = apc_v1.to_v2(doc)[0]
    acc = doc["payment_payload"]["accepted"]
    net = acc["network"]
    out = {}

    def listed(rule, value, reason):
        if rule not in policy:
            return "not_evaluated:absent:no_rule"
        return "verified" if _norm(net, value) in {_norm(net, x) for x in policy[rule]} else "failed:" + reason
    out["P1"] = ("not_evaluated:absent:no_rule" if "networks" not in policy else
                 "verified" if net in policy["networks"] else "failed:network_not_allowed")
    out["P2"] = listed("assets", acc["asset"], "asset_not_allowed")
    if "max_amount" not in policy:
        out["P3"] = "not_evaluated:absent:no_rule"
    else:
        caps = {_norm(net, k): int(v) for k, v in policy["max_amount"].items()}
        cap = caps.get(_norm(net, acc["asset"]))
        out["P3"] = ("failed:asset_without_a_cap" if cap is None else
                     "verified" if int(acc["amount"]) <= cap else "failed:amount_above_cap")
    out["P4"] = listed("pay_to", acc["payTo"], "recipient_not_allowed")
    url = (doc["payment_payload"].get("resource") or {}).get("url")
    if "hosts" not in policy:
        out["P5"] = "not_evaluated:absent:no_rule"
    elif url is None:
        out["P5"] = "failed:no_resource_url"
    else:
        import apc_intl                             # SPEC 0.11.4: hosts compared as IDNA A-labels
        try:
            host = (urlsplit(url).hostname or "")
        except ValueError:                              # e.g. "http://[bad": no host can be read
            host = None
        why = None
        if host:
            try:
                host = apc_intl.host_ascii(host)
            except apc_intl.NotComparable as e:
                why = str(e)
        allowed = {apc_intl.host_ascii(h) for h in policy["hosts"]}
        out["P5"] = ("failed:resource_url_not_parsable" if host is None else
                     "failed:resource_host_not_comparable(%s)" % why if why else
                     "verified" if host in allowed else "failed:host_not_allowed")
    rep = dict(report)
    rep["policy"] = out
    rep["policy_verdict"] = "policy_failed" if any(v.startswith("failed") for v in out.values()) else "policy_met"
    return rep


def _load(path):
    import apc_verify as av
    return av.strict_json(av.read_bundle_bytes(path).decode("utf-8"))


def main(argv):
    import apc_verify as av
    if len(argv) < 3 or argv[1] not in ("sign", "verify", "sarif", "policy", "merkle"):
        print(__doc__)
        return 64
    cmd, args = argv[1], argv[2:]
    try:
        at = keys = None
        if "--signed-at" in args:
            i = args.index("--signed-at")
            at, args = (args[i + 1] if i + 1 < len(args) else ""), args[:i] + args[i + 2:]
        if "--keys" in args:
            i = args.index("--keys")
            keys, args = parse_keys(_load(args[i + 1])) if i + 1 < len(args) else parse_keys(None), args[:i] + args[i + 2:]
        if cmd == "sign" and len(args) == 2:
            out = sign(_load(args[1]), read_seed(args[0]), at)
        elif cmd == "verify" and len(args) in (1, 2):
            r = verify(_load(args[0]), args[1] if len(args) == 2 else None, keys)
            print(json.dumps({"signature": r}))
            return 0 if r == "verified" else 1
        elif cmd == "sarif":
            items = []
            for p in args:
                try:
                    items.append((p, av.verify_bundle(_load(p))))
                except av.Refusal as e:
                    items.append((p, {"verdict": "refused", "reason": str(e)}))
            out = sarif(items)
        elif cmd == "policy" and len(args) == 2:
            doc = _load(args[1])
            out = apply_policy(parse_policy(_load(args[0])), doc, av.verify_bundle(doc))
            print(json.dumps(out, indent=1, sort_keys=True))
            return 1 if out["policy_verdict"] == "policy_failed" else 0
        elif cmd == "merkle":
            leaves = [canonical(_load(p)) for p in args]
            out = {"leaves": [hashlib.sha256(b"\0" + x).hexdigest() for x in leaves],
                   "root": merkle_root(leaves).hex(), "rule": "RFC 6962 2.1 over the canonical (RFC 8785) reports"}
        else:
            print(__doc__)
            return 64
    except (Bad, av.Refusal, OSError, UnicodeDecodeError) as e:
        print(json.dumps({"error": str(e)}))
        return 3
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
