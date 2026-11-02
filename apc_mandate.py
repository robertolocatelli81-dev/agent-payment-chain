"""SPEC 0.20 (section 31): the AP2 Payment Mandate carried as an ap2-evidence-pack 1.7.1 pack, its restriction records
(SPEC section 11 of ap2-evidence-pack), and the x402 payment (MP1-MP7). The pack is verified by ap2-evidence-pack
itself, loaded from the directory APC_AP2EV names (with the variable unset: ../ap2-evidence-pack beside this folder, SPEC
32.11) and accepted only when the two loaded files have the SHA-256 of tag v1.7.1; the AP2 constraints are evaluated
here from the AP2 text (AP2 e1ea56d), the SDK being a test oracle only."""
import calendar
import decimal
import hashlib
import importlib
import importlib.util
import json
import math
import os
import re
import shutil
import sys
import tempfile
import time

from apc_siglib import read_regular   # SPEC 32.12 (e) and (f): the same reader for the pack and the library

PROFILE = "ap2-evidence-pack/1.7.1"
AP2EV_SHA256 = {"ap2_evidence.py": "d128823a049d522aabfe8ec70806db4db984f7aa93b4487b70bf7905b4bfb39a",
                "sigsuite.py": "7b9126ad6530777c2fc18333186593a6b71d928e165b93107e4cdbf6ed27792b"}
CHECKS = ("MP1", "MP2", "MP3", "MP4", "MP5", "MP6", "MP7")
MAX_CHAIN = 1 << 16          # SPEC 31: the chain is hashed with Keccak-256, inside the budget of SPEC 29.2
RESTRICTS = "io.github.robertolocatelli81.restricts"
PRESET = ("payee", "payment_amount", "payment_instrument", "pisp", "execution_date", "risk_data")
# SPEC 31.4 MP4a: the issuers' naming of the measured tokens (apc_assets.py), a closed list; ISO 4217 minor units
TOKEN_CURRENCY = {"USDC": "USD", "USD₮": "USD", "USAT": "USD", "EURC": "EUR", "JPYC": "JPY"}
MINOR_UNIT = {"USD": 2, "EUR": 2, "JPY": 0}
# SPEC 31.3 amendment c: ISO 4217 exponents (CcyMnrUnts) of List One published 2026-09-17, downloaded 2026-11-01 from
# six-group.com (list-one.xml, sha256 33139b438657d1cee116ba737807ea71d19d6de4b90f799a09c56f0cc6a1b0ff): 165 codes;
# the 13 codes listed "N.A." (XAU, XDR, XXX, ...) are absent. Separate from MINOR_UNIT, which MP4 uses.
ISO4217_EXPONENT = {
    "AED": 2, "AFN": 2, "ALL": 2, "AMD": 2, "AOA": 2, "ARS": 2, "AUD": 2, "AWG": 2, "AZN": 2, "BAM": 2, "BBD": 2,
    "BDT": 2, "BHD": 3, "BIF": 0, "BMD": 2, "BND": 2, "BOB": 2, "BOV": 2, "BRL": 2, "BSD": 2, "BTN": 2, "BWP": 2,
    "BYN": 2, "BZD": 2, "CAD": 2, "CDF": 2, "CHE": 2, "CHF": 2, "CHW": 2, "CLF": 4, "CLP": 0, "CNY": 2, "COP": 2,
    "COU": 2, "CRC": 2, "CUP": 2, "CVE": 2, "CZK": 2, "DJF": 0, "DKK": 2, "DOP": 2, "DZD": 2, "EGP": 2, "ERN": 2,
    "ETB": 2, "EUR": 2, "FJD": 2, "FKP": 2, "GBP": 2, "GEL": 2, "GHS": 2, "GIP": 2, "GMD": 2, "GNF": 0, "GTQ": 2,
    "GYD": 2, "HKD": 2, "HNL": 2, "HTG": 2, "HUF": 2, "IDR": 2, "ILS": 2, "INR": 2, "IQD": 3, "IRR": 2, "ISK": 0,
    "JMD": 2, "JOD": 3, "JPY": 0, "KES": 2, "KGS": 2, "KHR": 2, "KMF": 0, "KPW": 2, "KRW": 0, "KWD": 3, "KYD": 2,
    "KZT": 2, "LAK": 2, "LBP": 2, "LKR": 2, "LRD": 2, "LSL": 2, "LYD": 3, "MAD": 2, "MDL": 2, "MGA": 2, "MKD": 2,
    "MMK": 2, "MNT": 2, "MOP": 2, "MRU": 2, "MUR": 2, "MVR": 2, "MWK": 2, "MXN": 2, "MXV": 2, "MYR": 2, "MZN": 2,
    "NAD": 2, "NGN": 2, "NIO": 2, "NOK": 2, "NPR": 2, "NZD": 2, "OMR": 3, "PAB": 2, "PEN": 2, "PGK": 2, "PHP": 2,
    "PKR": 2, "PLN": 2, "PYG": 0, "QAR": 2, "RON": 2, "RSD": 2, "RUB": 2, "RWF": 0, "SAR": 2, "SBD": 2, "SCR": 2,
    "SDG": 2, "SEK": 2, "SGD": 2, "SHP": 2, "SLE": 2, "SOS": 2, "SRD": 2, "SSP": 2, "STN": 2, "SVC": 2, "SYP": 2,
    "SZL": 2, "THB": 2, "TJS": 2, "TMT": 2, "TND": 3, "TOP": 2, "TRY": 2, "TTD": 2, "TWD": 2, "TZS": 2, "UAH": 2,
    "UGX": 0, "USD": 2, "USN": 2, "UYI": 0, "UYU": 2, "UYW": 4, "UZS": 2, "VED": 2, "VES": 2, "VND": 0, "VUV": 0,
    "WST": 2, "XAD": 2, "XAF": 0, "XCD": 2, "XCG": 2, "XOF": 0, "XPF": 0, "YER": 2, "ZAR": 2, "ZMW": 2, "ZWG": 2}
# SPEC 31.9: SVM tokens by (network, mint): (symbol, decimals); decimals measured with getTokenSupply on 2026-10-31
# (slot 463662928, api.mainnet-beta.solana.com)
SVM_ASSETS = {("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"): ("USDC", 6)}
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
DATETIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_AP2EV = []          # [(module, hashes, None, None)] once loaded; [(None, hashes, reason, cause)] when it cannot be
# SPEC 32.11 (0.21.2): with APC_AP2EV unset the pack is looked for beside this folder, resolved from this file's own
# path (never from the working directory), and read at the hashes of v1.7.1 exactly as a directory the variable names.
AP2EV_SIBLING = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "ap2-evidence-pack")
GET_PACK = ("clone github.com/robertolocatelli81-dev/ap2-evidence-pack at tag v1.7.1 beside this folder as "
            "../ap2-evidence-pack, or set APC_AP2EV to such a checkout")
UNAVAILABLE = "not_evaluated:ap2_evidence_pack_unavailable"
NOT_171 = "not_evaluated:ap2_evidence_pack_not_1.7.1"


def _load():
    """SPEC 31 and 32.11: ap2_evidence from APC_AP2EV, or from ../ap2-evidence-pack beside this folder when the variable
    is unset, only at the hashes of v1.7.1. (module, hashes, None) or (None, hashes, reason); the cause in words: cause()."""
    if _AP2EV:
        return _AP2EV[0][:3]
    hashes = {}

    def fail(reason, why):
        _AP2EV.append((None, hashes, reason, why))
        return _AP2EV[0][:3]

    d = os.environ.get("APC_AP2EV")
    if d:
        where = "APC_AP2EV"
    else:
        d, where = AP2EV_SIBLING, "../ap2-evidence-pack beside the verifier (APC_AP2EV unset or empty)"
        if not os.path.isdir(d):
            return fail(UNAVAILABLE, "APC_AP2EV is unset (or empty) and there is no ap2-evidence-pack beside the verifier (%s): %s"
                        % (d, GET_PACK))
    src = {}
    for name, rel in (("ap2_evidence.py", "ap2_evidence.py"), ("sigsuite.py", os.path.join("pqcrypto", "sigsuite.py"))):
        src[name] = read_regular(os.path.join(d, rel))
        hashes[name] = None if src[name] is None else hashlib.sha256(src[name]).hexdigest()
    if hashes != AP2EV_SHA256:
        return fail(NOT_171, "the files at %s (%s) are not those of ap2-evidence-pack tag v1.7.1 (hashes reported): %s"
                    % (where, d, GET_PACK))
    # SPEC 32.11 (e): the code run is the bytes hashed above and nothing else. The two files are compiled from those bytes
    # (no import by name: no package, extension, cached bytecode or other file of the folder can stand in for them, and
    # apc never puts the folder on sys.path: the pack's own code does, and its only import after that, sigsuite, is the module
    # already run below from the hashed bytes); a module of either name already loaded from another place is refused as before.
    files = {"ap2_evidence": os.path.join(d, "ap2_evidence.py"), "sigsuite": os.path.join(d, "pqcrypto", "sigsuite.py")}
    for name, path in files.items():
        m = sys.modules.get(name)
        if m is not None and os.path.realpath(getattr(m, "__file__", None) or "") != os.path.realpath(path):
            return fail(UNAVAILABLE, "a module %s was already loaded from another place (%s), not from %s"
                        % (name, getattr(m, "__file__", None), d))
    saved, before = list(sys.path), {n: sys.modules.get(n) for n in files}
    try:
        mods = {}
        for name, key in (("sigsuite", "sigsuite.py"), ("ap2_evidence", "ap2_evidence.py")):   # sigsuite first
            spec = importlib.util.spec_from_loader(name, loader=None, origin=files[name])
            m = importlib.util.module_from_spec(spec)
            m.__file__ = files[name]
            sys.modules[name] = m
            exec(compile(src[key], files[name], "exec", dont_inherit=True), m.__dict__)
            mods[name] = m
        mod = mods["ap2_evidence"]
    except ModuleNotFoundError as e:
        # SPEC 32.11 (b): the cause named; the pack imports the `cryptography` package, the usual missing one
        if e.name == "cryptography" or (e.name or "").startswith("cryptography."):
            return fail(UNAVAILABLE, "the `cryptography` package ap2-evidence-pack needs is not installed for this "
                        "interpreter (%s): pip install cryptography" % sys.executable)
        return fail(UNAVAILABLE, "the import of ap2_evidence.py at %s failed: %s" % (d, e))
    except Exception as e:      # noqa: BLE001  any other failure of the import: type and message, never silence
        return fail(UNAVAILABLE, "the import of ap2_evidence.py at %s failed: %s: %s" % (d, type(e).__name__, str(e)[:200]))
    finally:
        sys.path[:] = saved
        for name, m in before.items():          # the modules stay ours: sys.modules is left as it was found
            if m is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = m
    _AP2EV.append((mod, hashes, None, None))
    return _AP2EV[0][:3]


def cause():
    """SPEC 32.11 (b): why the pack cannot be used, in words; None when it is loaded or not yet looked for."""
    return _AP2EV[0][3] if _AP2EV else None


def parse_member(m):
    """The closed bundle member of SPEC 31; raises ValueError(path) outside it."""
    if not isinstance(m, dict):
        raise ValueError("mandate: not an object")
    extra = sorted(set(m) - {"profile", "pack", "chain"})
    missing = sorted({"profile", "pack", "chain"} - set(m))
    if extra or missing:
        raise ValueError("mandate: members %s" % ", ".join(["unknown " + k for k in extra] + ["missing " + k for k in missing]))
    if m["profile"] != PROFILE:
        raise ValueError("mandate.profile: not %r" % PROFILE)
    if not isinstance(m["pack"], dict):
        raise ValueError("mandate.pack: not an object")
    c = m["chain"]
    if not isinstance(c, str) or not c or len(c) > MAX_CHAIN or not c.isascii():
        raise ValueError("mandate.chain: not a non-empty ASCII string of at most %d characters" % MAX_CHAIN)
    return m


def _canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _is_int(v):
    return type(v) is int


def _b64u_sha256(b):
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b"=").decode("ascii")


def _content(resolved):
    """The Mandate Content (form of section 11.1 of ap2-evidence-pack), or None."""
    if not isinstance(resolved, dict):
        return None
    if "delegate_payload" not in resolved:
        return resolved
    dp = resolved["delegate_payload"]
    if isinstance(dp, list) and len(dp) == 1 and isinstance(dp[0], dict):
        return dp[0]
    return None


def _jwk_eq(a, b):
    return isinstance(a, dict) and isinstance(b, dict) and all(
        isinstance(a.get(k), str) and a.get(k) == b.get(k) for k in ("kty", "crv", "x", "y"))


def _p256(j):
    return isinstance(j, dict) and j.get("kty") == "EC" and j.get("crv") == "P-256" and all(
        isinstance(j.get(k), str) and j[k] for k in ("x", "y"))


def _amount(v):
    """C's payment_amount as (amount, currency), or None (types/amount.json: integer amount, string currency)."""
    if isinstance(v, dict) and set(v) == {"amount", "currency"} and _is_int(v["amount"]) and isinstance(v["currency"], str):
        return v["amount"], v["currency"]
    return None


def _merchant_matches(cand, target):
    """The AP2 SDK's merchant_matches (constraints.py at e1ea56d): both ids present -> equal ids; otherwise equal
    non-empty name and equal non-empty website."""
    if not isinstance(cand, dict) or not isinstance(target, dict):
        return False
    if cand.get("id") and target.get("id"):
        return cand["id"] == target["id"]
    return bool(cand.get("name")) and cand.get("name") == target.get("name") and bool(cand.get("website")) \
        and cand.get("website") == target.get("website")


def _date_cmp_form(*vals):
    if all(isinstance(v, str) and DATE.fullmatch(v) for v in vals):
        return "date"
    if all(isinstance(v, str) and DATETIME.fullmatch(v) for v in vals):
        return "datetime"
    return None


def _real_date(v):
    try:
        time.strptime(v, "%Y-%m-%dT%H:%M:%SZ" if "T" in v else "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _budget_readings(mx, cur):
    """SPEC 31.3 amendment c (2026-11-01): the readings of a budget `max` in minor units of `cur`, each kept only when it
    is a whole number: MAJOR = max x 10^e (ISO 4217 exponent, ISO4217_EXPONENT; AP2 pull requests #368/#377) and MINOR = max
    (AP2 issue #389, Mastercard Verifiable Intent). An int exactly, a finite float through its repr in decimal arithmetic
    that traps rounding. ((readings...), None) or (None, reason)."""
    if not isinstance(cur, str) or cur not in ISO4217_EXPONENT:
        return None, "not_evaluated:budget_currency_exponent_unknown"
    if _is_int(mx):         # Python integers: exact at any size (a Decimal context of 1000 digits would trap above it)
        out = sorted({mx * 10 ** ISO4217_EXPONENT[cur], mx})
    else:
        with decimal.localcontext() as ctx:     # repr has at most 17 significant digits: nothing here rounds
            ctx.prec, ctx.Emax, ctx.Emin = 1000, 10 ** 6, -10 ** 6
            ctx.traps[decimal.Inexact] = ctx.traps[decimal.Rounded] = True
            d = decimal.Decimal(repr(mx))
            out = sorted({int(x) for x in (d.scaleb(ISO4217_EXPONENT[cur]), d) if x == x.to_integral_value()})
    return (tuple(out), None) if out else (None, "not_evaluated:budget_unit")


# SPEC 31.3a: the AP2 schemas at e1ea56d (types/*.json, payment_mandate.json, open_payment_mandate.json): required members
# and JSON types, exact (an integer is `type(x) is int`, not a boolean); members outside a schema are left alone, as the
# SDK's models ignore them (its pydantic models also coerce "1250" into 1250: here a string is not an integer, declared)
_STR, _INT, _OBJ, _ARR = (lambda v: isinstance(v, str)), _is_int, (lambda v: isinstance(v, dict)), (lambda v: isinstance(v, list))
_TYPES = {"merchant": ({"id": _STR, "name": _STR}, {"website": _STR}),
          "amount": ({"amount": _INT, "currency": _STR}, {}),
          "instrument": ({"id": _STR, "type": _STR}, {"description": _STR}),
          "pisp": ({"legal_name": _STR, "brand_name": _STR, "domain_name": _STR}, {})}
_COMMON = {"pisp": "pisp", "execution_date": _STR, "risk_data": _OBJ, "iat": _INT, "exp": _INT}
CLOSED_SCHEMA = ({"vct": lambda v: v == "mandate.payment.1", "transaction_id": _STR, "payee": "merchant", "payment_amount": "amount",
                  "payment_instrument": "instrument"}, _COMMON)
OPEN_SCHEMA = ({"vct": lambda v: v == "mandate.payment.open.1", "constraints": _ARR, "cnf": _OBJ},
               dict(_COMMON, payee="merchant", payment_amount="amount", payment_instrument="instrument"))
ALLOWED_TYPE = {"payment.allowed_payees": "merchant", "payment.allowed_payment_instruments": "instrument",
                "payment.allowed_pisps": "pisp"}


def _member_ok(v, t):
    if isinstance(t, str):
        return schema_fault(v, _TYPES[t]) is None
    return t(v)


def schema_fault(obj, schema):
    """The first member of `obj` outside `schema` (required, optional): its name, or None when obj meets the schema."""
    if not isinstance(obj, dict):
        return "(not an object)"
    req, opt = schema
    for k, t in req.items():
        if k not in obj or not _member_ok(obj[k], t):
            return k
    for k, t in opt.items():
        if k in obj and not _member_ok(obj[k], t):
            return k
    return None


def eval_terms(terms, closed, ev, arts, sd_alg, btime, record=False):
    """SPEC 31.3 (and 31.5 for a restriction record, `record` True): the pre-set values and the constraints of an open
    Mandate Content `terms` against the closed Mandate Content `closed`. Returns (outcome, [(what, outcome)])."""
    out = []
    for k in PRESET:
        if k in terms:
            out.append(("preset." + k, "verified" if k in closed and _canon(closed[k]) == _canon(terms[k])
                        else "failed:preset_changed:" + k))
    cons = terms.get("constraints")
    if not isinstance(cons, list):
        out.append(("constraints", "failed:constraint_malformed"))
        cons = []
    amt = _amount(closed.get("payment_amount"))
    types = [c.get("type") for c in cons if isinstance(c, dict)]
    for i, c in enumerate(cons):
        at = "constraints[%d]" % i
        if record and isinstance(c, dict) and c.get("type") == RESTRICTS:
            continue                    # the reference of a restriction record (SPEC 31.5): the binding, not a term;
            #                             in the open hop it is a type AP2 does not know (SPEC 31.3, review 2026-10-31)
        shape, what = ev._constraint_shape(c)
        if shape == "unknown_type":
            out.append((at, "not_evaluated:unknown_constraint"))
            continue
        if (shape, what) == ("malformed", "max") and c["type"] == "payment.budget" and type(c.get("max")) is float \
                and math.isfinite(c["max"]):
            # SPEC 31.3: `max` is a JSON number in AP2's schema; a fraction is not malformed, its unit is unread
            # (an ABSENT max is also ("malformed", "max") for _constraint_shape: c.get, never c["max"], so it stays malformed)
            shape = "ok" if set(c) <= {"type", "currency", "max"} else "unknown_name"
        if shape == "unknown_name":   # a member outside the schema: not a wrong type, not a missing key (SPEC 31.3)
            out.append((at, "not_evaluated:constraint_unknown_member"))
            continue
        if shape != "ok" or (c["type"] in ALLOWED_TYPE and any(
                schema_fault(a, _TYPES[ALLOWED_TYPE[c["type"]]]) is not None for a in c["allowed"])):
            out.append((at, "failed:constraint_malformed"))     # SPEC 31.3a: each allowed element of its AP2 type
            continue
        t = c["type"]
        if t == "payment.amount_range":
            if amt is None:
                r = "failed:payment_amount_malformed"
            elif amt[0] < 0:
                r = "failed:payment_amount_negative"        # SPEC 31.3 amendment b (AP2 pull request #391: before currency)
            elif amt[1] != c["currency"]:
                r = "failed:currency_differs"
            elif amt[0] > c["max"] or ("min" in c and amt[0] < c["min"]):
                r = "failed:amount_out_of_range"
            else:
                r = "verified"
        elif t == "payment.allowed_payees":
            r = "verified" if any(_merchant_matches(a, closed.get("payee")) for a in c["allowed"]) \
                else "failed:payee_not_allowed"
        elif t == "payment.allowed_payment_instruments":
            pi = closed.get("payment_instrument")
            pid = pi.get("id") if isinstance(pi, dict) else None
            r = "verified" if isinstance(pid, str) and any(isinstance(a, dict) and a.get("id") == pid for a in c["allowed"]) \
                else "failed:instrument_not_allowed"
        elif t == "payment.allowed_pisps":
            p = closed.get("pisp")
            if not isinstance(p, dict):
                r = "failed:pisp_missing"
            else:
                r = "verified" if any(isinstance(a, dict) and all(isinstance(a.get(k), str) and a.get(k) == p.get(k) for k
                                      in ("domain_name", "legal_name", "brand_name")) for a in c["allowed"]) \
                    else "failed:pisp_not_allowed"
        elif t == "payment.execution_date":
            bounds = [c[k] for k in ("not_before", "not_after") if k in c]
            if "execution_date" in closed:
                d = closed["execution_date"]
            elif btime is not None and bounds:
                f = _date_cmp_form(*bounds)
                d = time.strftime("%Y-%m-%d" if f == "date" else "%Y-%m-%dT%H:%M:%SZ", time.gmtime(btime)) if f else None
            elif bounds:
                out.append((at, "not_evaluated:no_execution_date_no_block_time"))     # blocks: review observation O1
                continue
            else:
                d = None
            if not bounds:
                r = "verified"          # a window with neither bound admits every date
            elif d is None or _date_cmp_form(d, *bounds) is None or not all(_real_date(x) for x in [d] + bounds):
                r = "not_evaluated:date_form"
            elif ("not_before" in c and d < c["not_before"]) or ("not_after" in c and d > c["not_after"]):
                r = "failed:execution_date_outside"
            else:
                r = "verified"
        elif t == "payment.budget":
            rd, why = _budget_readings(c["max"], c["currency"])
            if amt is None:
                r = "failed:payment_amount_malformed"
            elif amt[0] < 0:
                r = "failed:payment_amount_negative"        # SPEC 31.3 amendment b (AP2 pull request #391: before currency)
            elif amt[1] != c["currency"]:
                r = "failed:currency_differs"
            elif rd is None:
                r = why
            elif amt[0] > rd[-1]:
                r = "failed:amount_exceeds_budget"
            elif amt[0] <= rd[0]:
                r = "not_evaluated:budget_needs_past_spend"
            else:
                r = "not_evaluated:budget_unit_ambiguous"   # SPEC 31.3 amendment c: the readings disagree
        elif t == "payment.agent_recurrence":
            r = "failed:recurrence_without_amount_range_or_budget" if not (
                "payment.amount_range" in types and "payment.budget" in types) else "not_evaluated:recurrence_needs_past_uses"
        elif t == "payment.reference":
            if sd_alg not in (None, "sha-256"):
                r = "not_evaluated:sd_alg_not_sha256"
            else:
                r = "verified" if any(
                    isinstance(a["content"], dict) and a["content"].get("vct") == "mandate.checkout.open.1"
                    and _b64u_sha256(a["compact"].encode("ascii")) == c["conditional_transaction_id"] for a in arts) \
                    else "not_evaluated:open_checkout_not_in_pack"
        else:                           # a checkout type in a payment mandate: no rule reads it against a payment
            r = "not_evaluated:unknown_constraint"
        out.append((at, r))
    return _first(r for _, r in out), out


def evaluate_mp3(oc, cc, ev, arts, sd_alg, btime):
    """SPEC 31.3 and 31.3a: the open and closed Mandate Contents against the AP2 schemas, then O's terms on C."""
    _, out = eval_terms(oc, cc, ev, arts, sd_alg, btime)
    for name, obj, sch in (("closed", cc, CLOSED_SCHEMA), ("open", oc, OPEN_SCHEMA)):
        f = schema_fault(obj, sch)
        if f is not None:
            out.insert(0, (name + "_mandate", "failed:%s_mandate_schema:%s" % (name, f)))
    return _first(r for _, r in out), out


def _first(outcomes):
    outcomes = list(outcomes)
    return next((x for x in outcomes if x.startswith("failed")), None) or \
        next((x for x in outcomes if not x.startswith("verified")), None) or "verified"


def _gentime(gt):
    """The RFC 3161 GeneralizedTime `YYYYMMDDHHMMSS[.f]Z` that ap2-evidence-pack reports as `existed_by` (its _gt_key
    shape), as seconds since the epoch with the fraction; None for anything else."""
    m = re.fullmatch(r"([0-9]{14})(?:\.([0-9]+))?Z", gt) if isinstance(gt, str) else None
    if m is None:
        return None
    try:
        t = calendar.timegm(time.strptime(m.group(1), "%Y%m%d%H%M%S"))
    except ValueError:
        return None
    return t + (float("0." + m.group(2)) if m.group(2) else 0.0)


def _keccak_hex(b):
    import apc_block
    return "0x" + apc_block.keccak256(b).hex()


def check(member, au, acc, btime, tsa_cert=None, svm=None):
    """SPEC 31: (res, notes, report member) for a parsed `mandate` member (parse_member), the bundle's EIP-3009
    authorization `au` and accepted requirement `acc`, the block time verified by B1 or None, the reader's TSA
    certificate path or None."""
    mod, hashes, why = _load()
    rep = {"profile": PROFILE, "ap2_evidence_sha256": hashes}
    if mod is None:
        return {k: why for k in CHECKS}, ["MP1-MP7: %s (SPEC 31: %s)" % (why.split(":", 1)[1], cause())], rep
    res, notes = {}, []
    tmp = tempfile.mkdtemp(prefix="apc-mandate-")
    try:
        path = os.path.join(tmp, "pack.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(member["pack"], ensure_ascii=False, separators=(",", ":")))
        try:
            rr = mod.verify_restrictions(path, tsa_cert=tsa_cert)
            er = mod.verify_evidence(path, tsa_cert=tsa_cert)
        except mod.Ap2WriteError:
            return {k: "not_evaluated:ap2_evidence_pack_check_not_run" for k in CHECKS}, [
                "MP1-MP7: ap2-evidence-pack could not run a check asked for (its exit 74)"], rep
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rep.update(admission=rr.get("admission"), valid=rr.get("valid"), time_anchor=rr.get("time_anchor"),
               existed_by=rr.get("existed_by"), self_asserted_only=er.get("self_asserted_only"))
    if rr.get("admission") != "admitted" or rr.get("valid") is not True:
        res["MP1"] = "failed:ap2_pack_not_valid"
        notes.append("MP1: the ap2-evidence-pack does not verify (admission %s, refusal_class %s): it is evidence of "
                     "nothing" % (rr.get("admission"), rr.get("refusal_class")))
        res.update({k: "not_evaluated:ap2_pack_not_valid" for k in CHECKS[1:]})
        return res, notes, rep
    res["MP1"] = "verified"
    if er.get("self_asserted_only") is not False:
        notes.append("MP1: the pack's keys are self-asserted (no x5c chain validated to an anchor the reader supplied): "
                     "who signed the mandates is not established (SPEC 31.1)")
    arts = []
    for a in member["pack"]["artifacts"]:
        p = mod.parse_sd_jwt(a["sd_jwt_compact"])
        resolved = mod.resolve_disclosures(p["payload"], p["disclosures"])
        arts.append({"name": a["name"], "compact": a["sd_jwt_compact"], "resolved": resolved,
                     "content": _content(resolved), "jwk": a["key"]["jwk"]})
    # MP2 (SPEC 31.2)
    segs = member["chain"].split("~~")
    o = c = None
    if len(segs) != 2:
        mp2 = "failed:chain_not_two_hops"
    else:
        # the join strips the open hop's final `~`; the SDK's _canonical_chain_segment restores it unless the last
        # `~`-part is a compact JWT, so an SD-JWT without disclosures ("h.p.s~") is read back as a JWT. The pack holds
        # each token as issued: the segment is matched as written and with the `~` (SPEC 31.2, independent review 2026-10-31;
        # split on "~~" never leaves a first segment ending in `~`)
        forms = {segs[0], segs[0] + "~"}
        m0 = [x for x in arts if x["compact"] in forms]
        m1 = [x for x in arts if x["compact"] == segs[1]]
        if not m0 or not m1:
            mp2 = "failed:chain_hop_not_in_pack"
        elif len(m0) > 1 or len(m1) > 1:
            mp2 = "failed:chain_hop_in_pack_twice"
        else:
            o, c = m0[0], m1[0]
            oc, cc = o["content"], c["content"]
            cp = c["resolved"]
            if not isinstance(oc, dict) or oc.get("vct") != "mandate.payment.open.1":
                mp2 = "failed:open_hop_not_an_open_payment_mandate"
            elif not isinstance(oc.get("cnf"), dict) or not _p256(oc["cnf"].get("jwk")):
                mp2 = "failed:open_hop_without_cnf_jwk"
            elif not isinstance(cc, dict) or cc.get("vct") != "mandate.payment.1":
                mp2 = "failed:closed_hop_not_a_payment_mandate"
            elif not _jwk_eq(c["jwk"], oc["cnf"]["jwk"]):
                mp2 = "failed:closed_hop_not_signed_by_the_delegate"
            elif (("sd_hash" in cp) == ("issuer_jwt_hash" in cp)) or not (
                    cp.get("sd_hash") == _b64u_sha256(o["compact"].encode("ascii")) if "sd_hash" in cp
                    else cp.get("issuer_jwt_hash") == mod.issuer_jwt_hash(o["compact"])):
                mp2 = "failed:closed_hop_not_bound_to_the_open_hop"
            else:
                mp2 = "verified"
                rep["closed_hop"] = {k: cp.get(k) for k in ("aud", "nonce", "iat")}
    res["MP2"] = mp2
    rep["open"], rep["closed"] = (o["name"] if o else None), (c["name"] if c else None)
    if mp2 != "verified":
        res.update({k: "not_evaluated:chain_not_verified" for k in CHECKS[2:]})
        return res, notes, rep
    oc, cc = o["content"], c["content"]
    sd_alg = o["resolved"].get("_sd_alg")
    # MP3 (SPEC 31.3, 31.3a): the two Mandate Contents meet the AP2 schemas, then the terms
    res["MP3"], rep["constraints"] = evaluate_mp3(oc, cc, mod, arts, sd_alg, btime)
    rep["constraints"] = [list(x) for x in rep["constraints"]]
    # MP4 (SPEC 31.4; on Solana, SPEC 31.9: the Memo carries the chain's SHA-256, this specification's own binding)
    if svm is None:
        n = "verified" if au["nonce"] == _keccak_hex(member["chain"].encode("ascii")) else "failed:nonce_not_the_chain_hash"
        value, to = au["value"], au["to"]
        import apc_assets
        ai = apc_assets.ASSETS.get((acc["network"], acc["asset"]))
        addr_ok, addr_eq = re.compile(r"0x[0-9a-fA-F]{40}").fullmatch, lambda x: x.lower() == to
    else:
        want = hashlib.sha256(member["chain"].encode("ascii")).hexdigest()
        if svm["seller_memo"] is not None and svm["seller_memo"] != want:
            n = "not_evaluated:seller_memo"     # the seller fixed the Memo (extra.memo): no room for the binding
        elif len(svm["memos"]) != 1:
            n = "failed:memo_count_%d" % len(svm["memos"])
        else:
            n = "verified" if svm["memos"][0] == want.encode("ascii") else "failed:memo_not_the_chain_hash"
        value, to = svm["amount"], svm["pay_to"]
        ai = SVM_ASSETS.get((acc["network"], acc["asset"]))
        addr_ok, addr_eq = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}").fullmatch, lambda x: x == to
    amt = _amount(cc.get("payment_amount"))
    cur = TOKEN_CURRENCY.get(ai[0]) if ai else None
    if cur is None:
        a = "not_evaluated:asset_currency_unknown"
    elif amt is None:
        a = "failed:payment_amount_malformed"
    elif amt[1] != cur:
        a = "failed:currency_not_the_token_currency"
    elif ai[1] < MINOR_UNIT[cur]:
        a = "not_evaluated:asset_currency_unknown"
    else:
        a = "verified" if value == amt[0] * 10 ** (ai[1] - MINOR_UNIT[cur]) else "failed:value_not_the_mandate_amount"
    pi = cc.get("payment_instrument")
    if isinstance(pi, dict) and "payee_address" in pi:
        pa = pi["payee_address"]
        if not (isinstance(pa, str) and addr_ok(pa)):
            p = "failed:malformed"
        else:
            p = "verified" if addr_eq(pa) else "failed:payee_address_not_the_authorization_to"
    else:
        p = "not_evaluated:mandate_names_no_address"
    rep["x402"] = {"nonce": n, "amount": a, "payee": p}
    res["MP4"] = _first((n, a, p))
    # MP5 and MP7 (SPEC 31.5, 31.7)
    mine = [e for e in rr.get("restrictions", []) if e.get("original") == o["name"]]
    rep["restrictions"] = []
    by = {x["name"]: x for x in arts}
    mp5, mp7 = [], []
    tav = rr.get("time_anchor")     # the §6.9 subject of the pack: {"state", "reasons"} (None on a refusal)
    ta = isinstance(tav, dict) and tav.get("state") == "verified"
    eb = rr.get("existed_by")
    eb_t = _gentime(eb)
    for e in mine:
        ent = {"in": e.get("in"), "state": e.get("state")}
        if e.get("state") != "verified":
            r5 = "not_evaluated:restriction_%s" % e.get("state")
            ent["reasons"] = e.get("reasons")
        else:
            rc = by[e["in"]]["content"]     # payment.reference hashes with the _sd_alg of the token it is in: R's
            r5, ent["constraints"] = eval_terms(rc, cc, mod, arts, by[e["in"]]["resolved"].get("_sd_alg"), btime,
                                                record=True)
            ent["constraints"] = [list(x) for x in ent["constraints"]]
            if r5.startswith("failed"):
                r5 = "failed:payment_outside_restriction"
            if ta and eb_t is not None and btime is not None:
                ent["existed_before_payment"] = eb_t < btime
            if r5 == "verified":
                r7 = "verified"         # within R: whether R existed before the payment changes nothing (SPEC 31.7)
            elif not r5.startswith("failed"):
                r7 = "not_evaluated:payment_within_restriction_not_shown"   # neither within nor outside R (review 2026-10-31)
            elif not ta or eb_t is None:
                r7 = "not_evaluated:no_time_anchor"
            elif btime is None:
                r7 = "not_evaluated:absent:no_block_time"
            elif eb_t < btime:
                r7 = "failed:paid_outside_restriction_that_existed_before"
            else:
                r7 = "verified"
                notes.append("MP7: %s is not shown to exist before the payment (existed_by %s, block time %d)"
                             % (e.get("in"), eb, btime))
            mp7.append(r7)
        ent["outcome"] = r5
        mp5.append(r5)
        rep["restrictions"].append(ent)
    res["MP5"] = _first(mp5) if mp5 else "not_evaluated:absent:no_restriction"
    res["MP7"] = _first(mp7) if mp7 else ("not_evaluated:absent:no_restriction" if not mp5 else
                                          "not_evaluated:no_verified_restriction")
    if any(x.startswith("failed") for x in mp7):
        notes.append("MP7: a restriction record that existed before the payment, by the TSA's clock, is not shown to "
                     "have been received or known by the agent, the merchant, the credentials provider or the payer; "
                     "AP2 has no revocation (SPEC 31.7)")
    # MP6 (SPEC 31.6): a mandate with time limits and no block time is not shown in force, and that blocks the verdict
    # (not an `absent:` outcome, which SPEC 5 lists without blocking: review observation O1, 31/10)
    exps = [x["exp"] for x in (o["resolved"], oc) if isinstance(x, dict) and "exp" in x]
    nbfs = [x["nbf"] for x in (o["resolved"], oc) if isinstance(x, dict) and "nbf" in x]
    if not all(_is_int(v) for v in exps + nbfs):
        res["MP6"] = "failed:malformed"
    elif not exps and not nbfs:
        res["MP6"] = "verified"         # no time limit to meet
    elif btime is None:
        res["MP6"] = "not_evaluated:no_block_time"
    else:
        if exps and btime > min(exps):
            res["MP6"] = "failed:paid_after_mandate_expiry"
        elif nbfs and btime < max(nbfs):
            res["MP6"] = "failed:paid_before_mandate_validity"
        else:
            res["MP6"] = "verified"
    return res, notes, rep
