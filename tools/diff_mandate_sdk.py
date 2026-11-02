"""SPEC 31.7/31.8: differential of apc_mandate.eval_terms (MP3) against the AP2 SDK's check_payment_constraints
(constraints.py at e1ea56d) on generated open/closed Payment Mandate pairs.

  env -u PYTHONPATH AP2_SDK_PATH=... APC_AP2EV=... /usr/bin/python3.11 tools/diff_mandate_sdk.py [N] [SEED] [presets]

With `presets` the open mandate also pre-sets `pisp`, `risk_data` and `execution_date` (the SDK's
check_preset_payment_claims compares payee, payment_amount, payment_instrument and execution_date only; SPEC 31.3 follows
the AP2 text, every claim of the open Mandate Content unchanged): a changed pisp or risk_data is a declared divergence.

Compares "verified" (apc) with "no violation" (SDK) and "failed:" (apc) with "a violation" (SDK). Outcomes apc leaves
not_evaluated (budget, recurrence, reference without the open checkout, unknown types) are counted apart: the SDK
is given an empty MandateContext and the open checkout hash, so it decides them, and apc by design does not."""
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.environ["AP2_SDK_PATH"])
sys.path.insert(0, os.environ["APC_AP2EV"])
import ap2_evidence  # noqa: E402
import apc_mandate as am  # noqa: E402
from ap2.sdk.constraints import MandateContext, check_payment_constraints  # noqa: E402
from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate  # noqa: E402
from ap2.sdk.generated.payment_mandate import PaymentMandate  # noqa: E402

MERCH = [{"id": "m1", "name": "A", "website": "https://a.example"}, {"id": "m2", "name": "B", "website": "https://b.example"},
         {"id": "m3", "name": "A", "website": "https://a.example"}, {"id": "m1", "name": "Z", "website": "https://z.example"},
         {"id": "m4", "name": "D"}]     # types/merchant.json requires `id` and `name`: the SDK refuses a merchant without
INSTR = [{"id": "i1", "type": "x402"}, {"id": "i2", "type": "card"}, {"id": "i1", "type": "card"}]
PISP = [{"legal_name": "L", "brand_name": "B", "domain_name": "d.example"},
        {"legal_name": "L", "brand_name": "B2", "domain_name": "d.example"}]
CUR = ["USD", "EUR"]
DATES = ["2026-10-01", "2026-10-15", "2026-10-31", "2026-11-30"]
DTS = ["2026-10-01T00:00:00Z", "2026-10-15T12:00:00Z", "2026-10-31T23:59:59Z"]


def gen_constraint(r):
    t = r.choice(["amount_range", "allowed_payees", "allowed_payment_instruments", "allowed_pisps", "execution_date"])
    if t == "amount_range":
        c = {"type": "payment.amount_range", "currency": r.choice(CUR), "max": r.randint(0, 5000)}
        if r.random() < 0.6:
            c["min"] = r.randint(0, 3000)
        return c
    if t == "allowed_payees":
        return {"type": "payment.allowed_payees", "allowed": r.sample(MERCH, r.randint(1, 3))}
    if t == "allowed_payment_instruments":
        return {"type": "payment.allowed_payment_instruments", "allowed": r.sample(INSTR, r.randint(1, 2))}
    if t == "allowed_pisps":
        return {"type": "payment.allowed_pisps", "allowed": r.sample(PISP, r.randint(1, 2))}
    pool = r.choice([DATES, DTS])
    c = {"type": "payment.execution_date"}
    for k in ("not_before", "not_after"):
        if r.random() < 0.7:
            c[k] = r.choice(pool)
    return c


def gen_pair(r):
    cons = [gen_constraint(r) for _ in range(r.randint(1, 4))]
    o = {"vct": "mandate.payment.open.1", "constraints": cons, "cnf": {"jwk": {"kty": "EC"}}}
    edges = [b + d for x in cons if x["type"] == "payment.amount_range" for b in (x["max"], x.get("min", 0))
             for d in (-1, 0, 1) if b + d >= 0]      # the bounds and their neighbours: where a comparison can be off by one
    c = {"vct": "mandate.payment.1", "transaction_id": "t", "payee": r.choice(MERCH),
         "payment_amount": {"amount": r.choice(edges) if edges and r.random() < 0.5 else r.randint(0, 6000),
                            "currency": r.choice(CUR)},
         "payment_instrument": r.choice(INSTR)}
    if r.random() < 0.5:
        c["pisp"] = r.choice(PISP)
    if r.random() < 0.6:
        c["execution_date"] = r.choice(r.choice([DATES, DTS]))
    for k in ("payee", "payment_amount", "payment_instrument"):     # pre-set values, sometimes changed
        if r.random() < 0.15:
            o[k] = c[k] if r.random() < 0.6 else r.choice({"payee": MERCH, "payment_instrument": INSTR,
                                                           "payment_amount": [{"amount": 1, "currency": "USD"}]}[k])
    return o, c


def gen_presets(r):
    """Independent review 2026-10-31: the pre-set values the base generator never sets."""
    o, c = gen_pair(r)
    k = r.random()
    if k < 0.3:
        o["pisp"] = r.choice(PISP)
        if r.random() < 0.5:
            c["pisp"] = o["pisp"]
    elif k < 0.6:
        o["risk_data"] = {"score": r.randint(0, 2)}
        if r.random() < 0.5:
            c["risk_data"] = dict(o["risk_data"])
        else:
            c["risk_data"] = {"score": r.randint(0, 2)}
    else:
        o["execution_date"] = r.choice(DATES)
        if r.random() < 0.5:
            c["execution_date"] = o["execution_date"]
    return o, c


def main(n, seed, presets=False):
    r = random.Random(seed)
    agree = disagree = apc_open = sdk_error = declared = declared_text = 0
    examples, errs = [], {}
    for _ in range(n):
        o, c = gen_presets(r) if presets else gen_pair(r)
        try:
            v = check_payment_constraints(OpenPaymentMandate.model_validate(o), PaymentMandate.model_validate(c),
                                          open_checkout_hash=None, mandate_context=MandateContext())
        except Exception as e:      # the SDK's own failure on a generated pair: not compared
            sdk_error += 1
            errs[type(e).__name__ + ": " + str(e).splitlines()[0][:90]] = errs.get(type(e).__name__ + ": " + str(e).splitlines()[0][:90], 0) + 1
            continue
        mine, _ = am.eval_terms(o, c, ap2_evidence, [], None, None)
        if not (mine.startswith("verified") or mine.startswith("failed")):
            apc_open += 1
            continue
        if (mine == "verified") == (not v):
            agree += 1
        elif mine == "failed:preset_changed:payee" and not v and o["payee"].get("id") == c["payee"].get("id"):
            declared += 1   # SPEC 31.3: "unchanged" is RFC 8785 equality here; the SDK's pre-set check matches by id
        elif mine in ("failed:preset_changed:pisp", "failed:preset_changed:risk_data") and not v:
            declared_text += 1  # SPEC 31.3: the AP2 text keeps every pre-set claim; the SDK does not compare these two
        else:
            disagree += 1
            if len(examples) < 8:
                examples.append({"open": o, "closed": c, "apc": mine, "sdk": v})
    print(json.dumps({"n": n, "seed": seed, "agree": agree, "disagree": disagree, "declared_divergence_preset_payee": declared, "declared_divergence_preset_pisp_risk_data": declared_text, "apc_not_evaluated": apc_open,
                      "sdk_error": sdk_error, "sdk_errors": sorted(errs.items(), key=lambda x: -x[1])[:6], "examples": examples}, indent=1))
    return 1 if disagree else 0


if __name__ == "__main__":
    if sys.argv[3:] not in ([], ["presets"]):
        sys.exit(__doc__)
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000, int(sys.argv[2]) if len(sys.argv) > 2 else 20261031,
                  sys.argv[3:] == ["presets"]))
