"""SPEC 10.1 (Unreleased, 2026-11-21): the window of an X7 signature read at the block time the bundle proves, the
keys given for a bundle without exchange, and --require-http-signature. Keys: RFC 9421 B.1.4 (test-key-ed25519);
signatures are our own, the base written out by hand as RFC 9421 2.5 says. WindowRule, KeysGiven and Required need no
real corpus; RealBlockTime reads two real bundles with B1 verified (bundles/real_v03, apc-0.3; bundles/real_permit2,
apc-0.10) and skips without them. Positive control: on 0f19843 (before this revision) 20 of these 23 tests fail."""
import base64
import copy
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_http as h  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


ED_PUB = b64u("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
ED_SEED = b64u("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")
KEYS = {"apc_http_keys": 1, "keys": {"k": {"alg": "ed25519", "public_key": ED_PUB.hex()}}}
HOST = "api.example.com"
PAYSIG = base64.b64encode(b'{"x402Version":2}').decode()
T0 = 1763700000                              # a block time (2025-11-21T04:40:00Z)


def params(created, expires, comps):
    p = "(" + " ".join('"%s"' % c for c in comps) + ")"
    if created is not None:
        p += ";created=%d" % created
    if expires is not None:
        p += ";expires=%d" % expires
    return p + ';keyid="k"'


def signed(lines, comps, created, expires):
    p = params(created, expires, comps)
    base = "\n".join(lines + ['"@signature-params": ' + p]).encode()
    return [["Signature-Input", "sig1=" + p],
            ["Signature", "sig1=:%s:" % base64.b64encode(sol.ed25519_sign(ED_SEED, base)).decode()]]


def request(created=None, expires=None, sign=True, uri="https://api.example.com/premium-data", paysig=PAYSIG):
    host = uri.split("/")[2]
    fields = [["Host", host], ["PAYMENT-SIGNATURE", paysig]]
    if sign:
        fields += signed(['"@method": POST', '"@authority": %s' % host, '"payment-signature": %s' % paysig],
                         ("@method", "@authority", "payment-signature"), created, expires)
    return {"method": "POST", "target_uri": uri, "fields": fields}


def response(created=None, expires=None):
    return {"status": 200, "fields": [["Content-Type", "application/json"]]
            + signed(['"@status": 200'], ("@status",), created, expires)}


def expected(where, c, x, t, n=0):
    """SPEC 10.1 (a) and (b), written from the text; n the reader's margin"""
    if c is not None and x is not None and x < c:
        return "failed:expires_before_created"
    if t is None:
        return "verified"
    if where == "request" and c is not None and c > t + n:
        return "not_evaluated:created_after_block_time"
    if x is not None and x < t - n:
        return "not_evaluated:expired_before_block_time"
    return "verified"


class WindowRule(unittest.TestCase):
    def one(self, where, c, x, t, keys=KEYS):
        ex = {"request": request(c, x)} if where == "request" else {"request": request(sign=False),
                                                                    "response": response(c, x)}
        res, notes, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(keys) if keys else None, t)
        (s,) = m["signatures"]
        return res["X7"], s["result"], notes

    def test_expires_before_created_fails_with_or_without_block_time(self):
        for where in ("request", "response"):
            for t in (None, T0):
                self.assertEqual(self.one(where, T0, T0 - 1, t)[:2], ("failed:expires_before_created",) * 2)
        # the 2026-11-20 measure: created=1618884473, expires=1
        self.assertEqual(self.one("request", 1618884473, 1, None)[1], "failed:expires_before_created")

    def test_equal_created_and_expires_is_one_second(self):
        self.assertEqual(self.one("request", T0, T0, T0)[1], "verified")
        self.assertEqual(self.one("request", T0, T0, T0 + 1)[1], "not_evaluated:expired_before_block_time")
        self.assertEqual(self.one("request", T0, T0, T0 - 1)[1], "not_evaluated:created_after_block_time")

    def test_request_window_at_the_block_time(self):
        self.assertEqual(self.one("request", T0 - 5, T0 + 60, T0)[:2], ("verified", "verified"))
        self.assertEqual(self.one("request", T0 + 1, T0 + 60, T0)[:2], ("not_evaluated:created_after_block_time",) * 2)
        self.assertEqual(self.one("request", T0 - 60, T0 - 1, T0)[:2], ("not_evaluated:expired_before_block_time",) * 2)
        self.assertEqual(self.one("request", None, T0 - 1, T0)[1], "not_evaluated:expired_before_block_time")
        self.assertEqual(self.one("request", T0 + 1, None, T0)[1], "not_evaluated:created_after_block_time")
        self.assertEqual(self.one("request", None, None, T0)[1], "verified")

    def test_response_created_after_the_block_is_the_normal_order(self):
        self.assertEqual(self.one("response", T0 + 3, T0 + 300, T0)[1], "verified")
        self.assertEqual(self.one("response", T0 - 10, T0 - 1, T0)[1], "not_evaluated:expired_before_block_time")

    def test_without_block_time_a_note_and_the_result_unchanged(self):
        x7, r, notes = self.one("request", T0 + 10, T0 + 20, None)
        self.assertEqual((x7, r), ("verified", "verified"))
        self.assertEqual([n for n in notes if "not compared" in n],
                         ["X7: request label sig1 carries created/expires, not compared: the bundle proves no block "
                          "time (SPEC 10.1 b)"])
        self.assertEqual([n for n in self.one("request", None, None, None)[2] if "not compared" in n], [])

    def test_without_keys_nothing_is_judged(self):
        self.assertEqual(self.one("request", T0, T0 - 1, T0, keys=None)[1], "not_evaluated:absent:no_http_keys")

    def test_a_signature_that_fails_keeps_its_failure(self):
        ex = {"request": request(T0 + 100, T0 + 200)}
        ex["request"]["fields"][1][1] = base64.b64encode(b'{"x402Version":1}').decode()     # covered field changed
        res, _, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), T0)
        self.assertEqual(m["signatures"][0]["result"], "failed:signature_invalid")

    def test_a_label_not_evaluated_keeps_its_reason(self):
        # @query-param is not supported (SPEC 10): the label is not judged, so its window is not read either
        p = '("@query-param";name="a");created=%d;expires=%d;keyid="k"' % (T0 + 100, T0 + 200)
        ex = {"request": request(sign=False)}
        ex["request"]["fields"] += [["Signature-Input", "sig1=" + p], ["Signature", "sig1=:AAAA:"]]
        for t in (None, T0):
            res, notes, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), t)
            self.assertEqual(m["signatures"][0]["result"], 'not_evaluated:component_not_supported:"@query-param";name="a"')
            self.assertEqual([n for n in notes if "not compared" in n], [])

    def test_a_malformed_field_with_keys_and_block_time(self):
        ex = {"request": request(T0, T0 + 1)}
        ex["request"]["fields"][2][1] += ", sig1=()"                # a repeated label (RFC 9421 4.1)
        res, _, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), T0)
        self.assertEqual((res["X7"], len(m["signatures"])), ("failed:signature_input_malformed", 1))

    def test_generated_windows(self):
        rng = random.Random(20261121)
        vals = [None, 0, 1, T0 - 10 ** 6, T0 - 1, T0, T0 + 1, T0 + 10 ** 6, 10 ** 14]
        seen = set()
        for _ in range(600):
            where = rng.choice(("request", "response"))
            c, x = rng.choice(vals), rng.choice(vals)
            t = rng.choice((None, T0, T0 + rng.randint(-5, 5)))
            r = self.one(where, c, x, t)[1]
            self.assertEqual(r, expected(where, c, x, t), (where, c, x, t))
            seen.add(r)
        self.assertEqual(seen, {"verified", "failed:expires_before_created", "not_evaluated:created_after_block_time",
                                "not_evaluated:expired_before_block_time"})

    def test_skew_is_a_parameter(self):
        old = h.WINDOW_SKEW
        try:
            h.WINDOW_SKEW = 2
            self.assertEqual(self.one("request", T0 + 2, T0 + 60, T0)[1], "verified")
            self.assertEqual(self.one("request", T0 + 3, T0 + 60, T0)[1], "not_evaluated:created_after_block_time")
            self.assertEqual(self.one("request", T0 - 60, T0 - 2, T0)[1], "verified")
            self.assertEqual(self.one("request", T0 - 60, T0 - 3, T0)[1], "not_evaluated:expired_before_block_time")
        finally:
            h.WINDOW_SKEW = old
        self.assertEqual(h.WINDOW_SKEW, 0)


def md_bundle():
    """the x402 http.md example payment (sources/http_20261025/http.md), without exchange"""
    import re
    with open(os.path.join(ROOT, "sources", "http_20261025", "http.md")) as fh:
        md = fh.read()
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", md, re.S)]
    return {"bundle_version": "apc-0.3", "payment_payload": blocks[1], "payment_required": blocks[0],
            "settlement": blocks[2]}


class KeysGiven(unittest.TestCase):
    def test_no_exchange_lists_x7_absent(self):
        r = av.verify_bundle(md_bundle(), None, KEYS)
        self.assertEqual(r["checks"]["X7"], "not_evaluated:absent:no_exchange")
        self.assertIn("X7", r["absent"])
        self.assertEqual(r["absent"], sorted(r["absent"]))
        self.assertIn("X7: http keys given, but the bundle carries no exchange: no HTTP signature was judged "
                      "(SPEC 10.1 c)", r["notes"])
        r0 = av.verify_bundle(md_bundle())
        self.assertNotIn("X7", r0["checks"])
        self.assertEqual(r0["verdict"], r["verdict"])          # absent does not block (section 5)
        self.assertEqual(sorted(set(r["absent"]) - set(r0["absent"])), ["X7"])

    def test_every_bundle_version_without_exchange(self):
        for ver in ("apc-0.1", "apc-0.2", "apc-0.3"):     # apc-0.1 and apc-0.2 cannot carry exchange
            d = md_bundle()
            d["bundle_version"] = ver
            r = av.verify_bundle(d, None, KEYS)
            self.assertEqual((r["verdict"], r["checks"]["X7"]), ("chain_verified", "not_evaluated:absent:no_exchange"),
                             ver)

    def test_keys_outside_the_grammar_refused_without_exchange(self):
        bad = [{"apc_http_keys": 2, "keys": KEYS["keys"]}, {"apc_http_keys": 1, "keys": {}},
               dict(KEYS, extra=1), {"apc_http_keys": 1, "keys": {"k": {"alg": "ed25519", "public_key": "00"}}}, [], None]
        for ver in ("apc-0.1", "apc-0.2", "apc-0.3"):     # until this revision apc-0.1 and apc-0.2 did not read them
            d = md_bundle()
            d["bundle_version"] = ver
            for k in bad[:-1]:
                with self.assertRaises(av.Refusal, msg=(ver, k)):
                    av.verify_bundle(d, None, k)
        self.assertNotIn("X7", av.verify_bundle(md_bundle(), None, bad[-1])["checks"])   # None = no keys given

    def test_absent_stays_sorted_with_keys_after_x7(self):
        d = md_bundle()
        d["exchange_mcp"] = {"request": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                         "params": {"_meta": {"x402/payment": d["payment_payload"]}}}}
        r = av.verify_bundle(d, None, KEYS)
        self.assertIn("XM2", r["absent"])                      # XM2 sorts after X7
        self.assertEqual(r["absent"], sorted(r["absent"]))
        self.assertEqual(r["checks"]["X7"], "not_evaluated:absent:no_exchange")

    def test_with_exchange_x7_is_the_exchange_one(self):
        d = md_bundle()
        d["exchange"] = {"request": request(sign=False)}
        self.assertEqual(av.verify_bundle(d, None, KEYS)["checks"]["X7"], "not_evaluated:absent:no_signature")


GOOD_REQ = {"where": "request", "label": "sig1", "covered": ['"@authority"', '"payment-signature"'], "created": 1,
            "expires": 2}


class Required(unittest.TestCase):
    def rep(self, verdict, x7, sigs=(GOOD_REQ,)):
        checks = {"K1": "verified"}
        if x7 is not None:
            checks["X7"] = x7
        return {"verdict": verdict, "checks": checks, "notes": [], "exchange": {"signatures": [dict(x) for x in sigs]}}

    def test_only_a_chain_verified_without_verified_x7_changes(self):
        x7s = (None, "verified", "not_evaluated:absent:no_exchange", "not_evaluated:absent:no_signature",
               "not_evaluated:created_after_block_time", "failed:expires_before_created")
        for v in ("chain_verified", "chain_incomplete", "chain_failed"):
            for x7 in x7s:
                r = av.require_http_signature(self.rep(v, x7))
                met = x7 == "verified"
                self.assertEqual(r["http_signature_required"],
                                 {"profile": "apc-http-coverage/1", "met": met, "X7": x7, "missing": []})
                self.assertEqual(r["verdict"], "chain_incomplete" if v == "chain_verified" and not met else v, (v, x7))
                self.assertEqual(len(r["notes"]), 1 if v == "chain_verified" and not met else 0)

    def cli(self, *args, bundle=None):
        with tempfile.TemporaryDirectory() as tmp:
            b, k = os.path.join(tmp, "b.json"), os.path.join(tmp, "k.json")
            with open(b, "w") as fh:
                json.dump(md_bundle() if bundle is None else bundle, fh)
            with open(k, "w") as fh:
                json.dump(KEYS, fh)
            argv = [a.replace("@B", b).replace("@K", k) for a in args]
            env = {x: y for x, y in os.environ.items() if x != "PYTHONPATH"}
            p = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py")] + argv, capture_output=True,
                               text=True, env=env, timeout=120)
            return p.returncode, (json.loads(p.stdout) if p.stdout.startswith("{") else None)

    def test_cli_needs_http_keys(self):
        self.assertEqual(self.cli("@B", "--require-http-signature")[0], 64)
        self.assertEqual(self.cli("--require-http-signature", "@B", "--require-level", "signature")[0], 64)

    def test_cli_with_keys(self):
        rc0, r0 = self.cli("@B", "--http-keys", "@K")
        rc, r = self.cli("@B", "--http-keys", "@K", "--require-http-signature")
        self.assertNotIn("http_signature_required", r0)
        self.assertEqual(r["http_signature_required"], {"profile": "apc-http-coverage/1", "met": False,
                                                        "X7": "not_evaluated:absent:no_exchange",
                                                        "missing": [{"where": "request", "label": None,
                                                                     "missing": ["signature"]}]})
        self.assertEqual((rc0, r0["verdict"]), (0, "chain_verified"))     # the http.md payment verifies
        self.assertEqual((rc, r["verdict"]), (2, "chain_incomplete"))


REAL = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")
REAL_P2 = os.path.join(ROOT, "bundles", "real_permit2", "p029_envelope_reconstructed_proof.json")   # apc-0.10, B1


def coverage_model(where, covered, created, expires):
    """profile apc-http-coverage/1 written from SPEC 10.1 (d)"""
    miss = []
    if where == "request":
        if '"@authority"' not in covered and '"@target-uri"' not in covered:
            miss.append("@authority|@target-uri")
        if '"payment-signature"' not in covered:
            miss.append("payment-signature")
        miss += [n for n, v in (("created", created), ("expires", expires)) if v is None]
    else:
        miss += [n for n in ("@status", "payment-response") if '"%s"' % n not in covered]
    return miss


class Coverage(unittest.TestCase):
    """SPEC 10.1 (d), Amendment 0.21.6: profile apc-http-coverage/1 under --require-http-signature"""
    IDS = ['"@authority"', '"@target-uri"', '"payment-signature"', '"@method"', '"@path"', '"@status"',
           '"payment-response"', '"@authority";req', '"@path";req', '"payment-required"', '"content-digest"']

    def test_generated_label_sets(self):
        rng = random.Random(20261123)
        for _ in range(800):
            sigs = []
            for i in range(rng.randint(0, 3)):
                where = rng.choice(("request", "response"))
                sigs.append({"where": where, "label": "s%d" % i, "covered": rng.sample(self.IDS, rng.randint(0, 5)),
                             "created": rng.choice((None, 5)), "expires": rng.choice((None, 9)), "result": "verified"})
            want = [{"where": x["where"], "label": x["label"],
                     "missing": coverage_model(x["where"], x["covered"], x["created"], x["expires"])} for x in sigs]
            want = [w for w in want if w["missing"]]
            if not any(x["where"] == "request" for x in sigs):
                want.append({"where": "request", "label": None, "missing": ["signature"]})
            r = av.require_http_signature({"verdict": "chain_verified", "checks": {"X7": "verified"}, "notes": [],
                                           "exchange": {"signatures": sigs}})
            self.assertEqual(r["http_signature_required"]["missing"], want, sigs)
            self.assertEqual((r["verdict"], r["http_signature_required"]["met"]),
                             ("chain_verified", True) if not want else ("chain_incomplete", False))

    def test_no_exchange_member_or_none(self):
        for rep in ({"verdict": "chain_verified", "checks": {"X7": "verified"}, "notes": []},
                    {"verdict": "chain_verified", "checks": {"X7": "verified"}, "notes": [], "exchange": None}):
            r = av.require_http_signature(rep)
            self.assertEqual(r["http_signature_required"]["missing"],
                             [{"where": "request", "label": None, "missing": ["signature"]}])

    def signed_md(self, c=None, x=None, resp=None):
        d = md_bundle()
        pp = base64.b64encode(json.dumps(d["payment_payload"]).encode()).decode()
        d["exchange"] = {"request": request(c, x, paysig=pp)}
        if resp is not None:
            d["exchange"]["response"] = resp
        return d

    def test_end_to_end_on_the_http_md_payment(self):
        r = av.require_http_signature(av.verify_bundle(self.signed_md(T0, T0 + 60), None, KEYS))
        self.assertEqual((r["checks"]["X7"], r["verdict"], r["http_signature_required"]["missing"]),
                         ("verified", "chain_verified", []))
        r = av.require_http_signature(av.verify_bundle(self.signed_md(T0, None), None, KEYS))
        self.assertEqual((r["checks"]["X7"], r["verdict"], r["http_signature_required"]["missing"]),
                         ("verified", "chain_incomplete", [{"where": "request", "label": "sig1", "missing": ["expires"]}]))
        # the response carries the settlement (X3); signed over @status only, then over @status and payment-response
        st = base64.b64encode(json.dumps(md_bundle()["settlement"]).encode()).decode()
        for comps, missing, verdict in ((("@status",), [{"where": "response", "label": "sig1",
                                                         "missing": ["payment-response"]}], "chain_incomplete"),
                                        (("@status", "payment-response"), [], "chain_verified")):
            lines = ['"@status": 200', '"payment-response": %s' % st][:len(comps)]
            resp = {"status": 200, "fields": [["Content-Type", "application/json"], ["PAYMENT-RESPONSE", st]]
                    + signed(lines, comps, T0, T0 + 60)}
            r0 = av.verify_bundle(self.signed_md(T0, T0 + 60, resp), None, KEYS)
            self.assertEqual((r0["verdict"], r0["checks"]["X3"], r0["checks"]["X7"]),
                             ("chain_verified", "verified", "verified"))
            r = av.require_http_signature(r0)
            self.assertEqual((r["verdict"], r["http_signature_required"]["missing"]), (verdict, missing), comps)


class ClockSkew(unittest.TestCase):
    """SPEC 10.1 (b), Amendment 0.21.6: --http-clock-skew N (0..300, with --http-keys), and the measured deltas"""

    def one(self, where, c, x, t, n):
        ex = {"request": request(c, x)} if where == "request" else {"request": request(sign=False),
                                                                    "response": response(c, x)}
        old = h.WINDOW_SKEW
        try:
            h.WINDOW_SKEW = n
            res, notes, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), t)
        finally:
            h.WINDOW_SKEW = old
        return m

    def test_generated_windows_with_a_margin(self):
        rng = random.Random(20261122)
        for _ in range(500):
            where, n = rng.choice(("request", "response")), rng.randint(0, 300)
            t = T0
            c = rng.choice((None, t - n - 1, t - n, t, t + n, t + n + 1, t + rng.randint(-400, 400)))
            x = rng.choice((None, t - n - 1, t - n, t, t + n, t + n + 1, t + rng.randint(-400, 400)))
            m = self.one(where, c, x, t, n)
            (sg,) = m["signatures"]
            self.assertEqual(sg["result"], expected(where, c, x, t, n), (where, c, x, n))
            self.assertEqual((sg["block_time_minus_created"], sg["expires_minus_block_time"]),
                             (None if c is None else t - c, None if x is None else x - t))
            self.assertEqual((m["block_time"], m["clock_skew"]), (t, n))

    def test_deltas_null_without_block_time_and_on_a_malformed_field(self):
        m = self.one("request", T0, T0 + 9, None, 0)
        self.assertEqual((m["signatures"][0]["block_time_minus_created"], m["signatures"][0]["expires_minus_block_time"],
                          m["block_time"]), (None, None, None))
        ex = {"request": request(T0, T0 + 1)}
        ex["request"]["fields"][2][1] += ", sig1=()"
        _, _, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), T0)
        self.assertEqual((m["signatures"][0]["result"], m["signatures"][0]["block_time_minus_created"],
                          m["signatures"][0]["expires_minus_block_time"]), ("failed:signature_input_malformed", None, None))
        _, _, m = h.check({"payment_payload": {}, "exchange": {"request": request(T0 - 4, T0 + 7)}}, None, T0)
        self.assertEqual((m["signatures"][0]["result"], m["signatures"][0]["block_time_minus_created"],
                          m["signatures"][0]["expires_minus_block_time"]), ("not_evaluated:absent:no_http_keys", 4, 7))

    def test_deltas_only_from_integer_parameters(self):
        # created as a String, a Boolean or a Decimal is outside RFC 9421 2.3 (Integer): the label fails, no delta
        for bad in ('created="5"', "created=?1", "created=5.5", "expires=?0", 'expires="9"'):
            p = '("@method");%s;keyid="k"' % bad
            ex = {"request": request(sign=False)}
            ex["request"]["fields"] += [["Signature-Input", "sig1=" + p], ["Signature", "sig1=:AAAA:"]]
            for keys in (h.parse_keys(KEYS), None):
                _, _, m = h.check({"payment_payload": {}, "exchange": ex}, keys, T0)
                sg = m["signatures"][0]
                self.assertEqual((sg["block_time_minus_created"], sg["expires_minus_block_time"]), (None, None), bad)
                if keys is not None:
                    self.assertEqual(sg["result"], "failed:signature_input_malformed", bad)

    def test_library_grammar(self):
        for n in (-1, 301, 10 ** 9, True, False, 5.0, "5", None, [5]):
            with self.assertRaises(av.Refusal, msg=repr(n)):
                av.verify_bundle(md_bundle(), None, KEYS, http_clock_skew=n)
        for n in (0, 1, 300):
            self.assertEqual(av.verify_bundle(md_bundle(), None, KEYS, http_clock_skew=n)["verdict"], "chain_verified")
        self.assertEqual(h.WINDOW_SKEW, 0)

    def cli(self, *args, bundle=None):
        return Required.cli(self, *args, bundle=bundle)

    def test_cli_margin_reaches_the_report(self):
        d = Coverage.signed_md(self, T0, T0 + 60)
        for extra, n in (((), 0), (("--http-clock-skew", "7"), 7), (("--http-clock-skew", "300"), 300)):
            rc, r = self.cli("@B", "--http-keys", "@K", *extra, bundle=d)
            self.assertEqual((rc, r["exchange"]["clock_skew"], r["checks"]["X7"]), (0, n, "verified"), extra)

    def test_cli_grammar(self):
        for v in ("0", "5", "300"):
            self.assertEqual(self.cli("@B", "--http-keys", "@K", "--http-clock-skew", v)[0], 0, v)
        for v in ("301", "-1", "+5", "05", "00", "5.0", " 5", "5 ", "1e2", "\u0663", "", "0x5", "1000"):
            self.assertEqual(self.cli("@B", "--http-keys", "@K", "--http-clock-skew", v)[0], 64, repr(v))
        self.assertEqual(self.cli("@B", "--http-keys", "@K", "--http-clock-skew")[0], 64)
        self.assertEqual(self.cli("@B", "--http-clock-skew", "5")[0], 64)                  # without --http-keys
        self.assertEqual(self.cli("@B", "--http-keys", "@K", "--http-clock-skew", "5", "--http-clock-skew", "5")[0], 64)


class RealBlockTime(unittest.TestCase):
    """a real Base payment with B1 verified, given an exchange signed by us: the window read at its block time"""

    @classmethod
    def setUpClass(cls):
        from tests import real_corpus
        real_corpus.need("real_v03", "real_permit2")
        cls.docs = []
        for p in (REAL, REAL_P2):
            with open(p) as fh:
                cls.docs.append(av.strict_json(fh.read()))
        cls.doc = cls.docs[0]
        cls.t = int(cls.doc["inclusion"]["block_header"]["timestamp"], 16)

    def with_exchange(self, c, x, doc=None):
        d = copy.deepcopy(self.doc if doc is None else doc)
        pp = base64.b64encode(json.dumps(d["payment_payload"]).encode()).decode()
        url = (d["payment_payload"].get("resource") or d.get("payment_required", {}).get("resource") or {}).get("url")
        d["exchange"] = {"request": request(c, x, uri=url or "https://api.example.com/premium-data", paysig=pp)}
        return d

    def test_base_bundles(self):
        for doc in self.docs:
            r = av.verify_bundle(doc)
            self.assertEqual((r["verdict"], r["checks"]["B1"]), ("chain_verified", "verified"))

    def test_window(self):
        for doc in self.docs:                   # apc-0.3 (apc_verify) and apc-0.10 (apc_permit2)
            t = int(doc["inclusion"]["block_header"]["timestamp"], 16)
            for (c, x), (verdict, x7) in (
                    ((t - 5, t + 60), ("chain_verified", "verified")),
                    ((t, t), ("chain_verified", "verified")),
                    ((t + 1, t + 60), ("chain_incomplete", "not_evaluated:created_after_block_time")),
                    ((t - 60, t - 1), ("chain_incomplete", "not_evaluated:expired_before_block_time")),
                    ((t - 5, t - 6), ("chain_failed", "failed:expires_before_created"))):
                r = av.verify_bundle(self.with_exchange(c, x, doc), None, KEYS)
                self.assertEqual((r["verdict"], r["checks"]["X7"], r["checks"]["X1"]), (verdict, x7, "verified"),
                                 (doc["bundle_version"], c, x))

    def test_block_time_only_with_b1_verified(self):
        for doc in self.docs:
            t = int(doc["inclusion"]["block_header"]["timestamp"], 16)
            d = self.with_exchange(t + 1000, t + 2000, doc)
            d["inclusion"]["block_header"]["parentHash"] = "0x" + "11" * 32     # the header no longer hashes to B1
            r = av.verify_bundle(d, None, KEYS)
            self.assertFalse(r["checks"]["B1"].startswith("verified"), doc["bundle_version"])
            self.assertEqual(r["checks"]["X7"], "verified", doc["bundle_version"])
            self.assertTrue(any("proves no block time" in n for n in r["notes"]), doc["bundle_version"])

    def test_margin_on_the_real_bundles(self):
        for doc in self.docs:
            t = int(doc["inclusion"]["block_header"]["timestamp"], 16)
            d = self.with_exchange(t + 3, t + 60, doc)
            for n, x7 in ((0, "not_evaluated:created_after_block_time"), (2, "not_evaluated:created_after_block_time"),
                          (3, "verified"), (300, "verified")):
                r = av.verify_bundle(d, None, KEYS, http_clock_skew=n)
                self.assertEqual(r["checks"]["X7"], x7, (doc["bundle_version"], n))
                self.assertEqual((r["exchange"]["block_time"], r["exchange"]["clock_skew"],
                                  r["exchange"]["signatures"][0]["block_time_minus_created"],
                                  r["exchange"]["signatures"][0]["expires_minus_block_time"]), (t, n, -3, 60))
            self.assertEqual(h.WINDOW_SKEW, 0)

    def test_required_on_the_real_bundle(self):
        r = av.require_http_signature(av.verify_bundle(self.doc, None, KEYS))
        self.assertEqual((r["verdict"], r["http_signature_required"]["met"]), ("chain_incomplete", False))
        r = av.require_http_signature(av.verify_bundle(self.with_exchange(self.t - 5, self.t + 60), None, KEYS))
        self.assertEqual((r["verdict"], r["http_signature_required"]["met"]), ("chain_verified", True))


if __name__ == "__main__":
    unittest.main()
