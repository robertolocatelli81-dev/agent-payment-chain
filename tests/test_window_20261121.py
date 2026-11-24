"""SPEC 10.1 (Amendment 0.21.6, 2026-11-22): the window of an X7 signature read at the block time the bundle proves, the
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
    """SPEC 10.1 (a) and (b), written from the text (one label, the other message unsigned); n the reader's margin"""
    if c is not None and x is not None and x < c:
        return "failed:expires_before_created"
    if t is None or c is None:
        return "verified"
    if where == "request" and c > t + n:
        return "not_evaluated:created_after_block_time"
    if where == "response" and c < t - n:
        return "not_evaluated:created_before_block_time"
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
        self.assertEqual(self.one("request", T0, T0, T0 + 1)[1], "verified")      # expires not compared with T
        self.assertEqual(self.one("request", T0, T0, T0 - 1)[1], "not_evaluated:created_after_block_time")
        self.assertEqual(self.one("response", T0, T0, T0)[1], "verified")
        self.assertEqual(self.one("response", T0, T0, T0 + 1)[1], "not_evaluated:created_before_block_time")

    def test_request_order_at_the_block_time(self):
        self.assertEqual(self.one("request", T0 - 5, T0 + 60, T0)[:2], ("verified", "verified"))
        self.assertEqual(self.one("request", T0 + 1, T0 + 60, T0)[:2], ("not_evaluated:created_after_block_time",) * 2)
        # an honest slow request: signed 70 s before the block, expired 10 s before it (D-B): verified
        self.assertEqual(self.one("request", T0 - 70, T0 - 10, T0)[:2], ("verified", "verified"))
        self.assertEqual(self.one("request", None, T0 - 1, T0)[1], "verified")
        self.assertEqual(self.one("request", T0 + 1, None, T0)[1], "not_evaluated:created_after_block_time")
        self.assertEqual(self.one("request", None, None, T0)[1], "verified")

    def test_response_order_at_the_block_time(self):
        self.assertEqual(self.one("response", T0 + 3, T0 + 300, T0)[1], "verified")
        self.assertEqual(self.one("response", T0, None, T0)[1], "verified")
        self.assertEqual(self.one("response", T0 - 1, T0 + 300, T0)[:2], ("not_evaluated:created_before_block_time",) * 2)
        self.assertEqual(self.one("response", None, T0 - 1, T0)[1], "verified")             # expires not compared

    def pair(self, rc, rx, sc, sx, t, n=0):
        ex = {"request": request(rc, rx), "response": response(sc, sx)}
        old = h.WINDOW_SKEW
        try:
            h.WINDOW_SKEW = n
            res, notes, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), t)
        finally:
            h.WINDOW_SKEW = old
        return res["X7"], [s["result"] for s in m["signatures"]]

    def test_response_after_its_request_with_or_without_block_time(self):
        self.assertEqual(self.pair(T0 - 5, None, T0 - 4, None, None), ("verified", ["verified", "verified"]))
        self.assertEqual(self.pair(T0 - 5, None, T0 - 5, None, None), ("verified", ["verified", "verified"]))
        self.assertEqual(self.pair(T0 - 5, None, T0 - 6, None, None),
                         ("not_evaluated:created_before_request", ["verified", "not_evaluated:created_before_request"]))
        self.assertEqual(self.pair(T0 - 5, None, T0 - 6, None, None, 1), ("verified", ["verified", "verified"]))
        self.assertEqual(self.pair(T0 - 5, None, T0 - 7, None, None, 1)[0], "not_evaluated:created_before_request")
        # with T, the block time is read first
        self.assertEqual(self.pair(T0 - 5, None, T0 - 6, None, T0)[1],
                         ["verified", "not_evaluated:created_before_block_time"])
        self.assertEqual(self.pair(T0 - 50, None, T0 + 1, None, T0), ("verified", ["verified", "verified"]))
        # a request out of order is not the request the response is compared with
        self.assertEqual(self.pair(T0 + 10, None, T0 + 5, None, T0)[1],
                         ["not_evaluated:created_after_block_time", "verified"])
        # a request without created, or not judged: nothing to compare with
        self.assertEqual(self.pair(None, None, 3, None, None)[1], ["verified", "verified"])

    def test_without_block_time_a_note_and_the_result_unchanged(self):
        x7, r, notes = self.one("request", T0 + 10, T0 + 20, None)
        self.assertEqual((x7, r), ("verified", "verified"))
        self.assertEqual([n for n in notes if "not compared" in n],
                         ["X7: request label sig1 carries created, not compared with a block time: the bundle proves "
                          "none (SPEC 10.1 b)"])
        self.assertEqual([n for n in self.one("request", None, None, None)[2] if "not compared" in n], [])
        # a response label has its note too (review of 2026-11-21, second round: a mutant that named only the
        # request labels was alive)
        x7, r, notes = self.one("response", T0 + 10, None, None)
        self.assertEqual((x7, r), ("verified", "verified"))
        self.assertEqual([n for n in notes if "not compared" in n],
                         ["X7: response label sig1 carries created, not compared with a block time: the bundle proves "
                          "none (SPEC 10.1 b)"])

    def test_without_keys_nothing_is_judged(self):
        self.assertEqual(self.one("request", T0, T0 - 1, T0, keys=None)[1], "not_evaluated:absent:no_http_keys")

    def test_a_signature_that_fails_keeps_its_failure(self):
        ex = {"request": request(T0 + 100, T0 + 200)}
        ex["request"]["fields"][1][1] = base64.b64encode(b'{"x402Version":1}').decode()     # covered field changed
        res, _, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), T0)
        self.assertEqual(m["signatures"][0]["result"], "failed:signature_invalid")

    def test_a_label_not_evaluated_keeps_its_reason(self):
        # sf is not supported (SPEC 10; @query-param is, from SPEC 10.2): the label is not judged, nor its window
        p = '("content-type";sf);created=%d;expires=%d;keyid="k"' % (T0 + 100, T0 + 200)
        ex = {"request": request(sign=False)}
        ex["request"]["fields"] += [["Signature-Input", "sig1=" + p], ["Signature", "sig1=:AAAA:"]]
        for t in (None, T0):
            res, notes, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), t)
            self.assertEqual(m["signatures"][0]["result"], 'not_evaluated:component_not_supported:"content-type";sf')
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
                                "not_evaluated:created_before_block_time"})

    def test_skew_is_a_parameter(self):
        old = h.WINDOW_SKEW
        try:
            h.WINDOW_SKEW = 2
            self.assertEqual(self.one("request", T0 + 2, T0 + 60, T0)[1], "verified")
            self.assertEqual(self.one("request", T0 + 3, T0 + 60, T0)[1], "not_evaluated:created_after_block_time")
            self.assertEqual(self.one("response", T0 - 2, T0 + 60, T0)[1], "verified")
            self.assertEqual(self.one("response", T0 - 3, T0 + 60, T0)[1], "not_evaluated:created_before_block_time")
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

    def test_the_note_counts_the_entries_of_missing(self):
        # review of 2026-11-21 (second round): the note said "1 label(s) short" of a report with no label at all
        full_q = {"where": "request", "label": "q", "covered": ['"@authority"', '"payment-signature"'], "created": 5,
                  "expires": 9, "result": "verified"}
        full_r = {"where": "response", "label": "r", "covered": ['"@status"', '"payment-response"'], "created": None,
                  "expires": None, "result": "verified"}
        bare_q = dict(full_q, label="q2", covered=[])
        bare_r = dict(full_r, label="r2", covered=['"@status"'])
        for sigs, x7, n in (([], "not_evaluated:absent:no_signature", 1), ([full_r], "verified", 1),
                            ([bare_r], "verified", 2), ([full_q, bare_q, bare_r], "verified", 2),
                            ([full_q, full_r], "not_evaluated:created_after_block_time", 0)):
            r = av.require_http_signature({"verdict": "chain_verified", "checks": {"X7": x7}, "notes": ["n"],
                                           "exchange": {"signatures": sigs}})
            self.assertEqual(len(r["http_signature_required"]["missing"]), n, sigs)
            note = ("X7 is %s and `missing` has %d entry(ies) under apc-http-coverage/1; a verified HTTP signature "
                    "with that coverage is required (--require-http-signature, SPEC 10.1 d): verdict chain_incomplete")
            self.assertEqual(r["notes"], ["n", note % (x7, n)])
        r = av.require_http_signature({"verdict": "chain_verified", "checks": {"X7": "verified"}, "notes": ["n"],
                                       "exchange": {"signatures": [full_q, full_r]}})
        self.assertEqual((r["verdict"], r["notes"]), ("chain_verified", ["n"]))

    def test_a_malformed_field_is_an_entry_of_missing_without_a_label(self):
        # review of 2026-11-21 (second round): a mutant that skipped the entries without a label was alive
        ex = {"request": request(T0, T0 + 1)}
        ex["request"]["fields"][2][1] += ", sig1=()"             # the label repeated: the whole field is malformed
        res, _, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), T0)
        r = av.require_http_signature({"verdict": "chain_verified", "checks": res, "notes": [], "exchange": m})
        self.assertEqual(r["http_signature_required"],
                         {"profile": "apc-http-coverage/1", "met": False, "X7": "failed:signature_input_malformed",
                          "missing": [{"where": "request", "label": None,
                                       "missing": ["@authority|@target-uri", "payment-signature", "created",
                                                   "expires"]}]})

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

    def test_deltas_whatever_the_result_of_the_label(self):
        # SPEC 10.1 (b): the deltas are integers "whatever the label's result" (review of 2026-11-21, second round:
        # a mutant that gave null to the labels that failed was alive)
        ex = {"request": request(T0 - 4, T0 + 7)}
        ex["request"]["fields"][3][1] = "sig1=:%s:" % base64.b64encode(bytes(64)).decode()
        other = {"apc_http_keys": 1, "keys": {"zz": KEYS["keys"]["k"]}}
        for keys, want in ((KEYS, "failed:signature_invalid"), (other, "failed:unknown_keyid")):
            _, _, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(keys), T0)
            sg = m["signatures"][0]
            self.assertEqual((sg["result"], sg["block_time_minus_created"], sg["expires_minus_block_time"]),
                             (want, 4, 7))
        sg = self.one("request", T0 + 9, T0 + 2, T0, 0)["signatures"][0]
        self.assertEqual((sg["result"], sg["block_time_minus_created"], sg["expires_minus_block_time"]),
                         ("failed:expires_before_created", -9, 2))

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
        self.assertEqual(self.cli("@B", "--http-clock-skew", "0")[0], 64)                  # (the default too)
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
                    ((t - 70, t - 10), ("chain_verified", "verified")),
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
            self.assertTrue(any("the bundle proves none" in n for n in r["notes"]), doc["bundle_version"])

    def test_the_block_time_still_reaches_offers_and_receipts(self):
        # review of 2026-11-21, mutant p03: apc_permit2 computes the block time before X7 now; the offer and receipt
        # checks of section 13 (apc_offer, OR 4.6 and the receipt's issuedAt) must still receive it
        import apc_permit2
        import apc_verify
        from unittest import mock
        for doc, mod in zip(self.docs, (apc_verify, apc_permit2)):
            t = int(doc["inclusion"]["block_header"]["timestamp"], 16)
            seen = []
            real = mod.offer_receipt_checks

            def spy(d, ctx, trust, real=real):
                seen.append(ctx["block_time"])
                return real(d, ctx, trust)
            with mock.patch.object(mod, "offer_receipt_checks", spy):
                av.verify_bundle(self.with_exchange(t - 5, t + 60, doc), None, KEYS)
            self.assertEqual(seen, [t], doc["bundle_version"])

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


class TextOf101(unittest.TestCase):
    """the branches SPEC 10.1 names in words: each sentence has its case (review of 2026-11-21)"""

    def one(self, ex, t):
        res, notes, m = h.check({"payment_payload": {}, "exchange": ex}, h.parse_keys(KEYS), t)
        return res["X7"], [s["result"] for s in m["signatures"]], notes

    def test_a_label_not_judged_with_an_empty_window_fails(self):
        # (a): "whether its signature verifies or the label is not judged (a component that is not supported)"
        p = '("content-type";sf);created=%d;expires=%d;keyid="k"' % (T0 + 5, T0 + 4)
        ex = {"request": request(sign=False)}
        ex["request"]["fields"] += [["Signature-Input", "sig1=" + p], ["Signature", "sig1=:AAAA:"]]
        for t in (None, T0):
            self.assertEqual(self.one(ex, t)[:2], ("failed:expires_before_created", ["failed:expires_before_created"]))

    def test_a_label_that_already_failed_keeps_its_reason_with_an_empty_window(self):
        # (a): "A label that already failed keeps its own reason"
        ex = {"request": request(T0 + 5, T0 + 4)}
        ex["request"]["fields"][1][1] = base64.b64encode(b'{"x402Version":1}').decode()     # covered field changed
        self.assertEqual(self.one(ex, T0)[1], ["failed:signature_invalid"])
        ex = {"request": request(T0 + 5, T0 + 4)}
        ex["request"]["fields"][2][1] = ex["request"]["fields"][2][1].replace('keyid="k"', 'keyid="zz"')
        self.assertEqual(self.one(ex, T0)[1], ["failed:unknown_keyid"])

    def test_the_order_of_the_exchange(self):
        # D-B (2026-11-21): a request that expired before the block may have been verified in time: verified
        self.assertEqual(self.one({"request": request(T0 - 70, T0 - 10)}, T0)[1], ["verified"])
        # a response signed before T, or before the created of the request it answers, is out of order
        ex = {"request": request(T0 - 5, T0 + 60), "response": response(T0 - 10 ** 6, T0 + 60)}
        self.assertEqual(self.one(ex, T0)[:2], ("not_evaluated:created_before_block_time",
                                                 ["verified", "not_evaluated:created_before_block_time"]))
        ex = {"request": request(T0 - 5, None), "response": response(0, None)}
        self.assertEqual(self.one(ex, None)[:2], ("not_evaluated:created_before_request",
                                                   ["verified", "not_evaluated:created_before_request"]))

    def test_a_response_follows_the_latest_request_signature(self):
        # two request labels, created T-50 and T-10; a response created T-20 precedes the latest: out of order
        r1, r2 = request(T0 - 50, None), request(T0 - 10, None)
        f = [x for x in r1["fields"] if x[0] not in ("Signature-Input", "Signature")]
        for name in ("Signature-Input", "Signature"):
            f.append([name, ", ".join(x[1].replace("sig1=", "s%d=" % i, 1) for i, r in enumerate((r1, r2))
                                      for x in r["fields"] if x[0] == name)])
        ex = {"request": dict(r1, fields=f), "response": response(T0 - 20, None)}
        self.assertEqual(self.one(ex, None)[1], ["verified", "verified", "not_evaluated:created_before_request"])
        ex["response"] = response(T0 - 10, None)
        self.assertEqual(self.one(ex, None)[1], ["verified", "verified", "verified"])

    def test_x7_is_the_first_failed_then_the_first_not_evaluated_of_several_labels(self):
        a, b, c = request(T0 - 5, T0 + 60), request(T0 + 1, None), request(T0, T0 - 1)

        def merged(*rs):
            f = [x for x in rs[0]["fields"] if x[0] not in ("Signature-Input", "Signature")]
            for name in ("Signature-Input", "Signature"):
                f.append([name, ", ".join(x[1].replace("sig1=", "s%d=" % i, 1) for i, r in enumerate(rs)
                                          for x in r["fields"] if x[0] == name)])
            return {"request": dict(rs[0], fields=f)}
        self.assertEqual(self.one(merged(a, b), T0)[:2],
                         ("not_evaluated:created_after_block_time",
                          ["verified", "not_evaluated:created_after_block_time"]))
        self.assertEqual(self.one(merged(b, a), T0)[0], "not_evaluated:created_after_block_time")
        self.assertEqual(self.one(merged(b, c), T0)[:2],
                         ("failed:expires_before_created",
                          ["not_evaluated:created_after_block_time", "failed:expires_before_created"]))

    def test_integers_at_the_edge_of_the_grammar(self):
        # RFC 9651 3.3.1: an Integer has at most 15 digits; a negative one is an Integer
        self.assertEqual(self.one({"request": request(999999999999999, None)}, T0)[1],
                         ["not_evaluated:created_after_block_time"])
        self.assertEqual(self.one({"request": request(-5, -1)}, T0)[1], ["verified"])
        self.assertEqual(self.one({"request": request(-999999999999999, 999999999999999)}, T0)[1], ["verified"])
        for bad in ("created=1000000000000000", "created=%d.0" % T0, 'created="%d"' % T0, "created"):
            ex = {"request": request(T0, None)}
            si = ex["request"]["fields"][2]
            si[1] = si[1].replace("created=%d" % T0, bad)
            self.assertEqual(self.one(ex, T0)[0], "failed:signature_input_malformed", bad)


class RequiredAtTheCli(unittest.TestCase):
    """--require-http-signature and --require-level together, twice in one process, and on a report without checks"""

    def run_main(self, doc, *opts):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            b, k = os.path.join(tmp, "b.json"), os.path.join(tmp, "k.json")
            with open(b, "w") as fh:
                json.dump(doc, fh)
            with open(k, "w") as fh:
                json.dump(KEYS, fh)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = av.main(["apc_verify.py", b] + [o.replace("@K", k) for o in opts])
        return rc, (json.loads(buf.getvalue()) if buf.getvalue().startswith("{") else None)

    def test_after_require_level_and_each_says_its_own_met(self):
        rc, r = self.run_main(md_bundle(), "--http-keys", "@K", "--require-http-signature", "--require-level",
                              "finality_proven")
        self.assertEqual((rc, r["verdict"]), (2, "chain_incomplete"))
        self.assertEqual(r["evidence_required"]["met"], False)
        self.assertEqual(r["http_signature_required"]["met"], False)
        # the level is applied first: its note is there, and the signature requirement, finding the verdict already
        # chain_incomplete, adds none
        self.assertEqual(len([n for n in r["notes"] if "--require-level" in n]), 1)
        self.assertEqual(len([n for n in r["notes"] if "--require-http-signature" in n]), 0)

    def test_the_note_is_added_to_the_notes_the_report_already_has(self):
        rc0, r0 = self.run_main(md_bundle(), "--http-keys", "@K")
        rc, r = self.run_main(md_bundle(), "--http-keys", "@K", "--require-http-signature")
        self.assertTrue(r0["notes"])                             # (the report has notes of its own: 10.1 c)
        self.assertEqual(r["notes"][:-1], r0["notes"])
        self.assertEqual(r["notes"][-1], "X7 is not_evaluated:absent:no_exchange and `missing` has 1 entry(ies) under "
                         "apc-http-coverage/1; a verified HTTP signature with that coverage is required "
                         "(--require-http-signature, SPEC 10.1 d): verdict chain_incomplete")

    def test_the_option_does_not_stay_for_the_next_call(self):
        self.assertEqual(self.run_main(md_bundle(), "--http-keys", "@K", "--require-http-signature")[0], 2)
        rc, r = self.run_main(md_bundle(), "--http-keys", "@K")
        self.assertEqual((rc, r["verdict"]), (0, "chain_verified"))
        self.assertNotIn("http_signature_required", r)

    def test_a_report_without_checks_carries_no_member(self):
        for doc in (dict(md_bundle(), zzz=1), dict(md_bundle(), bundle_version="apc-9.9")):
            rc, r = self.run_main(doc, "--http-keys", "@K", "--require-http-signature")
            self.assertEqual((rc, r["verdict"]), (3, "refused"))
            self.assertNotIn("http_signature_required", r)
            self.assertNotIn("checks", r)

    def test_usage(self):
        for opts in (["--http-keys", "@K", "--require-http-signature=1"],
                     ["--http-keys", "@K", "--require-http-signatur"], ["--http-keys", "", "--require-http-signature"]):
            self.assertEqual(self.run_main(md_bundle(), *opts), (64, None), opts)
        rc, r = self.run_main(md_bundle(), "--http-keys", "@K", "--require-http-signature", "--require-http-signature")
        self.assertEqual((rc, r["http_signature_required"]["met"]), (2, False))


class RequiredAndCoverage(unittest.TestCase):
    """SPEC 10.1 (d), apc-http-coverage/1: one signature over () verifies on every real bundle it is copied into, and is
    not met (review of 2026-11-21, R12)"""
    setUpClass = classmethod(RealBlockTime.setUpClass.__func__)
    with_exchange = RealBlockTime.with_exchange

    def test_an_empty_covered_list_verifies_and_is_not_met(self):
        p = '();keyid="k"'
        pair = [["Signature-Input", "sig1=" + p],
                ["Signature", "sig1=:%s:" % base64.b64encode(
                    sol.ed25519_sign(ED_SEED, ('"@signature-params": ' + p).encode())).decode()]]
        for doc in self.docs:
            d = self.with_exchange(None, None, doc)
            d["exchange"]["request"]["fields"][2:] = copy.deepcopy(pair)
            r = av.require_http_signature(av.verify_bundle(d, None, KEYS))
            self.assertEqual((r["verdict"], r["checks"]["X7"], r["http_signature_required"]["met"]),
                             ("chain_incomplete", "verified", False), doc["bundle_version"])
            self.assertEqual(r["http_signature_required"]["missing"],
                             [{"where": "request", "label": "sig1", "missing": ["@authority|@target-uri",
                                                                               "payment-signature", "created",
                                                                               "expires"]}])
            self.assertEqual(r["exchange"]["signatures"][0]["covered"], [])


class BatchKeyUnreadable(unittest.TestCase):
    """apc_batch (independent hunt 2026-11-23): a bundle verify_bundle reads (chain_failed) whose authorization key
    _key cannot read ended the program with a traceback, exit 1, which its docstring gives to a D1, D3 or D4 failure
    (measured on 30b0ac0: a real XRPL bundle, bundles/xrp_real_20261026/132d26ccea52.json, whose signedTxBlob lost its
    head, KeyError 'Sequence'). It is listed under `refused` with the reason and kept out of D1-D4, as a refused one."""

    def test_unreadable_key_is_kept_out_with_its_reason(self):
        import apc_batch
        from unittest import mock
        real, docs = apc_batch._key, [("a", md_bundle()), ("b", md_bundle())]

        for exc in (KeyError, IndexError, TypeError, ValueError, AttributeError):
            def key(doc):
                if doc is docs[1][1]:
                    raise exc("Sequence" + "x" * 500)
                return real(doc)
            with mock.patch.object(apc_batch, "_key", key):
                rep = apc_batch.check_set(docs)
            self.assertEqual((rep["verdict"], rep["authorizations"], [r["bundle"] for r in rep["refused"]], rep["D2"]),
                             ("set_consistent", 1, ["b"], "none"), exc)
            self.assertIn("kept out of D1-D4: no authorization key can be read (%s" % exc.__name__,
                          rep["refused"][0]["reason"])
            self.assertLess(len(rep["refused"][0]["reason"]), 200)
        self.assertEqual(apc_batch.check_set([docs[0], ("a2", md_bundle())])["D2"][0]["check"], "duplicate_bundle")

    def test_a_refusal_of_the_bundle_or_of_its_key_is_listed(self):
        import apc_batch
        from unittest import mock
        rep = apc_batch.check_set([("u", {"unreadable": "OSError"})])            # what main() gives for a file not read
        self.assertEqual((rep["verdict"], rep["authorizations"], [r["bundle"] for r in rep["refused"]]),
                         ("set_consistent", 0, ["u"]))
        with mock.patch.object(apc_batch, "_key", side_effect=apc_batch.av.Refusal("no key")):
            rep = apc_batch.check_set([("a", md_bundle())])
        self.assertEqual((rep["authorizations"], rep["refused"]), (0, [{"bundle": "a", "reason": "no key"}]))


if __name__ == "__main__":
    unittest.main()
