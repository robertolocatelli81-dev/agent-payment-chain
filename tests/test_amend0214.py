"""SPEC 32.14 (Amendment 0.21.5): a member of the x402 PaymentRequired (v2 and v1) that the specification does not
define is ignored and reported in `notes`, not refused; every member it defines keeps its rules, and the objects inside
(ResourceInfo, each accepts entry) stay closed. One rule in the seven readers (apc_verify.payment_required_obj).
Run from the root: python3 -m unittest tests.test_amend0214"""
import ast
import copy
import glob
import json
import os
import random
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_verify as av  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures_mandate", "base.json")       # synthetic, distributed with the public tree
V1_SRC = os.path.join(ROOT, "sources", "x402_schemes_20261026", "x402-specification-v1.md")
V2 = (("x402Version", "resource", "accepts"), ("error", "extensions"))
V1 = (("x402Version", "error", "accepts"), ())
MARK = "(SPEC 32.14)"


def obj(v, which=V2):
    return av.payment_required_obj(v, "payment_required", *which)


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Unsupported as e:
        return {"verdict": "unsupported", "reason": str(e)}
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e)}


def without_32_14(r):
    r = dict(r)
    r["notes"] = [n for n in r.get("notes", []) if MARK not in n]
    return r


def base_doc():
    with open(FIX) as fh:
        d = av.strict_json(fh.read())
    url = (d["payment_payload"].get("resource") or {}).get("url", "https://example.com/r")
    d["payment_required"] = {"x402Version": 2, "resource": {"url": url}, "accepts": [d["payment_payload"]["accepted"]]}
    return d


class TheRule(unittest.TestCase):
    def test_defined_members_only_no_note(self):
        pr = {"x402Version": 2, "resource": {}, "accepts": [], "error": "e", "extensions": {}}
        self.assertEqual(obj(pr), (pr, []))

    def test_an_undefined_member_is_dropped_and_named(self):
        pr, notes = obj({"x402Version": 2, "resource": {}, "accepts": [], "payment_diagnostics": {"a": 1}})
        self.assertEqual(sorted(pr), ["accepts", "resource", "x402Version"])
        self.assertEqual(notes, ["payment_required: member(s) the x402 specification does not define, ignored and not read "
                                 "(SPEC 32.14): ['payment_diagnostics']"])

    def test_case_variants_and_v1_names_in_v2_are_undefined(self):
        pr, notes = obj({"x402Version": 2, "resource": {}, "accepts": [], "Accepts": 1, "maxAmountRequired": "1"})
        self.assertNotIn("Accepts", pr)
        self.assertIn("['Accepts', 'maxAmountRequired']", notes[0])
        pr, notes = obj({"x402Version": 1, "error": "", "accepts": [], "resource": {}, "extensions": {}}, V1)
        self.assertEqual(sorted(pr), ["accepts", "error", "x402Version"])   # v1 defines neither resource nor extensions
        self.assertIn("['extensions', 'resource']", notes[0])

    def test_names_are_bounded_in_the_report(self):
        extra = {("k%02d" % i) + "x" * 100: i for i in range(20)}
        _, notes = obj(dict({"x402Version": 2, "resource": {}, "accepts": []}, **extra))
        names = re.search(r"\[(.*)\]", notes[0]).group(1).split(", ")
        self.assertEqual(len(names), 16)
        self.assertTrue(all(len(n) == 64 + 3 + 2 for n in names), names[:2])   # 64 characters, "...", the quotes
        self.assertTrue(notes[0].endswith(" and 4 more"))

    def test_the_defined_members_keep_their_rules(self):
        for bad, why in (([], "not an object"), ({"x402Version": 2, "resource": {}}, "missing member(s) ['accepts']"),
                         ({"x402Version": 2, "accepts": [], "x": 1}, "missing member(s) ['resource']")):
            with self.assertRaises(av.Refusal) as cm:
                obj(bad)
            self.assertIn(why, str(cm.exception))


class EveryReaderUsesTheRule(unittest.TestCase):
    PLACES = {"apc_verify.py": 1, "apc_svm.py": 1, "apc_xlm.py": 1, "apc_xrp.py": 1, "apc_authcap.py": 1,
              "apc_permit2.py": 1, "apc_v1.py": 1}

    def test_each_payment_required_goes_to_the_rule(self):
        got, other = {}, []
        for f in sorted(glob.glob(os.path.join(ROOT, "apc_*.py"))):
            with open(f) as fh:
                tree = ast.parse(fh.read())
            for n in ast.walk(tree):
                if not isinstance(n, ast.Call) or not n.args:
                    continue
                a = n.args[0]
                if isinstance(a, ast.Subscript) and isinstance(a.slice, ast.Constant) and a.slice.value == "payment_required":
                    name = getattr(n.func, "id", getattr(n.func, "attr", None))
                    if name == "payment_required_obj":
                        got[os.path.basename(f)] = got.get(os.path.basename(f), 0) + 1
                    elif name in ("_obj", "isinstance"):
                        other.append((os.path.basename(f), n.lineno, ast.unparse(n)[:80]))
        self.assertEqual([o for o in other if o[2].startswith("_obj")], [])
        self.assertEqual(got, self.PLACES)

    def test_each_call_names_the_members_of_its_version(self):
        # Independent review 2026-11-03: a reader that left `error` or `extensions` out of the defined members would ignore it,
        # unchecked, with only a note; the members are those of the specification's table, per version
        want = {"apc_v1.py": (["x402Version", "error", "accepts"], [])}
        got = {}
        for f in sorted(glob.glob(os.path.join(ROOT, "apc_*.py"))):
            with open(f) as fh:
                tree = ast.parse(fh.read())
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) == "payment_required_obj":
                    args = [ast.literal_eval(a) for a in n.args[2:]]
                    got.setdefault(os.path.basename(f), []).append((list(args[0]), list(args[1]) if len(args) > 1 else []))
        self.assertEqual(sorted(got), sorted(self.PLACES))
        for f, calls in got.items():
            self.assertEqual(calls, [want.get(f, (["x402Version", "resource", "accepts"], ["error", "extensions"]))], f)


class BundleLevel(unittest.TestCase):
    # the shape of the 402 of agent-payment-chain issue #1 (comment of 2026-11-03), synthetic values
    DIAG = {"failed_stage": "request_validation", "elapsed_ms": {"payment_total": 0}, "clock": "worker_wall_clock",
            "settlement_confirmed": False}

    def test_the_402_with_a_diagnostics_member_is_read_k4_decided_and_reported(self):
        d = base_doc(); r0 = run(d)
        d["payment_required"].update(error="invalid_payment_requirements", payment_diagnostics=self.DIAG)
        r1 = run(d)
        self.assertEqual(r1["checks"]["K4"], "verified")
        self.assertEqual(sum(MARK in n and "['payment_diagnostics']" in n for n in r1["notes"]), 1)
        self.assertEqual(without_32_14(r1), r0)                       # nothing else of the report changes

    def test_the_objects_inside_stay_closed(self):
        d = base_doc(); d["payment_required"]["resource"]["logo"] = "x"
        self.assertIn("payment_required.resource: unknown member(s) ['logo']", run(d)["reason"])
        d = base_doc(); d["payment_required"]["error"] = 5
        self.assertEqual(run(d)["reason"], "payment_required.error: not a string")
        d = base_doc(); d["payment_required"]["extensions"] = []
        self.assertEqual(run(d)["reason"], "payment_required.extensions: not an object")

    def test_generated_members_never_change_the_report(self):
        rnd = random.Random(20261103)
        d0 = base_doc(); r0 = run(d0)
        values = [None, True, 0, -1, 2 ** 53, 1.5, "", "x" * 300, [], [1, [2]], {}, {"a": {"b": None}}]
        names = ["payment_diagnostics", "Accepts", "ERROR", "x402version", "__proto__", "constructor", "", " ", "é",
                 "\u0000", "resource ", "maxAmountRequired", "a" * 200]
        n = 0
        for _ in range(400):
            d = copy.deepcopy(d0)
            extra = {rnd.choice(names) + ("" if rnd.random() < .7 else str(rnd.randrange(99))): rnd.choice(values)
                     for _ in range(rnd.randint(1, 20))}
            d["payment_required"].update(extra)
            r = run(d)
            self.assertEqual(without_32_14(r), r0, sorted(extra)[:3])
            self.assertEqual(sum(MARK in x for x in r["notes"]), 1)
            n += 1
        self.assertEqual(n, 400)


class VersionOne(unittest.TestCase):
    def test_v1_payment_required_follows_the_same_rule(self):
        if not os.path.exists(V1_SRC):
            self.skipTest("sources/x402_schemes_20261026 not present")
        with open(V1_SRC) as fh:
            req, pay, sett = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", fh.read(), re.S)[:3]]
        d = {"bundle_version": "apc-0.13", "payment_payload": pay, "payment_required": req, "settlement": sett}
        r0 = run(d)
        self.assertNotEqual(r0["verdict"], "refused", r0)
        d2 = copy.deepcopy(d); d2["payment_required"]["payment_diagnostics"] = {"x": 1}
        r1 = run(d2)
        self.assertEqual(without_32_14(r1), r0)
        self.assertEqual(sum(MARK in n and "['payment_diagnostics']" in n for n in r1["notes"]), 1)
        for bad in ("absent", 5):        # v1: `error` is required and a string, beside an ignored member too
            d3 = copy.deepcopy(d2)
            if bad == "absent":
                del d3["payment_required"]["error"]
            else:
                d3["payment_required"]["error"] = bad
            r3 = run(d3)
            self.assertEqual(r3["verdict"], "refused", (bad, r3.get("verdict")))
            self.assertIn("error", r3["reason"])

    def test_bounds_of_the_report_at_the_edges(self):
        # Independent review 2026-11-03: a name of exactly 64 characters is shown whole, one of 65 cut; 16 names, no "more"
        _, notes = obj({"x402Version": 2, "resource": {}, "accepts": [], "a" * 64: 1, "b" * 65: 2})
        self.assertIn("'%s'" % ("a" * 64), notes[0])
        self.assertIn("'%s...'" % ("b" * 64), notes[0])
        _, notes = obj(dict({"x402Version": 2, "resource": {}, "accepts": []}, **{"k%02d" % i: i for i in range(16)}))
        self.assertTrue(notes[0].endswith("'k15']"), notes[0][-40:])


class RealCorpus(unittest.TestCase):
    def test_each_reader_on_the_real_corpus(self):
        from tests import real_corpus
        sets = ["real", "real_svm", "xlm_real_20261026", "xrp_real_20261026", "real_permit2", "authcap_real_20261026"]
        real_corpus.need(*sets)
        for s in sets:
            got = None
            for p in sorted(glob.glob(os.path.join(ROOT, "bundles", s, "*.json"))):
                with open(p) as fh:
                    d = av.strict_json(fh.read())
                if isinstance(d, dict) and "payment_payload" in d and run(d)["verdict"] != "refused":
                    got = d
                    break
            self.assertIsNotNone(got, s)
            d = copy.deepcopy(got); d.pop("payment_required", None)
            d["payment_required"] = {"x402Version": 2, "resource": {"url": "https://example.com/r"},
                                     "accepts": [d["payment_payload"]["accepted"]]}
            r0 = run(d)
            self.assertNotEqual(r0["verdict"], "refused", (s, r0))
            d["payment_required"]["payment_diagnostics"] = {"settlement_confirmed": False}
            r1 = run(d)
            self.assertEqual(without_32_14(r1), r0, s)
            self.assertEqual(sum(MARK in n for n in r1["notes"]), 1, s)
            if s == "xrp_real_20261026":
                # the note joins the notes made before K4, it does not replace them (independent review 2026-11-03, mutant N13)
                import apc_xrp
                from unittest import mock
                orig = apc_xrp.rules
                def rules(*a):
                    r = orig(*a)
                    return (r[0], r[1] + ["sentinel before K4"]) + tuple(r[2:])
                with mock.patch.object(apc_xrp, "rules", rules):
                    self.assertIn("sentinel before K4", run(d)["notes"])
            # beside an ignored member, the defined members keep their rules in this reader (independent review 2026-11-03)
            for m, bad in (("error", 5), ("extensions", [])):
                e = copy.deepcopy(d)
                e["payment_required"][m] = bad
                r2 = run(e)
                self.assertEqual(r2["verdict"], "refused", (s, m, r2.get("verdict")))
                self.assertIn("payment_required.%s" % m if m == "error" else "extensions", r2["reason"], s)


if __name__ == "__main__":
    unittest.main()
