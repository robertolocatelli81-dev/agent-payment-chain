"""SPEC 32.13 (Amendment 0.21.4): the x402 ResourceInfo as x402-specification-v2 at 0aee759 writes it, one rule in every
reader (apc_verify.resource_info; apc_ap2._resource the same rule in its own schema errors). Run from the root:
python3 -m unittest tests.test_amend0213"""
import ast
import copy
import glob
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_ap2  # noqa: E402
import apc_verify as av  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures_mandate", "base.json")       # synthetic, distributed with the public tree


def verify_says(r):
    try:
        av.resource_info(r, "r")
        return True
    except av.Refusal:
        return False


def ap2_says(r):
    try:
        apc_ap2._resource(r, "r")
        return True
    except apc_ap2.SchemaError:
        return False


# (resource, accepted?) — the expected value is read off the specification's table, not off either implementation;
# where the table is silent (null, the empty string, an empty host) it is our reading, SPEC 32.13
U = {"url": "https://example.com/r"}
TABLE = [
    (dict(U), True),
    (dict(U, description="", mimeType=""), True),
    (dict(U, description=None), False), (dict(U, mimeType=None), False), (dict(U, description=5), False),
    (dict(U, mimeType=["a"]), False),
    (dict(U, serviceName=""), False), (dict(U, serviceName="x" * 32), True), (dict(U, serviceName="x" * 33), False),
    (dict(U, serviceName=" ~"), True), (dict(U, serviceName="\x1f"), False), (dict(U, serviceName="\x7f"), False),
    (dict(U, serviceName="café"), False), (dict(U, serviceName="a\n"), False), (dict(U, serviceName=None), False),
    (dict(U, serviceName=3), False),
    (dict(U, tags=[]), True), (dict(U, tags=["a"] * 5), True), (dict(U, tags=["a"] * 6), False),
    (dict(U, tags=["x" * 32]), True), (dict(U, tags=["x" * 33]), False), (dict(U, tags=[""]), False),
    (dict(U, tags=[1]), False), (dict(U, tags=[None]), False), (dict(U, tags="agents"), False),
    (dict(U, tags={"a": 1}), False), (dict(U, tags=None), False), (dict(U, tags=["é"]), False),
    (dict(U, iconUrl="https://a"), True), (dict(U, iconUrl="http://a/b?c#d"), True), (dict(U, iconUrl="HTTPS://A"), True),
    (dict(U, iconUrl="https://" + "a" * 2040), True), (dict(U, iconUrl="https://" + "a" * 2041), False),
    (dict(U, iconUrl="http://" + "a" * 2041), True), (dict(U, iconUrl="http://" + "a" * 2042), False),
    (dict(U, iconUrl=""), False), (dict(U, iconUrl="https://"), False), (dict(U, iconUrl="https:///x"), False),
    (dict(U, iconUrl="https://?x"), False), (dict(U, iconUrl="https://#x"), False), (dict(U, iconUrl="ftp://a"), False),
    (dict(U, iconUrl="/favicon.png"), False), (dict(U, iconUrl="https://a b"), False), (dict(U, iconUrl="https://a\n"), False),
    (dict(U, iconUrl="https://é"), False), (dict(U, iconUrl=None), False), (dict(U, iconUrl=7), False),
    (dict(U, iconUrl="data:image/png;base64,AA"), False), (dict(U, iconUrl="https:/a"), False),
    # Independent review 03/11: U+017F (long s) and U+212A (Kelvin) fold to ASCII under re.IGNORECASE; an empty host (RFC 9110 4.2.1)
    (dict(U, iconUrl="http\u017f://a"), False), (dict(U, iconUrl="HTTP\u017f://a"), False), (dict(U, iconUrl="https://@"), False),
    (dict(U, iconUrl="http://@/x"), False), (dict(U, iconUrl="https://:80/x"), False), (dict(U, iconUrl="http://u@/x"), False),
    (dict(U, iconUrl="https://u:p@:1/x"), False), (dict(U, iconUrl="https://u:p@h/x"), True), (dict(U, iconUrl="http://[::1]/i"), True),
    (dict(U, tags=["a", 1]), False), (dict(U, tags=["a", "x" * 33]), False), (dict(U, tags=["a", "b", "c", "d", "\x7f"]), False),
    (dict(U, iconUrl="https://a/\x7f"), False), (dict(U, iconUrl="https://a/!"), True),
    (dict(U, iconUrl="https://a#f"), True), (dict(U, iconUrl="https://a?q"), True), (dict(U, iconUrl="https://a/b c"), False),
    (dict(U, iconUrl="hTtPs://a"), True), (dict(U, iconUrl="https://a@b@c"), False), (dict(U, iconUrl="https://@h"), True),
    (dict(U, serviceName="s", tags=["t"], iconUrl="https://a/i.png", description="d", mimeType="m"), True),
    ({}, False), ({"url": ""}, False), ({"url": None}, False), ({"url": 1}, False),
    (dict(U, extra=1), False), (dict(U, method="GET"), False), (dict(U, ServiceName="s"), False), ("https://a", False),
    (None, False), ([], False),
]


class ResourceInfoTable(unittest.TestCase):
    def test_the_table_of_the_specification(self):
        for r, want in TABLE:
            self.assertEqual(verify_says(r), want, ("apc_verify", r))
            self.assertEqual(ap2_says(r), want, ("apc_ap2", r))

    def test_profile_member_only_where_the_profile_adds_it(self):
        av.resource_info(dict(U, method="GET"), "r", ("method",))           # apc_authcap's `method`
        with self.assertRaises(av.Refusal):
            av.resource_info(dict(U, method="GET"), "r")

    def test_generated_inputs_the_two_readers_agree(self):
        # every member of the grammar and unknown ones, values of every JSON type and of the borders, in random sets
        rng = random.Random(20261103)
        strs = ["", "a", "x" * 32, "x" * 33, " ", "~", "\x1f", "\x7f", "é", "a\n", "\t", "https://a", "http://a",
                "HTTPS://a", "https://", "https:///", "ftp://a", "https://a b", "https://" + "a" * 2040,
                "https://" + "a" * 2041, "//a", "https://a/é", "http\u017f://a", "https://@", "https://:1", "http://u@h"]
        vals = strs + [None, True, False, 0, 1, -1, 1.5, [], {}, ["a"], ["a"] * 6, [""] * 5, [None], [1], [["a"]],
                       {"a": "b"}]
        members = ["url", "description", "mimeType", "serviceName", "tags", "iconUrl", "method", "extra", "Url", ""]
        n_ok = n_refused = 0
        for _ in range(20000):
            r = {}
            if rng.random() < 0.95:
                r["url"] = rng.choice(["https://example.com/r", "u"] + vals)
            for m in rng.sample(members[1:], rng.randint(0, 4)):
                r[m] = rng.choice(vals)
            a, b = verify_says(r), ap2_says(r)
            self.assertEqual(a, b, r)
            n_ok += a
            n_refused += not a
        self.assertGreater(n_ok, 500)                              # both outcomes are exercised, not one alone
        self.assertGreater(n_refused, 500)

    def test_a_valid_resource_stays_valid_under_any_order_and_copy(self):
        r = dict(U, serviceName="s", tags=["a", "b"], iconUrl="https://a/i.png", description="d", mimeType="m")
        for _ in range(20):
            keys = list(r)
            random.Random(len(keys)).shuffle(keys)
            self.assertTrue(verify_says({k: copy.deepcopy(r[k]) for k in keys}))


class EveryReaderUsesTheRule(unittest.TestCase):
    def test_no_reader_of_a_resource_left_with_its_own_list(self):
        # a call of _obj or _strict whose path argument names `.resource` is a ResourceInfo read outside the one rule
        found = []
        for f in sorted(glob.glob(os.path.join(ROOT, "apc_*.py"))):
            with open(f) as fh:
                tree = ast.parse(fh.read())
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and getattr(n.func, "id", None) in ("_obj", "_strict") and len(n.args) >= 2:
                    seg = ast.unparse(n.args[1])
                    if "resource" in seg and "resources" not in seg:
                        found.append((os.path.basename(f), n.lineno, seg))
        allowed = {("apc_verify.py", "path"), ("apc_ap2.py", "path")}            # the two rule functions themselves
        self.assertEqual([x for x in found if (x[0], x[2]) not in allowed], [])
        users = set()
        for f in glob.glob(os.path.join(ROOT, "apc_*.py")):
            with open(f) as fh:
                if "resource_info(" in fh.read():
                    users.add(os.path.basename(f))
        self.assertEqual(users, {"apc_verify.py", "apc_svm.py", "apc_xlm.py", "apc_xrp.py", "apc_authcap.py",
                                 "apc_permit2.py"})


class EveryPlaceAppliesTheRule(unittest.TestCase):
    """Independent review 03/11: the file naming resource_info is not the place calling it. Each `X["resource"]` passed to a call
    goes to resource_info, two places per reader; and on the real corpus each reader refuses a member out of rule."""

    PLACES = {"apc_verify.py": 2, "apc_svm.py": 2, "apc_xlm.py": 2, "apc_xrp.py": 2, "apc_authcap.py": 2, "apc_permit2.py": 2}

    def test_each_resource_argument_goes_to_the_rule(self):
        got, other = {}, []
        for f in sorted(glob.glob(os.path.join(ROOT, "apc_*.py"))):
            with open(f) as fh:
                tree = ast.parse(fh.read())
            for n in ast.walk(tree):
                if not isinstance(n, ast.Call):
                    continue
                for a in n.args:
                    if isinstance(a, ast.Subscript) and isinstance(a.slice, ast.Constant) and a.slice.value == "resource":
                        name = getattr(n.func, "id", getattr(n.func, "attr", None))
                        if name == "resource_info":
                            got[os.path.basename(f)] = got.get(os.path.basename(f), 0) + 1
                        elif not (os.path.basename(f) == "apc_ap2.py" and name == "_resource"):
                            other.append((os.path.basename(f), n.lineno, ast.unparse(n)[:80]))
        self.assertEqual(other, [])
        self.assertEqual(got, self.PLACES)

    def test_each_reader_refuses_on_the_real_corpus(self):
        from tests import real_corpus
        sets = {"real": "eip155", "real_svm": "solana", "xlm_real_20261026": "stellar", "xrp_real_20261026": "xrpl",
                "real_permit2": "permit2", "authcap_real_20261026": "authcap"}
        real_corpus.need(*sets)
        bad = {"url": "https://example.com/r", "tags": ["a"] * 6}
        for s in sets:
            docs = []
            for p in sorted(glob.glob(os.path.join(ROOT, "bundles", s, "*.json"))):
                with open(p) as fh:
                    d = av.strict_json(fh.read())
                if isinstance(d, dict) and "payment_payload" in d and av.verify_bundle(copy.deepcopy(d))["verdict"] != "refused":
                    docs.append(d)
                    break
            self.assertEqual(len(docs), 1, s)
            for d in docs:
                acc = d["payment_payload"]["accepted"]
                for where in ("payment_payload", "payment_required"):
                    e = copy.deepcopy(d)
                    if where == "payment_payload":
                        e["payment_payload"]["resource"] = dict(bad, **({"method": "GET"} if "authcap" in s else {}))
                    else:
                        e.pop("payment_required", None)
                        e["payment_required"] = {"x402Version": 2, "resource": bad, "accepts": [acc]}
                    with self.assertRaises(av.Refusal, msg=(s, where)) as cm:
                        av.verify_bundle(e)
                    self.assertIn(where + ".resource.tags", str(cm.exception), (s, where))


class BundleLevel(unittest.TestCase):
    def doc(self, **resource):
        with open(FIX) as fh:
            d = av.strict_json(fh.read())
        url = (d["payment_payload"].get("resource") or {}).get("url", "https://example.com/r")
        d["payment_required"] = {"x402Version": 2, "resource": dict({"url": url}, **resource),
                                 "accepts": [d["payment_payload"]["accepted"]]}
        return d

    def test_a_402_with_the_three_members_is_read_and_k4_decided(self):
        # the shape of the 402 of agent-payment-chain issue #1 (a real server), with synthetic values
        d = self.doc(description="d", mimeType="application/json", serviceName="example.com",
                     tags=["agents", "time"], iconUrl="https://example.com/favicon-32x32.png")
        self.assertEqual(av.verify_bundle(d)["checks"]["K4"], "verified")

    def test_a_member_outside_the_rule_is_refused_with_its_path(self):
        for bad, where in ((dict(serviceName="x" * 33), "payment_required.resource.serviceName"),
                           (dict(tags=["a"] * 6), "payment_required.resource.tags"),
                           (dict(iconUrl="ftp://a"), "payment_required.resource.iconUrl"),
                           (dict(description=None), "payment_required.resource.description"),
                           (dict(logo="x"), "payment_required.resource: unknown member(s) ['logo']")):
            with self.assertRaises(av.Refusal) as cm:
                av.verify_bundle(self.doc(**bad))
            self.assertIn(where, str(cm.exception), bad)

    def test_the_payload_resource_follows_the_same_rule(self):
        with open(FIX) as fh:
            d = av.strict_json(fh.read())
        d["payment_payload"]["resource"] = {"url": "https://example.com/r", "serviceName": "s", "tags": ["a"],
                                            "iconUrl": "https://example.com/i.png"}
        av.verify_bundle(d)
        d["payment_payload"]["resource"]["iconUrl"] = "javascript:alert(1)"
        with self.assertRaises(av.Refusal):
            av.verify_bundle(d)


class Ap2X402Payload(unittest.TestCase):
    """apc_ap2 reads the resource of the x402 payload of a conformance case through _resource (the Pulse corpus that
    exercises it is not redistributed: a minimal case built here, valid as a whole, the resource changed alone)."""

    def case(self, resource):
        ref = "Hg-AV8lyTE-YZf5QE1axiBkrcaN-a1Jy7m6hQTP2bR8"                 # 43 base64url characters, a SHA-256
        a0 = "0x" + "11" * 20
        req = {"scheme": "exact", "network": "eip155:8453", "asset": a0, "amount": "1000", "payTo": a0,
               "maxTimeoutSeconds": 60, "extra": {"name": "USD Coin", "version": "2", "assetTransferMethod": "eip3009",
                                                  "ap2MandateReference": ref,
                                                  "ap2NonceDerivation": "base64url-decode-ap2-mandate-reference"}}
        return {"requirements": req,
                "payload": {"x402Version": 2, "resource": resource, "accepted": req,
                            "payload": {"signature": "0x" + "22" * 65,
                                        "authorization": {"from": a0, "to": a0, "value": "1000", "validAfter": "0",
                                                          "validBefore": "9", "nonce": "0x" + "33" * 32}}},
                "settlement": {"success": True, "payer": a0, "transaction": "0x" + "44" * 32, "network": "eip155:8453"}}

    def test_the_payload_resource_goes_through_the_rule(self):
        for r, want in TABLE:
            try:
                apc_ap2._x402(self.case(r), "x402")
                got = True
            except apc_ap2.SchemaError:
                got = False
            self.assertEqual(got, want, r)


class AuthcapResourceMethod(unittest.TestCase):
    """apc_authcap keeps the member `method` of payment_payload.resource it read since SPEC 0.15 (section 25)."""

    def test_method_kept_and_the_rule_applied(self):
        from tests import real_corpus
        real_corpus.need("authcap_real_20261026")
        import apc_authcap  # noqa: F401  (the module that reads it)
        p = sorted(glob.glob(os.path.join(ROOT, "bundles", "authcap_real_20261026", "*.json")))[0]
        with open(p) as fh:
            d = av.strict_json(fh.read())
        d["payment_payload"]["resource"] = {"url": "https://example.com/r", "method": "GET", "serviceName": "s"}
        av.verify_bundle(copy.deepcopy(d))
        d["payment_payload"]["resource"]["tags"] = ["a"] * 6
        with self.assertRaises(av.Refusal) as cm:
            av.verify_bundle(copy.deepcopy(d))
        self.assertIn("payment_payload.resource.tags", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
