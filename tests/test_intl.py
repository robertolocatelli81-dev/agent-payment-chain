"""Amendment 0.11.4: hosts and URLs outside ASCII (apc_intl.py; X2, P5, OR3, D4). Oracles: the sample strings of RFC
3492 section 7.1 ((E) Chinese, (I) Hebrew, (K) Japanese: Unicode label -> Punycode), urllib.parse.quote for the
%-escapes. Positive controls: apc_verify and apc_report 0.8.0 (5cbe7c7)."""
import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_intl as ai  # noqa: E402
import apc_report as rp  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
V002 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")
# RFC 3492 7.1: (E) simplified Chinese, (I) Hebrew, (K) Japanese, lower-case Unicode labels (no case for Nameprep)
RFC3492 = [("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"),
           ("למההםפשוטלאמדברים"
            "עברית", "4dbcagdahymbxekheh6e0a7fei0b"),
           ("なぜみんな日本語を話してくれないの"
            "か", "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa")]
JP = RFC3492[2]


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


class Hosts(unittest.TestCase):
    def test_rfc3492_samples(self):
        for u, a in RFC3492:
            self.assertEqual(ai.host_ascii(u + ".example"), "xn--" + a + ".example")
            self.assertEqual(ai.host_ascii("xn--" + a + ".example"), "xn--" + a + ".example")
            self.assertEqual(ai.host_ascii("XN--" + a.upper() + ".Example"), "xn--" + a + ".example")

    def test_not_comparable(self):
        for h, why in (("straße.de", "idna_deviation_character"), ("a‍b.example", "idna_deviation_character"),
                       ("σοφις.gr", "idna_deviation_character"),
                       ("xn--abc-.example", "label_not_ldh"), ("a..b", "empty_label"), ("", "host_empty_or_too_long"),
                       ("bad_host.example", "label_not_ldh"), ("xn--zz.example", "a_label_not_canonical"),
                       ("a" * 64 + ".example", "label_not_ldh")):
            with self.assertRaises(ai.NotComparable) as cm:
                ai.host_ascii(h)
            self.assertEqual(str(cm.exception), why, h)

    def test_iri_to_uri(self):
        path, q = "/データ", "q=円&x=1"
        iri = "https://%s.example%s?%s" % (JP[0], path, q)
        want = "https://xn--%s.example%s?%s" % (JP[1], quote(path, safe="/"), quote(q, safe="=&"))
        self.assertEqual(ai.iri_to_uri(iri), want)
        self.assertEqual(ai.iri_to_uri("https://api.example.com/a%20b?c"), "https://api.example.com/a%20b?c")
        for bad in ("ftp://x.example/", "https://user@x.example/", "https:///nohost"):
            with self.assertRaises(ai.NotComparable):
                ai.iri_to_uri(bad)
        self.assertEqual(ai.origin("HTTPS://%s.Example:8443/p" % JP[0]), "https://xn--%s.example:8443" % JP[1])


def exchange_bundle(iri, target):
    d = load(V002)
    d["payment_payload"]["resource"] = {"url": iri}
    sig = base64.b64encode(json.dumps(d["payment_payload"], ensure_ascii=False).encode()).decode()
    d["exchange"] = {"request": {"method": "GET", "target_uri": target,
                                 "fields": [["Host", target.split("/")[2]], ["PAYMENT-SIGNATURE", sig]]}}
    return d


class Uses(unittest.TestCase):
    IRI = "https://%s.example/データ?q=円" % JP[0]
    URI = "https://xn--%s.example/%%E3%%83%%87%%E3%%83%%BC%%E3%%82%%BF?q=%%E5%%86%%86" % JP[1]

    def test_x2_iri(self):
        r = av.verify_bundle(exchange_bundle(self.IRI, self.URI))
        self.assertEqual(r["checks"]["X2"], "verified")
        self.assertTrue(any("RFC 3987" in n for n in r["notes"]))
        r = av.verify_bundle(exchange_bundle(self.IRI, self.URI.replace("q=%E5", "q=%E6")))
        self.assertEqual(r["checks"]["X2"], "failed:request_not_for_the_resource")
        r = av.verify_bundle(exchange_bundle("https://straße.example/x", "https://strasse.example/x"))
        self.assertEqual(r["checks"]["X2"], "failed:request_not_for_the_resource")

    def test_p5_idn(self):
        d = load(V002)
        d["payment_payload"]["resource"] = {"url": self.URI}
        rep = av.verify_bundle(copy.deepcopy(d))
        out = rp.apply_policy(rp.parse_policy({"apc_policy": 1, "hosts": [JP[0] + ".example"]}), d, rep)
        self.assertEqual(out["policy"]["P5"], "verified")
        d["payment_payload"]["resource"] = {"url": self.IRI}
        out = rp.apply_policy(rp.parse_policy({"apc_policy": 1, "hosts": ["xn--%s.example" % JP[1]]}), d, rep)
        self.assertEqual(out["policy"]["P5"], "verified")
        d["payment_payload"]["resource"] = {"url": "https://straße.example/x"}
        out = rp.apply_policy(rp.parse_policy({"apc_policy": 1, "hosts": ["strasse.example"]}), d, rep)
        self.assertEqual(out["policy"]["P5"], "failed:resource_host_not_comparable(idna_deviation_character)")
        with self.assertRaises(rp.Bad):
            rp.parse_policy({"apc_policy": 1, "hosts": ["straße.example"]})

    def test_positive_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            p = os.path.join(tmp, "b.json")
            with open(p, "w") as fh:
                json.dump(exchange_bundle(self.IRI, self.URI), fh, ensure_ascii=False)
            rep = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), p],
                                            capture_output=True, text=True).stdout)
            self.assertEqual((rep["verifier"], rep["checks"]["X2"]),
                             ("apc_verify 0.8.0", "failed:request_not_for_the_resource"))
            d = load(V002)
            d["payment_payload"]["resource"] = {"url": self.URI}
            with open(p, "w") as fh:
                json.dump(d, fh)
            pol = os.path.join(tmp, "pol.json")
            with open(pol, "w") as fh:
                json.dump({"apc_policy": 1, "hosts": [JP[0] + ".example"]}, fh, ensure_ascii=False)
            out = json.loads(subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_report.py"), "policy", pol, p],
                                            capture_output=True, text=True).stdout)
            self.assertEqual(out["policy"]["P5"], "failed:host_not_allowed")


if __name__ == "__main__":
    unittest.main()
