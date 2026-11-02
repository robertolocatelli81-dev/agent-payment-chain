"""SPEC 0.12 (section 20): x402 `exact` on Stellar, bundle apc-0.12. Real data: bundles/xlm_real_20261026, 25 real x402
settlements on Stellar testnet by the x402.org facilitator (oracle/stellar_20261026). Oracles: the x402 constants for
the USDC Stellar Asset Contract ids; the real Ed25519 authorization signatures. Positive control: apc_verify 0.8.0
(5cbe7c7) refuses an apc-0.12 bundle (it has no Stellar verifier)."""
import base64
import copy
import glob
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("xlm_real_20261026")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_stellar as xs  # noqa: E402
import apc_verify as av  # noqa: E402

OLD = "5cbe7c7"
PATHS = sorted(glob.glob(os.path.join(ROOT, "bundles", "xlm_real_20261026", "*.json")))


def old_tree(tmp):
    """Extract apc_verify 0.8.0 (OLD) into tmp; skip where ROOT is not a git checkout (a mutant copy, a git archive)."""
    r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise unittest.SkipTest("positive control needs the git history of ROOT (commit %s)" % OLD)
    subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Unsupported:
        return {"verdict": "unsupported", "checks": {}}
    except av.Refusal as e:
        return {"verdict": "refused", "checks": {}, "reason": str(e)}


def account_payers():
    return [p for p in PATHS if load(p)["settlement"]["payer"].startswith("G")]


def resign_payload(d, mutate):
    """Change the payload transaction's operation bytes (signature left as is)."""
    raw = bytearray(base64.b64decode(d["payment_payload"]["payload"]["transaction"]))
    mutate(raw)
    d["payment_payload"]["payload"]["transaction"] = base64.b64encode(bytes(raw)).decode()
    return d


class Primitives(unittest.TestCase):
    def test_sac_ids_equal_the_x402_constants(self):
        self.assertEqual(xs.sac_contract_id("stellar:pubnet", "USDC", "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"),
                         "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75")
        self.assertEqual(xs.sac_contract_id("stellar:testnet", "USDC", "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"),
                         "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA")

    def test_strkey(self):
        g = "GC6CSXBV4C6RL3HEDTW57KXYXSSXKAWKGYDEOSATXM3XNKXSR2VRYN3K"
        self.assertEqual(xs.strkey_encode("G", xs.strkey_decode(g, "G")), g)
        for bad in (g[:-1] + ("A" if g[-1] != "A" else "B"), g.lower(), g[:-1], "C" + g[1:]):
            with self.assertRaises(xs.StellarRefusal):
                xs.strkey_decode(bad, "G")

    def test_tx_hash_is_the_rpc_hash(self):
        for p in PATHS:
            d = load(p)
            env = xs.envelope(d["chain_tx"]["envelopeXdr"])
            self.assertEqual(xs.tx_hash(env, "stellar:testnet"), d["settlement"]["transaction"])


class Real(unittest.TestCase):
    def test_corpus(self):
        self.assertEqual(len(PATHS), 25)
        v = {}
        for p in PATHS:
            r = run(load(p))
            v[(r["verdict"], r["checks"]["G2"])] = v.get((r["verdict"], r["checks"]["G2"]), 0) + 1
            for k in ("G1", "G3", "G4", "C1", "C2", "C3", "F2", "T1", "K6"):
                self.assertEqual(r["checks"][k], "verified", (p, k))
        self.assertEqual(v, {("chain_verified", "verified"): 7,
                             ("chain_incomplete", "not_evaluated:contract_account_check_auth"): 18})

    def test_breaks(self):
        p = account_payers()[0]
        d0 = load(p)
        cases = []
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["amount"] = str(int(d["payment_payload"]["accepted"]["amount"]) + 1)
        cases.append((d, "G1", "failed:amount_not_the_requirement"))
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["payTo"] = d["settlement"]["payer"]
        cases.append((d, "G1", "failed:to_not_payTo"))
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["maxTimeoutSeconds"] = 60
        cases.append((d, "G3", "failed:expiration_too_far"))
        d = copy.deepcopy(d0)
        d["settlement"]["transaction"] = "ab" * 32
        cases.append((d, "C2", "failed:settlement_names_another_transaction"))
        d = copy.deepcopy(d0)
        d["facilitator"]["signers"] = [d["settlement"]["payer"]]
        cases.append((d, "F2", "failed:settled_by_not_a_facilitator_signer"))
        d = copy.deepcopy(d0)
        d["chain_tx"]["status"] = "FAILED"
        cases.append((d, "C2", "failed:transaction_failed"))
        # the signature: flip one byte of the authorization signature inside the payload operation
        d = copy.deepcopy(d0)
        env = xs.envelope(d["payment_payload"]["payload"]["transaction"])
        sig = env["tx"]["ops"][0]["auth"][0]["credentials"]["signature"][1][0][1][1][1][1]
        raw = base64.b64decode(d["payment_payload"]["payload"]["transaction"])
        i = raw.index(sig)
        d = resign_payload(d, lambda b: b.__setitem__(i + 7, b[i + 7] ^ 1))
        cases.append((d, "G2", "failed:auth_signature_invalid"))
        d["chain_tx"]["envelopeXdr"] = d0["chain_tx"]["envelopeXdr"]
        # a payload operation different from the settled one
        d = copy.deepcopy(d0)
        cases.append((resign_payload(d, lambda b: b.__setitem__(i + 7, b[i + 7] ^ 1)), "C1", "failed:chain_tx_not_the_payload"))
        for d, k, want in cases:
            r = run(d)
            self.assertEqual((r["checks"].get(k), r["verdict"]), (want, "chain_failed"), want)

    def test_set_checks(self):
        import apc_batch
        a = load(account_payers()[0])
        b = copy.deepcopy(a)
        rep = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual((rep["verdict"], rep["D2"][0]["check"]), ("set_consistent", "duplicate_bundle"))
        b["settlement"]["transaction"] = "cd" * 32          # one authorization, two settlements named
        rep = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual(rep["D3"][0]["check"], "failed:same_authorization_two_settlements")
        c = copy.deepcopy(a)
        c["payment_payload"]["resource"] = {"url": "https://x.example/other"}
        a["payment_payload"]["resource"] = {"url": "https://x.example/one"}
        rep = apc_batch.check_set([("a", a), ("c", c)])
        self.assertEqual(rep["D1"][0]["check"], "failed:same_payment_for_two_deliveries")

    def test_zero_amount(self):
        d = load(account_payers()[0])
        d["payment_payload"]["accepted"]["amount"] = "0"
        self.assertEqual(run(d)["checks"]["K6"], "failed:zero_amount")

    def test_closed_and_fuzz(self):
        d0 = load(PATHS[0])
        for mut in (lambda d: d.__setitem__("x", 1), lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("x", 1),
                    lambda d: d["chain_tx"].__setitem__("x", 1), lambda d: d["payment_payload"]["accepted"].__setitem__("asset", "GA"),
                    lambda d: d["chain_tx"].__setitem__("status", "PENDING"),
                    lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("areFeesSponsored", "yes")):
            d = copy.deepcopy(d0)
            mut(d)
            self.assertEqual(run(d)["verdict"], "refused")
        rnd = random.Random(20)
        n = 0
        for p in PATHS[::5]:
            d0 = load(p)
            raw0 = base64.b64decode(d0["payment_payload"]["payload"]["transaction"])
            for _ in range(80):
                raw = bytearray(raw0)
                op = rnd.randrange(3)
                if op == 0:
                    raw[rnd.randrange(len(raw))] = rnd.randrange(256)
                elif op == 1:
                    del raw[rnd.randrange(len(raw)):]
                else:
                    raw.insert(rnd.randrange(len(raw) + 1), rnd.randrange(256))
                d = copy.deepcopy(d0)
                d["payment_payload"]["payload"]["transaction"] = base64.b64encode(bytes(raw)).decode()
                r = run(d)
                self.assertIn(r["verdict"], ("refused", "chain_failed", "chain_incomplete", "unsupported", "chain_verified"))
                if r["verdict"] == "chain_verified":       # only a change that leaves the signed operation equal
                    self.assertEqual(xs.envelope(d["payment_payload"]["payload"]["transaction"])["tx"]["ops"][0]["body_raw"],
                                     xs.envelope(d0["payment_payload"]["payload"]["transaction"])["tx"]["ops"][0]["body_raw"])
                n += 1
        self.assertEqual(n, 400)

    def test_positive_control_old(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_tree(tmp)
            out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), account_payers()[0]],
                                 capture_output=True, text=True)
            rep = json.loads(out.stdout)
            self.assertEqual((rep["verifier"], rep["verdict"]), ("apc_verify 0.8.0", "refused"))


if __name__ == "__main__":
    unittest.main()
