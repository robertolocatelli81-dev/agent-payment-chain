"""SPEC 0.15 (section 25): x402 scheme `auth-capture` on EVM, client collect payload (EIP-3009), bundle apc-0.15.
Real data: bundles/authcap_real_20261026 and authcap_real_v11_20261026, 20 + 18 commerce-payments authorizations on
Base (escrows v1.0 0xBdEA... and v1.1 0xf968..., oracle/authcapture_20261026): the chain itself is the oracle (the escrow's PaymentAuthorized carries getHash(PaymentInfo), the
token's AuthorizationUsed carries the signature nonce, and the token accepted the ERC-3009 signature). Positive
control: apc_verify 0.8.0 (5cbe7c7) refuses an apc-0.15 bundle. Charge path: synthetic keys (no real charge found)."""
import copy
import glob
import hashlib
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("authcap_real_20261026", "authcap_real_v11_20261026")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_authcap as ac  # noqa: E402
import apc_verify as av  # noqa: E402
from lib.secp256k1 import GX, GY, _mul, sign  # noqa: E402

OLD = "5cbe7c7"
PATHS = sorted(glob.glob(os.path.join(ROOT, "bundles", "authcap_real_20261026", "*.json")))
PATHS11 = sorted(glob.glob(os.path.join(ROOT, "bundles", "authcap_real_v11_20261026", "*.json")))
N = av.SECP_N


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(copy.deepcopy(d))
    except av.Refusal as e:
        return {"refused": str(e)}


def _sig(dg, priv):
    r, s, rec = sign(dg, priv, int.from_bytes(hashlib.sha256(dg + priv.to_bytes(32, "big")).digest(), "big") % N)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])


def _addr(priv):
    import apc_offer as ao
    return ao.evm_address(_mul(priv, (GX, GY)))


class Real(unittest.TestCase):
    def test_real_authorizations(self):
        self.assertEqual((len(PATHS), len(PATHS11)), (20, 18))
        for p in PATHS + PATHS11:
            r = run(load(p))
            self.assertEqual(r.get("verdict"), "chain_verified", (p, r))
            self.assertEqual(r["deployment"], "v1.0" if p in PATHS else "v1.1")

    def test_breaks(self):
        b = load(PATHS[0])
        cases = [
            (lambda d: d["payment_payload"]["accepted"].__setitem__("payTo", "0x" + "11" * 20), ("AC6", "C3")),
            (lambda d: d["payment_payload"]["payload"].__setitem__("signature", d["payment_payload"]["payload"]["signature"][:-4] + "ff1b"), ("AC7",)),
            (lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("to", "0x" + "22" * 20), ("AC5",)),
            (lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("refundDeadline", 1), ("AC4", "AC6", "C3")),
            (lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("authCaptureEscrow", "0x" + "33" * 20), ("AC1",)),
            (lambda d: d["payment_payload"]["payload"].__setitem__("saltNonce", "0x" + "00" * 31 + "01"), ("AC3",)),
            (lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("autoCapture", True), ("AC1",)),
            (lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("operatorType", "policy"), ("AC2",)),
            (lambda d: d["chain_tx"]["receipt"].__setitem__("status", "0x0"), ("C2",)),
            (lambda d: [lg.__setitem__("removed", True) for lg in d["chain_tx"]["receipt"]["logs"]], ("C3", "C4")),
            (lambda d: d["settlement"].__setitem__("payer", "0x" + "44" * 20), ("T1",)),
            (lambda d: d["settlement"].__setitem__("transaction", "0x" + "55" * 32), ("C1",)),
            (lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("policy", "0x" + "66" * 20), ("AC2", "AC3")),
            (lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__(
                "captureDeadline", int(d["payment_payload"]["payload"]["authorization"]["validBefore"]) - 1), ("AC4",)),
            (lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("validAfter", "1"), ("AC4", "AC7")),
            (lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", "1"), ("AC5", "AC7")),
            (lambda d: d.pop("settlement") and d.pop("provenance") and d["chain_tx"]["tx"].__setitem__(
                "nonce", hex(int(d["chain_tx"]["tx"]["nonce"], 16) + 1)), ("C1",)),
            (lambda d: [lg["topics"].__setitem__(1, "0x" + "77" * 32) for lg in d["chain_tx"]["receipt"]["logs"]
                        if lg["address"].lower() in ac.DEPLOY], ("C3",)),
            (lambda d: [lg.__setitem__("data", lg["data"][:-2] + ("00" if lg["data"][-2:] != "00" else "01"))
                        for lg in d["chain_tx"]["receipt"]["logs"] if lg["address"].lower() in ac.DEPLOY], ("C3",)),
        ]
        for mut, want in cases:
            d = copy.deepcopy(b)
            mut(d)
            r = run(d)
            self.assertEqual(r.get("verdict"), "chain_failed", (want, r))
            for k in want:
                self.assertTrue(r["checks"][k].startswith("failed"), (want, k, r["checks"]))

    def test_scope_and_ignored_extra(self):
        b = load(PATHS[0])
        d = copy.deepcopy(b)
        d["payment_payload"]["accepted"]["extra"]["assetTransferMethod"] = "permit2"   # SPEC 0.16.1: read, its shape
        self.assertIn("not the Permit2 payload shape", run(d)["refused"])
        d = copy.deepcopy(b)
        d["payment_payload"]["accepted"]["extra"]["vendorHint"] = "x"   # the scheme says to ignore it: reported
        r = run(d)
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertTrue(any("vendorHint" in n for n in r["notes"]))
        d = copy.deepcopy(b)
        d["payment_payload"]["resource"] = {"url": "https://a.example/r"}
        d["payment_required"] = {"x402Version": 2, "resource": {"url": "https://b.example/r"},
                                 "accepts": [copy.deepcopy(d["payment_payload"]["accepted"])]}
        self.assertEqual(run(d)["checks"]["K4"], "failed:resource_url_mismatch")
        d["payment_required"]["resource"]["url"] = "https://a.example/r"
        self.assertEqual(run(d)["checks"]["K4"], "verified")

    def test_positive_control_old_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
            if r.returncode != 0 or not r.stdout:
                raise unittest.SkipTest("needs the git history of ROOT")
            subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)
            out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), PATHS[0]],
                                 capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
            self.assertEqual(out.returncode, 3, out.stdout + out.stderr)


class Charge(unittest.TestCase):
    """The `authorization` flow with a bound salt and the server's completion (synthetic: anvil keys)."""
    PAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    AUTHZ = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

    def bundle(self):
        esc = ac.DEFAULT_ESCROW
        _, col, _ = ac.DEPLOY[esc]
        ra, payer = _addr(self.AUTHZ), _addr(self.PAYER)
        r = {"chain_id": 8453, "network": "eip155:8453", "amount": 1000000, "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
             "pay_to": "0x" + "ab" * 20, "captureAuthorizer": "0x" + "cd" * 20, "feeRecipient": "0x" + "ef" * 20,
             "receiverAuthorizer": ra, "policy": ac.ZERO, "escrow": esc, "captureDeadline": 1900000000,
             "refundDeadline": 1900086400, "minFeeBps": 100, "maxFeeBps": 100}
        salt_nonce = 0xabc
        salt = ac.salt_binding(ra, ac.ZERO, salt_nonce)
        au = {"from": payer, "to": col, "value": 1000000, "validAfter": 0, "validBefore": 1899999000}
        pi = [r["captureAuthorizer"], payer, r["pay_to"], r["asset"], 1000000, au["validBefore"], r["captureDeadline"],
              r["refundDeadline"], 100, 100, r["feeRecipient"], salt]
        au["nonce"] = ac.signature_nonce(8453, esc, pi)
        csig = _sig(ac.receive_digest("USD Coin", "2", 8453, r["asset"], au), self.PAYER)
        amt, fee = 750000, 7500
        asig = _sig(ac.charge_digest(8453, r["captureAuthorizer"], "feeAmount", ac.get_hash(8453, esc, pi), amt, col, csig,
                                     fee, r["feeRecipient"]), self.AUTHZ)
        acc = {"scheme": "auth-capture", "network": "eip155:8453", "amount": "1000000", "asset": r["asset"],
               "payTo": r["pay_to"], "maxTimeoutSeconds": 60,
               "extra": {"name": "USD Coin", "version": "2", "captureAuthorizer": r["captureAuthorizer"],
                         "receiverAuthorizer": ra, "paymentFlow": "authorization", "captureDeadline": r["captureDeadline"],
                         "refundDeadline": r["refundDeadline"], "minFeeBps": 100, "maxFeeBps": 100,
                         "feeRecipient": r["feeRecipient"]}}
        return {"bundle_version": "apc-0.15", "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
            "authorization": {"from": payer, "to": col, "value": "1000000", "validAfter": "0",
                              "validBefore": str(au["validBefore"]), "nonce": "0x" + au["nonce"].hex()},
            "signature": "0x" + csig.hex(), "salt": "0x" + salt.to_bytes(32, "big").hex(),
            "saltNonce": "0x" + salt_nonce.to_bytes(32, "big").hex(), "amount": str(amt), "feeAmount": str(fee),
            "feeReceiver": r["feeRecipient"], "authorizerSignature": "0x" + asig.hex()}}}

    def resign(self, d):
        """The receiver authorizer signs the completion as it now stands (to isolate the amount and fee rules)."""
        pp, r, w, _ = ac.parse(d["payment_payload"])
        pi, c = ac.payment_info(r, w), w["completion"]
        dep = ac.DEPLOY[r["escrow"]]
        sig = _sig(ac.charge_digest(8453, r["captureAuthorizer"], dep[2], ac.get_hash(8453, r["escrow"], pi), c["amount"],
                                    dep[1], w["signature"], c[dep[2]], c["feeReceiver"]), self.AUTHZ)
        d["payment_payload"]["payload"]["authorizerSignature"] = "0x" + sig.hex()

    def test_charge_rules_with_a_valid_authorizer_signature(self):
        b = self.bundle()
        for mut, want in ((lambda p: p.__setitem__("feeAmount", "7600"), "failed:invalid_auth_capture_evm_fee:out_of_range"),
                          (lambda p: p.__setitem__("amount", "1000001"), "failed:invalid_auth_capture_evm_amount:charge_amount"),
                          (lambda p: p.__setitem__("feeReceiver", "0x" + "12" * 20), "failed:invalid_auth_capture_evm_fee:fee_receiver"),
                          (lambda p: p.__setitem__("amount", "500000") or p.__setitem__("feeAmount", "5000"), "verified")):
            d = copy.deepcopy(b)
            mut(d["payment_payload"]["payload"])
            self.resign(d)
            self.assertEqual(run(d)["checks"]["AC8"], want)

    def test_charge(self):
        b = self.bundle()
        r = run(b)
        for k in ("AC1", "AC2", "AC3", "AC4", "AC5", "AC6", "AC7", "AC8"):
            self.assertEqual(r["checks"][k], "verified", (k, r["checks"]))
        for mut, k in ((lambda p: p.__setitem__("feeAmount", "7600"), "AC8"),
                       (lambda p: p.__setitem__("amount", "1000001"), "AC8"),
                       (lambda p: p.__setitem__("authorizerSignature", p["signature"]), "AC8"),
                       (lambda p: p.__setitem__("saltNonce", "0x" + "00" * 31 + "02"), "AC6"),
                       (lambda p: p.pop("saltNonce"), "AC3"),
                       (lambda p: p.pop("feeAmount"), "AC3"),
                       (lambda p: p.__setitem__("feeBps", 100), "AC3")):
            d = copy.deepcopy(b)
            mut(d["payment_payload"]["payload"])
            r = run(d)
            self.assertTrue(r["checks"][k].startswith("failed"), (k, r["checks"]))
        d = copy.deepcopy(b)
        d["payment_payload"]["accepted"]["extra"].pop("receiverAuthorizer")
        self.assertTrue(run(d)["checks"]["AC2"].startswith("failed"))


class Generative(unittest.TestCase):
    """Any input = verdict or refusal, never a traceback: new keys at every level, wrong types for every leaf."""
    def walk(self, d, path=()):
        if isinstance(d, dict):
            yield path, d
            for k, v in d.items():
                yield from self.walk(v, path + (k,))
        elif isinstance(d, list):
            for i, v in enumerate(d[:3]):
                yield from self.walk(v, path + (i,))

    def test_fuzz(self):
        rnd = random.Random(20261026)
        b = load(PATHS[0])
        b.update({"payment_required": {"x402Version": 2, "resource": {"url": "https://x.example/r"},
                                       "accepts": [copy.deepcopy(b["payment_payload"]["accepted"])]}})
        self.assertEqual(run(b)["verdict"], "chain_verified")
        objs = list(self.walk(b))
        n_ref = n_ver = 0
        for path, _ in objs:
            d = copy.deepcopy(b)
            o = d
            for k in path:
                o = o[k]
            o["unknownMember"] = 1
            r = run(d)
            closed = not (path[-1:] == ("extra",) and "accepted" in path) and "chain_tx" not in path[:1]
            if path == ("payment_required",):
                # SPEC 32.14 (0.21.5): a member of the PaymentRequired x402 does not define is ignored and named in notes
                self.assertEqual(r.get("verdict"), "chain_verified", r.get("reason"))
                self.assertTrue(any("(SPEC 32.14): ['unknownMember']" in n for n in r["notes"]))
                continue
            if closed and "accepts" not in path and path not in ((),) and "refused" not in r:
                # the members this verifier reads from are closed sets, except extra (ignored by the scheme's rule)
                # and the RPC objects inside chain_tx (as other bundle versions)
                self.fail((path, r.get("verdict")))
            if path == ():
                self.assertIn("refused", r)
        values = [None, True, 0, -1, 1.5, "", "x", "0x", [], {}, "0x" + "00" * 32, 2 ** 300, "9" * 5000, "\ud800"]
        leaves = []
        for path, o in objs:
            leaves += [path + (k,) for k, v in o.items() if not isinstance(v, (dict, list))]
        for _ in range(1500):
            d = copy.deepcopy(b)
            path = rnd.choice(leaves)
            o = d
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = rnd.choice(values)
            r = run(d)                                  # a traceback fails the test
            n_ref += "refused" in r
            n_ver += "verdict" in r
        self.assertEqual(n_ref + n_ver, 1500)


if __name__ == "__main__":
    unittest.main()
