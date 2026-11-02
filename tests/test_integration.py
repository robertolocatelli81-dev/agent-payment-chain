"""SPEC 0.16.1: the every-version amendments read in every bundle version (section 27), the Permit2 collect path of
auth-capture (section 25.1), and the set keys that two bundle versions share (apc_batch D1-D3).

Real bundles: one chain_verified bundle of each of apc-0.3, apc-0.5, apc-0.10, apc-0.12, apc-0.15, apc-0.16. Positive
control: apc_verify 0.16.0 (6b2049d) left the verdict of the apc-0.10, apc-0.15 and apc-0.16 bundles unchanged with a
forged offer, a mismatched builder-code echo and a malformed payment-identifier, and refused an auth-capture Permit2
bundle. Permit2 auth-capture vectors: rebuilt from the pinned sources with anvil keys (no real Permit2 collection was
found on Base, SPEC 25.1)."""
import copy
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))      # test_v1, also under `-m unittest`
from tests import real_corpus  # noqa: E402
real_corpus.need("*", "xlm_real_20261026")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_authcap as ac  # noqa: E402
import apc_batch  # noqa: E402
import apc_offer as ao  # noqa: E402
import apc_permit2 as p2  # noqa: E402
import apc_stellar as xs  # noqa: E402
import apc_verify as av  # noqa: E402
import apc_xrpl as xr  # noqa: E402
from lib.secp256k1 import GX, GY, _mul, sign  # noqa: E402

OLD = "6b2049d"
N = av.SECP_N
SAMPLES = {"apc-0.3": "real_v03/v001_b001_indirect_envelope_reconstructed.json",
           "apc-0.5": "real_svm/m001_mainnet_payment_20261024.json",
           "apc-0.10": "real_permit2/p005_envelope_reconstructed.json",
           "apc-0.12": "xlm_real_20261026/x017_envelope_reconstructed.json",
           "apc-0.15": "authcap_real_20261026/18ddc9b4ad8a.json",
           "apc-0.16": "xrp_real_20261026/0357d4c313ea.json"}
EVM = ("apc-0.3", "apc-0.10", "apc-0.15")
NEW = ("apc-0.10", "apc-0.15", "apc-0.16")          # versions that did not read sections 13-15 at 0.16.0
PAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80      # anvil keys 0 and 1
AUTHZ = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"


def load(rel):
    with open(os.path.join(ROOT, "bundles", rel)) as fh:
        return av.strict_json(fh.read())


def run(d, **kw):
    try:
        return av.verify_bundle(copy.deepcopy(d), **kw)
    except av.Refusal as e:
        return {"refused": str(e), "checks": {}}


def _sig(dg, priv):
    r, s, rec = sign(dg, priv, int.from_bytes(hashlib.sha256(dg + priv.to_bytes(32, "big")).digest(), "big") % N)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])


def _addr(priv):
    return ao.evm_address(_mul(priv, (GX, GY)))


def with_pr(d):
    """The bundle with a payment_required that offers its accepted terms (made from them when absent)."""
    d = copy.deepcopy(d)
    if "payment_required" not in d:
        url = (d["payment_payload"].get("resource") or {}).get("url", "https://api.example.com/r")
        d["payment_required"] = {"x402Version": 2, "resource": {"url": url},
                                 "accepts": [copy.deepcopy(d["payment_payload"]["accepted"])]}
    return d


def ext(d, where, name, value):
    d.setdefault(where, {}).setdefault("extensions", {})[name] = value
    return d


def injections():
    """(label, mutate, check, expected prefix): one forged or contradicting artifact of each amendment."""
    return [
        ("offer", lambda d: ext(d, "payment_required", "offer-receipt",
                                {"info": {"offers": [{"format": "jws", "signature": "a.b.c"}]}}), "OR1", "failed:"),
        ("echo", lambda d: ext(ext(d, "payment_required", "builder-code", {"info": {"a": "app_one"}}),
                               "payment_payload", "builder-code", {"a": "app_two"}), "BC1",
         "failed:builder_code_app_echo_mismatch"),
        ("payid", lambda d: ext(d, "payment_payload", "payment-identifier", {"info": {"required": False, "id": "short"}}),
         "PI1", "failed:payment_identifier_malformed"),
    ]


SEED = bytes(range(1, 33))                          # a test Ed25519 seed (RFC 8032 key derivation, apc_solana)


def _b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jws(payload, seed=SEED):
    """A compact JWS of the x402 offer-receipt extension (OR 3.3): EdDSA, kid did:key, payload in RFC 8785 form."""
    import apc_ap2
    import apc_solana as sol
    pub = sol.ed25519_public(seed)
    kid = "did:key:z" + sol.b58encode(b"\xed\x01" + pub)
    h = _b64u(json.dumps({"alg": "EdDSA", "kid": kid}).encode())
    p = _b64u(apc_ap2.canonical(payload).encode("utf-8"))
    return h + "." + p + "." + _b64u(sol.ed25519_sign(seed, (h + "." + p).encode("ascii"))), kid, pub


def resource_url(d):
    return (d["payment_payload"].get("resource") or d["payment_required"]["resource"])["url"]


def signed_receipt(d, payer, tx):
    sig, kid, pub = jws({"version": 1, "network": d["payment_payload"]["accepted"]["network"],
                         "resourceUrl": resource_url(d), "payer": payer, "issuedAt": 1, "transaction": tx})
    d["settlement"].setdefault("extensions", {})["offer-receipt"] = {"info": {"receipt": {"format": "jws",
                                                                                          "signature": sig}}}
    return kid, pub


def signed_offer(d):
    a = d["payment_payload"]["accepted"]
    sig, kid, pub = jws({"version": 1, "resourceUrl": resource_url(d), "scheme": a["scheme"], "network": a["network"],
                         "asset": a["asset"], "payTo": a["payTo"], "amount": a["amount"]})
    ext(d, "payment_required", "offer-receipt", {"info": {"offers": [{"format": "jws", "signature": sig}]}})
    return kid, pub


class EveryVersion(unittest.TestCase):
    def test_samples_verified(self):
        for v, rel in SAMPLES.items():
            b = with_pr(load(rel))
            self.assertEqual(b["bundle_version"], v)
            r = run(b)
            self.assertEqual(r.get("verdict"), "chain_verified", (v, r.get("refused"), r.get("failed")))

    def test_each_amendment_is_read(self):
        for v, rel in SAMPLES.items():
            for label, mut, check, want in injections():
                r = run(mut(with_pr(load(rel))))
                self.assertTrue(r["checks"].get(check, "").startswith(want), (v, label, r["checks"].get(check)))
                self.assertEqual(r["verdict"], "chain_failed", (v, label))

    def test_builder_code_off_evm_and_report(self):
        for v, rel in SAMPLES.items():
            d = ext(ext(with_pr(load(rel)), "payment_required", "builder-code", {"info": {"a": "app_one"}}),
                    "payment_payload", "builder-code", {"a": "app_one"})
            r = run(d)
            cd = r["builder_code"]["calldata"]
            self.assertEqual(r["checks"]["BC1"], "not_applicable:no_erc8021_calldata_off_evm" if v not in EVM else
                             "not_evaluated:absent:no_builder_code_calldata" if cd is None else
                             "failed:builder_code_calldata_app_mismatch" if cd.get("a") != "app_one" else "verified", v)
            self.assertEqual(r["builder_code"]["declared_app"], "app_one", v)
            self.assertTrue(v != "apc-0.10" or cd is not None, "the apc-0.10 sample is a direct settle call")

    def test_payid_verified_everywhere(self):
        for v, rel in SAMPLES.items():
            d = ext(with_pr(load(rel)), "payment_payload", "payment-identifier",
                    {"info": {"required": True, "id": "order_0123456789abcdef"}})
            self.assertEqual(run(d)["checks"]["PI1"], "verified", v)
            d = ext(ext(with_pr(load(rel)), "payment_required", "payment-identifier", {"info": {"required": True}}),
                    "payment_payload", "payment-identifier", {"info": {"required": True}})
            self.assertEqual(run(d)["checks"]["PI1"], "failed:payment_identifier_required_but_absent", v)

    def test_real_builder_code_in_a_permit2_settle(self):
        """p029: a real Base settle call whose ERC-8021 suffix carries a = bc_8da9xpmp (read since 0.16.1)."""
        b = with_pr(load("real_permit2/p029_envelope_reconstructed_rpc.json"))
        for app, want in (("bc_8da9xpmp", "verified"), ("bc_other", "failed:builder_code_calldata_app_mismatch")):
            d = ext(ext(copy.deepcopy(b), "payment_required", "builder-code", {"info": {"a": app}}),
                    "payment_payload", "builder-code", {"a": app})
            r = run(d)
            self.assertEqual((r["checks"]["BC1"], r["builder_code"]["calldata"]), (want, {"a": "bc_8da9xpmp",
                                                                                         "w": "cdp_facil1"}))

    def test_signed_offers_and_receipts(self):
        """A valid offer on the paid terms is OR1 verified on every version (the offer names the scheme: auth-capture
        on apc-0.15); a receipt naming the settled transaction is OR2 verified (XRPL: the id in lower case too)."""
        payers = {"apc-0.10": lambda d: d["payment_payload"]["payload"]["permit2Authorization"]["from"],
                  "apc-0.15": lambda d: d["payment_payload"]["payload"]["authorization"]["from"],
                  "apc-0.16": lambda d: run(d)["payer"]}
        for v in NEW:
            d = with_pr(load(SAMPLES[v]))
            kid, _ = signed_offer(d)
            tx = d["settlement"]["transaction"]
            signed_receipt(d, payers[v](d), tx.lower() if v == "apc-0.16" else tx)
            r = run(d)
            self.assertEqual((r["checks"]["OR1"], r["checks"]["OR2"], r["checks"]["OR3"]),
                             ("verified", "verified", "not_evaluated:absent:no_signer_trust"), v)
            self.assertEqual(r["verdict"], "chain_verified", v)
            self.assertEqual(r["offer_receipt"]["receipt"]["kid"], kid)
            # the reader's signer_trust reaches every version (apc-0.10 since 0.16.1): listed elsewhere -> failed
            trust = {"apc_signer_trust": 1, "authorized": [{"origin": "https://other.example", "signers": [kid]}]}
            self.assertEqual(run(d, signer_trust=trust)["checks"]["OR3"], "failed:signer_not_authorized", v)
            from urllib.parse import urlsplit
            u = urlsplit(resource_url(d))
            trust["authorized"][0]["origin"] = "%s://%s" % (u.scheme, u.netloc)
            self.assertEqual(run(d, signer_trust=trust)["checks"]["OR3"], "verified", v)
            e = copy.deepcopy(d)                        # another transaction named: OR2 failed
            signed_receipt(e, payers[v](e), tx[:-1] + ("0" if tx[-1] != "0" else "1"))
            self.assertEqual(run(e)["checks"]["OR2"], "failed:receipt_transaction_mismatch", v)

    def test_or3_by_the_key_that_names_payto(self):
        """Stellar and XRPL: a key whose address on that network is payTo authorizes (OR 4.5.1); the transfer itself
        then fails (payTo is not the real recipient), which does not concern OR3."""
        import apc_solana as sol
        pub = sol.ed25519_public(SEED)
        for v, addr in (("apc-0.12", xs.strkey_encode("G", pub)),
                        ("apc-0.16", xr.classic_address(xr.key_account(b"\xed" + pub)))):
            d = load(SAMPLES[v])
            d["payment_payload"]["accepted"]["payTo"] = addr
            d = with_pr(d)
            signed_offer(d)
            self.assertEqual(run(d)["checks"]["OR3"], "verified", v)

    def test_builder_code_state_and_c1(self):
        """The decoded suffix of one bundle is never read for the next one, and a suffix of a calldata that C1 did
        not verify is not compared (as section 14 in apc-0.3)."""
        p029 = with_pr(load("real_permit2/p029_envelope_reconstructed_rpc.json"))
        decl = lambda d: ext(ext(d, "payment_required", "builder-code", {"info": {"a": "bc_8da9xpmp"}}),  # noqa: E731
                             "payment_payload", "builder-code", {"a": "bc_8da9xpmp"})
        self.assertEqual(run(decl(copy.deepcopy(p029)))["checks"]["BC1"], "verified")
        p001 = decl(with_pr(load("real_permit2/p001_envelope_reconstructed.json")))
        self.assertEqual(run(p001)["checks"]["BC1"], "not_evaluated:absent:no_builder_code_calldata")
        d = decl(copy.deepcopy(p029))
        w = d["payment_payload"]["payload"]["permit2Authorization"]["witness"]
        w["validAfter"] = str(int(w["validAfter"]) + 1)
        r = run(d)
        self.assertTrue(r["checks"]["C1"].startswith("failed"), r["checks"]["C1"])
        self.assertEqual(r["checks"]["BC1"], "not_evaluated:absent:no_builder_code_calldata")

    def test_domain_notes(self):
        p005 = load(SAMPLES["apc-0.10"])
        self.assertFalse(any("measured domain" in n for n in run(p005)["notes"]))
        d = copy.deepcopy(p005)
        d["payment_payload"]["accepted"]["extra"].update(name="USDC", version="1")
        self.assertTrue(any("measured domain" in n for n in run(d)["notes"]))
        a = load(SAMPLES["apc-0.15"])
        self.assertFalse(any("measured domain" in n for n in run(a)["notes"]))
        a["payment_payload"]["accepted"]["extra"]["name"] = "Not USDC"
        self.assertTrue(any("measured domain" in n and "AC7 decides" in n for n in run(a)["notes"]))

    def test_asset_member_on_evm_versions(self):
        for v in EVM:
            r = run(load(SAMPLES[v]))
            self.assertEqual(r["asset"]["symbol"], "USDC", v)
            self.assertIn("eip712", r["asset"], v)

    def test_v1_cannot_carry_extensions(self):
        import test_v1
        d, _ = test_v1.as_v1(os.path.join(ROOT, "bundles", SAMPLES["apc-0.3"]))
        self.assertEqual(run(d).get("verdict"), "chain_verified")
        for where in ("payment_payload", "payment_required", "settlement"):
            e = copy.deepcopy(d)
            e[where]["extensions"] = {"payment-identifier": {"info": {"required": False}}}
            self.assertIn("unknown member", run(e)["refused"], where)

    def test_generative_inside_each_extension(self):
        rnd = random.Random(20261026)
        values = [None, True, 0, -1, 1.5, "", "x", [], {}, "0x", "9" * 600, "\ud800"]
        for v, rel in SAMPLES.items():
            base = with_pr(load(rel))
            for label, mut, check, _ in injections():
                d0 = mut(copy.deepcopy(base))
                paths = []

                def walk(o, path):
                    if isinstance(o, dict):
                        paths.append(path)
                        for k, x in o.items():
                            walk(x, path + (k,))
                    elif isinstance(o, list):
                        for i, x in enumerate(o):
                            walk(x, path + (i,))
                for where in ("payment_required", "payment_payload"):
                    for name, x in d0[where].get("extensions", {}).items():
                        walk(x, (where, "extensions", name))
                for path in paths:                              # a new key at every level of the extension
                    d = copy.deepcopy(d0)
                    o = d
                    for k in path:
                        o = o[k]
                    o["zzUnknown"] = 1
                    r = run(d)
                    got = r.get("refused") or r["checks"].get(check, "")
                    self.assertTrue("refused" in r or "not_supported" in got or "unknown member" in got,
                                    (v, label, path, got))
                for _ in range(40):                             # a wrong type at a random leaf of the extension
                    d = copy.deepcopy(d0)
                    path = rnd.choice(paths)
                    o = d
                    for k in path:
                        o = o[k]
                    if isinstance(o, dict) and o:
                        o[rnd.choice(sorted(o))] = rnd.choice(values)
                    r = run(d)                                  # a verdict or a refusal, never a traceback
                    self.assertTrue("refused" in r or "verdict" in r)
                where = "payment_payload" if "extensions" in d0["payment_payload"] else "payment_required"
                obj = next(iter(d0[where]["extensions"].values()))     # a duplicate member in the JSON text is refused
                k0 = next(iter(obj))
                et, text = json.dumps(obj), json.dumps(d0)
                dup = text.replace(et, et.replace('{"%s": ' % k0, '{"%s": 1, "%s": ' % (k0, k0), 1), 1)
                self.assertNotEqual(dup, text)
                with self.assertRaises(av.Refusal):
                    av.strict_json(dup)

    def test_positive_control_old_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
            if r.returncode != 0 or not r.stdout:
                raise unittest.SkipTest("needs the git history of ROOT (commit %s)" % OLD)
            os.mkdir(os.path.join(tmp, "t"))
            subprocess.run(["tar", "-x", "-C", os.path.join(tmp, "t")], input=r.stdout, check=True)
            for v in NEW + ("apc-0.5", "apc-0.12"):     # Solana and Stellar read PI1 and OR before 0.16.1, not BC1
                plain = with_pr(load(SAMPLES[v]))
                for label, mut, check, _ in injections():
                    if v in ("apc-0.5", "apc-0.12") and label != "echo":
                        continue
                    p = os.path.join(tmp, "b.json")
                    with open(p, "w") as fh:
                        json.dump(mut(copy.deepcopy(plain)), fh)
                    out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "t", "apc_verify.py"), p],
                                         capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
                    rep = json.loads(out.stdout)
                    self.assertEqual((out.returncode, rep["verdict"]), (0, "chain_verified"), (v, label))
                    self.assertNotIn(check, rep["checks"], (v, label))


class KeyAddress(unittest.TestCase):
    """OR3 by payTo: the address a key names on Stellar and XRPL (SPEC 13, 0.16.1)."""
    def test_xrpl_real_keys(self):
        import glob
        n = {"EdDSA": 0, "ES256K": 0}
        for p in sorted(glob.glob(os.path.join(ROOT, "bundles", "xrp_real_20261026", "*.json"))):
            with open(p) as fh:
                d = av.strict_json(fh.read())
            _, v = xr.decode(bytes.fromhex(d["payment_payload"]["payload"]["signedTxBlob"]))
            pk = v["SigningPubKey"]
            if len(pk) != 33:
                continue                                        # multi-signed: no single key
            acct = xr.classic_address(v["Account"])
            if pk[0] == 0xED:
                alg, key = "EdDSA", pk[1:]
            else:
                alg, key = "ES256K", ao._key("ES256K", pk)[1]
            got = ao.key_address(alg, key, "xrpl")
            if xr.key_account(pk) == v["Account"]:              # the master key (a regular key names another account)
                self.assertEqual(got, acct, p)
                n[alg] += 1
            else:
                self.assertNotEqual(got, acct, p)
        self.assertGreater(n["EdDSA"] + n["ES256K"], 0)

    def test_stellar_and_closed_families(self):
        key = bytes(range(32))
        g = ao.key_address("EdDSA", key, "stellar")
        self.assertEqual(xs.strkey_decode(g, "G"), key)
        self.assertNotEqual(g, ao.key_address("EdDSA", key, "solana"))
        for fam in ("", "cardano", None, "EVM"):
            self.assertIsNone(ao.key_address("EdDSA", key, fam))
        self.assertIsNone(ao.key_address("ES256", (1, 2), "xrpl"))


def permit_transfer_digest(chain_id, token, amount, spender, nonce, deadline):
    """The PermitTransferFrom digest by the generic EIP-712 of APC_SIGLIB (its self-test reproduces the EIP-712 "Mail"
    digests), from the type strings of Permit2 PermitHash.sol and EIP712.sol: an oracle independent of apc_permit2."""
    types = {"PermitTransferFrom": [{"name": "permitted", "type": "TokenPermissions"},
                                    {"name": "spender", "type": "address"}, {"name": "nonce", "type": "uint256"},
                                    {"name": "deadline", "type": "uint256"}],
             "TokenPermissions": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}]}
    dom = [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
           {"name": "verifyingContract", "type": "address"}]
    return av.signing_digest({"name": "Permit2", "chainId": chain_id, "verifyingContract": p2.PERMIT2},
                             "PermitTransferFrom", types, {"permitted": {"token": token, "amount": amount},
                                                           "spender": spender, "nonce": nonce, "deadline": deadline}, dom)


def _p2_bundle(escrow=ac.DEFAULT_ESCROW, flow="escrow", sig64=False, high_s=False):
    """An auth-capture payment on the Permit2 collect path, built from the pinned sources (SPEC 25.1)."""
    col = ac.P2_COLLECTOR[escrow]
    payer = _addr(PAYER)
    ra = _addr(AUTHZ) if flow == "authorization" else ac.ZERO
    r = {"captureAuthorizer": "0x" + "cd" * 20, "pay_to": "0x" + "ab" * 20, "feeRecipient": "0x" + "ef" * 20}
    salt_nonce = 0xabc
    salt = ac.salt_binding(ra, ac.ZERO, salt_nonce) if ra != ac.ZERO else 0x1234
    deadline = 1899999000
    pi = [r["captureAuthorizer"], payer, r["pay_to"], USDC, 1000000, deadline, 1900000000, 1900086400, 100, 100,
          r["feeRecipient"], salt]
    nonce = int.from_bytes(ac.signature_nonce(8453, escrow, pi), "big")
    dg = permit_transfer_digest(8453, USDC, 1000000, col, nonce, deadline)
    sig = _sig(dg, PAYER)
    if high_s:
        s = N - int.from_bytes(sig[32:64], "big")
        sig = sig[:32] + s.to_bytes(32, "big") + bytes([55 - sig[64]])
    if sig64:
        vs = int.from_bytes(sig[32:64], "big") | ((sig[64] - 27) << 255)
        sig = sig[:32] + vs.to_bytes(32, "big")
    extra = {"name": "USD Coin", "version": "2", "captureAuthorizer": r["captureAuthorizer"], "paymentFlow": flow,
             "captureDeadline": 1900000000, "refundDeadline": 1900086400, "minFeeBps": 100, "maxFeeBps": 100,
             "feeRecipient": r["feeRecipient"], "assetTransferMethod": "permit2", "authCaptureEscrow": escrow}
    if ra != ac.ZERO:
        extra["receiverAuthorizer"] = ra
    payload = {"permit2Authorization": {"from": payer, "permitted": {"token": USDC, "amount": "1000000"},
                                        "spender": col, "nonce": str(nonce), "deadline": str(deadline)},
               "signature": "0x" + sig.hex(), "salt": "0x" + salt.to_bytes(32, "big").hex()}
    if ra != ac.ZERO:
        payload["saltNonce"] = "0x" + salt_nonce.to_bytes(32, "big").hex()
        dep = ac.DEPLOY[escrow]
        amt, fee = 750000, 7500 if dep[2] == "feeAmount" else 100
        asig = _sig(ac.charge_digest(8453, r["captureAuthorizer"], dep[2], ac.get_hash(8453, escrow, pi), amt, col, sig,
                                     fee, r["feeRecipient"]), AUTHZ)
        payload.update({"amount": str(amt), dep[2]: str(fee) if dep[2] == "feeAmount" else fee,
                        "feeReceiver": r["feeRecipient"], "authorizerSignature": "0x" + asig.hex()})
    acc = {"scheme": "auth-capture", "network": "eip155:8453", "amount": "1000000", "asset": USDC, "payTo": r["pay_to"],
           "maxTimeoutSeconds": 60, "extra": extra}
    return {"bundle_version": "apc-0.15", "payment_payload": {"x402Version": 2, "accepted": acc, "payload": payload}}, pi


def _chain(d, pi, transfers=None):
    """A transaction and receipt carrying the escrow's event and the token's Transfer (hash recomputed, SPEC 25 C1)."""
    pp, r, w, _ = ac.parse(d["payment_payload"])
    amount = w["completion"].get("amount", r["amount"])
    tx = {"type": "0x2", "chainId": "0x2105", "nonce": "0x1", "maxPriorityFeePerGas": "0x1", "maxFeePerGas": "0x2",
          "gas": "0x30000", "to": "0x" + "cd" * 20, "value": "0x0", "input": "0x", "accessList": [], "yParity": "0x1",
          "r": "0x1", "s": "0x2"}
    tx["hash"] = av.tx_hash_eip1559(tx)
    blk = {"blockHash": "0x" + "b1" * 32, "blockNumber": "0x3291d38"}     # 27/10: SPEC 25 C1 binds the logs' block
    tx.update(blk)
    flow = r["paymentFlow"]
    dep = ac.DEPLOY[r["escrow"]]
    topic0 = ac.EV_AUTHORIZED if flow == "escrow" else ac.EV_CHARGED[dep[2]]
    data = ac.encode_pi(pi) + ac._wu(amount) + ac._wa(ac.P2_COLLECTOR[r["escrow"]])
    if flow == "authorization":
        data += ac._wu(int(w["completion"][dep[2]])) + ac._wa(w["completion"]["feeReceiver"])
    logs = [{"address": r["escrow"], "topics": [topic0, "0x" + ac.get_hash(8453, r["escrow"], pi).hex()],
             "data": "0x" + data.hex(), "transactionHash": tx["hash"], **blk}]
    for frm, val in (transfers if transfers is not None else [(w["auth"]["from"], amount)]):
        logs.append({"address": USDC, "topics": [ac.EV_TRANSFER, "0x" + ac._wa(frm).hex(), "0x" + "00" * 12 + "77" * 20],
                     "data": "0x" + ac._wu(val).hex(), "transactionHash": tx["hash"], **blk})
    d = copy.deepcopy(d)
    d["chain_tx"] = {"tx": tx, "receipt": {"transactionHash": tx["hash"], "status": "0x1", "logs": logs, **blk}}
    d["settlement"] = {"success": True, "transaction": tx["hash"], "network": "eip155:8453", "payer": w["auth"]["from"]}
    return d


class AuthCapturePermit2(unittest.TestCase):
    def test_digest_against_generic_eip712(self):
        for args in ((8453, USDC, 1000000, ac.P2_COLLECTOR[ac.DEFAULT_ESCROW], 1 << 255, 1899999000),
                     (1, "0x" + "12" * 20, 1, "0x" + "34" * 20, 0, 0)):
            self.assertEqual(p2.permit_transfer_digest(*args), permit_transfer_digest(*args))

    def test_authorize_both_deployments(self):
        for esc in ac.DEPLOY:
            d, pi = _p2_bundle(esc)
            r = run(_chain(d, pi))
            self.assertEqual(r["verdict"], "chain_verified", (esc, r["checks"]))
            self.assertEqual((r["asset_transfer_method"], r["deployment"]), ("permit2", ac.DEPLOY[esc][0]))
            for k in ("AC1", "AC2", "AC3", "AC4", "AC5", "AC6", "AC7", "C1", "C2", "C3", "C4"):
                self.assertEqual(r["checks"][k], "verified", k)

    def test_signature_forms(self):
        d, pi = _p2_bundle(sig64=True)
        self.assertEqual(run(d)["checks"]["AC7"], "verified")
        d, pi = _p2_bundle(high_s=True)
        r = run(d)
        self.assertEqual(r["checks"]["AC7"], "verified")             # Permit2: no s rule, the token never sees it
        self.assertTrue(any("upper half" in n for n in r["notes"]))
        for sig, want in (("0x" + "11" * 70, "not_evaluated:erc1271_needs_chain_state"),
                          ("0x" + "11" * 32 + av.ERC6492_MAGIC.hex(), "not_evaluated:erc6492_counterfactual_signature"),
                          ("0x" + "11" * 64 + "1d", "failed:v_not_27_or_28")):
            d, pi = _p2_bundle()
            d["payment_payload"]["payload"]["signature"] = sig
            self.assertEqual(run(d)["checks"]["AC7"], want)

    def test_breaks(self):
        cases = [
            (lambda a, x: a.__setitem__("spender", ac.DEPLOY[ac.DEFAULT_ESCROW][1]), "AC5", "collector_mismatch"),
            (lambda a, x: a["permitted"].__setitem__("token", "0x" + "12" * 20), "AC5", "token_mismatch"),
            (lambda a, x: a["permitted"].__setitem__("amount", "999999"), "AC5", "amount_mismatch"),
            (lambda a, x: a.__setitem__("nonce", str(int(a["nonce"]) + 1)), "AC6", "nonce_mismatch"),
            (lambda a, x: a.__setitem__("deadline", "1900000001"), "AC4", "deadline_after_capture"),
            (lambda a, x: a.__setitem__("deadline", str(1 << 48)), "AC4", "deadline_after_capture"),
            (lambda a, x: a.__setitem__("from", _addr(AUTHZ)), "AC7", "failed:signature_does_not_recover_the_payer"),
        ]       # deadline_not_uint48 cannot be reached: deadline <= captureDeadline, a uint48 by the grammar
        for mut, k, want in cases:
            d, pi = _p2_bundle()
            mut(d["payment_payload"]["payload"]["permit2Authorization"], d["payment_payload"]["accepted"])
            r = run(d)
            self.assertIn(want, r["checks"][k], (k, r["checks"]))
            self.assertTrue(r["checks"][k].startswith("failed"), (k, r["checks"]))
            if want == "collector_mismatch":            # Permit2 hashes its msg.sender, the deployment's collector
                self.assertEqual(r["checks"]["AC7"], "verified")
        d, pi = _p2_bundle()
        d["payment_payload"]["accepted"]["extra"]["authCaptureEscrow"] = "0x" + "33" * 20
        r = run(d)
        self.assertEqual((r["checks"]["AC1"][:7], r["checks"]["AC5"], r["checks"]["AC7"]),
                         ("failed:", "not_evaluated:after_AC1", "not_evaluated:after_AC1"))

    def test_charge(self):
        for esc in ac.DEPLOY:
            d, pi = _p2_bundle(esc, flow="authorization")
            r = run(_chain(d, pi))
            self.assertEqual(r["verdict"], "chain_verified", (esc, r["checks"]))
            self.assertEqual(r["checks"]["AC8"], "verified")
            # the Charge signed over the EIP-3009 collector, or over the ABI encoding of the signature: AC8 fails
            pl = d["payment_payload"]["payload"]
            sig = bytes.fromhex(pl["signature"][2:])
            dep = ac.DEPLOY[esc]
            fee = int(pl[dep[2]])
            for col, cdata in ((dep[1], sig), (ac.P2_COLLECTOR[esc], (32).to_bytes(32, "big") +
                                                len(sig).to_bytes(32, "big") + sig + bytes(31))):
                e = copy.deepcopy(d)
                e["payment_payload"]["payload"]["authorizerSignature"] = "0x" + _sig(ac.charge_digest(
                    8453, "0x" + "cd" * 20, dep[2], ac.get_hash(8453, esc, pi), 750000, col, cdata, fee,
                    "0x" + "ef" * 20), AUTHZ).hex()
                self.assertEqual(run(e)["checks"]["AC8"], "failed:invalid_auth_capture_evm_authorizer_signature")

    def test_chain_c3_c4(self):
        d, pi = _p2_bundle()
        payer = _addr(PAYER)
        for transfers, want in (([], "failed:no_transfer_of_the_amount_from_the_payer"),
                                ([(payer, 999999)], "failed:no_transfer_of_the_amount_from_the_payer"),
                                ([(_addr(AUTHZ), 1000000)], "failed:no_transfer_of_the_amount_from_the_payer"),
                                ([(payer, 1000000), (payer, 5)], "not_evaluated:more_than_one_transfer_from_the_payer")):
            self.assertEqual(run(_chain(d, pi, transfers))["checks"]["C4"], want)
        c = _chain(d, pi)                                   # a two-topic log is not an ERC-20 Transfer(from, to, value)
        c["chain_tx"]["receipt"]["logs"][1]["topics"].pop()
        self.assertEqual(run(c)["checks"]["C4"], "failed:no_transfer_of_the_amount_from_the_payer")
        c = _chain(d, pi)
        c["chain_tx"]["receipt"]["logs"][1]["removed"] = True
        self.assertEqual(run(c)["checks"]["C4"], "failed:removed_log")
        c = _chain(d, pi)                                   # the event names the EIP-3009 collector: not this payment
        lg = c["chain_tx"]["receipt"]["logs"][0]
        lg["data"] = lg["data"][:-40] + ac.DEPLOY[ac.DEFAULT_ESCROW][1][2:]
        self.assertEqual(run(c)["checks"]["C3"], "failed:escrow_event_data_mismatch")

    def test_shape_closed(self):
        d, pi = _p2_bundle()
        pl = d["payment_payload"]["payload"]
        for mut in (lambda p: p.__setitem__("authorization", {}),
                    lambda p: p["permit2Authorization"].__setitem__("witness", {"to": "0x" + "00" * 20, "validAfter": "0"}),
                    lambda p: p["permit2Authorization"]["permitted"].__setitem__("x", 1),
                    lambda p: p["permit2Authorization"].pop("deadline"),
                    lambda p: p["permit2Authorization"].__setitem__("nonce", "0x01"),
                    lambda p: p["permit2Authorization"].__setitem__("nonce", "01"),
                    lambda p: p["permit2Authorization"].__setitem__("nonce", 1),
                    lambda p: p.pop("permit2Authorization")):
            e = copy.deepcopy(d)
            mut(e["payment_payload"]["payload"])
            self.assertIn("refused", run(e), pl)
        e = copy.deepcopy(d)
        e["payment_payload"]["payload"]["authorization"] = {}
        self.assertIn("not the Permit2 payload shape", run(e)["refused"])
        e = copy.deepcopy(d)
        e["payment_payload"]["accepted"]["extra"]["assetTransferMethod"] = "erc7710"
        self.assertIn("not eip3009 or permit2", run(e)["refused"])

    def test_generative(self):
        rnd = random.Random(251)
        d, pi = _p2_bundle(flow="authorization")
        b = _chain(d, pi)
        self.assertEqual(run(b)["verdict"], "chain_verified")
        objs = []

        def walk(o, path):
            if isinstance(o, dict):
                objs.append((path, o))
                for k, x in o.items():
                    walk(x, path + (k,))
        walk(b["payment_payload"]["payload"], ("payment_payload", "payload"))
        for path, _ in objs:
            e = copy.deepcopy(b)
            o = e
            for k in path:
                o = o[k]
            o["zzUnknown"] = 1
            self.assertIn("refused", run(e), path)
        values = [None, True, 0, -1, 1.5, "", "x", "0x", [], {}, "0x" + "00" * 32, 2 ** 300, "9" * 600, "\ud800"]
        leaves = [p + (k,) for p, o in objs for k, x in o.items() if not isinstance(x, dict)]
        for _ in range(400):
            e = copy.deepcopy(b)
            path = rnd.choice(leaves)
            o = e
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = rnd.choice(values)
            r = run(e)
            self.assertTrue("refused" in r or "verdict" in r)

    def test_positive_control_old_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
            if r.returncode != 0 or not r.stdout:
                raise unittest.SkipTest("needs the git history of ROOT (commit %s)" % OLD)
            os.mkdir(os.path.join(tmp, "t"))
            subprocess.run(["tar", "-x", "-C", os.path.join(tmp, "t")], input=r.stdout, check=True)
            d, pi = _p2_bundle()
            p = os.path.join(tmp, "b.json")
            with open(p, "w") as fh:
                json.dump(_chain(d, pi), fh)
            out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "t", "apc_verify.py"), p],
                                 capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
            self.assertEqual(out.returncode, 3, out.stdout)
            self.assertIn("Permit2/ERC-7710", out.stdout + out.stderr)


def _exact_3009(nonce_hex, frm_case=str.lower, url="https://shop.example/a"):
    """An apc-0.3 exact payment (EIP-3009, USDC on Base) by the anvil payer with the given nonce."""
    payer = _addr(PAYER)
    au = {"from": payer, "to": "0x" + "ab" * 20, "value": 1000000, "validAfter": 0, "validBefore": 1899999000,
          "nonce": nonce_hex.lower()}
    dg = av.signing_digest({"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC},
                           "TransferWithAuthorization", av.TYPES, au, av.DOMAIN4)
    sig = _sig(dg, PAYER)
    acc = {"scheme": "exact", "network": "eip155:8453", "amount": "1000000", "asset": USDC.upper().replace("0X", "0x"),
           "payTo": "0x" + "ab" * 20, "maxTimeoutSeconds": 60, "extra": {"name": "USD Coin", "version": "2"}}
    return {"bundle_version": "apc-0.3", "payment_payload": {
        "x402Version": 2, "accepted": acc, "resource": {"url": url},
        "payload": {"signature": "0x" + sig.hex(), "authorization": {
            "from": "0x" + frm_case(payer[2:]), "to": au["to"], "value": "1000000", "validAfter": "0",
            "validBefore": "1899999000", "nonce": nonce_hex}}}}


def _authcap_3009(url="https://shop.example/b"):
    """An auth-capture payment on the EIP-3009 path (USDC on Base, escrow v1.1) by the anvil payer."""
    esc = ac.DEFAULT_ESCROW
    payer = _addr(PAYER)
    pi = ["0x" + "cd" * 20, payer, "0x" + "ab" * 20, USDC, 1000000, 1899999000, 1900000000, 1900086400, 100, 100,
          "0x" + "ef" * 20, 0x1234]
    nonce = ac.signature_nonce(8453, esc, pi)
    au = {"from": payer, "to": ac.DEPLOY[esc][1], "value": 1000000, "validAfter": 0, "validBefore": 1899999000,
          "nonce": nonce}
    sig = _sig(ac.receive_digest("USD Coin", "2", 8453, USDC, au), PAYER)
    extra = {"name": "USD Coin", "version": "2", "captureAuthorizer": pi[0], "captureDeadline": 1900000000,
             "refundDeadline": 1900086400, "minFeeBps": 100, "maxFeeBps": 100, "feeRecipient": pi[10]}
    d = {"bundle_version": "apc-0.15", "payment_payload": {
        "x402Version": 2, "resource": {"url": url},
        "accepted": {"scheme": "auth-capture", "network": "eip155:8453", "amount": "1000000", "asset": USDC,
                     "payTo": pi[2], "maxTimeoutSeconds": 60, "extra": extra},
        "payload": {"authorization": {"from": payer, "to": au["to"], "value": "1000000", "validAfter": "0",
                                      "validBefore": "1899999000", "nonce": "0x" + nonce.hex()},
                    "signature": "0x" + sig.hex(), "salt": "0x" + (0x1234).to_bytes(32, "big").hex()}}}
    return d, "0x" + nonce.hex()


def _exact_permit2(nonce, url="https://shop.example/a"):
    """An apc-0.10 exact payment by Permit2 (USDC on Base) by the anvil payer with the given Permit2 nonce."""
    payer = _addr(PAYER)
    au = {"token": USDC, "amount": 1000000, "from": payer, "spender": p2.EXACT_PROXY, "nonce": nonce,
          "deadline": 1899999000, "to": "0x" + "ab" * 20, "validAfter": 0}
    sig = _sig(p2.permit2_digest(8453, au), PAYER)
    return {"bundle_version": "apc-0.10", "payment_payload": {
        "x402Version": 2, "resource": {"url": url},
        "accepted": {"scheme": "exact", "network": "eip155:8453", "amount": "1000000", "asset": USDC,
                     "payTo": au["to"], "maxTimeoutSeconds": 60, "extra": {"assetTransferMethod": "permit2"}},
        "payload": {"signature": "0x" + sig.hex(), "permit2Authorization": {
            "permitted": {"token": USDC, "amount": "1000000"}, "from": payer, "spender": p2.EXACT_PROXY,
            "nonce": str(nonce), "deadline": "1899999000", "witness": {"to": au["to"], "validAfter": "0"}}}}}


class SharedNonceSpaces(unittest.TestCase):
    """apc_batch: one nonce of the token (EIP-3009) or of Permit2 used by bundles of two versions is one key."""
    def test_eip3009_exact_and_auth_capture(self):
        a, nonce = _authcap_3009()
        self.assertEqual(run(a)["checks"]["AC6"], "verified")
        for frm_case, nonce_case in ((str.lower, str.lower), (str.upper, str.upper)):
            e = _exact_3009("0x" + nonce_case(nonce[2:]), frm_case)
            self.assertEqual(run(e)["checks"]["L2.sig"], "verified")
            rep = apc_batch.check_set([("exact", e), ("authcap", a)])
            self.assertEqual(rep["authorizations"], 1, rep)
            self.assertEqual(rep["D1"][0]["check"], "failed:same_payment_for_two_deliveries")
            self.assertEqual(rep["verdict"], "set_failed")

    def test_v1_and_auth_capture(self):
        import test_v1
        a, nonce = _authcap_3009(url="https://api.example.com/r")
        e = _exact_3009("0x" + nonce[2:].upper())
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "e.json")
            e["settlement"] = {"success": True, "transaction": "0x" + "aa" * 32, "network": "eip155:8453"}
            with open(p, "w") as fh:
                json.dump(e, fh)
            v1, _ = test_v1.as_v1(p)
        self.assertEqual(v1["payment_payload"]["network"], "base")
        rep = apc_batch.check_set([("v1", v1), ("authcap", a)])
        self.assertEqual((rep["authorizations"], rep["D2"][0]["check"]), (1, "duplicate_bundle"), rep)

    def test_permit2_exact_and_auth_capture(self):
        d, pi = _p2_bundle()
        nonce = int(d["payment_payload"]["payload"]["permit2Authorization"]["nonce"])
        e = _exact_permit2(nonce)
        self.assertEqual(run(e)["checks"]["L2.sig"], "verified")
        rep = apc_batch.check_set([("exact_permit2", e), ("authcap_permit2", d)])
        self.assertEqual(rep["refused"], [])
        self.assertEqual(rep["authorizations"], 1, rep)
        self.assertEqual(rep["D1"][0]["check"], "failed:same_payment_for_two_deliveries")
        rep = apc_batch.check_set([("exact_permit2", _exact_permit2(nonce + 1)), ("authcap_permit2", d)])
        self.assertEqual((rep["authorizations"], rep["verdict"]), (2, "set_consistent"))
        # a Permit2 nonce and an EIP-3009 nonce are different spaces: never one key
        a, _ = _authcap_3009()
        rep = apc_batch.check_set([("authcap_permit2", d), ("authcap_3009", a)])
        self.assertEqual(rep["authorizations"], 2)


if __name__ == "__main__":
    unittest.main()
