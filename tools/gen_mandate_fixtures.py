"""SPEC 31.8: synthetic fixtures for MP1-MP7, made from keys generated here (no third-party data).

AP2 mandates are made with the AP2 SDK at e1ea56d (AP2_SDK_PATH = its code/sdk/python), packs with ap2-evidence-pack
v1.7.1 (APC_AP2EV), the EIP-3009 authorization signed with anvil key 0 (the AP2 x402 sample's default payer).

  env -u PYTHONPATH AP2_SDK_PATH=... APC_AP2EV=... /usr/bin/python3.11 tools/gen_mandate_fixtures.py OUT_DIR

Writes OUT_DIR/<case>.json (apc-0.1 bundles with a `mandate` member) and OUT_DIR/MANIFEST.json (case -> expected MP
outcomes as generated, and the SHA-256 of each file)."""
import hashlib
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/gen_mandate_fixtures", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
sys.path.insert(0, os.environ["AP2_SDK_PATH"])
sys.path.insert(0, os.environ["APC_AP2EV"])
import ap2_evidence  # noqa: E402
import apc_verify as av  # noqa: E402
from ap2.sdk.generated.open_checkout_mandate import AllowedMerchants, LineItems, OpenCheckoutMandate  # noqa: E402
from ap2.sdk.generated.open_payment_mandate import (AllowedPayees, AllowedPaymentInstruments, AmountRange,  # noqa: E402
                                                    OpenPaymentMandate, PaymentReference)
from ap2.sdk.generated.payment_mandate import PaymentMandate  # noqa: E402
from ap2.sdk.generated.types.amount import Amount  # noqa: E402
from ap2.sdk.generated.types.merchant import Merchant  # noqa: E402
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument  # noqa: E402
from ap2.sdk.mandate import MandateClient  # noqa: E402
from jwcrypto.jwk import JWK  # noqa: E402
from lib.secp256k1 import sign  # noqa: E402

PAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil key 0
PAYEE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"                        # anvil address 1
USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
MERCHANT = Merchant(id="merchant-1", name="Demo Merchant", website="https://merchant.example")
INSTRUMENT = PaymentInstrument(type="x402", id="x402-base-usdc", description="USDC on Base")


def b64u_sha256(s):
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def addr(priv):
    from lib.secp256k1 import GX, GY, _mul
    x, y = _mul(priv, (GX, GY))
    return "0x" + av.keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()


def sig(digest, priv):
    r, s, rec = sign(digest, priv, int.from_bytes(hashlib.sha256(digest + priv.to_bytes(32, "big")).digest(), "big") % av.SECP_N)
    return "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])).hex()


def payload(chain, value, to=PAYEE, nonce=None, now=None):
    au = {"from": addr(PAYER), "to": to, "value": str(value), "validAfter": "0",
          "validBefore": str(now + 3600), "nonce": nonce or "0x" + av.keccak256(chain.encode("ascii")).hex()}
    msg = dict(au, value=int(au["value"]), validAfter=0, validBefore=int(au["validBefore"]))
    dg = av.signing_digest({"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC_BASE},
                           "TransferWithAuthorization", av.TYPES, msg, av.DOMAIN4)
    return {"x402Version": 2, "accepted": {"scheme": "exact", "network": "eip155:8453", "amount": str(value),
                                           "asset": USDC_BASE, "payTo": to, "maxTimeoutSeconds": 60,
                                           "extra": {"name": "USD Coin", "version": "2"}},
            "payload": {"signature": sig(dg, PAYER), "authorization": au}}


def open_payment(agent, now, constraints, **kw):
    return OpenPaymentMandate(constraints=constraints, cnf={"jwk": json.loads(agent.export_public())}, iat=now,
                              exp=kw.pop("exp", now + 3600), **kw)


def _b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def restriction(user, original_token, constraints, now, agent):
    """A restriction record (SPEC section 11.1 of ap2-evidence-pack) in the delegate_payload form of the original: a
    plain constraint element `{"type": restricts, "issuer_jwt_hash": H}` beside the narrower AP2 constraints. The SDK's
    typed path refuses the unknown constraint type, so the token is signed here (ES256, the issuer's key), with the
    content one array-element disclosure of `delegate_payload` as the SDK writes O."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    content = open_payment(agent, now, constraints).model_dump(mode="json", exclude_none=True)
    content["constraints"].append({"type": "io.github.robertolocatelli81.restricts",
                                   "issuer_jwt_hash": ap2_evidence.issuer_jwt_hash(original_token)})
    disc = _b64u(json.dumps([_b64u(os.urandom(16)), content]).encode("utf-8"))
    payload = {"_sd_alg": "sha-256", "delegate_payload": [{"...": _b64u(hashlib.sha256(disc.encode("ascii")).digest())}]}
    si = _b64u(json.dumps({"alg": "ES256", "typ": "example+sd-jwt"}).encode()) + "." + _b64u(json.dumps(payload).encode())
    sk = serialization.load_pem_private_key(user.export_to_pem(private_key=True, password=None), None)
    r, s_ = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return si + "." + _b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big")) + "~" + disc + "~"


def build_pack(arts, keys):
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "pack.json")
        ap2_evidence.build_evidence([{"name": n, "sd_jwt": t} for n, t in arts], out, keys=keys)
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    now = int(time.time())
    user, agent = JWK.generate(kty="EC", crv="P-256"), JWK.generate(kty="EC", crv="P-256")
    mc = MandateClient()
    ochk = mc.create(payloads=[OpenCheckoutMandate(
        constraints=[LineItems(items=[{"id": "item-1", "acceptable_items": [{"id": "sku-1", "title": "Widget"}],
                                       "quantity": 1}]), AllowedMerchants(allowed=[MERCHANT])],
        cnf={"jwk": json.loads(agent.export_public())}, iat=now, exp=now + 3600)], issuer_key=user)
    ref = b64u_sha256(ochk)
    base_cons = [AmountRange(currency="USD", min=0, max=5000), AllowedPayees(allowed=[MERCHANT]),
                 PaymentReference(conditional_transaction_id=ref), AllowedPaymentInstruments(allowed=[INSTRUMENT])]
    cases, manifest = {}, {}

    def case(name, cons, cents, expect, extra_arts=(), value=None, to=PAYEE, nonce=None, open_kw=None, closed_kw=None,
             chain_edit=None, pack_edit=None):
        om = mc.create(payloads=[open_payment(agent, now, cons, **(open_kw or {}))], issuer_key=user)
        cm = PaymentMandate(transaction_id="checkout-jwt-hash", payee=MERCHANT,
                            payment_amount=Amount(amount=cents, currency="USD"), payment_instrument=INSTRUMENT,
                            **(closed_kw or {}))
        chain = mc.present(holder_key=agent, mandate_token=om, payloads=[cm], nonce="n-" + name, aud="credential-provider")
        o_seg, c_seg = chain.split("~~")
        arts = [("open_payment", om), ("closed_payment", c_seg), ("open_checkout", ochk)]
        keys = {"open_payment": json.loads(user.export_public()), "open_checkout": json.loads(user.export_public()),
                "closed_payment": json.loads(agent.export_public())}
        for n, t in extra_arts:
            arts.append((n, t(om) if callable(t) else t))
            keys[n] = json.loads(user.export_public())
        pack = build_pack(arts, keys)
        if pack_edit:
            pack_edit(pack)
        if chain_edit:
            chain = chain_edit(chain)
        doc = {"bundle_version": "apc-0.1",
               "payment_payload": payload(chain, cents * 10000 if value is None else value, to, nonce, now),
               "mandate": {"profile": "ap2-evidence-pack/1.7.1", "pack": pack, "chain": chain}}
        cases[name] = doc
        manifest[name] = {"expect": expect}

    case("base", base_cons, 1250, {"MP1": "verified", "MP2": "verified", "MP3": "verified",
                                   "MP4": "not_evaluated:mandate_names_no_address", "MP5": "not_evaluated:absent:no_restriction"})
    case("over_amount_range", base_cons, 6000, {"MP3": "failed:amount_out_of_range"})
    case("value_not_mandate_amount", base_cons, 1250, {"MP4": "failed:value_not_the_mandate_amount"}, value=12500001)
    case("nonce_not_chain_hash", base_cons, 1250, {"MP4": "failed:nonce_not_the_chain_hash"}, nonce="0x" + "11" * 32)
    case("restriction_within", base_cons, 1250, {"MP5": "verified"},
         extra_arts=[("restriction", lambda om: restriction(user, om, [AmountRange(currency="USD", min=0, max=2000),
                                                                      AllowedPayees(allowed=[MERCHANT]),
                                                                      PaymentReference(conditional_transaction_id=ref),
                                                                      AllowedPaymentInstruments(allowed=[INSTRUMENT])],
                                                     now, agent))])
    case("restriction_outside", base_cons, 1250, {"MP5": "failed:payment_outside_restriction"},
         extra_arts=[("restriction", lambda om: restriction(user, om, [AmountRange(currency="USD", min=0, max=1000),
                                                                      AllowedPayees(allowed=[MERCHANT]),
                                                                      PaymentReference(conditional_transaction_id=ref),
                                                                      AllowedPaymentInstruments(allowed=[INSTRUMENT])],
                                                     now, agent))])
    case("payee_not_allowed", [AmountRange(currency="USD", min=0, max=5000),
                               AllowedPayees(allowed=[Merchant(id="other", name="Other", website="https://other.example")])],
         1250, {"MP3": "failed:payee_not_allowed"})
    case("pack_tampered", base_cons, 1250, {"MP1": "failed:ap2_pack_not_valid"},
         pack_edit=lambda p: p["artifacts"][0]["resolved_claims"].update({"x": 1}))
    case("chain_one_hop", base_cons, 1250, {"MP2": "failed:chain_not_two_hops"}, chain_edit=lambda c: c.split("~~")[0])
    for name, doc in cases.items():
        text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
        with open(os.path.join(outdir, name + ".json"), "w", encoding="utf-8") as fh:
            fh.write(text)
        manifest[name]["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with open(os.path.join(outdir, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), "ap2": "e1ea56d",
                   "ap2_evidence_pack": "v1.7.1", "cases": manifest}, fh, indent=1, sort_keys=True)
    print("%d cases in %s" % (len(cases), outdir))


if __name__ == "__main__":
    main(sys.argv[1])
