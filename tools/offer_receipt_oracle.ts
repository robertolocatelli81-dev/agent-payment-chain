// Oracle: offers and receipts made AND verified by the x402 reference implementation (4241d56, ref/*.ts copied verbatim).
// Run (outside the repo): copy signing.ts, did.ts, types.ts of sources/x402_offer_receipt_20261026 to ./ref, npm install
// --ignore-scripts jose@5.10.0 viem@2.48.11 @noble/curves@1.9.7 @scure/base@1.2.6 tsx@4.21.0 (the versions of x402 4241d56
// typescript/pnpm-lock.yaml), then: npx tsx offer_receipt_oracle.ts offer_receipt_oracle_cases.json OUT.json
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import * as jose from "jose";
import { base58 } from "@scure/base";
import { secp256k1 } from "@noble/curves/secp256k1";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/nist";
import {
  createOfferEIP712, createReceiptEIP712, createOfferJWS, createReceiptJWS,
  verifyOfferSignatureEIP712, verifyReceiptSignatureEIP712, verifyOfferSignatureJWS, verifyReceiptSignatureJWS,
} from "./ref/signing.ts";

const [inPath, outPath] = process.argv.slice(2);
const cases = JSON.parse(readFileSync(inPath, "utf8"));
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL0);
const sha = (b: Uint8Array) => new Uint8Array(createHash("sha256").update(b).digest());
const seed = (s: string) => sha(new TextEncoder().encode(s));   // fixed test keys, derived from a label
const varint = (n: number) => { const o: number[] = []; while (n >= 0x80) { o.push((n & 0x7f) | 0x80); n >>= 7; } o.push(n); return o; };
const didKey = (codec: number, pub: Uint8Array) => "did:key:z" + base58.encode(new Uint8Array([...varint(codec), ...pub]));
function signer(kind: string, label: string, kidStyle: string) {
  const d = seed(label);
  let pubRaw: Uint8Array, alg: string, kid: string, sign: (m: Uint8Array) => Uint8Array, jwk: any;
  if (kind === "EdDSA") {
    pubRaw = ed25519.getPublicKey(d); alg = "EdDSA";
    sign = (m) => ed25519.sign(m, d);
    jwk = { kty: "OKP", crv: "Ed25519", x: jose.base64url.encode(pubRaw) };
    kid = didKey(0xed, pubRaw);
  } else if (kind === "ES256K") {
    pubRaw = secp256k1.getPublicKey(d, true); alg = "ES256K";
    sign = (m) => secp256k1.sign(sha(m), d).toCompactRawBytes();
    const u = secp256k1.getPublicKey(d, false);
    jwk = { kty: "EC", crv: "secp256k1", x: jose.base64url.encode(u.slice(1, 33)), y: jose.base64url.encode(u.slice(33)) };
    kid = didKey(0xe7, pubRaw);
  } else {
    pubRaw = p256.getPublicKey(d, true); alg = "ES256";
    sign = (m) => p256.sign(sha(m), d).toCompactRawBytes();
    const u = p256.getPublicKey(d, false);
    jwk = { kty: "EC", crv: "P-256", x: jose.base64url.encode(u.slice(1, 33)), y: jose.base64url.encode(u.slice(33)) };
    kid = didKey(0x1200, pubRaw);
  }
  if (kidStyle === "jwk") kid = "did:jwk:" + jose.base64url.encode(new TextEncoder().encode(JSON.stringify(jwk)));
  if (kidStyle === "web") kid = "did:web:api.example.com#key-1";
  const uncompressed = kind === "EdDSA" ? pubRaw : (kind === "ES256K" ? secp256k1 : p256).getPublicKey(d, false);
  return { s: { kid, algorithm: alg, format: "jws", sign: async (m: Uint8Array) => jose.base64url.encode(sign(m)) },
           jwk, alg, kid, public_key: Buffer.from(uncompressed).toString("hex") };
}
const out: any[] = [];
for (const c of cases) {
  const r: any = { id: c.id, bundle: c.bundle };
  if (c.kind === "offer") {
    const input = { scheme: c.terms.scheme, network: c.terms.network, asset: c.terms.asset, payTo: c.terms.payTo,
                    amount: c.terms.amount, acceptIndex: 0, offerValiditySeconds: 3600 };
    if (c.format === "eip712") {
      r.artifact = await createOfferEIP712(c.resourceUrl, input, (p: any) => account.signTypedData(p));
      r.ref_signer = (await verifyOfferSignatureEIP712(r.artifact)).signer;
    } else {
      const k = signer(c.alg, c.id, c.kidStyle);
      r.artifact = await createOfferJWS(c.resourceUrl, input, k.s as any);
      r.ref_payload = await verifyOfferSignatureJWS(r.artifact, k.jwk);
      Object.assign(r, { alg: k.alg, kid: k.kid, public_key: k.public_key });
    }
  } else {
    const input = { resourceUrl: c.resourceUrl, payer: c.payer, network: c.network, transaction: c.transaction };
    if (c.format === "eip712") {
      r.artifact = await createReceiptEIP712(input, (p: any) => account.signTypedData(p));
      r.ref_signer = (await verifyReceiptSignatureEIP712(r.artifact)).signer;
    } else {
      const k = signer(c.alg, c.id, c.kidStyle);
      r.artifact = await createReceiptJWS(input, k.s as any);
      r.ref_payload = await verifyReceiptSignatureJWS(r.artifact, k.jwk);
      Object.assign(r, { alg: k.alg, kid: k.kid, public_key: k.public_key });
    }
  }
  out.push(r);
}
writeFileSync(outPath, JSON.stringify({ made_by: "x402 4241d56 typescript/packages/extensions/src/offer-receipt (signing.ts, did.ts, types.ts), jose 5.10.0, viem 2.48.11, @noble/curves 1.9.7, @scure/base 1.2.6, node " + process.version, eip712_signer_key: "anvil account 0 (the reference tests' TEST_PRIVATE_KEY)", vectors: out }, null, 1));
console.log(out.length, "vectors");
