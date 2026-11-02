# StillOS Notary — Frozen Signing Keys

Public key material only, pinned as static files so a verifier never needs a live HTTP call to StillOS to determine which key to trust for a given receipt. Every receipt self-identifies its signing key via its own `notary_fp` field — resolve that fingerprint against the table below, not against whatever `GET /health` returns right now.

| File | Fingerprint | Algorithm | Status | Effective | Verifies which receipts |
|---|---|---|---|---|---|
| `stillos-notary-ed25519-v1.pub` | `21de066900082465` | Ed25519 | **active** | 2026-07-31T00:09:13.684Z → present | Any receipt whose `notary_fp` is `21de066900082465` |
| `stillos-notary-ed25519-retired-2026-07-31.pub` | `921e3af51250a1f5` | Ed25519 | retired | 2026-06-27T08:39:51.304Z → 2026-07-31T00:09:13.684Z | Any receipt whose `notary_fp` is `921e3af51250a1f5` |

## Fingerprint

`notary_fp = SHA256(public_key_pem_bytes).slice(0, 16)` — first 16 hex characters (8 bytes) of the SHA-256 digest of the exact PEM text above (including header/footer lines and trailing newline).

## Rotation policy

The key has rotated exactly once in production history (2026-07-31, planned rotation, not an incident). When the key rotates again, a new `stillos-notary-ed25519-vN.pub` file is added here, the retiring key's file is kept (never deleted — it remains required to verify receipts signed before rotation), and this table's `Status`/`Effective` columns are updated in the same commit. The live, authoritative, continuously-updated version of this same registry is `GET https://nolawealthfinancial.com/notary/keyring` — these static files are a point-in-time pin of that registry for verifiers who want zero network dependency, not a replacement source of truth for future rotations.

## Historical verification policy

A receipt signed under a retired key remains fully verifiable forever — retirement means "no longer used to sign new receipts," not "no longer trusted for old ones." Never assume the CURRENT key is correct for a receipt signed under a prior key; always resolve by the receipt's own `notary_fp`.

## How to verify entirely offline, zero network calls

```
recompute receipt_hash from the receipt's own fields (see ../docs/STILLOS_NOTARY_RECEIPT_V1.md)
resolve notary_fp -> the matching .pub file in this directory
crypto.verify(null, Buffer.from(receipt_hash), <resolved public key>, Buffer.from(signature, "base64"))
```

See `../verify-offline-pinned.js` for a runnable implementation (embeds these same two keys directly, no file I/O against this directory required, so the verifier is fully self-contained).
