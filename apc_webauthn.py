"""agent-payment-chain: WebAuthn assertion of a Coinbase Smart Wallet passkey owner (SPEC 0.17, section 28).
Offline, standard library only; the P-256 ECDSA is apc_ap2.py's (FIPS 186-5).

The rule is the deployed contract's, not WebAuthn's in general: CoinbaseSmartWallet 0x000100ab (Sourcify exact match)
calls webauthn-sol's WebAuthn.verify(challenge = abi.encode(hash), requireUV = false, auth, x, y)
(sources/coinbase_smart_wallet_000100ab/CoinbaseSmartWallet.sol 316-322; 337-343 in 0x00000110), and WebAuthn.verify is
sources/coinbase_smart_wallet_000100ab_libs/lib/webauthn-sol/src/WebAuthn.sol 105-163. `verify` below accepts exactly
what those lines accept (precompile or FreshCryptoLib = ECDSA P-256 verification, FIPS 186-5); what the contract does
not read is reported by `notes`, never used for the verdict.
"""
import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_ap2  # noqa: E402

N = apc_ap2.P256_N
HALF_N = N // 2                        # WebAuthn.sol 48: FCL_Elliptic_ZZ.n / 2
TYPE = b'"type":"webauthn.get"'        # WebAuthn.sol 56 (21 bytes, line 116)
FLAG_UP, FLAG_UV = 0x01, 0x04          # WebAuthn.sol 41, 45


class NotCanonical(Exception):
    """abi.encode(WebAuthnAuth) not in the one form abi.encode produces (SPEC 28: not_evaluated, not failed)."""


def b64url(b):
    """OpenZeppelin Base64.encodeURL (Base64.sol 27-29): URL alphabet, no padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def _word(b, i):
    return int.from_bytes(b[i:i + 32], "big")


def _tail(b, off):
    """A canonical ABI `bytes`/`string` tail at `off`: length word, data, zero padding to a word; returns (data, end)."""
    n = _word(b, off)              # past the end: 0 (a short read), and the end checks of decode_auth refuse it
    end = off + 32 + (n + 31) // 32 * 32
    if any(b[off + 32 + n:end]):
        raise NotCanonical("nonzero padding")
    return b[off + 32:off + 32 + n], end


def decode_auth(data):
    """abi.encode(WebAuthnAuth{authenticatorData, clientDataJSON, challengeIndex, typeIndex, r, s}) (WebAuthn.sol
    22-37), in the canonical form only: outer offset 0x20, head of six words, first tail at 0xc0 of the head, second
    right after the first, zero padding, nothing after. Anything else raises NotCanonical."""
    if _word(data, 0) != 32:
        raise NotCanonical("outer offset not 0x20")
    h = data[32:]
    if _word(h, 0) != 0xc0:
        raise NotCanonical("authenticatorData offset not 0xc0")
    ad, end1 = _tail(h, 0xc0)
    if _word(h, 32) != end1:
        raise NotCanonical("clientDataJSON offset not right after authenticatorData")
    cdj, end2 = _tail(h, end1)
    if end2 != len(h):
        raise NotCanonical("bytes after the encoding")
    return {"authenticatorData": ad, "clientDataJSON": cdj, "challengeIndex": _word(h, 64), "typeIndex": _word(h, 96),
            "r": _word(h, 128), "s": _word(h, 160)}


def verify(challenge, auth, x, y, require_uv=False):
    """WebAuthn.sol 105-163, in its order. Returns None when the contract returns true, else the reason (the first
    check that fails; a revert of the contract, which the token reads as an invalid signature, is a reason too)."""
    cdj, ad = auth["clientDataJSON"], auth["authenticatorData"]
    if auth["s"] > HALF_N:                                                   # 110-113
        return "s_above_half_order"
    ti = auth["typeIndex"]
    # 117-120. LibString.slice clamps start and end to the length (LibString.sol 707-708), as Python's slice does; an
    # index whose + 21 overflows makes the contract revert, and here gives an empty slice: invalid either way
    if cdj[ti:ti + 21] != TYPE:
        return "type_not_webauthn_get"
    want = b'"challenge":"' + b64url(challenge) + b'"'                       # 123
    ci = auth["challengeIndex"]
    if cdj[ci:ci + len(want)] != want:                                       # 124-128 (as above)
        return "challenge_not_at_index"
    if len(ad) < 33:                                                         # 133: authenticatorData[32] reverts
        return "authenticator_data_shorter_than_33"
    if not ad[32] & FLAG_UP:                                                 # 133-135
        return "user_present_flag_not_set"
    if require_uv and not ad[32] & FLAG_UV:                                  # 139-141
        return "user_verified_flag_not_set"
    # 146-150: sha256(authenticatorData || sha256(clientDataJSON)) is the digest; es256_verify hashes its message once
    # with SHA-256, so the message passed is authenticatorData || sha256(clientDataJSON)
    return p256_check(x, y, ad + hashlib.sha256(cdj).digest(), auth["r"], auth["s"])


def p256_check(x, y, msg, r, s):
    """The ECDSA step of WebAuthn.verify over SHA-256(msg): s <= n/2 (WebAuthn.sol 110), then lines 151-162, the
    RIP-7212 precompile and, when it gives no output, FreshCryptoLib's ecdsa_verify (FCL_ecdsa.sol 40-61): r and s in
    [1, n-1], (x, y) on the curve with x, y < p and not (0, 0) (FCL_elliptic.sol 308-319), the ECDSA equation."""
    if s > HALF_N:
        return "s_above_half_order"
    if not (x < apc_ap2.P256_P and y < apc_ap2.P256_P and apc_ap2.p256_on_curve((x, y))):
        return "owner_key_not_on_p256"
    if not (0 < r < N and 0 < s < N):
        return "r_or_s_out_of_range"
    if not apc_ap2.es256_verify((x, y), msg, r.to_bytes(32, "big") + s.to_bytes(32, "big")):
        return "p256_signature_invalid"
    return None


def notes(challenge, auth, require_uv=False):
    """What WebAuthn.sol does not read (lines 62-96 list it), reported beside the verdict, never changing it."""
    out = []
    ad, cdj = auth["authenticatorData"], auth["clientDataJSON"]
    if len(ad) >= 33 and not require_uv and not ad[32] & FLAG_UV:
        out.append("WebAuthn user-verified flag not set (the wallet calls WebAuthn.verify with requireUV false, "
                   "CoinbaseSmartWallet.sol 321)")
    import apc_verify as av     # here, not at the top: apc_verify imports this module
    try:
        # SPEC 28.3 and 29.1: read as the bundle's own JSON is read (64 deep, unique members, no NaN, no lone
        # surrogate), so that no text the contract does not read can turn the verdict into an internal error
        c = av.strict_json(cdj.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, av.Refusal) as e:
        out.append("clientDataJSON is not one JSON object with unique members (%s); the contract compares two "
                   "substrings only (WebAuthn.sol 117, 125)" % str(e)[:80])
        return out
    if not isinstance(c, dict):
        out.append("clientDataJSON is not a JSON object; the contract compares two substrings only")
        return out
    if c.get("type") != "webauthn.get":
        out.append("clientDataJSON member `type` read as JSON is %r, not webauthn.get (the contract reads the "
                   "substring at typeIndex)" % (c.get("type"),))
    if c.get("challenge") != b64url(challenge).decode():
        out.append("clientDataJSON member `challenge` read as JSON is not the expected challenge (the contract reads "
                   "the substring at challengeIndex)")
    if isinstance(c.get("origin"), str):
        out.append("WebAuthn origin %r (declared by the client; not checked by the contract, WebAuthn.sol 77)"
                   % c["origin"][:100])
    if c.get("crossOrigin") is True or "topOrigin" in c:
        out.append("clientDataJSON says crossOrigin true or carries topOrigin (not checked by the contract, "
                   "WebAuthn.sol 81)")
    other = sorted(set(c) - {"type", "challenge", "origin", "crossOrigin", "topOrigin"})
    if other:
        out.append("clientDataJSON other members %s (not read by the contract)" % [k[:40] for k in other[:8]])
    return out
