"""agent-payment-chain verifier, SPEC 0.3 to 0.16.1, 0.17 (SPEC.md section 28), 0.18.1 (section 29) 0.18.2 (section 25, C1 block), 0.18.3 (section 29: drafts' own Keccak budget, RLP bound per list, exit 74), 0.18.4 (sections 17 and 29: the budget in apc_drafts too, exit 74 with standard error unwritable), 0.19.0 (section 30: evidence_level, --require-level) and 0.19.1 (section 30: neutral levels, facilitator_reply, finality_proven with l1_state proven, closed list of qualified outcomes) and 0.20.0 (section 31: the AP2 mandate as an ap2-evidence-pack 1.7.1 pack, MP1-MP7) and 0.21.0 (section 32: a 65-byte signature of a payer with code, `payer_state`, the ERC-1271 of Circle_SingleOwnerMSCA 1.0.0; apc_msca.py) and 0.21.1 (32.10: a `verified (ERC-1271 …)` read from the payer's state needs the block anchored, canonical final with l1_state proven) and 0.21.2 (32.11: the verifier's environment — the pack beside the verifier when APC_AP2EV is unset, the cause named when MP1-MP7 are not evaluated, exit 64 with one line on standard error when the signature library is absent) and 0.21.3 (32.12: the code run is the code hashed — the pack's two files and the signature library's two files of tag v1.4.0 are run from the bytes hashed, never imported by name; exit 64 also for a library of other bytes); reads apc-0.1, apc-0.2, apc-0.3, apc-0.5, apc-0.10, apc-0.12, apc-0.13, apc-0.15, apc-0.16 bundles). Offline; Python 3 standard library plus the stdlib EIP-712 and
secp256k1 of x402-signature-vectors tag v1.4.0 (path in APC_SIGLIB, default: a sibling checkout ../x402-signature-vectors (tag v1.4.0); the two files at their
hashes, apc_siglib, SPEC 32.12).

  python3 apc_verify.py BUNDLE.json [--json] [--l1-checkpoint L1_BLOCK_HASH] [--http-keys KEYS.json]
      [--signer-trust TRUST.json] [--drafts] [--require-level LEVEL] [--ap2-tsa-cert TSA.pem]
      (the report is always JSON; --json is accepted and changes nothing; --l1-checkpoint: the hash of an L1 block the
      reader trusts, from which canonical.l1_state is proven, SPEC 0.4; --http-keys: the keys the reader trusts for
      the RFC 9421 signatures of exchange, SPEC 0.8; --signer-trust: the signers the reader trusts for x402
      signed offers and receipts, SPEC 0.11; --drafts: also the draft profiles of proposed x402 rules, SPEC section 17,
      reported apart in `drafts`, the verdict unchanged; --require-level: signature, settlement_record,
      inclusion_proof or finality_proven, a chain_verified whose evidence_level is lower becomes chain_incomplete, SPEC
      30.3; --ap2-tsa-cert: the TSA certificate the reader trusts for the RFC 3161 anchors of a mandate pack, SPEC 31.7;
      a mandate pack is verified by ap2-evidence-pack v1.7.1 from the directory APC_AP2EV names, or from
      ../ap2-evidence-pack beside this folder when the variable is unset, SPEC 31 and 32.11; it needs `cryptography`)

Exit 0 chain_verified, 1 chain_failed, 2 chain_incomplete, 3 bundle outside the grammar (or unsupported, or a file that
cannot be read, or verdict `error`: an internal error of the verifier, SPEC 29.3), 64 usage (an option outside the
grammar; or the signature library of APC_SIGLIB absent or not that of tag v1.4.0: one line on standard error, no report, SPEC 32.11 and
32.12), 74 the
report could not be written (standard output closed or full, SPEC 29.3).
"""
import json
import math
import os
import re
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_siglib  # noqa: E402
try:
    # SPEC 32.12 (f): the signature library is the bytes of x402-signature-vectors tag v1.4.0 at their hashes, read from
    # APC_SIGLIB or its default and run as lib.eip712 and lib.secp256k1 (apc_siglib); never an import by name from a path.
    apc_siglib.load()
except apc_siglib.SiglibError as _e:
    # SPEC 32.11 (c): without the signature library there is no verifier, hence no verdict: one line on standard error
    # and exit 64 (the reader's invocation, section 5), never a traceback's exit 1 (= chain_failed). Any other failure is
    # not this case and is raised as it is.
    _WHY = "apc_verify: " + str(_e)
    if __name__ == "__main__":
        try:
            sys.stderr.write(_WHY + "\n")      # standard error is line-buffered (Python >= 3.9): the write flushes
        except (OSError, AttributeError, ValueError):
            # standard error closed or full: the line is lost, the exit stays 64 (as 74 does in SPEC 29.3, 0.18.4): a
            # traceback's 1 would read as chain_failed, the interpreter's last flush as 120 (SPEC 32.12 (g))
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
            except OSError:
                pass
        sys.exit(64)
    raise ImportError(_WHY) from _e
import apc_block  # noqa: E402  (first: it puts the counted Keccak-256 of SPEC 29.2 in lib.eip712)
from apc_block import keccak256  # noqa: E402
import apc_mandate  # noqa: E402
from lib.eip712 import signing_digest  # noqa: E402
from lib.secp256k1 import public_key_to_address, recover_public_key  # noqa: E402

VERSION = "apc_verify 0.21.3"
import apc_l1proof  # noqa: E402
import apc_webauthn  # noqa: E402
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Refusal(Exception):
    """Bundle outside the grammar (exit 3)."""


class Unsupported(Refusal):
    """Inside the grammar but outside the scope of 0.1 (exit 3, reported as unsupported)."""


sys.modules.setdefault("apc_verify", sys.modules[__name__])     # run as a script: apc_svm imports this same module


# ------------------------------------------------------------------ strict JSON and grammar helpers
def _no_dups(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Refusal("duplicate member %r" % k)
        out[k] = v
    return out


def _no_const(c):
    raise Refusal("non-JSON number %s" % c)


MAX_JSON_DEPTH = 64        # SPEC 29.1: arrays and objects nested at most 64 deep in every JSON text read


def _no_surrogates(doc):
    """An unpaired UTF-16 surrogate (a \\ud800 escape) is not text: it cannot be hashed as UTF-8; a number that a parser
    turned into inf (1e400) or nan is not a number (SPEC 1, 0.3.1); arrays and objects nested deeper than
    MAX_JSON_DEPTH are refused (SPEC 29.1), so that no recursive reader after this one can exhaust the stack."""
    stack = [(doc, 0)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, (dict, list)) and d >= MAX_JSON_DEPTH:
            raise Refusal("JSON nested deeper than %d (SPEC 29.1)" % MAX_JSON_DEPTH)
        if isinstance(x, dict):
            stack.extend((k, d) for k in x.keys())
            stack.extend((v, d + 1) for v in x.values())
        elif isinstance(x, list):
            stack.extend((v, d + 1) for v in x)
        elif isinstance(x, str):
            try:
                x.encode("utf-8")
            except UnicodeEncodeError:
                raise Refusal("a string holds an unpaired UTF-16 surrogate")
        elif isinstance(x, float) and not math.isfinite(x):      # inf or nan from a caller's own parser
            raise Refusal("a number outside the double range")
    return doc


EVM_VERSIONS = ("apc-0.1", "apc-0.2", "apc-0.3", "apc-0.10", "apc-0.13", "apc-0.15")
RPC_MEMBERS = ("chain_tx", "inclusion", "canonical", "payer_wallet", "payer_code", "payer_state")


def _no_upper_x(doc):
    """SPEC 29.4: in the JSON-RPC objects an EVM bundle carries, no string begins with "0X". JSON-RPC hex is "0x"
    followed by hex digits (digits compared with case ignored, Amendment 0.3.2); the members read are compared after
    lower-casing, which read "0X" as "0x" (measured on 0bf2063: of 290 member paths read, 55, in 5 bundle versions,
    took "0X"; SPEC 29.4)."""
    stack = [(doc[m], m) for m in RPC_MEMBERS if m in doc]
    while stack:
        x, path = stack.pop()
        if isinstance(x, dict):
            stack.extend((v, "%s.%s" % (path, k)) for k, v in x.items())
        elif isinstance(x, list):
            stack.extend((v, "%s[%d]" % (path, i)) for i, v in enumerate(x))
        elif isinstance(x, str) and x[:2] == "0X":
            raise Refusal("%s: \"0X\" prefix, not JSON-RPC hex (SPEC 29.4)" % path)


def strict_json(text):
    try:
        return _no_surrogates(json.loads(text, object_pairs_hook=_no_dups, parse_constant=_no_const))
    except RecursionError:
        raise Refusal("not JSON: nested too deep")
    except ValueError as e:
        if isinstance(e, Refusal):
            raise
        raise Refusal("not JSON: %s" % e)


def _obj(v, path, required, optional=()):
    if not isinstance(v, dict):
        raise Refusal("%s: not an object" % path)
    unknown = sorted(set(v) - set(required) - set(optional))
    if unknown:
        raise Refusal("%s: unknown member(s) %s" % (path, unknown))
    missing = sorted(set(required) - set(v))
    if missing:
        raise Refusal("%s: missing member(s) %s" % (path, missing))
    return v


def _str(v, path):
    if not isinstance(v, str) or not v:
        raise Refusal("%s: not a non-empty string" % path)
    return v


def _int_json(v, path):
    if isinstance(v, bool) or not isinstance(v, int):
        raise Refusal("%s: not an integer" % path)
    return v


ADDR = re.compile(r"0x[0-9a-fA-F]{40}\Z")
ERC6492_MAGIC = bytes.fromhex("64926492" * 8)
# SPEC Amendment 0.3.2: (network, asset) whose token refuses an EOA signature with s > n/2, measured by eth_call
import apc_assets  # noqa: E402
# SPEC Amendment 0.3.2, list measured again and extended by Amendment 0.11.5 (apc_assets.py)
HIGH_S_REFUSED = {k for k, v in apc_assets.ASSETS.items() if v[4]}
HASH32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")
HEXDATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
UINT = re.compile(r"(0|[1-9][0-9]*)\Z")
CAIP2_EIP155 = re.compile(r"eip155:([1-9][0-9]{0,31})\Z")


def _addr(v, path):
    _str(v, path)
    if not ADDR.match(v):
        raise Refusal("%s: not a 20-byte hex address" % path)
    return v.lower()


def _uint(v, path, bits=256):
    _str(v, path)
    if not UINT.match(v):
        raise Refusal("%s: amount_not_canonical (decimal digits, no sign, no leading zeros)" % path)
    if len(v) > len(str((1 << bits) - 1)) or int(v) >= 1 << bits:   # the digit bound keeps int() under its own limit
        raise Refusal("%s: exceeds uint%d" % (path, bits))
    return int(v)


def eip55_ok(a):
    """True if all-lower, all-upper, or a correct EIP-55 checksum."""
    h = a[2:]
    if h == h.lower() or h == h.upper():
        return True
    d = keccak256(h.lower().encode()).hex()
    return all((c.upper() if int(d[i], 16) >= 8 else c.lower()) == c for i, c in enumerate(h))


# ------------------------------------------------------------------ x402 v2 objects (SPEC 1, x402 spec 5.x)
REQ_MEMBERS = ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds")


def parse_requirements(v, path):
    _obj(v, path, REQ_MEMBERS, ("extra",))
    if _str(v["scheme"], path + ".scheme") != "exact":
        raise Unsupported("%s.scheme %r (0.1: exact only)" % (path, v["scheme"]))
    m = CAIP2_EIP155.match(_str(v["network"], path + ".network"))
    if not m:
        if v["network"].startswith("eip155:"):
            raise Refusal("%s.network %r: not eip155:<decimal chain id without leading zeros>" % (path, v["network"]))
        raise Unsupported("%s.network %r (0.1: eip155 only)" % (path, v["network"]))
    r = {"chain_id": int(m.group(1)), "network": v["network"], "amount": _uint(v["amount"], path + ".amount"),
         "asset": _addr(v["asset"], path + ".asset"), "pay_to": _addr(v["payTo"], path + ".payTo"),
         "max_timeout": _int_json(v["maxTimeoutSeconds"], path + ".maxTimeoutSeconds"), "notes": []}
    extra = v.get("extra", {})
    if not isinstance(extra, dict):
        raise Refusal("%s.extra: not an object" % path)
    method = extra.get("assetTransferMethod", "eip3009")
    if method != "eip3009":
        raise Unsupported("%s.extra.assetTransferMethod %r (0.1: eip3009 only; permit2 and erc7710 are read in an apc-0.10 "
                          "bundle, SPEC 0.10)" % (path, method))
    for k in ("name", "version"):
        if k not in extra:
            raise Refusal("%s.extra.%s missing (the EIP-712 domain of the token)" % (path, k))
        _str(extra[k], "%s.extra.%s" % (path, k))
    r["domain_name"], r["domain_version"] = extra["name"], extra["version"]
    for k in sorted(set(extra) - {"name", "version", "assetTransferMethod", "paymentFlow"}):
        r["notes"].append("%s.extra.%s present (scheme-specific, not interpreted)" % (path, k))
    for k, a in (("asset", v["asset"]), ("payTo", v["payTo"])):
        if not eip55_ok(a):
            r["notes"].append("%s.%s: mixed case with a wrong EIP-55 checksum" % (path, k))
    return r


def parse_offer(a, path):
    """SPEC 0.10 (section 12.1): an entry of payment_required.accepts of the exact scheme on eip155 is read by the grammar
    of its asset transfer method (an EIP-3009 payment may have been offered Permit2 or ERC-7710 too); other entries
    are carried."""
    if a.get("scheme") == "exact" and str(a.get("network", "")).startswith("eip155:"):
        extra = a.get("extra")
        if isinstance(extra, dict) and extra.get("assetTransferMethod") in ("permit2", "erc7710"):
            import apc_permit2
            return apc_permit2.parse_requirements(a, path)
        return parse_requirements(a, path)
    return None


def parse_payload(v):
    p = "payment_payload"
    _obj(v, p, ("x402Version", "accepted", "payload"), ("resource", "extensions"))
    if "extensions" in v and not isinstance(v["extensions"], dict):
        raise Refusal("%s.extensions: not an object" % p)
    if _int_json(v["x402Version"], p + ".x402Version") != 2:
        raise Unsupported("%s.x402Version %r (0.1: 2 only)" % (p, v["x402Version"]))
    acc = parse_requirements(v["accepted"], p + ".accepted")
    pl = _obj(v["payload"], p + ".payload", ("signature", "authorization"))
    au = _obj(pl["authorization"], p + ".payload.authorization",
              ("from", "to", "value", "validAfter", "validBefore", "nonce"))
    sig = _str(pl["signature"], p + ".payload.signature")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", sig) or len(sig) % 2:
        raise Refusal("%s.payload.signature: not even-length hex" % p)
    nonce = _str(au["nonce"], p + ".payload.authorization.nonce")
    if not HASH32.match(nonce):
        raise Refusal("%s.payload.authorization.nonce: not 32 bytes hex" % p)
    resource_url = None
    if "resource" in v:
        res = _obj(v["resource"], p + ".resource", ("url",), ("description", "mimeType"))   # x402 v2 5.2.2 ResourceInfo
        resource_url = _str(res["url"], p + ".resource.url")
    return {"accepted": acc, "raw_accepted": v["accepted"], "resource_url": resource_url,
            "signature": bytes.fromhex(sig[2:]),
            "auth": {"from": _addr(au["from"], p + "..from"), "to": _addr(au["to"], p + "..to"),
                     "value": _uint(au["value"], p + "..value"),
                     "validAfter": _uint(au["validAfter"], p + "..validAfter"),
                     "validBefore": _uint(au["validBefore"], p + "..validBefore"), "nonce": nonce.lower()}}


# ------------------------------------------------------------------ checks
TYPES = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"}, {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"}]}
DOMAIN4 = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
           {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]


def check_signature(pp):
    """L2.sig: EIP-712 (4-member domain from `accepted`) and secp256k1 recovery == authorization.from."""
    sig, acc, au = pp["signature"], pp["accepted"], pp["auth"]
    if len(sig) != 65:
        return "not_evaluated:unsupported_signature_length_%d" % len(sig), []
    v = sig[64]
    if v not in (27, 28):
        return "failed:v_not_27_or_28", []
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    high_s = s > SECP_N // 2
    notes = ["signature s in the upper half of the order (EIP-3009 does not require low-s; the token decides: SPEC "
             "Amendment 0.3.2). Its low-s twin (s' = n - s, v flipped) encodes the same authorization; a settler that "
             "normalises s can still execute it"] if high_s else []
    dom = {"name": acc["domain_name"], "version": acc["domain_version"], "chainId": acc["chain_id"],
           "verifyingContract": acc["asset"]}
    msg = dict(au)
    try:
        digest = signing_digest(dom, "TransferWithAuthorization", TYPES, msg, DOMAIN4)
        who = public_key_to_address(recover_public_key(digest, r, s, v - 27), keccak256)
    except ValueError as e:
        return "failed:no_recovery(%s)" % e, notes
    if who != au["from"]:
        return "failed:recovers_%s_not_from" % who, notes
    if high_s:      # SPEC Amendment 0.3.2: the measured tokens refuse it (Circle ECRecover.sol 51-56)
        if (acc["network"], acc["asset"]) in HIGH_S_REFUSED:
            return "failed:high_s_refused_by_token", notes
        return "not_evaluated:high_s_token_rule_not_measured", notes
    return "verified", notes


ERC1967_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# closed list (SPEC 0.2 L2.sig-1271): proxy code hash -> implementation -> wallet name
WALLET_PROXY_CODE = {"aaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d"}
WALLET_IMPL = {"0x000100abaad02f1cfc8bbe32bd5a564817339e72": "CoinbaseSmartWallet",
               "0x00000110dcdedc9581cb5ecb8467282f2926534d": "CoinbaseSmartWallet"}     # SPEC 28.3
WALLET_7702 = {"0x7702cb554e6bfb442cb743a7df23154544a7176c"}     # EIP-7702 delegate: Coinbase EIP7702Proxy


def _reply(r, path, method, params):
    _obj(r, path, ("method", "params", "result"))
    if r["method"] != method or not isinstance(r["params"], list) or len(r["params"]) != len(params):
        raise Refusal("%s: not a %s reply" % (path, method))
    for i, (got, want) in enumerate(zip(r["params"], params)):
        # SPEC Amendment 0.3.2: JSON-RPC hex is "0x" then hex digits; the digits compare with case ignored
        vals = list(got.values()) if isinstance(got, dict) else [got]
        if not all(isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]*", v) for v in vals):
            raise Refusal("%s.params[%d]: not 0x-prefixed hex" % (path, i))
        g = got.lower() if isinstance(got, str) else got
        if isinstance(want, dict):
            if not isinstance(got, dict) or {k: v.lower() for k, v in got.items()} != want:
                return "failed:%s_params_%d" % (path.split(".")[-1], i)
        elif g != want:
            return "failed:%s_params_%d" % (path.split(".")[-1], i)
    return _str(r["result"], path + ".result")


def _abi_bytes(b, off, path):
    """Strict ABI `bytes` at offset `off` of b: length word, data, zero padding; returns (data, end)."""
    if off + 32 > len(b):
        raise Refusal("%s: bytes offset out of range" % path)
    n = int.from_bytes(b[off:off + 32], "big")
    end = off + 32 + (n + 31) // 32 * 32
    if end > len(b) or any(b[off + 32 + n:end]):
        raise Refusal("%s: bytes length or padding" % path)
    return b[off + 32:off + 32 + n], end


def check_signature_1271(pp, pw, tx_block, has_chain_tx=False):
    """SPEC 0.2 L2.sig-1271: Coinbase Smart Wallet payer, owner an address."""
    if pw is None:
        return "not_evaluated:contract_wallet_needs_payer_wallet", []
    _obj(pw, "payer_wallet", ("owner_index", "code", "implementation", "owner"))
    idx = _uint(pw["owner_index"], "payer_wallet.owner_index")
    for k in ("code", "implementation", "owner"):
        _obj(pw[k], "payer_wallet." + k, ("method", "params", "result"))
        if not isinstance(pw[k]["params"], list) or not pw[k]["params"]:
            raise Refusal("payer_wallet.%s.params: not a non-empty array" % k)
    blk = pw["code"]["params"][-1]
    if not isinstance(blk, str):
        raise Refusal("payer_wallet.code: no block")
    _q(blk, "payer_wallet.code.params[1]")
    if has_chain_tx:
        _q(tx_block, "chain_tx.tx.blockNumber")    # payer_wallet is read at the transaction's block: it must be named
    if tx_block is not None and blk.lower() != str(tx_block).lower():
        return "failed:payer_wallet_block_not_tx_block", []
    frm, sel = pp["auth"]["from"], "0x" + keccak256(b"ownerAtIndex(uint256)")[:4].hex() + "%064x" % idx
    code = _reply(pw["code"], "payer_wallet.code", "eth_getCode", [frm, blk.lower()])
    impl = _reply(pw["implementation"], "payer_wallet.implementation", "eth_getStorageAt", [frm, ERC1967_SLOT, blk.lower()])
    own = _reply(pw["owner"], "payer_wallet.owner", "eth_call", [{"to": frm, "data": sel}, blk.lower()])
    for x in (code, impl, own):
        if x.startswith("failed:"):
            return x, []
    cb = _d(code, "payer_wallet.code.result")
    if keccak256(cb).hex() not in WALLET_PROXY_CODE and not (
            len(cb) == 23 and cb[:3] == b"\xef\x01\x00" and "0x" + cb[3:].hex() in WALLET_7702):
        return "not_evaluated:wallet_implementation_not_known", []
    ib = _d(impl, "payer_wallet.implementation.result", 32)
    if ib[:12] != bytes(12) or ("0x" + ib[12:].hex()) not in WALLET_IMPL:
        return "not_evaluated:wallet_implementation_not_known", []
    name = WALLET_IMPL["0x" + ib[12:].hex()]
    sig = pp["signature"]
    if len(sig) == 65:      # SPEC 32.3 point 3: the wallet ABI-decodes a SignatureWrapper, which 65 raw bytes are not
        return "failed:payer_wallet_with_a_65_byte_signature", []
    if len(sig) < 96 or int.from_bytes(sig[:32], "big") != 32 or int.from_bytes(sig[64:96], "big") != 64:
        raise Refusal("payment_payload.payload.signature: not abi.encode(SignatureWrapper)")
    data, end = _abi_bytes(sig[32:], 64, "payment_payload.payload.signature")
    if 32 + end != len(sig):
        raise Refusal("payment_payload.payload.signature: bytes after the SignatureWrapper")
    if int.from_bytes(sig[32:64], "big") != idx:
        return "failed:wrapper_owner_index_not_payer_wallet_owner_index", []
    ob = _d(own, "payer_wallet.owner.result")
    if len(ob) < 64 or int.from_bytes(ob[:32], "big") != 32:
        raise Refusal("payer_wallet.owner.result: not abi-encoded bytes")
    owner, oend = _abi_bytes(ob, 32, "payer_wallet.owner.result")
    if oend != len(ob):
        raise Refusal("payer_wallet.owner.result: data after the bytes")
    acc = pp["accepted"]
    d = signing_digest({"name": acc["domain_name"], "version": acc["domain_version"], "chainId": acc["chain_id"],
                        "verifyingContract": acc["asset"]}, "TransferWithAuthorization", TYPES, dict(pp["auth"]), DOMAIN4)
    dom = keccak256(keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
                    + keccak256(b"Coinbase Smart Wallet") + keccak256(b"1") + acc["chain_id"].to_bytes(32, "big")
                    + bytes(12) + bytes.fromhex(frm[2:]))
    h = keccak256(b"\x19\x01" + dom + keccak256(keccak256(b"CoinbaseSmartWalletMessage(bytes32 hash)") + d))
    notes = ["payer is a %s (ERC-1271); its owner and implementation are chain state at block %s, read by RPC"
             % (name, blk.lower())]
    if len(owner) == 64:        # SPEC 28.3: a P-256 key, WebAuthn.verify(abi.encode(h), requireUV false)
        try:
            auth = apc_webauthn.decode_auth(data)
        except apc_webauthn.NotCanonical as e:
            return "not_evaluated:webauthn_auth_not_canonical_abi(%s)" % e, notes
        why = apc_webauthn.verify(h, auth, int.from_bytes(owner[:32], "big"), int.from_bytes(owner[32:], "big"))
        notes += apc_webauthn.notes(h, auth)
        return ("verified (ERC-1271 %s, passkey)" % name if why is None else "failed:webauthn_%s" % why), notes
    if len(owner) != 32 or owner[:12] != bytes(12):
        return "failed:owner_not_an_address", []
    if len(data) == 64:         # SPEC 28.3: EIP-2098 compact (SignatureCheckerLib.sol 44-63)
        vs = int.from_bytes(data[32:], "big")
        data = data[:32] + (vs & ((1 << 255) - 1)).to_bytes(32, "big") + bytes([27 + (vs >> 255)])
        notes.append("owner signature in the 64-byte EIP-2098 form")
    if len(data) != 65 or data[64] not in (27, 28):
        return "failed:owner_signature_not_65_bytes_v27_28", []
    r, s_ = int.from_bytes(data[:32], "big"), int.from_bytes(data[32:64], "big")
    try:
        who = public_key_to_address(recover_public_key(h, r, s_, data[64] - 27), keccak256)
    except ValueError as e:
        return "failed:no_recovery(%s)" % e, []
    return ("verified (ERC-1271 %s)" % name if who == "0x" + owner[12:].hex()
            else "failed:owner_signature_recovers_%s" % who), notes


ANCHOR_CHECKS = ("B1", "B2", "B3", "B4", "O1", "O2", "O3", "O4", "L1")


def block_anchored(res):
    """SPEC 32.10: whether the block of inclusion.block_header is tied to the chain by something outside the bundle. The
    predicate is the one of finality_proven (SPEC 30.1, evidence): block_bound (B1-B4), canonical final (O1-O4) and
    l1_state proven (L1: the eight L1 replies recomputed from proofs under an L1 header chained to --l1-checkpoint).
    Every other block — carried RPC data, or a header that hashes and binds the transaction but that no reader's
    checkpoint vouches for — is the block the bundle chooses."""
    return all(res.get(k) == "verified" for k in ANCHOR_CHECKS)


def _l2_sig(doc, pp, tx_block, res, v02, v03):
    """L2.sig of an EIP-3009 bundle (SPEC section 3, 0.3.2, 32.2-32.6 and 32.10): (result, notes, payer_state report
    member)."""
    # executed: C1 and C2 verified, and not contradicted by a proven receipt that says the transaction reverted or does
    # not hold the carried logs (B3 failed: the AuthorizationUsed log is not the chain's)
    sig = pp["signature"]
    executed = res.get("C1") == "verified" and res.get("C2") == "verified" and not str(res.get("B3", "")).startswith("failed")
    acc = pp["accepted"]
    ai = apc_assets.info(acc["network"], acc["asset"], acc["amount"])
    measured = ai is not None and (acc["domain_name"], acc["domain_version"]) == (ai["eip712"]["name"], ai["eip712"]["version"])
    state, st = None, None
    if "payer_state" in doc:                            # SPEC 32.4: the state is read whatever the signature's form
        import apc_msca
        st = apc_msca.payer_state(doc["payer_state"], pp, tx_block, doc.get("inclusion") if v03 else None, res.get("B1"))
        if not isinstance(st, str):
            state = st[2]
    if v03 and sig.endswith(ERC6492_MAGIC):
        # ERC-6492 (Final, ethereum/ERCs 8dd085d): the magic suffix is checked before ERC-1271 and ecrecover
        return "not_evaluated:erc6492_counterfactual_signature", [
            "L2.sig: the signature ends in the ERC-6492 magic bytes: its verification needs the factory call it carries "
            "to run first, which this offline verifier does not do; a facilitator that runs it executes calldata chosen "
            "by the payer (the asset-theft class of arXiv 2607.19545)"], state
    member = None
    # SPEC 32.10 (review 2, 2026-11-01): the state is anchored only when it is READ from the anchored block (the proof
    # form, proven at block N-1 and N); a declared rpc state beside an anchored inclusion is still declared, and
    # payer_wallet (section 3) is declared too
    anchored = block_anchored(res) and state == "proven_at_parent_and_block"
    if st is not None:                                  # SPEC 32.3 point 2
        member = "payer_state"
        if isinstance(st, str):
            r, n = st, []
        else:
            r, n = apc_msca.check(pp, st)
            if r.startswith("verified (") and not anchored:
                # SPEC 32.10 (Amendment 0.21.1): a `verified (ERC-1271 …)` of 32.6 is decided by values read from the
                # state of a block (owner, implementation, code hash); that block is tied to the chain only by the
                # predicate of finality_proven (SPEC 30.1: canonical final and l1_state proven from the reader's
                # checkpoint). A declared state, or one proven under a block hash that nothing outside the bundle
                # vouches for, is the state the bundle chooses: never verified
                n = n + [("L2.sig: the rule of SPEC 32.6 ends in %s, read from the payer's state declared by RPC; a "
                          "declared state is not read from any block, anchored or not (the proof form is), so it is "
                          "not verified here (SPEC 32.10)" % r) if state == "declared_rpc" else
                         ("L2.sig: the rule of SPEC 32.6 ends in %s, read from the payer's state proven under the "
                          "carried block header; that state binds the owner to a block that nothing outside the bundle "
                          "vouches for (B1-B4, O1-O4 and L1 must all be verified: canonical final with l1_state proven "
                          "from --l1-checkpoint, SPEC 30.1), so it is not verified here (SPEC 32.10)" % r)]
                r = "not_evaluated:payer_state_block_not_anchored"
    elif v02 and ("payer_wallet" in doc or len(sig) != 65):    # SPEC 32.3 point 3, and section 3 for another length
        member = "payer_wallet" if "payer_wallet" in doc else None
        r, n = check_signature_1271(pp, doc.get("payer_wallet"), tx_block, "chain_tx" in doc)
        if r == "not_evaluated:contract_wallet_needs_payer_wallet":
            n = n + ["L2.sig: a signature of %d bytes is a contract wallet's; the bundle carries neither payer_wallet "
                     "(section 3) nor payer_state (SPEC 32.4)" % len(sig)]
    else:
        r, n = check_signature(pp)
        if r.startswith("failed:recovers_") and executed and measured:
            # SPEC 32.2: the transaction carries this very signature and these arguments (C1) and the token logged
            # AuthorizationUsed (C2); the digest is the token's (a measured asset under its measured EIP-712 domain, SPEC
            # 0.11.5): USDC accepts a signature that does not recover `from` only through the payer's isValidSignature,
            # so the payer had code at that block (or the token was not the measured implementation)
            r = "not_evaluated:signature_accepted_on_chain_needs_payer_state"
            n = n + ["L2.sig: the signature does not recover the payer as an account without code, and it is the one the "
                     "transaction carries, which the token executed (AuthorizationUsed): the payer had code at that block "
                     "and its isValidSignature accepted it (ERC-1271, SPEC 32.2) or the token was not the measured "
                     "implementation; which rule accepted it is shown by payer_state (SPEC 32.4), not by the chain_tx"]
    if member is not None and len(sig) == 65 and r.startswith("not_evaluated:") and not anchored \
            and not (executed and measured):
        # SPEC 32.3 (review 2026-11-01) and 32.10: a member the bundle declares (payer_state by rpc, payer_wallet) or
        # proves under a block that is not anchored is unsigned like accepted.extra; it does not take a 65-byte
        # signature whose section-3 recovery fails out of `failed` unless the conditions of 32.2 hold (the token
        # executed this signature, measured asset and domain)
        r0, n0 = check_signature(pp)
        if r0.startswith("failed:"):
            r, n = r0, n0 + n + ["L2.sig: %s says %s, but it is not anchored to the chain (declared, or proven under a "
                                 "block no reader's checkpoint vouches for), and without the conditions of SPEC 32.2 it "
                                 "does not lift a 65-byte signature whose recovery fails" % (member, r)]
    if r == "failed:high_s_refused_by_token" and executed:
        # SPEC Amendment 0.3.2: the transaction carries this very high-s signature and the token's AuthorizationUsed
        # log: the token accepted it, which Circle's code does only through ERC-1271 (a payer with code at that
        # block, e.g. an EIP-7702 delegation) or a token implementation other than the measured one
        r = "not_evaluated:high_s_accepted_on_chain"
        n = n + ["L2.sig: the high-s signature is the one the transaction carries and the token logged "
                 "AuthorizationUsed: it was accepted, so the payer had code at that block (ERC-1271, not "
                 "evaluated for a 65-byte signature) or the token was not the measured implementation"]
    return r, n, state


def _json_eq(a, b):
    """JSON deep equality: true and false are not numbers (Python's True == 1 is not used), numbers by value.
    Iterative: a value nested as deep as the JSON parser allows is compared without recursion."""
    stack = [(a, b)]
    while stack:
        x, y = stack.pop()
        if isinstance(x, bool) or isinstance(y, bool):
            ok = type(x) is type(y) and x == y
        elif isinstance(x, dict):
            ok = isinstance(y, dict) and x.keys() == y.keys()
            if ok:
                stack.extend((x[k], y[k]) for k in x)
        elif isinstance(x, list):
            ok = isinstance(y, list) and len(x) == len(y)
            if ok:
                stack.extend(zip(x, y))
        elif isinstance(x, (int, float)):
            ok = isinstance(y, (int, float)) and x == y
        else:
            ok = type(x) is type(y) and x == y
        if not ok:
            return False
    return True


def eq(a, b, what):
    return "verified" if a == b else "failed:%s_mismatch" % what


# SPEC section 23: members that only draft profiles define; the merged rules read the bundle without them
DRAFT_RESOURCE_MEMBERS = ("method",)      # x402 PR 3741: resource.method


def _split_drafts(doc, drafts):
    """(the bundle the merged rules read, what was taken out for the draft profiles). `draft_artifacts` is a member of
    every bundle version (SPEC section 23), read only by draft profiles; with --drafts, a resource member a draft
    defines (PR 3741 `method`) is taken out too, and without --drafts it stays and the merged grammar refuses it."""
    if not isinstance(doc, dict):
        return doc, {}
    out, taken = doc, {}
    if "draft_artifacts" in doc:
        da = doc["draft_artifacts"]
        if not isinstance(da, list) or not 1 <= len(da) <= 64:
            raise Refusal("draft_artifacts: not a list of 1..64 entries")
        for i, e in enumerate(da):
            _obj(e, "draft_artifacts[%d]" % i, ("profile", "artifact"))
            _str(e["profile"], "draft_artifacts[%d].profile" % i)
        out = {k: v for k, v in doc.items() if k != "draft_artifacts"}
        taken["draft_artifacts"] = da
    if drafts:
        for m in ("payment_payload", "payment_required"):
            r = out.get(m, {}).get("resource") if isinstance(out.get(m), dict) else None
            if isinstance(r, dict) and any(k in r for k in DRAFT_RESOURCE_MEMBERS):
                out = dict(out, **{m: dict(out[m], resource={k: v for k, v in r.items()
                                                              if k not in DRAFT_RESOURCE_MEMBERS})})
                taken.setdefault("resource", {})[m] = {k: r[k] for k in DRAFT_RESOURCE_MEMBERS if k in r}
    return out, taken


def verify_bundle(doc, l1_checkpoint=None, http_keys=None, signer_trust=None, drafts=False):
    """drafts: also run the draft profiles of SPEC sections 17 and 23 (report member `drafts`, never the verdict).
    The bytes hashed with Keccak-256 are counted against apc_block.KECCAK_BUDGET (SPEC 29.2)."""
    outer = apc_block.KECCAK_SPENT is None
    if outer:
        apc_block.KECCAK_SPENT = 0
    try:
        return _verify_counted(doc, l1_checkpoint, http_keys, signer_trust, drafts)
    except apc_block.HashBudget as e:
        raise Refusal(str(e))
    finally:
        if outer:
            apc_block.KECCAK_SPENT = None


def _verify_counted(doc, l1_checkpoint, http_keys, signer_trust, drafts):
    main, taken = _split_drafts(doc, drafts)
    out = _verify_bundle(main, l1_checkpoint, http_keys, signer_trust)
    # SPEC 30.1: before the draft profiles
    out["evidence_level"], out["facilitator_reply"], en = evidence(main["bundle_version"], out)
    if en:
        out["notes"] = out["notes"] + en
    if taken:
        out["notes"] = out["notes"] + ["draft members carried, read only by the draft profiles (SPEC section 23): %s"
                                       % ", ".join(sorted(taken))]
    if drafts:
        # SPEC 29.2 and section 17: the draft profiles hash under a Keccak-256 budget of their own, opened after the
        # merged rules; a profile past it reports it in its checks and never changes the verdict, checks or exit
        spent, apc_block.KECCAK_SPENT = apc_block.KECCAK_SPENT, 0
        try:
            import apc_drafts
            import apc_offer
            trust = apc_offer.parse_trust(signer_trust) if signer_trust is not None else None
            out["drafts"] = apc_drafts.run(main, out, trust)
            import apc_drafts2
            import apc_drafts3
            out["drafts"].update(apc_drafts2.run(main, out, trust, taken))
            out["drafts"].update(apc_drafts3.run(main, out, trust, taken))
        finally:
            apc_block.KECCAK_SPENT = spent
    return out


DRAFT_BUDGET_CHECKS = {"budget": "not_evaluated:keccak_budget"}     # SPEC 29.2: a draft profile past the drafts' budget


def _verify_bundle(doc, l1_checkpoint=None, http_keys=None, signer_trust=None):
    """l1_checkpoint: the hash of an L1 block the reader trusts (SPEC 0.4), or None. http_keys: the reader's keys for
    the RFC 9421 signatures of exchange (SPEC 0.8, the apc_http_keys document), or None. signer_trust: the reader's
    apc_signer_trust document for signed offers and receipts (SPEC 0.11), or None."""
    _no_surrogates(doc)         # also for a caller that did not parse with strict_json
    ver = doc.get("bundle_version") if isinstance(doc, dict) else None
    if ver in EVM_VERSIONS:
        _no_upper_x(doc)
    if ver == "apc-0.16":       # SPEC 0.16 (section 26): XRP Ledger
        import apc_xrp
        return dict(apc_xrp.verify(doc, l1_checkpoint, http_keys, signer_trust), verifier=VERSION)
    if ver == "apc-0.15":       # SPEC 0.15 (section 25): scheme auth-capture on EVM
        import apc_authcap
        return dict(apc_authcap.verify(doc, http_keys, signer_trust), verifier=VERSION)
    if ver == "apc-0.13":       # SPEC 0.13 (section 21): x402 version 1
        import apc_v1
        return dict(apc_v1.verify(doc, l1_checkpoint, signer_trust), verifier=VERSION)
    if ver == "apc-0.12":       # SPEC 0.12 (section 20): Stellar
        import apc_xlm
        return dict(apc_xlm.verify(doc, http_keys, signer_trust), verifier=VERSION)
    if ver == "apc-0.5":        # SPEC 0.5 (section 7): Solana
        import apc_svm
        return dict(apc_svm.verify(doc, http_keys, signer_trust), verifier=VERSION)
    if ver == "apc-0.10":        # SPEC 0.10 (section 12): EVM exact by Permit2 or ERC-7710
        import apc_permit2
        return dict(apc_permit2.verify(doc, http_keys, l1_checkpoint, signer_trust), verifier=VERSION)
    v02, v03 = ver in ("apc-0.2", "apc-0.3"), ver == "apc-0.3"
    _obj(doc, "bundle", ("bundle_version", "payment_payload"),
         ("payment_required", "settlement", "chain_tx", "acceptance", "mandate")
         + (("payer_wallet", "payer_state") if v02 else ())
         + (("inclusion", "canonical", "facilitator", "provenance", "exchange") if v03 else ())
         + (("exchange_mcp", "exchange_a2a") if v03 else ()))
    if doc["bundle_version"] not in ("apc-0.1", "apc-0.2", "apc-0.3"):
        raise Refusal("bundle_version %r (this verifier reads apc-0.1, apc-0.2, apc-0.3, apc-0.5, apc-0.10, apc-0.12, apc-0.13, apc-0.15 and apc-0.16)"
                      % doc["bundle_version"])
    pp = parse_payload(doc["payment_payload"])
    acc, au = pp["accepted"], pp["auth"]
    res, notes = {}, list(acc["notes"])
    tx_block = None
    if isinstance(doc.get("chain_tx"), dict) and isinstance(doc["chain_tx"].get("tx"), dict):
        tx_block = doc["chain_tx"]["tx"].get("blockNumber")
    if "payer_state" in doc and "payer_wallet" in doc:
        raise Refusal("payer_state and payer_wallet: one member says what the payer is (SPEC 32.3)")
    res["K1"] = eq(au["to"], acc["pay_to"], "to_payTo")
    res["K2"] = eq(au["value"], acc["amount"], "value_amount")
    # SPEC 0.3 K6, every bundle version since Amendment 0.3.2: a zero-value payment pays nothing; our rule
    res["K6"] = "verified" if au["value"] > 0 else "failed:zero_amount"
    if "payment_required" in doc:
        pr = _obj(doc["payment_required"], "payment_required", ("x402Version", "resource", "accepts"),
                  ("error", "extensions"))
        if _int_json(pr["x402Version"], "payment_required.x402Version") != 2:     # as payment_payload (independent review 25/10)
            raise Unsupported("payment_required.x402Version %r (2 only)" % (pr["x402Version"],))
        if "error" in pr and not isinstance(pr["error"], str):
            raise Refusal("payment_required.error: not a string")
        if not isinstance(pr["accepts"], list) or not pr["accepts"]:
            raise Refusal("payment_required.accepts: not a non-empty array")
        for i, a in enumerate(pr["accepts"]):
            if not isinstance(a, dict):
                raise Refusal("payment_required.accepts[%d]: not an object" % i)
            if a.get("scheme") == "exact" and str(a.get("network", "")).startswith("eip155:"):
                parse_offer(a, "payment_required.accepts[%d]" % i)
        _obj(pr["resource"], "payment_required.resource", ("url",), ("description", "mimeType"))
        if "extensions" in pr and not isinstance(pr["extensions"], dict):
            raise Refusal("payment_required.extensions: not an object")
        res["K4"] = ("verified" if any(_json_eq(pp["raw_accepted"], a) for a in pr["accepts"])
                     else "failed:accepted_not_offered")
        if pp["resource_url"] is not None:
            url = _str(pr["resource"]["url"], "payment_required.resource.url")
            if pp["resource_url"] != url:
                res["K4"] = "failed:resource_url_mismatch"
    else:
        res["K4"] = "not_evaluated:absent:no_payment_required"
    if au["validAfter"] >= au["validBefore"]:
        res["K5"] = "failed:empty_validity_window"
    else:
        res["K5"] = "verified"
        notes.append("validity window %d s; accepted.maxTimeoutSeconds %d (relation not stated by the spec)"
                     % (au["validBefore"] - au["validAfter"], acc["max_timeout"]))
    tx_hash = failed_named = None
    reverted = False
    if "settlement" in doc:
        st = _obj(doc["settlement"], "settlement", ("success", "transaction", "network"),
                  ("errorReason", "payer", "amount", "extensions"))
        if not isinstance(st["success"], bool):     # x402 v2 5.3.2: success is a boolean, required
            raise Refusal("settlement.success: not a boolean")
        if st["success"] is not True:
            res["T1"] = "failed:settlement_not_successful"
            if isinstance(st["transaction"], str) and HASH32.match(st["transaction"]):
                failed_named = st["transaction"].lower()
            if st.get("errorReason") == "settlement_pending":
                # x402 v2 section 9 (x402 #3083, 2026-08-17): non-terminal, the broadcast transaction may still confirm;
                # it MUST carry a non-empty transaction. The reply does not say the payment failed.
                res["T1"] = ("not_evaluated:settlement_pending" if failed_named is not None
                             else "failed:settlement_pending_without_transaction_hash")
        elif not isinstance(st["transaction"], str) or not HASH32.match(st["transaction"]):
            res["T1"] = "failed:transaction_not_a_32_byte_hash"
        else:
            res["T1"] = "verified"
            tx_hash = st["transaction"].lower()
        if "extensions" in st and not isinstance(st["extensions"], dict):
            raise Refusal("settlement.extensions: not an object")
        t2 = [eq(_str(st["network"], "settlement.network"), acc["network"], "network")]
        if "payer" in st:
            t2.append(eq(_addr(st["payer"], "settlement.payer"), au["from"], "payer"))
        if "amount" in st:
            t2.append(eq(_uint(st["amount"], "settlement.amount"), acc["amount"], "amount"))
        res["T2"] = next((x for x in t2 if x != "verified"), "verified")
    else:
        res["T1"] = res["T2"] = "not_evaluated:absent:no_settlement"
    if v03 and "canonical" in doc and "inclusion" not in doc:
        raise Refusal("canonical without inclusion")
    del BUILDER[:]
    if "chain_tx" in doc:
        del CHAIN_NOTES[:]
        res["C1"], res["C2"], c3 = check_chain(doc["chain_tx"], pp, tx_hash, v02,
                                               logs_optional=v03 and "inclusion" in doc)
        if v02:
            res["C3"] = c3
            res["F1"] = check_forward(doc["chain_tx"], pp)
        notes += CHAIN_NOTES
        if res.get("T1") in ("failed:settlement_not_successful", "not_evaluated:settlement_pending") \
                and _executed(res, v02):
            # SPEC Amendment 0.3.2: the facilitator reported a failure, the chain shows this authorization executed
            pending = res["T1"] == "not_evaluated:settlement_pending"
            res["T1"] = ("not_evaluated:settlement_pending_executed_on_chain" if pending
                         else "failed:settlement_reported_failed_but_executed_on_chain")
            ran = str(doc["chain_tx"]["tx"]["hash"]).lower()
            notes.append("T1: the settlement reply %s, and the chain_tx the bundle carries shows this "
                         "authorization executed (C1-C2%s verified): the payer was charged, if that transaction is on "
                         "the canonical chain (C2 note; B and O in apc-0.3) (x402 issue #1062)%s"
                         % ("is settlement_pending (x402 v2 section 9: non-terminal, it does not say the payment "
                            "failed)" if pending else "says the payment did not succeed", "-C3" if v02 else "",
                            "" if failed_named is None else
                            "; it is the transaction the reply names" if failed_named == ran else
                            "; the reply names %s, another transaction executed it (the preemption pattern of arXiv "
                            "2605.11781 I-B)" % failed_named))
        if v03 and "inclusion" in doc:
            b, e1 = check_inclusion(doc["inclusion"], doc["chain_tx"], au)
            res.update(b)
            notes += e1
            tx = doc["chain_tx"]["tx"]
            if res["B3"] == "failed:receipt_status_not_success" and res["B1"] == "verified" and res["B2"] == "verified" \
                    and res["C1"] == "verified" and tx_hash_eip1559(tx) == str(tx.get("hash", "")).lower():
                # SPEC Amendment 0.3.3: the proven receipt says the transaction reverted; B2 binds its hash to the
                # block, the recomputed hash binds the fields C1 read to that hash
                reverted = True
                notes.append("B3: the transaction is in the block and REVERTED (receipt status 0): this authorization "
                             "was not executed by it and the payer was not charged by it")
                if res.get("T1") == "verified" and tx_hash == str(tx.get("hash", "")).lower():
                    res["T1"] = "failed:settlement_reported_success_but_reverted"
                    notes.append("T1: the settlement reply says success for a transaction the block shows reverted "
                                 "(arXiv 2607.19545 SR4)")
            if "canonical" in doc:
                o, on = check_canonical(doc["canonical"], doc["inclusion"]["block_header"], acc["network"],
                                        l1_checkpoint)
                res.update(o)
                notes += on
            else:
                res["O1"] = res["O2"] = res["O3"] = res["O4"] = res["L1"] = "not_evaluated:absent:no_canonical"
            notes.append("inclusion: the transaction and its receipt are bound to the block hash in inclusion.block_header "
                         "(B1-B3); " + ("whether that block is on the canonical chain is shown only by O1-O4, from the "
                                       "L1 replies the bundle carries (SPEC O)" if "canonical" in doc else
                                       "whether that block is on the canonical chain is not decided by this verifier "
                                       "(SPEC B)"))
        else:
            notes.append("chain_tx is RPC data carried by the bundle: C2 recomputes the transaction hash from its fields; "
                         "nothing here shows that the transaction or its logs are in a block of the canonical chain (SPEC C2)")
            if v03:
                res["B1"] = res["B2"] = res["B3"] = res["B4"] = "not_evaluated:absent:no_inclusion"
                res["O1"] = res["O2"] = res["O3"] = res["O4"] = res["L1"] = "not_evaluated:absent:no_inclusion"
    elif v03 and ("inclusion" in doc or "canonical" in doc):
        raise Refusal("inclusion or canonical without chain_tx")
    else:
        res["C1"] = res["C2"] = "not_evaluated:absent:no_chain_tx"
        if v03:
            res["B1"] = res["B2"] = res["B3"] = res["B4"] = "not_evaluated:absent:no_chain_tx"
            res["O1"] = res["O2"] = res["O3"] = res["O4"] = res["L1"] = "not_evaluated:absent:no_chain_tx"
        if v02:
            res["C3"] = "not_evaluated:absent:no_chain_tx"
            res["F1"] = "not_evaluated:absent:no_chain_tx"
    # L2.sig and K3 are decided after the chain checks: the exceptions of Amendment 0.3.2 and SPEC 32.2 read C1 and
    # C2, and the proof form of payer_state (SPEC 32.4) reads B1
    res["L2.sig"], n, state = _l2_sig(doc, pp, tx_block, res, v02, v03)
    notes += n
    # K3: the signed domain is built from accepted.network and accepted.asset, so K3 holds exactly when L2.sig does;
    # a failure cannot tell a wrong domain from a wrong signer
    res["K3"] = ("verified (by L2.sig)" if res["L2.sig"].startswith("verified")
                 else "failed:by_L2.sig" if res["L2.sig"].startswith("failed") else "not_evaluated:by_L2.sig")
    if res["L2.sig"] == "not_evaluated:high_s_accepted_on_chain":      # SPEC Amendment 0.3.2: K3 carries the same reason
        res["K3"] = res["L2.sig"]
    if v03:     # SPEC Amendment 0.3.3: who sent the settlement transaction, and is it a declared facilitator signer
        settled_by = None
        if isinstance(doc.get("chain_tx"), dict) and isinstance(doc["chain_tx"].get("tx"), dict) \
                and res.get("C2") in ("verified", "not_evaluated:no_log_authorization_used"):
            settled_by = tx_sender_eip1559(doc["chain_tx"]["tx"])
        if "facilitator" in doc:
            fc = _obj(doc["facilitator"], "facilitator", ("signers", "source", "fetched"))
            if not isinstance(fc["signers"], list) or not 1 <= len(fc["signers"]) <= 256:
                raise Refusal("facilitator.signers: not a list of 1..256 addresses")
            signers = {_addr(a, "facilitator.signers[]") for a in fc["signers"]}
            _str(fc["source"], "facilitator.source")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", _str(fc["fetched"], "facilitator.fetched")):
                raise Refusal("facilitator.fetched: not YYYY-MM-DDTHH:MM:SSZ")
            if settled_by is None:
                res["F2"] = "not_evaluated:settled_by_not_recovered"
            elif settled_by in signers:
                res["F2"] = "verified"
            else:
                res["F2"] = "failed:settled_by_not_a_facilitator_signer"
                notes.append("F2: the settlement transaction was sent by %s, not by a signer of the declared facilitator "
                             "list (%s, fetched %s; declared data): someone else submitted it (the preemption pattern "
                             "of arXiv 2605.11781 I-B) or the list is out of date" % (settled_by, fc["source"], fc["fetched"]))
        else:
            res["F2"] = "not_evaluated:absent:no_facilitator"
    if "acceptance" in doc:
        res["A1"], res["A2"] = check_acceptance(doc["acceptance"], pp, tx_hash)
    else:
        res["A1"] = res["A2"] = "not_evaluated:absent:no_acceptance"
    mandate_ap2ev = None
    if "mandate" in doc:
        if not isinstance(doc["mandate"], dict):
            raise Refusal("mandate: not an object")
        if doc["mandate"].get("profile") == "pulse-ap2-x402/0.3":
            res["M1"], mn = check_mandate(doc["mandate"], doc["payment_payload"])        # SPEC 0.7
            notes += mn
        elif doc["mandate"].get("profile") == apc_mandate.PROFILE:                      # SPEC 0.20 (section 31)
            try:
                mandate_ap2ev = apc_mandate.parse_member(doc["mandate"])
            except ValueError as e:
                raise Refusal(str(e))
            res["M1"] = "not_applicable:mandate_profile_" + apc_mandate.PROFILE
        else:
            res["M1"] = "not_evaluated:ap2_has_no_x402_binding"
    else:
        res["M1"] = "not_evaluated:absent:no_mandate"
    xm = None
    if v03:                                             # SPEC 0.8: the HTTP exchange (X1-X7)
        xr, xn, xm = exchange_checks(doc, http_keys)
        if xr:
            res.update(xr)
            notes += xn
    tm = {}
    if v03:                                             # SPEC 0.11.3: the payment over MCP or A2A (XM1-XM4, XA1-XA4)
        import apc_transport
        tr, tn, tm = apc_transport.check(doc)
        res.update(tr)
        notes += tn
    # SPEC 0.11.1: builder-code attribution (x402 builder_code.md): the declarations and the settlement calldata
    bcr, bcn, bcm = builder_code_checks(doc, BUILDER[0] if BUILDER and res.get("C1") == "verified" else None)
    res.update(bcr)
    notes += bcn
    # SPEC 0.11.2: payment-identifier (x402 payment_identifier.md)
    import apc_payid
    pir, pin = apc_payid.check(doc)
    res.update(pir)
    notes += pin
    # SPEC 0.11: signed offers and receipts of the x402 offer-receipt extension (OR1-OR3), every bundle version
    pr_doc = doc.get("payment_required")
    btime = None
    if v03 and res.get("B1") == "verified":
        btime = int(doc["inclusion"]["block_header"]["timestamp"], 16)
    mandate_rep = None
    if mandate_ap2ev is not None:                       # SPEC 0.20 (section 31): MP1-MP7, after the block time of B1
        mr, mn, mandate_rep = apc_mandate.check(mandate_ap2ev, au, acc, btime, AP2_TSA_CERT[0])
        res.update(mr)
        notes += mn
    st_doc = doc.get("settlement")
    orr, orn, orm = offer_receipt_checks(doc, {
        "evm": True, "network": acc["network"], "scheme": "exact", "asset": acc["asset"], "pay_to": acc["pay_to"],
        "amount": str(acc["amount"]),
        "resource_url": pp["resource_url"] if pp["resource_url"] is not None else
        (pr_doc["resource"]["url"] if isinstance(pr_doc, dict) else None),
        "payer": au["from"], "transaction": st_doc["transaction"] if isinstance(st_doc, dict) and
        isinstance(st_doc.get("transaction"), str) else None,
        "success": st_doc["success"] if isinstance(st_doc, dict) else None, "block_time": btime,
        "accepts": pr_doc["accepts"] if isinstance(pr_doc, dict) else None}, signer_trust)
    res.update(orr)
    notes += orn
    failed = sorted(k for k, x in res.items() if x.startswith("failed"))
    # SPEC 5: an artifact the bundle does not carry is listed, it does not block; a present one not evaluated does
    absent = sorted(k for k, x in res.items() if x.startswith("not_evaluated:absent:"))
    open_ = sorted(k for k, x in res.items() if x.startswith("not_evaluated") and k not in absent)
    core = all(res[k].startswith("verified") for k in ("L2.sig", "K1", "K2", "K3"))
    # SPEC 0.2 C3: an indirect call stands on the token's logs, so C3 must be verified
    if res.get("C1", "").startswith("not_applicable:"):
        core = core and res.get("C3") == "verified"
    verdict = "chain_failed" if failed else ("chain_verified" if core and not open_ else "chain_incomplete")
    out = {"verifier": VERSION, "verdict": verdict, "checks": res, "failed": failed, "not_evaluated": open_,
           "absent": absent, "notes": notes}
    # SPEC Amendment 0.3.3: a transfer to oneself is a real execution but pays no one else (reported, not decisive)
    ai = apc_assets.info(acc["network"], acc["asset"], acc["amount"])        # SPEC 0.11.5: measured assets only
    if ai is not None:
        out["asset"] = ai
        if (acc["domain_name"], acc["domain_version"]) != (ai["eip712"]["name"], ai["eip712"]["version"]):
            notes.append("accepted.extra names the EIP-712 domain (%r, %r); the measured domain of this asset is (%r, "
                         "%r) (SPEC 0.11.5): L2.sig decides" % (acc["domain_name"], acc["domain_version"],
                                                                ai["eip712"]["name"], ai["eip712"]["version"]))
    out["payer_is_payee"] = au["from"] == acc["pay_to"]
    if out["payer_is_payee"]:
        notes.append("the payer is the payee (%s): the transfer moves no value to anyone else; whether it counts as a "
                     "payment is the reader's policy (address-level only: a payer paying itself from another address "
                     "is not seen)" % au["from"])
    out.update(tm)                                       # SPEC 0.11.3: only the transports carried
    if bcm is not None:                                  # SPEC 0.11.1: only with a suffix or a declaration
        out["builder_code"] = bcm
    if orm is not None:                                  # SPEC 0.11: only with the extension
        out["offer_receipt"] = orm
    if mandate_rep is not None:                          # SPEC 0.20: only with an ap2-evidence-pack mandate
        out["mandate"] = mandate_rep
    if v02:                                              # SPEC 32.6: how the payer's state was known, or null
        out["payer_state"] = state
    if v03:     # SPEC 0.3: says apart a verdict on carried RPC data from one bound to a block hash
        out["block_bound"] = all(res.get(k) == "verified" for k in ("B1", "B2", "B3", "B4"))
        out["reverted"] = reverted      # SPEC Amendment 0.3.3
        out["settled_by"] = settled_by
        out["exchange"] = xm                             # SPEC 0.8
        out["provenance"], pn = provenance(doc)          # SPEC 0.6 G6
        if pn:
            notes.append(pn)
        bound_report(res, out)
    return out


def bound_report(res, out):
    """SPEC 0.4 and 0.3 report members l1_state and canonical, from the checks and out["block_bound"] (apc-0.3 and,
    SPEC 0.10 section 12.7, apc-0.10)."""
    # SPEC 0.4: whether the L1 replies behind O1-O4 are proven from the reader's checkpoint
    out["l1_state"] = ("proven" if res.get("L1") == "verified" else
                       "failed" if res.get("L1", "").startswith("failed") else "not_shown")
    o = [res.get(k, "") for k in ("O1", "O2", "O3", "O4")]
    out["canonical"] = ("final" if out["block_bound"] and all(x == "verified" for x in o) else
                        "proposed" if out["block_bound"] and o[:3] == ["verified"] * 3 and o[3].startswith("pending:")
                        else "failed" if any(x.startswith("failed") for x in o) else "not_shown")


def _words(b, i):
    return b[4 + 32 * i: 4 + 32 * (i + 1)]


# ------------------------------------------------------------------ RLP and the EIP-1559 transaction hash
def _rlp(x):
    if isinstance(x, list):
        body = b"".join(_rlp(i) for i in x)
        return _rlp_len(len(body), 0xC0) + body
    if len(x) == 1 and x[0] < 0x80:
        return x
    return _rlp_len(len(x), 0x80) + x


def _rlp_len(n, off):
    if n < 56:
        return bytes([off + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(b)]) + b


def _q(v, path):
    """RPC quantity: 0x-hex without leading zeros (the JSON-RPC encoding), at most 256 bits (SPEC 0.3, 0.3.1), as minimal
    big-endian bytes."""
    if not isinstance(v, str) or not re.fullmatch(r"0x(0|[1-9a-f][0-9a-f]{0,63})", v):
        raise Refusal("%s: not a JSON-RPC quantity" % path)
    n = int(v, 16)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _d(v, path, size=None):
    if not isinstance(v, str) or not re.fullmatch(r"0x([0-9a-fA-F]{2})*", v):
        raise Refusal("%s: not hex data" % path)
    b = bytes.fromhex(v[2:])
    if size is not None and len(b) != size:
        raise Refusal("%s: not %d bytes" % (path, size))
    return b


def tx_sender_eip1559(tx):
    """SPEC Amendment 0.3.3: the address that signed an EIP-1559 transaction, recovered from yParity, r, s over
    keccak256(0x02 || rlp([chainId .. accessList])); None for another type or a signature that does not recover."""
    if tx.get("type") != "0x2":
        return None
    p = "chain_tx.tx."
    acc = [[_d(e["address"], p + "accessList.address", 20), [_d(k, p + "storageKeys", 32) for k in e["storageKeys"]]]
           for e in tx["accessList"]]
    fields = [_q(tx.get("chainId"), p + "chainId"), _q(tx.get("nonce"), p + "nonce"),
              _q(tx.get("maxPriorityFeePerGas"), p + "maxPriorityFeePerGas"), _q(tx.get("maxFeePerGas"), p + "maxFeePerGas"),
              _q(tx.get("gas"), p + "gas"), _d(tx.get("to"), p + "to", 20), _q(tx.get("value"), p + "value"),
              _d(tx.get("input"), p + "input"), acc]
    y = int(_q(tx.get("yParity", tx.get("v")), p + "yParity").hex() or "0", 16)
    r, s_ = (int(_q(tx.get(k), p + k).hex() or "0", 16) for k in ("r", "s"))
    if y not in (0, 1) or not 0 < r < SECP_N or not 0 < s_ <= SECP_N // 2:      # EIP-2: transactions are low-s
        return None
    try:
        return public_key_to_address(recover_public_key(keccak256(b"\x02" + _rlp(fields)), r, s_, y), keccak256)
    except ValueError:
        return None


def tx_hash_eip1559(tx):
    """keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data,
    accessList, yParity, r, s])) (EIP-1559). Returns None for any other transaction type."""
    if tx.get("type") != "0x2":
        return None
    p = "chain_tx.tx."
    al = tx.get("accessList")
    if not isinstance(al, list):
        raise Refusal(p + "accessList: not a list")
    acc = []
    for i, e in enumerate(al):
        if not isinstance(e, dict) or set(e) != {"address", "storageKeys"} or not isinstance(e["storageKeys"], list):
            raise Refusal(p + "accessList[%d]: not {address, storageKeys}" % i)
        acc.append([_d(e["address"], p + "accessList.address", 20), [_d(k, p + "storageKeys", 32) for k in e["storageKeys"]]])
    fields = [_q(tx.get("chainId"), p + "chainId"), _q(tx.get("nonce"), p + "nonce"),
              _q(tx.get("maxPriorityFeePerGas"), p + "maxPriorityFeePerGas"), _q(tx.get("maxFeePerGas"), p + "maxFeePerGas"),
              _q(tx.get("gas"), p + "gas"), _d(tx.get("to"), p + "to", 20), _q(tx.get("value"), p + "value"),
              _d(tx.get("input"), p + "input"), acc, _q(tx.get("yParity", tx.get("v")), p + "yParity"),
              _q(tx.get("r"), p + "r"), _q(tx.get("s"), p + "s")]
    return "0x" + keccak256(b"\x02" + _rlp(fields)).hex()


ERC8021_MARKER = bytes.fromhex("80218021802180218021802180218021")
CHAIN_NOTES = []
BUILDER = []                # SPEC 0.11.1: the decoded Schema 2 map of the direct call's calldata, set by _c1


def erc8021_schema2(tail):
    """x402 builder_code.md (0aee759) "Suffix Format": [cborData][cborLength 2B][schemaId 0x02][16-byte marker],
    and the suffix is the whole tail. Returns the CBOR hex, or None if the tail is not exactly that."""
    if len(tail) < 19 or tail[-16:] != ERC8021_MARKER or tail[-17] != 0x02:
        return None
    n = int.from_bytes(tail[-19:-17], "big")
    if n == 0 or len(tail) != n + 19:
        return None
    return tail[:n].hex()


def erc8021_schema0(tail):
    """ERC-8021 draft (ethereum/ERCs PR #1209 @ 457532f) Schema 0: [codes][codesLength 1B][schemaId 0x00][16-byte
    marker], codes 7-bit ASCII, comma-delimited, the suffix being the whole tail. Returns the codes or None."""
    if len(tail) < 19 or tail[-16:] != ERC8021_MARKER or tail[-17] != 0x00:
        return None
    n = tail[-18]
    if n == 0 or len(tail) != n + 18 or any(c > 0x7F for c in tail[:n]):
        return None
    return tail[:n].decode("ascii")


def _executed(res, v02):
    """SPEC Amendment 0.3.2: chain_tx shows the authorization executed (a direct call verified by C1-C2, by C3 too in
    apc-0.2; an indirect call stands on C2 and C3)."""
    c1, c2, c3 = res.get("C1", ""), res.get("C2", ""), res.get("C3", "")
    if c1.startswith("not_applicable:"):
        return c2 == "verified" and c3 == "verified"
    return c1 == "verified" and c2 == "verified" and (not v02 or c3 in ("verified", "not_evaluated:absent:no_log_transfer"))


def check_chain(ct, pp, tx_hash, v02=False, logs_optional=False):
    """(C1, C2, C3); C3 is None for an apc-0.1 bundle. SPEC Amendment 0.3.3: with `inclusion` (apc-0.3) the logs may be
    absent, for a reverted transaction emits none; the proven receipt decides (B3)."""
    if logs_optional:
        _obj(ct, "chain_tx", ("network", "tx"), ("log_authorization_used", "log_transfer", "log_forward"))
    else:
        _obj(ct, "chain_tx", ("network", "tx", "log_authorization_used"), ("log_transfer", "log_forward") if v02 else ())
    for name in ("log_authorization_used", "log_transfer", "log_forward"):      # SPEC 0.3.1: read in every branch
        if isinstance(ct.get(name), dict) and "removed" in ct[name] and not isinstance(ct[name]["removed"], bool):
            raise Refusal("chain_tx.%s.removed: not a boolean" % name)
    acc, au = pp["accepted"], pp["auth"]
    if ct["network"] != acc["network"]:
        return "failed:chain_tx_network_mismatch", "not_evaluated:after_C1", "not_evaluated:after_C1" if v02 else None
    tx = ct["tx"]
    if not isinstance(tx, dict) or not all(isinstance(tx.get(k), str) for k in ("to", "input", "hash")):
        raise Refusal("chain_tx.tx: needs string members to, input, hash")
    if tx["to"].lower() != acc["asset"]:
        if not v02:
            return "failed:tx_not_to_asset", "not_evaluated:after_C1", None
        CHAIN_NOTES.append("indirect call through %s: the signature bytes in the transaction are not compared (C1), "
                           "the token's own logs are (C3)" % tx["to"].lower())
        return ("not_applicable:indirect_call",) + _c2_c3(ct, acc, au, tx, tx_hash, indirect=True, v02=True)
    c1 = _c1(tx, pp, au)
    if c1 != "verified":
        return c1, "not_evaluated:after_C1", "not_evaluated:after_C1" if v02 else None
    c2, c3 = _c2_c3(ct, acc, au, tx, tx_hash, indirect=False, v02=v02)
    return c1, c2, c3 if v02 else None


def _c1(tx, pp, au):
    b = _d(tx["input"], "chain_tx.tx.input")
    vrs = "0x" + keccak256(b"transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)")[:4].hex()
    byt = "0x" + keccak256(b"transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)")[:4].hex()
    sel = tx["input"][:10].lower()
    if sel not in (vrs, byt) or len(b) < 4 + 32 * 7:
        return "failed:tx_not_transferWithAuthorization"
    if any(_words(b, i)[:12] != bytes(12) for i in (0, 1)):
        return "failed:tx_address_word_not_padded"
    got = {"from": "0x" + _words(b, 0)[12:].hex(), "to": "0x" + _words(b, 1)[12:].hex(),
           "value": int.from_bytes(_words(b, 2), "big"), "validAfter": int.from_bytes(_words(b, 3), "big"),
           "validBefore": int.from_bytes(_words(b, 4), "big"), "nonce": "0x" + _words(b, 5).hex()}
    if sel == vrs:
        sig = _words(b, 7) + _words(b, 8) + bytes([int.from_bytes(_words(b, 6), "big") % 256])
        if int.from_bytes(_words(b, 6), "big") > 255:
            return "failed:tx_v_out_of_range"
        abi_end = 4 + 32 * 9
    else:
        off = int.from_bytes(_words(b, 6), "big")
        if off != 32 * 7 or len(b) < 4 + off + 32:
            return "failed:tx_signature_offset_not_canonical"
        n = int.from_bytes(b[4 + off: 4 + off + 32], "big")
        sig = b[4 + off + 32: 4 + off + 32 + n]
        abi_end = 4 + off + 32 + (n + 31) // 32 * 32
        if len(b) < abi_end or any(b[4 + off + 32 + n: abi_end]):
            return "failed:tx_signature_padding"
    tail = b[abi_end:]
    if tail:
        suffix = erc8021_schema2(tail)
        codes = erc8021_schema0(tail) if suffix is None else None
        if codes is not None:
            CHAIN_NOTES.append("calldata carries an ERC-8021 Schema 0 suffix (draft ERC, ethereum/ERCs PR #1209), codes %r, "
                               "not interpreted" % codes)
            suffix = ""
        if suffix is None:
            CHAIN_NOTES.append("%d bytes of calldata after the ABI arguments, not an ERC-8021 Schema 2 suffix" % len(tail))
            return "not_evaluated:unrecognized_trailing_calldata"
        elif suffix:
            import apc_builder      # SPEC 0.11.1: read under x402 builder_code.md, reported
            fields, why = apc_builder.decode(bytes.fromhex(suffix))
            BUILDER.append(fields if fields is not None else {"malformed": why, "cbor": suffix})
            CHAIN_NOTES.append("calldata carries an ERC-8021 Schema 2 suffix (x402 builder-code extension): %s"
                               % (json.dumps(fields, sort_keys=True) if fields is not None else
                                  "not an x402 builder-code map (%s), CBOR %s" % (why, suffix)))
    if got != au:
        return "failed:tx_arguments_differ_from_authorization"
    if sig != pp["signature"]:
        return "failed:tx_signature_differs_from_payload"
    return "verified"


def _removed(lg, name):
    """Ethereum JSON-RPC log member `removed`: true when the log was dropped by a chain reorganization. Such a log is
    not evidence of anything (SPEC 0.3.1, all bundle versions); a value that is not a JSON boolean is refused."""
    if "removed" not in lg:
        return True
    if not isinstance(lg["removed"], bool):
        raise Refusal("chain_tx.%s.removed: not a boolean" % name)
    return not lg["removed"] or "failed:%s_removed" % name


def _c2_c3(ct, acc, au, tx, tx_hash, indirect, v02=False):
    if "log_authorization_used" not in ct:      # SPEC Amendment 0.3.3: only with inclusion; B3 decides
        if "log_transfer" in ct or "log_forward" in ct:
            raise Refusal("chain_tx: log_transfer or log_forward without log_authorization_used")
        return _c2_tx_only(acc, tx, tx_hash), "not_evaluated:absent:no_log_transfer"
    lg = ct["log_authorization_used"]
    topic = "0x" + keccak256(b"AuthorizationUsed(address,bytes32)").hex()
    if not isinstance(lg, dict) or not isinstance(lg.get("topics"), list) or len(lg["topics"]) != 3:
        raise Refusal("chain_tx.log_authorization_used: needs topics[3]")
    c2 = []
    rm = _removed(lg, "log_authorization_used")
    if rm is not True:
        c2.append(rm)
    c2.append("verified" if str(lg.get("address", "")).lower() == acc["asset"] else "failed:log_not_from_asset")
    c2.append("verified" if str(lg["topics"][0]).lower() == topic else "failed:log_not_AuthorizationUsed")
    c2.append("verified" if str(lg["topics"][1]).lower() == "0x" + "0" * 24 + au["from"][2:] else "failed:log_authorizer_mismatch")
    c2.append("verified" if str(lg["topics"][2]).lower() == au["nonce"] else "failed:log_nonce_mismatch")
    c2.append("verified" if str(lg.get("transactionHash", "")).lower() == tx["hash"].lower() else "failed:log_other_tx")
    for k in ("blockHash", "blockNumber"):      # the log claims the transaction's block (required in apc-0.2)
        if isinstance(tx.get(k), str) and isinstance(lg.get(k), str):
            c2.append("verified" if tx[k].lower() == lg[k].lower() else "failed:log_block_not_tx_block")
        elif v02:
            raise Refusal("chain_tx.tx / log_authorization_used: needs string %s" % k)
    if tx_hash is not None:
        c2.append("verified" if tx["hash"].lower() == tx_hash else "failed:tx_hash_not_settlement_transaction")
    h = tx_hash_eip1559(tx)
    if h is None:
        c2.append("not_evaluated:tx_type_%s_hash_not_recomputed" % tx.get("type"))
    else:
        c2.append("verified" if h == tx["hash"].lower() else "failed:tx_hash_not_its_rlp")
        if int(_q(tx["chainId"], "chain_tx.tx.chainId").hex() or "0", 16) != acc["chain_id"]:
            c2.append("failed:tx_chainId_not_network")
        c2.append(_from_is_signer(tx))
    c2r = next((x for x in c2 if x != "verified"), "verified")
    if "log_transfer" not in ct:
        c3 = ("not_evaluated:indirect_call_needs_log_transfer" if indirect else "not_evaluated:absent:no_log_transfer")
    else:
        c3 = _c3(ct["log_transfer"], lg, acc, au, tx)
    return c2r, c3


def _c2_tx_only(acc, tx, tx_hash):
    """C2 on the transaction alone (no log carried): its hash recomputed, equal to the settlement's, its chainId."""
    c2 = []
    if not isinstance(tx.get("hash"), str):
        raise Refusal("chain_tx.tx: needs a string hash")
    if tx_hash is not None:
        c2.append("verified" if tx["hash"].lower() == tx_hash else "failed:tx_hash_not_settlement_transaction")
    h = tx_hash_eip1559(tx)
    if h is None:
        c2.append("not_evaluated:tx_type_%s_hash_not_recomputed" % tx.get("type"))
    else:
        c2.append("verified" if h == tx["hash"].lower() else "failed:tx_hash_not_its_rlp")
        if int(_q(tx["chainId"], "chain_tx.tx.chainId").hex() or "0", 16) != acc["chain_id"]:
            c2.append("failed:tx_chainId_not_network")
        c2.append(_from_is_signer(tx))
    c2.append("not_evaluated:no_log_authorization_used")
    return next(x for x in c2 if x != "verified")


def _from_is_signer(tx):
    """SPEC Amendment 0.3.3: chain_tx.tx.from, when present, must be the address that signed the transaction."""
    if "from" not in tx:
        return "verified"
    who = tx_sender_eip1559(tx)
    if who is None:
        return "failed:tx_signature_does_not_recover"
    return "verified" if str(tx["from"]).lower() == who else "failed:tx_from_not_its_signer"


TRANSFER_TOPIC = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()


def _c3(lt, lg, acc, au, tx):
    """SPEC 0.2 C3: the Transfer the token emits right after AuthorizationUsed (Circle EIP3009.sol 143-144)."""
    if not isinstance(lt, dict) or not isinstance(lt.get("topics"), list) or len(lt["topics"]) != 3 \
            or not all(isinstance(t, str) for t in lt["topics"]) or not isinstance(lt.get("data"), str):
        raise Refusal("chain_tx.log_transfer: needs topics[3] of strings and data")
    for k in ("address", "transactionHash", "blockHash", "blockNumber", "logIndex"):
        if not isinstance(lt.get(k), str) or not isinstance(lg.get(k), str):
            raise Refusal("chain_tx.log_transfer / log_authorization_used: needs string %s" % k)
    i_au = int(_q(lg["logIndex"], "chain_tx.log_authorization_used.logIndex").hex() or "0", 16)
    i_tr = int(_q(lt["logIndex"], "chain_tx.log_transfer.logIndex").hex() or "0", 16)
    data = _d(lt["data"], "chain_tx.log_transfer.data")
    pad = "0x" + "0" * 24
    checks = [
        _removed(lt, "log_transfer"),
        lt["address"].lower() == acc["asset"] or "failed:log_transfer_not_from_asset",
        lt["topics"][0].lower() == TRANSFER_TOPIC or "failed:log_transfer_not_Transfer",
        lt["transactionHash"].lower() == tx["hash"].lower() or "failed:log_transfer_other_tx",
        lt["blockHash"].lower() == lg["blockHash"].lower() or "failed:log_transfer_other_block",
        lt["blockNumber"].lower() == lg["blockNumber"].lower() or "failed:log_transfer_other_block",
        i_tr == i_au + 1 or "not_evaluated:log_transfer_not_next",
        lt["topics"][1].lower() == pad + au["from"][2:] or "failed:log_transfer_from_mismatch",
        lt["topics"][2].lower() == pad + au["to"][2:] or "failed:log_transfer_to_mismatch",
        (len(data) == 32 and int.from_bytes(data, "big") == au["value"]) or "failed:log_transfer_value_mismatch",
    ]
    return next((x for x in checks if x is not True), "verified")


def check_inclusion(inc, ct, au, anchor="log_authorization_used", nxt="log_transfer", anchor_is_payment=False):
    """SPEC 0.3 B1-B4 and E1. B1 header hash; B2 transaction proof; B3 receipt proof (status, the two logs);
    B4 block time inside the authorization window (Circle EIP3009.sol 319-323: now > validAfter, now < validBefore).
    SPEC 0.10 (section 12.7): an apc-0.10 bundle names its own anchor log (log_transfer, the payment's own Transfer:
    anchor_is_payment) and the log that follows it in the receipt (log_settled for permit2, none for erc7710)."""
    _obj(inc, "inclusion", ("block_header", "transaction_index", "tx_proof", "receipt_proof"))
    tx, lg = ct["tx"], ct.get(anchor)
    lt = ct.get(nxt) if nxt else None
    # check_chain may have returned before reading tx and the log (C1 failed early): B1 reads them, so check here
    for obj, what, keys in ((tx, "chain_tx.tx", ("hash", "blockHash", "blockNumber", "transactionIndex")),
                            (lg, "chain_tx." + anchor, ("blockHash", "transactionIndex"))):
        if obj is None and what != "chain_tx.tx":
            continue
        if not isinstance(obj, dict) or not all(isinstance(obj.get(k), str) for k in keys):
            raise Refusal("inclusion: %s needs string %s" % (what, ", ".join(keys)))
    hdr = _header_obj(inc["block_header"], "inclusion.block_header")
    for log, what in ((lg, anchor), (lt, nxt)):
        if log is None:
            continue
        if not isinstance(log, dict) or not isinstance(log.get("topics"), list) or not all(
                isinstance(v, str) for v in [log.get("address"), log.get("data")] + log["topics"]) \
                or not ADDR.match(log["address"]) or not all(HASH32.match(t) for t in log["topics"]) \
                or not HEXDATA.match(log["data"]):
            raise Refusal("inclusion: chain_tx.%s: address, topics or data not hex of their size (B3 compares bytes)"
                          % what)
    try:
        h = apc_block.header_hash(hdr)
        idx = apc_block._qty(inc["transaction_index"], "inclusion.transaction_index")
        proofs = {}
        for k in ("tx_proof", "receipt_proof"):
            if not isinstance(inc[k], list) or not inc[k] or len(inc[k]) > 64:
                raise Refusal("inclusion.%s: not a list of 1..64 nodes" % k)
            proofs[k] = [apc_block._hexbytes(n, "inclusion." + k) for n in inc[k]]
        roots = {k: apc_block._hexbytes(hdr[k], k, 32) for k in ("transactionsRoot", "receiptsRoot")}
        ts = apc_block._qty(hdr["timestamp"], "timestamp")
    except apc_block.BlockRefusal as e:
        raise Refusal("inclusion: %s" % e)
    out = {}
    b1 = [h == str(hdr.get("hash", "")).lower() or "failed:header_hash_mismatch",
          h == str(tx.get("blockHash", "")).lower() or "failed:tx_block_not_header",
          lg is None or h == str(lg.get("blockHash", "")).lower() or "failed:log_block_not_header",
          str(hdr["number"]).lower() == str(tx.get("blockNumber", "")).lower() or "failed:tx_number_not_header",
          hex(idx) == str(tx.get("transactionIndex", "")).lower() or "failed:transaction_index_not_tx",
          lg is None or hex(idx) == str(lg.get("transactionIndex", "")).lower() or "failed:transaction_index_not_log"]
    out["B1"] = next((x for x in b1 if x is not True), "verified")
    key = apc_block.rlp(apc_block._int_bytes(idx))
    try:
        raw_tx = apc_block.verify_proof(roots["transactionsRoot"], key, proofs["tx_proof"])
        out["B2"] = "verified" if "0x" + keccak256(raw_tx).hex() == tx["hash"].lower() else "failed:proven_tx_is_another_tx"
    except apc_block.BlockRefusal as e:
        out["B2"] = "failed:tx_proof:%s" % e
    try:
        raw_rc = apc_block.verify_proof(roots["receiptsRoot"], key, proofs["receipt_proof"])
        out["B3"], e1 = _b3(raw_rc, lg, lt, au, anchor_is_payment)
    except apc_block.BlockRefusal as e:
        out["B3"], e1 = "failed:receipt_proof:%s" % e, None
    out["B4"] = ("verified" if au["validAfter"] < ts < au["validBefore"]
                 else "failed:block_time_outside_authorization_window")
    return out, [e1] if e1 else []


def _header_obj(h, path):
    """A header object: the closed list of header fields plus a string "hash" (SPEC 0.3 B grammar)."""
    if not isinstance(h, dict) or set(h) - set(apc_block.HEADER_BASE + apc_block.HEADER_OPT + ("hash",)):
        raise Refusal("%s: not an object of header fields" % path)
    if not isinstance(h.get("hash"), str):
        raise Refusal("%s: needs a string hash" % path)
    return h


# SPEC 0.3 O1-O4: Base mainnet only. Addresses: docs.base.org (base-contracts page), read 2026-10-23; game type 621 =
# AggregateVerifier (base/contracts eaa7729, src/L1/proofs/AggregateVerifier.sol, pinned in sources/base_contracts_eaa7729)
BASE_FACTORY = "0x43edb88c4b80fdd2adff2412a7bebf9df42cb40e"
BASE_REGISTRY = "0x909f6cf47ed12f010a796527f562bfc26c7f4e72"
BASE_GAME_TYPE = 621
_SEL = lambda sig: "0x" + keccak256(sig.encode())[:4].hex()
CANON_GAME_CALLS = ("gameType()", "rootClaim()", "extraData()", "startingBlockNumber()", "status()")
CANON_REGISTRY_CALLS = ("isGameProper(address)", "isGameRespected(address)", "isGameClaimValid(address)")


def _word(r, what, bits=256):
    if not isinstance(r, str) or not HASH32.match(r):
        raise Refusal("canonical.l1_replies: %s result is not one 32-byte word" % what)
    v = int(r[2:], 16)
    if v >> bits:
        raise Refusal("canonical.l1_replies: %s result out of range" % what)
    return v


def _l1_nodes(v, path, lo=1):
    if not isinstance(v, list) or not lo <= len(v) <= 64 or not all(isinstance(x, str) and HEXDATA.match(x) and len(x) > 2
                                                                      for x in v):
        raise Refusal("%s: not a list of %d..64 hex nodes" % (path, lo))
    return [bytes.fromhex(x[2:]) for x in v]


def _l1_state(st):
    """SPEC 0.4 grammar of canonical.l1_state -> (headers, {address: (account proof, {slot: storage proof})}, game code).
    No declared value is carried: every value comes from a proof."""
    _obj(st, "canonical.l1_state", ("headers", "accounts", "game_code"))
    hs = st["headers"]
    if not isinstance(hs, list) or not 1 <= len(hs) <= 8192:
        raise Refusal("canonical.l1_state.headers: not a list of 1..8192 headers")
    for j, h in enumerate(hs):
        _header_obj(h, "canonical.l1_state.headers[%d]" % j)
    if not isinstance(st["accounts"], list) or not 1 <= len(st["accounts"]) <= 32:
        raise Refusal("canonical.l1_state.accounts: not a list of 1..32 account proofs")
    accs = {}
    for i, a in enumerate(st["accounts"]):
        p = "canonical.l1_state.accounts[%d]" % i
        _obj(a, p, ("address", "accountProof", "storageProof"))
        addr = bytes.fromhex(_addr(a["address"], p + ".address")[2:])
        if addr in accs:
            raise Refusal("%s.address: a second proof for the same account" % p)
        if not isinstance(a["storageProof"], list) or len(a["storageProof"]) > 64:
            raise Refusal("%s.storageProof: not a list of at most 64 proofs" % p)
        slots = {}
        for j, sp in enumerate(a["storageProof"]):
            q = "%s.storageProof[%d]" % (p, j)
            _obj(sp, q, ("key", "proof"))
            if not isinstance(sp["key"], str) or not HASH32.match(sp["key"]):
                raise Refusal("%s.key: not a 32-byte hex slot" % q)
            slot = int(sp["key"], 16)
            if slot in slots:
                raise Refusal("%s.key: a second proof for the same slot" % q)
            slots[slot] = _l1_nodes(sp["proof"], q + ".proof", 0)
        accs[addr] = (_l1_nodes(a["accountProof"], p + ".accountProof"), slots)
    return hs, accs, _d(st["game_code"], "canonical.l1_state.game_code")


def _check_l1(parsed, game, l1_block, results, checkpoint):
    """SPEC 0.4 L1: the eight replies recomputed from the proofs under the last header of a chain that starts at the
    checkpoint the reader trusts equal the carried replies, byte for byte."""
    hs, accs, code = parsed
    if checkpoint is None:
        return "not_evaluated:absent:no_l1_checkpoint"
    try:
        if any(apc_block.header_hash(h) != str(h["hash"]).lower() for h in hs):
            return "failed:l1_header_hash_mismatch"
        last = apc_l1proof.header_chain(checkpoint, hs)
        if _qty_int(last["number"], "canonical.l1_state.headers.number") != _qty_int(l1_block, "l1 block"):
            return "failed:l1_last_header_not_the_replies_block"
        used = set()
        got = apc_l1proof.replies(last, accs, code, bytes.fromhex(game[2:]), used)
    except apc_l1proof.NotPinned as e:
        return "not_evaluated:l1_%s" % e
    except apc_block.BlockRefusal as e:
        return "failed:l1_state:%s" % e
    carried = {(a, None) for a in accs} | {(a, k) for a, (_, sl) in accs.items() for k in sl}
    if carried != used:     # closed: a proof the eight replies do not read is not carried unread
        raise Refusal("canonical.l1_state: %d proof(s) not read by the eight replies" % len(carried - used))
    names = CANON_GAME_CALLS + CANON_REGISTRY_CALLS
    for name, g, r in zip(names, got, results):
        if g != _d(r, "canonical reply"):
            return "failed:l1_reply_not_proven:%s" % name.split("(")[0]
    return "verified"


def exchange_checks(doc, http_keys):
    """SPEC 0.8 (apc_http.py): (checks, notes, report member), (None, [], None) without exchange."""
    import apc_http
    keys = apc_http.parse_keys(http_keys) if http_keys is not None else None
    return apc_http.check(doc, keys)


BC_CODE = re.compile(r"[a-z0-9_]{1,32}\Z")


def _bc_decl(v, path, inner):
    """The builder-code object of PaymentRequired ({info: {a?, s?}, schema?}) or PaymentPayload ({a?, s?}), closed."""
    if inner:
        v = _obj(v, path, ("info",), ("schema",))
        if "schema" in v and not isinstance(v["schema"], dict):
            raise Refusal(path + ".schema: not an object")
        path, v = path + ".info", v["info"]
    v = _obj(v, path, (), ("a", "s"))
    if "a" in v and not (isinstance(v["a"], str) and BC_CODE.match(v["a"])):
        raise Refusal(path + ".a: not a builder code ^[a-z0-9_]{1,32}$")
    if "s" in v:
        s = v["s"] if isinstance(v["s"], list) else [v["s"]]
        if not s or not all(isinstance(x, str) and BC_CODE.match(x) for x in s):
            raise Refusal(path + ".s: not a builder code or a non-empty list of them")
    return v


def builder_code_checks(doc, calldata, evm=True):
    """SPEC 0.11.1 BC1: (checks, notes, report member); ({}, [], None) without a declaration or a calldata suffix.
    evm False (SPEC 0.16.1: Solana, Stellar, XRPL): the declarations are compared, and there is no ERC-8021 calldata."""
    def ext(name, inner):
        c = doc.get(name)
        e = c.get("extensions") if isinstance(c, dict) else None
        if isinstance(e, dict) and "builder-code" in e:
            return _bc_decl(e["builder-code"], "%s.extensions['builder-code']" % name, inner)
        return None
    srv, cli = ext("payment_required", True), ext("payment_payload", False)
    if srv is None and cli is None and calldata is None:
        return {}, [], None
    member = {"declared_app": (srv or {}).get("a"), "echoed": cli, "calldata": calldata}
    if srv is None and cli is None:     # attribution only: reported, nothing to compare
        return {}, [], member
    r = "verified"
    if cli is not None and "a" in cli and "payment_required" in doc and (srv is None or "a" not in srv):
        r = "failed:builder_code_app_not_declared"           # BC: the client MUST NOT set a the server did not declare
    elif cli is not None and srv is not None and "a" in srv and cli.get("a") != srv["a"]:
        r = "failed:builder_code_app_echo_mismatch"          # BC App Code Echo Validation (extension_echo_mismatch)
    elif calldata is not None and "malformed" in calldata:
        r = "not_evaluated:builder_code_calldata_malformed"
    elif calldata is not None and cli is not None and "a" in cli and calldata.get("a") != cli["a"]:
        r = "failed:builder_code_calldata_app_mismatch"      # BC Facilitator Behavior: it encodes the echoed a
    elif calldata is None:
        r = "not_evaluated:absent:no_builder_code_calldata" if evm else "not_applicable:no_erc8021_calldata_off_evm"
    return {"BC1": r}, [], member


def offer_receipt_checks(doc, ctx, signer_trust):
    """SPEC 0.11 (apc_offer.py): (checks, notes, report member); ({}, [], None) without the offer-receipt extension."""
    import apc_offer
    trust = apc_offer.parse_trust(signer_trust) if signer_trust is not None else None
    return apc_offer.check(doc, ctx, trust)


def provenance(doc):
    """SPEC 0.6 G6: who supplied the chain data and the settlement reply, and when (declared; closed grammar). Returns
    the member as given (for the report) and its note, or (None, None) without it."""
    if "provenance" not in doc:
        return None, None
    pv = _obj(doc["provenance"], "provenance", (), ("chain_tx", "settlement"))
    if not pv:
        raise Refusal("provenance: names neither chain_tx nor settlement")
    for k, v in pv.items():
        _obj(v, "provenance." + k, ("source", "fetched"))
        if len(_str(v["source"], "provenance.%s.source" % k)) > 256:
            raise Refusal("provenance.%s.source: longer than 256 characters" % k)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", _str(v["fetched"], "provenance.%s.fetched" % k)):
            raise Refusal("provenance.%s.fetched: not YYYY-MM-DDTHH:MM:SSZ" % k)
        if k not in doc:
            raise Refusal("provenance.%s: the bundle carries no %s" % (k, k))
    return pv, ("provenance (declared, not checked): " + "; ".join(
        "%s from %s at %s" % (k, v["source"], v["fetched"]) for k, v in sorted(pv.items())))


def check_mandate(m, payment_payload):
    """SPEC 0.7 M1: an AP2 Payment Mandate in the Pulse AP2-x402 profile (apc_ap2.py) is consistent, and the x402
    payload it binds is this bundle's payment_payload (RFC 8785 equality)."""
    import apc_ap2
    _obj(m, "mandate", ("profile", "case"))
    if not isinstance(m["case"], dict):
        raise Refusal("mandate.case: not an object")
    r = apc_ap2.verify_case(m["case"])
    if r["failureCodes"] == ["INPUT_SCHEMA_INVALID"]:
        raise Refusal("mandate.case: outside the Pulse 0.3 grammar (%s)" % r.get("schema", "unsafe key"))
    if not r["consistent"]:
        return "failed:ap2_" + r["failureCodes"][0].lower(), [
            "M1: the AP2 mandate is not consistent with its x402 payment (Pulse profile): " + ", ".join(r["failureCodes"])]
    if not apc_ap2.canon_eq(m["case"]["x402"]["payload"], payment_payload):
        return "failed:mandate_binds_another_payment", ["M1: the AP2 mandate is consistent but binds another x402 payload"]
    return "verified", ["M1: the AP2 Payment Mandate chain, its receipt and its x402 binding verify (Pulse AP2-x402 "
                        "profile 0.3); the trusted AP2 keys are the ones the mandate names, not established here"]


def check_canonical(can, inc_header, network, l1_checkpoint=None):
    """O1 the L1 replies (one L1 block, the exact calls, game type 621, the extraData layout of AggregateVerifier);
    O2 the L2 header chain from the root's block down to the bundle's block; O3 the output root (OP Stack: keccak256
    of bytes32(0), stateRoot, withdrawalsRoot = L2ToL1MessagePasser storage root since Isthmus, block hash) equals the
    game's intermediate root; O4 the game's state: final (isGameClaimValid), pending, or failed."""
    _obj(can, "canonical", ("l1_network", "game", "root_index", "l1_replies", "headers"), ("l1_state",))
    notes = ["canonical: the L1 answers are eth_call replies of an L1 RPC at one L1 block that the bundle names, carried "
             "by the bundle and not proven here; they can be asked again at that block of an Ethereum node that still "
             "holds its state (an archive node for an older block); a change after that block (blacklisting, "
             "retirement) is not seen (SPEC O1)"]
    # grammar first, on every network (closed: a member of the wrong type is refused, not left unread)
    if not isinstance(can["l1_network"], str) or not CAIP2_EIP155.match(can["l1_network"]):
        raise Refusal("canonical.l1_network: not an eip155 CAIP-2 network")
    game = _addr(can["game"], "canonical.game")
    idx = _int_json(can["root_index"], "canonical.root_index")
    if idx < 0:
        raise Refusal("canonical.root_index: negative")
    reps = can["l1_replies"]
    n_calls = len(CANON_GAME_CALLS) + len(CANON_REGISTRY_CALLS)
    if not isinstance(reps, list) or len(reps) != n_calls:
        raise Refusal("canonical.l1_replies: needs exactly %d replies" % n_calls)
    hs = can["headers"]
    if not isinstance(hs, list) or len(hs) > 64:
        raise Refusal("canonical.headers: not a list of at most 64 headers")
    for j, h in enumerate(hs):
        _header_obj(h, "canonical.headers[%d]" % j)
    l1 = _l1_state(can["l1_state"]) if "l1_state" in can else None        # SPEC 0.4
    if network != "eip155:8453":
        r = "not_evaluated:canonical_rules_only_for_base_mainnet"
        return {"O1": r, "O2": r, "O3": r, "O4": r, "L1": r}, []
    if can["l1_network"] != "eip155:1":
        raise Refusal("canonical.l1_network: not eip155:1")
    want = [(game, _SEL(s)) for s in CANON_GAME_CALLS] + [(BASE_REGISTRY, _SEL(s) + "%064x" % int(game, 16))
                                                          for s in CANON_REGISTRY_CALLS]
    l1_block = None
    res = []
    for i, ((to, data), r) in enumerate(zip(want, reps)):
        _obj(r, "canonical.l1_replies[%d]" % i, ("method", "params", "result"))
        if r["method"] != "eth_call" or not isinstance(r["params"], list) or len(r["params"]) != 2:
            raise Refusal("canonical.l1_replies[%d]: not an eth_call with two params" % i)
        call = r["params"][0]
        # addresses and hex data are compared case-insensitively, as in _reply (SPEC 4: case ignored)
        if not isinstance(call, dict) or set(call) != {"to", "data"} \
                or not all(isinstance(v, str) for v in call.values()) \
                or not ADDR.match(call["to"]) or not HEXDATA.match(call["data"]) \
                or (call["to"].lower(), call["data"].lower()) != (to.lower(), data.lower()):
            raise Refusal("canonical.l1_replies[%d]: not the call SPEC O1 names" % i)
        _q(r["params"][1], "canonical.l1_replies[%d].block" % i)
        if l1_block is None:
            l1_block = r["params"][1]
        elif r["params"][1] != l1_block:
            raise Refusal("canonical.l1_replies: not all at one L1 block")
        res.append(r["result"])
    l1res = "not_evaluated:absent:no_l1_state" if l1 is None else _check_l1(l1, game, l1_block, res, l1_checkpoint)
    if l1res == "verified":
        notes = ["canonical: the eight L1 answers are recomputed from account and storage proofs under the state root of "
                 "L1 block %d, reached by parent links from the checkpoint the reader gave (SPEC 0.4 L1); a change after "
                 "that block (blacklisting, retirement) is not seen" % _qty_int(l1_block, "l1 block")]
    gtype, claim = _word(res[0], "gameType", 32), _word(res[1], "rootClaim")
    start, status = _word(res[3], "startingBlockNumber", 64), _word(res[4], "status", 8)
    proper, respected, valid = (_word(res[i], CANON_REGISTRY_CALLS[i - 5], 1) for i in (5, 6, 7))
    if status > 2:      # GameStatus: IN_PROGRESS 0, CHALLENGER_WINS 1, DEFENDER_WINS 2
        raise Refusal("canonical.l1_replies: status %d is not a GameStatus" % status)
    if valid and not (proper and respected and status == 2):
        # AnchorStateRegistry.sol 307-329: isGameClaimValid implies proper, respected and DEFENDER_WINS
        raise Refusal("canonical.l1_replies: isGameClaimValid true with a reply that contradicts it")
    ed = _d(res[2], "canonical extraData result")
    if len(ed) < 64 or int.from_bytes(ed[:32], "big") != 32:
        raise Refusal("canonical.l1_replies: extraData is not ABI bytes")
    n_ed = int.from_bytes(ed[32:64], "big")
    if n_ed < 84 or (n_ed - 52) % 32 or len(ed) != 64 + (n_ed + 31) // 32 * 32 or any(ed[64 + n_ed:]):
        raise Refusal("canonical.l1_replies: extraData is not l2SequenceNumber, parent and 32-byte roots")
    seq = int.from_bytes(ed[64:96], "big")
    roots = [ed[116 + 32 * j:148 + 32 * j] for j in range((n_ed - 52) // 32)]
    o1 = [gtype == BASE_GAME_TYPE or "failed:game_type_not_621",
          roots[-1] == claim.to_bytes(32, "big") or "failed:last_intermediate_root_not_root_claim",
          (start < seq and (seq - start) % len(roots) == 0) or "failed:game_range_not_divisible"]
    out = {"L1": l1res, "O1": next((x for x in o1 if x is not True), "verified")}
    if out["O1"] != "verified":
        out["O2"] = out["O3"] = out["O4"] = "not_evaluated:after_O1"
        return out, notes
    k = (seq - start) // len(roots)
    n = _qty_int(inc_header["number"], "inclusion.block_header.number")
    try:
        hashes = [apc_block.header_hash(h) for h in hs]
        nums = [_qty_int(h["number"], "canonical.headers.number") for h in hs]
    except apc_block.BlockRefusal as e:
        raise Refusal("canonical.headers: %s" % e)
    n_hash = apc_block.header_hash(inc_header)
    chain = list(zip(hs, hashes, nums)) + [(inc_header, n_hash, n)]
    o2 = [idx < len(roots) or "failed:root_index_out_of_range",
          start < n <= seq or "failed:block_not_in_game_range",
          chain[0][2] == start + (idx + 1) * k or "failed:first_header_not_the_root_block",
          (chain[0][2] - n) < k or "failed:not_the_first_root_at_or_after_the_block"]
    # a header whose own hash field is not its content is reported first (the bundle's own header too, so O2 stands
    # without B1); then the parent links
    o2 += ["failed:header_hash_mismatch" for h, hh, _ in chain if hh != str(h.get("hash", "")).lower()]
    o2 += ["failed:header_chain_broken" for (h, _, num), (_, ph, pnum) in zip(chain, chain[1:])
           if str(h["parentHash"]).lower() != ph or num != pnum + 1]
    out["O2"] = next((x for x in o2 if x is not True), "verified")
    if out["O2"] != "verified":
        out["O3"] = out["O4"] = "not_evaluated:after_O2"
        return out, notes
    top = chain[0][0]
    if "withdrawalsRoot" not in top:
        out["O3"] = "not_evaluated:header_without_withdrawalsRoot"
    else:
        root = keccak256(bytes(32) + bytes.fromhex(top["stateRoot"][2:]) + bytes.fromhex(top["withdrawalsRoot"][2:])
                         + bytes.fromhex(chain[0][1][2:]))
        out["O3"] = "verified" if root == roots[idx] else "failed:output_root_not_the_game_root"
    if status == 1:
        out["O4"] = "failed:game_challenger_wins"
    elif not (proper and respected):
        # isGameProper is false for a game the factory did not register, a blacklisted or retired game, and while the
        # system is paused (AnchorStateRegistry.sol 262-284); the eight calls do not say which, so the payment is not
        # failed by it: canonicality is just not shown
        out["O4"] = "not_evaluated:game_not_proper_or_not_respected"
        notes.append("O4: at that L1 block the registry does not call the game proper and respected (not registered by "
                     "the factory, blacklisted, retired, or the system paused): the block is not shown canonical")
    elif valid and status == 2:
        out["O4"] = "verified"
    else:
        out["O4"] = "pending:game_not_final"
        notes.append("O4: the game is proper and respected but not yet a valid claim (in progress, or resolved and "
                     "still inside the finality delay): the block is proposed on L1, not final")
    return out, notes


def _qty_int(v, path):
    try:
        return apc_block._qty(v, path)
    except apc_block.BlockRefusal as e:
        raise Refusal(str(e))


def _log_eq(enc, js):
    """enc = [address, [topics], data] from the receipt; js = the bundle's JSON log."""
    try:
        return (enc[0] == bytes.fromhex(js["address"][2:]) and enc[1] == [bytes.fromhex(t[2:]) for t in js["topics"]]
                and enc[2] == bytes.fromhex(js["data"][2:]))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _b3(raw, lg, lt, au, anchor_is_payment=False):
    if not raw:
        return "failed:empty_receipt", None
    body = raw[1:] if raw[0] < 0x80 else raw
    try:
        rc = apc_block.rlp_decode(body)
    except apc_block.BlockRefusal as e:
        return "failed:receipt_not_rlp:%s" % e, None
    if not isinstance(rc, list) or len(rc) < 4 or not isinstance(rc[3], list):
        return "failed:receipt_shape", None
    if rc[0] != b"\x01":
        return "failed:receipt_status_not_success", None
    if lg is None:      # SPEC Amendment 0.3.3: a successful EIP-3009 execution emits AuthorizationUsed
        raise Refusal("chain_tx.log_authorization_used absent next to a receipt with status 1")
    logs = rc[3]
    pos = [i for i, x in enumerate(logs) if isinstance(x, list) and len(x) == 3 and _log_eq(x, lg)]
    if len(pos) != 1:
        return "failed:authorization_log_not_in_receipt", None
    p = pos[0]
    if lt is not None and not (p + 1 < len(logs) and _log_eq(logs[p + 1], lt)):
        return "failed:transfer_log_not_next_in_receipt", None
    asset = bytes.fromhex(str(lg["address"])[2:])
    tr = bytes.fromhex(TRANSFER_TOPIC[2:])
    payer = bytes(12) + bytes.fromhex(au["from"][2:])
    # the log after AuthorizationUsed is left out only when the bundle's log_transfer matched it above
    own = p + 1 if lt is not None else None
    if anchor_is_payment:       # SPEC 0.10: the anchor is the payment's own Transfer (Permit2, ERC-7710)
        own = p
    out = [x for i, x in enumerate(logs) if i != own and isinstance(x, list) and len(x) == 3 and x[0] == asset
           and isinstance(x[1], list) and len(x[1]) == 3 and x[1][0] == tr and x[1][1] == payer
           and isinstance(x[1][2], bytes) and isinstance(x[2], bytes)]
    e1 = None
    if out:
        e1 = ("E1: the same transaction moves %d %s of the asset out of the payer: %s (reported, "
              "not decisive)" % (len(out), "other Transfer(s)" if own is not None else
                                 "Transfer(s), the payment's own among them (no log_transfer carried)", ", ".join("to 0x%s value %d" % (x[1][2][12:].hex(), int.from_bytes(x[2], "big"))
                                                      for x in out)))
    return "verified", e1


def check_forward(ct, pp):
    """SPEC 0.2 F1: the payee's onward Transfer right after the payment's Transfer; reported, never decisive."""
    if "log_forward" not in ct:
        return "not_evaluated:absent:no_log_forward"
    if "log_transfer" not in ct:
        return "failed:log_forward_without_log_transfer"
    lf, lt, acc, au = ct["log_forward"], ct["log_transfer"], pp["accepted"], pp["auth"]
    if not isinstance(lf, dict) or not isinstance(lf.get("topics"), list) or len(lf["topics"]) != 3 \
            or not all(isinstance(t, str) for t in lf["topics"]) or not isinstance(lf.get("data"), str):
        raise Refusal("chain_tx.log_forward: needs topics[3] of strings and data")
    for k in ("address", "transactionHash", "blockHash", "blockNumber", "logIndex"):
        if not isinstance(lf.get(k), str) or not isinstance(lt, dict) or not isinstance(lt.get(k), str):
            raise Refusal("chain_tx.log_forward / log_transfer: needs string %s" % k)
    data = _d(lf["data"], "chain_tx.log_forward.data")
    i_f = int(_q(lf["logIndex"], "chain_tx.log_forward.logIndex").hex() or "0", 16)
    i_t = int(_q(lt["logIndex"], "chain_tx.log_transfer.logIndex").hex() or "0", 16)
    checks = [
        _removed(lf, "log_forward"),
        lf["address"].lower() == acc["asset"] or "failed:log_forward_not_from_asset",
        lf["topics"][0].lower() == TRANSFER_TOPIC or "failed:log_forward_not_Transfer",
        lf["transactionHash"].lower() == lt["transactionHash"].lower() or "failed:log_forward_other_tx",
        lf["blockHash"].lower() == lt["blockHash"].lower() or "failed:log_forward_other_block",
        lf["blockNumber"].lower() == lt["blockNumber"].lower() or "failed:log_forward_other_block",
        i_f == i_t + 1 or "failed:log_forward_not_next",
        lf["topics"][1].lower() == "0x" + "0" * 24 + au["to"][2:] or "failed:log_forward_not_from_payee",
        (len(data) == 32 and lf["topics"][2].lower().startswith("0x" + "0" * 24)) or "failed:log_forward_malformed",
    ]
    bad = next((x for x in checks if x is not True), None)
    if bad:
        return bad
    v = int.from_bytes(data, "big")
    if v > au["value"]:
        CHAIN_NOTES.append("payee %s forwarded %d to 0x%s in the same transaction, more than the %d received in this payment"
                           % (au["to"], v, lf["topics"][2][-40:].lower(), au["value"]))
        return "verified"
    CHAIN_NOTES.append("payee %s forwarded %d of %d to 0x%s in the same transaction; %d not forwarded in this log"
                       % (au["to"], v, au["value"], lf["topics"][2][-40:].lower(), au["value"] - v))
    return "verified"


def check_acceptance(rec, pp, tx_hash):
    """A1/A2 on the work-acceptance 1.4.1 `payment` member. The receipt's own verdict is war-verify's, not ours."""
    body = rec.get("receipt") if isinstance(rec, dict) else None
    if not isinstance(body, dict):
        raise Refusal("acceptance: no receipt object")
    pm = body.get("payment")
    if pm is None:
        return "not_evaluated:no_payment_member", "not_evaluated:no_payment_member"
    _obj(pm, "acceptance.receipt.payment", ("protocol", "scheme", "network", "asset", "payer", "pay_to", "amount", "nonce"),
         ("settlement_tx",))
    acc, au = pp["accepted"], pp["auth"]
    checks = [eq(pm["protocol"], "x402", "protocol"), eq(pm["scheme"], "exact", "scheme"),
              eq(pm["network"], acc["network"], "network"),
              eq(_addr(pm["asset"], "payment.asset"), acc["asset"], "asset"),
              eq(_addr(pm["payer"], "payment.payer"), au["from"], "payer"),
              eq(_addr(pm["pay_to"], "payment.pay_to"), au["to"], "pay_to"),
              eq(_uint(pm["amount"], "payment.amount"), au["value"], "amount"),
              eq(_str(pm["nonce"], "payment.nonce").lower(), au["nonce"], "nonce")]
    a1 = next((x for x in checks if x != "verified"), "verified")
    if "settlement_tx" not in pm:
        a2 = "not_evaluated:absent:no_settlement_tx"     # optional in the profile; A1 already names the settlement
    elif tx_hash is None:
        a2 = "not_evaluated:absent:no_settlement"
    else:
        a2 = eq(_str(pm["settlement_tx"], "payment.settlement_tx").lower(), tx_hash, "settlement_tx")
    return a1, a2


MAX_BUNDLE_BYTES = 64 << 20
AP2_TSA_CERT = [None]       # SPEC 0.20: --ap2-tsa-cert, the reader's trust (never read from the bundle)


# SPEC section 30 (0.19, revised by 0.19.1): the evidence level of a verdict, the facilitator's reply apart
EVIDENCE_LEVELS = ("none", "signature", "settlement_record", "inclusion_proof", "finality_proven")
FACILITATOR_REPLY = ("verified", "failed", "absent", "not_evaluated")
NO_SETTLEMENT = "not_evaluated:absent:no_settlement"

# SPEC 30.4 (ii), a closed list: bundle version -> check -> the qualified outcomes `verified (...)` that count, each
# matched whole; a qualified outcome outside it does not count and is named in a note
_K3_EVM = {"K3": (r"verified \(by L2\.sig\)",)}
_L2_CBSW = {"L2.sig": (r"verified \(ERC-1271 CoinbaseSmartWallet\)", r"verified \(ERC-1271 CoinbaseSmartWallet, passkey\)",
                       r"verified \(ERC-1271 Circle_SingleOwnerMSCA 1\.0\.0\)")}     # SPEC 32.7
EVIDENCE_QUALIFIED = {
    "apc-0.1": dict(_K3_EVM),
    "apc-0.2": dict(_K3_EVM, **_L2_CBSW),
    "apc-0.3": dict(_K3_EVM, **_L2_CBSW),
    "apc-0.13": dict(_K3_EVM, K2=(r"verified \(v1: value [0-9]+ exceeds maxAmountRequired [0-9]+\)",), **_L2_CBSW),
    "apc-0.10": {"L2.sig": (r"verified \(ERC-1271 Kernel 0\.3\.3 by EIP-7702\)",
                            r"verified \(ERC-1271 EIP7702StatelessDeleGator by EIP-7702\)"),
                 "K3": (r"verified \(token; chainId by L2\.sig\)",)},
    "apc-0.5": {}, "apc-0.12": {}, "apc-0.15": {}, "apc-0.16": {},
}


class _Counter:
    """SPEC 30.1: `verified`, or a qualified outcome of the closed list of 30.4 for (version, check), counts; any other
    outcome, or no outcome, does not. A `verified (` outside the list is remembered for the note."""
    def __init__(self, version, res):
        self.allowed, self.res, self.outside = EVIDENCE_QUALIFIED[version], res, []

    def __call__(self, k):
        x = self.res.get(k)
        if not isinstance(x, str):
            return False
        if x == "verified":
            return True
        if x.startswith("verified ("):
            if any(re.fullmatch(f, x) for f in self.allowed.get(k, ())):
                return True
            if (k, x) not in self.outside:
                self.outside.append((k, x))
        return False


def _evm_chain(c):
    """SPEC 5 and 12.2: C2, and C1, or C1 not_applicable:indirect_call with C3."""
    return c("C2") and (c("C1") or (c.res.get("C1") == "not_applicable:indirect_call" and c("C3")))


def _all(*keys):
    return lambda c: all([c(k) for k in keys])


# SPEC 30.2, a closed table: bundle version -> (signature checks, facilitator checks, settlement_record predicate,
# whether report member block_bound can lift the level, whether canonical final with l1_state proven can)
_EVM = (("L2.sig", "K1", "K2", "K3"), ("T1", "T2"), _evm_chain)
EVIDENCE_RULES = {
    "apc-0.1": _EVM + (False, False),
    "apc-0.2": _EVM + (False, False),
    "apc-0.3": _EVM + (True, True),
    "apc-0.13": _EVM + (True, True),
    "apc-0.10": (("L2.sig", "K1", "K2", "K3", "K7"), ("T1", "T2"), _evm_chain, True, True),
    "apc-0.5": (("S1", "S2"), ("T1",), _all("C1", "C2", "C3"), False, False),
    "apc-0.12": (("G1", "G2"), ("T1",), _all("C1", "C2", "C3"), False, False),
    "apc-0.15": (("AC5", "AC6", "AC7"), ("T1",), _all("C1", "C2", "C3", "C4"), False, False),
    "apc-0.16": (("R3", "R4", "R5", "R6", "R10"), ("T1",), _all("C1", "C2", "C3", "C4"), True, False),
}


def evidence(version, out):
    """SPEC 30.1: (evidence_level, facilitator_reply, notes). The level is the highest of 30.2 whose checks, and those of
    every level below, count (`none` for chain_failed); facilitator_reply reads the facilitator checks of the row,
    whatever the verdict. A version without a row is a KeyError: an internal error (SPEC 29.3), never a level."""
    sig, fac, chain, bb, can = EVIDENCE_RULES[version]
    res = out["checks"]
    c = _Counter(version, res)
    if all(res.get(k) == NO_SETTLEMENT for k in fac):
        reply = "absent"
    elif any(isinstance(res.get(k), str) and res[k].startswith("failed:") for k in fac):
        reply = "failed"
    elif all([c(k) for k in fac]):
        reply = "verified"
    else:
        reply = "not_evaluated"
    notes = []
    if out["verdict"] == "chain_failed":
        level = 0
    else:
        final = can and out.get("canonical") == "final"
        steps = (all([c(k) for k in sig]), chain(c), bb and out.get("block_bound") is True,
                 final and out.get("l1_state") == "proven")
        level = 0
        while level < len(steps) and steps[level]:
            level += 1
        if level == 3 and final:
            notes.append("evidence_level inclusion_proof: canonical final rests on L1 replies the bundle carries, "
                         "declared (l1_state %s); finality_proven needs l1_state proven (SPEC 30.1)" % out.get("l1_state"))
    notes = ["evidence_level: %s outcome %s is not in the closed list of SPEC 30.4 for %s: it does not count"
             % (k, x, version) for k, x in c.outside] + notes
    return EVIDENCE_LEVELS[level], reply, notes


def evidence_level(version, out):
    """SPEC 30.1: the member evidence_level alone."""
    return evidence(version, out)[0]


def require_level(rep, level):
    """SPEC 30.3: `evidence_required` on a report of verify_bundle (every one carries evidence_level); chain_verified
    below LEVEL becomes chain_incomplete. No other verdict changes."""
    met = EVIDENCE_LEVELS.index(rep["evidence_level"]) >= EVIDENCE_LEVELS.index(level)
    rep["evidence_required"] = {"level": level, "met": met}
    if rep["verdict"] == "chain_verified" and not met:
        rep["verdict"] = "chain_incomplete"
        rep["notes"] = rep["notes"] + ["evidence_level %s is below the required %s (--require-level, SPEC 30.3): "
                                       "verdict chain_incomplete" % (rep["evidence_level"], level)]
    return rep


def read_bundle_bytes(path):
    """The bytes of a regular file of at most MAX_BUNDLE_BYTES (a FIFO would block, /dev/zero would never end)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refusal("cannot read %s: not a regular file" % path)
        with os.fdopen(fd, "rb") as fh:
            fd = None
            data = fh.read(MAX_BUNDLE_BYTES + 1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(data) > MAX_BUNDLE_BYTES:
        raise Refusal("cannot read %s: larger than %d bytes" % (path, MAX_BUNDLE_BYTES))
    return data


def main(argv):
    drafts = "--drafts" in argv[1:]                     # SPEC section 17: draft profiles, kept apart
    args = [a for a in argv[1:] if a not in ("--json", "--drafts")]
    checkpoint = None
    if "--l1-checkpoint" in args:                       # SPEC 0.4: an L1 block hash the reader trusts
        i = args.index("--l1-checkpoint")
        checkpoint = args[i + 1].lower() if i + 1 < len(args) else ""
        del args[i:i + 2]
        if not HASH32.match(checkpoint):
            print(__doc__)
            return 64
    keys_path = None
    if "--http-keys" in args:                           # SPEC 0.8: the reader's RFC 9421 keys
        i = args.index("--http-keys")
        keys_path = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        if not keys_path or keys_path.startswith("-"):
            print(__doc__)
            return 64
    trust_path = None
    if "--signer-trust" in args:                        # SPEC 0.11: the reader's signer_trust for offers and receipts
        i = args.index("--signer-trust")
        trust_path = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        if not trust_path or trust_path.startswith("-"):
            print(__doc__)
            return 64
    if "--ap2-tsa-cert" in args:                        # SPEC 0.20: the reader's TSA certificate for the mandate pack
        i = args.index("--ap2-tsa-cert")
        AP2_TSA_CERT[0] = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        if not AP2_TSA_CERT[0] or AP2_TSA_CERT[0].startswith("-"):
            print(__doc__)
            return 64
    level = None
    if "--require-level" in args:                       # SPEC 30.3: the evidence the reader requires
        i = args.index("--require-level")
        level = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        if level not in EVIDENCE_LEVELS[1:]:
            print(__doc__)
            return 64
    if len(args) != 1 or args[0].startswith("-"):
        print(__doc__)
        return 64
    try:
        try:
            doc = strict_json(read_bundle_bytes(args[0]).decode("utf-8"))
        except OSError as e:
            raise Refusal("cannot read %s: %s" % (args[0], e.strerror or e))
        keys = None
        if keys_path is not None:
            try:
                keys = strict_json(read_bundle_bytes(keys_path).decode("utf-8"))
            except OSError as e:
                raise Refusal("cannot read %s: %s" % (keys_path, e.strerror or e))
        trust = None
        if trust_path is not None:
            try:
                trust = strict_json(read_bundle_bytes(trust_path).decode("utf-8"))
            except OSError as e:
                raise Refusal("cannot read %s: %s" % (trust_path, e.strerror or e))
        rep = verify_bundle(doc, checkpoint, keys, trust, drafts)
        if level is not None:
            rep = require_level(rep, level)
    except Unsupported as e:
        rep = {"verifier": VERSION, "verdict": "unsupported", "reason": str(e)}
    except (Refusal, UnicodeDecodeError) as e:
        rep = {"verifier": VERSION, "verdict": "refused", "reason": str(e)}
    except Exception as e:          # SPEC 29.3: a defect of this verifier is never an outcome 0, 1 or 2 (nor a traceback's 1)
        rep = {"verifier": VERSION, "verdict": "error", "reason": "internal error of the verifier: %s (SPEC 29.3)"
               % type(e).__name__}
    try:
        sys.stdout.write(json.dumps(rep, indent=1, sort_keys=True) + "\n")
        sys.stdout.flush()
    except (OSError, AttributeError, ValueError) as e:
        # SPEC 29.3: a report that cannot be written (standard output closed or full) is exit 74, never 0-3 (a
        # traceback's 1 would read as chain_failed); standard output goes to the null device so that the interpreter's
        # last flush cannot turn the exit into 120
        fds = [1]
        try:
            sys.stderr.write("apc_verify: the report could not be written (%s)\n" % type(e).__name__)
        except (OSError, AttributeError, ValueError):
            fds.append(2)           # standard error full too: its last flush must not turn 74 into 120 (independent review 2 27/10)
        for fd in fds:
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), fd)
            except OSError:
                pass
        return 74
    return {"chain_verified": 0, "chain_failed": 1, "chain_incomplete": 2}.get(rep["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
