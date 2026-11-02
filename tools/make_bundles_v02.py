"""apc-0.2 bundles from a census file (census_eip3009.py) and its Transfer logs (log_pairs.py), one per
AuthorizationUsed log, for direct AND indirect calls. REAL: authorization, signature, transaction, both logs, as the
RPC returned them. RECONSTRUCTED: the x402 envelope (accepted.payTo = to, amount = value; the settlement response).

Indirect calls: the inner transferWithAuthorization is searched for by its 4-byte selector anywhere in the calldata
(Multicall3 and batchers carry it whole) and kept only if its (from, nonce) are the log's and the signature recovers
`from` under the token's 4-member EIP-712 domain: the recovery is what shows the extraction is right. If no inner call
is found (a router that derives the nonce itself, e.g. one payment split in two authorizations), a LOG-GUIDED search
takes from and nonce from AuthorizationUsed, to and value from the Transfer after it, and tries the validity windows
(two consecutive words, or two words with a word 1 between them, the first 0 or a unix time, the second a later
unix time) and the 65-byte signatures (ABI
`bytes` of length 65, or v,r,s words) present in the calldata; again only a recovery of `from` is kept, and the
manifest says `extraction: log_guided`. With --wallets (needs BASE_RPC), a payer that has code gets `payer_wallet`
(its code, ERC-1967 implementation and ownerAtIndex(0), read at the transaction's block) and the candidate signatures
are every ABI `bytes` in the calldata; kept only if apc_verify's L2.sig-1271 verifies it (`extraction:
log_guided_wallet`). Calls found by none are counted by target contract and reason, not guessed.

  python3 tools/make_bundles_v02.py CENSUS.json TRANSFERS.json OUTDIR [FACILITATORS_DIR] [--wallets]

Writes OUTDIR/MANIFEST.json: per bundle the sender, the target, direct/indirect and the facilitator named for the
sender or target address by the pinned x402scan list (FACILITATORS_DIR, default sources/x402scan_5732bb8)."""
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_bundles_v02", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_verify as av  # noqa: E402
from apc_verify import TYPES, DOMAIN4  # noqa: E402
from lib.eip712 import keccak256, signing_digest  # noqa: E402
from lib.secp256k1 import public_key_to_address, recover_public_key  # noqa: E402

SEL = {bytes.fromhex("e3ee160e"): "vrs", bytes.fromhex("cf092995"): "bytes"}


def facilitator_map(d):
    m = {}
    for f in sorted(glob.glob(os.path.join(d, "src", "facilitators", "*.ts"))):
        s = open(f).read()
        ids = re.findall(r"\bid:\s*'([^']+)'", s)
        if "addresses" not in s or not ids:
            continue
        for a in re.findall(r"'(0x[0-9a-fA-F]{40})'", s[s.index("addresses"):]):
            m.setdefault(a.lower(), set()).add(ids[0])
    ours = os.path.join(ROOT, "sources", "labels_ours.json")     # labels not in x402scan, each with its source
    if os.path.exists(ours):
        for a, x in json.load(open(ours))["labels"].items():
            m.setdefault(a.lower(), set()).add(x["name"])
    return {a: sorted(v) for a, v in m.items()}


def w(b, i):
    return b[i * 32:(i + 1) * 32]


def decode_at(b, pos):
    """Decode a transferWithAuthorization call whose selector starts at b[pos]; None if it does not fit."""
    form = SEL.get(b[pos:pos + 4])
    a = b[pos + 4:]
    if form is None or len(a) < 32 * 7 or any(w(a, i)[:12] != bytes(12) for i in (0, 1)):
        return None
    msg = {"from": "0x" + w(a, 0)[12:].hex(), "to": "0x" + w(a, 1)[12:].hex(), "value": int.from_bytes(w(a, 2), "big"),
           "validAfter": int.from_bytes(w(a, 3), "big"), "validBefore": int.from_bytes(w(a, 4), "big"),
           "nonce": "0x" + w(a, 5).hex()}
    if form == "vrs":
        if len(a) < 32 * 9 or int.from_bytes(w(a, 6), "big") > 255:
            return None
        sig = w(a, 7) + w(a, 8) + bytes([int.from_bytes(w(a, 6), "big")])
    else:
        off = int.from_bytes(w(a, 6), "big")
        if off > len(a) - 32:
            return None
        n = int.from_bytes(a[off:off + 32], "big")
        sig = a[off + 32:off + 32 + n]
        if n != 65 or len(sig) != 65:
            return None
    return form, msg, sig


def log_guided(b, frm, nonce, to, value):
    """Candidates from the calldata for the parts of the authorization the logs do not carry."""
    words = [b[4 + 32 * i:4 + 32 * (i + 1)] for i in range((len(b) - 4) // 32)]
    ints = [int.from_bytes(x, "big") for x in words]
    is_time = [10 ** 9 <= n < 10 ** 10 for n in ints]
    windows = sorted({(ints[i], ints[i + 1]) for i in range(len(ints) - 1)
                      if (ints[i] == 0 or is_time[i]) and is_time[i + 1] and ints[i + 1] > ints[i]})
    sigs = []
    for i in range(len(words) - 3):
        if ints[i] == 65:                                       # ABI bytes: length 65, then 65 bytes
            sigs.append(b"".join(words[i + 1:i + 4])[:65])
        if ints[i] in (27, 28) and i + 2 < len(words):          # v, r, s words
            sigs.append(words[i + 1] + words[i + 2] + bytes([ints[i]]))
    for va, vb in windows:
        for sig in dict.fromkeys(sigs):
            yield {"from": frm, "to": to, "value": value, "validAfter": va, "validBefore": vb, "nonce": nonce}, sig


def abi_blobs(b, lo=66, hi=4096):
    """Every word-aligned ABI `bytes` (length word, data, zero padding) of length lo..hi in the calldata."""
    out = []
    for i in range(4, len(b) - 32, 32):
        n = int.from_bytes(b[i:i + 32], "big")
        end = i + 32 + (n + 31) // 32 * 32
        if lo <= n <= hi and end <= len(b) and not any(b[i + 32 + n:end]):
            out.append(b[i + 32:i + 32 + n])
    return out


def windows_of(b):
    ints = [int.from_bytes(b[4 + 32 * i:4 + 32 * (i + 1)], "big") for i in range((len(b) - 4) // 32)]
    is_time = [10 ** 9 <= n < 10 ** 10 for n in ints]
    # consecutive words, or two words apart: each value the only member of an ABI array (a length word 1 between
    # them), as a batch call of 0xa757c942 carries them (SPEC 28.5)
    return sorted({(ints[i], ints[i + d]) for d in (1, 2) for i in range(len(ints) - d)
                   if (ints[i] == 0 or is_time[i]) and is_time[i + d] and ints[i + d] > ints[i]
                   and (d == 1 or ints[i + 1] == 1)})


_WALLET = {}


def payer_wallet(frm, blk):
    """The three chain reads L2.sig-1271 needs, at the transaction's block. None if the payer has no code; a string
    naming the code or implementation if it is not in apc_verify's closed list (ownerAtIndex is then not called)."""
    from tools.fetch_base_eip3009 import rpc
    if (frm, blk) not in _WALLET:
        code = rpc("eth_getCode", [frm, blk])
        if code["result"] == "0x":
            _WALLET[(frm, blk)] = None
        elif code["result"].startswith("0xef0100") and "0x" + code["result"][8:] not in av.WALLET_7702:
            _WALLET[(frm, blk)] = "eip7702_delegate_" + code["result"][8:48]
        elif not code["result"].startswith("0xef0100") \
                and keccak256(bytes.fromhex(code["result"][2:])).hex() not in av.WALLET_PROXY_CODE:
            _WALLET[(frm, blk)] = "code_not_known"
        else:
            impl = rpc("eth_getStorageAt", [frm, av.ERC1967_SLOT, blk])
            if "0x" + impl["result"][-40:] not in av.WALLET_IMPL:
                _WALLET[(frm, blk)] = "implementation_" + impl["result"][-40:]
            else:
                _WALLET[(frm, blk)] = {
                    "owner_index": "0", "code": code, "implementation": impl,
                    "owner": rpc("eth_call", [{"to": frm, "data": "0x" + keccak256(b"ownerAtIndex(uint256)")[:4].hex()
                                               + "%064x" % 0}, blk])}
    return _WALLET[(frm, blk)]


def recovers(dom, msg, sig):
    digest = signing_digest(dom, "TransferWithAuthorization", TYPES, msg, DOMAIN4)
    try:
        return public_key_to_address(recover_public_key(digest, int.from_bytes(sig[:32], "big"),
                                                        int.from_bytes(sig[32:64], "big"), sig[64] - 27),
                                     keccak256) == msg["from"]
    except ValueError:
        return False


def main(argv):
    c, t, out = json.load(open(argv[1])), json.load(open(argv[2])), argv[3]
    wallets = "--wallets" in argv
    argv = [a for a in argv if a != "--wallets"]
    fac = facilitator_map(argv[4] if len(argv) > 4 else os.path.join(ROOT, "sources", "x402scan_5732bb8"))
    s = c["summary"]
    token, net = s["token"], "eip155:%d" % s["chain_id"]
    dom = {"name": s["token_name"], "version": s["token_version"], "chainId": s["chain_id"], "verifyingContract": token}
    txs = {x["params"][0]: x["result"] for x in c["calls"] if x["method"] == "eth_getTransactionByHash"}
    au = [lg for x in c["calls"] if x["method"] == "eth_getLogs" for lg in x["result"]]
    tr = {(lg["transactionHash"], int(lg["logIndex"], 16)): lg for x in t["calls"] for lg in x["result"]}
    manifest, skipped = [], {}
    for lg in au:
        h = lg["transactionHash"]
        tx = txs[h]
        lt = tr.get((h, int(lg["logIndex"], 16) + 1))
        b = bytes.fromhex(tx["input"][2:])
        direct = (tx["to"] or "").lower() == token
        found = None
        for pos in ([0] if direct else [i for i in range(len(b) - 3) if b[i:i + 4] in SEL]):
            d = decode_at(b, pos)
            if d and d[1]["from"] == "0x" + lg["topics"][1][-40:] and d[1]["nonce"] == lg["topics"][2].lower() \
                    and recovers(dom, d[1], d[2]):
                found = d
                break
        target = (tx["to"] or "").lower()
        extraction = "calldata"
        if found is None and lt is not None and not direct:
            frm, nonce = "0x" + lg["topics"][1][-40:], lg["topics"][2].lower()
            to, value = "0x" + lt["topics"][2][-40:], int(lt["data"], 16)
            if "0x" + lt["topics"][1][-40:] == frm:
                for msg, sig in log_guided(b, frm, nonce, to, value):
                    if sig[64] in (27, 28) and recovers(dom, msg, sig):
                        found, extraction = ("bytes", msg, sig), "log_guided"
                        break
        pw = None
        if found is None and lt is not None and wallets and "0x" + lt["topics"][1][-40:] == "0x" + lg["topics"][1][-40:]:
            frm, nonce = "0x" + lg["topics"][1][-40:], lg["topics"][2].lower()
            pw = payer_wallet(frm, tx["blockNumber"])
            if isinstance(pw, dict):
                to, value = "0x" + lt["topics"][2][-40:], int(lt["data"], 16)
                acc0 = {"domain_name": s["token_name"], "domain_version": s["token_version"], "chain_id": s["chain_id"],
                        "asset": token, "notes": []}
                for va, vb in windows_of(b):
                    msg = {"from": frm, "to": to, "value": value, "validAfter": va, "validBefore": vb, "nonce": nonce}
                    for blob in abi_blobs(b):
                        try:
                            r, _ = av.check_signature_1271({"signature": blob, "auth": msg, "accepted": acc0}, pw,
                                                           tx["blockNumber"])
                        except av.Refusal:
                            continue
                        if r.startswith("verified"):
                            found, extraction = ("wallet", msg, blob), "log_guided_wallet"
                            break
                    if found:
                        break
        if found is None or lt is None:
            why = "no_transfer_next" if lt is None else ("direct_not_decoded" if direct else "indirect_not_extracted")
            if pw is not None:
                why += "_wallet_" + (pw if isinstance(pw, str) else "CoinbaseSmartWallet_no_signature_verified")
            skipped.setdefault(why, {}).setdefault(target, 0)
            skipped[why][target] += 1
            continue
        form, msg, sig = found
        acc = {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": token, "payTo": msg["to"],
               "maxTimeoutSeconds": 60, "extra": {"name": s["token_name"], "version": s["token_version"]}}
        bundle = {"bundle_version": "apc-0.2",
                  "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
                      "signature": "0x" + sig.hex(),
                      "authorization": {"from": msg["from"], "to": msg["to"], "value": str(msg["value"]),
                                        "validAfter": str(msg["validAfter"]), "validBefore": str(msg["validBefore"]),
                                        "nonce": msg["nonce"]}}},
                  "settlement": {"success": True, "transaction": h, "network": net, "payer": msg["from"]},
                  "chain_tx": {"network": net, "tx": tx, "log_authorization_used": lg, "log_transfer": lt}}
        if isinstance(pw, dict) and extraction == "log_guided_wallet":
            bundle["payer_wallet"] = pw
        lf = tr.get((h, int(lt["logIndex"], 16) + 1))
        if lf is not None and lf["topics"][1].lower() == "0x" + "0" * 24 + msg["to"][2:]:
            bundle["chain_tx"]["log_forward"] = lf      # the payee passes the payment on (SPEC 0.2 F1)
        name = "b%03d_%s_envelope_reconstructed.json" % (len(manifest) + 1, "direct" if direct else "indirect")
        with open(os.path.join(out, name), "x") as fh:
            json.dump(bundle, fh, indent=1)
        manifest.append({"file": name, "tx": h, "sender": tx["from"].lower(), "target": target, "direct": direct,
                         "form": form, "extraction": extraction, "forwarded": "log_forward" in bundle["chain_tx"], "facilitator": fac.get(tx["from"].lower()) or fac.get(target) or []})
    with open(os.path.join(out, "MANIFEST.json"), "x") as fh:
        json.dump({"census": os.path.basename(argv[1]), "bundles": manifest, "skipped": skipped}, fh, indent=1)
    print(len(manifest), "bundles;", "skipped:", json.dumps(skipped))


if __name__ == "__main__":
    main(sys.argv)
