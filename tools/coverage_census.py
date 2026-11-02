"""Coverage census: which share of the real x402 payments saved in this repository apc verifies today, per network
and asset, and why the rest is left out. Offline (standard library and the repository's own modules); every number
is derived from saved RPC replies.

  python3 -B tools/coverage_census.py CAMPAIGN.json [--json OUT.json] [--no-table]

CAMPAIGN.json (closed: any other member is refused): {"campaign": str, "entries": [ENTRY, ...]}; ENTRY members:
  kind      "evm_eip3009"   census_eip3009.py file + log_pairs.py file (+ payer-wallet replies): every
                            AuthorizationUsed log of the token over the window, direct and indirect calls
            "evm_direct"    fetch_base_eip3009.py file: only the direct calls were saved; the rest is counted, not
                            classified
            "evm_permit2"   proxy transactions with receipts ({"items": {hash: {"tx", "receipt"}}}) of the
                            x402ExactPermit2Proxy (SPEC section 12)
            "svm_exact"     getTransaction replies of transactions signed by listed fee payers (SPEC section 7)
  network, asset, label     strings (label names the window)
  files                     {role: path} relative to the repository root; roles per kind: evm_eip3009 census,
                            transfers, wallets (optional, list); evm_direct oracle; evm_permit2 txs; svm_exact source

Per authorization (evm_eip3009) the bundle is built in memory exactly as tools/make_bundles_v02.py builds it
(--wallets mode, wallet replies read from the saved files instead of the RPC) and verified by apc_verify.verify_bundle;
an authorization with no bundle gets an exclusion class: the ROUTE (what the transaction calls, from the closed table
ROUTES keyed by network and address, plus oracle/coverage_20261026/routes/ROUTES.json, each entry with the text it
rests on; an address in neither is `other_contract`) and the PAYER (eoa, a wallet kind, or `not_read` when a reply the
wallet rule reads is not saved: the payer's code, its ERC-1967 implementation slot, or, for a listed implementation,
ownerAtIndex(0)), and a diagnostic `inner`: the EIP-3009 calls found anywhere in the calldata
and whether their signature recovers the payer. evm_direct: a token without a public version() gets the EIP-712
domain version under which every executed signature recovers (as tools/world_bundles.py), or none.
recover_public_key is memoized for the run (a pure function; it only saves time). x402 attribution, two criteria, both
reported: the facilitator lists (x402scan @5732bb8 per network, sources/labels_ours.json) on the transaction sender
or the called contract; and the ERC-8021 Schema 2 builder code `w` in a direct call's calldata (x402 builder_code.md;
self-declared, no contract checks it).

Output: canonical JSON (keys sorted, no spaces, UTF-8, one final newline) and a text table."""
import glob
import gzip
import json
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import apc_msca  # noqa: E402
import apc_verify as av  # noqa: E402
import make_bundles_v02 as mb  # noqa: E402
from apc_verify import keccak256  # noqa: E402

VERSION = "coverage_census 0.2.1"


def _memo_recover():
    """The bundle builder and the verifier recover the same signatures: recover_public_key is a pure function, so its
    results are memoized for the run (an exception is not cached: it is raised again on every call)."""
    import functools
    import lib.secp256k1 as k1
    f = functools.lru_cache(maxsize=65536)(k1.recover_public_key)
    for m in (av, mb):
        m.recover_public_key = f


_memo_recover()
TOKEN_SELECTORS = {"0xe3ee160e": "vrs", "0xcf092995": "bytes"}
# EIP-3009 calls that emit AuthorizationUsed (Circle stablecoin-evm EIP3009.sol); only the transfer ones are built.
INNER = {bytes.fromhex("e3ee160e"): "transferWithAuthorization_vrs", bytes.fromhex("cf092995"): "transferWithAuthorization_bytes",
         bytes.fromhex("ef55bec6"): "receiveWithAuthorization_vrs", bytes.fromhex("88b7ab63"): "receiveWithAuthorization_bytes"}


def _recovers_as(dom, msg, sig, primary):
    """Does the 65-byte signature recover `from` for the EIP-3009 type `primary` (same members for both types)."""
    from lib.eip712 import signing_digest
    from lib.secp256k1 import public_key_to_address
    types = {primary: av.TYPES["TransferWithAuthorization"]}
    digest = signing_digest(dom, primary, types, msg, av.DOMAIN4)
    if sig[64] not in (27, 28):
        return False
    try:
        return public_key_to_address(av.recover_public_key(digest, int.from_bytes(sig[:32], "big"),
                                                           int.from_bytes(sig[32:64], "big"), sig[64] - 27),
                                     keccak256) == msg["from"]
    except ValueError:
        return False


def inner_calls(b, frm, nonce, dom):
    """What an excluded transaction's calldata carries: for each EIP-3009 selector found anywhere in it, whether its
    (from, nonce) are the log's and, for a 65-byte signature, whether it recovers `from` (diagnostic only)."""
    out = set()
    for i in range(len(b) - 3):
        name = INNER.get(b[i:i + 4])
        if name is None:
            continue
        a = b[i + 4:]
        if len(a) < 32 * 7 or any(a[k * 32:k * 32 + 12] != bytes(12) for k in (0, 1)):
            continue
        if "0x" + a[12:32].hex() != frm or "0x" + a[160:192].hex() != nonce:
            out.add(name + ":other_authorization")
            continue
        sel = b[i:i + 4]
        probe = (bytes.fromhex("e3ee160e") if name.endswith("vrs") else bytes.fromhex("cf092995")) + b[i + 4:]
        d = mb.decode_at(probe, 0)
        if d is None:
            out.add(name + ":signature_not_65_bytes")
        elif _recovers_as(dom, d[1], d[2], "TransferWithAuthorization" if sel in mb.SEL else "ReceiveWithAuthorization"):
            out.add(name + (":recovers" if sel in mb.SEL else ":recovers_receive_not_built"))
        else:
            out.add(name + ":does_not_recover")
    return sorted(out) or ["no_eip3009_call_in_calldata"]

# What a transaction calls, when it is not the token itself. Closed: an address not here is `other_contract`.
# Key (network, address); network "*" for a deployment at the same address on every chain (CREATE2 / keyless, stated
# by its source). Each entry: (class, the text it rests on).
SRC = "oracle/coverage_20261026/routes/sourcify_"
ROUTES = {
    ("*", "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"): (
        "erc4337_entrypoint_v0_6", "ERC-4337 EntryPoint v0.6: Sourcify exact_match contracts/core/EntryPoint.sol, solc "
        "0.8.17, on eip155:8453 (%s8453_0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789.json)" % SRC),
    ("*", "0x0000000071727de22e5e9d8baf0edac6f37da032"): (
        "erc4337_entrypoint_v0_7", "ERC-4337 EntryPoint v0.7: Sourcify exact_match contracts/core/EntryPoint.sol on "
        "eip155:8453 and eip155:1 (%s8453_0x0000000071727de22e5e9d8baf0edac6f37da032.json, "
        "%s1_0x0000000071727de22e5e9d8baf0edac6f37da032.json)" % (SRC, SRC)),
    ("*", "0x4020074e9df2ce1dee5a9c1b5c3f541d02a10003"): (
        "x402_batch_settlement", "sources/x402_schemes_20261026/scheme_batch_settlement_evm.md lines 680, 684 "
        "(\"deterministic address across all supported EVM chains\"); Sourcify match src/x402BatchSettlement.sol on "
        "eip155:8453 (%s8453_0x4020074e9df2ce1dee5a9c1b5c3f541d02a10003.json)" % SRC),
    ("*", "0xca11bde05977b3631167028862be2a173976ca11"): (
        "multicall3", "Sourcify exact_match Multicall3.sol on eip155:8453 and eip155:43114 "
        "(%s8453_0xca11bde05977b3631167028862be2a173976ca11.json, "
        "%s43114_0xca11bde05977b3631167028862be2a173976ca11.json)" % (SRC, SRC)),
    ("eip155:8453", "0xf96815976523e00e65be8f34ca5e64b4f41eb19c"): (
        "x402_auth_capture_escrow", "sources/x402_schemes_20261026/scheme_auth_capture_evm.md line 142 (v1.1)"),
    ("eip155:8453", "0xbdea0d1bcc5966192b070fdf62ab4ef5b4420cff"): (
        "x402_auth_capture_escrow", "sources/x402_schemes_20261026/scheme_auth_capture_evm.md line 142 (v1.0)"),
    ("eip155:8453", "0xe807a76385ec3d76d17ab955091c12329d0a1403"): (
        "centralcity_fee_router", "sources/labels_ours.json (centralcity protocol-fees.md lines 91-99, read 2026-10-22: URL and sha256 in sources/centralcity_20261022/PROVENANCE and SHA256SUMS; the page is not redistributed)"),
}
EXTRA_ROUTES = os.path.join(ROOT, "oracle", "coverage_20261026", "routes", "ROUTES.json")


def load_routes():
    """ROUTES plus the explorer-read entries of oracle/coverage_20261026/routes/ROUTES.json (if present)."""
    r = dict(ROUTES)
    if os.path.exists(EXTRA_ROUTES):
        with open(EXTRA_ROUTES) as fh:
            extra = json.load(fh)["routes"]
        for k, x in extra.items():
            net, a = k.rsplit(":", 1)
            r.setdefault((net, a.lower()), (x["class"], x["source"]))
    return r


def route_of(routes, net, target):
    return routes.get((net, target)) or routes.get(("*", target)) or ("other_contract", None)


def _read(path):
    p = os.path.join(ROOT, path)
    with (gzip.open(p, "rt") if p.endswith(".gz") else open(p)) as fh:
        return json.load(fh)


NETWORK_IDS = {"BASE": "eip155:8453", "POLYGON": "eip155:137", "SOLANA": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}


def facilitators(d=os.path.join(ROOT, "sources", "x402scan_5732bb8")):
    """{network: {address: [ids]}} from the pinned x402scan list (addresses under each `[Network.X]:` key), the
    labels of sources/labels_ours.json under eip155:8453, and under "*" every address of any network."""
    m = {}
    for f in sorted(glob.glob(os.path.join(d, "src", "facilitators", "*.ts"))):
        with open(f) as fh:
            s = fh.read()
        ids = re.findall(r"\bid:\s*'([^']+)'", s)
        if "addresses" not in s or not ids:
            continue
        body = s[s.index("addresses"):]
        parts = re.split(r"\[Network\.([A-Z_]+)\]\s*:", body)
        for net, chunk in zip(parts[1::2], parts[2::2]):
            for a in re.findall(r"'(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})'", chunk):
                key = a.lower() if a.startswith("0x") else a
                for n in (NETWORK_IDS.get(net, "x402scan:" + net), "*"):
                    m.setdefault(n, {}).setdefault(key, set()).add(ids[0])
    ours = os.path.join(ROOT, "sources", "labels_ours.json")
    with open(ours) as fh:
        lab = json.load(fh)["labels"]
    for a, x in lab.items():
        for n in ("eip155:8453", "*"):
            m.setdefault(n, {}).setdefault(a.lower(), set()).add(x["name"])
    return {n: {a: sorted(v) for a, v in t.items()} for n, t in m.items()}


class WalletReplies:
    """mb.payer_wallet from saved replies: (method, params) -> result. A missing reply gives `not_read`."""

    def __init__(self, paths):
        self.r = {}
        for p in paths:
            d = _read(p)
            items = d.get("replies") if isinstance(d, dict) and "replies" in d else d
            if isinstance(items, dict):
                items = list(items.items())
            for it in items:
                for rep in self._walk(it):
                    self.r[self._key(rep["method"], rep["params"])] = rep
        self.missing = set()
        self.not_read = set()

    def _walk(self, x):
        if isinstance(x, dict):
            if "method" in x and "params" in x and "result" in x:
                yield x
            else:
                for v in x.values():
                    yield from self._walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                yield from self._walk(v)

    @staticmethod
    def _key(method, params):
        return json.dumps([method, params], sort_keys=True).lower()

    def get(self, method, params):
        rep = self.r.get(self._key(method, params))
        if rep is None:
            self.missing.add(json.dumps([method, params]))
        return rep

    def payer_wallet(self, frm, blk):
        """Same answers as make_bundles_v02.payer_wallet, from the saved replies."""
        code = self.get("eth_getCode", [frm, blk])
        if code is None:
            self.not_read.add((frm, blk))
            return "not_read"
        if code["result"] == "0x":
            return None
        if code["result"].startswith("0xef0100") and "0x" + code["result"][8:] not in av.WALLET_7702:
            return "eip7702_delegate_" + code["result"][8:48]
        if not code["result"].startswith("0xef0100") \
                and keccak256(bytes.fromhex(code["result"][2:])).hex() not in av.WALLET_PROXY_CODE:
            return "code_not_known"
        impl = self.get("eth_getStorageAt", [frm, av.ERC1967_SLOT, blk])
        if impl is None:
            self.not_read.add((frm, blk))
            return "not_read"
        if "0x" + impl["result"][-40:] not in av.WALLET_IMPL:
            return "implementation_" + impl["result"][-40:]
        owner = self.get("eth_call", [{"to": frm, "data": "0x" + keccak256(b"ownerAtIndex(uint256)")[:4].hex()
                                       + "%064x" % 0}, blk])
        if owner is None:
            self.not_read.add((frm, blk))
            return "not_read"
        return {"owner_index": "0", "code": code, "implementation": impl, "owner": owner}

    def payer_state(self, frm, blk):
        """SPEC 32.4, the rpc form from the saved replies, for a payer whose code is in apc_msca.WALLETS (32.5): the
        member, or None when the code is not listed, or `not_read` when one of the five replies is not saved."""
        code = self.get("eth_getCode", [frm, blk])
        if code is None:
            self.not_read.add((frm, blk))
            return "not_read"
        pin = apc_msca.WALLETS.get(keccak256(bytes.fromhex(code["result"][2:])).hex())
        if pin is None:
            return None
        impl = self.get("eth_getStorageAt", [frm, "0x%064x" % apc_msca.ERC1967_SLOT, blk])
        own = self.get("eth_getStorageAt", [frm, "0x%064x" % pin[2], blk])
        if impl is None or own is None:
            self.not_read.add((frm, blk))
            return "not_read"
        impl_addr, owner = "0x" + impl["result"][-40:], "0x%040x" % (int(own["result"], 16) >> 16)
        ic, oc = self.get("eth_getCode", [impl_addr, blk]), self.get("eth_getCode", [owner, blk])
        if ic is None or oc is None:
            self.not_read.add((frm, blk))
            return "not_read"
        return {"rpc": {"code": code, "wallet": {"implementation": impl, "owner": own, "implementation_code": ic,
                                                 "owner_code": oc}}}


def _report(bundle):
    """The report of apc_verify on a copy of the bundle; a refusal or an unsupported version as a verdict-only report."""
    try:
        return av.verify_bundle(json.loads(json.dumps(bundle)))
    except av.Unsupported:
        return {"verdict": "unsupported", "checks": {}}
    except av.Refusal:
        return {"verdict": "refused", "checks": {}}


def _verdict(bundle):
    return _report(bundle)["verdict"]


def builder_w(inp):
    """The `w` code of an ERC-8021 Schema 2 suffix on a direct token call, or None."""
    form = TOKEN_SELECTORS.get(inp[:10].lower())
    if form is None:
        return None
    try:
        from census_eip3009 import tail_of
        cb = av.erc8021_schema2(tail_of(inp, form))
    except (ValueError, IndexError):
        return None
    if cb is None:
        return None
    import apc_builder
    try:
        dec, _why = apc_builder.decode(bytes.fromhex(cb))
    except (IndexError, ValueError):        # a suffix the decoder cannot read: no code
        return None
    w = dec.get("w") if isinstance(dec, dict) else None
    return w if isinstance(w, str) else None


def classify_eip3009(entry, fac, routes, disable=(), only=None):
    """One record per AuthorizationUsed log. `disable` names rules switched off (positive controls in the tests):
    "log_guided", "wallet_1271", "msca_1271", "route:<address>". `only`: a set of transaction hashes to keep (tests)."""
    f = entry["files"]
    c, t = _read(f["census"]), _read(f["transfers"])
    wal = WalletReplies(f.get("wallets", []))
    s = c["summary"]
    token, net = s["token"], "eip155:%d" % s["chain_id"]
    dom = {"name": s["token_name"], "version": s["token_version"], "chainId": s["chain_id"], "verifyingContract": token}
    txs = {x["params"][0]: x["result"] for x in c["calls"] if x["method"] == "eth_getTransactionByHash"}
    au = [lg for x in c["calls"] if x["method"] == "eth_getLogs" for lg in x["result"]
          if only is None or lg["transactionHash"] in only]
    tr = {(lg["transactionHash"], int(lg["logIndex"], 16)): lg for x in t["calls"] for lg in x["result"]}
    nfac, anyfac = fac.get(net, {}), fac["*"]
    recs = []
    for lg in au:
        h = lg["transactionHash"]
        tx = txs[h]
        lt = tr.get((h, int(lg["logIndex"], 16) + 1))
        b = bytes.fromhex(tx["input"][2:])
        direct = (tx["to"] or "").lower() == token
        target = (tx["to"] or "").lower()
        sender = tx["from"].lower()
        frm = "0x" + lg["topics"][1][-40:]
        found = None
        for pos in ([0] if direct else [i for i in range(len(b) - 3) if b[i:i + 4] in mb.SEL]):
            d = mb.decode_at(b, pos)
            if d and d[1]["from"] == frm and d[1]["nonce"] == lg["topics"][2].lower() and mb.recovers(dom, d[1], d[2]):
                found = d
                break
        extraction = "calldata"
        if found is None and lt is not None and not direct and "log_guided" not in disable:
            nonce = lg["topics"][2].lower()
            to, value = "0x" + lt["topics"][2][-40:], int(lt["data"], 16)
            if "0x" + lt["topics"][1][-40:] == frm:
                for msg, sig in mb.log_guided(b, frm, nonce, to, value):
                    if sig[64] in (27, 28) and mb.recovers(dom, msg, sig):
                        found, extraction = ("bytes", msg, sig), "log_guided"
                        break
        pw = None
        if found is None and lt is not None and "0x" + lt["topics"][1][-40:] == frm:
            pw = wal.payer_wallet(frm, tx["blockNumber"])
            if isinstance(pw, dict) and "wallet_1271" not in disable:
                to, value = "0x" + lt["topics"][2][-40:], int(lt["data"], 16)
                acc0 = {"domain_name": s["token_name"], "domain_version": s["token_version"],
                        "chain_id": s["chain_id"], "asset": token, "notes": []}
                for va, vb in mb.windows_of(b):
                    msg = {"from": frm, "to": to, "value": value, "validAfter": va, "validBefore": vb,
                           "nonce": lg["topics"][2].lower()}
                    for blob in mb.abi_blobs(b):
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
        state = None
        if found is None and lt is not None and direct and pw == "code_not_known" and "msca_1271" not in disable:
            # SPEC 32: a direct call whose authorization names the payer and nonce of the log but whose 65-byte signature
            # does not recover the payer; the payer's code is a listed wallet (32.5) and its state is in the saved replies
            d = mb.decode_at(b, 0)
            if d and d[1]["from"] == frm and d[1]["nonce"] == lg["topics"][2].lower():
                ps = wal.payer_state(frm, tx["blockNumber"])
                if isinstance(ps, dict):
                    found, extraction, state = d, "msca_1271", ps
                elif ps == "not_read":
                    pw = "not_read"
        labels = nfac.get(sender) or nfac.get(target) or []
        other_net = [] if labels else (anyfac.get(sender) or anyfac.get(target) or [])
        rec = {"tx": h, "log_index": int(lg["logIndex"], 16), "sender": sender, "target": target, "direct": direct,
               "facilitator": labels, "facilitator_other_network": other_net,
               "builder_w": builder_w(tx["input"]) if direct else None}
        if found is None or lt is None:
            why = "no_transfer_next" if lt is None else ("direct_not_decoded" if direct else "indirect_not_extracted")
            route = "token_direct" if direct else ("other_contract" if ("route:" + target) in disable
                                                   else route_of(routes, net, target)[0])
            payer = ("eoa_or_not_read" if pw is None and lt is None else "eoa" if pw is None
                     else pw if isinstance(pw, str) else "CoinbaseSmartWallet_no_signature_verified")
            if payer.startswith("eip7702_delegate_"):
                payer = "eip7702_delegate"
            elif payer.startswith("implementation_"):
                payer = "wallet_implementation_not_listed"
            rec.update(built=False, reason=why, route=route, payer=payer,
                       payer_detail=pw if isinstance(pw, str) else None,
                       inner=inner_calls(b, frm, lg["topics"][2].lower(), dom),
                       selector=tx["input"][:10].lower())
            recs.append(rec)
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
        if state is not None:
            bundle["payer_state"] = state
        lf = tr.get((h, int(lt["logIndex"], 16) + 1))
        if lf is not None and lf["topics"][1].lower() == "0x" + "0" * 24 + msg["to"][2:]:
            bundle["chain_tx"]["log_forward"] = lf
        rep = _report(bundle)
        # l2_sig: the L2.sig outcome, so that a bundle built with payer_state (SPEC 32) is told apart from one without
        # it (both chain_incomplete since 0.21.1: 32.2 without the member, 32.10 with it)
        rec.update(built=True, extraction=extraction, verdict=rep["verdict"], l2_sig=rep["checks"].get("L2.sig"))
        recs.append(rec)
    return recs, {"window": [s.get("from_block"), s.get("n_blocks")], "token_name": s["token_name"],
                  "missing_replies": len(wal.missing), "wallet_not_read": sorted(map(list, wal.not_read))}, wal


def classify_direct(entry, fac):
    """fetch_base_eip3009.py file: only direct calls saved; each built and verified, the rest only counted."""
    d = _read(entry["files"]["oracle"])
    s = d["summary"]
    net = "eip155:%d" % s["chain_id"]
    txs = {x["params"][0]: x["result"] for x in d["calls"] if x["method"] == "eth_getTransactionByHash"}
    au = [lg for x in d["calls"] if x["method"] == "eth_getLogs" for lg in x["result"]]
    recs = []
    kept = {k["tx"] for k in d["kept"]}
    nfac, anyfac = fac.get(net, {}), fac["*"]
    version, how = s.get("token_version"), "version()"
    if version is None:         # no public version() (as tools/world_bundles.py): the one under which every executed
        decs = [x for x in (mb.decode_at(bytes.fromhex(txs[h]["input"][2:]), 0) for h in kept) if x]   # signature
        ok = [v for v in ("1", "2", "3") if decs and all(mb.recovers(                                    # recovers
            {"name": s["token_name"], "version": v, "chainId": s["chain_id"], "verifyingContract": s["token"]},
            x[1], x[2]) for x in decs)]
        version, how = (ok[0], "recovery") if len(ok) == 1 else (None, "not_found:%d" % len(ok))
        s = dict(s, token_version=version)
    for lg in au:
        h = lg["transactionHash"]
        if h not in kept:
            recs.append({"tx": h, "built": False, "reason": "transaction_not_saved", "route": "not_saved",
                         "payer": "not_read", "direct": None, "facilitator": [], "facilitator_other_network": [],
                         "builder_w": None})
            continue
        tx = txs[h]
        sender = tx["from"].lower()
        labels = nfac.get(sender) or []
        rec = {"tx": h, "sender": sender, "target": tx["to"].lower(), "direct": True, "facilitator": labels,
               "facilitator_other_network": [] if labels else anyfac.get(sender, []), "builder_w": builder_w(tx["input"])}
        dec = mb.decode_at(bytes.fromhex(tx["input"][2:]), 0)
        if dec is None or s.get("token_version") is None:
            rec.update(built=False, reason="direct_not_decoded" if dec is None else "domain_version_not_public",
                       route="token_direct", payer="not_read")
            recs.append(rec)
            continue
        _, au_msg, sigb = dec
        sig = "0x" + sigb.hex()
        if au_msg["from"] != "0x" + lg["topics"][1][-40:] or au_msg["nonce"] != lg["topics"][2].lower():
            rec.update(built=False, reason="log_not_this_authorization", route="token_direct", payer="not_read")
            recs.append(rec)
            continue
        acc = {"scheme": "exact", "network": net, "amount": str(au_msg["value"]), "asset": s["token"],
               "payTo": au_msg["to"], "maxTimeoutSeconds": 60,
               "extra": {"name": s["token_name"], "version": s["token_version"]}}
        bundle = {"bundle_version": "apc-0.1",
                  "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
                      "signature": sig, "authorization": {k: str(au_msg[k]) if k in ("value", "validAfter", "validBefore")
                                                          else au_msg[k] for k in
                                                          ("from", "to", "value", "validAfter", "validBefore", "nonce")}}},
                  "settlement": {"success": True, "transaction": h, "network": net, "payer": au_msg["from"]},
                  "chain_tx": {"network": net, "tx": tx, "log_authorization_used": lg}}
        rec.update(built=True, extraction="calldata", verdict=_verdict(bundle))
        recs.append(rec)
    return recs, {"window": [s["head_block"] - s["blocks_scanned"] + 1, s["blocks_scanned"]],
                  "token_name": s["token_name"], "missing_replies": 0, "domain_version": [version, how]}, None


def classify_permit2(entry, fac):
    import make_bundles_permit2 as mp
    items = _read(entry["files"]["txs"])["items"]
    out, skipped = mp.build(items)
    nfac = fac.get(entry["network"], {})
    recs = []
    for name, b in out:
        tx = b["chain_tx"]["tx"]
        recs.append({"tx": b["settlement"]["transaction"], "sender": tx["from"].lower(), "target": tx["to"].lower(),
                     "direct": False, "facilitator": nfac.get(tx["from"].lower(), []), "facilitator_other_network": [],
                     "builder_w": None, "built": True, "extraction": "calldata", "verdict": _verdict(b)})
    for h, why in skipped:
        recs.append({"tx": h, "built": False, "reason": why, "route": "x402_exact_permit2_proxy", "payer": "not_read",
                     "direct": False, "facilitator": [], "facilitator_other_network": [], "builder_w": None})
    return recs, {"window": None, "token_name": None, "missing_replies": 0}, None


def classify_svm(entry, fac):
    saved = sys.argv
    sys.argv = [saved[0]]
    try:
        import make_bundles_svm as ms
    finally:
        sys.argv = saved
    d = _read(entry["files"]["source"])
    recs = []
    for t in d["txs"]:
        rec = {"tx": t["signature"], "sender": t["fee_payer_listed"], "target": None, "direct": None,
               "facilitator": [t["facilitator"]], "facilitator_other_network": [], "builder_w": None}
        if t["raw"] is None:
            rec.update(built=False, reason="transaction_not_returned", route="not_saved", payer="not_read")
        elif t["raw"]["meta"]["err"] is not None:
            rec.update(built=False, reason="transaction_failed_on_chain", route="failed", payer="not_read")
        else:
            try:
                b, why = ms.bundle(t["raw"], t["fee_payer_listed"])
            except Exception as e:  # noqa: BLE001 - a transaction outside the builder's reach is counted, not hidden
                b, why = None, "builder_error:" + type(e).__name__
            if b is None:
                rec["inner"] = [_svm_inner_transfer(t["raw"], ms.sol)]
                rec.update(built=False, reason=why, payer="not_read",
                           route={"account 0 is not the listed fee payer": "fee_payer_not_account0",
                                  "no top-level TransferChecked": "no_top_level_transfer_checked"}.get(why, "other"))
            else:
                rec.update(built=True, extraction="transaction", verdict=_verdict(b))
        recs.append(rec)
    return recs, {"window": None, "token_name": None, "missing_replies": 0}, None


def _svm_inner_transfer(raw, sol):
    """Diagnostic for a transaction left out: does its CPI trace (meta.innerInstructions) carry a TransferChecked
    (SPL Token or Token-2022, discriminator 12)? SVM exact allows the transfer as an inner instruction (scheme_exact_svm
    "MAY appear either as a top-level instruction or as an inner instruction")."""
    import base64
    tx = sol.parse_tx(base64.b64decode(raw["transaction"][0]))
    la = raw["meta"].get("loadedAddresses") or {"writable": [], "readonly": []}
    keys = list(tx["keys"]) + list(la.get("writable", [])) + list(la.get("readonly", []))
    for grp in raw["meta"].get("innerInstructions") or []:
        for ix in grp["instructions"]:
            prog = keys[ix["programIdIndex"]] if ix["programIdIndex"] < len(keys) else None
            data = sol.b58decode(ix["data"]) if ix.get("data") else b""
            if prog in (sol.SPL_TOKEN, sol.TOKEN_2022) and data[:1] == b"\x0c":
                return "inner_transfer_checked"
    return "no_transfer_checked_in_trace"


ENTRY_KEYS = {"kind", "network", "asset", "label", "files"}
KINDS = {"evm_eip3009": ({"census", "transfers"}, {"wallets"}), "evm_direct": ({"oracle"}, set()),
         "evm_permit2": ({"txs"}, set()), "svm_exact": ({"source"}, set())}


def check_campaign(c):
    if not isinstance(c, dict) or set(c) != {"campaign", "entries"} or not isinstance(c["entries"], list):
        raise ValueError("campaign: members must be exactly campaign, entries")
    for i, e in enumerate(c["entries"]):
        if not isinstance(e, dict) or set(e) != ENTRY_KEYS:
            raise ValueError("entries[%d]: members must be exactly %s" % (i, sorted(ENTRY_KEYS)))
        if e["kind"] not in KINDS:
            raise ValueError("entries[%d].kind: %r not one of %s" % (i, e["kind"], sorted(KINDS)))
        need, opt = KINDS[e["kind"]]
        if not isinstance(e["files"], dict) or not need <= set(e["files"]) <= need | opt:
            raise ValueError("entries[%d].files: roles must be %s (optional %s)" % (i, sorted(need), sorted(opt)))


def wilson(k, n, z=1.959964):
    """95 % Wilson interval of k successes in n, as fractions; None when n = 0."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 6), round(min(1.0, c + h), 6)]


def summarize(recs):
    n = len(recs)
    built = [r for r in recs if r["built"]]
    verd = {}
    for r in built:
        verd[r["verdict"]] = verd.get(r["verdict"], 0) + 1
    excl = {}
    for r in recs:
        if not r["built"]:
            k = "%s|%s|%s" % (r["reason"], r["route"], r["payer"])
            x = excl.setdefault(k, {"count": 0, "x402_listed": 0, "x402_builder_w": 0, "targets": {}, "inner": {},
                                    "selectors": {}, "senders_listed": {}})
            for tag in r.get("inner", []):
                x["inner"][tag] = x["inner"].get(tag, 0) + 1
            if r.get("selector"):
                x["selectors"][r["selector"]] = x["selectors"].get(r["selector"], 0) + 1
            for f in r["facilitator"]:
                x["senders_listed"][f] = x["senders_listed"].get(f, 0) + 1
            x["count"] += 1
            x["x402_listed"] += bool(r["facilitator"])
            x["x402_builder_w"] += bool(r.get("builder_w"))
            if r.get("target"):
                x["targets"][r["target"]] = x["targets"].get(r["target"], 0) + 1
    att = {"listed": sum(bool(r["facilitator"]) for r in recs),
           "listed_other_network_only": sum(bool(r["facilitator_other_network"]) for r in recs),
           "builder_w": sum(bool(r.get("builder_w")) for r in recs),
           "listed_or_builder_w": sum(bool(r["facilitator"]) or bool(r.get("builder_w")) for r in recs)}
    ok = verd.get("chain_verified", 0)
    xr = [r for r in recs if r["facilitator"] or r.get("builder_w")]
    xok = sum(r["built"] and r["verdict"] == "chain_verified" for r in xr)
    return {"observed": n, "built": len(built), "verdicts": verd, "excluded": excl, "x402_attribution": att,
            "chain_verified_share": round(ok / n, 6) if n else None, "chain_verified_ci95": wilson(ok, n),
            "x402_attributed": {"observed": len(xr), "chain_verified": xok, "share": round(xok / len(xr), 6)
                                if xr else None, "ci95": wilson(xok, len(xr))}}


def run(campaign, disable=(), only=None):
    check_campaign(campaign)
    fac, routes = facilitators(), load_routes()
    groups, entries = {}, []
    for e in campaign["entries"]:
        if e["kind"] == "evm_eip3009":
            recs, meta, _ = classify_eip3009(e, fac, routes, disable, only)
        elif e["kind"] == "evm_direct":
            recs, meta, _ = classify_direct(e, fac)
        elif e["kind"] == "evm_permit2":
            recs, meta, _ = classify_permit2(e, fac)
        else:
            recs, meta, _ = classify_svm(e, fac)
        key = "%s %s %s" % (e["network"], e["asset"], e["kind"])
        groups.setdefault(key, []).extend(recs)
        entries.append(dict(summarize(recs), label=e["label"], kind=e["kind"], network=e["network"], asset=e["asset"],
                            files={k: v for k, v in sorted(e["files"].items())}, **meta))
    return {"tool": VERSION, "verifier": av.VERSION, "campaign": campaign["campaign"],
            "routes": {"%s:%s" % k: {"class": c, "source": s} for k, (c, s) in sorted(routes.items())},
            "groups": {k: summarize(v) for k, v in sorted(groups.items())}, "entries": entries}


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def table(res):
    lines = ["%-42s %7s %7s %7s %8s %13s  %s" % ("group", "obs", "built", "verif", "share", "x402 obs/ver", "excluded")]
    for k, g in res["groups"].items():
        lines.append("%-42s %7d %7d %7d %7.1f%% %6d/%-6d  %d" % (
            k, g["observed"], g["built"], g["verdicts"].get("chain_verified", 0),
            100 * (g["chain_verified_share"] or 0), g["x402_attributed"]["observed"],
            g["x402_attributed"]["chain_verified"], g["observed"] - g["built"]))
        for c, x in sorted(g["excluded"].items(), key=lambda kv: -kv[1]["count"]):
            lines.append("    %-60s %5d  (x402 listed %d, builder w %d)" % (c, x["count"], x["x402_listed"],
                                                                           x["x402_builder_w"]))
        other = {v: n for v, n in g["verdicts"].items() if v != "chain_verified"}
        if other:
            lines.append("    built, not chain_verified: %s" % json.dumps(other, sort_keys=True))
    return "\n".join(lines)


def main(argv):
    args = argv[1:]
    out = None
    if "--json" in args:
        i = args.index("--json")
        out = args[i + 1]
        del args[i:i + 2]
    quiet = "--no-table" in args
    args = [a for a in args if a != "--no-table"]
    if len(args) != 1:
        print(__doc__)
        return 64
    res = run(json.load(open(args[0])))
    text = canonical(res)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
    if not quiet:
        print(table(res))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
