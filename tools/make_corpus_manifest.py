"""Write corpus/MANIFEST.json (SPEC section 33) from the local corpus: bundles/, the raw replies in oracle/ where they
hold the receipts, and the frozen verdicts of regress/VERDICTS.json. Offline; for the authors of the corpus (the public
tree carries the list, not bundles/ or oracle/).

  python3 tools/make_corpus_manifest.py [OUT.json] [--cache DIR[,DIR..]] [--rpc CAIP2=URL ..]

--cache: the raw-reply caches of earlier tools/rebuild_corpus.py runs, read for the receipts the local oracle/ does not
hold (eth_getBlockReceipts of the block, else eth_getTransactionReceipt); --rpc: fetch eth_getTransactionReceipt for the
rest (the only network use of this tool; the list then anchors those receipts by hash, `receipt_root_verified` false
unless the block's set recomputed to the header's receiptsRoot).

Per bundle: the chain facts that locate the payment and the consensus fingerprints tools/rebuild_corpus.py checks
(block hash, transaction hash and index, the receipt's keccak when a verified receipt is at hand; the Solana id, slot,
fee payer and the sha256 of the execution record; the XRPL ledger hash and transaction id), what of OURS the recipe
needs (the extraction path, the settlement reply quoted from a public issue, the mandate fixture, the accepted of a
payment made for this work; for an anchored bundle the `anchor` member, SPEC 33.10), the sha256 of the file, of its content without `provenance`, its frozen verdict and the
sha256 of its checks. Per set: the recipe, the rebuild level (33.3) and its reason, the serialization that reproduces
the bytes (found by re-serializing), the parameters of the reconstruction."""
import glob
import gzip
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_corpus_manifest", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_block as ab  # noqa: E402
import apc_xrpl as xr  # noqa: E402
import make_bundles_v02 as v02  # noqa: E402
import rebuild_corpus as rc  # noqa: E402
from apc_verify import keccak256  # noqa: E402
from tools import regress  # noqa: E402

B = os.path.join(ROOT, "bundles")
O = os.path.join(ROOT, "oracle")

# set -> (recipe, rebuild level, reason or None, extra params)
SETS = {
    "real": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_world_20261026": ("evm_eip3009", "verdict", "raw RPC objects carry client-side members: their order follows the endpoint's "
                            "client (ethereum-rpc.publicnode.com, 2026-11-01, orders the tx members differently from 2026-10-26) and a log's "
                            "blockTimestamp is what the client fills (Arbitrum gave 0x0 on 2026-10-26 and the real time on 2026-11-01; Celo "
                            "omits it today); on Arbitrum, Celo and Avalanche the header or the receipts are not re-encodable here "
                            "(declared anchors, 33.4). The verdict and the checks are the same", {}),
    "real_giskard_issue1": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_issue1062": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_reverted": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_negatives_20261026": ("evm_eip3009", "verdict", "mixed set: the EVM negatives rebuild to the byte, the Solana ones to the verdict "
                                "(meta is declared data, 33.5), the XRPL ones to the content (provenance of the new fetch)", {}),
    "real_v02": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_v02_misc": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_v02_passkey": ("evm_eip3009", "verdict", "b001 carries payer_wallet: state replies of an archive endpoint, declared data (33.5)",
                         {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_v02_wallet": ("evm_eip3009", "verdict", "payer_wallet: state replies of an archive endpoint, declared data (33.5)",
                        {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_v03": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_v03_canonical": ("evm_eip3009", "local_only", "the `canonical` member needs L1 archive eth_call replies and the dispute game of "
                           "the block (tools/canonical.py): not rebuilt by this version of the list", {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_v04_l1state": ("evm_eip3009", "local_only", "canonical.l1_state needs L1 eth_getProof at block 26259631 (archive): not rebuilt "
                         "by this version of the list", {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_msca_20261101": ("evm_eip3009", "bytes", None, {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "token_name": "USD Coin", "token_version": "2"}),
    "real_permit2": ("evm_permit2", "bytes", None, {}),
    "authcap_real_20261026": ("evm_authcap", "content", None, {"escrow": "0xbdea0d1bcc5966192b070fdf62ab4ef5b4420cff", "chain_name": "Base mainnet"}),
    "authcap_real_v11_20261026": ("evm_authcap", "content", None, {"escrow": "0xf96815976523e00e65be8f34ca5e64b4f41eb19c", "chain_name": "Base mainnet"}),
    "real_svm": ("svm_exact", "verdict", "chain_tx.meta, slot and blockTime are the endpoint's execution record (declared, 33.5): accepted "
                 "only if their sha256 is the recorded one, so the bytes are ours when they are", {}),
    "real_svm_mandate": ("svm_exact", "verdict", "as real_svm; the mandate is our own ap2-evidence-pack fixture, carried in the list", {}),
    "xrp_real_20261026": ("xrpl_exact", "content", None, {}),
    "xlm_real_20261026": ("xlm_exact", "local_only", "the `facilitator` member is a reply of a third-party service (x402.org /supported), "
                          "not redistributed and not a chain fact; Stellar testnet keeps a bounded history and is reset", {}),
}
RECONSTRUCTED = {
    "evm_eip3009": "the x402 envelope (accepted: payTo = to, amount = value, maxTimeoutSeconds 60, the token's EIP-712 name and "
                   "version) and the settlement reply; the chain data is as the RPC returned it",
    "evm_authcap": "the payment payload from the escrow's authorize call (PaymentInfo, collectorData) and the settlement reply",
    "evm_permit2": "the x402 envelope from the proxy calldata (permit, witness, signature) and the settlement reply",
    "svm_exact": "the client's payload: the confirmed transaction with the fee payer's signature zeroed; accepted from the first "
                 "top-level TransferChecked; the settlement reply",
    "xrpl_exact": "the requirements as a server asking for exactly this Payment would have written them; the settlement reply",
    "xlm_exact": "the x402 envelope and the client's payload transaction around the real operation",
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def load(p):
    with (gzip.open(p, "rt") if p.endswith(".gz") else open(p)) as fh:
        d = json.load(fh)
    return d["result"] if isinstance(d, dict) and "jsonrpc" in d else d


def detect_serialization(doc, data):
    # sorted keys first: when both reproduce the bytes, the order-independent form is the one to declare
    for ser in ({"indent": 1, "sort_keys": True, "newline": False}, {"indent": 1, "sort_keys": False, "newline": False},
                {"indent": 1, "sort_keys": True, "newline": True}, {"indent": 1, "sort_keys": False, "newline": True}):
        if rc.serialize(doc, ser) == data:
            return ser
    return None


def local_receipt(tx, block_hash):
    """The receipt of tx from a local raw reply, verified against the block's receiptsRoot when the full set is there."""
    n = int(tx["blockNumber"], 16)
    h = tx["hash"].lower()
    for pat in ("blocks_v03/%d_receipts.json.gz", "msca_20261101/%d_receipts.json.gz", "permit2_7702_20261026/%d_receipts.json.gz",
                "negatives_20261026/eth_getBlockReceipts_%d.json.gz", "reverted_53020172/eth_getBlockReceipts_%d.json"):
        p = os.path.join(O, pat % n)
        if os.path.exists(p):
            rcs = load(p)
            if rcs and (rcs[0].get("blockHash") or "").lower() == block_hash:
                mine = [r for r in rcs if r["transactionHash"].lower() == h]
                if len(mine) == 1:
                    hdrp = p.replace("_receipts", "_block").replace("eth_getBlockReceipts", "eth_getBlockByNumber")
                    ok = False
                    if os.path.exists(hdrp):
                        try:        # Avalanche: the root does not recompute with our encoder (the reason apc-0.3 was not built)
                            ok = ab.receipts_root(rcs) == load(hdrp)["receiptsRoot"].lower()
                        except ab.BlockRefusal:
                            ok = False
                    return mine[0], ok
    p = os.path.join(O, "permit2_base_20261026", "proxy_txs.json.gz")
    if os.path.exists(p):
        items = load(p)["items"]
        if tx["hash"] in items:
            return items[tx["hash"]]["receipt"]["result"], False
    if h == "0x8e01aace01ced4155b30d636b547727becdbb8a700f9b7f54ed02c4d629ae696":
        return load(os.path.join(O, "issue1062", "eth_getTransactionReceipt.json")), False
    return None, False


CACHES, RPC = [], None


def cached(network, method, params):
    key = hashlib.sha256(rc.canon([network, method, params]).encode()).hexdigest()
    for d in CACHES:
        p = os.path.join(d, key + ".json.gz")
        if os.path.exists(p):
            with gzip.open(p) as fh:
                return json.loads(fh.read())
    return None


def remote_receipt(network, tx, block_hash, header_root=None):
    """From the caches (block receipts first, root-checked when encodable), else eth_getTransactionReceipt by --rpc."""
    n, h = int(tx["blockNumber"], 16), tx["hash"].lower()
    rcs = cached(network, "eth_getBlockReceipts", [hex(n)])
    if isinstance(rcs, list):
        mine = [r for r in rcs if (r.get("transactionHash") or "").lower() == h and (r.get("blockHash") or "").lower() == block_hash]
        if len(mine) == 1:
            ok = False
            hdr = cached(network, "eth_getBlockByNumber", [hex(n), False])
            if hdr:
                try:
                    ok = ab.receipts_root(rcs) == hdr["receiptsRoot"].lower()
                except ab.BlockRefusal:
                    ok = False
            return mine[0], ok
    r = cached(network, "eth_getTransactionReceipt", [tx["hash"]])
    if r is None and RPC is not None:
        try:
            r = RPC.call(network, "eth_getTransactionReceipt", [tx["hash"]])
        except rc.Rejected as e:
            print("receipt not fetched:", network, h[:12], e, file=sys.stderr)
            return None, False
    if isinstance(r, dict) and (r.get("transactionHash") or "").lower() == h and (r.get("blockHash") or "").lower() == block_hash:
        return r, False
    return None, False


def evm_chain(doc, receipt=None):
    tx = doc["chain_tx"]["tx"]
    c = {"block_number": int(tx["blockNumber"], 16), "block_hash": tx["blockHash"].lower(), "tx_hash": tx["hash"].lower(),
         "tx_index": int(tx["transactionIndex"], 16), "receipt_hash": None, "receipt_root_verified": False}
    r, root = (receipt, False) if receipt is not None else local_receipt(tx, c["block_hash"])
    if r is None:
        r, root = remote_receipt(doc["chain_tx"]["network"], tx, c["block_hash"])
    if r is not None:
        assert r["transactionHash"].lower() == c["tx_hash"] and r["blockHash"].lower() == c["block_hash"]
        c["receipt_hash"] = rc.receipt_hash_of(r)
        c["receipt_root_verified"] = bool(root)
    return c


def extraction_of(doc, token, name, version, chain_id):
    """Which search of tools/make_bundles_v02.py found the authorization: calldata, log_guided or log_guided_wallet."""
    tx, lg = doc["chain_tx"]["tx"], doc["chain_tx"]["log_authorization_used"]
    if "payer_wallet" in doc:
        return "log_guided_wallet"
    dom = {"name": name, "version": version, "chainId": chain_id, "verifyingContract": token}
    b = bytes.fromhex(tx["input"][2:])
    direct = (tx["to"] or "").lower() == token
    for pos in ([0] if direct else [i for i in range(len(b) - 3) if b[i:i + 4] in v02.SEL]):
        d = v02.decode_at(b, pos)
        if d and d[1]["from"] == "0x" + lg["topics"][1][-40:] and d[1]["nonce"] == lg["topics"][2].lower() and v02.recovers(dom, d[1], d[2]):
            return "calldata"
    return "log_guided"


def entry_evm(name, rel, doc, params, tokens):
    ct = doc["chain_tx"]
    tx = ct["tx"]
    net = ct["network"]
    c = evm_chain(doc)
    ours = {}
    if "log_authorization_used" in ct:
        c["log_index"] = int(ct["log_authorization_used"]["logIndex"], 16)
    else:
        c["log_index"] = None
        ours["form"] = "reverted"
    c["state"] = None
    if "inclusion" in doc:
        ours["inclusion"] = True
    token = (tx["to"] or "").lower() if name == "real_world_20261026" or "negatives" in name else params["token"]
    if name == "real_world_20261026" or "negatives" in name:
        token = doc["payment_payload"]["accepted"]["asset"].lower()
        tokens.setdefault(token, [doc["payment_payload"]["accepted"]["extra"]["name"], doc["payment_payload"]["accepted"]["extra"]["version"]])
        tname, tver = tokens[token]
    else:
        tname, tver = params["token_name"], params["token_version"]
    if doc["bundle_version"] in ("apc-0.2", "apc-0.3") and "log_authorization_used" in ct:
        # a payer with code (payer_state, SPEC 32): the direct call is decoded without ecrecover (make_bundles_msca.payload)
        ours["extraction"] = "calldata" if "payer_state" in doc else extraction_of(doc, token, tname, tver, int(net[7:]))
    if name == "real_issue1062":
        ours["settlement"] = doc["settlement"]
    if "payer_wallet" in doc:
        pw = doc["payer_wallet"]
        code = pw["code"]["result"]
        c["state"] = {"code_keccak": keccak256(bytes.fromhex(code[2:])).hex(),
                      "implementation": "0x" + pw["implementation"]["result"][-40:]}
        ours["state_sha256"] = {"owner": rc._hash_result(pw["owner"]["result"])}
    if "payer_state" in doc:
        ps = doc["payer_state"]
        form = "rpc" if "rpc" in ps else "proof"
        ours["payer_state"] = form
        code = ps[form]["code"]["result"] if form == "rpc" else ps[form]["code"]
        if form == "rpc":
            impl = "0x" + ps["rpc"]["wallet"]["implementation"]["result"][-40:]
            owner = "0x%040x" % (int(ps["rpc"]["wallet"]["owner"]["result"], 16) >> 16)
        else:
            # the proof form (and its anchored twin, 33.10) carries proofs, not values: read them from the rpc twin
            twin = json.load(open(os.path.join(B, name, os.path.basename(rel).replace("_proof_", "_rpc_").replace("_anchored_", "_rpc_"))))["payer_state"]["rpc"]
            impl = "0x" + twin["wallet"]["implementation"]["result"][-40:]
            owner = "0x%040x" % (int(twin["wallet"]["owner"]["result"], 16) >> 16)
        c["state"] = {"code_keccak": keccak256(bytes.fromhex(code[2:])).hex(), "implementation": impl,
                      "owner_keccak": rc._addr_keccak(owner)}          # no address of a person in clear (33.2)
    if "l1_state" in doc.get("canonical", {}) and SETS[name][1] != "local_only":     # the anchored bundles (SPEC 33.10)
        can = doc["canonical"]
        hs = can["l1_state"]["headers"]
        assert len(hs) == 1, (rel, "the anchor member describes one L1 header: the replies' block is the checkpoint")
        assert hs[0]["hash"].lower() == regress.DIRS["bundles/" + name][2][1].lower(), (rel, "checkpoint is not regress.py's")
        c["anchor"] = {"l1_network": can["l1_network"], "l1_block_number": int(hs[0]["number"], 16),
                       "l1_block_hash": hs[0]["hash"].lower(), "game": can["game"].lower(), "root_index": can["root_index"]}
    return net, c, ours


def entry_permit2(rel, doc):
    c = evm_chain(doc)
    ours = {}
    c["state"] = None
    if "payer_code" in doc:
        pc = doc["payer_code"]
        form = "rpc" if "rpc" in pc else "proof"
        ours["payer_code"] = form
        twin_rpc = pc["rpc"] if form == "rpc" else json.load(open(os.path.join(B, "real_permit2", os.path.basename(rel).replace("_proof", "_rpc"))))["payer_code"]["rpc"]
        code = twin_rpc["code"]["result"]
        st = {"code_keccak": keccak256(bytes.fromhex(code[2:])).hex(), "slots": [twin_rpc["storage"]["params"][1]]}
        if code.startswith("0xef0100"):
            st["delegate"] = "0x" + code[8:48]
        c["state"] = st
        if form == "rpc":
            ours["state_sha256"] = {"storage": rc._hash_result(twin_rpc["storage"]["result"])}
    return doc["chain_tx"]["network"], c, ours


def entry_svm(doc):
    m = rc._tool_module("make_bundles_svm")
    ct = doc["chain_tx"]
    acc = doc["payment_payload"]["accepted"]
    c = {"signature": doc["settlement"]["transaction"], "slot": ct["slot"], "chain_tx_sha256": rc._hash_result(ct)}
    r = {"transaction": [ct["transaction"], "base64"], "meta": ct["meta"], "slot": ct["slot"], "blockTime": ct["blockTime"]}
    ours = {}
    memo = acc["extra"].get("memo")
    if memo is not None:
        ours["memo"] = memo
    # the fee payer is derived from the message (account 0), as the rebuild does: the list carries no address (33.2)
    b, why = m.bundle(json.loads(json.dumps(r)), acc["extra"]["feePayer"], memo)
    assert b is not None, why
    assert b["payment_payload"]["accepted"] == acc, "accepted not derived from the chain alone"
    if "mandate" in doc:
        ours["mandate"] = doc["mandate"]
    return doc["settlement"]["network"], c, ours


def xrpl_ledger_hashes():
    """ledger_index -> ledger hash, from every binary ledger reply saved in oracle/ (recomputed from ledger_data)."""
    out = {}
    paths = glob.glob(os.path.join(O, "xrpl_20261026", "*.json")) + glob.glob(os.path.join(O, "negatives_20261026", "xrpl_ledgers_*.json.gz"))
    for p in paths:
        d = load(p)
        for call in d["calls"]:
            if call["params"].get("binary") and "ledger" in call["result"]:
                hdr = xr.ledger_header(bytes.fromhex(call["result"]["ledger"]["ledger_data"]))
                out[hdr["ledger_index"]] = hdr["hash"]
    return out


ORACLE_LOCAL = {
    "coverage_20261022": ("the authors' coverage census of 2026-10-22 (manifests, payer_wallet_replies: state reads at historical blocks over "
                          "7 windows of 50-100 Base blocks); rebuildable in principle with the anchors of 33.4, not provided by this version", ["test_coverage_census", "test_msca"]),
    "coverage_20261026": ("the authors' coverage census of 2026-10-26 (payer wallets, routes); as coverage_20261022", ["test_coverage_census", "test_msca"]),
    "census_base_*.json": ("the raw census replies (eth_getLogs over 50-100 Base blocks per window, eth_getTransactionByHash) of 7 windows; "
                           "rebuildable in principle, not provided by this version", ["test_coverage_census", "test_msca"]),
    "transfers_base_*.json": ("the Transfer logs of the census windows (eth_getLogs by block hash); as census_base_*.json", ["test_coverage_census", "test_msca"]),
    "msca_20261101": ("campaign and coverage files derived from the census and the MSCA state replies; the 56 bundles are rebuilt, "
                      "these derived files are not", ["test_msca"]),
    "negatives_20261026": ("the authors' scans for reverted calls (eth_getBlockReceipts over 1500-4000 blocks per chain, Solana signature "
                           "scans, 120 XRPL ledgers), their logs, SHA256SUMS and NEGATIVES.json; the 529 bundles are rebuilt, the scans are not", ["test_negatives"]),
    "permit2_base_20261026": ("the 231 x402ExactPermit2Proxy settlements found in 800,000 Base blocks with their receipts (proxy_txs.json.gz) and "
                              "the payer_code replies; the 6 bundles are rebuilt, the scan is not", ["test_permit2", "test_permit2_state"]),
    "permit2_7702_20261026": ("raw block, receipts and eth_getProof replies behind the p029 state bundles (archive endpoint); the bundles are "
                              "rebuilt, the raw files are not", ["test_permit2_state"]),
    "passkey_20261026": ("the census of Base block 53093490 and 10 ERC-4337 operations with WebAuthn signatures (raw replies read as "
                         "WebAuthn-layer oracles); not rebuilt by this version", ["test_webauthn"]),
    "world_20261026": ("per-chain census replies of 2026-10-26 and the authors' high-s probe texts (probe_*.txt); the 90 bundles are rebuilt, "
                       "the census and the probes are not", ["test_world"]),
}


def oracle_section(xrpl_hashes):
    out = {}
    items, shas = [], {}
    for p in sorted(glob.glob(os.path.join(O, "blocks_v03", "*_block.json.gz"))):
        n = int(os.path.basename(p).split("_")[0])
        blk = load(p)
        rcs = load(p.replace("_block.json.gz", "_receipts.json.gz"))
        assert ab.header_hash({k: blk[k] for k in rc.HEADER_KEYS if k in blk}) == blk["hash"].lower() and ab.receipts_root(rcs) == blk["receiptsRoot"].lower(), p
        items.append({"number": n, "hash": blk["hash"].lower()})
        shas["%d_block.json.gz" % n] = sha(rc.canon(blk).encode())
        shas["%d_receipts.json.gz" % n] = sha(rc.canon(rcs).encode())
    out["blocks_v03"] = {"kind": "evm_blocks", "network": "eip155:8453", "items": items, "files": ["<n>_block.json.gz", "<n>_receipts.json.gz"],
                         "result_sha256": shas, "read_by": ["test_apc03"]}
    d = json.load(open(os.path.join(O, "xrpl_20261026", "mainnet_ledgers.json")))
    items, shas = [], {}
    js = {c["params"]["ledger_index"]: c["result"] for c in d["calls"]
          if "binary" not in c["params"] and isinstance(c["params"]["ledger_index"], int)}
    for c in d["calls"]:
        if c["params"].get("binary") and "ledger" in c["result"]:
            hdr = xr.ledger_header(bytes.fromhex(c["result"]["ledger"]["ledger_data"]))
            items.append({"ledger_index": hdr["ledger_index"], "ledger_hash": hdr["hash"]})
            # both replies whole (33.8): the binary one and the JSON one the tests read the ledger hash from
            shas[str(hdr["ledger_index"])] = sha(rc.canon({"binary": c["result"], "json": js[hdr["ledger_index"]]}).encode())
    out["xrpl_20261026"] = {"kind": "xrpl_ledgers", "network": "xrpl:0", "items": items, "file": "mainnet_ledgers.json",
                            "result_sha256": shas, "read_by": ["test_xrp", "test_evidence_level"]}
    for n, (reason, read_by) in ORACLE_LOCAL.items():
        out[n] = {"kind": "local_only", "reason": reason, "read_by": read_by}
    return out


def main(argv):
    global RPC
    args = list(argv[1:])
    urls = {}
    while "--cache" in args:
        i = args.index("--cache")
        CACHES.extend(args[i + 1].split(","))
        del args[i:i + 2]
    while "--rpc" in args:
        i = args.index("--rpc")
        k, v = args[i + 1].split("=", 1)
        urls[k] = v
        del args[i:i + 2]
    if urls:
        RPC = rc.Rpc(urls, rate=1.0, cache=CACHES[0] if CACHES else None)
    out = args[0] if args else rc.MANIFEST
    frozen = regress.load_frozen()
    ledgers = xrpl_ledger_hashes()
    sets, bundles = {}, []
    for name, (recipe, level, reason, params) in SETS.items():
        d = os.path.join(B, name)
        paths = sorted(p for p in glob.glob(os.path.join(d, "**", "*.json"), recursive=True)
                       if os.path.basename(p) not in ("MANIFEST.json", "ANCHORED.json"))     # the manifests of a directory, as regress.corpus()
        params = dict(params)
        tokens = {}
        sers, versions = set(), set()
        for p in paths:
            rel = os.path.relpath(p, B)
            data = open(p, "rb").read()
            doc = json.loads(data)
            fr = frozen["bundles/" + rel]
            assert fr["sha256"] == sha(data), rel
            ser = detect_serialization(doc, data)
            assert ser is not None, rel
            sers.add(json.dumps(ser, sort_keys=True))
            versions.add(doc["bundle_version"])
            rcp = recipe
            if name == "real_negatives_20261026":
                rcp = {"evm": "evm_eip3009", "svm": "svm_exact", "xrp": "xrpl_exact"}[os.path.basename(rel)[:3]]
            if rcp == "evm_eip3009":
                net, c, ours = entry_evm(name, rel, doc, params, tokens)
            elif rcp == "evm_permit2":
                net, c, ours = entry_permit2(rel, doc)
            elif rcp == "evm_authcap":
                net, c, ours = doc["settlement"]["network"], evm_chain(doc, doc["chain_tx"]["receipt"]), {}
            elif rcp == "svm_exact":
                net, c, ours = entry_svm(doc)
            elif rcp == "xrpl_exact":
                li = doc["chain_tx"]["ledger_index"]
                net, c, ours = "xrpl:0", {"ledger_index": li, "ledger_hash": ledgers[li], "tx_hash": doc["settlement"]["transaction"]}, {}
                if "inclusion" in doc:
                    assert xr.ledger_header(bytes.fromhex(doc["inclusion"]["ledger_data"]))["hash"] == ledgers[li]
                    ours["inclusion"] = True
            else:   # xlm
                net, c, ours = doc["settlement"]["network"], {"ledger": doc["chain_tx"]["ledger"], "tx_hash": doc["settlement"]["transaction"]}, {}
            e = {"file": rel, "set": name, "network": net, "bundle_version": doc["bundle_version"], "chain": c}
            if rcp != recipe:
                e["recipe"] = rcp
            if ours:
                e["ours"] = ours
            e.update({"sha256": fr["sha256"], "content_sha256": rc.content_digest(doc), "verdict": fr["verdict"],
                      "checks_sha256": sha(rc.canon(fr["checks"]).encode())})
            bundles.append(e)
        if name == "real_negatives_20261026":
            params["recipes_by_prefix"] = {"evm": "evm_eip3009", "svm": "svm_exact", "xrp": "xrpl_exact"}
        if tokens:
            params["tokens"] = tokens
        opts = regress.DIRS["bundles/" + name][2]           # the options the verdicts were frozen with (--l1-checkpoint)
        if opts:
            assert opts[0] == "--l1-checkpoint" and len(opts) == 2, (name, opts)
            params["options"] = {"l1_checkpoint": opts[1]}
        assert len(sers) == 1, (name, sers)
        s = {"dir": "bundles/" + name, "recipe": recipe, "bundle_versions": sorted(versions), "real": regress.DIRS["bundles/" + name][0],
             "reconstructed": RECONSTRUCTED[recipe], "rebuild": level, "serialization": json.loads(sers.pop()), "params": params,
             "count": sum(1 for e in bundles if e["set"] == name)}
        if reason:
            s["reason"] = reason
        sets[name] = s
    doc = {"format": rc.FORMAT, "written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "verifier": regress.spec_version(),
           "oracle": oracle_section(ledgers), "sets": sets, "bundles": bundles}
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        fh.write(text)
    rc.load_manifest(out)        # the list must read back closed
    print("sets %d, bundles %d, sha256 %s" % (len(sets), len(bundles), sha(text.encode())))


if __name__ == "__main__":
    main(sys.argv)
