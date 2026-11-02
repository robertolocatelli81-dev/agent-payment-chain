"""Rebuild the real corpus (bundles/) from any JSON-RPC endpoint, by the list corpus/MANIFEST.json (SPEC section 33).

  python3 tools/rebuild_corpus.py --rpc eip155:8453=https://HOST [--rpc CAIP2=URL ...] [--out DIR] [--only SET[,SET]]
                                  [--sample N] [--rate R] [--cache DIR] [--report FILE] [--force]
  python3 tools/rebuild_corpus.py --check-manifest                     offline: read the list, refuse what is not closed

The list names each real payment (chain, transaction, block or ledger) with the fingerprints consensus gives it; this
tool asks the endpoint YOU name for the data, accepts a reply ONLY when those fingerprints recompute from the bytes
received (a block header that hashes to the pinned hash, a transaction whose RLP hashes to its id, a receipt inside
that header's receiptsRoot, a ledger whose SHAMap root is the header's, a Solana message signed by its fee payer),
and only then rebuilds the bundle as our tools built it. A reply that does not recompute is refused with the reason.
For the anchored bundles (SPEC 33.10) the `canonical` member is fetched from the L1 endpoint too and accepted only when
apc_verify recomputes it under the pinned L1 header hash (L1, O1-O3 verified).
Where a fingerprint cannot be recomputed (a header layout our encoder does not know, on the networks the list names;
a receipt set that does not recompute; the Solana execution record; the declared state replies) the list's own digest
is the anchor and the report says so: the reader then gets OUR bytes, not consensus (SPEC 33.5). A bundle below its
set's level is not written. No content of a third-party service is redistributed: every bundle is made from
chain facts fetched by whoever runs this.

Levels, per set, as the list declares them (33.3): `bytes` (the rebuilt file is byte-identical to ours; the sha256 says
so), `content` (identical but for `provenance`, which names the endpoint and time of THIS fetch), `verdict` (same
verdict and checks under apc_verify; the bytes may differ where state replies are declared data), `local_only` (not
rebuilt: the reason is in the list). Standard library only.

Endpoints: none is written in this tool. Each network's URL comes from `--rpc CAIP2=URL` or from the environment
variable APC_RPC_<CAIP2 with ':' and '-' as '_'> (APC_RPC_eip155_8453, APC_RPC_solana_5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp,
APC_RPC_xrpl_0). WHOEVER RUNS THIS IS RESPONSIBLE FOR THE TERMS OF SERVICE OF THE ENDPOINT CHOSEN: a node of your own
is the recommended one; public endpoints have their own limits and terms. The tool paces itself (default 1 request per
second per host, exponential backoff on 429/5xx/403, User-Agent naming the tool), logs hosts only (never a URL, which may
carry a key), and writes the host alone into `provenance`.
"""
import argparse
import base64
import copy
import gzip
import hashlib
import importlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "sources", "l1proof_20261024"))     # fetch_l1proof (SPEC 33.10)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/rebuild_corpus", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import apc_block as ab  # noqa: E402
import apc_l1proof  # noqa: E402
import apc_verify as av  # noqa: E402
from apc_verify import keccak256  # noqa: E402

FORMAT = "apc-corpus-0.3"           # 0.3: the `anchor` member of an evm_eip3009 entry (SPEC 33.10)
MANIFEST = os.path.join(ROOT, "corpus", "MANIFEST.json")
LEVELS = ("bytes", "content", "verdict", "local_only")
RECIPES = ("evm_eip3009", "evm_authcap", "evm_permit2", "svm_exact", "xrpl_exact", "xlm_exact")
TOPIC_AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
HEADER_KEYS = ab.HEADER_BASE + ab.HEADER_OPT + ("hash",)

# ------------------------------------------------------------------ the closed list


class ManifestRefusal(Exception):
    pass


class Rejected(Exception):
    """A reply, or a bundle, refused: the reason names the fingerprint that did not recompute."""


# a reply outside the shape a recipe reads (33.4, 33.8, 33.11): the recipe's row says so, the run goes on. One list for
# the bundle recipes and the two oracle recipes; RecursionError is a document nested beyond the interpreter's limit that
# passed the parse and a recipe wrapped deeper, ArithmeticError a reply word longer than 32 bytes, AttributeError a
# member of another JSON type where a recipe reads an object or a string (2026-11-02)
SHAPE_ERRORS = (KeyError, TypeError, ValueError, IndexError, AttributeError, ArithmeticError, RecursionError)


def loads(raw, where):
    """json.loads bounded (33.11): a document nested beyond the interpreter's recursion limit is refused with where it
    came from (`rpc:<host>:<method>`, `cache:<method>`), never a traceback. ValueError (not JSON) is the caller's."""
    try:
        return json.loads(raw)
    except RecursionError:
        raise Rejected("json_too_nested:%s" % where)


def _err_text(x, absent):
    """The endpoint's error, as the row prints it: its text, or the JSON type it came as (an error member that is not an
    object nor a string, or a message that is not a string, 33.11)."""
    if x is None or x == "":
        return absent
    return x if isinstance(x, str) else "error_not_text:%s" % type(x).__name__


_HEX32 = re.compile(r"^0x[0-9a-f]{64}\Z")
_HEX20 = re.compile(r"^0x[0-9a-f]{40}\Z")
_SHA = re.compile(r"^[0-9a-f]{64}\Z")
_HEXU = re.compile(r"^[0-9A-F]{64}\Z")
_B58 = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,88}\Z")
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")          # a set name, or one segment of a bundle path
# the networks whose header layout our encoder does not know (measured 2026-10-26/11-01): only there may a header be
# accepted on the hash it states (33.4); anywhere else a header that does not recompute is refused
HEADER_DECLARED_NETWORKS = ("eip155:43114",)
_EVM_NET = re.compile(r"^eip155:[0-9]+\Z")
PARAMS_KEYS = {"token": str, "token_name": str, "token_version": str, "tokens": dict, "escrow": str, "chain_name": str,
               "recipes_by_prefix": dict, "options": dict}

ORACLE_KINDS = ("evm_blocks", "xrpl_ledgers", "local_only")
ORACLE_EVM_FILES = ("<n>_block.json.gz", "<n>_receipts.json.gz")
ORACLE_KEYS = {"kind": str, "network": str, "items": list, "files": list, "file": str, "result_sha256": dict, "reason": str,
               "read_by": list}
_ORACLE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.*-]*\Z")       # a directory of oracle/, or a glob of its files
SET_KEYS = {"dir": str, "recipe": str, "bundle_versions": list, "real": str, "reconstructed": str, "rebuild": str,
            "reason": str, "serialization": dict, "params": dict, "count": int}
SET_REQUIRED = ("dir", "recipe", "bundle_versions", "real", "reconstructed", "rebuild", "serialization", "params", "count")
SER_KEYS = {"indent": int, "sort_keys": bool, "newline": bool}
ENTRY_KEYS = {"file": str, "set": str, "network": str, "bundle_version": str, "recipe": str, "chain": dict, "ours": dict,
              "sha256": str, "content_sha256": str, "verdict": str, "checks_sha256": str}
ENTRY_REQUIRED = ("file", "set", "network", "bundle_version", "chain", "sha256", "content_sha256", "verdict", "checks_sha256")
CHAIN_KEYS = {
    "evm_eip3009": {"block_number": int, "block_hash": str, "tx_hash": str, "tx_index": int, "receipt_hash": (str, type(None)),
                    "receipt_root_verified": bool, "log_index": (int, type(None)), "state": (dict, type(None)), "anchor": dict},
    "evm_authcap": {"block_number": int, "block_hash": str, "tx_hash": str, "tx_index": int, "receipt_hash": (str, type(None)),
                    "receipt_root_verified": bool},
    "evm_permit2": {"block_number": int, "block_hash": str, "tx_hash": str, "tx_index": int, "receipt_hash": (str, type(None)),
                    "receipt_root_verified": bool, "state": (dict, type(None))},
    "svm_exact": {"signature": str, "slot": int, "chain_tx_sha256": str},
    "xrpl_exact": {"ledger_index": int, "ledger_hash": str, "tx_hash": str},
    "xlm_exact": {"ledger": int, "tx_hash": str},
}
OURS_KEYS = {"form": str, "extraction": str, "inclusion": bool, "settlement": dict, "payer_wallet": dict,
             "payer_state": str, "payer_code": str, "memo": str, "mandate": dict, "state_sha256": dict}
# no address of a person in clear (33.2): the payer is derived from the log or the calldata, the owner pinned by keccak
STATE_KEYS = {"code_keccak": str, "implementation": str, "owner_keccak": str, "slots": list, "delegate": str}
# 33.10: the anchored bundles (32.10). Optional, only in an evm_eip3009 entry of Base mainnet with inclusion; the game is a
# contract (the clone the factory deployed), the L1 header hash is the checkpoint the reader passes to the verifier
ANCHOR_KEYS = {"l1_network": str, "l1_block_number": int, "l1_block_hash": str, "game": str, "root_index": int}
ANCHOR_L1, ANCHOR_L2 = "eip155:1", "eip155:8453"
MAX_CANONICAL_HEADERS = 64                   # SPEC section 6: canonical.headers holds at most 64 headers


def _typed(obj, keys, required, where):
    if not isinstance(obj, dict):
        raise ManifestRefusal("%s: not an object" % where)
    for k in obj:
        if k not in keys:
            raise ManifestRefusal("%s.%s: unknown member" % (where, k))
        if not isinstance(obj[k], keys[k]) or (isinstance(obj[k], bool) and bool not in
                                                (keys[k] if isinstance(keys[k], tuple) else (keys[k],))):
            raise ManifestRefusal("%s.%s: wrong type" % (where, k))
    for k in required:
        if k not in obj:
            raise ManifestRefusal("%s.%s: missing" % (where, k))


def load_manifest(path=MANIFEST):
    """The list, read closed: any member outside this grammar is refused with its path."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        doc = av.strict_json(raw.decode("utf-8"))
    except (ValueError, av.Refusal) as e:
        raise ManifestRefusal("not strict JSON: %s" % e)
    _typed(doc, {"format": str, "written": str, "verifier": str, "oracle": dict, "sets": dict, "bundles": list},
           ("format", "written", "verifier", "oracle", "sets", "bundles"), "manifest")
    if doc["format"] != FORMAT:
        raise ManifestRefusal("manifest.format: %r is not %r" % (doc["format"], FORMAT))
    for name, o in doc["oracle"].items():
        w = "oracle.%s" % name
        if not _ORACLE_NAME.match(name) or name in (".", ".."):
            raise ManifestRefusal("%s: not an oracle name" % w)
        _typed(o, ORACLE_KEYS, ("kind", "read_by"), w)
        if o["kind"] not in ORACLE_KINDS:
            raise ManifestRefusal("%s.kind: unknown %r" % (w, o["kind"]))
        if not o["read_by"] or not all(isinstance(x, str) and _NAME.match(x) for x in o["read_by"]):
            raise ManifestRefusal("%s.read_by: not a list of test module names" % w)
        if o["kind"] == "local_only":
            if not o.get("reason") or set(o) != {"kind", "reason", "read_by"}:
                raise ManifestRefusal("%s: local_only holds kind, reason and read_by, and only those" % w)
            continue
        if "*" in name or not _NAME.match(name):                     # a rebuilt directory is written: a plain name
            raise ManifestRefusal("%s: a rebuildable oracle names one directory" % w)
        for k in ("network", "items", "result_sha256"):
            if k not in o:
                raise ManifestRefusal("%s.%s: missing" % (w, k))
        if not o["items"]:
            raise ManifestRefusal("%s.items: empty" % w)
        if not all(isinstance(v, str) and _SHA.match(v) for v in o["result_sha256"].values()):
            raise ManifestRefusal("%s.result_sha256: not 64 lowercase hex" % w)
        for i, it in enumerate(o["items"]):
            if o["kind"] == "evm_blocks":
                _typed(it, {"number": int, "hash": str}, ("number", "hash"), "%s.items[%d]" % (w, i))
                if not _HEX32.match(it["hash"]) or isinstance(it["number"], bool) or it["number"] < 0:
                    raise ManifestRefusal("%s.items[%d]: malformed" % (w, i))
            else:
                _typed(it, {"ledger_index": int, "ledger_hash": str}, ("ledger_index", "ledger_hash"), "%s.items[%d]" % (w, i))
                if not _HEXU.match(it["ledger_hash"]) or isinstance(it["ledger_index"], bool) or it["ledger_index"] < 0:
                    raise ManifestRefusal("%s.items[%d]: malformed" % (w, i))
        if o["kind"] == "evm_blocks":
            if o.get("files") != list(ORACLE_EVM_FILES) or "file" in o or not _EVM_NET.match(o["network"]):
                raise ManifestRefusal("%s: evm_blocks wants files %s, no file, and an eip155 network" % (w, list(ORACLE_EVM_FILES)))
            want = {"%d%s" % (it["number"], f[3:]) for it in o["items"] for f in ORACLE_EVM_FILES}
            n_items = len({it["number"] for it in o["items"]})
        else:
            if not isinstance(o.get("file"), str) or not _NAME.match(o["file"]) or o["file"] in (".", "..") \
                    or "files" in o or not o["network"].startswith("xrpl:"):
                raise ManifestRefusal("%s: xrpl_ledgers wants one file name under its directory, and an xrpl network" % w)
            want = {str(it["ledger_index"]) for it in o["items"]}
            n_items = len(want)
        if n_items != len(o["items"]) or set(o["result_sha256"]) != want:
            raise ManifestRefusal("%s: items repeated, or result_sha256 not exactly one digest per file" % w)
    for name, s in doc["sets"].items():
        w = "sets.%s" % name
        if not _NAME.match(name) or name in (".", ".."):
            raise ManifestRefusal("%s: not a set name ([A-Za-z0-9_][A-Za-z0-9_.-]*)" % w)
        _typed(s, SET_KEYS, SET_REQUIRED, w)
        _typed(s["params"], PARAMS_KEYS, (), w + ".params")
        if "options" in s["params"]:
            _typed(s["params"]["options"], {"l1_checkpoint": str}, (), w + ".params.options")
        if s["recipe"] not in RECIPES:
            raise ManifestRefusal("%s.recipe: unknown %r" % (w, s["recipe"]))
        if s["rebuild"] not in LEVELS:
            raise ManifestRefusal("%s.rebuild: unknown level %r" % (w, s["rebuild"]))
        if s["rebuild"] == "local_only" and not s.get("reason"):
            raise ManifestRefusal("%s: local_only without a reason" % w)
        if s["dir"] != "bundles/" + name:
            raise ManifestRefusal("%s.dir: %r is not bundles/%s" % (w, s["dir"], name))
        _typed(s["serialization"], SER_KEYS, tuple(SER_KEYS), w + ".serialization")
        if not all(isinstance(v, str) for v in s["bundle_versions"]):
            raise ManifestRefusal("%s.bundle_versions: not strings" % w)
    seen = set()
    for i, e in enumerate(doc["bundles"]):
        w = "bundles[%d]" % i
        _typed(e, ENTRY_KEYS, ENTRY_REQUIRED, w)
        if e["set"] not in doc["sets"]:
            raise ManifestRefusal("%s.set: %r is not a listed set" % (w, e["set"]))
        s = doc["sets"][e["set"]]
        segs = e["file"].split("/")
        if segs[0] != e["set"] or len(segs) < 2 or not e["file"].endswith(".json") \
                or not all(_NAME.match(x) and x not in (".", "..") for x in segs[1:]):
            raise ManifestRefusal("%s.file: %r is outside bundles/%s" % (w, e["file"], e["set"]))
        if e["file"] in seen:
            raise ManifestRefusal("%s.file: duplicate %r" % (w, e["file"]))
        seen.add(e["file"])
        if e["bundle_version"] not in s["bundle_versions"]:
            raise ManifestRefusal("%s.bundle_version: %r not among the set's" % (w, e["bundle_version"]))
        if not _SHA.match(e["sha256"]) or not _SHA.match(e["content_sha256"]) or not _SHA.match(e["checks_sha256"]):
            raise ManifestRefusal("%s: a digest is not 64 lowercase hex" % w)
        recipe = e.get("recipe", s["recipe"])
        if recipe not in RECIPES:
            raise ManifestRefusal("%s.recipe: unknown %r" % (w, recipe))
        ck = CHAIN_KEYS[recipe]
        _typed(e["chain"], ck, tuple(k for k in ck if k != "anchor"), w + ".chain")
        c = e["chain"]
        if "anchor" in c:                                            # 33.10
            an = c["anchor"]
            _typed(an, ANCHOR_KEYS, tuple(ANCHOR_KEYS), w + ".chain.anchor")
            if an["l1_network"] != ANCHOR_L1 or e["network"] != ANCHOR_L2:
                raise ManifestRefusal("%s.chain.anchor: the canonical rules are for %s under %s" % (w, ANCHOR_L2, ANCHOR_L1))
            if not _HEX32.match(an["l1_block_hash"]) or not _HEX20.match(an["game"]):
                raise ManifestRefusal("%s.chain.anchor: l1_block_hash or game is not 0x + lowercase hex of its length" % w)
            if an["l1_block_number"] < 0 or an["root_index"] < 0:
                raise ManifestRefusal("%s.chain.anchor: negative l1_block_number or root_index" % w)
            if e["bundle_version"] != "apc-0.3" or not e.get("ours", {}).get("inclusion"):
                raise ManifestRefusal("%s.chain.anchor: canonical needs an apc-0.3 entry with inclusion (SPEC 0.3)" % w)
            if an["l1_block_hash"] != doc["sets"].get(e["set"], {}).get("params", {}).get("options", {}).get("l1_checkpoint"):
                raise ManifestRefusal("%s.chain.anchor: l1_block_hash is not the set's params.options.l1_checkpoint (one "
                                      "checkpoint for the rebuild and the frozen verdict)" % w)
        if recipe.startswith("evm_"):
            if not _EVM_NET.match(e["network"]):
                raise ManifestRefusal("%s.network: not eip155:<id>" % w)
            if not _HEX32.match(c["block_hash"]) or not _HEX32.match(c["tx_hash"]):
                raise ManifestRefusal("%s.chain: block_hash or tx_hash is not 0x + 64 lowercase hex" % w)
            if c["receipt_hash"] is not None and not _HEX32.match(c["receipt_hash"]):
                raise ManifestRefusal("%s.chain.receipt_hash: not 0x + 64 lowercase hex" % w)
            if c["block_number"] < 0 or c["tx_index"] < 0:
                raise ManifestRefusal("%s.chain: negative block_number or tx_index" % w)
            if c.get("state") is not None:
                _typed(c["state"], STATE_KEYS, ("code_keccak",), w + ".chain.state")
                for k in ("code_keccak", "owner_keccak"):
                    if k in c["state"] and not _SHA.match(c["state"][k]):
                        raise ManifestRefusal("%s.chain.state.%s: not 64 lowercase hex" % (w, k))
        elif recipe == "svm_exact":
            if not _B58.match(c["signature"]) or not _SHA.match(c["chain_tx_sha256"]):
                raise ManifestRefusal("%s.chain: signature or chain_tx_sha256 malformed" % w)
        elif recipe == "xrpl_exact":
            if not _HEXU.match(c["ledger_hash"]) or not _HEXU.match(c["tx_hash"]):
                raise ManifestRefusal("%s.chain: ledger_hash or tx_hash is not 64 uppercase hex" % w)
        if "ours" in e:
            _typed(e["ours"], OURS_KEYS, (), w + ".ours")
    counts = {}
    for e in doc["bundles"]:
        counts[e["set"]] = counts.get(e["set"], 0) + 1
    for name, s in doc["sets"].items():
        if counts.get(name, 0) != s["count"]:
            raise ManifestRefusal("sets.%s.count: %d listed, %d entries" % (name, s["count"], counts.get(name, 0)))
    return doc


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(doc):
    """sha256 of the bundle without `provenance` (the member that names the fetch itself), canonical JSON."""
    d = {k: v for k, v in doc.items() if k != "provenance"}
    return hashlib.sha256(canon(d).encode()).hexdigest()


def serialize(doc, ser):
    text = json.dumps(doc, indent=ser["indent"], sort_keys=ser["sort_keys"])
    if ser["newline"]:
        text += "\n"
    return text.encode("utf-8")


# ------------------------------------------------------------------ the endpoint


def host_of(url):
    return urllib.parse.urlsplit(url).hostname or "?"


_RATE_LIMITED = re.compile(r"rate limit|too many requests|slow ?down|too ?busy|exceeded", re.I)
_NO_METHOD = re.compile(r"method not found|not supported|unsupported method|does not exist|not available|not implemented|not whitelisted|null result", re.I)
USER_AGENT = "apc-rebuild-corpus/0.1 (agent-payment-chain tools/rebuild_corpus.py)"


def env_name(network):
    return "APC_RPC_" + re.sub(r"[^A-Za-z0-9]", "_", network)


class Rpc:
    """One JSON-RPC client per network, rate-limited per host; raw replies optionally cached (gzip) under --cache."""

    def __init__(self, urls, rate=1.0, cache=None, log=print):
        self.urls, self.rate, self.cache, self.log = urls, rate, cache, log
        self.last = {}
        self.calls = 0

    def url(self, network):
        u = self.urls.get(network) or os.environ.get(env_name(network))
        if u is None:
            raise Rejected("no_rpc_for_network:%s (pass --rpc %s=URL or set %s)" % (network, network, env_name(network)))
        return u

    def _wait(self, host):
        gap = 1.0 / self.rate
        dt = time.monotonic() - self.last.get(host, 0)
        if dt < gap:
            time.sleep(gap - dt)
        self.last[host] = time.monotonic()

    def _post(self, url, body):
        host = host_of(url)
        err = None
        for attempt in range(6):
            self._wait(host)
            try:
                req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": USER_AGENT})
            except ValueError:
                raise Rejected("rpc_url_not_usable:%s" % host)           # the URL itself is never written
            try:
                with urllib.request.urlopen(req, timeout=180) as r:
                    self.calls += 1
                    return r.read()
            except urllib.error.HTTPError as e:
                err = "HTTP %d" % e.code
                try:                       # some endpoints answer a JSON-RPC error under an HTTP error status
                    d = json.loads(e.read())
                    if isinstance(d, dict) and "error" in d:
                        self.calls += 1
                        return json.dumps(d).encode()
                except (ValueError, RecursionError):    # no JSON-RPC error body (not JSON, or nested beyond the limit,
                    pass                                # 33.11): the HTTP status stands
                if e.code not in (403, 429, 500, 502, 503, 504):     # public endpoints throttle with 403 too
                    break
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                err = type(e).__name__
            time.sleep(2.0 * 2 ** attempt)
        raise Rejected("rpc_unreachable:%s:%s" % (host, err))

    def call(self, network, method, params, xrpl=False):
        url = self.url(network)
        key = hashlib.sha256(canon([network, method, params]).encode()).hexdigest()
        if self.cache:
            p = os.path.join(self.cache, key + ".json.gz")
            if os.path.exists(p):
                with gzip.open(p) as fh:
                    return loads(fh.read(), "cache:%s" % method)
        body = json.dumps({"method": method, "params": [params]} if xrpl
                          else {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        for attempt in range(6):
            raw = self._post(url, body)
            try:
                d = loads(raw, "rpc:%s:%s" % (host_of(url), method))
            except ValueError:
                raise Rejected("rpc_not_json:%s:%s" % (host_of(url), method))
            if not isinstance(d, dict):                   # a JSON-RPC reply is an object (33.11)
                raise Rejected("rpc_not_object:%s:%s" % (host_of(url), method))
            msg = ""
            if isinstance(d, dict):
                err = d.get("error")
                if err is None and isinstance(d.get("result"), dict):
                    err = d["result"].get("error") or d["result"].get("error_message")     # XRPL style
                msg = json.dumps(err) if err is not None else ""
            if not _RATE_LIMITED.search(msg) or attempt == 5:
                break
            time.sleep(5.0 * 2 ** attempt)           # an endpoint that says "rate limit" in a JSON-RPC error
        if xrpl:
            res = d.get("result")
            if not isinstance(res, dict) or res.get("status") != "success":
                raise Rejected("rpc_error:%s:%s:%s" % (host_of(url), method, _err_text(res.get("error") if isinstance(res, dict) else None, "no result")))
        else:
            if "error" in d or d.get("result") is None:
                er = d.get("error")
                raise Rejected("rpc_error:%s:%s:%s" % (host_of(url), method, _err_text(er.get("message", "null result") if isinstance(er, dict) else er, "null result")))
            res = d["result"]
        if self.cache:
            os.makedirs(self.cache, exist_ok=True)
            with open(p + ".tmp", "wb") as f0, gzip.GzipFile(filename="", fileobj=f0, mode="wb", mtime=0) as fh:
                fh.write(json.dumps(res).encode())
            os.replace(p + ".tmp", p)
        return res


# ------------------------------------------------------------------ EVM: consensus checks


def check_header(header, block_hash, note=None, network=None):
    """The header the endpoint returned must hash to the pinned block hash (apc_block.header_hash); returned pruned to
    the header members. On a chain whose header layout is not the Ethereum/OP-stack one (extra or missing fields:
    Avalanche, Arbitrum, Celo), the hash cannot be recomputed here: the header is then accepted only if the hash it
    STATES is the pinned one, and the caller records the anchor as declared (`note`), never as recomputed."""
    if not isinstance(header, dict):
        raise Rejected("header_not_object")
    if (header.get("hash") or "").lower() != block_hash.lower():
        raise Rejected("header_hash_mismatch:stated:%s" % header.get("hash"))
    h = {k: header[k] for k in HEADER_KEYS if k in header}
    try:
        got = ab.header_hash({k: v for k, v in h.items() if k != "hash"} | {"hash": h.get("hash")})
    except ab.BlockRefusal as e:
        if note is not None and network in HEADER_DECLARED_NETWORKS \
                and str(e).split(":")[0] in ("header_fields_not_a_fork_prefix", "unknown_block_member", "missing_header_field"):
            note.append("header_declared:%s" % e)
            return h
        raise Rejected("header_refused:%s" % e)
    if got != block_hash.lower():
        raise Rejected("header_hash_mismatch:%s" % got)
    return h


def tx_hash_of(tx):
    from inclusion import encode_tx
    try:
        return "0x" + keccak256(encode_tx(tx)).hex()
    except (ab.BlockRefusal, KeyError, TypeError, ValueError) as e:
        raise Rejected("tx_not_encodable:%s" % e)


def check_tx(tx, c):
    if not isinstance(tx, dict):
        raise Rejected("tx_not_object")
    if tx_hash_of(tx) != c["tx_hash"] or (tx.get("hash") or "").lower() != c["tx_hash"]:
        raise Rejected("tx_hash_mismatch")
    if (tx.get("blockHash") or "").lower() != c["block_hash"] or int(tx.get("blockNumber", "0x"), 16) != c["block_number"] \
            or int(tx.get("transactionIndex", "0x"), 16) != c["tx_index"]:
        raise Rejected("tx_not_at_pinned_position")
    # `from` is not in the RLP: it must be the address the signature recovers (every EVM bundle of the list is type 0x2;
    # another type is refused, not trusted)
    try:
        sender = av.tx_sender_eip1559(tx)
    except (av.Refusal, KeyError, TypeError) as e:
        raise Rejected("tx_sender_not_recovered:%s" % e)
    if sender is None or (tx.get("from") or "").lower() != sender.lower():
        raise Rejected("tx_from_is_not_the_signer")
    return tx


def receipt_hash_of(rc):
    try:
        return "0x" + keccak256(ab.encode_receipt(rc, 0)).hex()
    except ab.BlockRefusal as e:
        raise Rejected("receipt_not_encodable:%s" % e)


class Block:
    """One block of one network: header (pinned), the hashes of its transactions, its receipts verified in the
    receiptsRoot when the endpoint serves eth_getBlockReceipts, the full block when inclusion proofs are needed."""

    def __init__(self, rpc, network, number, block_hash):
        self.rpc, self.network, self.number, self.block_hash = rpc, network, number, block_hash
        self._header = self._hashes = self._full = self._receipts = None
        self.receipts_root_verified = None
        self.notes = []

    def header(self):
        if self._header is None:
            # by number (a by-hash read counts as an archive request on some public endpoints); the pinned hash decides
            b = self.rpc.call(self.network, "eth_getBlockByNumber", [hex(self.number), False])
            self._header = check_header(b, self.block_hash, self.notes, self.network)
            if not isinstance(b.get("transactions"), list):
                raise Rejected("block_transactions_not_list")
            self._hashes = [h.lower() for h in b["transactions"]]
        return self._header

    def tx_hashes(self):
        self.header()
        return self._hashes

    def full(self):
        """eth_getBlockByNumber(n, true): every transaction, each re-encoded to its hash, the transactionsRoot
        recomputed (inclusion.build does both); the header must be the pinned one."""
        if self._full is None:
            b = self.rpc.call(self.network, "eth_getBlockByNumber", [hex(self.number), True])
            check_header(b, self.block_hash)
            self._full = b
        return self._full

    def receipts(self):
        """eth_getBlockReceipts, accepted only when its receiptsRoot recomputes to the pinned header's. None when the
        endpoint has no such method (the receipt is then anchored to the list's receipt_hash, 33.4)."""
        if self._receipts is None:
            try:
                rcs = self.rpc.call(self.network, "eth_getBlockReceipts", [hex(self.number)])
            except Rejected as e:
                if "rpc_error" not in str(e) or not _NO_METHOD.search(str(e)):
                    raise                     # an endpoint that fails otherwise is not worked around
                self._receipts = False
                self.receipts_root_verified = False
                self.notes.append("no_eth_getBlockReceipts")
                return None
            if not isinstance(rcs, list):
                raise Rejected("receipts_not_list")
            try:
                root = ab.receipts_root(rcs)
            except ab.BlockRefusal as e:
                # a receipt type our encoder does not know (Arbitrum, Celo): the set cannot be checked, nothing of
                # it is used; the receipt is anchored to the list's receipt_hash, and the report says so
                self._receipts = False
                self.receipts_root_verified = False
                self.notes.append("receipts_not_encodable:%s" % e)
                return None
            if any(n.startswith("header_declared") for n in self.notes):
                # a receiptsRoot read from a header that was not recomputed anchors nothing (33.5)
                self._receipts = False
                self.receipts_root_verified = False
                self.notes.append("receipts_root_of_a_declared_header")
                return None
            if root != self.header()["receiptsRoot"].lower():
                # the set does not recompute to the pinned header (a chain whose receipt encoding differs from the
                # Ethereum one, e.g. Avalanche: measured 2026-10-26): nothing of it is used; the receipt is then
                # anchored to the list's receipt_hash, and the report says so
                self._receipts = False
                self.receipts_root_verified = False
                self.notes.append("receipts_root_mismatch")
                return None
            self._receipts = rcs
            self.receipts_root_verified = True
        return self._receipts or None

    def receipt(self, c):
        """The receipt of the pinned transaction: from the root-verified set, else eth_getTransactionReceipt matched to
        the list's receipt_hash; without either, refused."""
        rcs = self.receipts()
        rc = None
        if rcs is not None:
            if c["tx_index"] >= len(rcs):
                raise Rejected("tx_index_beyond_receipts")
            rc = rcs[c["tx_index"]]
            if (rc.get("transactionHash") or "").lower() != c["tx_hash"]:
                raise Rejected("receipt_at_index_is_another_transaction")
            if c["receipt_hash"] is not None and receipt_hash_of(rc) != c["receipt_hash"]:
                raise Rejected("receipt_hash_mismatch_with_list")
            return rc, "receiptsRoot"
        rc = self.rpc.call(self.network, "eth_getTransactionReceipt", [c["tx_hash"]])
        if c["receipt_hash"] is None:
            raise Rejected("receipt_unanchored:no_eth_getBlockReceipts_and_no_receipt_hash")
        if receipt_hash_of(rc) != c["receipt_hash"]:
            raise Rejected("receipt_hash_mismatch")
        if (rc.get("blockHash") or "").lower() != self.block_hash or (rc.get("transactionHash") or "").lower() != c["tx_hash"]:
            raise Rejected("receipt_not_at_pinned_position")
        return rc, "receipt_hash"

    def tx(self, c):
        hashes = self.tx_hashes()
        if c["tx_index"] >= len(hashes) or hashes[c["tx_index"]] != c["tx_hash"]:
            raise Rejected("tx_not_in_block_at_index")
        return check_tx(self.rpc.call(self.network, "eth_getTransactionByHash", [c["tx_hash"]]), c)

    def inclusion(self, tx_hash):
        import inclusion
        rcs = self.receipts()
        if rcs is None:
            raise Rejected("inclusion_needs_eth_getBlockReceipts")
        try:
            return inclusion.build(self.full(), rcs, tx_hash)
        except ab.BlockRefusal as e:
            raise Rejected("inclusion_refused:%s" % e)

    def logs(self, address, topic0, tx_hash, receipt):
        """eth_getLogs by block hash (the call our census tools made), each log accepted only if the receipt verified
        above holds a log at that index with the same address, topics and data."""
        got = self.rpc.call(self.network, "eth_getLogs", [{"blockHash": self.block_hash, "address": address, "topics": [topic0]}])
        if not isinstance(got, list):
            raise Rejected("logs_not_list")
        by_index = {}
        for lg in receipt.get("logs") or []:
            by_index[int(lg["logIndex"], 16)] = lg
        out = []
        for lg in got:
            if (lg.get("transactionHash") or "").lower() != tx_hash:
                continue
            # the members of a log that are not in the receipt: position (pinned) and `removed` (a reorged log)
            if (lg.get("blockHash") or "").lower() != self.block_hash or int(lg.get("blockNumber", "0x"), 16) != self.number \
                    or lg.get("removed") not in (False, None):
                raise Rejected("log_not_at_pinned_block:%s" % lg.get("logIndex"))
            ref = by_index.get(int(lg.get("logIndex", "0x"), 16))
            if ref is None or [t.lower() for t in ref["topics"]] != [t.lower() for t in lg["topics"]] \
                    or ref["data"].lower() != lg["data"].lower() or ref["address"].lower() != lg["address"].lower():
                raise Rejected("log_not_in_verified_receipt:%s" % lg.get("logIndex"))
            out.append(lg)
        return out


# ------------------------------------------------------------------ recipes


def _rlog(receipt, index):
    for lg in receipt.get("logs") or []:
        if int(lg["logIndex"], 16) == index:
            return lg
    return None


def recipe_evm_eip3009(rpc, s, e, blocks):
    """apc-0.1 / apc-0.2 / apc-0.3 bundles of EIP-3009 executions (bundles/real, real_world, real_v02*, real_v03,
    real_msca, real_reverted, real_issue1062, the EVM negatives), built as tools/make_real_bundles.py,
    make_bundles_v02.py, make_bundles_v03.py and make_bundles_msca.py build them."""
    import make_bundles_v02 as v02
    from check_eip3009_oracle import decode
    c, ours, p = e["chain"], e.get("ours", {}), s["params"]
    net = e["network"]
    blk = blocks.get(rpc, net, c["block_number"], c["block_hash"])
    tx = blk.tx(c)
    rc, _anchor = blk.receipt(c)
    token = p["token"].lower() if "token" in p else (tx.get("to") or "").lower()
    tokens = p.get("tokens", {})
    name, version = (tokens[token] if token in tokens else (p.get("token_name"), p.get("token_version")))
    ver = e["bundle_version"]
    if ours.get("form") == "reverted":
        # tools/make_bundle_reverted.py and make_bundles_negatives.py: transaction alone (+ inclusion when apc-0.3)
        if rc.get("status") != "0x0":
            raise Rejected("receipt_status_not_0_for_a_reverted_call")
        form = {"0xe3ee160e": "vrs", "0xcf092995": "bytes"}[tx["input"][:10].lower()]
        msg, sig = decode(form, tx["input"])
        v, r, sv = sig
        b = {"bundle_version": ver,
             "payment_payload": {"x402Version": 2,
                                 "accepted": {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": token,
                                              "payTo": msg["to"], "maxTimeoutSeconds": 60, "extra": {"name": name, "version": version}},
                                 "payload": {"signature": "0x" + r.to_bytes(32, "big").hex() + sv.to_bytes(32, "big").hex() + bytes([v]).hex(),
                                             "authorization": {k: (str(x) if isinstance(x, int) else x) for k, x in msg.items()}}},
             "settlement": {"success": True, "transaction": tx["hash"], "network": net, "payer": msg["from"]},
             "chain_tx": {"network": net, "tx": tx}}
        if ours.get("inclusion"):
            b["inclusion"] = blk.inclusion(tx["hash"])
        return b
    if rc.get("status") != "0x1":
        raise Rejected("receipt_status_not_1")
    lg = _rlog(rc, c["log_index"])
    if lg is None or lg["address"].lower() != token or lg["topics"][0].lower() != TOPIC_AUTH_USED:
        raise Rejected("pinned_log_is_not_AuthorizationUsed_of_the_token")
    used = blk.logs(token, TOPIC_AUTH_USED, c["tx_hash"], rc)
    lg = next((x for x in used if int(x["logIndex"], 16) == c["log_index"]), None)
    if lg is None:
        raise Rejected("AuthorizationUsed_log_not_returned_by_eth_getLogs")
    if ver == "apc-0.1":
        form = {"0xe3ee160e": "vrs", "0xcf092995": "bytes"}.get(tx["input"][:10].lower())
        if form is None:
            raise Rejected("not_a_direct_transferWithAuthorization_call")
        msg, sig = decode(form, tx["input"])
        if sig[0] == "contract":
            raise Rejected("contract_signature_in_an_apc-0.1_bundle")
        v, r, sv = sig
        if lg["topics"][2].lower() != msg["nonce"]:
            raise Rejected("log_nonce_is_not_the_calldata_nonce")
        signature = "0x" + r.to_bytes(32, "big").hex() + sv.to_bytes(32, "big").hex() + bytes([v]).hex()
        acc = {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": token,
               "payTo": msg["to"], "maxTimeoutSeconds": 60, "extra": {"name": name, "version": version}}
        b = {"bundle_version": "apc-0.1",
             "payment_payload": {"x402Version": 2, "accepted": acc,
                                 "payload": {"signature": signature, "authorization": {
                                     "from": msg["from"], "to": msg["to"], "value": str(msg["value"]),
                                     "validAfter": str(msg["validAfter"]), "validBefore": str(msg["validBefore"]),
                                     "nonce": msg["nonce"]}}},
             "settlement": {"success": True, "transaction": tx["hash"], "network": net, "payer": msg["from"]},
             "chain_tx": {"network": net, "tx": tx, "log_authorization_used": lg}}
        if "settlement" in ours:                      # bundles/real_issue1062: the reply quoted in the public issue
            o = ours["settlement"]                    # in the member order tools/make_bundle_issue1062.py writes
            b["settlement"] = {k: o[k] for k in ("success", "errorReason", "network", "transaction") if k in o}
            b["settlement"].update({k: v for k, v in o.items() if k not in b["settlement"]})
            b["payment_payload"]["payload"]["authorization"] = {k: (str(x) if isinstance(x, int) else x) for k, x in msg.items()}
            rlg = dict(_rlog(rc, c["log_index"]))
            rlg.setdefault("blockTimestamp", tx.get("blockTimestamp"))
            b["chain_tx"]["log_authorization_used"] = rlg
        return b
    # apc-0.2 / apc-0.3: tools/make_bundles_v02.py (the Transfer log right after AuthorizationUsed, the extraction)
    transfers = blk.logs(token, TOPIC_TRANSFER, c["tx_hash"], rc)
    tr = {int(x["logIndex"], 16): x for x in transfers}
    lt = tr.get(c["log_index"] + 1)
    if lt is None:
        raise Rejected("no_transfer_log_after_AuthorizationUsed")
    chain_id = int(net[7:])
    dom = {"name": name, "version": version, "chainId": chain_id, "verifyingContract": token}
    bts = bytes.fromhex(tx["input"][2:])
    direct = (tx["to"] or "").lower() == token
    found, extraction = None, "calldata"
    for pos in ([0] if direct else [i for i in range(len(bts) - 3) if bts[i:i + 4] in v02.SEL]):
        d = v02.decode_at(bts, pos)
        if d and d[1]["from"] == "0x" + lg["topics"][1][-40:] and d[1]["nonce"] == lg["topics"][2].lower() \
                and (v02.recovers(dom, d[1], d[2]) or (direct and ours.get("payer_state") and d[0] == "vrs")):
            found = d                 # a payer with code (SPEC 32): the chain asked its ERC-1271, not ecrecover
            break
    frm, nonce = "0x" + lg["topics"][1][-40:], lg["topics"][2].lower()
    to, value = "0x" + lt["topics"][2][-40:], int(lt["data"], 16)
    if found is None and not direct and "0x" + lt["topics"][1][-40:] == frm:
        for msg, sig in v02.log_guided(bts, frm, nonce, to, value):
            if sig[64] in (27, 28) and v02.recovers(dom, msg, sig):
                found, extraction = ("bytes", msg, sig), "log_guided"
                break
    pw = None
    if found is None and ours.get("extraction") == "log_guided_wallet":
        pw = payer_wallet_replies(rpc, net, frm, tx["blockNumber"], c.get("state") or {}, ours.get("state_sha256") or {})
        acc0 = {"domain_name": name, "domain_version": version, "chain_id": chain_id, "asset": token, "notes": []}
        for va, vb in v02.windows_of(bts):
            msg = {"from": frm, "to": to, "value": value, "validAfter": va, "validBefore": vb, "nonce": nonce}
            for blob in v02.abi_blobs(bts):
                try:
                    r, _ = av.check_signature_1271({"signature": blob, "auth": msg, "accepted": acc0}, pw, tx["blockNumber"])
                except av.Refusal:
                    continue
                if r.startswith("verified"):
                    found, extraction = ("wallet", msg, blob), "log_guided_wallet"
                    break
            if found:
                break
    if found is None:
        raise Rejected("authorization_not_extracted_from_calldata")
    if ours.get("extraction", extraction) != extraction:
        raise Rejected("extraction_%s_not_%s" % (extraction, ours["extraction"]))
    form, msg, sig = found
    acc = {"scheme": "exact", "network": net, "amount": str(msg["value"]), "asset": token, "payTo": msg["to"],
           "maxTimeoutSeconds": 60, "extra": {"name": name, "version": version}}
    bundle = {"bundle_version": "apc-0.2",
              "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
                  "signature": "0x" + sig.hex(),
                  "authorization": {"from": msg["from"], "to": msg["to"], "value": str(msg["value"]),
                                    "validAfter": str(msg["validAfter"]), "validBefore": str(msg["validBefore"]),
                                    "nonce": msg["nonce"]}}},
              "settlement": {"success": True, "transaction": tx["hash"], "network": net, "payer": msg["from"]},
              "chain_tx": {"network": net, "tx": tx, "log_authorization_used": lg, "log_transfer": lt}}
    if pw is not None and extraction == "log_guided_wallet":
        bundle["payer_wallet"] = pw
    lf = tr.get(c["log_index"] + 2)
    if lf is not None and lf["topics"][1].lower() == "0x" + "0" * 24 + msg["to"][2:]:
        bundle["chain_tx"]["log_forward"] = lf
    if ours.get("payer_wallet") and "payer_wallet" not in bundle:       # bundles/real_v02_wallet, real_v03 (direct calls)
        bundle["payer_wallet"] = payer_wallet_replies(rpc, net, frm, tx["blockNumber"], c.get("state") or {},
                                                      ours.get("state_sha256") or {})
    if ours.get("inclusion"):
        bundle["bundle_version"] = "apc-0.3"
        bundle["inclusion"] = blk.inclusion(tx["hash"])
    if ours.get("payer_state"):                                          # bundles/real_msca_20261101 (SPEC 32.4)
        bundle = dict(bundle)
        bundle["bundle_version"] = ver
        bundle["payer_state"] = payer_state(rpc, blk, c["state"], ours["payer_state"], frm)
    if "anchor" in c:                                                    # the anchored twins (SPEC 33.10)
        bundle["canonical"] = canonical_member(rpc, c, blk, bundle["inclusion"]["block_header"], blocks)
    bundle["bundle_version"] = ver
    return bundle


def _hash_result(x):
    return hashlib.sha256(canon(x).encode()).hexdigest()


def payer_wallet_replies(rpc, net, payer, blk_hex, state, recorded):
    """The three replies of SPEC 3 L2.sig-1271 at the transaction's block (an archive endpoint). Declared data: the
    code is checked by its keccak256, the implementation by its address, the ownerAtIndex reply by the sha256 the list
    recorded (33.5); a reply outside those is refused."""
    code = rpc.call(net, "eth_getCode", [payer, blk_hex])
    if state.get("code_keccak") and keccak256(bytes.fromhex(code[2:])).hex() != state["code_keccak"]:
        raise Rejected("payer_code_keccak_mismatch")
    impl = rpc.call(net, "eth_getStorageAt", [payer, av.ERC1967_SLOT, blk_hex])
    if state.get("implementation") and "0x" + impl[-40:].lower() != state["implementation"].lower():
        raise Rejected("payer_implementation_mismatch")
    data = "0x" + keccak256(b"ownerAtIndex(uint256)")[:4].hex() + "%064x" % 0
    owner = rpc.call(net, "eth_call", [{"to": payer, "data": data}, blk_hex])
    if recorded.get("owner") and _hash_result(owner) != recorded["owner"]:
        raise Rejected("payer_owner_reply_not_the_recorded_one")
    return {"owner_index": "0",
            "code": {"method": "eth_getCode", "params": [payer, blk_hex], "result": code},
            "implementation": {"method": "eth_getStorageAt", "params": [payer, av.ERC1967_SLOT, blk_hex], "result": impl},
            "owner": {"method": "eth_call", "params": [{"to": payer, "data": data}, blk_hex], "result": owner}}


def _proof(rpc, net, address, slots, number):
    p = rpc.call(net, "eth_getProof", [address, slots, hex(number)])
    if not isinstance(p, dict) or not isinstance(p.get("accountProof"), list):
        raise Rejected("proof_not_object")
    return p


def _addr_keccak(addr):
    return keccak256(bytes.fromhex(addr[2:].rjust(40, "0"))).hex()


def payer_state(rpc, blk, state, form, payer):
    """SPEC 32.4 payer_state of a Circle_SingleOwnerMSCA payer, as tools/make_bundles_msca.py builds it: proofs at the
    parent block and at the block (form proof) or the plain replies (form rpc). apc_verify proves them against the
    headers; here the parent header must be the pinned header's parent. `payer` is the address derived from the
    AuthorizationUsed log; the owner is read from the state and accepted only if its keccak256 is the list's."""
    import apc_msca
    net, n = blk.network, blk.number
    code = rpc.call(net, "eth_getCode", [payer, hex(n)])
    pin = apc_msca.WALLETS.get(keccak256(bytes.fromhex(code[2:])).hex())
    if pin is None or (state.get("code_keccak") and keccak256(bytes.fromhex(code[2:])).hex() != state["code_keccak"]):
        raise Rejected("payer_code_not_the_listed_msca")
    slots = ["0x%064x" % apc_msca.ERC1967_SLOT, "0x%064x" % pin[2]]
    if form == "rpc":
        impl_w = rpc.call(net, "eth_getStorageAt", [payer, slots[0], hex(n)])
        own_w = rpc.call(net, "eth_getStorageAt", [payer, slots[1], hex(n)])
        impl = "0x" + impl_w[-40:]
        owner = "0x%040x" % (int(own_w, 16) >> 16)
        if impl != state["implementation"] or _addr_keccak(owner) != state["owner_keccak"]:
            raise Rejected("payer_state_rpc_addresses_mismatch")
        rep = lambda m, p, r: {"method": m, "params": p, "result": r}       # noqa: E731
        return {"rpc": {"code": rep("eth_getCode", [payer, hex(n)], code), "wallet": {
            "implementation": rep("eth_getStorageAt", [payer, slots[0], hex(n)], impl_w),
            "owner": rep("eth_getStorageAt", [payer, slots[1], hex(n)], own_w),
            "implementation_code": rep("eth_getCode", [impl, hex(n)], rpc.call(net, "eth_getCode", [impl, hex(n)])),
            "owner_code": rep("eth_getCode", [owner, hex(n)], rpc.call(net, "eth_getCode", [owner, hex(n)]))}}}
    ph = rpc.call(net, "eth_getBlockByNumber", [hex(n - 1), False])
    parent = check_header(ph, blk.header()["parentHash"], blk.notes, net)
    ends = {}
    for end, b in (("at_parent", n - 1), ("at_block", n)):
        p = _proof(rpc, net, payer, slots, b)
        impl = "0x" + p["storageProof"][0]["value"][2:].rjust(40, "0")[-40:]
        owner = "0x%040x" % (int(p["storageProof"][1]["value"], 16) >> 16)
        if impl != state["implementation"] or _addr_keccak(owner) != state["owner_keccak"]:
            raise Rejected("payer_state_proof_addresses_mismatch")
        ends[end] = {"payer": {"accountProof": p["accountProof"],
                               "storageProof": [p["storageProof"][0]["proof"], p["storageProof"][1]["proof"]]},
                     "implementation": {"accountProof": _proof(rpc, net, impl, [], b)["accountProof"]},
                     "owner": {"accountProof": _proof(rpc, net, owner, [], b)["accountProof"]}}
    return {"proof": {"code": code, "parent_header": {k: parent[k] for k in HEADER_KEYS if k in parent},
                      "at_parent": ends["at_parent"], "at_block": ends["at_block"]}}


def canonical_member(rpc, c, blk, inc_header, blocks):
    """SPEC 33.10: the `canonical` member of an anchored bundle (32.10), built as tools/anchor_msca.py builds it — the L1
    side as sources/l1proof_20261024/fetch_l1proof.fetch at the pinned L1 block for the pinned game, `l1_state` as
    tools/make_bundles_l1state.l1_state, the L2 headers from the root's block down to the block after the payment's — and
    accepted only through apc_verify.check_canonical with the pinned L1 header hash as the checkpoint: L1, O1, O2 and O3
    verified, else refused with the check and its reason. Nothing here is declared data."""
    import anchor_msca
    import fetch_l1proof as FL
    ML = _tool_module("make_bundles_l1state")
    a, net, n = c["anchor"], blk.network, blk.number
    key = (a["l1_network"], a["l1_block_hash"], a["game"])
    if key not in blocks.l1:                              # once per (L1 block, game), whatever the number of bundles
        try:
            d = FL.fetch(a["game"], hex(a["l1_block_number"]), lambda m, p: rpc.call(a["l1_network"], m, p), pins=False)
            check_header(d["header"], a["l1_block_hash"])     # the checkpoint: no declared layout here
            try:
                st = ML.l1_state(d)
            except (ab.BlockRefusal, apc_l1proof.NotPinned) as e:
                raise Rejected("l1_state_not_recomputed:%s" % e)
            blocks.l1[key] = (d, st)
        except Rejected as e:                             # kept: the other bundles of the game do not ask again
            blocks.l1[key] = e                            # (measured 2026-11-02: 28 refusals for one endpoint answer)
            raise
    if isinstance(blocks.l1[key], Rejected):
        raise blocks.l1[key]
    d, st = blocks.l1[key]
    replies = [{"method": "eth_call", "params": [{"to": x["to"], "data": x["data"]}, d["block"]], "result": x["result"]}
               for x in d["calls"]]
    try:                                                  # start, l2SequenceNumber, roots: as tools/anchor_msca.game_facts
        ed = bytes.fromhex(d["calls"][2]["result"][2:])
        f = {"start": int(d["calls"][3]["result"], 16), "seq": int.from_bytes(ed[64:96], "big"),
             "roots": (int.from_bytes(ed[32:64], "big") - 52) // 32}
        if not f["start"] < n <= f["seq"]:
            raise Rejected("block_not_in_game_range")
        i, m, _k = anchor_msca.place(f, n)
    except (ValueError, ZeroDivisionError) as e:
        raise Rejected("game_replies_not_readable:%s" % type(e).__name__)
    if i != a["root_index"]:
        raise Rejected("root_index_not_the_first_root_at_or_after_the_block:%d" % i)
    if m - n > MAX_CANONICAL_HEADERS:
        raise Rejected("root_block_too_far:%d" % (m - n))
    headers = []
    for b in range(m, n, -1):
        if (net, b) not in blocks.headers:
            h = rpc.call(net, "eth_getBlockByNumber", [hex(b), False])
            if not isinstance(h, dict):
                raise Rejected("header_not_object")
            blocks.headers[(net, b)] = {k: h[k] for k in HEADER_KEYS if k in h}
        headers.append(blocks.headers[(net, b)])
    can = {"l1_network": a["l1_network"], "game": a["game"], "root_index": a["root_index"], "l1_replies": replies,
           "headers": headers, "l1_state": st}
    try:
        checks, _notes = av.check_canonical(json.loads(json.dumps(can)), json.loads(json.dumps(inc_header)), net, a["l1_block_hash"])
    except av.Refusal as e:
        raise Rejected("canonical_refused:%s" % e)
    for k in ("L1", "O1", "O2", "O3"):
        if checks[k] != "verified":
            raise Rejected("canonical_not_recomputed:%s:%s" % (k, checks[k]))
    return can


def recipe_evm_authcap(rpc, s, e, blocks):
    """apc-0.15 bundles of commerce-payments authorizations (tools/make_bundles_authcap.py), provenance of THIS fetch."""
    import make_bundles_authcap as mk
    c, p = e["chain"], s["params"]
    blk = blocks.get(rpc, e["network"], c["block_number"], c["block_hash"])
    tx = blk.tx(c)
    rc, _anchor = blk.receipt(c)
    if (tx.get("to") or "").lower() != p["escrow"].lower() and tx["input"].lower().find(mk.SEL.hex()) < 0:
        raise Rejected("not_an_authorize_call_of_the_escrow")
    b = mk.build_one(p["escrow"].lower(), int(e["network"][7:]), tx, rc)
    if b is None:
        raise Rejected("not_the_scheme_authorize_call")
    fetched = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    b["provenance"] = {"chain_tx": {"source": "%s JSON-RPC %s (tools/rebuild_corpus.py, SPEC section 33)"
                                              % (p.get("chain_name", e["network"]), host_of(rpc.url(e["network"]))),
                                    "fetched": fetched},
                       "settlement": {"source": "reconstructed from chain_tx, as the payment payload (tools/make_bundles_authcap.py)",
                                      "fetched": fetched}}
    return b


def recipe_evm_permit2(rpc, s, e, blocks):
    """apc-0.10 bundles of x402ExactPermit2Proxy settlements (tools/make_bundles_permit2.py); with `inclusion` and
    `payer_code` in its two forms for the state bundles (make_bundles_permit2_state.py, SPEC 12.5)."""
    import make_bundles_permit2 as mk
    c, ours = e["chain"], e.get("ours", {})
    blk = blocks.get(rpc, e["network"], c["block_number"], c["block_hash"])
    tx = blk.tx(c)
    rc, _anchor = blk.receipt(c)
    out, skipped = mk.build({tx["hash"]: {"tx": {"result": tx}, "receipt": {"result": rc}}})
    if not out:
        raise Rejected("permit2_not_built:%s" % (skipped[0][1] if skipped else "?"))
    b = out[0][1]
    form = ours.get("payer_code")
    if not form:
        return b
    b = copy.deepcopy(b)
    n, net, st = blk.number, e["network"], c["state"]
    payer = b["payment_payload"]["payload"]["permit2Authorization"]["from"]
    b["inclusion"] = blk.inclusion(tx["hash"])
    code = rpc.call(net, "eth_getCode", [payer, hex(n)])
    if keccak256(bytes.fromhex(code[2:])).hex() != st["code_keccak"]:
        raise Rejected("payer_code_keccak_mismatch")
    if form == "rpc":
        slot = st["slots"][0]
        storage = rpc.call(net, "eth_getStorageAt", [payer, slot, hex(n)])
        if (ours.get("state_sha256") or {}).get("storage") and _hash_result(storage) != ours["state_sha256"]["storage"]:
            raise Rejected("payer_storage_reply_not_the_recorded_one")
        b["payer_code"] = {"rpc": {"code": {"method": "eth_getCode", "params": [payer, hex(n)], "result": code},
                                   "storage": {"method": "eth_getStorageAt", "params": [payer, slot, hex(n)], "result": storage}}}
        return b
    ph = rpc.call(net, "eth_getBlockByNumber", [hex(n - 1), False])
    parent = check_header(ph, blk.header()["parentHash"], blk.notes, net)
    ends = {}
    for end, bn in (("at_parent", n - 1), ("at_block", n)):
        p = _proof(rpc, net, payer, st["slots"], bn)
        ends[end] = {"payer": {"accountProof": p["accountProof"], "storageProof": p["storageProof"][0]["proof"]}}
        if st.get("delegate"):
            ends[end]["delegate"] = {"accountProof": _proof(rpc, net, st["delegate"], [], bn)["accountProof"]}
    b["payer_code"] = {"proof": {"code": code, "parent_header": {k: parent[k] for k in HEADER_KEYS if k in parent},
                                 "at_parent": ends["at_parent"], "at_block": ends["at_block"]}}
    return b


def _tool_module(name):
    """tools/make_bundles_svm.py and tools/make_bundles_l1state.py read ROOT from sys.argv[1] at import (their own
    programs); imported here with this program's argv they would read `--rpc`. Imported once, under the right ROOT."""
    argv, sys.argv = sys.argv, [sys.argv[0], ROOT]
    try:
        return importlib.import_module(name)
    finally:
        sys.argv = argv


def recipe_svm_exact(rpc, s, e, blocks):
    """apc-0.5 bundles (tools/make_bundles_svm.py): getTransaction base64; the fee payer's ed25519 signature over the
    message must verify and be the pinned id (consensus); slot, blockTime and the reduced meta are the endpoint's
    execution record, accepted only if their sha256 is the one the list recorded (declared data, 33.5)."""
    import apc_solana as sol
    m = _tool_module("make_bundles_svm")
    c, ours = e["chain"], e.get("ours", {})
    r = rpc.call(e["network"], "getTransaction", [c["signature"], {"encoding": "base64", "maxSupportedTransactionVersion": 0}])
    if not isinstance(r, dict) or not isinstance(r.get("transaction"), list) or not isinstance(r.get("meta"), dict):
        raise Rejected("getTransaction_shape")
    try:
        raw = base64.b64decode(r["transaction"][0], validate=True)
        tx = sol.parse_tx(raw)
    except (ValueError, sol.SolRefusal) as e2:
        raise Rejected("transaction_not_parsed:%s" % e2)
    if not tx["signatures"] or sol.b58encode(tx["signatures"][0]) != c["signature"]:
        raise Rejected("first_signature_is_not_the_pinned_id")
    if not tx["keys"]:
        raise Rejected("message_without_accounts")
    fee_payer = tx["keys"][0]                 # derived from the signed message, not carried in clear by the list (33.2)
    try:
        ok = sol.ed25519_verify(sol.b58decode(fee_payer, 32), tx["message"], tx["signatures"][0])
    except (ValueError, sol.SolRefusal):
        ok = False
    if not ok:
        raise Rejected("fee_payer_signature_invalid")
    if r.get("slot") != c["slot"]:
        raise Rejected("slot_mismatch")
    b, why = m.bundle(r, fee_payer, ours.get("memo"))
    if b is None:
        raise Rejected("svm_not_built:%s" % why)
    if _hash_result(b["chain_tx"]) != c["chain_tx_sha256"]:
        raise Rejected("chain_tx_not_the_recorded_execution_record")
    if "mandate" in ours:                                   # bundles/real_svm_mandate: our own ap2-evidence-pack fixture
        b = {"bundle_version": b["bundle_version"], "payment_payload": b["payment_payload"], "settlement": b["settlement"],
             "chain_tx": b["chain_tx"], "mandate": ours["mandate"]}
    return b


class Ledger:
    """One XRPL ledger, fetched once with every transaction in binary, accepted only if ledger_data hashes to the pinned
    ledger hash and the SHAMap root of all (tx, meta) leaves is the header's transaction_hash."""

    def __init__(self, rpc, network, index, ledger_hash):
        import apc_xrpl as xr
        res = rpc.call(network, "ledger", {"ledger_index": index, "transactions": True, "expand": True, "binary": True}, xrpl=True)
        L = res.get("ledger")
        if not isinstance(L, dict) or not isinstance(L.get("ledger_data"), str) or not isinstance(L.get("transactions"), list):
            raise Rejected("ledger_shape")
        try:
            hdr = xr.ledger_header(bytes.fromhex(L["ledger_data"]))
        except (ValueError, xr.XrplError) as e:
            raise Rejected("ledger_data_refused:%s" % e)
        if hdr["hash"] != ledger_hash or hdr["ledger_index"] != index:
            raise Rejected("ledger_hash_mismatch")
        leaves = {}
        for t in L["transactions"]:
            try:
                tid, leaf = xr.tx_leaf(bytes.fromhex(t["tx_blob"]), bytes.fromhex(t["meta"]))
            except (KeyError, TypeError, ValueError, xr.XrplError) as e:
                raise Rejected("transaction_leaf_refused:%s" % e)
            leaves[tid] = leaf
        if xr.shamap_root(leaves) != hdr["transaction_hash"]:
            raise Rejected("transaction_tree_mismatch")
        self.index, self.hash, self.ledger, self.result, self.header = index, ledger_hash, L, res, hdr
        self.ids = {tid.hex().upper() for tid in leaves}


def recipe_xrpl_exact(rpc, s, e, ledgers):
    import make_bundles_xrp as mk
    c = e["chain"]
    key = (e["network"], c["ledger_index"])
    if key not in ledgers:
        ledgers[key] = Ledger(rpc, e["network"], c["ledger_index"], c["ledger_hash"])
    L = ledgers[key]
    if c["tx_hash"] not in L.ids:
        raise Rejected("tx_not_in_ledger")
    fetched = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    prov = {"chain_tx": {"source": "XRPL mainnet %s ledger (binary), tools/rebuild_corpus.py (SPEC section 33)"
                                   % host_of(rpc.url(e["network"])), "fetched": fetched},
            "settlement": {"source": "reconstructed from chain_tx, as the requirements (tools/make_bundles_xrp.py)", "fetched": fetched}}
    for t in L.ledger["transactions"]:
        b = mk.build_one(t, L.ledger, c["ledger_index"], prov, first=bool(e.get("ours", {}).get("inclusion")))
        if b is not None and b["settlement"]["transaction"] == c["tx_hash"]:
            return b
    raise Rejected("payment_not_built_from_ledger")


RECIPE_FN = {"evm_eip3009": recipe_evm_eip3009, "evm_authcap": recipe_evm_authcap, "evm_permit2": recipe_evm_permit2,
             "svm_exact": recipe_svm_exact, "xrpl_exact": recipe_xrpl_exact}


class Blocks:
    def __init__(self):
        self.d = {}
        self.l1, self.headers = {}, {}             # 33.10: the L1 fetch per (L1 block, game), the L2 headers per block

    def get(self, rpc, net, number, block_hash):
        k = (net, block_hash)
        if k not in self.d:
            self.d[k] = Block(rpc, net, number, block_hash)
        return self.d[k]


# ------------------------------------------------------------------ driver


def verdict_of(doc, options):
    rep = av.verify_bundle(json.loads(json.dumps(doc)), **_opts(options))
    return rep["verdict"], hashlib.sha256(canon(rep.get("checks", {})).encode()).hexdigest()


def _opts(options):
    out = {}
    if options.get("l1_checkpoint"):
        out["l1_checkpoint"] = options["l1_checkpoint"]
    return out


def compare(e, s, data, doc):
    """bytes | content | verdict | mismatch: the strongest level the rebuilt bundle reaches against the list."""
    if hashlib.sha256(data).hexdigest() == e["sha256"]:
        return "bytes"
    if content_digest(doc) == e["content_sha256"]:
        return "content"
    v, ck = verdict_of(doc, s["params"].get("options", {}))
    if v == e["verdict"] and ck == e["checks_sha256"]:
        return "verdict"
    return "mismatch:verdict=%s" % v


def rebuild(man, rpc, out, only=None, sample=None, force=False, log=print):
    blocks, ledgers = Blocks(), {}
    report = {"written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "format": FORMAT, "results": [], "summary": {}}
    per_set = {}
    for e in man["bundles"]:
        if only and e["set"] not in only and e["file"] not in only:
            continue
        per_set.setdefault(e["set"], []).append(e)
    for name in sorted(per_set):
        s = man["sets"][name]
        entries = sorted(per_set[name], key=lambda x: x["file"])
        if sample:
            entries = entries[:sample]
        if s["rebuild"] == "local_only":
            for e in entries:
                report["results"].append({"file": e["file"], "status": "local_only", "reason": s["reason"]})
            log("%s: %d bundles local_only (%s)" % (name, len(entries), s["reason"]))
            continue
        for e in entries:
            recipe = e.get("recipe", s["recipe"])
            fn = RECIPE_FN[recipe]
            row = {"file": e["file"], "declared": s["rebuild"]}
            try:
                doc = fn(rpc, s, e, ledgers if recipe == "xrpl_exact" else blocks)
                data = serialize(doc, s["serialization"])
                row["status"] = compare(e, s, data, doc)
                row["ok"] = LEVELS.index(row["status"]) <= LEVELS.index(s["rebuild"]) if row["status"] in LEVELS else False
                if recipe.startswith("evm_"):
                    blk = blocks.d.get((e["network"], e["chain"]["block_hash"]))
                    row["anchors"] = {"header": "declared" if any(n.startswith("header_declared") for n in blk.notes) else "recomputed",
                                      "receipt": "receiptsRoot" if blk.receipts_root_verified else "receipt_hash"}
                    if "anchor" in e["chain"]:
                        row["anchors"]["canonical"] = "recomputed"          # L1, O1-O3 under the pinned checkpoint (33.10)
                    if blk.notes:
                        row["notes"] = sorted(set(blk.notes))
                path = os.path.join(out, e["file"])
                if not row["ok"]:
                    row["written"] = False            # a bundle below its set's level is not written (33.3)
                elif os.path.exists(path) and not force:
                    row["written"] = False
                    with open(path, "rb") as fh:
                        old = fh.read()
                    try:
                        old_level = compare(e, s, old, json.loads(old))
                    except (ValueError, KeyError, TypeError, RecursionError, av.Refusal) as ex:    # 33.11: nested too
                        old_level = "unreadable:%s" % type(ex).__name__
                    row["note"] = "exists, not overwritten (--force); the file there: %s" % old_level
                    if old_level not in LEVELS or LEVELS.index(old_level) > LEVELS.index(s["rebuild"]):
                        row["ok"] = False
                else:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as fh:
                        fh.write(data)
                    row["written"] = True
            except Rejected as ex:
                row["status"], row["ok"] = "refused:%s" % ex, False
            except SHAPE_ERRORS as ex:                    # a reply outside the shape the recipe reads (33.11)
                row["status"], row["ok"] = "refused:reply_shape:%s:%s" % (type(ex).__name__, ex), False
            report["results"].append(row)
            log("%s %s" % (row["status"], e["file"]))
    agg = {}
    for r in report["results"]:
        k = r["status"].split(":")[0]
        agg[k] = agg.get(k, 0) + 1
    agg["below_declared_level"] = sum(1 for r in report["results"] if r.get("ok") is False)
    agg["anchors"] = {"header_recomputed": sum(1 for r in report["results"] if r.get("anchors", {}).get("header") == "recomputed"),
                      "header_declared": sum(1 for r in report["results"] if r.get("anchors", {}).get("header") == "declared"),
                      "receipt_in_receiptsRoot": sum(1 for r in report["results"] if r.get("anchors", {}).get("receipt") == "receiptsRoot"),
                      "receipt_by_list_hash": sum(1 for r in report["results"] if r.get("anchors", {}).get("receipt") == "receipt_hash"),
                      "canonical_recomputed": sum(1 for r in report["results"] if r.get("anchors", {}).get("canonical") == "recomputed")}
    report["summary"] = agg
    report["rpc_calls"] = rpc.calls
    return report


def _envelope(result):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()


def _existing_result(path):
    """The canonical `result` digest of a gzip raw file already under --out-oracle, or None when it cannot be read."""
    try:
        with gzip.open(path) as fh:
            return hashlib.sha256(canon(json.loads(fh.read())["result"]).encode()).hexdigest()
    except (OSError, ValueError, KeyError, TypeError, EOFError, RecursionError):      # 33.11: nested too deep = not ours
        return None


def _existing_xrpl_is_ours(path, o):
    """A ledger file already under --out-oracle counts only if, for every listed ledger, its binary and JSON replies
    have the list's digest (other calls it holds, such as the `validated` one of the authors' file, are not read)."""
    try:
        with open(path, "rb") as fh:
            calls = json.loads(fh.read())["calls"]
        got = {}
        for c in calls:
            k = c["params"].get("ledger_index")
            if isinstance(k, int) and not isinstance(k, bool):
                got.setdefault(k, {})["binary" if c["params"].get("binary") else "json"] = c["result"]
        return all(set(got.get(it["ledger_index"], {})) == {"binary", "json"} and
                   hashlib.sha256(canon(got[it["ledger_index"]]).encode()).hexdigest() == o["result_sha256"][str(it["ledger_index"])]
                   for it in o["items"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):   # 33.11
        return False


def _gz_write(path, data, force):
    if os.path.exists(path) and not force:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "wb") as f0, gzip.GzipFile(filename="", fileobj=f0, mode="wb", mtime=0) as fh:
        fh.write(data)
    os.replace(path + ".tmp", path)
    return True


def rebuild_oracle(man, rpc, out, only=None, force=False, log=print):
    """The raw-reply directories of 33.8 that the list declares rebuildable: each reply is accepted only on the anchors
    of 33.4 and written as the tests read it, only at level `content` (the canonical result is ours: for XRPL both replies
    whole); `anchored` (the anchors hold, members no fingerprint covers differ) is reported, not written, exit 1."""
    import inclusion
    report = {"written": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "format": FORMAT, "results": [], "summary": {}}
    for name in sorted(man["oracle"]):
        o = man["oracle"][name]
        if only and name not in only:
            continue
        if o["kind"] == "local_only":
            report["results"].append({"oracle": name, "status": "local_only", "reason": o["reason"]})
            log("%s: local_only (%s)" % (name, o["reason"]))
            continue
        net = o["network"]
        if o["kind"] == "evm_blocks":
            for it in o["items"]:
                row = {"oracle": name, "item": it["number"]}
                try:
                    blk = Block(rpc, net, it["number"], it["hash"])
                    full, rcs = blk.full(), blk.receipts()
                    if any(n.startswith("header_declared") for n in blk.notes):
                        raise Rejected("header_not_recomputed")
                    if rcs is None or not blk.receipts_root_verified:
                        raise Rejected("receipts_not_in_a_recomputed_root")
                    try:
                        inclusion.build(full, rcs, full["transactions"][0]["hash"])     # every tx re-encoded to its hash
                    except (ab.BlockRefusal, IndexError, KeyError) as e:
                        raise Rejected("block_refused:%s" % e)
                    files = []
                    for suffix, res in (("_block.json.gz", full), ("_receipts.json.gz", rcs)):
                        fname = "%d%s" % (it["number"], suffix)
                        got = hashlib.sha256(canon(res).encode()).hexdigest()
                        files.append((fname, res, "content" if o["result_sha256"].get(fname) == got else "anchored"))
                    row["status"] = "content" if all(x[2] == "content" for x in files) else "anchored"
                    for fname, res, level in files:          # a file already there counts only if it is ours (33.5)
                        path = os.path.join(out, name, fname)
                        if not force and os.path.exists(path) and _existing_result(path) != o["result_sha256"].get(fname):
                            row["status"] = "existing_file_differs:%s" % fname
                    for fname, res, level in files:          # below content (members no fingerprint covers): not written
                        row.setdefault("files", {})[fname] = {"level": level, "written": row["status"] == "content" and
                                                              _gz_write(os.path.join(out, name, fname), _envelope(res), force)}
                except Rejected as e:
                    row["status"] = "refused:%s" % e
                except SHAPE_ERRORS as e:
                    row["status"] = "refused:reply_shape:%s:%s" % (type(e).__name__, e)
                report["results"].append(row)
                log("%s %s/%d" % (row["status"], name, it["number"]))
        else:
            calls, levels, row = [], [], {"oracle": name, "file": o["file"]}
            try:
                for it in o["items"]:
                    L = Ledger(rpc, net, it["ledger_index"], it["ledger_hash"])
                    j = rpc.call(net, "ledger", {"ledger_index": it["ledger_index"]}, xrpl=True)
                    jl = j.get("ledger") if isinstance(j.get("ledger"), dict) else {}
                    if j.get("ledger_hash") != it["ledger_hash"] or jl.get("ledger_hash") != it["ledger_hash"] \
                            or (jl.get("transaction_hash") or "").upper() != L.header["transaction_hash"].hex().upper() \
                            or (jl.get("account_hash") or "").upper() != L.header["account_hash"].hex().upper() \
                            or (jl.get("parent_hash") or "").upper() != L.header["parent_hash"].hex().upper() \
                            or jl.get("ledger_index") not in (it["ledger_index"], str(it["ledger_index"])):
                        raise Rejected("ledger_json_reply_mismatch:%d" % it["ledger_index"])
                    calls.append({"method": "ledger", "params": {"ledger_index": it["ledger_index"], "transactions": True,
                                                                 "expand": True, "binary": True}, "result": L.result})
                    calls.append({"method": "ledger", "params": {"ledger_index": it["ledger_index"]}, "result": j})
                    got = hashlib.sha256(canon({"binary": L.result, "json": j}).encode()).hexdigest()     # both replies whole
                    levels.append("content" if o["result_sha256"].get(str(it["ledger_index"])) == got else "anchored")
                doc = {"server": host_of(rpc.url(net)), "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "rebuilt_by": "tools/rebuild_corpus.py --oracle (SPEC 33.8)", "calls": calls}
                path = os.path.join(out, name, o["file"])
                row["status"] = "content" if levels and all(x == "content" for x in levels) else "anchored"
                if row["status"] == "content" and not force and os.path.exists(path) \
                        and not _existing_xrpl_is_ours(path, o):
                    row["status"] = "existing_file_differs:%s" % o["file"]
                if row["status"] != "content" or (os.path.exists(path) and not force):
                    row["written"] = False                   # below content: not written (33.8)
                else:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path + ".tmp", "w") as fh:
                        json.dump(doc, fh)
                    os.replace(path + ".tmp", path)
                    row["written"] = True
                row["ledgers"] = {"content": levels.count("content"), "anchored": levels.count("anchored")}
            except Rejected as e:
                row["status"] = "refused:%s" % e
            except SHAPE_ERRORS as e:
                row["status"] = "refused:reply_shape:%s:%s" % (type(e).__name__, e)
            report["results"].append(row)
            log("%s %s/%s" % (row["status"], name, o["file"]))
    agg = {}
    for r in report["results"]:
        k = r["status"].split(":")[0]
        agg[k] = agg.get(k, 0) + 1
    report["summary"] = agg
    report["rpc_calls"] = rpc.calls
    return report


def parse_rpcs(items):
    urls = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit("--rpc wants CAIP2=URL, got a value without '='")
        k, v = it.split("=", 1)
        urls[k] = v
    return urls


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], add_help=True)
    ap.add_argument("--rpc", action="append", help="CAIP-2 network = JSON-RPC URL (repeatable; or APC_RPC_<CAIP2> in the "
                    "environment). You are responsible for the terms of service of the endpoint you choose; a node of "
                    "your own is recommended. URLs are never logged.")
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--out", default=os.path.join(ROOT, "bundles"))
    ap.add_argument("--only", help="comma-separated set names or bundle files (set/name.json)")
    ap.add_argument("--sample", type=int, help="the first N bundles of each set, by file name")
    ap.add_argument("--rate", type=float, default=1.0, help="requests per second per host (default 1; do not exceed what "
                    "your endpoint's terms allow)")
    ap.add_argument("--cache", help="directory for the raw replies (gzip), resumable")
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--force", action="store_true", help="overwrite existing files under --out")
    ap.add_argument("--check-manifest", action="store_true", help="only read the list (closed) and exit")
    ap.add_argument("--oracle", help="comma-separated oracle/ directories of the list to rebuild (33.8) instead of bundles")
    ap.add_argument("--out-oracle", default=os.path.join(ROOT, "oracle"), help="where --oracle writes (default oracle/)")
    a = ap.parse_args(argv[1:])
    try:
        man = load_manifest(a.manifest)
    except ManifestRefusal as e:
        print("refused: manifest:", e)
        return 3
    if a.check_manifest:
        print("manifest %s: %d sets, %d bundles" % (man["format"], len(man["sets"]), len(man["bundles"])))
        return 0
    urls = parse_rpcs(a.rpc)
    if not urls and not any(k.startswith("APC_RPC_") for k in os.environ):
        print("no endpoint: pass --rpc CAIP2=URL or set APC_RPC_<CAIP2> (see --help; you are responsible for its terms "
              "of service)", file=sys.stderr)
        return 64
    if not (0 < a.rate <= 5):                 # NaN and negatives too: a pace that never waits is not a pace
        print("refused: --rate must be above 0 and at most 5 requests per second per host", file=sys.stderr)
        return 64
    if a.sample is not None and a.sample < 1:
        print("refused: --sample must be at least 1", file=sys.stderr)
        return 64
    for k, u in list(urls.items()) + [(k[8:], v) for k, v in os.environ.items() if k.startswith("APC_RPC_")]:
        sp = urllib.parse.urlsplit(u)
        if sp.scheme not in ("http", "https") or not sp.hostname:
            print("refused: the endpoint for %s is not an http(s) URL with a host (the URL is not printed)" % k, file=sys.stderr)
            return 64
    rpc = Rpc(urls, rate=a.rate, cache=a.cache)
    only = set(a.only.split(",")) if a.only is not None else None
    if only is not None:
        unknown = sorted(x for x in only if x not in man["sets"] and x not in {e["file"] for e in man["bundles"]})
        if unknown or not only:
            print("refused: --only names nothing the list holds: %s" % (unknown or ["(empty)"]), file=sys.stderr)
            return 64
    if a.oracle is not None:
        names = set(a.oracle.split(","))
        unknown = sorted(x for x in names if x not in man["oracle"])
        if unknown or not names:
            print("refused: --oracle names nothing the list holds: %s" % (unknown or ["(empty)"]), file=sys.stderr)
            return 64
        local = sorted(x for x in names if man["oracle"][x]["kind"] == "local_only")
        if local:
            print("refused: --oracle names directories the list declares local_only (not rebuilt): %s" % local, file=sys.stderr)
            return 64
        if only or a.sample is not None:
            print("refused: --oracle rebuilds raw directories; --only and --sample select bundles", file=sys.stderr)
            return 64
        rep = rebuild_oracle(man, rpc, a.out_oracle, only=names, force=a.force)
        if a.report:
            with open(a.report, "w") as fh:
                json.dump(rep, fh, indent=1, sort_keys=True)
        print(json.dumps(rep["summary"], sort_keys=True), "rpc calls", rep["rpc_calls"])
        return 1 if any(r["status"].startswith(("refused", "anchored", "existing_file_differs")) for r in rep["results"]) else 0
    rep = rebuild(man, rpc, a.out, only=only, sample=a.sample, force=a.force)
    if a.report:
        with open(a.report, "w") as fh:
            json.dump(rep, fh, indent=1, sort_keys=True)
    print(json.dumps(rep["summary"], sort_keys=True), "rpc calls", rep["rpc_calls"])
    return 1 if rep["summary"]["below_declared_level"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
