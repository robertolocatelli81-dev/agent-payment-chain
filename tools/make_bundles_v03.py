"""apc-0.3 bundles from apc-0.2 bundles: adds the `inclusion` member (block header + Merkle proofs of the transaction
and of its receipt), built by tools/inclusion.py from the block's JSON-RPC replies. Read-only RPC (BASE_RPC).

  BASE_RPC=https://... python3 tools/make_bundles_v03.py OUT_DIR RAW_DIR BUNDLE.json [BUNDLE.json ...]

RAW_DIR keeps every raw reply, gzip-compressed, named by block number, with its sha256 in RAW_DIR/SHA256SUMS: the
proofs can be rebuilt offline from them. A bundle whose block does not recompute (roots, header hash, transaction
encodings) is not written; the reason goes to OUT_DIR/MANIFEST.json.
"""
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_bundles_v03", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import inclusion  # noqa: E402
from apc_block import BlockRefusal  # noqa: E402


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(4):
        req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "apc-tools"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
            d = json.loads(raw)
            if "result" in d and d["result"] is not None:
                return raw, d["result"]
            err = d.get("error")
        except (OSError, ValueError) as e:
            err = repr(e)
        time.sleep(3 * (attempt + 1))
    raise RuntimeError("rpc %s %s: %s" % (method, params[0], err))


def fetch_block(url, raw_dir, number):
    out = {}
    for name, method, params in (("block", "eth_getBlockByNumber", [number, True]),
                                 ("receipts", "eth_getBlockReceipts", [number])):
        path = os.path.join(raw_dir, "%s_%s.json.gz" % (int(number, 16), name))
        if os.path.exists(path):
            with gzip.open(path) as fh:
                out[name] = json.loads(fh.read())["result"]
            continue
        raw, res = rpc(url, method, params)
        with open(path + ".tmp", "wb") as f0, gzip.GzipFile(filename="", fileobj=f0, mode="wb", mtime=0) as fh:
            fh.write(raw)
        with open(path + ".tmp", "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        with open(os.path.join(raw_dir, "SHA256SUMS"), "a") as fh:
            fh.write("%s  %s\n" % (digest, os.path.basename(path)))
        os.replace(path + ".tmp", path)      # a file under its final name always has its SHA256SUMS line
        out[name] = res
    return out["block"], out["receipts"]


def main(argv):
    url = os.environ.get("BASE_RPC")
    if len(argv) < 4 or not url:
        print(__doc__.strip().splitlines()[3].strip(), file=sys.stderr)
        return 64
    out_dir, raw_dir = argv[1], argv[2]
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    manifest = {"made": [], "not_made": []}
    for i, src in enumerate(argv[3:], 1):
        with open(src) as fh:
            doc = json.load(fh)
        tx = doc["chain_tx"]["tx"]
        try:
            block, receipts = fetch_block(url, raw_dir, tx["blockNumber"])
            inc = inclusion.build(block, receipts, tx["hash"])
        except (BlockRefusal, RuntimeError, KeyError) as e:
            manifest["not_made"].append({"source": os.path.basename(src), "tx": tx.get("hash"), "reason": str(e)})
            print("not made", src, e, flush=True)
            continue
        doc["bundle_version"] = "apc-0.3"
        doc["inclusion"] = inc
        name = "v%03d_%s" % (i, os.path.basename(src))
        with open(os.path.join(out_dir, name), "w") as fh:
            json.dump(doc, fh, indent=1)
            fh.write("\n")
        manifest["made"].append({"file": name, "source": src.split("/")[-2] + "/" + os.path.basename(src),
                                 "tx": tx["hash"], "block": tx["blockNumber"]})
        print("made", name, flush=True)
    with open(os.path.join(out_dir, "MANIFEST.json"), "w") as fh:
        json.dump(manifest, fh, indent=1)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
