"""Raw replies for the Permit2 bundles whose payer had code (EIP-7702) at the settlement block: the block and its
receipts (for `inclusion`), the parent header, and eth_getProof of the payer (with the Kernel validation slot) and of
the delegate at the parent block and at the block (for `payer_code.proof`, SPEC 0.10 section 12.5). Read-only RPC.

  BASE_RPC=<blocks> PROOF_RPC=<archive proofs> python3 tools/fetch_permit2_state.py RAW_DIR TXS.json.gz NAME [NAME ...]

Every raw reply is kept gzip-compressed with its sha256 in RAW_DIR/SHA256SUMS (as tools/make_bundles_v03.py)."""
import gzip
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from make_bundles_v03 import fetch_block, rpc  # noqa: E402
from make_bundles_permit2 import build, load  # noqa: E402

KERNEL_SLOT = "0x7bcaa2ced2a71450ed5a9a1b4848e8e5206dbc3f06011e595f7f55428cc6f84f"


def keep(raw_dir, name, url, method, params):
    path = os.path.join(raw_dir, name + ".json.gz")
    if os.path.exists(path):
        return
    raw, _ = rpc(url, method, params)
    with open(path + ".tmp", "wb") as f0, gzip.GzipFile(filename="", fileobj=f0, mode="wb", mtime=0) as fh:
        fh.write(raw)
    with open(path + ".tmp", "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    with open(os.path.join(raw_dir, "SHA256SUMS"), "a") as fh:
        fh.write("%s  %s\n" % (digest, os.path.basename(path)))
    os.replace(path + ".tmp", path)


def main(argv):
    url, purl = os.environ["BASE_RPC"], os.environ["PROOF_RPC"]
    raw_dir = argv[1]
    os.makedirs(raw_dir, exist_ok=True)
    bundles = dict(build(load(argv[2]))[0])
    for name in argv[3:]:
        tx = bundles[name]["chain_tx"]["tx"]
        n = int(tx["blockNumber"], 16)
        payer = bundles[name]["payment_payload"]["payload"]["permit2Authorization"]["from"]
        fetch_block(url, raw_dir, tx["blockNumber"])
        keep(raw_dir, "%d_header" % (n - 1), url, "eth_getBlockByNumber", [hex(n - 1), False])
        code = rpc(url, "eth_getCode", [payer, hex(n)])[1]
        delegate = "0x" + code[8:48] if code.startswith("0xef0100") and len(code) == 48 else None
        for b in (n - 1, n):
            keep(raw_dir, "%d_proof_%s" % (b, payer), purl, "eth_getProof", [payer, [KERNEL_SLOT], hex(b)])
            if delegate:
                keep(raw_dir, "%d_proof_%s" % (b, delegate), purl, "eth_getProof", [delegate, [], hex(b)])
        print("fetched", name, n, payer, delegate, flush=True)


if __name__ == "__main__":
    main(sys.argv)
