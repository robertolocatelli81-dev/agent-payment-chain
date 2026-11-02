"""apc-0.10 Permit2 bundles of payers with code, offline, from the raw replies of tools/fetch_permit2_state.py:
`inclusion` (tools/inclusion.py: header, transaction and receipt proofs) and `payer_code` in its two forms of SPEC 0.10
section 12.5: "rpc" (the eth_getCode / eth_getStorageAt replies of oracle/permit2_base_20261026/payer_code_7702.json)
and "proof" (the parent header and the eth_getProof replies of the payer and of its delegate at the parent block and
at the block).

  python3 tools/make_bundles_permit2_state.py OUTDIR NAME [NAME ...]"""
import copy
import gzip
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/make_bundles_permit2_state", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import inclusion  # noqa: E402
from make_bundles_permit2 import build, load  # noqa: E402

RAW = os.path.join(ROOT, "oracle", "permit2_7702_20261026")
RPC = os.path.join(ROOT, "oracle", "permit2_base_20261026", "payer_code_7702.json")
HEADER_KEYS = inclusion.HEADER_KEYS


def _raw(name):
    with gzip.open(os.path.join(RAW, name + ".json.gz")) as fh:
        return json.loads(fh.read())["result"]


def with_state(name, b, form, inc=None):
    """A copy of bundle b (from tools/make_bundles_permit2.py) with inclusion (built, or `inc` when given) and
    payer_code in `form`."""
    b = copy.deepcopy(b)
    tx = b["chain_tx"]["tx"]
    n = int(tx["blockNumber"], 16)
    payer = b["payment_payload"]["payload"]["permit2Authorization"]["from"]
    b["inclusion"] = copy.deepcopy(inc) if inc is not None else inclusion.build(_raw("%d_block" % n),
                                                                                _raw("%d_receipts" % n), tx["hash"])
    if form == "rpc":
        with open(RPC) as fh:
            b["payer_code"] = {"rpc": json.load(fh)["replies"][name]}
        return b
    ph = _raw("%d_header" % (n - 1))
    ends = {}
    for end, blk in (("at_parent", n - 1), ("at_block", n)):
        p = _raw("%d_proof_%s" % (blk, payer))
        e = {"payer": {"accountProof": p["accountProof"], "storageProof": p["storageProof"][0]["proof"]}}
        dpaths = [f for f in os.listdir(RAW) if f.startswith("%d_proof_" % blk) and payer not in f]
        if dpaths:
            e["delegate"] = {"accountProof": _raw(dpaths[0][:-8])["accountProof"]}
        ends[end] = e
    with open(RPC) as fh:
        code = json.load(fh)["replies"][name]["code"]["result"]
    b["payer_code"] = {"proof": {"code": code, "parent_header": {k: ph[k] for k in HEADER_KEYS if k in ph},
                                 "at_parent": ends["at_parent"], "at_block": ends["at_block"]}}
    return b


def main(argv):
    out = dict(build(load(os.path.join(ROOT, "oracle", "permit2_base_20261026", "proxy_txs.json.gz")))[0])
    for name in argv[2:]:
        for form in ("rpc", "proof"):
            with open(os.path.join(argv[1], name.replace(".json", "_%s.json" % form)), "x") as fh:
                json.dump(with_state(name, out[name], form), fh, indent=1)


if __name__ == "__main__":
    main(sys.argv)
