"""Fetch the payer-wallet reads that a coverage census could not find in the saved replies: for each [payer, block]
in the census output's `wallet_not_read`, the same chain reads as tools/make_bundles_v02.py payer_wallet (eth_getCode,
then for a known proxy the ERC-1967 slot and ownerAtIndex(0)), at the transaction's block. Read-only public JSON-RPC
(BASE_RPC); every raw reply saved.

  BASE_RPC=https://... python3 -B tools/fetch_payer_wallets.py CENSUS_OUT.json LABEL OUT.json      (LABEL * = every entry)
  BASE_RPC=https://... python3 -B tools/fetch_payer_wallets.py --all CENSUS_EIP3009.json OUT.json
      (--all: every distinct [payer, block] of the AuthorizationUsed logs of a census_eip3009.py file, so that a
      census needs no first pass to know which payers it will look up)"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_siglib  # noqa: E402
apc_siglib.guard("tools/fetch_payer_wallets", __name__ == "__main__")  # SPEC 32.12 (f): without the signature library one line, exit 64, no traceback
import tools.fetch_base_eip3009 as fb  # noqa: E402
import make_bundles_v02 as mb  # noqa: E402


def main(argv):
    if argv[1] == "--all":
        c, label, out = json.load(open(argv[2])), "--all " + os.path.basename(argv[2]), argv[3]
        want = sorted({("0x" + lg["topics"][1][-40:], lg["blockNumber"]) for x in c["calls"]
                       if x["method"] == "eth_getLogs" for lg in x["result"]})
        want = [list(p) for p in want]
    else:
        res, label, out = json.load(open(argv[1])), argv[2], argv[3]
        want = [p for e in res["entries"] if label in ("*", e["label"]) for p in e.get("wallet_not_read", [])]
    replies, done = [], set()
    part = out + ".partial"             # one line per finished pair: a stopped run resumes where it was
    if os.path.exists(part):
        with open(part) as fh:
            for line in fh:
                x = json.loads(line)
                done.add(tuple(x["pair"]))
                replies += x["replies"]
    real = fb.rpc
    for frm, blk in want:
        if (frm, blk) in done:
            continue
        mine = []

        def rec(method, params):
            r = real(method, params)
            mine.append(r)
            return r
        fb.rpc = rec
        for attempt in range(6):
            mine.clear()
            mb._WALLET.pop((frm, blk), None)
            try:
                mb.payer_wallet(frm, blk)
                break
            except (OSError, SystemExit) as e:      # rate limit, timeout, RPC error: wait and try again
                if attempt == 5:
                    raise
                print("retry", frm, blk, str(e)[:120], flush=True)
                time.sleep(30 * (attempt + 1))
        replies += mine
        with open(part, "a") as fh:
            fh.write(json.dumps({"pair": [frm, blk], "replies": mine}) + "\n")
    with open(out, "x") as fh:
        json.dump({"rpc": fb.RPC, "label": label, "pairs": want, "replies": replies}, fh, indent=1)
    os.unlink(part)
    print(len(want), "payers,", len(replies), "replies")


if __name__ == "__main__":
    main(sys.argv)
