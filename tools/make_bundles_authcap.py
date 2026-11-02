"""Bundles apc-0.15 from real commerce-payments authorizations on Base (tools/fetch_authcapture.py output): the
payment payload is RECONSTRUCTED from the escrow's authorize call found in the transaction input (PaymentInfo, the
collectorData = the client's ERC-3009 signature), as the scheme's facilitator derives it; maxTimeoutSeconds is not
on chain and is written as 0 (unknown, not checked). These are commerce-payments payments, not known to be x402.

  python3 tools/make_bundles_authcap.py ORACLE.json OUTDIR"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_authcap as ac  # noqa: E402
from apc_verify import keccak256  # noqa: E402

SEL = keccak256(("authorize(%s,uint256,address,bytes)" % ac.PI_TUPLE).encode())[:4]


def W(b, i):
    return b[32 * i:32 * i + 32]


def build_one(esc, chain, tx, rc):
    """The apc-0.15 bundle of one transaction (without `provenance`), or None when it is not the scheme's authorize call."""
    inp = bytes.fromhex(tx["input"][2:])
    k = inp.find(SEL)
    if k < 0 or inp.find(SEL, k + 4) >= 0:
        return None                                # one authorize call per bundle
    a = inp[k + 4:]
    pi = [W(a, i) for i in range(12)]
    addr = lambda w: "0x" + w[12:].hex()      # noqa: E731
    num = lambda w: int.from_bytes(w, "big")  # noqa: E731
    amount, col = num(W(a, 12)), addr(W(a, 13))
    off = num(W(a, 14))
    cd = a[off + 32:off + 32 + num(a[off:off + 32])]
    if amount != num(pi[4]) or ac.DEPLOY[esc][1] != col:
        return None                                # partial authorize or another collector: not the scheme's call
    pinfo = [addr(pi[0]), addr(pi[1]), addr(pi[2]), addr(pi[3])] + [num(x) for x in pi[4:10]] + [addr(pi[10]), num(pi[11])]
    nonce = ac.signature_nonce(chain, esc, pinfo)
    acc = {"scheme": "auth-capture", "network": "eip155:%d" % chain, "amount": str(pinfo[4]), "asset": pinfo[3],
           "payTo": pinfo[2], "maxTimeoutSeconds": 0,
           "extra": {"name": "USD Coin", "version": "2", "authCaptureEscrow": esc, "captureAuthorizer": pinfo[0],
                     "paymentFlow": "escrow", "captureDeadline": pinfo[6], "refundDeadline": pinfo[7],
                     "minFeeBps": pinfo[8], "maxFeeBps": pinfo[9], "feeRecipient": pinfo[10],
                     "assetTransferMethod": "eip3009"}}
    return {"bundle_version": "apc-0.15",
            "payment_payload": {"x402Version": 2, "accepted": acc, "payload": {
                "authorization": {"from": pinfo[1], "to": col, "value": str(pinfo[4]), "validAfter": "0",
                                  "validBefore": str(pinfo[5]), "nonce": "0x" + nonce.hex()},
                "signature": "0x" + cd.hex(), "salt": "0x" + pinfo[11].to_bytes(32, "big").hex()}},
            "settlement": {"success": True, "transaction": tx["hash"], "network": "eip155:%d" % chain, "payer": pinfo[1]},
            "chain_tx": {"tx": tx, "receipt": rc}}


def main(argv):
    d = json.load(open(argv[1]))
    out = argv[2]
    os.makedirs(out, exist_ok=True)
    esc = d["escrow"].lower()
    chain = int(next(c for c in d["calls"] if c["method"] == "eth_chainId")["result"], 16)
    txs = {c["result"]["hash"]: c["result"] for c in d["calls"] if c["method"] == "eth_getTransactionByHash"}
    rcs = {c["result"]["transactionHash"]: c["result"] for c in d["calls"] if c["method"] == "eth_getTransactionReceipt"}
    n = 0
    for h, tx in sorted(txs.items()):
        b = build_one(esc, chain, tx, rcs[h])
        if b is None:
            continue
        b["provenance"] = {"chain_tx": {"source": "Base mainnet public JSON-RPC base-rpc.publicnode.com "
                                                  "(tools/fetch_authcapture.py)", "fetched": d["fetched"]},
                           "settlement": {"source": "reconstructed from chain_tx, as the payment payload "
                                                    "(tools/make_bundles_authcap.py)", "fetched": d["fetched"]}}
        with open(os.path.join(out, h[2:14] + ".json"), "w") as fh:
            json.dump(b, fh, indent=1, sort_keys=True)
        n += 1
    print(n, "bundles")


if __name__ == "__main__":
    main(sys.argv)
