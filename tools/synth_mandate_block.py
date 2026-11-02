"""SPEC 31.8: a synthetic Base block carrying one x402 payment bound to an AP2 mandate pack, so that MP6 and MP7 run on a
block header that B1 verifies. The block is on NO chain (canonical checks O1-O4 do not apply). Keys are made per call
(payer, payee, settler); the pack's RFC 3161 anchor comes from a local TSA (tests/test_mandate.LocalTSA). Nothing is sent.
Used by tests/test_mandate.py (TestSyntheticBlock); as a script it writes the four cases of the test and their reports.

  env -u PYTHONPATH python3 tools/synth_mandate_block.py OUT_DIR"""
import copy
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, W)
sys.path.insert(0, os.path.join(W, "tools"))
os.environ.setdefault("APC_AP2EV", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "ap2-evidence-pack"))
import apc_block as ab  # noqa: E402
import apc_mandate as am  # noqa: E402
import apc_verify as av  # noqa: E402
import inclusion  # noqa: E402
from lib.secp256k1 import GX, GY, _mul, sign  # noqa: E402
from tests import test_mandate as T  # noqa: E402

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
REAL = os.path.join(W, "bundles/real_v03/v002_b004_direct_envelope_reconstructed.json")


def addr(k):
    x, y = _mul(k, (GX, GY))
    return "0x" + av.keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()


def sig65(dg, k):
    r, s, rec = sign(dg, k, secrets.randbelow(av.SECP_N - 1) + 1)
    return r, s, rec


def word(x):
    return x.to_bytes(32, "big") if isinstance(x, int) else bytes(12) + bytes.fromhex(x[2:]) if len(x) == 42 \
        else bytes.fromhex(x[2:]).rjust(32, b"\0")


def bloom(logs):
    b = bytearray(256)
    for lg in logs:
        for item in [bytes.fromhex(lg["address"][2:])] + [bytes.fromhex(t[2:]) for t in lg["topics"]]:
            h = av.keccak256(item)
            for i in (0, 2, 4):
                bit = ((h[i] << 8) | h[i + 1]) & 2047
                b[255 - bit // 8] |= 1 << (bit % 8)
    return "0x" + b.hex()


def make(out, btime, restriction_max, tsa, label, exp=None):
    """exp: the open mandate's exp (default btime + 3600, so that only the case that asks for it is expired)."""
    payer, payee = (secrets.randbelow(av.SECP_N - 1) + 1 for _ in range(2))
    settler = secrets.randbelow(av.SECP_N - 1) + 1
    cents = 1250
    narrow = [{"type": "payment.amount_range", "currency": "USD", "min": 0, "max": restriction_max}] + T.BASE[1:]
    exp = btime + 3600 if exp is None else exp
    o = T.issue(T.open_content(T.BASE, exp=exp))
    hop, chain = T.present(o, T.closed_content(cents))
    r = T.restriction(o, narrow, exp=exp)      # R's exp not later than O's (section 11.4 of ap2-evidence-pack)
    pack = T.pack([("open_payment", o), ("closed_payment", hop), ("restriction", r)],
                  {"open_payment": T.USER.jwk, "closed_payment": T.AGENT.jwk, "restriction": T.USER.jwk}, tsa)
    pp = T.payload(chain, cents * 10000, to=addr(payee))
    # re-sign the authorization with the testnet payer (T.payload signs with anvil key 0)
    au = pp["payload"]["authorization"]
    au["from"] = addr(payer)
    au["validBefore"] = str(btime + 3600)
    msg = dict(au, value=int(au["value"]), validAfter=0, validBefore=int(au["validBefore"]))
    dg = av.signing_digest({"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC},
                           "TransferWithAuthorization", av.TYPES, msg, av.DOMAIN4)
    rr, ss, rec = sig65(dg, payer)
    if ss > av.SECP_N // 2:          # low-s, as the token requires
        ss, rec = av.SECP_N - ss, rec ^ 1
    pp["payload"]["signature"] = "0x" + (rr.to_bytes(32, "big") + ss.to_bytes(32, "big") + bytes([27 + rec])).hex()
    # the settlement transaction: transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s)
    data = bytes.fromhex("e3ee160e") + b"".join(word(x) for x in (
        au["from"], au["to"], int(au["value"]), 0, int(au["validBefore"]), au["nonce"], 27 + rec, rr, ss))
    tx = {"type": "0x2", "chainId": "0x2105", "nonce": "0x0", "gas": "0x186a0", "maxFeePerGas": "0x3b9aca00",
          "maxPriorityFeePerGas": "0x1", "to": USDC, "value": "0x0", "accessList": [], "input": "0x" + data.hex()}
    body = [ab._int_bytes(0x2105), ab._int_bytes(0), ab._int_bytes(1), ab._int_bytes(0x3b9aca00), ab._int_bytes(0x186a0),
            bytes.fromhex(USDC[2:]), b"", data, []]
    th = av.keccak256(b"\x02" + ab.rlp(body))
    tr, ts_, trec = sig65(th, settler)
    if ts_ > av.SECP_N // 2:
        ts_, trec = av.SECP_N - ts_, trec ^ 1
    tx.update(r=hex(tr), s=hex(ts_), yParity=hex(trec), v=hex(trec))
    tx["hash"] = "0x" + av.keccak256(inclusion.encode_tx(tx)).hex()
    tx["from"] = addr(settler)
    logs = [{"address": USDC, "topics": ["0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5",
                                         "0x" + word(au["from"]).hex(), au["nonce"]], "data": "0x"},
            {"address": USDC, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                                         "0x" + word(au["from"]).hex(), "0x" + word(au["to"]).hex()],
             "data": "0x" + word(int(au["value"])).hex()}]
    rc = {"type": "0x2", "status": "0x1", "cumulativeGasUsed": "0xea60", "logsBloom": bloom(logs), "logs": logs}
    with open(REAL) as fh:
        real = json.load(fh)
    hdr = copy.deepcopy(real["inclusion"]["block_header"])
    hdr.update(number="0x3200000", timestamp=hex(btime), gasUsed="0xea60", logsBloom=bloom(logs),
               transactionsRoot="0x" + ab.trie_root([(ab.rlp(ab._int_bytes(0)), inclusion.encode_tx(tx))]).hex(),
               receiptsRoot="0x" + ab.trie_root([(ab.rlp(ab._int_bytes(0)), ab.encode_receipt(rc, 0))]).hex())
    hdr.pop("hash")
    hdr["hash"] = ab.header_hash(hdr)
    block = dict(hdr, transactions=[tx])
    inc = inclusion.build(block, [rc], tx["hash"])
    meta = {"blockHash": hdr["hash"], "blockNumber": hdr["number"], "blockTimestamp": hdr["timestamp"],
            "transactionHash": tx["hash"], "transactionIndex": "0x0", "removed": False}
    tx.update(blockHash=hdr["hash"], blockNumber=hdr["number"], transactionIndex="0x0", blockTimestamp=hdr["timestamp"],
              gasPrice="0x2")
    la, lt = (dict(lg, logIndex=hex(i), **meta) for i, lg in enumerate(logs))
    doc = {"bundle_version": "apc-0.3", "payment_payload": pp,
           "settlement": {"success": True, "transaction": tx["hash"], "network": "eip155:8453", "payer": au["from"]},
           "chain_tx": {"network": "eip155:8453", "tx": tx, "log_authorization_used": la, "log_transfer": lt},
           "inclusion": inc, "mandate": {"profile": am.PROFILE, "pack": pack, "chain": chain}}
    path = os.path.join(out, label + ".json")
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    return path


def main(out):
    os.makedirs(out, exist_ok=True)
    d = tempfile.mkdtemp(prefix="apc-tsa-")
    tsa = T.LocalTSA(d)
    now = int(time.time())
    cases = [("within_restriction_after_anchor", now + 600, 2000),
             ("outside_restriction_after_anchor", now + 600, 1000),
             ("outside_restriction_before_anchor", now - 600, 1000),
             ("after_mandate_expiry", now + 600, 2000)]
    res = {}
    for label, bt, mx in cases:
        p = make(out, bt, mx, tsa, label, exp=bt - 100 if label == "after_mandate_expiry" else None)
        rep = json.loads(subprocess.run([sys.executable, os.path.join(W, "apc_verify.py"), p, "--ap2-tsa-cert", tsa.crt],
                                        capture_output=True, text=True, env=dict(os.environ)).stdout)
        c = rep.get("checks", {})
        res[label] = {"verdict": rep.get("verdict"), "block_bound": rep.get("block_bound"),
                      **{k: c.get(k) for k in ("L2.sig", "C1", "C2", "B1", "B2", "B3", "B4") + am.CHECKS},
                      "existed_before": [e.get("existed_before_payment") for e in rep.get("mandate", {}).get("restrictions", [])],
                      "failed": rep.get("failed"), "not_evaluated": rep.get("not_evaluated")}
    with open(tsa.crt) as fh, open(os.path.join(out, "tsa.crt"), "w") as g:
        g.write(fh.read())
    json.dump(res, open(os.path.join(out, "RESULTS.json"), "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
