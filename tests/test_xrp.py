"""SPEC 0.16 (section 26): x402 `exact` on the XRP Ledger, bundle apc-0.16. Real data: 12 validated mainnet ledgers
(oracle/xrpl_20261026, xrplcluster.com, 2026-10-26) with every transaction and metadata in binary: the codec, the
signatures, the SHAMap roots and the ledger hashes are checked against the server's own JSON values, and
bundles/xrp_real_20261026 holds their 99 Payments with requirements rebuilt from each one. Synthetic payments
(test keys) exercise every rule in both directions. Positive control: apc_verify 0.8.0 (5cbe7c7) refuses apc-0.16."""
import copy
import glob
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("*", oracle=("xrpl_20261026",))   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402
import apc_xrpl as xr  # noqa: E402
from lib.secp256k1 import GX, GY, _mul, sign  # noqa: E402

OLD = "5cbe7c7"
ORACLE = os.path.join(ROOT, "oracle", "xrpl_20261026", "mainnet_ledgers.json")
PATHS = sorted(glob.glob(os.path.join(ROOT, "bundles", "xrp_real_20261026", "*.json")))


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d, cp=None):
    try:
        return av.verify_bundle(copy.deepcopy(d), l1_checkpoint=cp)
    except av.Refusal as e:
        return {"refused": str(e)}


def oracle():
    with open(ORACLE) as fh:
        d = json.load(fh)
    hashes = {c["params"]["ledger_index"]: c["result"]["ledger_hash"] for c in d["calls"]
              if "binary" not in c["params"] and isinstance(c["params"]["ledger_index"], int)}
    return d, hashes


# ------------------------------------------------------------------ a small encoder for the synthetic payments
def _fid(name):
    f = xr.BY_NAME[name]
    t, n = f["code"], f["nth"]
    if t < 16 and n < 16:
        return bytes([t << 4 | n])
    if t >= 16 and n < 16:
        return bytes([n, t])
    if t < 16:
        return bytes([t << 4, n])
    return bytes([0, t, n])


def _vl(b):
    assert len(b) <= 192
    return bytes([len(b)]) + b


def _iou(value, cur, iss):
    m, e = value
    while m and m < 10 ** 15:
        m, e = m * 10, e - 1
    while m >= 10 ** 16:
        m, e = m // 10, e + 1
    v = (1 << 63) | (1 << 62) | ((e + 97) << 54) | m
    return v.to_bytes(8, "big") + cur + iss


def _enc(name, v):
    f = xr.BY_NAME[name]
    t = f["type"]
    if t in xr.FIXED:
        return _fid(name) + (v if isinstance(v, bytes) else v.to_bytes(xr.FIXED[t], "big"))
    if t == "Amount":
        return _fid(name) + ((0x4000000000000000 | v[1]).to_bytes(8, "big") if v[0] == "xrp" else _iou(*v[1:]))
    if t in ("Blob", "AccountID"):
        return _fid(name) + _vl(v)
    if t == "STArray":                      # Memos: [Memo{MemoData}]
        return _fid(name) + b"".join(_fid("Memo") + _enc("MemoData", x) + b"\xe1" for x in v) + b"\xf1"
    raise ValueError(t)


def build(fields, key):
    """fields: {name: value} without SigningPubKey/TxnSignature; key: ('secp', int) or ('ed', seed)."""
    if key[0] == "secp":
        x, y = _mul(key[1], (GX, GY))
        pk = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    else:
        pk = b"\xed" + sol.ed25519_public(key[1])
    fields = dict(fields, SigningPubKey=pk)
    order = sorted(fields, key=lambda n: (xr.BY_NAME[n]["code"], xr.BY_NAME[n]["nth"]))
    data = b"STX\0" + b"".join(_enc(n, fields[n]) for n in order)
    if key[0] == "secp":
        dg = xr.sha512half(data)
        r, s, _ = sign(dg, key[1], int.from_bytes(hashlib.sha256(dg + b"k").digest(), "big") % xr.SECP_N)

        def der(i):
            b = i.to_bytes((i.bit_length() + 8) // 8, "big")
            return b"\x02" + bytes([len(b)]) + b
        body = der(r) + der(s)
        sig = b"\x30" + bytes([len(body)]) + body
    else:
        sig = sol.ed25519_sign(key[1], data)
    fields["TxnSignature"] = sig
    order = sorted(fields, key=lambda n: (xr.BY_NAME[n]["code"], xr.BY_NAME[n]["nth"]))
    return b"".join(_enc(n, fields[n]) for n in order), xr.key_account(pk)


SECP = ("secp", 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
ED = ("ed", hashlib.sha256(b"apc xrp test seed").digest())
DEST = hashlib.sha256(b"dest").digest()[:20]
ISSUER = hashlib.sha256(b"issuer").digest()[:20]
USD = bytes(12) + b"USD" + bytes(5)


def payment(key=SECP, **over):
    acct = build({}, key)[1]
    f = {"TransactionType": xr.TX_TYPES["Payment"].to_bytes(2, "big"), "Flags": 0, "Sequence": 7,
         "LastLedgerSequence": 1000, "Amount": ("xrp", 1000000), "Fee": ("xrp", 12), "Account": acct, "Destination": DEST}
    for k, v in over.items():
        if v is None:
            f.pop(k, None)
        else:
            f[k] = v
    return build(f, key)


def bundle(blob, extra=None, asset="XRP", amount="1000000", network="xrpl:0", ledger=999, meta_over=None):
    meta = {"TransactionIndex": 0, "TransactionResult": 0}
    meta.update(meta_over or {})
    order = sorted(meta, key=lambda n: (xr.BY_NAME[n]["code"], xr.BY_NAME[n]["nth"]))
    mb = b"".join(_enc(n, meta[n]) for n in order)
    tid = xr.tx_id(blob)
    try:
        acct = xr.decode(blob)[1]["Account"]
    except (xr.XrplError, KeyError):
        acct = bytes(20)                    # an undecodable blob: the verifier must refuse it, not this helper
    return {"bundle_version": "apc-0.16",
            "payment_payload": {"x402Version": 2, "accepted": {
                "scheme": "exact", "network": network, "asset": asset, "payTo": xr.classic_address(DEST),
                "amount": amount, "maxTimeoutSeconds": 600, "extra": dict({"areFeesSponsored": False}, **(extra or {}))},
                "payload": {"signedTxBlob": blob.hex().upper()}},
            "settlement": {"success": True, "transaction": tid, "network": network,
                           "payer": xr.classic_address(acct)},
            "chain_tx": {"tx_blob": blob.hex().upper(), "meta": mb.hex().upper(), "ledger_index": ledger}}


class Oracle(unittest.TestCase):
    def test_ripemd160_and_addresses(self):
        self.assertEqual(xr.ripemd160(b"").hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")     # RIPEMD-160 paper
        self.assertEqual(xr.ripemd160(b"abc").hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        self.assertEqual(xr.ripemd160(b"a" * 1000).hex(), hashlib.new("ripemd160", b"a" * 1000).hexdigest()
                         if "ripemd160" in hashlib.algorithms_available else xr.ripemd160(b"a" * 1000).hex())
        self.assertEqual(xr.classic_address(bytes(20)), "rrrrrrrrrrrrrrrrrrrrrhoLvTp")     # ACCOUNT_ZERO (XRPL docs)
        with self.assertRaises(xr.XrplError):
            xr.account_id("rrrrrrrrrrrrrrrrrrrrrhoLvTq")

    def test_real_ledgers(self):
        d, hashes = oracle()
        c = Counter()
        for call in d["calls"]:
            if not call["params"].get("binary"):
                continue
            L = call["result"]["ledger"]
            h = xr.ledger_header(bytes.fromhex(L["ledger_data"]))
            self.assertEqual(h["hash"], hashes[call["params"]["ledger_index"]])
            leaves = {}
            for t in L["transactions"]:
                tb, mb = bytes.fromhex(t["tx_blob"]), bytes.fromhex(t["meta"])
                k, lf = xr.tx_leaf(tb, mb)
                leaves[k] = lf
                f, v = xr.decode(tb)
                xr.decode(mb)
                self.assertEqual(b"".join(tb[a:b] for *_, a, b, _t in f), tb)
                c[xr.verify_signature(tb, f, v)] += 1
            self.assertEqual(xr.shamap_root(leaves), h["transaction_hash"])
            c["ledgers"] += 1
        self.assertEqual(dict(c), {"ledgers": 12, "verified": 758, "not_evaluated:multisigned": 37})

    def test_real_bundles(self):
        d, hashes = oracle()
        c, reasons = Counter(), Counter()
        for p in PATHS:
            b = load(p)
            cp = hashes[b["chain_tx"]["ledger_index"]] if "inclusion" in b else None
            r = run(b, cp)
            c[r["verdict"]] += 1
            reasons.update(k for k in r["failed"])
            if "inclusion" in b:
                self.assertTrue(r["block_bound"], p)
                self.assertEqual(run(b, "00" * 32)["checks"]["I2"], "failed:ledger_hash_not_the_trusted_one")
        self.assertEqual(dict(c), {"chain_verified": 21, "chain_failed": 78})
        self.assertEqual(reasons["R9"], 37)            # Memos: x402 forbids them, ordinary payments carry them

    def test_positive_control_old_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(["git", "-C", ROOT, "archive", OLD], capture_output=True)
            if r.returncode != 0 or not r.stdout:
                raise unittest.SkipTest("needs the git history of ROOT")
            subprocess.run(["tar", "-x", "-C", tmp], input=r.stdout, check=True)
            out = subprocess.run([sys.executable, "-B", os.path.join(tmp, "apc_verify.py"), PATHS[0]],
                                 capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=""))
            self.assertEqual(out.returncode, 3, out.stdout + out.stderr)


class Rules(unittest.TestCase):
    def test_good_secp_and_ed25519(self):
        for key in (SECP, ED):
            r = run(bundle(payment(key)[0]))
            self.assertEqual(r["verdict"], "chain_verified", r)

    def test_each_rule_fails(self):
        inv = hashlib.sha256(b"INV-1").digest()
        cases = [
            (payment(TransactionType=xr.TX_TYPES["TrustSet"].to_bytes(2, "big")), {}, "R3"),
            (payment(Destination=ISSUER), {}, "R4"),
            (payment(DestinationTag=5), {"destinationTag": 6}, "R4"),
            (payment(NetworkID=1), {}, "R5"),
            (payment(Amount=("xrp", 999999)), {}, "R6"),
            (payment(SendMax=("xrp", 2000000)), {}, "R6"),
            (payment(Flags=0x00020000), {}, "R6"),
            (payment(LastLedgerSequence=None), {}, "R7"),
            (payment(TicketSequence=3), {}, "R7"),
            (payment(Sequence=7, TicketSequence=3), {"assetTransferMethod": "ticketSequence"}, "R7"),
            (payment(), {"invoiceId": "INV-1"}, "R8"),
            (payment(InvoiceID=hashlib.sha256(b"INV-2").digest()), {"invoiceId": "INV-1"}, "R8"),
            (payment(Delegate=ISSUER), {}, "R9"),
            (payment(Memos=[b"hi"]), {}, "R9"),
        ]
        for (blob, _), ex, want in cases:
            r = run(bundle(blob, ex))
            self.assertTrue(r["checks"][want].startswith("failed"), (want, r["checks"]))
        self.assertEqual(run(bundle(payment(InvoiceID=inv)[0], {"invoiceId": "INV-1"}))["verdict"], "chain_verified")
        self.assertEqual(run(bundle(payment(DestinationTag=6)[0], {"destinationTag": 6}))["verdict"], "chain_verified")
        self.assertEqual(run(bundle(payment(Sequence=0, TicketSequence=3)[0], {"assetTransferMethod": "ticketSequence"}))["verdict"],
                         "chain_verified")
        self.assertEqual(run(bundle(payment(NetworkID=2000)[0], network="xrpl:2000"))["verdict"], "chain_verified")
        self.assertTrue(run(bundle(payment()[0], network="xrpl:2000"))["checks"]["R5"].startswith("failed"))

    def test_signature_and_blob(self):
        blob, _ = payment()
        b = bytearray(blob)
        i = blob.index(_fid("TxnSignature")) + 10
        b[i] ^= 1
        r = run(bundle(bytes(b)))
        self.assertTrue(r.get("checks", {}).get("R10", "failed").startswith("failed") or "refused" in r, r)
        self.assertIn("refused", run(bundle(blob + b"\x00")))          # trailing byte
        f, _ = xr.decode(blob)
        a, b2 = f[0], f[1]                                              # swap two fields: not canonical
        swapped = blob[b2[2]:b2[3]] + blob[a[2]:a[3]] + blob[b2[3]:]
        self.assertIn("refused", run(bundle(swapped)))
        # a high-s twin of a valid secp256k1 signature is refused (fully canonical)
        sig = xr.decode(blob)[1]["TxnSignature"]
        r_, s_ = xr._der(sig)
        hs = xr.SECP_N - s_
        body = b"\x02" + bytes([len(r_.to_bytes((r_.bit_length() + 8) // 8, "big"))]) + r_.to_bytes((r_.bit_length() + 8) // 8, "big")
        body += b"\x02" + bytes([len(hs.to_bytes((hs.bit_length() + 8) // 8, "big"))]) + hs.to_bytes((hs.bit_length() + 8) // 8, "big")
        f2, v2 = xr.decode(blob)
        v2 = dict(v2, TxnSignature=b"\x30" + bytes([len(body)]) + body)
        self.assertEqual(xr.verify_signature(blob, f2, v2), "failed:signature_not_fully_canonical")

    def test_more_breaks(self):
        blob = payment(Account=ISSUER)[0]                     # signed by a key that is not the account's master key
        self.assertEqual(run(bundle(blob))["checks"]["R10"], "not_evaluated:regular_key_needs_account_state")
        blob = payment(ED)[0]
        b = bytearray(blob)
        b[blob.index(_fid("TxnSignature")) + 5] ^= 1
        self.assertEqual(run(bundle(bytes(b)))["checks"]["R10"], "failed:ed25519_signature")
        # non-minimal DER: r with a needless leading 00
        blob = payment()[0]
        f, v = xr.decode(blob)
        r_, s_ = xr._der(v["TxnSignature"])
        rb, sb = r_.to_bytes((r_.bit_length() + 8) // 8, "big"), s_.to_bytes((s_.bit_length() + 8) // 8, "big")
        body = b"\x02" + bytes([len(rb) + 1]) + b"\x00" + rb + b"\x02" + bytes([len(sb)]) + sb
        self.assertEqual(xr.verify_signature(blob, f, dict(v, TxnSignature=b"\x30" + bytes([len(body)]) + body)),
                         "failed:signature_not_strict_der")
        # a partial payment without a stored DeliveredAmount: the amount delivered is unknown
        b = bundle(payment(Flags=0x00020000)[0])
        self.assertEqual(run(b)["checks"]["C3"], "failed:no_delivered_amount")
        # accepted not offered
        b = bundle(payment()[0])
        b["payment_required"] = {"x402Version": 2, "resource": {"url": "https://x.example/r"},
                                 "accepts": [dict(copy.deepcopy(b["payment_payload"]["accepted"]), amount="2")]}
        self.assertEqual(run(b)["checks"]["K4"], "failed:accepted_not_offered")
        # an issued amount whose mantissa is not normalized is not a canonical amount
        raw = ((1 << 63) | (1 << 62) | ((-1 + 97) << 54) | 105).to_bytes(8, "big") + USD + ISSUER
        good = payment(Amount=("iou", (105, -1), USD, ISSUER), SendMax=("iou", (106, -1), USD, ISSUER))[0]
        i = good.index(_fid("Amount")) + 1
        bad = good[:i] + raw + good[i + 48:]
        self.assertEqual(run(bundle(bad, {"issuer": xr.classic_address(ISSUER)}, "USD", "10.5"))["checks"]["R6"],
                         "failed:amount_mismatch")

    def test_single_transaction_ledger(self):
        blob = payment()[0]
        mb = bytes.fromhex(bundle(blob)["chain_tx"]["meta"])
        k, lf = xr.tx_leaf(blob, mb)
        kids = [bytes(32)] * 16
        kids[k[0] >> 4] = lf                                    # the root stays an inner node over one leaf
        self.assertEqual(xr.shamap_root({k: lf}), xr.sha512half(b"MIN\0" + b"".join(kids)))

    def test_iou(self):
        val = (105, -1)                                                 # 10.5
        good = payment(Amount=("iou", val, USD, ISSUER), SendMax=("iou", (106, -1), USD, ISSUER))[0]
        ex = {"issuer": xr.classic_address(ISSUER)}
        meta = {"DeliveredAmount": ("iou", val, USD, ISSUER)}
        self.assertEqual(run(bundle(good, ex, "USD", "10.5", meta_over=meta))["verdict"], "chain_verified")
        self.assertEqual(run(bundle(good, ex, "USD", "10.50", meta_over=meta))["verdict"], "chain_verified")   # exact decimal
        self.assertTrue(run(bundle(good, ex, "USD", "10.51", meta_over=meta))["checks"]["R6"].startswith("failed"))
        low = payment(Amount=("iou", val, USD, ISSUER), SendMax=("iou", (104, -1), USD, ISSUER))[0]
        self.assertEqual(run(bundle(low, ex, "USD", "10.5", meta_over=meta))["checks"]["R6"], "failed:send_max_policy")
        nosm = payment(Amount=("iou", val, USD, ISSUER))[0]
        self.assertEqual(run(bundle(nosm, ex, "USD", "10.5", meta_over=meta))["checks"]["R6"], "failed:send_max_policy")
        short = {"DeliveredAmount": ("iou", (104, -1), USD, ISSUER)}
        self.assertEqual(run(bundle(good, ex, "USD", "10.5", meta_over=short))["checks"]["C3"], "failed:delivered_amount_mismatch")

    def test_chain(self):
        blob = payment()[0]
        self.assertEqual(run(bundle(blob, meta_over={"TransactionResult": 104}))["checks"]["C2"],
                         "failed:transaction_result_tecUNFUNDED_PAYMENT")
        self.assertEqual(run(bundle(blob, ledger=1001))["checks"]["C4"], "failed:validated_after_last_ledger_sequence")
        b = bundle(blob)
        b["chain_tx"]["tx_blob"] = payment(Sequence=8)[0].hex()
        self.assertEqual(run(b)["checks"]["C1"], "failed:settled_blob_not_the_payload")
        b = bundle(blob)
        b["settlement"]["transaction"] = "AB" * 32
        self.assertEqual(run(b)["checks"]["T1"], "failed:settlement_names_another_transaction")
        b = bundle(blob, meta_over={"DeliveredAmount": ("xrp", 1)})
        self.assertEqual(run(b)["checks"]["C3"], "failed:delivered_amount_mismatch")

    def test_inclusion(self):
        blob = payment()[0]
        b = bundle(blob)
        mb = bytes.fromhex(b["chain_tx"]["meta"])
        other = payment(Sequence=9)[0]
        k1, l1 = xr.tx_leaf(blob, mb)
        k2, l2 = xr.tx_leaf(other, mb)
        root = xr.shamap_root({k1: l1, k2: l2})
        hdr = (999).to_bytes(4, "big") + bytes(8) + bytes(32) + root + bytes(32) + bytes(8) + b"\x0a\x00"
        b["inclusion"] = {"ledger_data": hdr.hex(), "transactions": [{"tx_blob": blob.hex(), "meta": mb.hex()},
                                                                       {"tx_blob": other.hex(), "meta": mb.hex()}]}
        h = xr.ledger_header(hdr)["hash"]
        r = run(b, h)
        self.assertEqual((r["checks"]["I1"], r["checks"]["I2"], r["block_bound"]), ("verified", "verified", True))
        b2 = copy.deepcopy(b)
        b2["inclusion"]["transactions"] = b2["inclusion"]["transactions"][1:]
        self.assertEqual(run(b2, h)["checks"]["I1"], "failed:transaction_not_in_the_set")
        b2 = copy.deepcopy(b)
        b2["inclusion"]["ledger_data"] = ((998).to_bytes(4, "big") + hdr[4:]).hex()
        self.assertEqual(run(b2, h)["checks"]["I1"], "failed:ledger_index_not_chain_tx")
        b2 = copy.deepcopy(b)
        b2["inclusion"]["transactions"].append({"tx_blob": payment(Sequence=10)[0].hex(), "meta": mb.hex()})
        self.assertEqual(run(b2, h)["checks"]["I1"], "failed:set_not_the_ledger_transaction_hash")
        self.assertEqual(run(b)["checks"]["I2"], "not_evaluated:absent:no_trusted_ledger_hash")


class Generative(unittest.TestCase):
    """Any input = verdict or refusal, never a traceback; every member set is closed (extra included)."""
    def test_unknown_members_and_bytes(self):
        rnd = random.Random(26)
        b = bundle(payment()[0])
        b["payment_required"] = {"x402Version": 2, "resource": {"url": "https://x.example/r"},
                                 "accepts": [copy.deepcopy(b["payment_payload"]["accepted"])]}
        self.assertEqual(run(b)["verdict"], "chain_verified")

        def walk(d, path=()):
            if isinstance(d, dict):
                yield path, d
                for k, v in d.items():
                    yield from walk(v, path + (k,))
            elif isinstance(d, list):
                for i, v in enumerate(d):
                    yield from walk(v, path + (i,))
        for path, _ in list(walk(b)):
            if "accepts" in path:
                continue
            d = copy.deepcopy(b)
            o = d
            for k in path:
                o = o[k]
            o["unknownMember"] = 1
            if path == ("payment_required",):
                # SPEC 32.14 (0.21.5): a member of the PaymentRequired x402 does not define is ignored and named in notes
                r = run(d)
                self.assertNotIn("refused", r, path)
                self.assertTrue(any("(SPEC 32.14): ['unknownMember']" in n for n in r["notes"]))
                continue
            self.assertIn("refused", run(d), path)
        leaves = []
        for path, o in walk(b):
            leaves += [path + (k,) for k, v in o.items() if not isinstance(v, (dict, list))]
        values = [None, True, 0, -1, 1.5, "", "x", "ZZ", [], {}, "00" * 32, 2 ** 300, "9" * 5000, "\ud800", "xrpl:0", "XRP"]
        for _ in range(800):
            d = copy.deepcopy(b)
            path = rnd.choice(leaves)
            o = d
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = rnd.choice(values)
            run(d)
        blob = bytes.fromhex(b["payment_payload"]["payload"]["signedTxBlob"])
        for _ in range(800):
            x = bytearray(blob)
            for _ in range(rnd.randint(1, 3)):
                op = rnd.random()
                i = rnd.randrange(len(x))
                if op < 0.5:
                    x[i] = rnd.randrange(256)
                elif op < 0.75:
                    del x[i]
                else:
                    x.insert(i, rnd.randrange(256))
            d = copy.deepcopy(b)
            d["payment_payload"]["payload"]["signedTxBlob"] = bytes(x).hex()
            d["chain_tx"]["tx_blob"] = bytes(x).hex()
            r = run(d)
            self.assertTrue("refused" in r or r["verdict"] in ("chain_failed", "chain_incomplete", "chain_verified"))
            if "verdict" in r and bytes(x) != blob:
                self.assertNotEqual(r["verdict"], "chain_verified", bytes(x).hex())


if __name__ == "__main__":
    unittest.main()
