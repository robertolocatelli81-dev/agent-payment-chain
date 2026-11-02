"""SPEC 0.5 (section 7): Solana, bundle apc-0.5. Real data: bundles/real_svm (45 facilitator transactions rebuilt, one
payment made for this work on mainnet). Each rule is also broken one way at a time on the real bundles; S4 and the
lookup tables, absent from the real set, on transactions built and signed here."""
import base64
import copy
import glob
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402

DIR = os.path.join(ROOT, "bundles", "real_svm")
FILES = sorted(p for p in glob.glob(os.path.join(DIR, "*.json")) if "MANIFEST" not in p)
MINE = os.path.join(DIR, "m001_mainnet_payment_20261024.json")
OTHER = os.path.join(DIR, "s000_cascade.json")       # a facilitator bundle (FILES[0] is the mainnet payment: "m" < "s")
FEE_PAYER_AUTHORITY = {"s039_openx402.json", "s045_relai.json"}


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def run(d):
    try:
        return av.verify_bundle(d)
    except av.Unsupported:
        return {"verdict": "unsupported"}
    except av.Refusal:
        return {"verdict": "refused"}


def tx_of(d, where="payload"):
    b64 = d["payment_payload"]["payload"]["transaction"] if where == "payload" else d["chain_tx"]["transaction"]
    return bytearray(base64.b64decode(b64))


def put(d, raw, where="payload"):
    s = base64.b64encode(bytes(raw)).decode()
    if where == "payload":
        d["payment_payload"]["payload"]["transaction"] = s
    else:
        d["chain_tx"]["transaction"] = s


# ------------------------------------------------------------------ Ed25519 signing (RFC 8032 5.1.6), for built cases
def _enc(p):
    zi = pow(p[2], sol.P - 2, sol.P)
    x, y = p[0] * zi % sol.P, p[1] * zi % sol.P
    return (y | (x & 1) << 255).to_bytes(32, "little")


class Key:
    def __init__(self, n):
        h = hashlib.sha512(hashlib.sha256(b"apc test key %d" % n).digest()).digest()
        a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
        self.a, self.prefix = a, h[32:]
        self.pub = _enc(sol._mul(a, sol.G))
        self.addr = sol.b58encode(self.pub)

    def sign(self, m):
        r = int.from_bytes(hashlib.sha512(self.prefix + m).digest(), "little") % sol.L
        rb = _enc(sol._mul(r, sol.G))
        k = int.from_bytes(hashlib.sha512(rb + self.pub + m).digest(), "little") % sol.L
        return rb + ((r + k * self.a) % sol.L).to_bytes(32, "little")


def message(header, keys, ixs, version="legacy", lookups=()):
    """keys: 32-byte strings; ixs: (program index, [account indices], data)."""
    m = bytes([0x80]) if version == 0 else b""
    m += bytes(header) + bytes([len(keys)]) + b"".join(keys) + bytes(32)
    m += bytes([len(ixs)]) + b"".join(bytes([p, len(a)]) + bytes(a) + bytes([len(d)]) + d for p, a, d in ixs)
    if version == 0:
        m += bytes([len(lookups)]) + b"".join(t + bytes([len(w)]) + bytes(w) + bytes([len(r)]) + bytes(r)
                                              for t, w, r in lookups)
    return m


def built(nsigners=2, version="legacy", lookups=(), extra_accounts=0, amount=1000, sign_fee_payer=False, tc_mint=None,
          memos=1, fee_payer_program=False, inner=False, chain=False, loaded=None):
    """A Path-1 payment: fee payer (account 0, unsigned), client authority, extra signers, source, destination ATA,
    mint, token program, ComputeBudget, Memo. tc_mint: the TransferChecked names another mint account; inner: the
    transfer is made by an unknown program (a wallet) and appears only in chain_tx's inner instructions; chain: add the
    confirmed transaction (fee payer signed), its balances, and the settlement reply."""
    fp, client, merchant, mint = Key(1), Key(2), Key(3), Key(4)
    signers = [fp, client] + [Key(10 + i) for i in range(nsigners - 2)]
    dest = sol.ata(merchant.addr, mint.addr, sol.SPL_TOKEN)
    src = sol.ata(client.addr, mint.addr, sol.SPL_TOKEN)
    ro = [mint.pub, sol.b58decode(sol.SPL_TOKEN, 32), sol.b58decode(sol.COMPUTE_BUDGET, 32),
          sol.b58decode(sol.MEMO_PROGRAM, 32)] + ([tc_mint.pub] if tc_mint else []) + ([Key(20).pub] if inner else [])
    keys = [x.pub for x in signers] + [sol.b58decode(src, 32), sol.b58decode(dest, 32)] \
        + [bytes([200 + i]) * 32 for i in range(extra_accounts)] + ro
    k = {x: keys.index(x) for x in keys}
    i_src, i_dst, i_mint = nsigners, nsigners + 1, k[mint.pub]
    i_tok, i_cb, i_memo = k[sol.b58decode(sol.SPL_TOKEN, 32)], k[sol.b58decode(sol.COMPUTE_BUDGET, 32)], \
        k[sol.b58decode(sol.MEMO_PROGRAM, 32)]
    tc_accounts = [i_src, k[tc_mint.pub] if tc_mint else i_mint, i_dst, 1]
    tc_data = b"\x0c" + amount.to_bytes(8, "little") + b"\x06"
    pay = (k[Key(20).pub], tc_accounts + [i_tok], b"\x01") if inner else (i_tok, tc_accounts, tc_data)
    ixs = [(i_cb, [], b"\x02" + (40000).to_bytes(4, "little")), (i_cb, [], b"\x03" + (1).to_bytes(8, "little")), pay] \
        + [(i_memo, [], b"0123456789abcdef0123456789abcdef")] * memos + ([(0, [], b"")] if fee_payer_program else [])
    m = message((nsigners, 0, len(ro)), keys, ixs, version, lookups)
    sigs = [fp.sign(m) if sign_fee_payer else bytes(64)] + [x.sign(m) for x in signers[1:]]
    raw = bytes([nsigners]) + b"".join(sigs) + m
    d = {"bundle_version": "apc-0.5",
         "payment_payload": {"x402Version": 2, "accepted": {
             "scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "amount": str(amount),
             "asset": mint.addr, "payTo": merchant.addr, "maxTimeoutSeconds": 60, "extra": {"feePayer": fp.addr}},
             "payload": {"transaction": base64.b64encode(raw).decode()}}}
    if chain:
        full = bytes([nsigners]) + fp.sign(m) + b"".join(sigs[1:]) + m
        bal = [{"accountIndex": i_dst, "mint": mint.addr, "uiTokenAmount": {"amount": a, "decimals": 6}}
               for a in ("0", str(amount))]
        d["chain_tx"] = {"slot": 1, "blockTime": 1, "transaction": base64.b64encode(full).decode(), "meta": {
            "err": None, "fee": 10001, "preTokenBalances": [bal[0]], "postTokenBalances": [bal[1]],
            "innerInstructions": [{"index": 2, "instructions": [{"programIdIndex": i_tok, "accounts": tc_accounts,
                                                                  "data": sol.b58encode(tc_data), "stackHeight": 2}]}]
            if inner else [],
            "loadedAddresses": loaded or {"writable": [], "readonly": []}}}
        d["settlement"] = {"success": True, "transaction": sol.b58encode(full[1:65]),
                           "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}
    return d


class Real(unittest.TestCase):
    def test_counts_and_verdicts(self):
        self.assertEqual(len(FILES), 46)
        man = load(os.path.join(DIR, "MANIFEST.json"))
        self.assertEqual((len(man["bundles"]), len(man["skipped"])), (46, 7))
        for p in FILES:
            r = run(load(p))
            if os.path.basename(p) in FEE_PAYER_AUTHORITY:
                self.assertEqual((r["verdict"], r["failed"]), ("chain_failed", ["S3"]), p)
                self.assertEqual(r["checks"]["S3"], "failed:fee_payer_in_an_instruction", p)
                self.assertEqual(r["payer"], r["fee_payer"], p)       # the fee payer is the transfer's authority
            else:
                self.assertEqual(r["verdict"], "chain_verified", p)
                self.assertEqual([r["checks"][k] for k in ("S1", "S2", "S3", "S4", "S5", "T1", "C1", "C2", "C3")],
                                 ["verified"] * 9, p)
                self.assertNotEqual(r["payer"], r["fee_payer"], p)
            self.assertIs(r["block_bound"], False)
            self.assertEqual(r["transaction_id"], load(p)["settlement"]["transaction"], p)

    def test_mainnet_payment_of_this_work(self):
        d = load(MINE)
        r = run(d)
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertEqual(r["transaction_id"], "5DyEtgNkz2djjfKbvkWpyCQMRyPd5b4RqsCnSx49SKEmxuepuoxemoGtaLLy4pyUxKxyQokExn8B91hS2QnT4nn4")
        self.assertEqual(d["chain_tx"]["slot"], 460849863)
        self.assertEqual(d["payment_payload"]["accepted"]["extra"]["memo"][:16], "apc mainnet test")
        # the bound computed from the payload equals the fee the chain charged (meta.fee, declared): 2 x 5000 + 1
        self.assertEqual(d["chain_tx"]["meta"]["fee"], 10001)
        self.assertTrue(any(n.startswith("S6: fee bound 10001 lamports") for n in r["notes"]), r["notes"])

    def test_without_chain_tx(self):
        for p in FILES[:10]:
            d = load(p)
            del d["chain_tx"]
            r = run(d)
            self.assertEqual(r["absent"], ["C1", "C2", "C3", "K4"], p)
            self.assertIsNone(r["transaction_id"], p)


class Broken(unittest.TestCase):
    """one rule broken at a time on the real bundles (the payment of this work, and a facilitator bundle)"""
    def cases(self):
        return [load(MINE), load(OTHER)]

    def test_client_signature_bit(self):
        for d in self.cases():
            raw = tx_of(d)
            raw[1 + 64 + 10] ^= 1                                    # the second signature (the client's)
            put(d, raw)
            self.assertEqual(run(d)["checks"]["S1"], "failed:signer_1_signature_invalid")

    def test_message_bit_every_region(self):
        d0 = load(MINE)
        raw0 = tx_of(d0)
        start = 1 + 64 * raw0[0]
        for i in range(start, len(raw0), 7):
            d = copy.deepcopy(d0)
            raw = bytearray(raw0)
            raw[i] ^= 0x01
            put(d, raw)
            r = run(d)
            self.assertTrue(r["verdict"] == "refused" or r["checks"]["S1"] != "verified", i)

    def test_fee_payer_slot(self):
        for d in self.cases():
            raw = tx_of(d)
            raw[5] ^= 1                                              # no longer zeros, not a signature
            put(d, raw)
            self.assertEqual(run(d)["checks"]["S1"], "failed:signer_0_signature_invalid")
            d2 = copy.deepcopy(d)
            raw2 = tx_of(d2)
            raw2[1:65] = tx_of(d2, "chain")[1:65]                    # the fee payer's real signature: accepted
            put(d2, raw2)
            self.assertEqual(run(d2)["checks"]["S1"], "verified")

    def test_fee_payer_not_account_0(self):
        for d in self.cases():
            d["payment_payload"]["accepted"]["extra"]["feePayer"] = Key(9).addr
            self.assertEqual(run(d)["checks"]["S1"], "failed:fee_payer_not_account_0")

    def test_amount_asset_payto(self):
        for d0 in self.cases():
            a = d0["payment_payload"]["accepted"]
            for k, v in (("amount", str(int(a["amount"]) + 1)), ("asset", Key(5).addr), ("payTo", Key(6).addr)):
                d = copy.deepcopy(d0)
                d["payment_payload"]["accepted"][k] = v
                r = run(d)
                self.assertEqual(r["checks"]["S2"], "failed:no_matching_transfer", k)
                self.assertEqual(r["checks"]["C3"], "not_evaluated:no_single_matching_transfer", k)
                self.assertIsNone(r["payer"])
            d = copy.deepcopy(d0)
            d["payment_payload"]["accepted"]["amount"] = str(int(a["amount"]) - 1)    # overpayment: tolerated
            r = run(d)
            self.assertEqual(r["checks"]["S2"], "verified")
            self.assertEqual(len([n for n in r["notes"] if "more than the" in n]), 1)

    def test_transfer_inside_an_unknown_program(self):
        d = load(os.path.join(DIR, "s039_openx402.json"))        # top level holds the ATA and System programs
        d["payment_payload"]["accepted"]["amount"] = str(10 ** 18)
        self.assertEqual(run(d)["checks"]["S2"], "failed:no_matching_transfer")
        del d["chain_tx"]
        self.assertEqual(run(d)["checks"]["S2"], "not_evaluated:transfer_may_be_inside_a_program_call")
        e = load(MINE)                                           # only known programs: a plain failure
        del e["chain_tx"]
        e["payment_payload"]["accepted"]["amount"] = str(10 ** 18)
        self.assertEqual(run(e)["checks"]["S2"], "failed:no_matching_transfer")

    def test_two_matching_transfers(self):
        d = load(os.path.join(DIR, "s039_openx402.json"))
        raw = tx_of(d)
        t = sol.parse_tx(bytes(raw))
        tcs = [ix for ix in t["instructions"] if sol.transfer_checked(t, ix)]
        self.assertEqual(len(tcs), 2)
        # both transfers matched: pay to the second's destination owner too is impossible offline, so make the
        # requirement the smaller amount and the destination the same ATA by pointing accepted at the first one
        r = run(d)
        self.assertEqual(r["checks"]["S2"], "verified")              # the two go to different accounts
        built_d = built()
        raw = tx_of(built_d)
        m = sol.parse_tx(bytes(raw))
        self.assertEqual(run(built_d)["checks"]["S2"], "verified")
        ix = m["instructions"][2]
        dup = bytes([ix["program"], len(ix["accounts"])]) + bytes(ix["accounts"]) + bytes([len(ix["data"])]) + ix["data"]
        msg = bytearray(m["message"])
        n_ix_at = len(msg) - sum(2 + len(x["accounts"]) + 1 + len(x["data"]) for x in m["instructions"]) - 1
        msg[n_ix_at] += 1
        msg = bytes(msg) + dup
        sigs = [bytes(64), Key(2).sign(msg)]
        put(built_d, bytes([2]) + b"".join(sigs) + msg)
        r = run(built_d)
        self.assertEqual(r["checks"]["S1"], "verified")
        self.assertEqual(r["checks"]["S2"], "failed:more_than_one_matching_transfer")

    def test_memo(self):
        d = load(MINE)
        d["payment_payload"]["accepted"]["extra"]["memo"] += "x"
        self.assertEqual(run(d)["checks"]["S5"], "failed:memo_mismatch")
        e = load(OTHER)
        r = run(e)
        if not any(n.startswith("S5:") for n in r["notes"]):
            e["payment_payload"]["accepted"]["extra"]["memo"] = "x"
            self.assertIn(run(e)["checks"]["S5"], ("failed:memo_mismatch",))
        n = 0
        for p in FILES:                                          # a transaction with no Memo: noted, and a required
            f = load(p)                                          # memo then fails with count 0
            if any(x.startswith("S5: no Memo") for x in run(f)["notes"]):
                f["payment_payload"]["accepted"]["extra"]["memo"] = "x"
                self.assertEqual(run(f)["checks"]["S5"], "failed:memo_count_0", p)
                n += 1
        self.assertGreater(n, 5)

    def test_settlement(self):
        d0 = load(MINE)
        d = copy.deepcopy(d0)
        d["settlement"]["transaction"] = load(OTHER)["settlement"]["transaction"]
        self.assertEqual(run(d)["checks"]["C2"], "failed:settlement_names_another_transaction")
        d = copy.deepcopy(d0)
        d["settlement"]["success"] = False
        self.assertEqual(run(d)["checks"]["T1"], "failed:settlement_not_successful")
        d["settlement"]["errorReason"] = "settlement_pending"
        r = run(d)
        self.assertEqual((r["checks"]["T1"], r["verdict"]), ("not_evaluated:settlement_pending", "chain_incomplete"))
        d = copy.deepcopy(d0)
        d["settlement"]["network"] = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
        self.assertEqual(run(d)["checks"]["T1"], "failed:settlement_network_not_accepted")
        d = copy.deepcopy(d0)
        d["settlement"]["transaction"] = ""
        self.assertEqual(run(d)["checks"]["T1"], "failed:settlement_without_transaction")
        for bad in ("0x12", "1" * 88, d0["settlement"]["transaction"][:-10], d0["settlement"]["transaction"] + "11", 5):
            d = copy.deepcopy(d0)
            d["settlement"]["transaction"] = bad
            self.assertEqual(run(d)["verdict"], "refused", bad)

    def test_failed_on_chain(self):
        d = load(MINE)
        d["chain_tx"]["meta"]["err"] = {"InstructionError": [2, {"Custom": 1}]}
        r = run(d)
        self.assertEqual(r["checks"]["C2"], "failed:transaction_error")
        self.assertEqual(r["checks"]["T1"], "failed:settlement_reported_success_but_failed")
        d["settlement"]["transaction"] = load(OTHER)["settlement"]["transaction"]   # a reply about another tx
        r = run(d)
        self.assertEqual(r["checks"]["C2"], "failed:settlement_names_another_transaction")
        self.assertEqual(r["checks"]["T1"], "verified")

    def test_chain_tx_binding(self):
        d = load(MINE)
        d["chain_tx"]["transaction"] = load(OTHER)["chain_tx"]["transaction"]
        self.assertEqual(run(d)["checks"]["C1"], "failed:chain_tx_not_the_payload")
        d = load(MINE)
        raw = tx_of(d, "chain")
        raw[3] ^= 1                                                  # the fee payer's signature in the confirmed tx
        put(d, raw, "chain")
        self.assertEqual(run(d)["checks"]["C1"], "failed:fee_payer_signature_invalid")
        d = load(MINE)
        raw = tx_of(d, "chain")
        raw[70] ^= 1                                                 # the client's signature in the confirmed tx
        put(d, raw, "chain")
        self.assertEqual(run(d)["checks"]["C1"], "failed:chain_tx_not_the_payload")

    def test_balances(self):
        d0 = load(MINE)
        raw = sol.parse_tx(bytes(tx_of(d0)))
        dest = raw["keys"].index(sol.ata(d0["payment_payload"]["accepted"]["payTo"],
                                         d0["payment_payload"]["accepted"]["asset"], sol.SPL_TOKEN))
        d = copy.deepcopy(d0)
        b = next(x for x in d["chain_tx"]["meta"]["postTokenBalances"] if x["accountIndex"] == dest)
        b["uiTokenAmount"]["amount"] = str(int(b["uiTokenAmount"]["amount"]) - 1)
        self.assertEqual(run(d)["checks"]["C3"], "failed:balance_delta_short")
        d = copy.deepcopy(d0)
        d["chain_tx"]["meta"]["postTokenBalances"] = [x for x in d["chain_tx"]["meta"]["postTokenBalances"]
                                                      if x["accountIndex"] != dest]
        self.assertEqual(run(d)["checks"]["C3"], "failed:balance_delta_short")
        d = copy.deepcopy(d0)
        b = next(x for x in d["chain_tx"]["meta"]["postTokenBalances"] if x["accountIndex"] == dest)
        b["mint"] = Key(7).addr
        self.assertEqual(run(d)["checks"]["C3"], "failed:balance_delta_short")


class Built(unittest.TestCase):
    def test_control(self):
        r = run(built())
        self.assertEqual(r["verdict"], "chain_verified", r)

    def test_three_required_signers(self):
        r = run(built(nsigners=3))
        self.assertEqual(r["checks"]["S1"], "verified")
        self.assertEqual(r["checks"]["S4"], "failed:more_than_two_required_signers")

    def test_lookup_tables(self):
        d = built(version=0, lookups=[(bytes([7]) * 32, [0], [1])])
        r = run(d)
        self.assertEqual(r["checks"]["S1"], "verified")
        self.assertEqual(r["checks"]["S3"], "not_evaluated:lookup_tables_not_resolved")
        self.assertEqual(r["verdict"], "chain_incomplete")
        self.assertEqual(run(built(version=0))["verdict"], "chain_verified")

    def test_fee_payer_signed_payload(self):
        self.assertEqual(run(built(sign_fee_payer=True))["checks"]["S1"], "verified")

    def test_fee_payer_as_authority(self):
        d = built()
        raw = tx_of(d)
        t = sol.parse_tx(bytes(raw))
        msg = bytearray(t["message"])
        ix = t["instructions"][2]
        tail = bytes([ix["program"], 4]) + bytes(ix["accounts"])
        at = bytes(msg).index(tail) + 2 + 3                           # the authority index of the TransferChecked
        msg[at] = 0
        put(d, bytes([2]) + bytes(64) + Key(2).sign(bytes(msg)) + bytes(msg))
        r = run(d)
        self.assertEqual(r["checks"]["S3"], "failed:fee_payer_in_an_instruction")


class BuiltChain(unittest.TestCase):
    """the cases the real set does not hold, on transactions built and signed here"""
    def test_control_with_chain_tx(self):
        r = run(built(chain=True))
        self.assertEqual(r["verdict"], "chain_verified", r)
        self.assertEqual([r["checks"][k] for k in ("S1", "S2", "S3", "C1", "C2", "C3", "T1")], ["verified"] * 7)

    def test_transfer_in_the_cpi_trace(self):
        r = run(built(inner=True, chain=True))
        self.assertEqual((r["checks"]["S2"], r["verdict"]), ("verified", "chain_verified"))
        self.assertEqual(r["payer"], Key(2).addr)
        d = built(inner=True)
        self.assertEqual(run(d)["checks"]["S2"], "not_evaluated:transfer_may_be_inside_a_program_call")
        d = built(inner=True, chain=True)
        d["chain_tx"]["meta"]["innerInstructions"] = []                 # the trace shown, without the transfer
        self.assertEqual(run(d)["checks"]["S2"], "failed:no_matching_transfer")

    def test_other_mint_account(self):
        r = run(built(tc_mint=Key(8)))
        self.assertEqual(r["checks"]["S2"], "failed:no_matching_transfer")
        self.assertEqual(r["checks"]["S1"], "verified")

    def test_fee_payer_invoked_as_a_program(self):
        r = run(built(fee_payer_program=True))
        self.assertEqual((r["checks"]["S1"], r["checks"]["S3"]), ("verified", "failed:fee_payer_in_an_instruction"))

    def test_two_memos(self):
        d = built(memos=2)
        d["payment_payload"]["accepted"]["extra"]["memo"] = "0123456789abcdef0123456789abcdef"
        self.assertEqual(run(d)["checks"]["S5"], "failed:memo_count_2")
        d = built()
        d["payment_payload"]["accepted"]["extra"]["memo"] = "0123456789abcdef0123456789abcdef"
        self.assertEqual(run(d)["checks"]["S5"], "verified")

    def test_chain_tx_with_another_message_signed_by_the_fee_payer(self):
        d = built(chain=True)
        raw = bytearray(base64.b64decode(d["chain_tx"]["transaction"]))
        at = 1 + 64 * 2
        msg = bytearray(raw[at:])
        i = bytes(msg).index(b"\x03" + (1).to_bytes(8, "little"))      # the compute unit price
        msg[i + 1] = 2
        raw[1:65] = Key(1).sign(bytes(msg))                             # the client's signature kept as it was
        put(d, bytes(raw[:at]) + bytes(msg), "chain")
        self.assertEqual(run(d)["checks"]["C1"], "failed:chain_tx_not_the_payload")

    def test_lookup_tables_resolved(self):
        table = (bytes([7]) * 32, [0], [1])
        ok = {"writable": [Key(30).addr], "readonly": [Key(31).addr]}
        self.assertEqual(run(built(version=0, lookups=[table], chain=True, loaded=ok))["checks"]["S3"], "verified")
        bad = {"writable": [Key(1).addr], "readonly": [Key(31).addr]}
        self.assertEqual(run(built(version=0, lookups=[table], chain=True, loaded=bad))["checks"]["S3"],
                         "failed:fee_payer_in_a_lookup_table")
        short = {"writable": [], "readonly": [Key(31).addr]}
        self.assertEqual(run(built(version=0, lookups=[table], chain=True, loaded=short))["verdict"], "refused")
        d = load(MINE)                                                  # loaded addresses for a tx with no tables
        d["chain_tx"]["meta"]["loadedAddresses"]["writable"] = [Key(30).addr]
        self.assertEqual(run(d)["verdict"], "refused")

    def test_more_signers_than_keys(self):
        m = message((3, 0, 0), [Key(1).pub, Key(2).pub], [])
        d = built()
        put(d, bytes([3]) + bytes(64) * 3 + m)
        self.assertEqual(run(d)["verdict"], "refused")

    def test_balance_delta_with_a_prior_balance(self):
        n = 0
        for p in FILES:
            d = load(p)
            r = run(d)
            if r["verdict"] != "chain_verified":
                continue
            m = d["chain_tx"]["meta"]
            pre = {b["accountIndex"]: b for b in m["preTokenBalances"]}
            for b in m["postTokenBalances"]:
                if b["accountIndex"] in pre and int(pre[b["accountIndex"]]["uiTokenAmount"]["amount"]) > 0 \
                        and int(b["uiTokenAmount"]["amount"]) > int(pre[b["accountIndex"]]["uiTokenAmount"]["amount"]):
                    e = copy.deepcopy(d)
                    for c in e["chain_tx"]["meta"]["postTokenBalances"]:
                        if c["accountIndex"] == b["accountIndex"]:
                            c["uiTokenAmount"]["amount"] = pre[b["accountIndex"]]["uiTokenAmount"]["amount"]
                    self.assertEqual(run(e)["checks"]["C3"], "failed:balance_delta_short", p)
                    n += 1
        self.assertGreater(n, 10)

    def test_payment_required(self):
        d0 = load(MINE)
        acc = d0["payment_payload"]["accepted"]
        pr = {"x402Version": 2, "resource": {"url": "https://example.org/r"}, "accepts": [copy.deepcopy(acc)]}
        d = copy.deepcopy(d0)
        d["payment_required"] = copy.deepcopy(pr)
        self.assertEqual(run(d)["checks"]["K4"], "verified")
        d["payment_required"]["accepts"][0]["amount"] = "1"
        self.assertEqual(run(d)["checks"]["K4"], "failed:accepted_not_offered")
        d = copy.deepcopy(d0)
        d["payment_required"] = copy.deepcopy(pr)
        d["payment_payload"]["resource"] = {"url": "https://example.org/other"}
        self.assertEqual(run(d)["checks"]["K4"], "failed:resource_url_mismatch")
        d["payment_payload"]["resource"]["url"] = "https://example.org/r"
        self.assertEqual(run(d)["checks"]["K4"], "verified")
        for bad in ([], [1], {"a": 1}):
            d = copy.deepcopy(d0)
            d["payment_required"] = dict(pr, accepts=bad)
            self.assertEqual(run(d)["verdict"], "refused", bad)
        d = copy.deepcopy(d0)
        d["payment_required"] = dict(pr, accepts=[dict(acc, amount="01")])     # an offered solana entry is parsed
        self.assertEqual(run(d)["verdict"], "refused")


class Batch(unittest.TestCase):
    """apc_batch D1-D3 on Solana bundles: the payment is the transaction message"""
    def test_real_set_consistent(self):
        import apc_batch
        r = apc_batch.check_set([(os.path.basename(p), load(p)) for p in FILES])
        self.assertEqual((r["refused"], r["authorizations"], r["verdict"]), ([], 46, "set_consistent"))

    def test_same_payment_two_deliveries_and_duplicate(self):
        import apc_batch
        a, b = load(MINE), load(MINE)
        a["payment_payload"]["resource"] = {"url": "https://example.org/a"}
        b["payment_payload"]["resource"] = {"url": "https://example.org/b"}
        r = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual((r["verdict"], r["D1"][0]["check"]), ("set_failed", "failed:same_payment_for_two_deliveries"))
        r = apc_batch.check_set([("a", a), ("a2", copy.deepcopy(a))])
        self.assertEqual((r["verdict"], r["D2"][0]["check"]), ("set_consistent", "duplicate_bundle"))

    def test_two_settlements(self):
        import apc_batch
        a, b = load(MINE), load(MINE)
        del a["chain_tx"], b["chain_tx"]
        b["settlement"]["transaction"] = load(OTHER)["settlement"]["transaction"]
        r = apc_batch.check_set([("a", a), ("b", b)])
        self.assertEqual(r["D3"][0]["check"], "failed:same_authorization_two_settlements")
        self.assertEqual(r["D3"][0]["transactions"], sorted([a["settlement"]["transaction"],
                                                             b["settlement"]["transaction"]]))


class Grammar(unittest.TestCase):
    """closed at every level, generative: a new member, a wrong type, every truncation, encodings"""
    def test_unknown_member_everywhere(self):
        d0 = load(MINE)
        paths = []

        def walk(x, p):
            if isinstance(x, dict):
                paths.append(p)
                for k, v in x.items():
                    walk(v, p + [k])
            elif isinstance(x, list):
                for i, v in enumerate(x):
                    walk(v, p + [i])
        walk(d0, [])
        n = 0
        for p in paths:
            if p[:2] == ["payment_payload", "accepted"] and p[2:3] == ["extra"]:
                continue                                              # extra: noted, not refused (as for EVM)
            d = copy.deepcopy(d0)
            o = d
            for k in p:
                o = o[k]
            o["zz_new"] = 1
            self.assertEqual(run(d)["verdict"], "refused", p)
            n += 1
        self.assertGreater(n, 15)
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["extra"]["zz_new"] = 1
        r = run(d)
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertTrue(any("extra.zz_new present" in x for x in r["notes"]))

    def test_wrong_types(self):
        d0 = load(MINE)
        for path in (["payment_payload", "x402Version"], ["payment_payload", "accepted", "amount"],
                     ["payment_payload", "accepted", "payTo"], ["payment_payload", "payload", "transaction"],
                     ["settlement", "success"], ["chain_tx", "slot"], ["chain_tx", "meta", "fee"],
                     ["chain_tx", "meta", "innerInstructions"], ["chain_tx", "meta", "loadedAddresses"],
                     ["payment_payload", "accepted", "maxTimeoutSeconds"], ["payment_payload", "accepted", "extra"]):
            for bad in (None, True, 1.5, "1", [], {}, -1):
                d = copy.deepcopy(d0)
                o = d
                for k in path[:-1]:
                    o = o[k]
                if type(bad) is type(o[path[-1]]):
                    continue                                          # same type: may be a valid value
                o[path[-1]] = bad
                self.assertIn(run(d)["verdict"], ("refused", "unsupported"), (path, bad))

    def test_every_truncation_and_trailing_byte(self):
        d0 = load(MINE)
        raw = bytes(tx_of(d0))
        for n in range(len(raw)):
            d = copy.deepcopy(d0)
            put(d, raw[:n])
            self.assertEqual(run(d)["verdict"], "refused", n)
        d = copy.deepcopy(d0)
        put(d, raw + b"\0")
        self.assertEqual(run(d)["verdict"], "refused")

    def test_encodings(self):
        d0 = load(MINE)
        s = d0["payment_payload"]["payload"]["transaction"]
        for bad in (s + "\n", " " + s, s.rstrip("="), s.replace("+", "-").replace("/", "_") if ("+" in s or "/" in s)
                    else s[:-4] + "!!!!", ""):
            d = copy.deepcopy(d0)
            d["payment_payload"]["payload"]["transaction"] = bad
            self.assertEqual(run(d)["verdict"], "refused", bad[-8:])
        for k, bad in (("amount", "01"), ("amount", str(1 << 64)), ("amount", "-1"), ("payTo", "1" * 31), ("payTo", "1" * 33),
                       ("asset", d0["payment_payload"]["accepted"]["asset"] + "1"), ("network", "solana:abc"),
                       ("network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvd0")):
            d = copy.deepcopy(d0)
            d["payment_payload"]["accepted"][k] = bad
            self.assertEqual(run(d)["verdict"], "refused", (k, bad))
        b64 = "AAE="                                                    # bytes 00 01; "AAF=" decodes alike
        self.assertEqual(base64.b64decode("AAF="), base64.b64decode(b64))
        d = copy.deepcopy(d0)
        body = s.rstrip("=")
        self.assertIn(len(s) - len(body), (1, 2))                       # one or two "=": 2 or 4 unused bits
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        c = alphabet[alphabet.index(body[-1]) | 1]                      # set the lowest unused bit
        self.assertNotEqual(c, body[-1])
        d["payment_payload"]["payload"]["transaction"] = body[:-1] + c + s[len(body):]
        self.assertEqual(base64.b64decode(d["payment_payload"]["payload"]["transaction"]), base64.b64decode(s))
        self.assertEqual(run(d)["verdict"], "refused")
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["network"] += "1"
        self.assertEqual(run(d)["verdict"], "refused")
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["network"] = "eip155:8453"
        self.assertEqual(run(d)["verdict"], "unsupported")
        d = copy.deepcopy(d0)
        d["payment_payload"]["accepted"]["extra"]["memo"] = "é" * 128 + "a"              # 257 bytes
        self.assertEqual(run(d)["verdict"], "refused")
        d["payment_payload"]["accepted"]["extra"]["memo"] = "é" * 128      # 256 bytes: inside the limit
        self.assertNotEqual(run(d)["verdict"], "refused")

    def test_header_rules(self):
        d0 = load(MINE)
        raw = bytes(tx_of(d0))
        at = 1 + 64 * raw[0]                                          # the message header
        for h in ((0, 0, 0), (2, 2, 0), (2, 0, 200), (9, 0, 0)):
            d = copy.deepcopy(d0)
            r = bytearray(raw)
            r[at:at + 3] = bytes(h)
            put(d, r)
            self.assertEqual(run(d)["verdict"], "refused", h)
        d = built()
        m = sol.parse_tx(bytes(tx_of(d)))
        dup = m["message"].replace(sol.b58decode(m["keys"][3], 32), sol.b58decode(m["keys"][2], 32), 1)
        put(d, bytes([2]) + bytes(64) + Key(2).sign(dup) + dup)
        self.assertEqual(run(d)["verdict"], "refused")

    def test_random_bytes_never_crash(self):
        """seeded byte mutations of the payload and of the confirmed transaction: a verdict or a refusal, never an
        exception of another kind (run() lets those through)"""
        import random
        rnd = random.Random(20261024)
        for p in (MINE, OTHER, os.path.join(DIR, "s039_openx402.json")):
            d0 = load(p)
            for where in ("payload", "chain"):
                raw0 = bytes(tx_of(d0, where))
                for _ in range(400):
                    r = bytearray(raw0)
                    for _ in range(rnd.choice((1, 2, 8))):
                        r[rnd.randrange(len(r))] = rnd.randrange(256)
                    d = copy.deepcopy(d0)
                    put(d, r, where)
                    self.assertIn(run(d)["verdict"], ("refused", "chain_failed", "chain_incomplete", "chain_verified"))

    def test_cli(self):
        import subprocess
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), MINE], capture_output=True,
                           text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)["verdict"], "chain_verified")
        bad = load(MINE)
        bad["zz"] = 1
        p = os.path.join(os.environ.get("TMPDIR", "/tmp"), "apc_svm_cli_%d.json" % os.getpid())
        with open(p, "w") as fh:
            json.dump(bad, fh)
        try:
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), p], capture_output=True,
                               text=True, env=env)
        finally:
            os.unlink(p)
        self.assertEqual((r.returncode, json.loads(r.stdout)["verdict"]), (3, "refused"))


if __name__ == "__main__":
    unittest.main()
