"""Tests for apc_verify against bundles built from real Base executions (bundles/real). Every mutation names the check
it must fail; unknown members are tried at every object level of the bundle's own grammar.

  python3 tests/test_apc.py
"""
import copy
import glob
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402

REAL = sorted(glob.glob(os.path.join(ROOT, "bundles", "real", "*.json")))
REAL02 = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02", "b*.json")))


def _one_per_kind():
    """One apc-0.2 bundle per (target, extraction, forwarded): the mutation tests run on these."""
    with open(os.path.join(ROOT, "bundles", "real_v02", "MANIFEST.json")) as fh:
        man = json.load(fh)
    kinds = {}
    for b in man["bundles"]:
        kinds.setdefault((b["target"], b["extraction"], b["forwarded"]), os.path.join(ROOT, "bundles", "real_v02", b["file"]))
    return sorted(kinds.values())


KINDS02 = _one_per_kind()
FORWARDED02 = [p for p in KINDS02 if "log_forward" in json.load(open(p))["chain_tx"]]


def load(p):
    with open(p, "rb") as fh:
        return av.strict_json(fh.read().decode("utf-8"))


def run(doc):
    try:
        return av.verify_bundle(doc)
    except av.Unsupported as e:
        return {"verdict": "unsupported", "reason": str(e)}
    except av.Refusal as e:
        return {"verdict": "refused", "reason": str(e)}


def hexflip(h, pos=-1):
    c = h[pos]
    return h[:pos] + ("1" if c != "1" else "2") + (h[pos + 1:] if pos != -1 else "")


class RealBundles(unittest.TestCase):
    def test_there_are_real_bundles(self):
        self.assertGreaterEqual(len(REAL), 30)

    def test_every_real_bundle_verifies(self):
        for p in REAL:
            r = run(load(p))
            self.assertEqual(r["verdict"], "chain_verified", (p, r))
            for k in ("L2.sig", "K1", "K2", "K3", "K5", "T1", "T2", "C1", "C2"):
                self.assertTrue(r["checks"][k].startswith("verified"), (p, k, r["checks"][k]))


# mutation -> (expected verdict, check that must fail or None for refusal)
def m_value(d):
    a = d["payment_payload"]["payload"]["authorization"]; a["value"] = str(int(a["value"]) + 1)


def m_to(d):
    a = d["payment_payload"]["payload"]["authorization"]; a["to"] = hexflip(a["to"])


def m_from(d):
    a = d["payment_payload"]["payload"]["authorization"]; a["from"] = hexflip(a["from"])


def m_nonce(d):
    a = d["payment_payload"]["payload"]["authorization"]; a["nonce"] = hexflip(a["nonce"])


def m_valid_before(d):
    a = d["payment_payload"]["payload"]["authorization"]; a["validBefore"] = str(int(a["validBefore"]) + 1)


def m_accepted_amount(d):
    acc = d["payment_payload"]["accepted"]; acc["amount"] = str(int(acc["amount"]) + 1)


def m_accepted_payto(d):
    acc = d["payment_payload"]["accepted"]; acc["payTo"] = hexflip(acc["payTo"])


def m_domain_name(d):
    d["payment_payload"]["accepted"]["extra"]["name"] = "USDC"


def m_domain_version(d):
    d["payment_payload"]["accepted"]["extra"]["version"] = "1"


def m_network(d):
    d["payment_payload"]["accepted"]["network"] = "eip155:84532"


def m_asset(d):
    acc = d["payment_payload"]["accepted"]; acc["asset"] = hexflip(acc["asset"])


def m_sig_byte(d):
    p = d["payment_payload"]["payload"]; p["signature"] = p["signature"][:10] + hexflip(p["signature"][10:12], 0) + p["signature"][12:]


def m_sig_v(d):
    p = d["payment_payload"]["payload"]; v = int(p["signature"][-2:], 16); p["signature"] = p["signature"][:-2] + "%02x" % (55 - v)


def m_settle_tx(d):
    d["settlement"]["transaction"] = hexflip(d["settlement"]["transaction"])


def m_settle_fail(d):
    d["settlement"]["success"] = False


def m_settle_payer(d):
    d["settlement"]["payer"] = hexflip(d["settlement"]["payer"])


def m_settle_network(d):
    d["settlement"]["network"] = "eip155:1"


def m_tx_to(d):
    d["chain_tx"]["tx"]["to"] = hexflip(d["chain_tx"]["tx"]["to"])


def m_tx_input_value(d):
    t = d["chain_tx"]["tx"]; i = 10 + 64 * 2 + 63; t["input"] = t["input"][:i] + hexflip(t["input"][i], 0) + t["input"][i + 1:]


def m_tx_input_sig(d):
    t = d["chain_tx"]["tx"]                    # last byte of the signature: s word (vrs) or signature bytes
    i = 10 + 2 * (32 * 9) - 1 if t["input"].startswith("0xe3ee160e") else 10 + 2 * (32 * 8 + 65) - 1
    t["input"] = t["input"][:i] + hexflip(t["input"][i], 0) + t["input"][i + 1:]


def m_tx_address_padding(d):
    t = d["chain_tx"]["tx"]; t["input"] = t["input"][:10] + "01" + t["input"][12:]


def m_log_nonce(d):
    lg = d["chain_tx"]["log_authorization_used"]; lg["topics"][2] = hexflip(lg["topics"][2])


def m_log_from(d):
    lg = d["chain_tx"]["log_authorization_used"]; lg["topics"][1] = hexflip(lg["topics"][1])


def m_log_tx(d):
    lg = d["chain_tx"]["log_authorization_used"]; lg["transactionHash"] = hexflip(lg["transactionHash"])


def m_tx_hash(d):
    d["chain_tx"]["tx"]["hash"] = hexflip(d["chain_tx"]["tx"]["hash"])


def m_chain_network(d):
    d["chain_tx"]["network"] = "eip155:1"


MUTATIONS = [  # name, function, failed checks that MUST appear (all of them)
    ("authorization.value + 1", m_value, ["L2.sig", "K2"]),
    ("authorization.to", m_to, ["L2.sig", "K1"]),
    ("authorization.from", m_from, ["L2.sig"]),
    ("authorization.nonce", m_nonce, ["L2.sig"]),
    ("authorization.validBefore + 1", m_valid_before, ["L2.sig"]),
    ("accepted.amount + 1 (declared only)", m_accepted_amount, ["K2"]),
    ("accepted.payTo (declared only)", m_accepted_payto, ["K1"]),
    ("extra.name USDC (Sepolia's name)", m_domain_name, ["L2.sig", "K3"]),
    ("extra.version 1", m_domain_version, ["L2.sig", "K3"]),
    ("network Base Sepolia", m_network, ["L2.sig", "T2"]),
    ("asset", m_asset, ["L2.sig"]),
    ("signature byte", m_sig_byte, ["L2.sig"]),
    ("signature v flipped", m_sig_v, ["L2.sig"]),
    ("settlement.transaction", m_settle_tx, ["C2"]),
    ("settlement.success false", m_settle_fail, ["T1"]),
    ("settlement.payer", m_settle_payer, ["T2"]),
    ("settlement.network", m_settle_network, ["T2"]),
    ("tx.to", m_tx_to, ["C1"]),
    ("tx input: value word", m_tx_input_value, ["C1"]),
    ("tx input: last byte of the signature", m_tx_input_sig, ["C1"]),
    ("tx input: from word not zero-padded", m_tx_address_padding, ["C1"]),
    ("log nonce", m_log_nonce, ["C2"]),
    ("log authorizer", m_log_from, ["C2"]),
    ("log transactionHash", m_log_tx, ["C2"]),
    ("tx.hash", m_tx_hash, ["C2"]),
    ("chain_tx.network", m_chain_network, ["C1"]),
]


class Mutations(unittest.TestCase):
    def test_each_mutation_fails_its_checks_on_every_real_bundle(self):
        for p in REAL:
            base = load(p)
            for name, fn, must in MUTATIONS:
                d = copy.deepcopy(base)
                fn(d)
                r = run(d)
                self.assertEqual(r["verdict"], "chain_failed", (p, name, r))
                for k in must:
                    self.assertIn(k, r["failed"], (p, name, r["failed"]))

    def test_declared_only_mutation_keeps_the_signature_verified(self):
        d = load(REAL[0])
        m_accepted_amount(d)
        r = run(d)
        self.assertEqual(r["checks"]["L2.sig"], "verified")
        self.assertEqual(r["failed"], ["K2"])


def _levels(d):
    """Every object of the bundle's own grammar, as (path, object)."""
    pp = d["payment_payload"]
    out = [("bundle", d), ("payment_payload", pp), ("accepted", pp["accepted"]), ("payload", pp["payload"]),
           ("authorization", pp["payload"]["authorization"]), ("settlement", d["settlement"]),
           ("chain_tx", d["chain_tx"])]
    return out


class CalldataTail(unittest.TestCase):
    def test_every_real_tx_carries_a_recognized_erc8021_suffix_or_none(self):
        for p in REAL:
            r = run(load(p))
            self.assertEqual(r["checks"]["C1"], "verified", p)

    def test_corrupted_or_unknown_tail_is_not_evaluated_never_verified(self):
        def marker(t):
            t["input"] = t["input"][:-2] + "00"
        def schema(t):
            t["input"] = t["input"][:-34] + "03" + t["input"][-32:]
        def length(t):
            t["input"] = t["input"][:-38] + "ffff" + t["input"][-34:]
        def garbage(t):
            t["input"] = t["input"] + "00"
        for fn in (marker, schema, length, garbage):
            for p in REAL:
                d = load(p)
                if fn is not garbage and not d["chain_tx"]["tx"]["input"].endswith("80218021802180218021802180218021"):
                    continue  # a tx without a suffix: only appended bytes apply
                fn(d["chain_tx"]["tx"])
                r = run(d)
                self.assertEqual(r["checks"]["C1"], "not_evaluated:unrecognized_trailing_calldata", (fn.__name__, p))
                self.assertEqual(r["verdict"], "chain_incomplete", (fn.__name__, p))

    def test_signature_padding_of_the_bytes_form(self):
        n = 0
        for p in REAL:
            d = load(p)
            t = d["chain_tx"]["tx"]
            if not t["input"].startswith("0xcf092995"):
                continue
            byte = 4 + 32 * 8 + 65 + 5                    # inside the 31 padding bytes after the 65-byte signature
            i = 2 + 2 * byte
            t["input"] = t["input"][:i] + "1" + t["input"][i + 1:]
            self.assertEqual(run(d)["checks"]["C1"], "failed:tx_signature_padding", p)
            n += 1
        self.assertGreaterEqual(n, 1)

    def test_tail_removed_keeps_the_arguments_but_breaks_the_transaction_hash(self):
        import apc_verify
        for p in REAL:
            d = load(p)
            t = d["chain_tx"]["tx"]
            b = bytes.fromhex(t["input"][2:])
            if t["input"].startswith("0xe3ee160e"):
                end = 4 + 32 * 9
            else:
                n = int.from_bytes(b[4 + 224: 4 + 256], "big"); end = 4 + 256 + (n + 31) // 32 * 32
            had_tail = len(b) > end
            t["input"] = "0x" + b[:end].hex()
            r = run(d)
            self.assertEqual(r["checks"]["C1"], "verified", p)
            self.assertEqual(r["checks"]["C2"], "failed:tx_hash_not_its_rlp" if had_tail else "verified", p)


class TxHash(unittest.TestCase):
    def test_every_field_of_the_signed_transaction_is_bound_by_its_hash(self):
        def bump(v):
            return hex(int(v, 16) + 1)
        for p in REAL:
            for k in ("chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gas", "value", "r", "s", "yParity"):
                d = load(p)
                t = d["chain_tx"]["tx"]
                t[k] = bump(t[k])
                if k == "yParity":
                    t["v"] = t["yParity"]
                r = run(d)
                self.assertEqual(r["checks"]["C2"], "failed:tx_hash_not_its_rlp", (p, k, r["checks"]["C2"]))
            d = load(p)
            d["chain_tx"]["tx"]["accessList"] = [{"address": "0x" + "11" * 20, "storageKeys": []}]
            self.assertEqual(run(d)["checks"]["C2"], "failed:tx_hash_not_its_rlp", p)

    def test_quantities_must_be_json_rpc_canonical(self):
        for bad in ("0x01", "0X1", "1", "", 1):
            d = load(REAL[0])
            d["chain_tx"]["tx"]["gas"] = bad
            self.assertEqual(run(d)["verdict"], "refused", bad)

    def test_other_tx_types_are_not_evaluated(self):
        d = load(REAL[0])
        d["chain_tx"]["tx"]["type"] = "0x0"
        r = run(d)
        self.assertEqual(r["checks"]["C2"], "not_evaluated:tx_type_0x0_hash_not_recomputed")
        self.assertEqual(r["verdict"], "chain_incomplete")


class Grammar(unittest.TestCase):
    def test_unknown_member_refused_at_every_level(self):
        for path, _ in _levels(load(REAL[0])):
            d = load(REAL[0])
            dict(_levels(d))[path]["zz_unknown"] = 1
            r = run(d)
            self.assertEqual(r["verdict"], "refused", (path, r))
            self.assertIn("zz_unknown", r["reason"], path)

    def test_missing_member_refused_at_every_level(self):
        for path, obj in _levels(load(REAL[0])):
            for key in list(obj):
                if path == "bundle" and key in ("settlement", "chain_tx"):
                    continue  # optional artifacts
                if path == "settlement" and key == "payer":
                    continue  # optional member
                d = load(REAL[0])
                del dict(_levels(d))[path][key]
                r = run(d)
                self.assertIn(r["verdict"], ("refused",), (path, key, r))

    def test_wrong_types_refused(self):
        cases = [("value int", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", 5)),
                 ("value leading zero", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", "0100")),
                 ("value sign", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", "+100")),
                 ("value exponent", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", "1e3")),
                 ("value 2**256", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", str(2 ** 256))),
                 ("amount empty", lambda d: d["payment_payload"]["accepted"].__setitem__("amount", "")),
                 ("address short", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("to", "0x1234")),
                 ("address no 0x", lambda d: d["payment_payload"]["accepted"].__setitem__("payTo", "a" * 40)),
                 ("nonce short", lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("nonce", "0x12")),
                 ("x402Version string", lambda d: d["payment_payload"].__setitem__("x402Version", "2")),
                 ("x402Version bool", lambda d: d["payment_payload"].__setitem__("x402Version", True)),
                 ("maxTimeoutSeconds float", lambda d: d["payment_payload"]["accepted"].__setitem__("maxTimeoutSeconds", 60.0)),
                 ("network leading zero", lambda d: d["payment_payload"]["accepted"].__setitem__("network", "eip155:08453")),
                 ("extra not object", lambda d: d["payment_payload"]["accepted"].__setitem__("extra", [])),
                 ("extra without name", lambda d: d["payment_payload"]["accepted"]["extra"].pop("name")),
                 ("signature odd hex", lambda d: d["payment_payload"]["payload"].__setitem__("signature", "0xabc")),
                 ("bundle_version", lambda d: d.__setitem__("bundle_version", "apc-0.4")),
                 ("payload list", lambda d: d["payment_payload"].__setitem__("payload", []))]
        for name, fn in cases:
            d = load(REAL[0])
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused", name)

    def test_out_of_scope_is_unsupported_not_failed(self):
        cases = [lambda d: d["payment_payload"]["accepted"].__setitem__("scheme", "upto"),
                 lambda d: d["payment_payload"]["accepted"].__setitem__("network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
                 lambda d: d["payment_payload"]["accepted"]["extra"].__setitem__("assetTransferMethod", "permit2"),
                 lambda d: d["payment_payload"].__setitem__("x402Version", 1)]
        for fn in cases:
            d = load(REAL[0])
            fn(d)
            self.assertEqual(run(d)["verdict"], "unsupported")

    def test_strict_json(self):
        with open(REAL[0], encoding="utf-8") as fh:
            raw = fh.read()
        for bad in (raw.replace('"bundle_version"', '"bundle_version": "x", "bundle_version"', 1),
                    raw[:-2] + ', "n": NaN}', "[]", "not json"):
            with self.assertRaises(av.Refusal):
                d = av.strict_json(bad)
                av.verify_bundle(d)

    def test_cli_exit_codes(self):
        import subprocess
        import tempfile
        r = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), REAL[0]], capture_output=True)
        self.assertEqual(r.returncode, 0)
        d = load(REAL[0]); m_value(d)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(d, fh)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), fh.name], capture_output=True)
        self.assertEqual(r.returncode, 1)
        d = load(REAL[0]); d["zz"] = 1
        with open(fh.name, "w") as g:
            json.dump(d, g)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), fh.name], capture_output=True)
        self.assertEqual(r.returncode, 3)
        os.unlink(fh.name)


class Acceptance(unittest.TestCase):
    def _with_payment(self, **over):
        d = load(REAL[0])
        acc, au = d["payment_payload"]["accepted"], d["payment_payload"]["payload"]["authorization"]
        pm = {"protocol": "x402", "scheme": "exact", "network": acc["network"], "asset": acc["asset"],
              "payer": au["from"], "pay_to": au["to"], "amount": au["value"], "nonce": au["nonce"],
              "settlement_tx": d["settlement"]["transaction"]}
        pm.update(over)
        d["acceptance"] = {"receipt": {"payment": pm}}
        return d

    def test_matching_payment_member(self):
        r = run(self._with_payment())
        self.assertEqual((r["checks"]["A1"], r["checks"]["A2"]), ("verified", "verified"))

    def test_each_payment_member_mismatch(self):
        d0 = self._with_payment()
        pm0 = d0["acceptance"]["receipt"]["payment"]
        for k in ("network", "asset", "payer", "pay_to", "amount", "nonce", "protocol", "scheme"):
            v = pm0[k]
            new = {"network": "eip155:1", "amount": str(int(v) + 1) if k == "amount" else None,
                   "protocol": "x402x", "scheme": "upto"}.get(k) or hexflip(v)
            r = run(self._with_payment(**{k: new}))
            self.assertIn("A1", r["failed"], (k, r))
        r = run(self._with_payment(settlement_tx=hexflip(pm0["settlement_tx"])))
        self.assertIn("A2", r["failed"])

    def test_payment_member_grammar(self):
        d = self._with_payment()
        d["acceptance"]["receipt"]["payment"]["extra"] = "x"
        self.assertEqual(run(d)["verdict"], "refused")
        d = self._with_payment()
        del d["acceptance"]["receipt"]["payment"]["nonce"]
        self.assertEqual(run(d)["verdict"], "refused")

    def test_no_settlement_tx_is_absent_and_does_not_block(self):
        d = self._with_payment()
        del d["acceptance"]["receipt"]["payment"]["settlement_tx"]
        r = run(d)
        self.assertEqual((r["checks"]["A1"], r["checks"]["A2"], r["verdict"]),
                         ("verified", "not_evaluated:absent:no_settlement_tx", "chain_verified"))
        d["acceptance"]["receipt"]["payment"]["nonce"] = hexflip(d["acceptance"]["receipt"]["payment"]["nonce"])
        self.assertEqual(run(d)["verdict"], "chain_failed")      # without settlement_tx, A1 still decides

    def test_no_payment_member_is_not_evaluated_and_blocks(self):
        d = load(REAL[0])
        d["acceptance"] = {"receipt": {}}
        r = run(d)
        self.assertEqual(r["verdict"], "chain_incomplete")
        self.assertIn("A1", r["not_evaluated"])


class Mandate(unittest.TestCase):
    def test_mandate_present_is_incomplete_in_0_1(self):
        d = load(REAL[0])
        d["mandate"] = {}
        r = run(d)
        self.assertEqual(r["verdict"], "chain_incomplete")
        self.assertEqual(r["checks"]["M1"], "not_evaluated:ap2_has_no_x402_binding")


class LogTransferV02(unittest.TestCase):
    """SPEC 0.2 C3 and indirect calls, on apc-0.2 bundles from real Base executions (bundles/real_v02)."""

    def test_every_v02_bundle_verifies_with_c3(self):
        self.assertGreaterEqual(len(REAL02), 30)
        for p in REAL02:
            r = run(load(p))
            self.assertEqual(r["verdict"], "chain_verified", (p, r))
            self.assertEqual(r["checks"]["C3"], "verified", p)

    def test_each_log_transfer_mutation(self):
        def topic(i, f):
            return lambda lt: lt["topics"].__setitem__(i, f(lt["topics"][i]))
        cases = [
            ("address", lambda lt: lt.__setitem__("address", hexflip(lt["address"])), "failed:log_transfer_not_from_asset"),
            ("topic0", topic(0, hexflip), "failed:log_transfer_not_Transfer"),
            ("from", topic(1, hexflip), "failed:log_transfer_from_mismatch"),
            ("to", topic(2, hexflip), "failed:log_transfer_to_mismatch"),
            ("value", lambda lt: lt.__setitem__("data", hexflip(lt["data"])), "failed:log_transfer_value_mismatch"),
            ("value short", lambda lt: lt.__setitem__("data", lt["data"][:-2]), "failed:log_transfer_value_mismatch"),
            ("value 33 bytes, same number", lambda lt: lt.__setitem__("data", "0x00" + lt["data"][2:]), "failed:log_transfer_value_mismatch"),
            ("tx", lambda lt: lt.__setitem__("transactionHash", hexflip(lt["transactionHash"])), "failed:log_transfer_other_tx"),
            ("block", lambda lt: lt.__setitem__("blockHash", hexflip(lt["blockHash"])), "failed:log_transfer_other_block"),
            ("index", lambda lt: lt.__setitem__("logIndex", hex(int(lt["logIndex"], 16) + 1)), "not_evaluated:log_transfer_not_next"),
        ]
        for p in KINDS02:
            for name, fn, want in cases:
                d = load(p)
                fn(d["chain_tx"]["log_transfer"])
                r = run(d)
                self.assertEqual(r["checks"]["C3"], want, (p, name))
                if name == "index" and "log_forward" in d["chain_tx"]:
                    # the forward log is no longer right after the payment's Transfer: F1 fails, so the bundle fails
                    self.assertEqual((r["checks"]["F1"], r["verdict"]), ("failed:log_forward_not_next", "chain_failed"))
                    continue
                self.assertEqual(r["verdict"], "chain_failed" if want.startswith("failed") else "chain_incomplete", (p, name))

    def test_log_transfer_grammar(self):
        for fn in (lambda lt: lt.__setitem__("topics", lt["topics"][:2]), lambda lt: lt.__setitem__("data", 5),
                   lambda lt: lt.__setitem__("logIndex", "0x01"), lambda lt: lt.pop("blockHash"),
                   lambda lt: lt.__setitem__("data", "0xabc")):
            d = load(REAL02[0])
            fn(d["chain_tx"]["log_transfer"])
            self.assertEqual(run(d)["verdict"], "refused")

    def test_direct_call_without_log_transfer_is_absent_and_does_not_block(self):
        d = load(REAL02[0])
        del d["chain_tx"]["log_transfer"]
        r = run(d)
        self.assertEqual(r["checks"]["C3"], "not_evaluated:absent:no_log_transfer")
        self.assertEqual(r["verdict"], "chain_verified")

    def test_v01_bundle_with_log_transfer_is_refused_and_has_no_c3(self):
        d = load(REAL02[0])
        d["bundle_version"] = "apc-0.1"
        self.assertEqual(run(d)["verdict"], "refused")
        del d["chain_tx"]["log_transfer"]
        r = run(d)
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertNotIn("C3", r["checks"])

    def test_indirect_call_stands_on_c3(self):
        # tx.to changed: the real hash no longer matches and the signature no longer recovers to `from`, so the RLP
        # recomputation is replaced by the identity and the sender check by "verified" here, to isolate the
        # indirect-call rule; C2's hash check is tested in TxHash, the sender check in tests/test_sender.py
        from unittest import mock
        with mock.patch.object(av, "tx_hash_eip1559", lambda tx: tx["hash"].lower()), \
                mock.patch.object(av, "_from_is_signer", lambda tx: "verified"):
            d = load(REAL02[0])
            d["chain_tx"]["tx"]["to"] = "0xca11bde05977b3631167028862be2a173976ca11"
            r = run(d)
            self.assertEqual(r["checks"]["C1"], "not_applicable:indirect_call")
            self.assertEqual((r["checks"]["C3"], r["verdict"]), ("verified", "chain_verified"))
            d1 = copy.deepcopy(d)
            del d1["chain_tx"]["log_transfer"]
            r = run(d1)
            self.assertEqual((r["checks"]["C3"], r["verdict"]),
                             ("not_evaluated:indirect_call_needs_log_transfer", "chain_incomplete"))
            d2 = copy.deepcopy(d)
            d2["chain_tx"]["log_transfer"]["logIndex"] = hex(int(d2["chain_tx"]["log_transfer"]["logIndex"], 16) + 1)
            self.assertEqual(run(d2)["verdict"], "chain_incomplete")
            d3 = copy.deepcopy(d)
            d3["chain_tx"]["log_transfer"]["data"] = hexflip(d3["chain_tx"]["log_transfer"]["data"])
            self.assertEqual(run(d3)["verdict"], "chain_failed")
            d4 = copy.deepcopy(d)
            d4["bundle_version"] = "apc-0.1"
            del d4["chain_tx"]["log_transfer"]
            self.assertEqual(run(d4)["checks"]["C1"], "failed:tx_not_to_asset")

    def test_every_kind_is_present(self):
        kinds = {(json.load(open(p))["chain_tx"]["tx"]["to"].lower() == json.load(open(p))["payment_payload"]["accepted"]["asset"],
                  "log_forward" in json.load(open(p))["chain_tx"]) for p in KINDS02}
        self.assertEqual(kinds, {(True, False), (False, False), (False, True)})


class ForwardV02(unittest.TestCase):
    """SPEC 0.2 F1, on the real bundles whose payee passes the payment on (Meridian on Base)."""

    def test_forward_is_reported_and_does_not_change_the_verdict(self):
        self.assertGreaterEqual(len(FORWARDED02), 1)
        for p in FORWARDED02:
            d = load(p)
            r = run(d)
            self.assertEqual((r["verdict"], r["checks"]["F1"]), ("chain_verified", "verified"))
            lf = d["chain_tx"]["log_forward"]
            v = int(lf["data"], 16)
            au = d["payment_payload"]["payload"]["authorization"]
            note = [n for n in r["notes"] if "forwarded" in n]
            self.assertEqual(note, ["payee %s forwarded %d of %s to 0x%s in the same transaction; %d not forwarded in this log"
                                    % (au["to"].lower(), v, au["value"], lf["topics"][2][-40:], int(au["value"]) - v)])
            del d["chain_tx"]["log_forward"]
            r = run(d)
            self.assertEqual((r["verdict"], r["checks"]["F1"]), ("chain_verified", "not_evaluated:absent:no_log_forward"))

    def test_each_log_forward_mutation_fails(self):
        def topic(i):
            return lambda lf: lf["topics"].__setitem__(i, hexflip(lf["topics"][i]))
        cases = [("address", lambda lf: lf.__setitem__("address", hexflip(lf["address"])), "failed:log_forward_not_from_asset"),
                 ("topic0", topic(0), "failed:log_forward_not_Transfer"),
                 ("from", topic(1), "failed:log_forward_not_from_payee"),
                 ("tx", lambda lf: lf.__setitem__("transactionHash", hexflip(lf["transactionHash"])), "failed:log_forward_other_tx"),
                 ("block", lambda lf: lf.__setitem__("blockHash", hexflip(lf["blockHash"])), "failed:log_forward_other_block"),
                 ("index", lambda lf: lf.__setitem__("logIndex", hex(int(lf["logIndex"], 16) + 1)), "failed:log_forward_not_next"),
                 ("data short", lambda lf: lf.__setitem__("data", lf["data"][:-2]), "failed:log_forward_malformed"),
                 ("to not address", lambda lf: lf["topics"].__setitem__(2, "0x" + "1" * 64), "failed:log_forward_malformed")]
        for p in FORWARDED02:
            for name, fn, want in cases:
                d = load(p)
                fn(d["chain_tx"]["log_forward"])
                r = run(d)
                self.assertEqual((r["checks"]["F1"], r["verdict"]), (want, "chain_failed"), name)
            d = load(p)
            del d["chain_tx"]["log_transfer"]
            r = run(d)
            self.assertEqual(r["checks"]["F1"], "failed:log_forward_without_log_transfer")

    def test_log_forward_refused_in_v01_and_grammar(self):
        d = load(FORWARDED02[0])
        d["bundle_version"] = "apc-0.1"
        del d["chain_tx"]["log_transfer"]
        self.assertEqual(run(d)["verdict"], "refused")
        for fn in (lambda lf: lf.__setitem__("topics", lf["topics"][:2]), lambda lf: lf.__setitem__("data", 7),
                   lambda lf: lf.pop("logIndex"), lambda lf: lf.__setitem__("logIndex", "0x0a1".replace("0x0", "0x00"))):
            d = load(FORWARDED02[0])
            fn(d["chain_tx"]["log_forward"])
            self.assertEqual(run(d)["verdict"], "refused")


WALLET02 = sorted(glob.glob(os.path.join(ROOT, "bundles", "real_v02_wallet", "w_*.json")))


class WalletV02(unittest.TestCase):
    """SPEC 0.2 L2.sig-1271 on real smart-wallet payers (Coinbase Smart Wallet behind its ERC-1967 proxy and behind
    EIP-7702), each with its payer_wallet chain reads."""

    def test_real_wallet_bundles_verify(self):
        self.assertEqual(len(WALLET02), 2)
        for p in WALLET02:
            r = run(load(p))
            self.assertEqual((r["verdict"], r["checks"]["L2.sig"]), ("chain_verified", "verified (ERC-1271 CoinbaseSmartWallet)"), p)

    def test_each_wallet_mutation(self):
        def res(k, f):
            return lambda d: d["payer_wallet"][k].__setitem__("result", f(d["payer_wallet"][k]["result"]))

        def sig(f):
            return lambda d: d["payment_payload"]["payload"].__setitem__("signature", f(d["payment_payload"]["payload"]["signature"]))
        cases = [
            ("owner other", res("owner", hexflip), "failed:owner_signature_recovers_"),
            ("implementation other", res("implementation", hexflip), "not_evaluated:wallet_implementation_not_known"),
            ("code other", res("code", lambda c: c[:-2] + ("00" if c[-2:] != "00" else "01")), "not_evaluated:wallet_implementation_not_known"),
            ("code address", lambda d: d["payer_wallet"]["code"]["params"].__setitem__(0, hexflip(d["payer_wallet"]["code"]["params"][0])), "failed:code_params_0"),
            ("slot", lambda d: d["payer_wallet"]["implementation"]["params"].__setitem__(1, hexflip(d["payer_wallet"]["implementation"]["params"][1])), "failed:implementation_params_1"),
            ("owner call data", lambda d: d["payer_wallet"]["owner"]["params"][0].__setitem__("data", hexflip(d["payer_wallet"]["owner"]["params"][0]["data"])), "failed:owner_params_0"),
            ("owner block", lambda d: d["payer_wallet"]["owner"]["params"].__setitem__(1, "0x1"), "failed:owner_params_1"),
            ("block not tx block", lambda d: [d["payer_wallet"][k]["params"].__setitem__(-1, hex(int(d["payer_wallet"][k]["params"][-1], 16) + 1)) for k in ("code", "implementation", "owner")], "failed:payer_wallet_block_not_tx_block"),
            ("wrapper owner index", sig(lambda x: x[:2 + 64 * 2 - 1] + "1" + x[2 + 64 * 2:]), "failed:wrapper_owner_index_not_payer_wallet_owner_index"),
            ("owner signature byte", sig(lambda x: x[:2 + 64 * 5 + 10] + hexflip(x[2 + 64 * 5 + 10:2 + 64 * 5 + 12], 0) + x[2 + 64 * 5 + 12:]), "failed:"),
            ("payer_wallet missing", lambda d: d.pop("payer_wallet"), "not_evaluated:contract_wallet_needs_payer_wallet"),
        ]
        for p in WALLET02:
            for name, fn, want in cases:
                d = load(p)
                fn(d)
                r = run(d)
                if name == "block not tx block" and "chain_tx" not in d:
                    continue
                self.assertTrue(r.get("checks", {}).get("L2.sig", r.get("verdict", "")).startswith(want), (p, name, r.get("checks", r)))
                self.assertNotEqual(r["verdict"], "chain_verified", (p, name))

    def test_wrapper_and_reply_grammar_refused(self):
        def sig(f):
            return lambda d: d["payment_payload"]["payload"].__setitem__("signature", f(d["payment_payload"]["payload"]["signature"]))
        for fn in (sig(lambda x: x + "00" * 32),                                  # bytes after the wrapper
                   sig(lambda x: x[:2 + 31 * 2] + "40" + x[2 + 32 * 2:]),          # first offset not 0x20
                   sig(lambda x: x[:-2] + "01"),                                  # padding not zero
                   lambda d: d["payer_wallet"].__setitem__("zz", 1),
                   lambda d: d["payer_wallet"]["owner"].pop("params"),
                   lambda d: d["payer_wallet"]["code"].__setitem__("method", "eth_call"),
                   lambda d: d["payer_wallet"].__setitem__("owner_index", "01")):
            d = load(WALLET02[0])
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused")

    def test_passkey_owner_with_an_ecdsa_signature_is_not_evaluated(self):
        # SPEC 0.17 28.3: a 64-byte owner is a passkey; a 65-byte signatureData is not abi.encode(WebAuthnAuth) in the
        # canonical form, so not judged (tests/test_webauthn.py has the passkey cases)
        d = load(WALLET02[0])
        ob = bytes.fromhex(d["payer_wallet"]["owner"]["result"][2:])
        d["payer_wallet"]["owner"]["result"] = "0x" + (ob[:32] + (64).to_bytes(32, "big") + bytes(range(64))).hex()
        r = run(d)
        self.assertEqual((r["checks"]["L2.sig"], r["verdict"]),
                         ("not_evaluated:webauthn_auth_not_canonical_abi(outer offset not 0x20)",
                          "chain_incomplete"))

    def test_payer_wallet_beside_a_65_byte_signature_or_in_v01(self):
        # SPEC 32.3 point 3 (0.21): the member is read beside a 65-byte signature too; this one names another payer
        d = load(REAL02[0])
        d["payer_wallet"] = load(WALLET02[0])["payer_wallet"]
        self.assertEqual(run(d)["checks"]["L2.sig"], "failed:payer_wallet_block_not_tx_block")   # another block, read first
        d = load(WALLET02[0])
        d["bundle_version"] = "apc-0.1"
        for k in ("log_transfer", "log_forward"):
            d["chain_tx"].pop(k, None)
        self.assertEqual(run(d)["verdict"], "refused")


class Erc8021Schema0(unittest.TestCase):
    """The one real transaction (of 2449) whose calldata ends with an ERC-8021 Schema 0 suffix."""
    P = os.path.join(ROOT, "bundles", "real_v02_misc", "erc8021_schema0.json")

    def test_real_schema0_suffix_is_recognized(self):
        r = run(load(self.P))
        self.assertEqual(r["verdict"], "chain_verified")
        self.assertIn("calldata carries an ERC-8021 Schema 0 suffix (draft ERC, ethereum/ERCs PR #1209), codes 'bc_o3dj3qk8', "
                      "not interpreted", r["notes"])

    def test_altered_schema0_suffix_is_not_recognized(self):
        # each alteration keeps the transaction hash out of the picture: C1 decides before C2
        for name, f in (("non-ASCII code byte", lambda t: t[:2] + "e2" + t[4:]),
                        ("length one less", lambda t: t[:-36] + "%02x" % (int(t[-36:-34], 16) - 1) + t[-34:]),
                        ("schema 3", lambda t: t[:-34] + "03" + t[-32:]),
                        ("one byte more in front", lambda t: "61" + t)):
            d = load(self.P)
            inp = d["chain_tx"]["tx"]["input"]
            head, tail = inp[:2 + 2 * (4 + 9 * 32)], inp[2 + 2 * (4 + 9 * 32):]
            d["chain_tx"]["tx"]["input"] = head + f(tail)
            r = run(d)
            self.assertEqual(r["checks"]["C1"], "not_evaluated:unrecognized_trailing_calldata", name)
        self.assertEqual(av.erc8021_schema0(bytes.fromhex("62635f6f33646a33716b380b00" + "8021" * 8)), "bc_o3dj3qk8")



class ReviewV02(unittest.TestCase):
    """Added with the independent review of 3e11eb0: inputs that crashed (exit 1 = chain_failed), the payer_wallet block
    when chain_tx has no blockNumber, logs claiming another block than the transaction, the levels the SPEC calls
    closed, the wallet decoder's strictness, Schema 1, C3 at logIndex - 1, the CLI exit codes."""

    def test_former_crashes_are_refused(self):
        cases = [("code.params []", WALLET02[1], lambda d: d["payer_wallet"]["code"].__setitem__("params", [])),
                 ("code.params 5", WALLET02[1], lambda d: d["payer_wallet"]["code"].__setitem__("params", 5)),
                 ("code.params {}", WALLET02[1], lambda d: d["payer_wallet"]["code"].__setitem__("params", {})),
                 ("value 5000 digits", REAL02[0], lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", "1" * 5000)),
                 ("value 79 digits", REAL02[0], lambda d: d["payment_payload"]["payload"]["authorization"].__setitem__("value", "1" * 79)),
                 ("amount 5000 digits", REAL02[0], lambda d: d["payment_payload"]["accepted"].__setitem__("amount", "9" * 5000)),
                 ("owner_index 5000 digits", WALLET02[1], lambda d: d["payer_wallet"].__setitem__("owner_index", "1" * 5000)),
                 ("settlement.amount 5000 digits", REAL02[0], lambda d: d["settlement"].__setitem__("amount", "1" * 5000)),
                 ("tx.input with a space", REAL02[0], lambda d: d["chain_tx"]["tx"].__setitem__("input", d["chain_tx"]["tx"]["input"][:20] + " " + d["chain_tx"]["tx"]["input"][20:]))]
        for name, p, fn in cases:
            d = load(p)
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused", name)
        with self.assertRaises(av.Refusal):
            av.strict_json("[" * 100000)
        self.assertEqual(run(load(REAL02[0]) | {"payment_payload": dict(load(REAL02[0])["payment_payload"], extensions={"a": 1})})["verdict"], "chain_verified")

    def test_payer_wallet_needs_the_transaction_block_when_chain_tx_is_present(self):
        for fn in (lambda t: t.pop("blockNumber"), lambda t: t.__setitem__("blockNumber", None), lambda t: t.__setitem__("blockNumber", "latest")):
            for p in WALLET02:
                d = load(p)
                fn(d["chain_tx"]["tx"])
                for k in ("code", "implementation", "owner"):
                    d["payer_wallet"][k]["params"][-1] = "0x1"
                self.assertEqual(run(d)["verdict"], "refused", p)
        d = load(WALLET02[1])
        del d["chain_tx"]
        d.pop("settlement", None)
        self.assertEqual(run(d)["verdict"], "chain_verified")   # without chain_tx there is no transaction block to tie to

    def test_logs_must_claim_the_transaction_block(self):
        for p in KINDS02:
            d = load(p)
            for k in ("log_authorization_used", "log_transfer"):
                d["chain_tx"][k]["blockHash"] = hexflip(d["chain_tx"][k]["blockHash"])
            r = run(d)
            self.assertEqual((r["checks"]["C2"], r["verdict"]), ("failed:log_block_not_tx_block", "chain_failed"), p)
            d = load(p)
            d["chain_tx"]["log_authorization_used"]["blockNumber"] = hex(int(d["chain_tx"]["log_authorization_used"]["blockNumber"], 16) + 1)
            self.assertEqual(run(d)["checks"]["C2"], "failed:log_block_not_tx_block", p)
            d = load(p)
            d["chain_tx"]["log_transfer"]["blockNumber"] = hex(int(d["chain_tx"]["log_transfer"]["blockNumber"], 16) + 1)
            self.assertEqual(run(d)["checks"]["C3"], "failed:log_transfer_other_block", p)
            d = load(p)
            del d["chain_tx"]["log_authorization_used"]["blockNumber"]
            self.assertEqual(run(d)["verdict"], "refused", p)
        for p in FORWARDED02:
            d = load(p)
            d["chain_tx"]["log_forward"]["blockNumber"] = hex(int(d["chain_tx"]["log_forward"]["blockNumber"], 16) + 1)
            self.assertEqual(run(d)["checks"]["F1"], "failed:log_forward_other_block", p)
        d = load(REAL[0])                       # apc-0.1: compared when carried, as before not required
        d["chain_tx"]["log_authorization_used"]["blockHash"] = hexflip(d["chain_tx"]["log_authorization_used"]["blockHash"])
        self.assertEqual(run(d)["checks"]["C2"], "failed:log_block_not_tx_block")
        d = load(REAL[0])
        del d["chain_tx"]["log_authorization_used"]["blockHash"]
        self.assertEqual(run(d)["verdict"], "chain_verified")

    def test_closed_levels_named_by_the_spec(self):
        acc = load(REAL02[0])["payment_payload"]["accepted"]
        pr = {"x402Version": 2, "resource": {"url": "u"}, "accepts": [acc]}
        cases = [("resource unknown member", lambda d: d["payment_payload"].__setitem__("resource", {"url": "u", "zz": 1})),
                 ("payload extensions not object", lambda d: d["payment_payload"].__setitem__("extensions", 5)),
                 ("payment_required.resource not object", lambda d: d.__setitem__("payment_required", dict(pr, resource=5))),
                 ("payment_required.resource unknown member", lambda d: d.__setitem__("payment_required", dict(pr, resource={"url": "u", "zz": 1}))),
                 ("accepts entry not object", lambda d: d.__setitem__("payment_required", dict(pr, accepts=[5, acc]))),
                 ("payment_required.extensions not object", lambda d: d.__setitem__("payment_required", dict(pr, extensions=[]))),
                 ("payment_required.x402Version not an integer", lambda d: d.__setitem__("payment_required", dict(pr, x402Version="2"))),
                 ("payment_required.error not a string", lambda d: d.__setitem__("payment_required", dict(pr, error=99))),
                 ("settlement.extensions not object", lambda d: d["settlement"].__setitem__("extensions", 5)),
                 ("settlement.network not string", lambda d: d["settlement"].__setitem__("network", 8453)),
                 ("mandate not object", lambda d: d.__setitem__("mandate", 5))]
        for name, fn in cases:
            d = load(REAL02[0])
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused", name)
        d = load(REAL02[0])
        d["payment_required"] = dict(pr, x402Version=1)        # as payment_payload: another version is unsupported
        self.assertEqual(run(d)["verdict"], "unsupported")
        d = load(REAL02[0])
        d["payment_payload"]["resource"] = {"url": "u", "description": "d", "mimeType": "m"}
        d["payment_required"] = dict(pr, resource={"url": "u", "mimeType": "m"}, extensions={}, error="e",
                                     accepts=[{"scheme": "upto", "zz": 1}, acc])
        r = run(d)
        self.assertEqual((r["verdict"], r["checks"]["K4"]), ("chain_verified", "verified"))

    def test_wallet_decoder_strictness(self):
        def sig(f):
            return lambda d: d["payment_payload"]["payload"].__setitem__("signature", f(d["payment_payload"]["payload"]["signature"]))

        def longer(x):                                        # SignatureWrapper with 66 bytes of signatureData
            b = bytes.fromhex(x[2:])
            data = b[128:128 + 65] + b"\x00"
            return "0x" + (b[:96] + (66).to_bytes(32, "big") + data + bytes(96 - 66)).hex()
        cases = [("7702 version byte", WALLET02[0], lambda d: d["payer_wallet"]["code"].__setitem__("result", "0xef0101" + d["payer_wallet"]["code"]["result"][8:]), "not_evaluated:wallet_implementation_not_known"),
                 ("slot high bytes", WALLET02[1], lambda d: d["payer_wallet"]["implementation"].__setitem__("result", "0x01" + d["payer_wallet"]["implementation"]["result"][4:]), "not_evaluated:wallet_implementation_not_known"),
                 ("owner high bytes", WALLET02[1], lambda d: d["payer_wallet"]["owner"].__setitem__("result", d["payer_wallet"]["owner"]["result"][:130] + "01" + d["payer_wallet"]["owner"]["result"][132:]), "failed:owner_not_an_address"),
                 ("owner signature v 0", WALLET02[1], sig(lambda x: x[:2 + 2 * (32 * 4 + 64)] + "00" + x[2 + 2 * (32 * 4 + 64) + 2:]), "failed:owner_signature_not_65_bytes_v27_28"),
                 ("owner signature 66 bytes", WALLET02[1], sig(longer), "failed:owner_signature_not_65_bytes_v27_28")]
        for name, p, fn, want in cases:
            d = load(p)
            fn(d)
            r = run(d)
            self.assertEqual(r["checks"]["L2.sig"], want, name)
            self.assertNotEqual(r["verdict"], "chain_verified", name)
        for name, fn in (("second offset 0x60", sig(lambda x: x[:2 + 64 * 2 + 62] + "60" + x[2 + 64 * 3:])),
                         ("reply with a fourth param", lambda d: d["payer_wallet"]["implementation"]["params"].append("0x0"))):
            d = load(WALLET02[1])
            fn(d)
            self.assertEqual(run(d)["verdict"], "refused", name)

    def test_schema_1_suffix_is_not_read_as_schema_0(self):
        d = load(Erc8021Schema0.P)
        inp = d["chain_tx"]["tx"]["input"]
        d["chain_tx"]["tx"]["input"] = inp[:-34] + "01" + inp[-32:]
        self.assertEqual(run(d)["checks"]["C1"], "not_evaluated:unrecognized_trailing_calldata")

    def test_c3_transfer_one_before_is_not_next(self):
        for p in KINDS02:
            d = load(p)
            lt = d["chain_tx"]["log_transfer"]
            lt["logIndex"] = hex(int(d["chain_tx"]["log_authorization_used"]["logIndex"], 16) - 1)
            self.assertEqual(run(d)["checks"]["C3"], "not_evaluated:log_transfer_not_next", p)

    def test_forward_of_more_than_received_is_said(self):
        d = load(FORWARDED02[0])
        d["chain_tx"]["log_forward"]["data"] = "0x" + "ff" * 32
        r = run(d)
        self.assertEqual(r["checks"]["F1"], "verified")
        self.assertTrue(any("more than the" in n for n in r["notes"]), r["notes"])
        self.assertFalse(any("-" in n.split("forwarded")[-1][:3] for n in r["notes"] if "forwarded" in n))

    def test_chain_note_and_cli_exit_codes(self):
        import subprocess
        r = run(load(REAL02[0]))
        self.assertTrue(any(n.startswith("chain_tx is RPC data carried by the bundle") for n in r["notes"]))
        self.assertFalse(any("RPC data carried" in n for n in run({k: v for k, v in load(REAL02[0]).items() if k != "chain_tx"})["notes"]))
        for arg, rc in (("/nonexistent/x.json", 3), (ROOT, 3), ("-x", 64)):
            p = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), arg], capture_output=True, text=True)
            self.assertEqual(p.returncode, rc, (arg, p.stdout[-200:], p.stderr[-200:]))
            self.assertEqual(p.stderr, "", arg)


if __name__ == "__main__":
    unittest.main(verbosity=1)
