"""SPEC 0.18.2, section 25 C1, block (the author's decision of 27/10): the receipt and every log of an apc-0.15 bundle
claim the transaction's block, hash and number; another block is C1 failed:log_block_not_tx_block, a missing or
malformed blockHash/blockNumber (blockNumber read as the JSON-RPC quantity of apc_verify._q) is a refusal, and a C1
not verified keeps its reason. Positive control: with apc_authcap.py of bef021d (before the rule) these tests fail."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_authcap import PATHS, PATHS11, load, run  # noqa: E402


def _other(h):
    return h[:-1] + ("0" if h[-1] != "0" else "1")


class BlockBinding(unittest.TestCase):
    def test_real_bundles_bind(self):
        for p in PATHS + PATHS11:
            self.assertEqual(run(load(p))["checks"]["C1"], "verified", p)

    def test_another_block(self):
        b = load(PATHS[0])
        n = len(b["chain_tx"]["receipt"]["logs"])
        cases = [lambda d: d["chain_tx"]["receipt"].__setitem__("blockHash", _other(d["chain_tx"]["receipt"]["blockHash"])),
                 lambda d: d["chain_tx"]["receipt"].__setitem__("blockNumber", hex(int(d["chain_tx"]["receipt"]["blockNumber"], 16) + 1))]
        for i in range(n):
            cases.append(lambda d, i=i: d["chain_tx"]["receipt"]["logs"][i].__setitem__(
                "blockHash", _other(d["chain_tx"]["receipt"]["logs"][i]["blockHash"])))
            cases.append(lambda d, i=i: d["chain_tx"]["receipt"]["logs"][i].__setitem__(
                "blockNumber", hex(int(d["chain_tx"]["receipt"]["logs"][i]["blockNumber"], 16) - 1)))
        for k, mut in enumerate(cases):
            d = copy.deepcopy(b)
            mut(d)
            r = run(d)
            self.assertEqual(r.get("checks", {}).get("C1"), "failed:log_block_not_tx_block", (k, r))
            self.assertEqual(r["verdict"], "chain_failed", k)

    def test_same_block_other_case_passes(self):
        d = load(PATHS11[0])
        for lg in d["chain_tx"]["receipt"]["logs"]:
            lg["blockHash"] = lg["blockHash"].upper().replace("0X", "0x")
        self.assertEqual(run(d)["checks"]["C1"], "verified")

    def test_first_failure_kept(self):
        """A C1 already failed keeps its reason (mutant BB03)."""
        d = load(PATHS[0])
        d.pop("settlement"), d.pop("provenance")
        d["chain_tx"]["tx"]["nonce"] = hex(int(d["chain_tx"]["tx"]["nonce"], 16) + 1)
        d["chain_tx"]["receipt"]["logs"][0]["blockHash"] = _other(d["chain_tx"]["receipt"]["logs"][0]["blockHash"])
        self.assertEqual(run(d)["checks"]["C1"], "failed:tx_hash_not_the_transaction")

    def test_receipt_block_read_when_c1_failed(self):
        """The receipt's block is read whatever C1 is: missing, it is a refusal also when C1 has already failed."""
        d = load(PATHS[0])
        d.pop("settlement"), d.pop("provenance")
        d["chain_tx"]["tx"]["nonce"] = hex(int(d["chain_tx"]["tx"]["nonce"], 16) + 1)
        del d["chain_tx"]["receipt"]["blockHash"]
        self.assertIn("chain_tx.receipt.blockHash", run(d).get("refused", ""))

    def test_number_is_a_quantity(self):
        """blockNumber is a JSON-RPC quantity as everywhere else in the verifier: no leading zeros, lower case, at most
        256 bits; a number that is not one is a refusal, not a block compared by its value."""
        b = load(PATHS[0])
        n = b["chain_tx"]["receipt"]["logs"][0]["blockNumber"]
        for bad in ("0x0" + n[2:], n.upper().replace("0X", "0x"), "0x", "0x1" + "0" * 64, " " + n, n + "\n", int(n, 16)):
            for where in ("tx", "receipt", "log"):
                d = copy.deepcopy(b)
                o = d["chain_tx"]["receipt"]["logs"][0] if where == "log" else d["chain_tx"][where]
                o["blockNumber"] = bad
                self.assertIn("blockNumber: not a JSON-RPC quantity", run(d).get("refused", ""), (where, bad))

    def test_missing_or_malformed_is_refused(self):
        b = load(PATHS[0])
        for where, path in (("tx", "chain_tx.tx"), ("receipt", "chain_tx.receipt"), ("log", "chain_tx.receipt.logs[0]")):
            for k, v in (("blockHash", None), ("blockNumber", None), ("blockHash", "0x12"), ("blockNumber", 7),
                         ("blockHash", 7), ("blockHash", "0x" + "g" * 64), ("blockHash", "0x" + "ab" * 32 + "\n")):
                d = copy.deepcopy(b)
                o = d["chain_tx"]["receipt"]["logs"][0] if where == "log" else d["chain_tx"][where]
                if v is None:
                    del o[k]
                else:
                    o[k] = v
                self.assertIn(path + "." + k + ": not", run(d).get("refused", ""), (where, k, v))

if __name__ == "__main__":
    unittest.main()
