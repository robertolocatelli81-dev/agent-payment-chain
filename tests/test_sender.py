"""SPEC Amendment 0.3.3 part 3: the settlement sender is recovered from the transaction's own signature (a `from`
member that is not the signer fails C2), reported as `settled_by` (apc-0.3) and compared with a declared facilitator
signer list (F2). Real data: every real bundle; the x402scan facilitator list pinned in sources/x402scan_5732bb8."""
import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from tests import real_corpus  # noqa: E402
real_corpus.need("*")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_verify as av  # noqa: E402
from test_apc03 import load, real_bundles, run  # noqa: E402
from make_bundles_v02 import facilitator_map  # noqa: E402

REAL = real_bundles("evm")         # EVM bundles (Solana and XRPL have their own tests)
SIGNERS = sorted(facilitator_map(os.path.join(ROOT, "sources", "x402scan_5732bb8")))


def fac(signers):
    return {"signers": signers, "source": "sources/x402scan_5732bb8", "fetched": "2026-10-22T00:00:00Z"}


class Sender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = [(p, load(p)) for p in REAL]
        cls.v03 = [(p, d) for p, d in cls.docs if d["bundle_version"] == "apc-0.3"]

    def test_real_from_is_signer(self):
        n = 0
        for p, d in self.docs:
            if d.get("chain_tx", {}).get("tx", {}).get("type") != "0x2" or "from" not in d["chain_tx"]["tx"]:
                continue
            r = run(d)
            self.assertNotIn("tx_from_not_its_signer", r["checks"].get("C2", ""), p)
            if d["bundle_version"] == "apc-0.3":
                self.assertEqual(r["settled_by"], d["chain_tx"]["tx"]["from"].lower(), p)
            n += 1
        self.assertGreater(n, 150)

    def test_forged_from_fails(self):
        for p, d in self.docs[:20] + self.v03[:10]:
            if "chain_tx" not in d:
                continue
            e = copy.deepcopy(d)
            e["chain_tx"]["tx"]["from"] = "0x" + "11" * 20
            r = run(e)
            self.assertEqual(r["checks"]["C2"], "failed:tx_from_not_its_signer", p)
            if d["bundle_version"] == "apc-0.3":     # C2 failed: no sender is reported, F2 is not evaluated
                self.assertIsNone(r["settled_by"], p)
                e["facilitator"] = fac(SIGNERS)
                self.assertEqual(run(e)["checks"]["F2"], "not_evaluated:settled_by_not_recovered", p)

    def test_unrecoverable_and_high_s_signature(self):
        """r = 0 does not recover; the high-s twin (s' = n - s, yParity flipped) is refused by EIP-2, not recovered"""
        n = 0
        for p, d in self.docs:
            tx = d.get("chain_tx", {}).get("tx", {})
            if tx.get("type") != "0x2" or "from" not in tx:
                continue
            self.assertEqual(av._from_is_signer(tx), "verified", p)
            e = copy.deepcopy(tx)
            e["r"] = "0x0"
            self.assertEqual(av._from_is_signer(e), "failed:tx_signature_does_not_recover", p)
            e = copy.deepcopy(tx)
            e["s"] = hex(av.SECP_N - int(tx["s"], 16))
            y = "yParity" if "yParity" in tx else "v"
            e[y] = hex(1 - int(tx[y], 16))
            self.assertIsNone(av.tx_sender_eip1559(e), p)
            self.assertEqual(av._from_is_signer(e), "failed:tx_signature_does_not_recover", p)
            e = copy.deepcopy(tx)
            e["type"] = "0x0"                              # another type: not recovered over the 1559 preimage
            self.assertIsNone(av.tx_sender_eip1559(e), p)
            n += 1
            if n == 20:
                break
        self.assertEqual(n, 20)

    def test_facilitator_list_real(self):
        """the pinned x402scan list: listed senders verify, the others fail with the note (both occur in the corpus)"""
        seen = {}
        for p, d in self.v03:
            e = copy.deepcopy(d)
            e["facilitator"] = fac(SIGNERS)
            r = run(e)
            seen[r["checks"]["F2"]] = seen.get(r["checks"]["F2"], 0) + 1
            listed = r["settled_by"] in SIGNERS
            self.assertEqual(r["checks"]["F2"], "verified" if listed else "failed:settled_by_not_a_facilitator_signer", p)
            self.assertEqual(any(n.startswith("F2:") for n in r["notes"]), not listed, p)
        self.assertGreater(seen.get("verified", 0), 0)
        self.assertGreater(seen.get("failed:settled_by_not_a_facilitator_signer", 0), 0)

    def test_facilitator_absent_and_grammar(self):
        p, d = self.v03[0]
        self.assertEqual(run(d)["checks"]["F2"], "not_evaluated:absent:no_facilitator")
        for bad in ({"signers": [], "source": "x", "fetched": "2026-10-22T00:00:00Z"},
                    {"signers": ["0x12"], "source": "x", "fetched": "2026-10-22T00:00:00Z"},
                    {"signers": SIGNERS[:1], "source": "x", "fetched": "22/10/2026"},
                    {"signers": SIGNERS[:1], "source": "x", "fetched": "2026-10-22T00:00:00Z", "extra": 1}):
            e = copy.deepcopy(d)
            e["facilitator"] = bad
            self.assertEqual(run(e)["verdict"], "refused", bad)
        e = copy.deepcopy(load([q for q, _ in self.docs if "/real_v02/" in q][0]))
        e["facilitator"] = fac(SIGNERS)
        self.assertEqual(run(e)["verdict"], "refused")          # an apc-0.3 member only


if __name__ == "__main__":
    unittest.main()
