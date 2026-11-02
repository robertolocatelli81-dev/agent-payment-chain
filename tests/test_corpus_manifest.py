"""SPEC section 33: the list of the real corpus (corpus/MANIFEST.json) and tools/rebuild_corpus.py.

Offline, always: the list reads back closed (a member outside the grammar at any level is refused with its path; a wrong
count, a duplicate file, a bad digest likewise), its sets and levels, the skip discipline of tests/real_corpus.py and of
the package loader (a module that raises SkipTest at import is reported skipped, never passed or crashed).
With the local corpus (bundles/, oracle/): the digests of the list are those of our files; and the positive controls of
the rebuild through a fake endpoint that serves the saved replies — the unaltered data rebuilds a bundle to the byte,
and an altered block hash, transaction input, receipt log, XRPL metadata blob or Solana message byte is refused with its
reason; for the anchored bundles (33.10) an altered L2 header, L1 proof, L1 header, L1 reply, game code, another game or
root index in the list. No network."""
import base64
import copy
import glob
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import rebuild_corpus as rc  # noqa: E402
from tests import real_corpus  # noqa: E402

MAN = rc.load_manifest()


def entry(file):
    return next(e for e in MAN["bundles"] if e["file"] == file)


class ListClosed(unittest.TestCase):
    """33.2: the list reads back; anything outside the grammar is refused with its path."""

    def _refused(self, doc, needle):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(doc, fh)
        try:
            with self.assertRaises(rc.ManifestRefusal) as cm:
                rc.load_manifest(fh.name)
            self.assertIn(needle, str(cm.exception))
        finally:
            os.unlink(fh.name)

    def test_reads_back(self):
        self.assertEqual(MAN["format"], rc.FORMAT)
        self.assertEqual(len(MAN["sets"]), 20)
        self.assertEqual({o["kind"] for n, o in MAN["oracle"].items() if n in ("blocks_v03", "xrpl_20261026")}, {"evm_blocks", "xrpl_ledgers"})
        self.assertEqual(len(MAN["bundles"]), sum(s["count"] for s in MAN["sets"].values()))
        for s in MAN["sets"].values():
            self.assertIn(s["rebuild"], rc.LEVELS)
            self.assertIn(s["recipe"], rc.RECIPES)
        self.assertEqual({s["rebuild"] for n, s in MAN["sets"].items() if n in ("xlm_real_20261026", "real_v03_canonical", "real_v04_l1state")},
                         {"local_only"})

    def test_unknown_member_at_each_level(self):
        d = copy.deepcopy(MAN)
        d["extra"] = 1
        self._refused(d, "manifest.extra")
        d = copy.deepcopy(MAN)
        d["sets"]["real"]["note"] = "x"
        self._refused(d, "sets.real.note")
        d = copy.deepcopy(MAN)
        d["bundles"][0]["comment"] = "x"
        self._refused(d, "bundles[0].comment")
        d = copy.deepcopy(MAN)
        d["bundles"][0]["chain"]["gas"] = 1
        self._refused(d, "bundles[0].chain.gas")
        d = copy.deepcopy(MAN)
        d["bundles"][0].setdefault("ours", {})["x"] = 1
        self._refused(d, "bundles[0].ours.x")
        d = copy.deepcopy(MAN)
        d["sets"]["real"]["serialization"]["pretty"] = True
        self._refused(d, "sets.real.serialization.pretty")

    def test_counts_duplicates_digests_levels(self):
        d = copy.deepcopy(MAN)
        d["sets"]["real"]["count"] += 1
        self._refused(d, "sets.real.count")
        d = copy.deepcopy(MAN)
        d["bundles"].append(copy.deepcopy(d["bundles"][0]))
        self._refused(d, "duplicate")
        d = copy.deepcopy(MAN)
        d["bundles"][0]["sha256"] = d["bundles"][0]["sha256"][:-1] + "G"
        self._refused(d, "digest")
        d = copy.deepcopy(MAN)
        d["sets"]["real"]["rebuild"] = "maybe"
        self._refused(d, "unknown level")
        d = copy.deepcopy(MAN)
        d["sets"]["xlm_real_20261026"].pop("reason")
        self._refused(d, "local_only without a reason")
        d = copy.deepcopy(MAN)
        d["format"] = "apc-corpus-0.9"
        self._refused(d, "manifest.format")
        d = copy.deepcopy(MAN)
        d["bundles"][0]["file"] = "../" + d["bundles"][0]["file"]
        self._refused(d, "outside bundles/")
        d = copy.deepcopy(MAN)
        e = next(x for x in d["bundles"] if x["set"] == "xrp_real_20261026")
        e["chain"]["ledger_hash"] = e["chain"]["ledger_hash"].lower()
        self._refused(d, "uppercase hex")

    def test_wrong_types(self):
        d = copy.deepcopy(MAN)
        d["bundles"][0]["chain"]["block_number"] = "0x1"
        self._refused(d, "wrong type")
        d = copy.deepcopy(MAN)
        d["bundles"][0]["chain"].pop("tx_hash")
        self._refused(d, "missing")


class NoAddressInClear(unittest.TestCase):
    """33.2 (format 0.2): no payer, owner or fee payer in clear; contracts only."""

    def test_state_and_svm_members(self):
        for e in MAN["bundles"]:
            st = e["chain"].get("state")
            if st:
                self.assertNotIn("payer", st, e["file"])
                self.assertNotIn("owner", st, e["file"])
            self.assertNotIn("fee_payer", e["chain"], e["file"])
            self.assertNotIn("accepted", e.get("ours", {}), e["file"])

    def test_every_evm_address_in_the_list_is_a_contract(self):
        import re
        contracts = set()
        for s in MAN["sets"].values():
            p = s["params"]
            contracts.update(a.lower() for a in [p.get("token"), p.get("escrow")] if a)
            contracts.update(a.lower() for a in p.get("tokens", {}))
        for e in MAN["bundles"]:
            st = e["chain"].get("state") or {}
            contracts.update(a.lower() for a in [st.get("implementation"), st.get("delegate")] if a)
            if "anchor" in e["chain"]:                 # 33.10: the dispute game, the clone the factory deployed
                contracts.add(e["chain"]["anchor"]["game"].lower())
        text = json.dumps({"sets": MAN["sets"], "bundles": [{k: v for k, v in e.items() if k != "ours"} for e in MAN["bundles"]]})
        found = {a.lower() for a in re.findall(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])", text)}
        self.assertEqual(found - contracts, set())

    def test_format_01_members_are_refused(self):
        d = copy.deepcopy(MAN)
        e = next(x for x in d["bundles"] if x["chain"].get("state"))
        e["chain"]["state"]["payer"] = "0x" + "11" * 20
        ListClosed._refused(self, d, "chain.state.payer")
        d = copy.deepcopy(MAN)
        e = next(x for x in d["bundles"] if x["set"] == "real_svm")
        e["chain"]["fee_payer"] = "1" * 32
        ListClosed._refused(self, d, "chain.fee_payer")


class SkipDiscipline(unittest.TestCase):
    """33: a test that needs the corpus skips with the reason and the command; the loader reports it as a skip."""

    def test_need_names_what_is_missing(self):
        with self.assertRaises(unittest.SkipTest) as cm:
            real_corpus.need("no_such_set_xyz", oracle=("no_such_dir_xyz",))
        msg = str(cm.exception)
        self.assertIn("bundles/no_such_set_xyz", msg)
        self.assertIn("oracle/no_such_dir_xyz", msg)
        self.assertIn("tools/rebuild_corpus.py --only no_such_set_xyz", msg)

    def test_star_means_every_listed_set(self):
        gone, _ = real_corpus.missing(["*"])
        for name, s in MAN["sets"].items():
            if s["rebuild"] == "local_only":
                self.assertNotIn("bundles/" + name, gone)        # "*" is every set that is not local_only (33.8)
            elif not real_corpus.has_set(name):
                self.assertIn("bundles/" + name, gone)

    def test_loader_reports_a_skipping_module_as_skipped(self):
        import tempfile
        import tests  # noqa: F401  (installs the loader)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "skipmod_apc.py"), "w") as fh:
                fh.write("import unittest\nraise unittest.SkipTest('corpus missing: rebuild with X')\n")
            sys.path.insert(0, d)
            try:
                suite = unittest.defaultTestLoader.loadTestsFromName("skipmod_apc")
                r = unittest.TestResult()
                suite.run(r)
            finally:
                sys.path.remove(d)
                sys.modules.pop("skipmod_apc", None)
        self.assertEqual((r.testsRun, len(r.skipped), len(r.errors), len(r.failures)), (1, 1, 0, 0))
        self.assertIn("rebuild with X", r.skipped[0][1])

    def test_regress_refuses_without_the_corpus(self):
        import tempfile
        from tools import regress as rg
        with tempfile.TemporaryDirectory() as d, mock.patch.object(rg, "ROOT", d):
            with self.assertRaises(rg.Refused) as cm:
                rg.corpus()
        self.assertIn("rebuild_corpus.py", str(cm.exception))


class FakeRpc(rc.Rpc):
    """Serves saved replies; `alter` edits a reply before it is returned."""

    def __init__(self, replies, alter=None):
        super().__init__({}, rate=1000)
        self.replies, self.alter, self.log = replies, alter or (lambda m, p, r: r), []

    def url(self, network):
        return "https://fake.invalid/"

    def call(self, network, method, params, xrpl=False):
        self.calls += 1
        self.log.append((method, params))
        key = method if method in ("eth_getBlockReceipts", "ledger", "getTransaction") else (method, rc.canon(params))
        if key not in self.replies and method not in self.replies:
            raise rc.Rejected("rpc_error:fake.invalid:%s:the method %s does not exist/is not available" % (method, method))
        r = self.replies[key] if key in self.replies else self.replies[method]
        r = r(params) if callable(r) else r
        return self.alter(method, params, copy.deepcopy(r))


def _gz(p):
    with gzip.open(p) as fh:
        return json.loads(fh.read())["result"]


def _jload(p):
    with open(p) as fh:
        return json.load(fh)


@unittest.skipUnless(real_corpus.has_set("real_v03") and real_corpus.has_oracle("blocks_v03"), "needs bundles/real_v03 and oracle/blocks_v03")
class EvmControls(unittest.TestCase):
    """33.4 evm_eip3009 on bundles/real_v03/v001 with the saved block and receipts (oracle/blocks_v03)."""
    FILE = "real_v03/v001_b001_indirect_envelope_reconstructed.json"

    @classmethod
    def setUpClass(cls):
        cls.e = entry(cls.FILE)
        cls.s = MAN["sets"]["real_v03"]
        cls.doc = json.load(open(os.path.join(ROOT, "bundles", cls.FILE)))
        n = cls.e["chain"]["block_number"]
        cls.block = _gz(os.path.join(ROOT, "oracle", "blocks_v03", "%d_block.json.gz" % n))
        cls.receipts = _gz(os.path.join(ROOT, "oracle", "blocks_v03", "%d_receipts.json.gz" % n))

    def rpc(self, alter=None, with_block_receipts=True):
        tx = self.doc["chain_tx"]["tx"]
        hdr = dict(self.block, transactions=[t["hash"] for t in self.block["transactions"]])
        rc_mine = next(r for r in self.receipts if r["transactionHash"].lower() == tx["hash"].lower())

        def logs(params):
            f = params[0]
            out = []
            for r in self.receipts:
                for lg in r["logs"]:
                    if lg["address"].lower() == f["address"].lower() and lg["topics"][0].lower() == f["topics"][0].lower():
                        out.append(lg)
            return out
        rep = {("eth_getBlockByNumber", rc.canon([hex(self.e["chain"]["block_number"]), False])): hdr,
               ("eth_getBlockByNumber", rc.canon([hex(self.e["chain"]["block_number"]), True])): self.block,
               ("eth_getTransactionByHash", rc.canon([tx["hash"]])): tx,
               ("eth_getTransactionReceipt", rc.canon([tx["hash"]])): rc_mine,
               "eth_getLogs": logs}
        if with_block_receipts:
            rep["eth_getBlockReceipts"] = self.receipts
        return FakeRpc(rep, alter)

    def build(self, rpc, e=None):
        return rc.recipe_evm_eip3009(rpc, self.s, e or self.e, rc.Blocks())

    def test_unaltered_rebuilds_to_the_byte(self):
        doc = self.build(self.rpc())
        data = rc.serialize(doc, self.s["serialization"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.e["sha256"])
        self.assertEqual(rc.compare(self.e, self.s, data, doc), "bytes")

    def test_altered_block_hash_in_the_list(self):
        e = copy.deepcopy(self.e)
        e["chain"]["block_hash"] = "0x" + "11" * 32
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(), e)
        self.assertIn("header_hash_mismatch", str(cm.exception))

    def test_altered_transaction_input(self):
        def alter(m, p, r):
            if m == "eth_getTransactionByHash":
                r["input"] = r["input"][:-2] + ("00" if r["input"][-2:] != "00" else "01")
            return r
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter))
        self.assertIn("tx_hash_mismatch", str(cm.exception))

    def test_altered_receipt_log(self):
        tx = self.doc["chain_tx"]["tx"]["hash"].lower()

        def alter(m, p, r):
            if m in ("eth_getBlockReceipts", "eth_getTransactionReceipt"):
                for x in (r if isinstance(r, list) else [r]):
                    if x["transactionHash"].lower() == tx:
                        x["logs"][0]["data"] = "0x" + "00" * 32          # the AuthorizationUsed log carries no data: now it does
            return r
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter))
        # the set no longer recomputes to the receiptsRoot, so the single receipt is read: its keccak is not the list's
        self.assertIn("receipt_hash_mismatch", str(cm.exception))
        # and with no receipt_hash to fall back on, the receipt is unanchored
        e = copy.deepcopy(self.e)
        e["chain"]["receipt_hash"] = None
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter), e)
        self.assertIn("receipt_unanchored", str(cm.exception))

    def test_altered_header_from_the_endpoint(self):
        def alter(m, p, r):
            if m == "eth_getBlockByNumber":
                r["gasUsed"] = hex(int(r["gasUsed"], 16) + 1)
            return r
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter))
        self.assertIn("header_hash_mismatch", str(cm.exception))

    def test_log_outside_the_verified_receipt(self):
        def alter(m, p, r):
            if m == "eth_getLogs":
                for lg in r:
                    lg["topics"][-1] = "0x" + "ab" * 32
            return r
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter))
        self.assertIn("log_not_in_verified_receipt", str(cm.exception))

    def test_without_block_receipts_the_list_anchor_holds(self):
        # inclusion proofs need the whole receipt set: refused without it
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(with_block_receipts=False))
        self.assertIn("inclusion_needs_eth_getBlockReceipts", str(cm.exception))
        # the same payment as an apc-0.2 bundle: the single receipt is accepted on the list's receipt_hash alone
        e = copy.deepcopy(self.e)
        e["bundle_version"] = "apc-0.2"
        e["ours"].pop("inclusion")
        blocks = rc.Blocks()
        doc = rc.recipe_evm_eip3009(self.rpc(with_block_receipts=False), self.s, e, blocks)
        self.assertEqual(doc["bundle_version"], "apc-0.2")
        self.assertEqual(doc["chain_tx"]["log_authorization_used"], self.doc["chain_tx"]["log_authorization_used"])
        blk = blocks.d[(e["network"], e["chain"]["block_hash"])]
        self.assertFalse(blk.receipts_root_verified)
        self.assertIn("no_eth_getBlockReceipts", blk.notes)


@unittest.skipUnless(real_corpus.has_set("real_v03") and real_corpus.has_oracle("blocks_v03"), "needs bundles/real_v03 and oracle/blocks_v03")
class OracleRebuild(EvmControls):
    """33.8: oracle/blocks_v03 rebuilt from the saved block and receipts through the same anchors; tampering refused."""

    def _man(self):
        n = self.e["chain"]["block_number"]
        o = MAN["oracle"]["blocks_v03"]
        return {"format": MAN["format"], "written": MAN["written"], "verifier": MAN["verifier"], "sets": {}, "bundles": [],
                "oracle": {"blocks_v03": dict(o, items=[it for it in o["items"] if it["number"] == n])}}

    def test_unaltered_writes_our_results(self):
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild_oracle(self._man(), self.rpc(), out, log=lambda *a: None)
            row = rep["results"][0]
            self.assertEqual(row["status"], "content", row)
            n = self.e["chain"]["block_number"]
            for suffix in ("_block.json.gz", "_receipts.json.gz"):
                got = _gz(os.path.join(out, "blocks_v03", "%d%s" % (n, suffix)))
                ours = _gz(os.path.join(ROOT, "oracle", "blocks_v03", "%d%s" % (n, suffix)))
                self.assertEqual(rc.canon(got), rc.canon(ours), suffix)

    def test_altered_header_or_receipt_refused(self):
        import tempfile

        def alter_h(m, p, r):
            if m == "eth_getBlockByNumber" and isinstance(r, dict):
                r["gasUsed"] = hex(int(r["gasUsed"], 16) + 1)
            return r

        def alter_r(m, p, r):
            if m == "eth_getBlockReceipts":
                r[0]["cumulativeGasUsed"] = hex(int(r[0]["cumulativeGasUsed"], 16) + 1)
            return r
        for alter, needle in ((alter_h, "header_hash_mismatch"), (alter_r, "receipts_not_in_a_recomputed_root")):
            with tempfile.TemporaryDirectory() as out:
                rep = rc.rebuild_oracle(self._man(), self.rpc(alter), out, log=lambda *a: None)
                self.assertIn(needle, rep["results"][0]["status"])
                self.assertEqual(os.listdir(out), [])


@unittest.skipUnless(real_corpus.has_set("xrp_real_20261026") and real_corpus.has_oracle("xrpl_20261026"), "needs bundles/xrp_real_20261026 and oracle/xrpl_20261026")
class XrplControls(unittest.TestCase):
    FILE = "xrp_real_20261026/030bddfe56be.json"

    @classmethod
    def setUpClass(cls):
        cls.e = entry(cls.FILE)
        cls.s = MAN["sets"]["xrp_real_20261026"]
        idx = cls.e["chain"]["ledger_index"]
        for p in glob.glob(os.path.join(ROOT, "oracle", "xrpl_20261026", "*.json")):
            for c in json.load(open(p))["calls"]:
                if c["params"].get("binary") and c["params"]["ledger_index"] == idx:
                    cls.reply = c["result"]

    def rpc(self, alter=None):
        return FakeRpc({"ledger": self.reply}, alter)

    def test_unaltered_rebuilds_the_content(self):
        doc = rc.recipe_xrpl_exact(self.rpc(), self.s, self.e, {})
        self.assertEqual(rc.content_digest(doc), self.e["content_sha256"])
        self.assertEqual(rc.compare(self.e, self.s, rc.serialize(doc, self.s["serialization"]), doc), "content")

    def test_altered_meta(self):
        def alter(m, p, r):
            t = r["ledger"]["transactions"][0]
            t["meta"] = t["meta"][:-2] + ("00" if t["meta"][-2:] != "00" else "01")
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_xrpl_exact(self.rpc(alter), self.s, self.e, {})
        self.assertIn("transaction_tree_mismatch", str(cm.exception))

    def test_altered_ledger_hash_in_the_list(self):
        e = copy.deepcopy(self.e)
        e["chain"]["ledger_hash"] = "0" * 64
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_xrpl_exact(self.rpc(), self.s, e, {})
        self.assertIn("ledger_hash_mismatch", str(cm.exception))

    def test_altered_ledger_data(self):
        def alter(m, p, r):
            d = r["ledger"]["ledger_data"]
            r["ledger"]["ledger_data"] = d[:-2] + ("00" if d[-2:] != "00" else "01")
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_xrpl_exact(self.rpc(alter), self.s, self.e, {})
        self.assertIn("ledger_hash_mismatch", str(cm.exception))


@unittest.skipUnless(real_corpus.has_set("real_svm"), "needs bundles/real_svm")
class SvmControls(unittest.TestCase):
    FILE = "real_svm/m001_mainnet_payment_20261024.json"

    @classmethod
    def setUpClass(cls):
        cls.e = entry(cls.FILE)
        cls.s = MAN["sets"]["real_svm"]
        ct = json.load(open(os.path.join(ROOT, "bundles", cls.FILE)))["chain_tx"]
        cls.reply = {"slot": ct["slot"], "blockTime": ct["blockTime"], "transaction": [ct["transaction"], "base64"], "meta": ct["meta"]}

    def rpc(self, alter=None):
        return FakeRpc({"getTransaction": self.reply}, alter)

    def test_unaltered_rebuilds_to_the_byte(self):
        doc = rc.recipe_svm_exact(self.rpc(), self.s, self.e, None)
        self.assertEqual(hashlib.sha256(rc.serialize(doc, self.s["serialization"])).hexdigest(), self.e["sha256"])

    def test_altered_message_byte(self):
        def alter(m, p, r):
            raw = bytearray(base64.b64decode(r["transaction"][0]))
            raw[-1] ^= 1                                  # the last byte of the message (instruction data)
            r["transaction"][0] = base64.b64encode(bytes(raw)).decode()
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_svm_exact(self.rpc(alter), self.s, self.e, None)
        self.assertIn("fee_payer_signature_invalid", str(cm.exception))

    def test_altered_execution_record(self):
        def alter(m, p, r):
            r["meta"]["fee"] += 1
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_svm_exact(self.rpc(alter), self.s, self.e, None)
        self.assertIn("chain_tx_not_the_recorded_execution_record", str(cm.exception))

    def test_altered_slot(self):
        def alter(m, p, r):
            r["slot"] += 1
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_svm_exact(self.rpc(alter), self.s, self.e, None)
        self.assertIn("slot_mismatch", str(cm.exception))


@unittest.skipUnless(real_corpus.has_set("real"), "needs the local corpus")
class ListMatchesTheFiles(unittest.TestCase):
    """The digests of the list are the digests of our files, set by set (every set that is here)."""

    def test_sha256_of_every_present_bundle(self):
        n = 0
        for e in MAN["bundles"]:
            p = os.path.join(ROOT, "bundles", e["file"])
            if not os.path.exists(p):
                continue
            data = open(p, "rb").read()
            self.assertEqual(hashlib.sha256(data).hexdigest(), e["sha256"], e["file"])
            self.assertEqual(rc.content_digest(json.loads(data)), e["content_sha256"], e["file"])
            n += 1
        self.assertGreater(n, 0)


class ReviewEd180e0(unittest.TestCase):
    """Review of ed180e0: closed names and paths, no bool for int, CLI hygiene, URL never printed, regress sample."""

    def _refused(self, doc, needle):
        ListClosed._refused(self, doc, needle)

    def _one_set(self, name, file):
        d = copy.deepcopy(MAN)
        e = copy.deepcopy(next(x for x in d["bundles"] if x["set"] == "real"))
        s = copy.deepcopy(d["sets"]["real"])
        s["dir"], s["count"], e["set"], e["file"] = "bundles/" + name, 1, name, file
        d["sets"][name] = s
        d["bundles"].append(e)
        return d

    def test_set_names_and_paths_stay_under_out(self):
        self._refused(self._one_set("", "/tmp/x.json"), "not a set name")
        self._refused(self._one_set("..", "../x.json"), "not a set name")
        d = copy.deepcopy(MAN)
        e = copy.deepcopy(d["bundles"][0])
        e["file"] = e["file"].replace("/", "/./", 1)
        d["bundles"].append(e)
        d["sets"][e["set"]]["count"] += 1
        self._refused(d, "outside bundles/")

    def test_bool_is_not_an_int_and_params_closed(self):
        d = copy.deepcopy(MAN)
        d["bundles"][0]["chain"]["block_number"] = True
        self._refused(d, "wrong type")
        d = copy.deepcopy(MAN)
        d["sets"]["real"]["serialization"]["indent"] = True
        self._refused(d, "wrong type")
        d = copy.deepcopy(MAN)
        d["sets"]["real"]["params"]["anything"] = 1
        self._refused(d, "sets.real.params.anything")

    def _main(self, *args, env=None):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.dict(os.environ, env or {}, clear=False):
            code = rc.main(["rebuild_corpus.py"] + list(args))
        return code, out.getvalue() + err.getvalue()

    def test_cli_hygiene(self):
        base = ["--rpc", "eip155:8453=https://h.invalid/", "--out", "/nonexistent-review"]
        for rate in ("0", "-1", "nan", "6"):
            self.assertEqual(self._main(*base, "--rate", rate)[0], 64, rate)
        for sample in ("0", "-1"):
            self.assertEqual(self._main(*base, "--sample", sample)[0], 64, sample)
        code, text = self._main(*base, "--only", "no_such_set")
        self.assertEqual(code, 64)
        self.assertIn("no_such_set", text)
        code, text = self._main("--rpc", "eip155:8453=mainnet.example.invalid/v3/SECRETKEY", "--only", "real")
        self.assertEqual(code, 64)
        self.assertNotIn("SECRETKEY", text)
        code, text = self._main("--only", "real", env={"APC_RPC_eip155_8453": "host.invalid/SECRETKEY"})
        self.assertEqual(code, 64)
        self.assertNotIn("SECRETKEY", text)

    def test_url_never_in_a_refusal(self):
        r = rc.Rpc({"eip155:8453": "host.invalid/v3/SECRETKEY"})
        with self.assertRaises(rc.Rejected) as cm:
            r.call("eip155:8453", "eth_chainId", [])
        self.assertNotIn("SECRETKEY", str(cm.exception))

    def test_regress_sample_does_not_pass_on_an_empty_corpus(self):
        import tempfile
        from tools import regress as rg
        with tempfile.TemporaryDirectory() as d, mock.patch.object(rg, "ROOT", d):
            os.makedirs(os.path.join(d, "bundles"))
            with self.assertRaises(rg.Refused) as cm:         # an empty bundles/ is refused with the reason, not 0 differences
                rg.check(sample=True, log=lambda *a: None)
            self.assertIn("rebuild_corpus.py", str(cm.exception))
            # one bundle of 1094: the sample is drawn from the frozen corpus, so the missing ones are `removed`
            src = next(e["file"] for e in MAN["bundles"] if e["set"] == "real")
            if os.path.exists(os.path.join(ROOT, "bundles", src)):
                os.makedirs(os.path.join(d, "bundles", "real"))
                with open(os.path.join(ROOT, "bundles", src), "rb") as a, open(os.path.join(d, "bundles", src), "wb") as b:
                    b.write(a.read())
                with mock.patch.object(rg, "REG", os.path.join(ROOT, "regress")):
                    now, diff, bad = rg.check(sample=True, log=lambda *a: None)
                self.assertGreater(len(bad), 0)

    def test_star_means_the_rebuildable_sets(self):
        listed = real_corpus.sets_listed()
        for n, st in MAN["sets"].items():
            self.assertEqual(n in listed, st["rebuild"] != "local_only", n)

    def test_oracle_skip_reasons(self):
        with mock.patch.dict(os.environ, {"APC_CORPUS_PRETEND_MISSING": "oracle/blocks_v03,oracle/negatives_20261026,oracle/nowhere_x"}):
            with self.assertRaises(unittest.SkipTest) as cm:
                real_corpus.need(oracle=("blocks_v03", "negatives_20261026", "nowhere_x"))
        msg = str(cm.exception)
        self.assertIn("--oracle blocks_v03", msg)
        self.assertIn("oracle/negatives_20261026 is local_only in the list: not rebuilt by this version", msg)
        self.assertIn("oracle/nowhere_x is not in the list", msg)
        self.assertNotIn("--oracle negatives_20261026", msg)

    def test_local_only_skip_names_no_rebuild(self):
        with mock.patch.dict(os.environ, {"APC_CORPUS_PRETEND_MISSING": "real_v03_canonical"}):
            with self.assertRaises(unittest.SkipTest) as cm:
                real_corpus.need("real_v03_canonical")
        self.assertNotIn("--only real_v03_canonical", str(cm.exception))
        self.assertIn("local_only", str(cm.exception))


@unittest.skipUnless(real_corpus.has_set("real_v03") and real_corpus.has_oracle("blocks_v03"), "needs bundles/real_v03 and oracle/blocks_v03")
class ReviewHostileEndpoint(EvmControls):
    """Members a hostile endpoint could invent that no fingerprint covers (ed180e0): refused now."""

    def test_from_not_the_signer(self):
        def alter(m, p, r):
            if m == "eth_getTransactionByHash":
                r["from"] = "0x" + "de" * 20
            return r
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter))
        self.assertIn("tx_from_is_not_the_signer", str(cm.exception))

    def test_removed_or_foreign_log(self):
        for k, v in (("removed", True), ("blockHash", "0x" + "00" * 32), ("blockNumber", "0x1")):
            def alter(m, p, r, k=k, v=v):
                if m == "eth_getLogs":
                    for lg in r:
                        lg[k] = v
                return r
            with self.assertRaises(rc.Rejected) as cm:
                self.build(self.rpc(alter))
            self.assertIn("log_not_at_pinned_block", str(cm.exception), k)

    def test_header_not_recomputable_off_the_listed_networks(self):
        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and isinstance(r, dict):
                r.pop("withdrawalsRoot", None)
            return r
        e = copy.deepcopy(self.e)             # apc-0.2: no inclusion, so only the header read by number decides
        e["bundle_version"] = "apc-0.2"
        e["ours"].pop("inclusion")
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter), e)
        self.assertIn("header_refused", str(cm.exception))

    def test_mismatch_not_written_and_existing_file_checked(self):
        import tempfile
        man = {"format": MAN["format"], "written": MAN["written"], "verifier": MAN["verifier"],
               "sets": {"real_v03": self.s}, "bundles": [self.e]}

        def alter(m, p, r):
            if m == "eth_getLogs":
                for lg in r:
                    lg["blockTimestamp"] = "0x1"
            return r
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild(man, self.rpc(alter), out, log=lambda *a: None)
            row = rep["results"][0]
            self.assertFalse(row["ok"])
            self.assertFalse(row["written"])
            self.assertFalse(os.path.exists(os.path.join(out, self.FILE)))
            path = os.path.join(out, self.FILE)
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as fh:
                fh.write('{"corrupt": true}')
            rep = rc.rebuild(man, self.rpc(), out, log=lambda *a: None)
            self.assertFalse(rep["results"][0]["ok"])
            self.assertEqual(rep["summary"]["below_declared_level"], 1)


@unittest.skipUnless(real_corpus.has_set("real_v03") and real_corpus.has_oracle("blocks_v03"), "needs bundles/real_v03 and oracle/blocks_v03")
class ReviewEachFingerprint(EvmControls):
    """Each fingerprint of 33.4 refuses on its own, with its own reason (mutants that lived on ed180e0's tests)."""

    def _apc02(self):
        e = copy.deepcopy(self.e)
        e["bundle_version"] = "apc-0.2"
        e["ours"].pop("inclusion")
        return e

    def _refused(self, needle, alter=None, e=None, **kw):
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter, **kw), e)
        self.assertIn(needle, str(cm.exception))

    def test_header_recomputed_without_inclusion(self):
        def alter(m, p, r):
            if m == "eth_getBlockByNumber":
                r["gasUsed"] = hex(int(r["gasUsed"], 16) + 1)
            return r
        self._refused("header_hash_mismatch", alter, self._apc02())

    def test_declared_header_states_the_pinned_hash(self):
        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and isinstance(r, dict):
                r.pop("withdrawalsRoot", None)
                r["hash"] = "0x" + "22" * 32
            return r
        with mock.patch.object(rc, "HEADER_DECLARED_NETWORKS", (self.e["network"],)):
            self._refused("header_hash_mismatch:stated", alter, self._apc02())

    def test_declared_header_receipts_root_anchors_nothing(self):
        """P10: on a declared-network header the receiptsRoot read from it anchors nothing; the receipt then rests on the
        list's receipt_hash and the report says so."""
        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and isinstance(r, dict):
                r.pop("withdrawalsRoot", None)
            return r
        blocks = rc.Blocks()
        with mock.patch.object(rc, "HEADER_DECLARED_NETWORKS", (self.e["network"],)):
            doc = rc.recipe_evm_eip3009(self.rpc(alter), self.s, self._apc02(), blocks)
        blk = blocks.d[(self.e["network"], self.e["chain"]["block_hash"])]
        self.assertFalse(blk.receipts_root_verified)
        self.assertIn("receipts_root_of_a_declared_header", blk.notes)
        self.assertEqual(doc["chain_tx"]["log_authorization_used"], self.doc["chain_tx"]["log_authorization_used"])

    def test_transaction_position(self):
        def alter(m, p, r):
            if m == "eth_getTransactionByHash":
                r["transactionIndex"] = hex(int(r["transactionIndex"], 16) + 1)
            return r
        self._refused("tx_not_at_pinned_position", alter)

        def alter2(m, p, r):
            if m == "eth_getBlockByNumber" and not p[1]:
                r["transactions"] = list(reversed(r["transactions"]))
            return r
        self._refused("tx_not_in_block_at_index", alter2)

    def test_receipt_of_the_root_set_against_the_list(self):
        e = copy.deepcopy(self.e)
        e["chain"]["receipt_hash"] = "0x" + "33" * 32
        self._refused("receipt_hash_mismatch_with_list", None, e)

    def test_log_data_outside_the_verified_receipt(self):
        def alter(m, p, r):
            if m == "eth_getLogs":
                for lg in r:
                    lg["data"] = "0x" + "44" * 32
            return r
        self._refused("log_not_in_verified_receipt", alter)


@unittest.skipUnless(real_corpus.has_set("real_svm"), "needs bundles/real_svm")
class ReviewSvmReasons(SvmControls):
    def test_first_signature_and_fee_payer(self):
        e = copy.deepcopy(self.e)
        e["chain"]["signature"] = "1" * 64
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_svm_exact(self.rpc(), self.s, e, None)
        self.assertIn("first_signature_is_not_the_pinned_id", str(cm.exception))
        # format 0.2: no fee payer in the list; account 0 is derived and its signature must verify (SvmControls)
        self.assertNotIn("fee_payer", self.e["chain"])

    def test_message_without_accounts(self):
        def alter(m, p, r):
            raw = base64.b64decode(r["transaction"][0])
            sig = raw[1:65]                                   # the pinned id, then a legacy message with no account
            msg = bytes([1, 0, 0]) + bytes([0]) + bytes(32) + bytes([0])
            r["transaction"][0] = base64.b64encode(bytes([1]) + sig + msg).decode()
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_svm_exact(self.rpc(alter), self.s, self.e, None)
        self.assertIn("message_without_accounts", str(cm.exception))


@unittest.skipUnless(real_corpus.has_set("xrp_real_20261026") and real_corpus.has_oracle("xrpl_20261026"), "needs bundles/xrp_real_20261026 and oracle/xrpl_20261026")
class ReviewXrplReasons(XrplControls):
    def test_tx_not_in_the_ledger(self):
        e = copy.deepcopy(self.e)
        e["chain"]["tx_hash"] = "AB" * 32
        with self.assertRaises(rc.Rejected) as cm:
            rc.recipe_xrpl_exact(self.rpc(), self.s, e, {})
        self.assertIn("tx_not_in_ledger", str(cm.exception))


class Review6d069a3(unittest.TestCase):
    """Review of 6d069a3 (33.8): the oracle section closed, nothing below `content` written, XRPL replies whole."""

    def _refused(self, doc, needle):
        ListClosed._refused(self, doc, needle)

    def test_oracle_section_closed(self):
        cases = [
            (lambda d: d["oracle"]["xrpl_20261026"].__setitem__("file", "../../x.json"), "one file name"),
            (lambda d: d["oracle"]["xrpl_20261026"].__setitem__("file", "/tmp/x.json"), "one file name"),
            (lambda d: d["oracle"]["xrpl_20261026"].__setitem__("file", "mainnet_ledgers.json\n"), "one file name"),
            (lambda d: d["oracle"]["blocks_v03"].__setitem__("files", ["/etc/x"]), "evm_blocks wants files"),
            (lambda d: d["oracle"]["blocks_v03"].__setitem__("kind", "evm_block"), "kind: unknown"),
            (lambda d: d["oracle"]["blocks_v03"]["result_sha256"].update({k: v.upper() for k, v in list(d["oracle"]["blocks_v03"]["result_sha256"].items())[:1]}), "not 64 lowercase hex"),
            (lambda d: d["oracle"]["blocks_v03"]["items"][0].__setitem__("hash", d["oracle"]["blocks_v03"]["items"][0]["hash"].upper()), "malformed"),
            (lambda d: d["oracle"]["blocks_v03"]["items"][0].__setitem__("number", -1), "malformed"),
            (lambda d: d["oracle"]["xrpl_20261026"]["items"][0].__setitem__("ledger_hash", d["oracle"]["xrpl_20261026"]["items"][0]["ledger_hash"].lower()), "malformed"),
            (lambda d: d["oracle"]["xrpl_20261026"]["items"][0].__setitem__("ledger_index", True), "wrong type"),
            (lambda d: d["oracle"]["blocks_v03"].pop("items"), "items: missing"),
            (lambda d: d["oracle"]["xrpl_20261026"].pop("network"), "network: missing"),
            (lambda d: d["oracle"]["xrpl_20261026"].pop("result_sha256"), "result_sha256: missing"),
            (lambda d: d["oracle"]["blocks_v03"].__setitem__("network", "eip155:\u0668\u0664"), "evm_blocks wants files"),
            (lambda d: d["oracle"]["xrpl_20261026"].__setitem__("items", []), "items: empty"),
            (lambda d: d["oracle"]["xrpl_20261026"]["items"].append(dict(d["oracle"]["xrpl_20261026"]["items"][0])), "items repeated"),
            (lambda d: d["oracle"]["blocks_v03"].__setitem__("result_sha256", {}), "one digest per file"),
            (lambda d: d["oracle"]["xrpl_20261026"]["result_sha256"].__setitem__("1", "0" * 64), "one digest per file"),
            (lambda d: d["oracle"]["xrpl_20261026"].__setitem__("read_by", [1]), "read_by"),
            (lambda d: d["oracle"]["world_20261026"].__setitem__("network", "eip155:1"), "only those"),
            (lambda d: d["oracle"].__setitem__("a*b", dict(d["oracle"]["xrpl_20261026"])), "names one directory"),
            (lambda d: d["oracle"].__setitem__("blocks_v03\n", d["oracle"].pop("blocks_v03")), "not an oracle name"),
        ]
        for mut, needle in cases:
            d = copy.deepcopy(MAN)
            mut(d)
            self._refused(d, needle)

    def test_trailing_newline_is_not_a_name_nor_a_digest(self):
        d = copy.deepcopy(MAN)
        e = next(x for x in d["bundles"] if x["set"] == "real")
        e["sha256"] += "\n"
        self._refused(d, "a digest is not 64 lowercase hex")
        d = copy.deepcopy(MAN)
        d["sets"]["real\n"] = d["sets"].pop("real")
        self._refused(d, "not a set name")

    def test_cli_oracle(self):
        main = ReviewEd180e0._main
        r = ("--rpc", "eip155:8453=https://h.invalid/", "--out-oracle", "/nonexistent-review")
        no_network = mock.patch.object(rc.Rpc, "call", side_effect=AssertionError("a refused option reached the network"))
        no_network.start()
        self.addCleanup(no_network.stop)
        code, text = main(self, *r, "--oracle", "world_20261026")
        self.assertEqual(code, 64)
        self.assertIn("local_only", text)
        code, text = main(self, *r, "--oracle", "blocks_v03", "--only", "real")
        self.assertEqual(code, 64)
        code, text = main(self, *r, "--oracle", "blocks_v03", "--sample", "1")
        self.assertEqual(code, 64)
        for bad in ("no_such_dir", ",", "blocks_v03,no_such_dir"):
            code, text = main(self, *r, "--oracle", bad)
            self.assertEqual(code, 64, bad)
            self.assertIn("names nothing the list holds", text)


@unittest.skipUnless(real_corpus.has_set("real_v03") and real_corpus.has_oracle("blocks_v03"), "needs bundles/real_v03 and oracle/blocks_v03")
class ReviewOracleBelowContent(OracleRebuild):
    def test_member_outside_the_fingerprints_not_written(self):
        import tempfile

        def alter(m, p, r):
            if m == "eth_getBlockReceipts":
                for x in r:
                    x["from"] = "0x" + "de" * 20
                    for lg in x["logs"]:
                        lg["removed"] = True
            return r
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild_oracle(self._man(), self.rpc(alter), out, log=lambda *a: None)
            self.assertEqual(rep["results"][0]["status"], "anchored")
            self.assertEqual(os.listdir(out), [])

    def test_declared_header_network_refused(self):
        import tempfile
        man = self._man()
        man["oracle"]["blocks_v03"]["network"] = "eip155:43114"     # a network whose header may be declared (33.4)

        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and isinstance(r, dict) and not p[1]:
                r.pop("withdrawalsRoot", None)       # the header-only reply no longer recomputes; the full one does
            return r
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild_oracle(man, self.rpc(alter), out, log=lambda *a: None)
            self.assertEqual(rep["results"][0]["status"], "refused:header_not_recomputed")
            self.assertEqual(os.listdir(out), [])

    def test_transaction_not_hashing_to_its_id_refused(self):
        import tempfile

        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and p[1]:
                t = r["transactions"][-1]
                t["value"] = hex(int(t["value"], 16) + 1)          # in the RLP, not in the header: only the re-encoding sees it
            return r
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild_oracle(self._man(), self.rpc(alter), out, log=lambda *a: None)
            self.assertIn("block_refused:tx_encoding_does_not_hash_to_rpc_hash", rep["results"][0]["status"])
            self.assertEqual(os.listdir(out), [])

    def test_existing_file_is_compared(self):
        import tempfile
        n = self.e["chain"]["block_number"]
        with tempfile.TemporaryDirectory() as out:
            os.makedirs(os.path.join(out, "blocks_v03"))
            path = os.path.join(out, "blocks_v03", "%d_block.json.gz" % n)
            with gzip.open(path, "wb") as fh:
                fh.write(b'{"result": {"corrupted": true}}')
            rep = rc.rebuild_oracle(self._man(), self.rpc(), out, log=lambda *a: None)
            self.assertIn("existing_file_differs", rep["results"][0]["status"])
            self.assertEqual(_gz(path), {"corrupted": True})
        import shutil
        with tempfile.TemporaryDirectory() as out:                     # our own files (a copy) count as ours
            os.makedirs(os.path.join(out, "blocks_v03"))
            for suffix in ("_block.json.gz", "_receipts.json.gz"):
                shutil.copy(os.path.join(ROOT, "oracle", "blocks_v03", "%d%s" % (n, suffix)), os.path.join(out, "blocks_v03"))
            rep = rc.rebuild_oracle(self._man(), self.rpc(), out, log=lambda *a: None)
        self.assertEqual(rep["results"][0]["status"], "content")
        self.assertEqual({f["written"] for f in rep["results"][0]["files"].values()}, {False})     # not rewritten without --force


@unittest.skipUnless(real_corpus.has_oracle("xrpl_20261026"), "needs oracle/xrpl_20261026")
class ReviewOracleXrpl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "oracle", "xrpl_20261026", "mainnet_ledgers.json")) as fh:
            cls.calls = json.load(fh)["calls"]
        o = MAN["oracle"]["xrpl_20261026"]
        it = o["items"][0]
        cls.man = {"format": MAN["format"], "written": MAN["written"], "verifier": MAN["verifier"], "sets": {}, "bundles": [],
                   "oracle": {"xrpl_20261026": dict(o, items=[it], result_sha256={str(it["ledger_index"]): o["result_sha256"][str(it["ledger_index"])]})}}

    def rpc(self, alter=None):
        def ledger(params):
            for c in self.calls:
                if c["params"].get("ledger_index") == params["ledger_index"] and bool(c["params"].get("binary")) == bool(params.get("binary")):
                    return c["result"]
            raise rc.Rejected("not saved")
        return FakeRpc({"ledger": ledger}, alter)

    def _run(self, alter=None):
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild_oracle(self.man, self.rpc(alter), out, log=lambda *a: None)
            return rep["results"][0], sorted(os.listdir(out))

    def test_unaltered_is_content_and_written(self):
        row, files = self._run()
        self.assertEqual(row["status"], "content", row)
        self.assertEqual(files, ["xrpl_20261026"])

    def test_recipe_errors_are_its_row(self):      # review 2026-11-02 (33.11): the second oracle recipe, SHAPE_ERRORS too
        for exc in (RecursionError("deep"), OverflowError("int too big to convert"), AttributeError("no attribute")):
            with mock.patch.object(rc, "Ledger", side_effect=exc):
                row, files = self._run()
            self.assertEqual((row["status"], files), ("refused:reply_shape:%s:%s" % (type(exc).__name__, exc), []))

    def test_json_reply_member_not_written(self):
        def alter(m, p, r):
            if not p.get("binary"):
                r["ledger"]["close_time"] = 1
            return r
        row, files = self._run(alter)
        self.assertEqual(row["status"], "anchored")
        self.assertEqual(files, [])

    def test_binary_reply_outer_member_not_written(self):
        def alter(m, p, r):
            if p.get("binary"):
                r["validated"] = False
            return r
        row, files = self._run(alter)
        self.assertEqual(row["status"], "anchored")
        self.assertEqual(files, [])

    def test_existing_file_is_compared(self):
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            os.makedirs(os.path.join(out, "xrpl_20261026"))
            path = os.path.join(out, "xrpl_20261026", "mainnet_ledgers.json")
            with open(path, "w") as fh:
                fh.write('{"calls": []}')
            rep = rc.rebuild_oracle(self.man, self.rpc(), out, log=lambda *a: None)
            self.assertIn("existing_file_differs", rep["results"][0]["status"])
            with open(path) as fh:
                self.assertEqual(fh.read(), '{"calls": []}')
        # a file holding the first ledger only, for a list of two: not ours
        o = MAN["oracle"]["xrpl_20261026"]
        two = copy.deepcopy(self.man)
        two["oracle"]["xrpl_20261026"]["items"] = o["items"][:2]
        two["oracle"]["xrpl_20261026"]["result_sha256"] = {str(it["ledger_index"]): o["result_sha256"][str(it["ledger_index"])] for it in o["items"][:2]}
        first = o["items"][0]["ledger_index"]
        with tempfile.TemporaryDirectory() as out:
            os.makedirs(os.path.join(out, "xrpl_20261026"))
            with open(os.path.join(out, "xrpl_20261026", "mainnet_ledgers.json"), "w") as fh:
                json.dump({"calls": [c for c in self.calls if c["params"].get("ledger_index") == first]}, fh)
            rep = rc.rebuild_oracle(two, self.rpc(), out, log=lambda *a: None)
            self.assertIn("existing_file_differs", rep["results"][0]["status"])
        # our own file (25 calls, one more than a rebuild writes) counts as ours; a copy, never oracle/ itself
        import shutil
        with tempfile.TemporaryDirectory() as out:
            shutil.copytree(os.path.join(ROOT, "oracle", "xrpl_20261026"), os.path.join(out, "xrpl_20261026"))
            rep = rc.rebuild_oracle(self.man, self.rpc(), out, log=lambda *a: None)
        self.assertEqual(rep["results"][0]["status"], "content")
        self.assertFalse(rep["results"][0]["written"])

    def test_cli_exit_code(self):
        import tempfile
        saved = self.rpc()

        def call(alter):
            def f(rpc, network, method, params, xrpl=False):
                r = saved.call(network, method, params, xrpl)
                return alter(method, params, r) if alter else r
            return f

        def alter(m, p, r):
            if not p.get("binary"):
                r["validated"] = False
            return r
        for alt, want in ((None, 0), (alter, 1)):
            with tempfile.TemporaryDirectory() as out, mock.patch.object(rc.Rpc, "call", call(alt)):
                code, text = ReviewEd180e0._main(self, "--oracle", "xrpl_20261026", "--rpc", "xrpl:0=https://h.invalid/",
                                                  "--out-oracle", out)
            self.assertEqual(code, want, text)

    def test_json_header_hash_refused(self):
        for where, key, value in (("ledger", "account_hash", "0" * 64), ("ledger", "transaction_hash", "0" * 64),
                                  ("ledger", "parent_hash", "0" * 64), ("ledger", "ledger_hash", "0" * 64),
                                  ("ledger", "ledger_index", "1"), ("top", "ledger_hash", "0" * 64)):
            def alter(m, p, r, where=where, key=key, value=value):
                if not p.get("binary"):
                    (r["ledger"] if where == "ledger" else r)[key] = value
                return r
            row, files = self._run(alter)
            self.assertIn("ledger_json_reply_mismatch", row["status"], (where, key))
            self.assertEqual(files, [])


@unittest.skipUnless(real_corpus.has_set("real_msca_20261101"), "needs bundles/real_msca_20261101")
class ReviewDerivedOwner(unittest.TestCase):
    """33.2/33.4 (format 0.2): the MSCA owner is read from the state and accepted only on the list's owner_keccak; the
    payer is the address the AuthorizationUsed log names (the bundle's payload `from`), not the transaction's sender."""

    @classmethod
    def setUpClass(cls):
        cls.e = next(b for b in MAN["bundles"] if (b.get("ours") or {}).get("payer_state") == "rpc")
        with open(os.path.join(ROOT, "bundles", cls.e["file"])) as fh:
            cls.doc = json.load(fh)
        cls.payer = cls.doc["payment_payload"]["payload"]["authorization"]["from"]

    def rpc(self, alter=None):
        w = self.doc["payer_state"]["rpc"]
        calls = [w["code"]] + list(w["wallet"].values())
        return FakeRpc({(c["method"], rc.canon(c["params"])): c["result"] for c in calls}, alter)

    def blk(self):
        return type("B", (), {"network": self.e["network"], "number": self.e["chain"]["block_number"]})()

    def test_payer_is_not_the_sender(self):
        self.assertNotEqual(self.payer.lower(), self.doc["chain_tx"]["tx"]["from"].lower())
        self.assertEqual("0x" + self.doc["chain_tx"]["log_authorization_used"]["topics"][1][-40:], self.payer.lower())

    def test_unaltered_state_rebuilds(self):
        got = rc.payer_state(self.rpc(), self.blk(), self.e["chain"]["state"], "rpc", self.payer)
        self.assertEqual(rc.canon(got), rc.canon(self.doc["payer_state"]))

    def test_owner_keccak_decides(self):
        st = dict(self.e["chain"]["state"], owner_keccak="0" * 64)
        with self.assertRaises(rc.Rejected) as cm:
            rc.payer_state(self.rpc(), self.blk(), st, "rpc", self.payer)
        self.assertIn("payer_state_rpc_addresses_mismatch", str(cm.exception))

        def alter(m, p, r):
            if m == "eth_getStorageAt" and p[1] != "0x%064x" % __import__("apc_msca").ERC1967_SLOT:
                return "0x%064x" % (int(r, 16) ^ (1 << 40))              # another owner in the slot
            return r
        with self.assertRaises(rc.Rejected) as cm:
            rc.payer_state(self.rpc(alter), self.blk(), self.e["chain"]["state"], "rpc", self.payer)
        self.assertIn("payer_state_rpc_addresses_mismatch", str(cm.exception))

    def test_state_members_closed(self):
        d = copy.deepcopy(MAN)
        e = next(b for b in d["bundles"] if b["file"] == self.e["file"])
        e["chain"]["state"].pop("code_keccak")
        ListClosed._refused(self, d, "code_keccak")
        d = copy.deepcopy(MAN)
        e = next(b for b in d["bundles"] if b["file"] == self.e["file"])
        e["chain"]["state"]["owner_keccak"] = e["chain"]["state"]["owner_keccak"].upper()
        ListClosed._refused(self, d, "owner_keccak: not 64 lowercase hex")


@unittest.skipUnless(real_corpus.has_set("real_msca_20261101") and real_corpus.has_oracle("msca_20261101/raw")
                     and real_corpus.has_oracle("msca_20261101/anchor"), "needs bundles/real_msca_20261101 and oracle/msca_20261101 (raw, anchor)")
class AnchoredControls(unittest.TestCase):
    """33.10: the anchored bundle m001 rebuilt from the saved L2 replies (oracle/msca_20261101/raw, /anchor) and the saved
    L1 fetch (anchor/l1proof_*.json) through the fake endpoint: unaltered, to the byte and chain_verified at
    finality_proven under the checkpoint; every alteration of a thing that is proven is refused with its reason."""
    FILE = "real_msca_20261101/m001_anchored_0119601b_envelope_reconstructed.json"

    @classmethod
    def setUpClass(cls):
        cls.e = entry(cls.FILE)
        cls.s = MAN["sets"]["real_msca_20261101"]
        with open(os.path.join(ROOT, "bundles", cls.FILE)) as fh:
            cls.doc = json.load(fh)
        cls.n = cls.e["chain"]["block_number"]
        cls.a = cls.e["chain"]["anchor"]
        cls.bh = hex(cls.a["l1_block_number"])
        R = os.path.join(ROOT, "oracle", "msca_20261101", "raw")
        A = os.path.join(ROOT, "oracle", "msca_20261101", "anchor")
        cls.block = _gz(os.path.join(R, "%d_block.json.gz" % cls.n))
        cls.receipts = _gz(os.path.join(R, "%d_receipts.json.gz" % cls.n))
        cls.parent = _gz(os.path.join(R, "%d_header.json.gz" % (cls.n - 1)))
        cls.l2_proofs, cls.l2_codes = {}, {}
        for b in (cls.n - 1, cls.n):
            for q in glob.glob(os.path.join(R, "%d_proof_0x*.json.gz" % b)):
                cls.l2_proofs[(os.path.basename(q)[len("%d_proof_" % b):-len(".json.gz")], hex(b))] = _gz(q)
        for q in glob.glob(os.path.join(R, "%d_code_0x*.json.gz" % cls.n)):
            cls.l2_codes[(os.path.basename(q)[len("%d_code_" % cls.n):-len(".json.gz")], hex(cls.n))] = _gz(q)
        cls.hdrs = {int(os.path.basename(q)[4:-8]): _gz(q) for q in glob.glob(os.path.join(A, "hdr_*.json.gz"))}
        cls.l1 = {}
        for q in glob.glob(os.path.join(A, "l1proof_*.json")):
            with open(q) as fh:
                d = json.load(fh)
            cls.l1[d["game"]] = d
        cls.games = sorted(cls.l1)

    def rpc(self, alter=None):
        tx = self.doc["chain_tx"]["tx"]
        hdr = dict(self.block, transactions=[t["hash"] for t in self.block["transactions"]])
        T = self

        def logs(params):
            f = params[0]
            return [lg for r in T.receipts for lg in r["logs"]
                    if lg["address"].lower() == f["address"].lower() and lg["topics"][0].lower() == f["topics"][0].lower()]

        def by_number(params):
            if params[1] is True:
                return T.block
            if params[0] == T.bh:                                     # L1: the checkpoint header
                return T.l1[T.games[0]]["header"]
            b = int(params[0], 16)
            return {T.n: hdr, T.n - 1: T.parent}.get(b) or T.hdrs[b]   # KeyError: not saved (reply_shape in the driver)

        def proof(params):
            addr, slots, blk = params[0].lower(), params[1], params[2]
            if blk == T.bh:
                same = [pf for d in T.l1.values() for pf in d["proofs"].values() if pf["address"].lower() == addr]
                exact = [pf for pf in same if [sp["key"] for sp in pf["storageProof"]] == slots]
                if exact or same:        # other slots asked (an altered reply moved a key): the saved proof, as a node
                    return (exact or same)[0]     # would answer with proofs of the slots asked, which are then not read
                raise rc.Rejected("rpc_error:fake.invalid:eth_getProof:not saved")
            return T.l2_proofs[(addr, blk)]

        def code(params):
            addr, blk = params[0].lower(), params[1]
            if blk == T.bh:
                for d in T.l1.values():
                    for k, who in (("game", d["game"]), ("impl", d["impl"])):
                        if who.lower() == addr:
                            return d["codes"][k]
                raise rc.Rejected("rpc_error:fake.invalid:eth_getCode:not saved")
            return T.l2_codes[(addr, blk)]

        def call(params):
            to, data = params[0]["to"].lower(), params[0]["data"].lower()
            for d in T.l1.values():
                for c in d["calls"]:
                    if c["to"].lower() == to and c["data"].lower() == data:
                        return c["result"]
            raise rc.Rejected("rpc_error:fake.invalid:eth_call:not saved")
        rep = {"eth_getBlockByNumber": by_number, "eth_getBlockReceipts": self.receipts, "eth_getLogs": logs,
               ("eth_getTransactionByHash", rc.canon([tx["hash"]])): tx, "eth_getProof": proof, "eth_getCode": code,
               "eth_call": call}
        return FakeRpc(rep, alter)

    def build(self, rpc, e=None, blocks=None):
        return rc.recipe_evm_eip3009(rpc, self.s, e or self.e, blocks or rc.Blocks())

    def _refused(self, needle, alter=None, e=None):
        with self.assertRaises(rc.Rejected) as cm:
            self.build(self.rpc(alter), e)
        self.assertIn(needle, str(cm.exception))
        return str(cm.exception)

    def test_unaltered_rebuilds_to_the_byte_and_verifies(self):
        rpc = self.rpc()
        doc = self.build(rpc)
        data = rc.serialize(doc, self.s["serialization"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.e["sha256"])
        self.assertEqual(rc.compare(self.e, self.s, data, doc), "bytes")
        self.assertEqual(self.s["params"]["options"]["l1_checkpoint"], self.a["l1_block_hash"])
        rep = __import__("apc_verify").verify_bundle(json.loads(data), l1_checkpoint=self.a["l1_block_hash"])
        self.assertEqual((rep["verdict"], rep["evidence_level"], rep["checks"]["O4"], rep["checks"]["L1"], rep["canonical"], rep["l1_state"]),
                         ("chain_verified", "finality_proven", "verified", "verified", "final", "proven"))
        # without the checkpoint the same bytes are not finality_proven: the anchor is the reader's, not the file's
        rep0 = __import__("apc_verify").verify_bundle(json.loads(data))
        self.assertNotEqual(rep0["evidence_level"], "finality_proven")
        # the L1 side is fetched once per (L1 block, game) and each L2 header once, across the 28 bundles (33.10)
        blocks = rc.Blocks()
        rpc = self.rpc()
        self.build(rpc, blocks=blocks)
        n1 = rpc.calls
        twin = next(b for b in MAN["bundles"] if b["set"] == self.e["set"] and "anchor" in b["chain"]
                    and b["chain"]["anchor"]["game"] == self.a["game"] and b["file"] != self.FILE)
        with mock.patch.object(AnchoredControls, "block", _gz(os.path.join(ROOT, "oracle", "msca_20261101", "raw", "%d_block.json.gz" % twin["chain"]["block_number"]))), \
                mock.patch.object(AnchoredControls, "receipts", _gz(os.path.join(ROOT, "oracle", "msca_20261101", "raw", "%d_receipts.json.gz" % twin["chain"]["block_number"]))), \
                mock.patch.object(AnchoredControls, "parent", _gz(os.path.join(ROOT, "oracle", "msca_20261101", "raw", "%d_header.json.gz" % (twin["chain"]["block_number"] - 1)))), \
                mock.patch.object(AnchoredControls, "n", twin["chain"]["block_number"]), \
                mock.patch.object(AnchoredControls, "doc", _jload(os.path.join(ROOT, "bundles", twin["file"]))):
            R = os.path.join(ROOT, "oracle", "msca_20261101", "raw")
            for b in (self.n - 1, self.n):
                for q in glob.glob(os.path.join(R, "%d_proof_0x*.json.gz" % b)):
                    self.l2_proofs[(os.path.basename(q)[len("%d_proof_" % b):-len(".json.gz")], hex(b))] = _gz(q)
            for q in glob.glob(os.path.join(R, "%d_code_0x*.json.gz" % self.n)):
                self.l2_codes[(os.path.basename(q)[len("%d_code_" % self.n):-len(".json.gz")], hex(self.n))] = _gz(q)
            rpc2 = self.rpc()
            doc2 = self.build(rpc2, twin, blocks)
        self.assertEqual(hashlib.sha256(rc.serialize(doc2, self.s["serialization"])).hexdigest(), twin["sha256"])
        self.assertEqual(sum(1 for m, p in rpc2.log if self.bh in (p[0], p[-1])), 0)    # no L1 call the second time
        self.assertLess(rpc2.calls, n1)

    def test_l1_refusal_kept_for_the_other_bundles_of_the_game(self):
        # the first bundle meets an endpoint that refuses the archive eth_call (measured 2026-11-02, 33.10): the refusal
        # is kept per (L1 block, game) and the second bundle of the same game is refused without asking the L1 again
        def alter(m, p, r):
            if m == "eth_call" and p[1] == self.bh:
                raise rc.Rejected("rpc_error:fake.invalid:eth_call:archive requests need a token")
            return r
        rpc, blocks = self.rpc(alter), rc.Blocks()
        with self.assertRaises(rc.Rejected) as cm:
            self.build(rpc, blocks=blocks)
        self.assertIn("archive requests need a token", str(cm.exception))
        l1_calls = lambda: sum(1 for m, p in rpc.log if self.bh in (p[0], p[-1]))     # noqa: E731
        n1 = l1_calls()
        self.assertEqual(n1, 2)                                   # the L1 header, then the first eth_call
        twin = copy.deepcopy(self.e)                              # the same payment named as another entry of the game
        twin["file"] = twin["file"].replace("m001", "m0xx")
        with self.assertRaises(rc.Rejected) as cm:
            self.build(rpc, twin, blocks)
        self.assertIn("archive requests need a token", str(cm.exception))
        self.assertEqual(l1_calls(), n1)
        # a fresh Blocks asks again (the refusal is of one run, not of the list)
        with self.assertRaises(rc.Rejected):
            self.build(self.rpc(alter), blocks=rc.Blocks())

    def test_altered_l2_header(self):
        lo = self.n

        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and p[1] is False and p[0] != self.bh and int(p[0], 16) > lo:
                r["gasUsed"] = hex(int(r["gasUsed"], 16) + 1)
            return r
        self._refused("canonical_not_recomputed:O2:failed:header_hash_mismatch", alter)

    def test_altered_l1_proof_node(self):
        def alter(m, p, r):
            if m == "eth_getProof" and p[2] == self.bh and p[0].lower() == self.a["game"]:
                node = r["accountProof"][0]
                r["accountProof"][0] = node[:-2] + ("00" if node[-2:] != "00" else "01")
            return r
        self._refused("l1_state_not_recomputed", alter)

    def test_another_game_in_the_list(self):
        e = copy.deepcopy(self.e)
        e["chain"]["anchor"]["game"] = next(g for g in self.games if g != self.a["game"])
        self._refused("block_not_in_game_range", e=e)

    def test_l1_header_altered_by_the_endpoint_or_in_the_list(self):
        def alter(m, p, r):
            if m == "eth_getBlockByNumber" and p[0] == self.bh:
                r["gasUsed"] = hex(int(r["gasUsed"], 16) + 1)
            return r
        self.assertNotIn("stated", self._refused("header_hash_mismatch", alter))
        e = copy.deepcopy(self.e)
        e["chain"]["anchor"]["l1_block_hash"] = "0x" + "22" * 32
        self._refused("header_hash_mismatch:stated", e=e)

    def test_altered_l1_reply(self):
        def alter(m, p, r):
            if m == "eth_call" and p[0]["data"].lower() == "0xbcef3b55":          # rootClaim(): one bit flipped
                return "0x" + "%064x" % (int(r, 16) ^ 1)
            return r
        # the fetch derives the factory's slot from the game's uuid (gameType, rootClaim, extraData): an altered rootClaim
        # asks the factory for another slot, and the replies recomputed from the real game's code do not find theirs
        self._refused("l1_state_not_recomputed:storage_proof_missing", alter)
        # a reply that feeds no key of the fetch, altered: the L1 check of the verifier finds it not proven by the proofs
        self._refused("canonical_not_recomputed:L1:failed:l1_reply_not_proven:isGameClaimValid",
                      lambda m, p, r: "0x" + "%064x" % 0 if m == "eth_call" and p[0]["data"].lower().startswith("0x6c4f4467") else r)
        # a status outside GameStatus is a grammar refusal of the verifier, before L1
        self._refused("canonical_refused:canonical.l1_replies: status 3 is not a GameStatus",
                      lambda m, p, r: "0x" + "%064x" % 3 if m == "eth_call" and p[0]["data"].lower() == "0x200d2ed2" else r)

    def test_altered_root_index_and_game_code(self):
        e = copy.deepcopy(self.e)
        e["chain"]["anchor"]["root_index"] += 1
        self._refused("root_index_not_the_first_root_at_or_after_the_block:%d" % self.a["root_index"], e=e)

        def alter(m, p, r):
            if m == "eth_getCode" and p[1] == self.bh and p[0].lower() == self.a["game"]:
                return r[:-2] + ("00" if r[-2:] != "00" else "01")
            return r
        self._refused("l1_state_not_recomputed", alter)

    def game_facts(self):
        # start, l2SequenceNumber, roots from the saved replies of the pinned game, as the tool reads them
        d = self.l1[self.a["game"]]
        ed = bytes.fromhex(d["calls"][2]["result"][2:])
        return {"start": int(d["calls"][3]["result"], 16), "seq": int.from_bytes(ed[64:96], "big"),
                "roots": (int.from_bytes(ed[32:64], "big") - 52) // 32}

    def test_top_l2_header_altered_with_its_hash_recomputed(self):
        # 33.10, what anchors what: the top header m is held only by O3 (its output root is the game's root, proven from
        # L1 state); no parent link reaches it. An endpoint that serves another header m, hashing to the `hash` it states,
        # passes O2 (every header hashes to its hash, the links hold from m down) and is refused at O3
        import anchor_msca
        import apc_block as ab
        i, m, _k = anchor_msca.place(self.game_facts(), self.n)
        self.assertEqual(i, self.a["root_index"])
        self.assertLessEqual(m - self.n, rc.MAX_CANONICAL_HEADERS)

        def alter(meth, p, r):
            if meth == "eth_getBlockByNumber" and p[1] is False and p[0] == hex(m):
                r["stateRoot"] = "0x" + "%064x" % (int(r["stateRoot"], 16) ^ 1)
                r["hash"] = ab.header_hash({k: v for k, v in r.items() if k in rc.HEADER_KEYS})
            return r
        self._refused("canonical_not_recomputed:O3:failed:output_root_not_the_game_root", alter)
        # the same alteration without the hash recomputed is O2, before O3
        self._refused("canonical_not_recomputed:O2:failed:header_hash_mismatch",
                      lambda meth, p, r: dict(r, stateRoot="0x" + "%064x" % (int(r["stateRoot"], 16) ^ 1))
                      if meth == "eth_getBlockByNumber" and p[1] is False and p[0] == hex(m) else r)

    def test_root_block_too_far(self):
        # an endpoint that states a smaller startingBlockNumber widens the root spacing: the root's block m moves above
        # the 64 headers section 6 allows, and the rebuild is refused before any header is asked (startingBlockNumber
        # feeds no key of the fetch, so the L1 side is built; the root index is the one that spacing gives)
        import anchor_msca
        f = self.game_facts()
        span = f["seq"] - f["start"]
        for mult in range(2, 40):
            g = dict(f, start=f["start"] - span * mult)
            i, m, _k = anchor_msca.place(g, self.n)
            if m - self.n > rc.MAX_CANONICAL_HEADERS:
                break
        else:
            self.fail("no spacing found")
        e = copy.deepcopy(self.e)
        e["chain"]["anchor"]["root_index"] = i

        def alter(meth, p, r):
            if meth == "eth_call" and p[1] == self.bh and p[0]["data"].lower() == self.l1[self.a["game"]]["calls"][3]["data"].lower():
                return "0x%064x" % g["start"]
            return r
        rpc = self.rpc(alter)
        with self.assertRaises(rc.Rejected) as cm:
            self.build(rpc, e)
        self.assertEqual(str(cm.exception), "root_block_too_far:%d" % (m - self.n))
        self.assertEqual(sum(1 for mm, p in rpc.log if mm == "eth_getBlockByNumber" and p[1] is False and p[0] != self.bh
                             and int(p[0], 16) > self.n), 0)                # no L2 header above n was asked

    def test_block_outside_the_game_range(self):
        # 33.10: the payment's block must sit in (startingBlockNumber, l2SequenceNumber]; an endpoint that states a
        # startingBlockNumber at or above it is refused at the range, before the root is placed (M07 of the bench of
        # 2026-11-02 lived: the guard was loosened to `start <= n` and no test asked). l2SequenceNumber is in extraData,
        # a key of the fetch: altered, the proofs are not found first (test_altered_l1_reply)
        data = self.l1[self.a["game"]]["calls"][3]["data"].lower()
        for start in (self.n, self.n + 1):
            rpc = self.rpc(lambda meth, p, r, s=start: "0x%064x" % s
                           if meth == "eth_call" and p[1] == self.bh and p[0]["data"].lower() == data else r)
            with self.assertRaises(rc.Rejected) as cm:
                self.build(rpc)
            self.assertEqual(str(cm.exception), "block_not_in_game_range")
            self.assertEqual(sum(1 for mm, p in rpc.log if mm == "eth_getBlockByNumber" and p[1] is False and p[0] != self.bh
                                 and int(p[0], 16) > self.n), 0)

    def test_l2_headers_fetched_once_across_the_bundles_of_a_root(self):
        # 33.10: each L2 header once per run. m002 sits under the same root as m001 (root_index 10, both): after m001 the
        # headers m..n+1 of m002 are all in the cache, and its build asks the L2 for no header above its block
        twin = next(b for b in MAN["bundles"] if b["set"] == self.e["set"] and "anchor" in b["chain"]
                    and b["chain"]["anchor"] == self.a and b["file"] != self.FILE)
        self.assertGreater(twin["chain"]["block_number"], self.n)
        blocks = rc.Blocks()
        self.build(self.rpc(), blocks=blocks)
        n2 = twin["chain"]["block_number"]
        R = os.path.join(ROOT, "oracle", "msca_20261101", "raw")
        with mock.patch.object(AnchoredControls, "block", _gz(os.path.join(R, "%d_block.json.gz" % n2))), \
                mock.patch.object(AnchoredControls, "receipts", _gz(os.path.join(R, "%d_receipts.json.gz" % n2))), \
                mock.patch.object(AnchoredControls, "parent", _gz(os.path.join(R, "%d_header.json.gz" % (n2 - 1)))), \
                mock.patch.object(AnchoredControls, "n", n2), \
                mock.patch.object(AnchoredControls, "doc", _jload(os.path.join(ROOT, "bundles", twin["file"]))):
            for b in (n2 - 1, n2):
                for q in glob.glob(os.path.join(R, "%d_proof_0x*.json.gz" % b)):
                    self.l2_proofs[(os.path.basename(q)[len("%d_proof_" % b):-len(".json.gz")], hex(b))] = _gz(q)
            for q in glob.glob(os.path.join(R, "%d_code_0x*.json.gz" % n2)):
                self.l2_codes[(os.path.basename(q)[len("%d_code_" % n2):-len(".json.gz")], hex(n2))] = _gz(q)
            rpc2 = self.rpc()
            doc2 = self.build(rpc2, twin, blocks)
        self.assertEqual(hashlib.sha256(rc.serialize(doc2, self.s["serialization"])).hexdigest(), twin["sha256"])
        asked = [int(p[0], 16) for mm, p in rpc2.log if mm == "eth_getBlockByNumber" and p[1] is False and p[0] != self.bh]
        self.assertEqual([b for b in asked if b > n2], [])                   # the headers above n2: all from the cache
        self.assertIn(n2 - 1, asked)                                          # the parent header of its own block: asked

    def test_l1_side_per_game_across_games(self):
        # review 2026-11-02: the L1 cache is per (L1 block, game); a bundle of ANOTHER game in the same run must fetch its
        # own L1 side (a cache keyed by the block alone hands it the first game's replies: refused, 19 of the 28 lost)
        blocks = rc.Blocks()
        self.build(self.rpc(), blocks=blocks)
        other = next(b for b in MAN["bundles"] if b["set"] == self.e["set"] and "anchor" in b["chain"]
                     and b["chain"]["anchor"]["game"] != self.a["game"])
        R = os.path.join(ROOT, "oracle", "msca_20261101", "raw")
        on = other["chain"]["block_number"]
        with mock.patch.object(AnchoredControls, "block", _gz(os.path.join(R, "%d_block.json.gz" % on))), \
                mock.patch.object(AnchoredControls, "receipts", _gz(os.path.join(R, "%d_receipts.json.gz" % on))), \
                mock.patch.object(AnchoredControls, "parent", _gz(os.path.join(R, "%d_header.json.gz" % (on - 1)))), \
                mock.patch.object(AnchoredControls, "n", on), \
                mock.patch.object(AnchoredControls, "doc", _jload(os.path.join(ROOT, "bundles", other["file"]))):
            for b in (on - 1, on):
                for q in glob.glob(os.path.join(R, "%d_proof_0x*.json.gz" % b)):
                    self.l2_proofs[(os.path.basename(q)[len("%d_proof_" % b):-len(".json.gz")], hex(b))] = _gz(q)
            for q in glob.glob(os.path.join(R, "%d_code_0x*.json.gz" % on)):
                self.l2_codes[(os.path.basename(q)[len("%d_code_" % on):-len(".json.gz")], hex(on))] = _gz(q)
            rpc2 = self.rpc()
            doc2 = self.build(rpc2, other, blocks)
        self.assertEqual(hashlib.sha256(rc.serialize(doc2, self.s["serialization"])).hexdigest(), other["sha256"])
        self.assertGreater(sum(1 for m, p in rpc2.log if m == "eth_getProof" and p[-1] == self.bh), 0)

    def test_reply_beyond_32_bytes_is_refused_not_a_crash(self):
        # review 2026-11-02: an eth_call word of 33 bytes made fetch_l1proof.word / int.to_bytes raise OverflowError, which
        # rebuild() did not catch: the run ended with a traceback, no report, the other bundles never asked
        man = {"sets": MAN["sets"], "bundles": [self.e]}
        with tempfile.TemporaryDirectory() as out:                  # control: unaltered, written, the report says how
            rep = rc.rebuild(man, self.rpc(), out, log=lambda *a: None)
            self.assertEqual([(r["status"], r["written"], r["anchors"]["canonical"]) for r in rep["results"]],
                             [("bytes", True, "recomputed")])
            self.assertEqual(rep["summary"]["anchors"]["canonical_recomputed"], 1)
        for data in ("0xbbdc02db", "0xbcef3b55"):                   # gameType, rootClaim
            alter = (lambda d: lambda m, p, r: "0x01" + "00" * 32 if m == "eth_call" and p[0]["data"].lower() == d else r)(data)
            with tempfile.TemporaryDirectory() as out:
                rep = rc.rebuild(man, self.rpc(alter), out, log=lambda *a: None)
                self.assertEqual([r["status"].split(":")[:3] for r in rep["results"]], [["refused", "reply_shape", "OverflowError"]])
                self.assertEqual([r.get("written", False) for r in rep["results"]], [False])
                self.assertEqual(os.listdir(out), [])

    def test_anchor_grammar_closed(self):
        def with_anchor(fn):
            d = copy.deepcopy(MAN)
            fn(next(b for b in d["bundles"] if b["file"] == self.FILE))
            return d
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].__setitem__("owner", "0x" + "11" * 20)), "chain.anchor.owner: unknown member")
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].__setitem__("game", self.a["game"].upper())), "chain.anchor: l1_block_hash or game")
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].__setitem__("l1_network", "eip155:10")), "canonical rules are for")
        ListClosed._refused(self, with_anchor(lambda b: b.__setitem__("network", "eip155:1")), "canonical rules are for")
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].__setitem__("root_index", True)), "chain.anchor.root_index: wrong type")
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].__setitem__("root_index", -1)), "negative l1_block_number or root_index")
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].pop("game")), "chain.anchor.game: missing")
        ListClosed._refused(self, with_anchor(lambda b: b["ours"].pop("inclusion")), "canonical needs an apc-0.3 entry with inclusion")
        # one checkpoint: the anchor's L1 header hash is the set's params.options.l1_checkpoint (review 2026-11-02)
        ListClosed._refused(self, with_anchor(lambda b: b["chain"]["anchor"].__setitem__("l1_block_hash", "0x" + "22" * 32)),
                            "is not the set's params.options.l1_checkpoint")
        d = copy.deepcopy(MAN)
        d["sets"][self.e["set"]]["params"].pop("options")
        ListClosed._refused(self, d, "is not the set's params.options.l1_checkpoint")
        d = copy.deepcopy(MAN)
        d["format"] = "apc-corpus-0.2"
        ListClosed._refused(self, d, "'apc-corpus-0.2' is not 'apc-corpus-0.3'")
        # an anchor on another recipe is an unknown member of its chain
        d = copy.deepcopy(MAN)
        b = next(x for x in d["bundles"] if x["set"] == "real_permit2")
        b["chain"]["anchor"] = dict(self.a)
        ListClosed._refused(self, d, "chain.anchor: unknown member")
        # and the real list holds the 28, all under one checkpoint, each with its proof and rpc twins
        anchored = [b for b in MAN["bundles"] if "anchor" in b["chain"]]
        self.assertEqual(len(anchored), 28)
        self.assertEqual({b["chain"]["anchor"]["l1_block_hash"] for b in anchored}, {self.a["l1_block_hash"]})
        files = {b["file"] for b in MAN["bundles"]}
        for b in anchored:
            self.assertEqual((b["set"], b["bundle_version"], b["ours"]["payer_state"], b["ours"]["inclusion"], b["verdict"]),
                             ("real_msca_20261101", "apc-0.3", "proof", True, "chain_verified"))
            self.assertIn(b["file"].replace("_anchored_", "_proof_"), files)
            self.assertIn(b["file"].replace("_anchored_", "_rpc_"), files)


class NestedInputPublic(unittest.TestCase):
    """33.11 (2026-11-02): a JSON document nested beyond the interpreter's limit — a reply, an HTTP error body, a file
    read back from --out-oracle — is refused with where it came from. No saved block is needed: these run in the public
    tree too. Before, json.loads raised RecursionError through rebuild(): a traceback, no report, the other bundles never
    asked (positive control: NestedInputPublic and NestedInput on the tool of 82f5ec4 error in every test but the
    fixture's own and the two unaltered ones)."""
    NESTED = b"[" * 100000 + b"]" * 100000

    @classmethod
    def setUpClass(cls):
        cls.e = entry(EvmControls.FILE)                          # the list's entry: the bundle itself is not read

    def man(self):
        return {"sets": MAN["sets"], "bundles": [self.e]}

    def real_rpc(self, **kw):
        return rc.Rpc({self.e["network"]: "http://127.0.0.1:9/"}, rate=1000, **kw)

    def test_nested_parses_to_a_recursion_error_here(self):      # the fixture is what it says: RecursionError, not ValueError
        with self.assertRaises(RecursionError):
            json.loads(self.NESTED)

    def test_reply_nested_beyond_the_limit_is_refused(self):
        rpc = self.real_rpc()
        rpc._post = lambda url, body: self.NESTED
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild(self.man(), rpc, out, log=lambda *a: None)
            self.assertEqual([(r["status"], r.get("written", False)) for r in rep["results"]],
                             [("refused:json_too_nested:rpc:127.0.0.1:eth_getBlockByNumber", False)])
            self.assertEqual(os.listdir(out), [])
        self.assertEqual((rep["summary"]["refused"], rep["summary"]["below_declared_level"]), (1, 1))

    def test_http_error_body_nested_is_no_json_rpc_error(self):
        def boom(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, io.BytesIO(self.NESTED))
        with mock.patch.object(rc.urllib.request, "urlopen", boom), mock.patch.object(rc.time, "sleep", lambda s: None):
            with self.assertRaises(rc.Rejected) as cm:
                self.real_rpc().call(self.e["network"], "eth_chainId", [])
        self.assertEqual(str(cm.exception), "rpc_unreachable:127.0.0.1:HTTP 400")

    def test_oracle_files_nested_are_not_ours(self):
        with tempfile.TemporaryDirectory() as d:
            gz = os.path.join(d, "x.json.gz")
            with gzip.open(gz, "wb") as fh:
                fh.write(self.NESTED)
            self.assertIsNone(rc._existing_result(gz))
            p = os.path.join(d, "ledgers.json")
            with open(p, "wb") as fh:
                fh.write(self.NESTED)
            self.assertIs(rc._existing_xrpl_is_ours(p, {"items": [], "result_sha256": {}}), False)


class ReplyShapePublic(unittest.TestCase):
    """Review 2026-11-02 (runs in the public tree too): a reply that is JSON but not a JSON-RPC object (a list, a string,
    a number, null), an error member that is a string or a list, a member of another type inside a recipe
    (AttributeError) is the bundle's row, never a traceback. Before, `d.get` / `(error or {}).get` raised AttributeError
    out of rebuild(): no report, the other bundles never asked (`{"error": "rate limited"}` after 155 s of retries)."""

    @classmethod
    def setUpClass(cls):
        cls.e = entry(EvmControls.FILE)

    def run_with(self, raw):
        rpc = rc.Rpc({self.e["network"]: "http://127.0.0.1:9/"}, rate=1000)
        rpc._post = lambda url, body: raw
        with tempfile.TemporaryDirectory() as out, mock.patch.object(rc.time, "sleep", lambda s: None):
            rep = rc.rebuild({"sets": MAN["sets"], "bundles": [self.e]}, rpc, out, log=lambda *a: None)
            self.assertEqual(os.listdir(out), [])
        return [r["status"] for r in rep["results"]]

    def test_reply_not_an_object_is_refused(self):
        for raw in (b"[]", b'[{"jsonrpc":"2.0","id":1,"result":"0x1"}]', b'"error"', b"5", b"null"):
            self.assertEqual(self.run_with(raw), ["refused:rpc_not_object:127.0.0.1:eth_getBlockByNumber"], raw)

    def test_error_member_not_an_object_is_refused_with_it(self):
        for err, text in ((b'"boom"', "boom"), (b"[1]", "error_not_text:list"), (b"5", "error_not_text:int"),
                          (b'{"message":{"a":1}}', "error_not_text:dict"), (b'{"code":1}', "null result")):
            self.assertEqual(self.run_with(b'{"jsonrpc":"2.0","id":1,"error":' + err + b"}"),
                             ["refused:rpc_error:127.0.0.1:eth_getBlockByNumber:" + text], err)

    def test_xrpl_result_not_an_object_is_refused(self):
        rpc = rc.Rpc({"xrpl:0": "http://127.0.0.1:9/"}, rate=1000)
        for raw, text in ((b'{"result":[1]}', "no result"), (b'{"result":"x"}', "no result"),
                          (b'{"result":{"status":"error","error":["x"]}}', "error_not_text:list")):
            rpc._post = lambda url, body, raw=raw: raw
            with self.assertRaises(rc.Rejected) as cm:
                rpc.call("xrpl:0", "ledger", {}, xrpl=True)
            self.assertEqual(str(cm.exception), "rpc_error:127.0.0.1:ledger:" + text)

    def test_attribute_error_in_a_recipe_is_its_row(self):
        recipe = self.e.get("recipe", MAN["sets"][self.e["set"]]["recipe"])

        def boom(*a):
            raise AttributeError("'list' object has no attribute 'lower'")
        with mock.patch.dict(rc.RECIPE_FN, {recipe: boom}):
            self.assertEqual(self.run_with(b"{}"), ["refused:reply_shape:AttributeError:'list' object has no attribute 'lower'"])

    def test_object_reply_still_reaches_the_recipe(self):      # control: an object with a result is read, not refused here
        self.assertEqual(self.run_with(b'{"jsonrpc":"2.0","id":1,"result":[]}'), ["refused:header_not_object"])


class FetchL1proofProgram(unittest.TestCase):
    """Review 2026-11-02 (runs in the public tree too): sources/l1proof_20261024/fetch_l1proof.py says "at most one
    request per second" and "the output records the endpoint's scheme and host only"; before these tests, rpc() without
    the wait and main() writing the whole URL passed every test."""

    def run_code(self, body):
        code = ("import io, json, os, sys, tempfile, urllib.error\n"
                "sys.path[:0] = ['sources/l1proof_20261024']\n"
                "import fetch_l1proof as FL\n" + body)
        e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=e, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stderr.decode("utf-8", "replace")[-400:]), (0, ""))

    def test_paced_retries_included(self):
        self.run_code(
            "now, sent = [1000.0], []\n"
            "FL.time.monotonic = lambda: now[0]\n"
            "def sleep(s):\n    now[0] += s\n"
            "FL.time.sleep = sleep\n"
            "def urlopen(req, timeout=None):\n"
            "    sent.append(now[0])\n"
            "    if len(sent) == 2:\n        raise urllib.error.URLError('down')\n"
            "    return io.BytesIO(b'{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}')\n"
            "FL.urllib.request.urlopen = urlopen\n"
            "for _ in range(3):\n    assert FL.rpc('http://127.0.0.1:9', 'eth_chainId', []) == '0x1'\n"
            "gaps = [b - a for a, b in zip(sent, sent[1:])]\n"
            "assert len(sent) == 4 and min(gaps) >= 1.0 and gaps[0] == 1.0, sent\n")

    def test_output_records_scheme_and_host_only(self):
        self.run_code(
            "assert FL.where('https://u:pw@rpc.example:8545/v2/KEY?apikey=K#f') == 'https://rpc.example:8545'\n"
            "assert FL.where('https://rpc.example/KEY') == 'https://rpc.example'\n"
            "FL.fetch = lambda game, b, call: {'impl': 'i', 'sysconf': 's', 'impls': []}\n"
            "out = os.path.join(tempfile.mkdtemp(), 'o.json')\n"
            "sys.argv = ['fetch_l1proof.py', '0x' + '11' * 20, out, 'https://u:pw@rpc.example/v2/SECRETKEY?k=1', '100']\n"
            "import contextlib\n"
            "with contextlib.redirect_stdout(io.StringIO()):\n    FL.main()\n"
            "raw = open(out).read()\n"
            "assert json.loads(raw)['rpc'] == 'https://rpc.example' and 'SECRETKEY' not in raw and 'pw' not in raw, raw\n")


class NestedInput(OracleRebuild):
    """33.11 with the saved block and receipts of oracle/blocks_v03: the cached reply, the file under --out, an error
    while a recipe processes, the oracle recipes; the same fixtures unaltered rebuild."""
    NESTED = NestedInputPublic.NESTED
    man, real_rpc = NestedInputPublic.man, NestedInputPublic.real_rpc

    def test_cached_reply_nested_beyond_the_limit_is_refused(self):
        first = self.rpc()
        self.build(first)
        m, p = first.log[0]
        with tempfile.TemporaryDirectory() as cache, tempfile.TemporaryDirectory() as out:
            key = hashlib.sha256(rc.canon([self.e["network"], m, p]).encode()).hexdigest()
            with gzip.open(os.path.join(cache, key + ".json.gz"), "wb") as fh:
                fh.write(self.NESTED)
            rpc = self.real_rpc(cache=cache)
            rpc._post = mock.Mock(side_effect=AssertionError("the cache answers first"))
            rep = rc.rebuild(self.man(), rpc, out, log=lambda *a: None)
            self.assertEqual([r["status"] for r in rep["results"]], ["refused:json_too_nested:cache:%s" % m])
            self.assertEqual(os.listdir(out), [])
            self.assertEqual(rpc._post.call_count, 0)

    def test_file_under_out_nested_is_unreadable_not_a_crash(self):
        with tempfile.TemporaryDirectory() as out:
            p = os.path.join(out, self.e["file"])
            os.makedirs(os.path.dirname(p))
            with open(p, "wb") as fh:
                fh.write(self.NESTED)
            rep = rc.rebuild(self.man(), self.rpc(), out, log=lambda *a: None)
            row = rep["results"][0]
            self.assertEqual((row["status"], row["ok"], row["written"]), ("bytes", False, False))
            self.assertIn("unreadable:RecursionError", row["note"])
            with open(p, "rb") as fh:
                self.assertEqual(fh.read(), self.NESTED)                   # not overwritten

    def test_recursion_while_a_recipe_processes_is_its_row(self):
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(rc, "serialize", side_effect=RecursionError("maximum recursion depth exceeded")):
            rep = rc.rebuild(self.man(), self.rpc(), out, log=lambda *a: None)
            self.assertEqual([r["status"] for r in rep["results"]],
                             ["refused:reply_shape:RecursionError:maximum recursion depth exceeded"])
            self.assertEqual(os.listdir(out), [])

    def test_oracle_recipe_errors_are_its_row(self):
        for exc in (RecursionError("deep"), OverflowError("int too big to convert")):
            with tempfile.TemporaryDirectory() as out, mock.patch("inclusion.build", side_effect=exc):
                rep = rc.rebuild_oracle(self._man(), self.rpc(), out, log=lambda *a: None)
                self.assertEqual([r["status"] for r in rep["results"]],
                                 ["refused:reply_shape:%s:%s" % (type(exc).__name__, exc)])
                self.assertEqual(os.listdir(out), [])

    def test_oracle_file_ours_is_read(self):                   # control of NestedInputPublic.test_oracle_files_nested_are_not_ours
        n = self.e["chain"]["block_number"]
        ours = os.path.join(ROOT, "oracle", "blocks_v03", "%d_block.json.gz" % n)
        self.assertEqual(rc._existing_result(ours), MAN["oracle"]["blocks_v03"]["result_sha256"]["%d_block.json.gz" % n])

    def test_unaltered_still_rebuilds(self):                     # the bound costs nothing on a reply within the limit
        with tempfile.TemporaryDirectory() as out:
            rep = rc.rebuild(self.man(), self.rpc(), out, log=lambda *a: None)
            self.assertEqual([(r["status"], r["written"]) for r in rep["results"]], [("bytes", True)])
            rep = rc.rebuild_oracle(self._man(), self.rpc(), out, log=lambda *a: None)
            self.assertEqual([r["status"] for r in rep["results"]], ["content"])


for _cls, _base in ((ReviewHostileEndpoint, EvmControls), (ReviewEachFingerprint, EvmControls), (OracleRebuild, EvmControls), (ReviewOracleBelowContent, OracleRebuild), (NestedInput, OracleRebuild),
                    (ReviewSvmReasons, SvmControls), (ReviewXrplReasons, XrplControls)):
    for _n in dir(_base):
        if _n.startswith("test_"):
            setattr(_cls, _n, None)          # the fixture is inherited, the base tests are not run twice
del _cls, _base, _n                          # module globals that are TestCase classes would be collected again



class RebuildImportsItsRecipes(unittest.TestCase):
    """Review 2026-11-02 (runs in the public tree too): every module tools/rebuild_corpus.py imports inside a function
    imports when the program runs with its own arguments. In the public tree of a3d0362, make_bundles_l1state (the anchored
    bundles, 33.10) and make_bundles_svm (real_svm) ended the program at import (`the saved RPC replies are not in the
    public tree`, exit 1, no report) as soon as a recipe reached them."""

    def test_lazy_imports_with_the_programs_argv(self):
        import ast
        with open(os.path.join(ROOT, "tools", "rebuild_corpus.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        mods = sorted({a.name.split(".")[0] for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                       for n in ast.walk(f) if isinstance(n, ast.Import) for a in n.names}
                      | {n.module.split(".")[0] for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                         for n in ast.walk(f) if isinstance(n, ast.ImportFrom) and n.module}
                      | {n.args[0].value for n in ast.walk(tree) if isinstance(n, ast.Call)        # _tool_module("x")
                         and getattr(n.func, "id", None) == "_tool_module" and n.args and isinstance(n.args[0], ast.Constant)})
        self.assertIn("make_bundles_l1state", mods)
        self.assertIn("make_bundles_svm", mods)
        plain = {a.name.split(".")[0] for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                 for n in ast.walk(f) if isinstance(n, (ast.Import, ast.ImportFrom))
                 for a in (n.names if isinstance(n, ast.Import) else [ast.alias(name=n.module or "")])}
        self.assertFalse(plain & {"make_bundles_l1state", "make_bundles_svm"},           # review 2026-11-02: imported
                         "read ROOT from argv at import: only through _tool_module")      # plain, ROOT = `--rpc` in sys.path
        code = ("import importlib, sys\n"
                "sys.argv = ['tools/rebuild_corpus.py', '--rpc', 'eip155:1=http://127.0.0.1:9', '--only', 'x']\n"
                "sys.path[:0] = ['tools', 'sources/l1proof_20261024']\n"
                "import rebuild_corpus\n"
                "for m in %r:\n    importlib.import_module(m)\n" % mods)
        e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=e, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stderr.decode("utf-8", "replace")[-400:]), (0, ""))

    def test_tool_modules_read_root_from_the_tool_not_from_argv(self):
        # 2026-11-02: make_bundles_l1state and make_bundles_svm read ROOT from sys.argv[1] at import; imported by
        # rebuild_corpus under its own arguments they read `--rpc` (a path that is not there). _tool_module imports them
        # under the tool's ROOT, once; before, make_bundles_l1state was imported plain (ROOT `--rpc`, SRC under it)
        code = ("import sys\n"
                "sys.argv = ['tools/rebuild_corpus.py', '--rpc', 'eip155:1=http://127.0.0.1:9', '--only', 'x']\n"
                "sys.path[:0] = ['tools', 'sources/l1proof_20261024']\n"
                "import rebuild_corpus as rc\n"
                "for name in ('make_bundles_l1state', 'make_bundles_svm'):\n"
                "    m = rc._tool_module(name)\n"
                "    assert m.ROOT == rc.ROOT and m.SRC.startswith(rc.ROOT + '/'), (name, m.ROOT, m.SRC)\n"
                "    assert sys.argv[1] == '--rpc', sys.argv\n"
                "    assert rc._tool_module(name) is m\n")
        e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=e, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stderr.decode("utf-8", "replace")[-400:]), (0, ""))

    def test_anchor_msca_paces_only_when_run(self):
        # review 2026-11-02: tools/anchor_msca.py says "at most one request per second"; the overrides moved from import
        # time into main (throttle_all): import leaves the three fetch modules alone, main rewires all three, and the
        # wrapper waits a second between two requests. Before this test, main without throttle_all() passed every test.
        code = ("import io, sys, time, contextlib\n"
                "sys.path[:0] = ['tools', 'sources/l1proof_20261024']\n"
                "import canonical as C, fetch_l1proof as FL, make_bundles_msca as mb\n"
                "before = (C.rpc, FL.rpc, mb.rpc)\n"
                "import anchor_msca as A\n"
                "assert (C.rpc, FL.rpc, mb.rpc) == before, 'rewired at import'\n"
                "with contextlib.redirect_stderr(io.StringIO()):\n"
                "    assert A.main(['anchor_msca.py']) == 64\n"
                "assert (C.rpc, FL.rpc, mb.rpc) == (A.rpc, A.rpc, A.raw_rpc), 'not rewired by main'\n"
                "t = []\n"
                "A._raw_rpc = lambda u, m, p: t.append(time.monotonic()) or b'{}'\n"
                "A.raw_rpc('http://127.0.0.1:9', 'eth_chainId', []); A.raw_rpc('http://127.0.0.1:9', 'eth_chainId', [])\n"
                "assert t[1] - t[0] >= 0.99, t\n")
        e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, cwd=ROOT, env=e, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stderr.decode("utf-8", "replace")[-400:]), (0, ""))


if __name__ == "__main__":
    unittest.main()
