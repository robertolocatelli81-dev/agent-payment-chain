"""SPEC section 33: the list of the real corpus (corpus/MANIFEST.json) and tools/rebuild_corpus.py.

Offline, always: the list reads back closed (a member outside the grammar at any level is refused with its path; a wrong
count, a duplicate file, a bad digest likewise), its sets and levels, the skip discipline of tests/real_corpus.py and of
the package loader (a module that raises SkipTest at import is reported skipped, never passed or crashed).
With the local corpus (bundles/, oracle/): the digests of the list are those of our files; and the positive controls of
the rebuild through a fake endpoint that serves the saved replies — the unaltered data rebuilds a bundle to the byte,
and an altered block hash, transaction input, receipt log, XRPL metadata blob or Solana message byte is refused with its
reason. No network."""
import base64
import copy
import glob
import gzip
import hashlib
import json
import os
import sys
import unittest
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
        self.replies, self.alter = replies, alter or (lambda m, p, r: r)

    def url(self, network):
        return "https://fake.invalid/"

    def call(self, network, method, params, xrpl=False):
        self.calls += 1
        key = method if method in ("eth_getBlockReceipts", "ledger", "getTransaction") else (method, rc.canon(params))
        if key not in self.replies and method not in self.replies:
            raise rc.Rejected("rpc_error:fake.invalid:%s:the method %s does not exist/is not available" % (method, method))
        r = self.replies[key] if key in self.replies else self.replies[method]
        r = r(params) if callable(r) else r
        return self.alter(method, params, copy.deepcopy(r))


def _gz(p):
    with gzip.open(p) as fh:
        return json.loads(fh.read())["result"]


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


for _cls, _base in ((ReviewHostileEndpoint, EvmControls), (ReviewEachFingerprint, EvmControls), (OracleRebuild, EvmControls), (ReviewOracleBelowContent, OracleRebuild),
                    (ReviewSvmReasons, SvmControls), (ReviewXrplReasons, XrplControls)):
    for _n in dir(_base):
        if _n.startswith("test_"):
            setattr(_cls, _n, None)          # the fixture is inherited, the base tests are not run twice
del _cls, _base, _n                          # module globals that are TestCase classes would be collected again

if __name__ == "__main__":
    unittest.main()
