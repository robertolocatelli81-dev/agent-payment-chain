"""SPEC section 29 (apc_verify 0.18.0): the bundle as hostile input. Each test is a case that tools/fuzz_bundles.py or the
fleet audit after it found (a crash, a stall, a member read past its grammar), rebuilt small from a real bundle of
bundles/, and the limit next to it: at the limit the input is read, one past it is refused (or fails) with its reason.
On the tree before section 29 (0bf2063) 31 of the 41 tests fail (a traceback, a stall, or a verdict the input should
not get); the 10 that pass there are ExistingLimits (8: limits already in the code), Harness (tools/fuzz_bundles.py is
new) and the control that text outside the RPC objects may begin with "0X"."""
import contextlib
import copy
import glob
import io
import json
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))      # test_http (HttpLabels), also under `-m unittest`
from tests import real_corpus  # noqa: E402
real_corpus.need("real_svm", "xrp_real_20261026", "real_v02", "real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_ap2 as a2  # noqa: E402
import apc_block as ab  # noqa: E402
import apc_dr3783 as dr  # noqa: E402
import apc_mcp  # noqa: E402
import apc_solana as sol  # noqa: E402
import apc_verify as av  # noqa: E402
import apc_xrpl as xr  # noqa: E402
from lib.eip712 import keccak256  # noqa: E402

B = os.path.join(ROOT, "bundles")
SVM = os.path.join(B, "real_svm", "s047_relai.json")
XRP = os.path.join(B, "xrp_real_20261026", "13db81da30d3.json")
V02 = os.path.join(B, "real_v02", "b001_direct_envelope_reconstructed.json")
V03 = os.path.join(B, "real_v03", "v002_b004_direct_envelope_reconstructed.json")
AUTHCAP = os.path.join(B, "authcap_real_20261026", "18ddc9b4ad8a.json")
CASES = os.environ.get("APC_PULSE_CASES")


def load(p):
    with open(p) as fh:
        return av.strict_json(fh.read())


def cli(doc, opts=()):
    """apc_verify.main on the bundle as a file (bytes, or a document written as JSON): (exit code, report, seconds)"""
    import tempfile
    data = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    with tempfile.NamedTemporaryFile(suffix=".json") as fh:
        fh.write(data)
        fh.flush()
        buf = io.StringIO()
        t0 = time.process_time()
        with contextlib.redirect_stdout(buf):
            code = av.main(["apc_verify.py"] + list(opts) + [fh.name])
        return code, json.loads(buf.getvalue()), time.process_time() - t0


def nested(depth, inner=0):
    v = inner
    for _ in range(depth):
        v = [v]
    return v


class JsonDepth(unittest.TestCase):
    """29.1: arrays and objects nested at most MAX_JSON_DEPTH (64) in every JSON text the verifier reads."""

    def test_limit_and_one_past(self):
        self.assertEqual(av.MAX_JSON_DEPTH, 64)
        av.strict_json(json.dumps(nested(64)))
        with self.assertRaisesRegex(av.Refusal, "nested deeper than 64"):
            av.strict_json(json.dumps(nested(65)))
        with self.assertRaisesRegex(av.Refusal, "nested deeper than 64"):    # objects count as arrays do
            av.strict_json(json.dumps({"a": nested(64)}))

    def test_bundle_with_a_deep_carried_member(self):
        d = load(V02)
        d["payment_payload"]["extensions"] = {"x": nested(60)}             # 2 + 1 + 60 levels: read
        self.assertNotIn("nested", json.dumps(cli(d)[1]))
        d["payment_payload"]["extensions"] = {"x": nested(900)}            # the stdlib parser reads it; 29.1 does not
        code, rep, _ = cli(d)
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertIn("SPEC 29.1", rep["reason"])

    def test_counted_iteratively(self):
        """a document built in memory, deeper than the stdlib parser goes, is refused without a RecursionError"""
        with self.assertRaisesRegex(av.Refusal, "nested deeper"):
            av._no_surrogates(nested(5000))


class InternalError(unittest.TestCase):
    """29.3: an exception no rule names is verdict `error`, exit 3; never 0, 1 or 2 (a traceback exits 1 = chain_failed)."""

    def test_error_is_exit_3(self):
        real = av.verify_bundle

        def broken(*a, **k):
            raise KeyError("planted")
        av.verify_bundle = broken
        try:
            code, rep, _ = cli(load(V02))
        finally:
            av.verify_bundle = real
        self.assertEqual((code, rep["verdict"]), (3, "error"))
        self.assertIn("KeyError", rep["reason"])

    def run_cli(self, doc, stdout):
        import subprocess
        import tempfile
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        with tempfile.NamedTemporaryFile(suffix=".json") as fh:
            fh.write(json.dumps(doc).encode())
            fh.flush()
            return subprocess.run([sys.executable, "-B", os.path.join(ROOT, "apc_verify.py"), fh.name], stdout=stdout,
                                  stderr=subprocess.PIPE, env=env).returncode

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_report_not_written_is_74(self):
        """Independent review 27/10: a report that cannot be written exited 1 (a traceback, read as chain_failed) when it was larger
        than the buffer, 120 when smaller, 0 with standard output closed; now 74 in each case, never 0-3"""
        import subprocess
        big = load(V02)
        big["Z" * 20000] = 1                    # refused, with a reason longer than the output buffer
        ok = load(V02)
        self.assertEqual(self.run_cli(ok, subprocess.DEVNULL), 0)               # control: written, chain_verified
        self.assertEqual(self.run_cli(big, subprocess.DEVNULL), 3)              # control: written, refused
        with open("/dev/full", "wb") as full:
            self.assertEqual(self.run_cli(big, full), 74)
            self.assertEqual(self.run_cli(ok, full), 74)
        r = subprocess.run([sys.executable, "-B", "-c", "import os, runpy, sys; os.close(1); sys.argv = sys.argv[1:]; "
                            "runpy.run_path(sys.argv[0], run_name='__main__')", os.path.join(ROOT, "apc_verify.py"), V02],
                           stderr=subprocess.PIPE, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        self.assertEqual(r.returncode, 74, r.stderr[-300:])
        # descriptor 1 closed before the interpreter starts: sys.stdout is None
        r = subprocess.run(["sh", "-c", 'exec "$0" -B "$1" "$2" >&-', sys.executable, os.path.join(ROOT, "apc_verify.py"), V02],
                           stderr=subprocess.PIPE, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        self.assertEqual(r.returncode, 74, r.stderr[-300:])

    def test_report_and_stderr_not_written_is_74(self):
        """Independent review 2 27/10: with standard error full too (or closed stdout, full stderr), the interpreter's last flush of
        standard error turned 74 into 120"""
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        # standard error closed too (sys.stderr None: AttributeError on the line), independent review, round 2 27/10: without these two
        # cases the AttributeError of the standard-error write could leave the handler (exit 1, or 120)
        for redir in (">/dev/full 2>/dev/full", ">&- 2>/dev/full", ">&- 2>&-", ">/dev/full 2>&-"):
            r = subprocess.run(["sh", "-c", 'exec "$0" -B "$1" "$2" ' + redir, sys.executable,
                                os.path.join(ROOT, "apc_verify.py"), V02], env=env)
            self.assertEqual(r.returncode, 74, redir)
        # standard output a closed file object (ValueError on write; mutant N04 of independent review 2 lived without this case)
        r = subprocess.run([sys.executable, "-B", "-c", "import io, runpy, sys; s = io.StringIO(); s.close(); "
                            "sys.stdout = s; sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')",
                            os.path.join(ROOT, "apc_verify.py"), V02], stderr=subprocess.PIPE, env=env)
        self.assertEqual(r.returncode, 74, r.stderr[-300:])
        # standard output and standard error closed file objects (ValueError on both writes)
        r = subprocess.run([sys.executable, "-B", "-c", "import io, runpy, sys; s = io.StringIO(); s.close(); "
                            "sys.stdout = sys.stderr = s; sys.argv = sys.argv[1:]; "
                            "runpy.run_path(sys.argv[0], run_name='__main__')",
                            os.path.join(ROOT, "apc_verify.py"), V02], stderr=subprocess.PIPE, env=env)
        self.assertEqual(r.returncode, 74, r.stderr[-300:])


class Rlp(unittest.TestCase):
    """29.2: RLP lists nested at most 16 deep (apc_block.RLP_MAX_DEPTH)."""

    @staticmethod
    def deep(n):
        """the RLP of [[...[b""]...]] with n lists, built from the inside (ab.rlp recurses)"""
        b = ab.rlp(b"")
        for _ in range(n):
            b = (bytes([0xC0 + len(b)]) if len(b) < 56 else
                 bytes([0xF7 + (len(b).bit_length() + 7) // 8]) + len(b).to_bytes((len(b).bit_length() + 7) // 8, "big")) + b
        return b

    def test_limit_and_one_past(self):
        self.assertEqual(ab.rlp_decode(self.deep(16)), nested(16, b""))
        with self.assertRaisesRegex(ab.BlockRefusal, "rlp_nested_too_deep"):
            ab.rlp_decode(self.deep(17))

    def test_empty_innermost_list(self):
        """Independent review 27/10: the bound was on the item, so 17 lists with the innermost empty were read"""
        def lists(n):
            b = b"\xc0"
            for _ in range(n - 1):
                b = bytes([0xC0 + len(b)]) + b
            return b
        self.assertEqual(ab.rlp_decode(lists(16)), nested(15, []))
        with self.assertRaisesRegex(ab.BlockRefusal, "rlp_nested_too_deep"):
            ab.rlp_decode(lists(17))

    def test_inclusion_proof_node_nested_3000_deep(self):
        """the node hashes to the header's transactionsRoot (the bundle writes both): B2 fails, no RecursionError"""
        d = load(V03)
        node = self.deep(3000)
        d["inclusion"]["block_header"]["transactionsRoot"] = "0x" + keccak256(node).hex()
        d["inclusion"]["tx_proof"] = ["0x" + node.hex()]
        code, rep, _ = cli(d)
        self.assertEqual(rep["checks"]["B2"], "failed:tx_proof:rlp_nested_too_deep")
        self.assertEqual((code, rep["verdict"]), (1, "chain_failed"))


class Xrpl(unittest.TestCase):
    """29.2: STObjects nested at most 10 deep (STArrays not counted); a VL blob at most 918744 bytes."""

    MEMO = next(tf for tf, f in sorted(xr.FIELDS.items()) if f["type"] == "STObject" and tf[1] < 16 and tf != (14, 1))

    def obj(self, n):
        fid = bytes([self.MEMO[0] << 4 | self.MEMO[1]])
        return fid * n + b"\xe1" * n            # ObjectEndMarker closes each

    def test_depth_limit_and_one_past(self):
        xr.decode(self.obj(9))                  # the top object plus 9 nested: 10
        with self.assertRaisesRegex(xr.XrplError, "nested deeper than 10"):
            xr.decode(self.obj(10))

    def test_arrays_not_counted(self):
        """Independent review 2 27/10: the bound counts STObjects only; 10 objects with 9 STArrays between them are read (SPEC 29.2)"""
        arr = next(tf for tf, f in sorted(xr.FIELDS.items()) if f["type"] == "STArray" and tf[1] < 16 and tf != (15, 1))
        a, o = bytes([arr[0] << 4 | arr[1]]), bytes([self.MEMO[0] << 4 | self.MEMO[1]])
        xr.decode((a + o) * 9 + (b"\xe1" + b"\xf1") * 9)
        with self.assertRaisesRegex(xr.XrplError, "nested deeper than 10"):
            xr.decode((a + o) * 10 + (b"\xe1" + b"\xf1") * 10)

    def test_payload_blob_nested_3000_deep(self):
        d = load(XRP)
        d["payment_payload"]["payload"]["signedTxBlob"] = self.obj(3000).hex().upper()
        code, rep, _ = cli(d)
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertIn("nested deeper than 10", rep["reason"])

    def test_vl_limit(self):
        xr.tx_leaf(b"\x00" * xr.VL_MAX, b"")
        with self.assertRaisesRegex(xr.XrplError, "longer than the VL prefix encodes"):
            xr.tx_leaf(b"\x00" * (xr.VL_MAX + 1), b"")

    def test_chain_tx_leaf_past_vl(self):
        """Independent review 27/10: the leaf of chain_tx itself past the VL bound is a refusal naming chain_tx (the bound lowered
        to 200 bytes so that one transaction of the set fits and the chain_tx meta, 749 bytes, does not)"""
        d = load(XRP)
        small = min(d["inclusion"]["transactions"], key=lambda t: max(len(t["tx_blob"]), len(t["meta"])))
        self.assertLessEqual(max(len(small["tx_blob"]), len(small["meta"])) // 2, 200)
        d["inclusion"]["transactions"] = [small]
        old = xr.VL_MAX
        try:
            xr.VL_MAX = 200
            code, rep, _ = cli(d)
        finally:
            xr.VL_MAX = old
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertTrue(rep["reason"].startswith("chain_tx: blob of "), rep["reason"])

    def test_inclusion_tx_blob_past_vl(self):
        """tests/fuzz_cases: a 6 MiB tx_blob in inclusion.transactions was a ValueError out of tx_leaf (exit 1)"""
        d = load(XRP)
        d["inclusion"]["transactions"][4]["tx_blob"] = "AB" * (xr.VL_MAX + 1)
        code, rep, _ = cli(d)
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertIn("inclusion.transactions[4]", rep["reason"])


class Base58(unittest.TestCase):
    """29.2: base58 text longer than its byte bound is refused before the quadratic conversion."""

    def test_bound(self):
        for n in (32, 64):
            self.assertEqual(sol.b58decode(sol.b58encode(b"\xff" * n), n), b"\xff" * n)
            self.assertEqual(sol.b58decode("1" * n, n), bytes(n))
        self.assertEqual(len(sol.b58encode(b"\xff" * 32)), 44)
        with self.assertRaisesRegex(sol.SolRefusal, "base58_too_long"):
            sol.b58decode("1" * 45, 32)
        sol.b58decode(sol.b58encode(b"\xff" * sol.B58_MAX_BYTES))
        # Independent review 27/10: the bound without a size is ceil(1232 * log 256 / log 58) = 1683 characters, one past refused
        self.assertEqual(sol.B58_MAX_BYTES, 1232)
        self.assertEqual(len(sol.b58encode(b"\xff" * sol.B58_MAX_BYTES)), 1683)
        with self.assertRaisesRegex(sol.SolRefusal, "base58_too_long"):
            sol.b58decode("2" * 1684)
        with self.assertRaisesRegex(sol.SolRefusal, "base58_too_long"):
            sol.b58decode("2" * 1700)

    def test_fuzz_case_long_mint(self):
        """tests/fuzz_cases (s1:88): a 1 MiB mint in meta.preTokenBalances took more than 20 s of CPU"""
        d = load(SVM)
        d["chain_tx"]["meta"]["preTokenBalances"][0]["mint"] = "A" * (1 << 20)
        code, rep, sec = cli(d)
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertIn("base58_too_long", rep["reason"])
        self.assertLess(sec, 5)


class SolanaMetaTypes(unittest.TestCase):
    """29.4: the balance members read for nothing are checked to their type."""

    def test_each(self):
        base = load(SVM)
        self.assertEqual(av.verify_bundle(copy.deepcopy(base))["verdict"], "chain_verified")
        for k, v in (("owner", {}), ("owner", "7A3gjC5YNQ=="), ("programId", "x"),
                     ("uiTokenAmount.decimals", 1.5), ("uiTokenAmount.decimals", 256), ("uiTokenAmount.uiAmount", "1"),
                     ("uiTokenAmount.uiAmount", True), ("uiTokenAmount.uiAmountString", 5)):
            d = copy.deepcopy(base)
            b = d["chain_tx"]["meta"]["preTokenBalances"][0]
            if "." in k:
                b["uiTokenAmount"][k.split(".")[1]] = v
            else:
                b[k] = v
            with self.assertRaises(av.Refusal, msg=(k, v)):
                av.verify_bundle(d)
        d = copy.deepcopy(base)
        d["chain_tx"]["meta"]["preTokenBalances"][0]["uiTokenAmount"]["uiAmount"] = None    # the RPC writes null
        self.assertEqual(av.verify_bundle(d)["verdict"], "chain_verified")


class UpperX(unittest.TestCase):
    """29.4: no string of the JSON-RPC objects of an EVM bundle begins with "0X"."""

    def test_members_that_were_read_as_0x(self):
        base = load(V02)
        self.assertEqual(av.verify_bundle(copy.deepcopy(base))["verdict"], "chain_verified")
        for path in (("tx", "hash"), ("tx", "from"), ("tx", "blockHash"), ("log_authorization_used", "topics", 1),
                     ("log_authorization_used", "address"), ("log_transfer", "transactionHash")):
            d = copy.deepcopy(base)
            o = d["chain_tx"]
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = "0X" + o[path[-1]][2:]
            with self.assertRaisesRegex(av.Refusal, "SPEC 29.4", msg=path):
                av.verify_bundle(d)
        d = copy.deepcopy(base)
        d["chain_tx"]["tx"]["hash"] = d["chain_tx"]["tx"]["hash"].upper().replace("0X", "0x")    # digits: case ignored
        self.assertEqual(av.verify_bundle(d)["verdict"], "chain_verified")

    def test_other_versions(self):
        p = sorted(glob.glob(os.path.join(B, "real", "real_*.json")))[0]          # apc-0.1 (independent review 27/10)
        d = load(p)
        self.assertEqual(d["bundle_version"], "apc-0.1")
        self.assertEqual(av.verify_bundle(copy.deepcopy(d))["verdict"], "chain_verified")
        d["chain_tx"]["tx"]["hash"] = "0X" + d["chain_tx"]["tx"]["hash"][2:]
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.4"):
            av.verify_bundle(d)
        d = load(V03)
        d["inclusion"]["block_header"]["hash"] = "0X" + d["inclusion"]["block_header"]["hash"][2:]
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.4"):
            av.verify_bundle(d)
        d = load(AUTHCAP)
        d["chain_tx"]["tx"]["hash"] = "0X" + d["chain_tx"]["tx"]["hash"][2:]
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.4"):
            av.verify_bundle(d)
        d = load(os.path.join(B, "real_permit2", "p029_envelope_reconstructed_rpc.json"))
        d["payer_code"]["rpc"]["code"]["params"][0] = "0X" + d["payer_code"]["rpc"]["code"]["params"][0][2:]
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.4"):
            av.verify_bundle(d)
        d = load(os.path.join(B, "real_v02_wallet", "w_7702_direct.json"))
        d["payer_wallet"]["code"]["result"] = "0X" + d["payer_wallet"]["code"]["result"][2:]
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.4"):
            av.verify_bundle(d)

    @real_corpus.unless("real_v03_canonical")
    def test_canonical_l1_replies(self):
        d = load(os.path.join(B, "real_v03_canonical", "v001_b001_indirect_envelope_reconstructed.json"))
        d["canonical"]["l1_replies"][0]["result"] = "0X" + d["canonical"]["l1_replies"][0]["result"][2:]
        with self.assertRaisesRegex(av.Refusal, "SPEC 29.4"):
            av.verify_bundle(d)

    def test_text_outside_rpc_objects_untouched(self):
        d = load(V02)
        d["payment_payload"]["resource"] = {"url": "https://example.com/0X", "description": "0Xfoo"}
        self.assertEqual(av.verify_bundle(d)["verdict"], "chain_verified")


class AuthCaptureTopics(unittest.TestCase):
    """29.4: PaymentAuthorized has one indexed parameter: the escrow's event has exactly two topics."""

    def test_extra_topic(self):
        base = load(AUTHCAP)
        self.assertEqual(av.verify_bundle(copy.deepcopy(base))["checks"]["C3"], "verified")
        import apc_authcap as ac
        d = copy.deepcopy(base)
        lg = next(lg for lg in d["chain_tx"]["receipt"]["logs"] if lg["topics"][0].lower() == ac.EV_AUTHORIZED)
        lg["topics"].append(lg["topics"][1])
        self.assertEqual(av.verify_bundle(d)["checks"]["C3"], "failed:no_escrow_event_for_this_payment_info")


class Ap2Embedded(unittest.TestCase):
    """29.1 inside the AP2 evaluator: JSON in JWS segments and disclosures, and the resolved disclosure chain."""

    def test_jws_header_nested_past_the_parser(self):
        jwt = a2.b64u(b"[" * 5000 + b"]" * 5000) + ".e30.AA"
        with self.assertRaises(a2.CryptoFail) as e:
            a2._verify_jws(jwt, None, "leaf")
        self.assertEqual(e.exception.code, "SIGNATURE_INVALID")
        with self.assertRaises(a2.CryptoFail):
            a2._verify_jws(a2.b64u(json.dumps(nested(65)).encode()) + ".e30.AA", None, "leaf")

    def test_json_reader_limit(self):
        """apc_ap2._json: 64 levels read, 65 (objects too) a ValueError, past the parser's recursion a ValueError"""
        self.assertEqual(a2._json(json.dumps(nested(64))), nested(64))
        for t in (json.dumps(nested(65)), json.dumps({"a": nested(64)}), "[" * 5000 + "]" * 5000):
            with self.assertRaises(ValueError):
                a2._json(t)

    def test_disclosure_nested(self):
        with self.assertRaises(a2.CryptoFail) as e:
            a2._decode_disclosure(a2.b64u(b"[" * 5000 + b"]" * 5000), "leaf")
        self.assertEqual(e.exception.code, "DISCLOSURE_INVALID")

    def test_disclosure_chain(self):
        """each disclosure shallow, each one naming the next: the resolution depth is bounded (64)"""
        def chain(n):
            discs, inner = [], "end"
            for i in range(n):
                enc = a2.b64u(json.dumps(["salt%d" % i, inner]).encode())
                discs.append(enc)
                inner = {"...": a2.sha_b64u(enc)}
            return {"delegate_payload": [inner]}, {"disc": discs}
        env, tok = chain(62)       # the envelope, the list and 62 disclosures: the last value at depth 64
        self.assertEqual(a2._resolve_disclosures(env, tok, "leaf")["delegate_payload"][0], "end")
        env, tok = chain(63)
        with self.assertRaises(a2.CryptoFail):
            a2._resolve_disclosures(env, tok, "leaf")
        env, tok = chain(400)
        with self.assertRaises(a2.CryptoFail) as e:
            a2._resolve_disclosures(env, tok, "leaf")
        self.assertEqual(e.exception.code, "DISCLOSURE_INVALID")

    @unittest.skipUnless(CASES and os.path.isfile(CASES), "APC_PULSE_CASES (the pinned Pulse fixtures)")
    def test_mandate_in_a_bundle(self):
        with open(CASES) as fh:
            c = next(c for c in json.load(fh)["cases"] if c["expected"]["consistent"])
        ev = c["ap2"]["verification"]["cryptographicEvidence"]
        ev["mandateChain"] = a2.b64u(b"[" * 5000 + b"]" * 5000) + ev["mandateChain"][ev["mandateChain"].index("."):]
        d = {"bundle_version": "apc-0.1", "payment_payload": copy.deepcopy(c["x402"]["payload"]),
             "mandate": {"profile": "pulse-ap2-x402/0.3", "case": c}}
        code, rep, _ = cli(d)
        self.assertEqual((code, rep["verdict"]), (1, "chain_failed"))
        self.assertTrue(rep["checks"]["M1"].startswith("failed:ap2_"), rep["checks"]["M1"])


class DeliveryReceiptDraft(unittest.TestCase):
    """the draft profile of x402 PR 3783 parses JSON inside an SSE event: a deep one is a failure, not a traceback"""

    def test_sse_event_nested(self):
        stream = "event: x402-delivery-receipt\ndata: " + "[" * 5000 + "]" * 5000 + "\n\n"
        levels, why = dr.verify_session({"eventStream": stream})
        self.assertTrue(why["code"].startswith("VERIFIER_INPUT_"), why)      # RecursionError on 3.11; 3.13 parses it

    def test_sse_event_depth_limit(self):
        """29.1: 64 deep is read (and fails later, for another reason), 65 deep is the depth failure"""
        def run(depth):
            ev = json.dumps({"a": nested(depth - 1)})
            return dr.verify_session({"eventStream": "event: x402-delivery-receipt\ndata: " + ev + "\n\n"})[1]["code"]
        self.assertNotEqual(run(64), "VERIFIER_INPUT_ValueError")
        self.assertEqual(run(65), "VERIFIER_INPUT_ValueError")

    def test_in_memory_document_past_the_stack(self):
        """verify_session called directly (not through a parsed bundle) with a document object 5000 deep: _jcs runs out
        of stack; that is the profile's VERIFIER_INPUT_ failure, never an exception out of it"""
        ref = {"digest": "00", "receiptId": "x", "receiptUrl": "https://e/x"}
        why = dr.verify_session({"reference": ref, "receiptDocument": {"a": nested(5000)}})[1]
        self.assertEqual(why["code"], "VERIFIER_INPUT_RecursionError")

    def test_reference_document_depth_limit(self):
        """29.1: the receipt document named by its digest, 64 deep read, 65 deep the depth failure"""
        import hashlib

        def run(depth):
            doc = json.dumps({"a": nested(depth - 1)}, separators=(",", ":"))       # JCS form: integers, one member
            ref = {"digest": hashlib.sha256(doc.encode()).hexdigest(), "receiptId": "x", "receiptUrl": "https://e/x"}
            return dr.verify_session({"reference": ref, "receiptDocument": doc})[1]["code"]
        self.assertNotEqual(run(64), "VERIFIER_INPUT_ValueError")
        self.assertEqual(run(65), "VERIFIER_INPUT_ValueError")


class McpLine(unittest.TestCase):
    """29.2: one JSON-RPC message line is at most apc_mcp.MAX_LINE bytes; the rest of a longer line is dropped."""

    def run_lines(self, data, limit):
        old_in, old_out, old_max = sys.stdin, sys.stdout, apc_mcp.MAX_LINE
        out = io.StringIO()
        sys.stdin = io.TextIOWrapper(io.BytesIO(data))
        sys.stdout = out
        apc_mcp.MAX_LINE = limit
        try:
            apc_mcp.main()
        finally:
            sys.stdin, sys.stdout, apc_mcp.MAX_LINE = old_in, old_out, old_max
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_long_line(self):
        self.assertEqual(apc_mcp.MAX_LINE, 2 * av.MAX_BUNDLE_BYTES + (1 << 20))
        ping = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode()
        out = self.run_lines(b" " * 5000 + ping + b"\n" + ping + b"\n", 4096)
        self.assertEqual(len(out), 2, out)                       # the ping at the end of the long line is not read
        self.assertEqual(out[0]["error"]["code"], -32600)
        self.assertEqual(out[1], {"jsonrpc": "2.0", "id": 7, "result": {}})
        out = self.run_lines(ping + b"\n", len(ping) + 1)          # at the limit: read
        self.assertEqual(out, [{"jsonrpc": "2.0", "id": 7, "result": {}}])


class FuzzCases(unittest.TestCase):
    """every case of tests/fuzz_cases: rebuilt from its real base bundle, run as the command line runs it, an outcome
    of SPEC section 5 in under 5 s of CPU, never `error`"""

    def test_all(self):
        d = os.path.join(ROOT, "tests", "fuzz_cases")
        names = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        self.assertTrue(names)
        for n in names:
            with open(os.path.join(d, n)) as fh:
                case = json.load(fh)
            doc = load(os.path.join(ROOT, case["base"]))
            o = doc
            for k in case["path"][:-1]:
                o = o[int(k) if isinstance(o, list) else k]
            last = case["path"][-1]
            last = int(last) if isinstance(o, list) else last
            v = case["value"]
            o[last] = v["repeat"] * v["times"] if isinstance(v, dict) and "repeat" in v else v
            code, rep, sec = cli(doc, case.get("options", []))
            self.assertIn(code, (0, 1, 2, 3), n)
            self.assertEqual(code, {"chain_verified": 0, "chain_failed": 1, "chain_incomplete": 2}.get(rep["verdict"], 3))
            self.assertNotEqual(rep["verdict"], "error", n)
            self.assertEqual(rep["verdict"], case["expect_verdict"], (n, rep.get("reason")))
            self.assertLess(sec, 5, n)


class KeccakBudget(unittest.TestCase):
    """29.2: at most apc_block.KECCAK_BUDGET (1 MiB) hashed with Keccak-256 in one verification (corpus: 75765 at most)"""

    def test_budget(self):
        self.assertEqual(ab.KECCAK_BUDGET, 1 << 20)
        d = load(V02)
        d["payment_payload"]["accepted"]["extra"]["name"] = "a" * (2 << 20)
        t0 = time.process_time()
        with self.assertRaisesRegex(av.Refusal, "Keccak-256 \\(SPEC 29.2\\)"):
            av.verify_bundle(d)
        self.assertLess(time.process_time() - t0, 5)
        self.assertIsNone(ab.KECCAK_SPENT)                       # closed again: nothing counted outside
        ab.keccak256(b"a" * 10)
        self.assertIsNone(ab.KECCAK_SPENT)
        self.assertEqual(av.verify_bundle(load(V02))["verdict"], "chain_verified")

    def test_at_the_limit(self):
        old = ab.KECCAK_BUDGET
        try:
            ab.KECCAK_SPENT = 0
            ab.KECCAK_BUDGET = 100
            ab.keccak256(b"a" * 100)
            with self.assertRaises(ab.HashBudget):
                ab.keccak256(b"a")
        finally:
            ab.KECCAK_BUDGET, ab.KECCAK_SPENT = old, None

    def test_cli(self):
        d = load(V02)
        d["payment_payload"]["accepted"]["extra"]["name"] = "a" * (2 << 20)
        code, rep, sec = cli(d)
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertLess(sec, 5)

    def test_drafts_have_their_own_budget(self):
        """Independent review 27/10: the draft profiles hashed under the merged rules' budget, so --drafts turned a chain_verified
        real bundle carrying a 1 MiB compliance-fields record (read only by the PR 2853 profile) into refused, exit 3
        (section 17: verdict, checks and exit are the merged rules' with or without --drafts)"""
        import apc_drafts3 as d3
        d = load(V03)
        d["settlement"]["extensions"] = {"compliance-fields": {"info": {"record": {
            "version": 1, "canonicalizationVersion": 1, "receiptDigest": "0x" + "00" * 32,
            "issuer": {"name": "X" * (1 << 20)}}}}}
        a = av.verify_bundle(copy.deepcopy(d))
        self.assertEqual(a["verdict"], "chain_verified")
        t0 = time.process_time()
        b = av.verify_bundle(copy.deepcopy(d), drafts=True)
        self.assertLess(time.process_time() - t0, 10)
        self.assertEqual({k: v for k, v in b.items() if k != "drafts"}, a)
        self.assertEqual(b["drafts"][d3.P2853]["checks"], {"budget": "not_evaluated:keccak_budget"})
        self.assertEqual(b["drafts"][d3.P2853]["verdict"], "draft_incomplete")
        self.assertIsNone(ab.KECCAK_SPENT)
        for flags in ([], ["--drafts"]):
            code, rep, _ = cli(d, flags)
            self.assertEqual((code, rep["verdict"]), (0, "chain_verified"), flags)
        # a budget of their own, not what the merged rules left: V03's merged rules hash 6658 bytes (measured 27/10),
        # the PR 2853 profile about 150 + the name; KECCAK_BUDGET - 4000 fits the drafts' budget alone, not the sum
        d = load(V03)
        d["settlement"]["extensions"] = {"compliance-fields": {"info": {"record": {
            "version": 1, "canonicalizationVersion": 1, "receiptDigest": "0x" + "00" * 32,
            "issuer": {"name": "X" * (ab.KECCAK_BUDGET - 4000)}}}}}
        b = av.verify_bundle(copy.deepcopy(d), drafts=True)
        self.assertEqual(b["verdict"], "chain_verified")
        self.assertEqual(b["drafts"][d3.P2853]["checks"]["CF1"], "verified")
        # apc_drafts2 too (PR 3604: the claimId is hashed for the EIP-191 recovery whatever DC2 says)
        import apc_drafts2 as d2
        d = load(V03)
        claim = {"sellerAddress": "0x" + "11" * 20, "buyerAddress": "0x" + "22" * 20, "assetType": "api-credits",
                 "promisedSpec": "x", "delivered": "yes", "evidenceHash": "00" * 32, "settlementRef": "x",
                 "timestamp": "2026-10-27T00:00:00.000Z", "claimId": "Y" * (1 << 20), "signature": "0x" + "11" * 65}
        d["draft_artifacts"] = [{"profile": d2.P3604, "artifact": claim}]
        a = av.verify_bundle(copy.deepcopy(d))
        b = av.verify_bundle(copy.deepcopy(d), drafts=True)
        self.assertEqual({k: v for k, v in b.items() if k != "drafts"}, a)
        self.assertEqual(b["drafts"][d2.P3604]["checks"], {"budget": "not_evaluated:keccak_budget"})
        # apc_drafts too (PR 3827: the version-2 receipt is hashed for its EIP-712 signer; the merged rules do not read
        # version 2): independent review 2 27/10, a 1.2 MB receipt `transaction` turned chain_incomplete into refused, exit 3
        import test_drafts as tdr
        d = tdr.v2_bundle()
        d["settlement"]["extensions"]["offer-receipt"]["info"]["receipt"]["payload"]["transaction"] = "0x" + "ab" * 600000
        a = av.verify_bundle(copy.deepcopy(d), signer_trust=tdr.trust())
        self.assertEqual(a["verdict"], "chain_incomplete")
        b = av.verify_bundle(copy.deepcopy(d), signer_trust=tdr.trust(), drafts=True)
        self.assertEqual({k: v for k, v in b.items() if k != "drafts"}, a)
        self.assertEqual(b["drafts"][tdr.dr.P3827]["checks"], {"budget": "not_evaluated:keccak_budget"})
        self.assertIsNone(ab.KECCAK_SPENT)
        # inside a count opened by a caller, the drafts' bytes are not added to it and the caller's count comes back
        try:
            ab.KECCAK_SPENT = 0
            av.verify_bundle(load(V03))
            alone = ab.KECCAK_SPENT
            ab.KECCAK_SPENT = 0
            av.verify_bundle(load(V03), drafts=True)
            self.assertGreater(alone, 0)
            self.assertEqual(ab.KECCAK_SPENT, alone)
        finally:
            ab.KECCAK_SPENT = None
        # the merged rules keep theirs: a record the merged rules hash is still counted and refused
        d = load(V02)
        d["payment_payload"]["accepted"]["extra"]["name"] = "a" * (2 << 20)
        with self.assertRaisesRegex(av.Refusal, "Keccak-256 \\(SPEC 29.2\\)"):
            av.verify_bundle(d, drafts=True)


class HttpLabels(unittest.TestCase):
    """29.2: at most 64 RFC 9421 signature labels per message (measured: 3.4 s of CPU for 1024 labels with keys)"""

    def doc(self, n, m=None):
        import test_http as th
        d = th.rfc_doc()
        f = d["exchange"]["response"]["fields"]
        si = next(v for k, v in f if k == "Signature-Input").split("=", 1)[1]
        sg = next(v for k, v in f if k == "Signature").split("=", 1)[1]
        f[:] = [x for x in f if x[0] not in ("Signature-Input", "Signature")]
        f += [["Signature-Input", ", ".join("s%d=%s" % (i, si) for i in range(n))],
              ["Signature", ", ".join("s%d=%s" % (i, sg) for i in range(n if m is None else m))]]
        return d, th

    def test_each_field_bounded(self):
        """Independent review 27/10: 65 labels in only one of the two fields (the bound read with `or`)"""
        for n, m in ((65, 1), (1, 65)):
            d, th = self.doc(n, m)
            with self.assertRaisesRegex(av.Refusal, "more than 64 signature labels", msg=(n, m)):
                th.sigs(d)

    def test_limit(self):
        d, th = self.doc(64)
        self.assertEqual(th.sigs(d)[0]["X7"], "verified")
        d, th = self.doc(65)
        with self.assertRaisesRegex(av.Refusal, "more than 64 signature labels"):
            th.sigs(d)
        with self.assertRaisesRegex(av.Refusal, "more than 64 signature labels"):
            th.sigs(d, None)                                    # without keys too: one grammar


class ExistingLimits(unittest.TestCase):
    """the limits that were in the code before section 29 with no test naming them (inventory of 2026-10-26): at the
    limit read, one past it refused"""

    def test_stdlib_recursion_on_the_command_line(self):
        code, rep, _ = cli(b"[" * 100000 + b"]" * 100000)
        self.assertEqual((code, rep["verdict"]), (3, "refused"))
        self.assertRegex(rep["reason"], "nested too deep|nested deeper than 64")

    def test_uint256_digits(self):
        self.assertEqual(av._uint(str((1 << 256) - 1), "v"), (1 << 256) - 1)
        for v in (str(1 << 256), "9" * 79, "9" * 5000):
            with self.assertRaisesRegex(av.Refusal, "exceeds uint256"):
                av._uint(v, "v")

    def test_mpt_and_l1_proof_nodes(self):
        import apc_l1proof as l1
        with self.assertRaisesRegex(ab.BlockRefusal, "proof_node_hash_mismatch"):
            ab.verify_proof(bytes(32), b"\x80", [b"\xc0"] * 64)
        with self.assertRaisesRegex(ab.BlockRefusal, "proof_not_a_node_list"):
            ab.verify_proof(bytes(32), b"\x80", [b"\xc0"] * 65)
        with self.assertRaisesRegex(ab.BlockRefusal, "proof_node_hash_mismatch"):
            l1.proof_get(bytes(32), b"\x80", [b"\xc0"] * 64)
        with self.assertRaisesRegex(ab.BlockRefusal, "proof_not_a_node_list"):
            l1.proof_get(bytes(32), b"\x80", [b"\xc0"] * 65)

    def test_xdr_count(self):
        import apc_stellar as st
        self.assertEqual(st.R(b"\x00\x00\x00\x02" + bytes(8)).count(), 2)
        with self.assertRaisesRegex(st.StellarRefusal, "xdr_array_length"):
            st.R(b"\x00\x00\x00\x03" + bytes(8)).count()           # 3 entries cannot fit in 8 bytes
        with self.assertRaisesRegex(st.StellarRefusal, "xdr_array_length"):
            st.R(b"\xff\xff\xff\xff").count()

    def test_i128_digits(self):
        import apc_xlm
        m = (1 << 127) - 1
        self.assertEqual(apc_xlm._amount(str(m), "a"), m)
        for v in (str(m + 1), "9" * 40, "9" * 5000):
            with self.assertRaisesRegex(av.Refusal, "i128"):
                apc_xlm._amount(v, "a")

    def test_xrpl_address_length(self):
        a = xr.classic_address(bytes(range(20)))
        self.assertEqual(xr.account_id(a), bytes(range(20)))
        for s_ in ("r" * 24, "r" * 36, "r" * 100000):
            with self.assertRaisesRegex(xr.XrplError, "not an XRPL base58 string"):
                xr.b58check_decode(s_)

    def test_http_fields_and_sf_integer(self):
        import apc_http as h
        h._fields([["a", "b"]] * h.MAX_FIELDS, "f", 0)
        with self.assertRaisesRegex(av.Refusal, "fields"):
            h._fields([["a", "b"]] * (h.MAX_FIELDS + 1), "f", 0)
        self.assertEqual(h.parse_dictionary("a=999999999999999"), [("a", (999999999999999, []))])
        with self.assertRaises(h.SFError):
            h.parse_dictionary("a=1000000000000000")
        with self.assertRaises(h.SFError):
            h.parse_dictionary("a=" + "1" * 100000)

    def test_mcp_text(self):
        old = apc_mcp.MAX_TEXT
        apc_mcp.MAX_TEXT = 10
        try:
            self.assertEqual(apc_mcp._text({"t": "x" * 10}, "t"), "x" * 10)
            with self.assertRaisesRegex(av.Refusal, "at most 10 bytes"):
                apc_mcp._text({"t": "é" * 6}, "t")                  # 12 UTF-8 bytes
        finally:
            apc_mcp.MAX_TEXT = old


class Harness(unittest.TestCase):
    """tools/fuzz_bundles.classify: each kind of defect is named, an outcome of section 5 is not"""

    def test_classify(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import fuzz_bundles as fb
        ok = {"cpu": 0.1, "wall": 0.1, "maxrss_mib": 50, "exit": 3}

        def rep(v, **k):
            return json.dumps(dict({"verdict": v, "checks": {"C1": "verified"}}, **k)).encode()
        cases = [
            (ok, rep("refused"), "", "chain_failed", False, None),
            (dict(ok, exit=0), rep("chain_verified"), "", "chain_verified", False, None),
            (dict(ok, exit=70), b"", "Traceback", "chain_failed", False, "crash"),
            (dict(ok, exit=71), b"", "MemoryError", "chain_failed", False, "memory"),
            (dict(ok, exit=4), rep("refused"), "", "chain_failed", False, "exit"),
            (dict(ok, exit=1), rep("refused"), "", "chain_failed", False, "exit"),
            (ok, b"not json", "", "chain_failed", False, "exit"),
            (ok, rep("error"), "", "chain_failed", False, "crash"),
            (dict(ok, cpu=5.5), rep("refused"), "", "chain_failed", False, "time"),
            ({"kind": "signal", "signal": 24, "cpu": 21, "wall": 21, "maxrss_mib": 1}, None, "", "chain_failed", False, "time"),
            ({"kind": "signal", "signal": 11, "cpu": 1, "wall": 1, "maxrss_mib": 1}, None, "", "chain_failed", False, "crash"),
            (dict(ok, maxrss_mib=3000), rep("refused"), "", "chain_failed", False, "memory"),
            (dict(ok, exit=0), rep("chain_verified"), "", "chain_failed", False, "promoted"),
            # an artifact taken away (fuzz s8:2204, chain_tx deleted from a failed Solana bundle): section 5, no defect
            (dict(ok, exit=0), rep("chain_verified", checks={"C1": "not_evaluated:absent:no_chain_tx"}), "",
             "chain_failed", False, None),
            (dict(ok, exit=1), rep("chain_failed"), "", "chain_verified", True, "equivalence"),
            (dict(ok, exit=0), rep("chain_verified", checks={"C1": "failed:x"}), "", "chain_verified", True, "equivalence"),
        ]
        for res, out, err, base, eq, want in cases:
            self.assertEqual(fb.classify(res, out, err, base, {"C1": "verified"}, eq, 5, 2048)[0], want, (res, out, base))


if __name__ == "__main__":
    unittest.main()
