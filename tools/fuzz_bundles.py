"""The bundle as hostile input (SPEC section 29): structural fuzzing of apc_verify from the real bundles of the frozen
corpus (regress/VERDICTS.json). Standard library only; Linux (fork, wait4, resource limits).

  python3 tools/fuzz_bundles.py run SEED N [--families F01,F02,...] [--out DIR] [--cpu-cap S] [--mem-cap MiB]
  python3 tools/fuzz_bundles.py replay CASE.json          (one saved case again: its outcome as JSON)
  python3 tools/fuzz_bundles.py seeds DIR                 (bundles from the test helpers; then run --bases DIR/index.json)

Case i of seed S is drawn by random.Random("S:i") alone: the base bundle (bases taken round-robin over the corpus,
sorted by path), the family and every choice inside it, so a case is reproduced from (S, i) without the others.
Each case is written to a scratch file and run as `apc_verify.py [options of its directory] FILE` in a forked child of
this process (apc_verify imported once in the parent): RLIMIT_AS = --mem-cap MiB (default 2048), RLIMIT_CPU and an
alarm as a hard stop, stdout and stderr to files. An outcome is a DEFECT when
  crash      the child ended by an exception (a traceback: the command line would print it and exit 1, an outcome
             it never chose) or by a signal other than the hard stops below;
  exit       the exit code is not 0, 1, 2 or 3 (SPEC section 5), or the report does not parse, or its verdict does
             not match its exit code;
  time       the child's CPU time is over --cpu-cap seconds (default 5) or it was stopped by the hard stop;
  memory     MemoryError, or the child's maximum resident set over --mem-cap;
  promoted   the mutated bundle is chain_verified while its base is not, unless more of its checks are
             `not_evaluated:absent:` than the base's (an artifact taken away: section 5 judges only what is carried
             and lists the rest under `absent`);
  equivalence a declared equivalence (F12: members reordered at every level, other JSON whitespace) changed the
             verdict or a check.
A value-changing mutation of a chain_verified base that stays chain_verified is not a defect by itself (members the
SPEC carries and does not interpret exist); it is listed under `survivors` with its path for review.
Only DEFECT cases are saved (the mutated bundle, greedily reduced while the same defect signature remains, plus its
seed, index, family, path and outcome) under --out (default fuzz_found/, ignored by git); the summary is printed as
JSON. A case kept as a test is rewritten by hand into tests/fuzz_cases as (base, path, value, expected verdict), the
form tests/test_hostile.FuzzCases rebuilds; the raw records are not that form and never go there.
"""
import base64
import binascii
import collections
import contextlib
import hashlib
import io
import json
import os
import random
import re
import resource
import signal
import sys
import tempfile
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FAMILIES = {
    "F01": "new member at a random level",
    "F02": "value replaced by a value of another type",
    "F03": "duplicate JSON member (text level)",
    "F04": "numbers: huge, negative, float, exponent, beyond int digits; decimal strings likewise",
    "F05": "very long string",
    "F06": "hex: odd length, upper case, 0X, non-hex digit, empty, very long",
    "F07": "unicode: unpaired surrogate escape, NUL, non-ASCII digits, BOM, invalid UTF-8",
    "F08": "deep nesting at a leaf",
    "F09": "list beyond its bound (65, 1000, 20000 entries)",
    "F10": "binary blob (hex or base64: RLP, XDR, CBOR, XRPL codec, Solana wire) truncated, flipped, false lengths",
    "F11": "proof lists inflated: nodes duplicated, reordered, one huge node",
    "F12": "declared equivalence: members reordered at every level, other whitespace",
    "F13": "member deleted",
    "F14": "file level: empty, truncated JSON, trailing bytes, top level not an object",
}
VALUE_FAMILIES = {"F02", "F04", "F05", "F06", "F07", "F10", "F11"}
CODES = {"chain_verified": 0, "chain_failed": 1, "chain_incomplete": 2}


# ------------------------------------------------------------------ JSON tree helpers (order kept)
def load(b):
    return json.loads(b, object_pairs_hook=lambda p: dict(p))


def nodes(o, path=()):
    yield path, o
    if isinstance(o, dict):
        for k, v in o.items():
            yield from nodes(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from nodes(v, path + (i,))


def get(o, path):
    for k in path:
        o = o[k]
    return o


def put(o, path, v):
    get(o, path[:-1])[path[-1]] = v


HEX = re.compile(r"(0x)?([0-9a-fA-F]{2})+\Z")
B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}\Z")


def blob_kind(s):
    if not isinstance(s, str) or len(s) < 8:
        return None
    if HEX.match(s) and (s.startswith("0x") or len(s) >= 16):
        return "hex"
    if len(s) % 4 == 0 and B64.match(s):
        try:
            base64.b64decode(s, validate=True)
            return "b64"
        except (binascii.Error, ValueError):
            return None
    return None


def blob_decode(s, kind):
    if kind == "hex":
        return bytes.fromhex(s[2:] if s.startswith("0x") else s)
    return base64.b64decode(s)


def blob_encode(b, kind, like):
    if kind == "hex":
        return ("0x" if like.startswith("0x") else "") + (b.hex().upper() if like[2:4].isupper() else b.hex())
    return base64.b64encode(b).decode()


def mutate_bytes(rng, b):
    b = bytearray(b)
    op = rng.choice(["truncate", "flip", "lenlie", "lenlie4", "extend", "dup", "zero_tail", "cut_head"])
    if not b:
        return bytes([0xff]), "extend"
    i = rng.randrange(len(b))
    if op == "truncate":
        b = b[:i]
    elif op == "flip":
        b[i] ^= 1 << rng.randrange(8)
    elif op == "lenlie":                       # RLP / CBOR / shortvec / XRPL VL length bytes
        b[i] = rng.choice([0x7f, 0x80, 0x81, 0xb7, 0xb8, 0xbf, 0xc0, 0xf7, 0xf8, 0xff, 0x1b, 0x9b, 0xbb, 0xc1, 0xf0, 0xfe])
    elif op == "lenlie4":                      # XDR: a 4-byte aligned word set to a large length
        j = (i // 4) * 4
        b[j:j + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x7f\xff\xff\xff", b"\x00\x10\x00\x00", b"\x00\x00\x00\xff"])
    elif op == "extend":
        b += bytes(rng.randrange(256) for _ in range(rng.choice([1, 7, 64, 4096])))
    elif op == "dup":
        j = rng.randrange(i, len(b) + 1)
        b[j:j] = b[i:j] * rng.choice([1, 2, 50])
    elif op == "zero_tail":
        b[i:] = bytes(len(b) - i)
    elif op == "cut_head":
        b = b[i:]
    return bytes(b), op


def deep(v, n, rng):
    for _ in range(n):
        v = [v] if rng.random() < .5 else {"a": v}
    return v


HUGE_DIGITS = "9" * 5000          # beyond Python's int_max_str_digits (4300)


def mutate(rng, base_bytes, family):
    """-> (bytes of the mutated bundle, path, op, equivalence?)"""
    doc = load(base_bytes)
    allp = list(nodes(doc))
    if family == "F14":
        op = rng.choice(["empty", "truncated", "trailing", "list", "string", "number", "null", "bom", "nul_in"])
        txt = base_bytes
        out = {"empty": b"", "truncated": txt[:rng.randrange(1, max(2, len(txt)))], "trailing": txt + b" {}",
               "list": b"[" + txt + b"]", "string": b'"apc-0.1"', "number": b"1e400", "null": b"null",
               "bom": b"\xef\xbb\xbf" + txt, "nul_in": txt[:1] + b"\x00" + txt[1:]}[op]
        return out, (), op, False
    if family == "F03":
        objs = [(p, o) for p, o in allp if isinstance(o, dict) and o]
        p, o = rng.choice(objs)
        k = rng.choice(list(o))
        o["\x00DUP\x00"] = rng.choice([o[k], 0, "x", None])
        txt = json.dumps(doc, ensure_ascii=False).replace('"\\u0000DUP\\u0000"', json.dumps(k, ensure_ascii=False))
        return txt.encode("utf-8"), p + (k,), "dup", False
    if family == "F12":
        def shuf(o):
            if isinstance(o, dict):
                ks = list(o)
                rng.shuffle(ks)
                return {k: shuf(o[k]) for k in ks}
            if isinstance(o, list):
                return [shuf(x) for x in o]
            return o
        sep = rng.choice([(", ", ": "), (",", ":"), (" ,\n", " :\t")])
        return json.dumps(shuf(doc), separators=sep, indent=rng.choice([None, 0, 3])).encode(), (), "reorder", True
    if family == "F07" and rng.random() < .4:     # text level: surrogate escape, invalid UTF-8
        txt = json.dumps(doc)
        strs = [m.start() + 1 for m in re.finditer(r'"[^"\\]{2,}"', txt)]
        i = rng.choice(strs) if strs else 1
        ins = rng.choice(["\\ud800", "\\udfff", "\\ud83d", b"\xff", b"\xc0\xaf"])
        raw = txt[:i].encode() + (ins if isinstance(ins, bytes) else ins.encode()) + txt[i:].encode()
        return raw, (), "text:" + repr(ins), False
    leaves = [(p, o) for p, o in allp if p]
    if family == "F01":
        objs = [(p, o) for p, o in allp if isinstance(o, dict)]
        p, o = rng.choice(objs)
        name = rng.choice(["zz", "__proto__", "x402Version", "", "é", "constructor", "extra", "hash"])
        if name in o:
            name += "_"
        o[name] = rng.choice([0, "0x", None, {}, [], "x"])
        return dump(doc), p + (name,), "new:" + name, False
    if family == "F13":
        p, _ = rng.choice([(p, o) for p, o in leaves if isinstance(get(doc, p[:-1]), dict)] or leaves)
        parent = get(doc, p[:-1])
        if isinstance(parent, dict):
            del parent[p[-1]]
        else:
            parent.pop(p[-1])
        return dump(doc), p, "del", False
    if family == "F02":
        p, o = rng.choice(leaves)
        cands = [None, True, False, 0, -1, 1.5, "", "x", [], {}, [o], {"v": o}, str(o) if not isinstance(o, str) else 7]
        put(doc, p, rng.choice([c for c in cands if type(c) is not type(o)] or [None]))
        return dump(doc), p, "type", False
    if family == "F04":
        nums = [(p, o) for p, o in leaves if (isinstance(o, (int, float)) and not isinstance(o, bool))
                or (isinstance(o, str) and re.fullmatch(r"-?(0x)?[0-9a-fA-F]+", o) and len(o) < 80)]
        p, o = rng.choice(nums or leaves)
        if isinstance(o, str):
            v = rng.choice([HUGE_DIGITS, "-" + o.lstrip("-"), "0" + o, o + "e5", "1e400", "0x" + "f" * 4000,
                            "00", "+1", " 1", "1.0", str(1 << 256), "0x" + "0" * 70 + "1", "١٢"])
        else:
            v = rng.choice(["HUGE", -1, -0.0, 1.5, 1e308, 2 ** 64, 2 ** 256, 10 ** 4000, 1e-300, "E"])
        if v == "HUGE":
            txt = dump(doc, sentinel=(p, "\x00N\x00"))
            return txt.replace(b'"\\u0000N\\u0000"', HUGE_DIGITS.encode()), p, "num:huge", False
        if v == "E":
            txt = dump(doc, sentinel=(p, "\x00N\x00"))
            return txt.replace(b'"\\u0000N\\u0000"', b"1E+2"), p, "num:exp", False
        put(doc, p, v)
        return dump(doc), p, "num:%r" % (v if not isinstance(v, (int, str)) or len(str(v)) < 30 else "long"), False
    if family == "F05":
        strs = [(p, o) for p, o in leaves if isinstance(o, str)] or leaves
        p, o = rng.choice(strs)
        n = rng.choice([1 << 16, 1 << 20, 6 << 20])
        put(doc, p, (o if isinstance(o, str) and o else "a") * (n // max(1, len(o) if isinstance(o, str) else 1)))
        return dump(doc), p, "long:%d" % n, False
    if family == "F06":
        hx = [(p, o) for p, o in leaves if isinstance(o, str) and HEX.match(o)] or \
             [(p, o) for p, o in leaves if isinstance(o, str)] or leaves
        p, o = rng.choice(hx)
        o = o if isinstance(o, str) else "0x00"
        body = o[2:] if o.startswith("0x") else o
        pre = "0x" if o.startswith("0x") else ""
        v = rng.choice([pre + body[:-1], pre + body.upper(), "0X" + body, pre + body[:-1] + "g", pre, "0x",
                        pre + body * 2000, pre + "0" + body, " " + o, o + "\n", "0x" + body.replace("a", "A", 1)])
        put(doc, p, v)
        return dump(doc), p, "hex", False
    if family == "F07":
        strs = [(p, o) for p, o in leaves if isinstance(o, str)] or leaves
        p, o = rng.choice(strs)
        o = o if isinstance(o, str) else ""
        i = rng.randrange(len(o) + 1)
        ins = rng.choice(["\x00", "١", "０", "​", "‮", "﻿", "é", "\U0001f600", "́", "K",
                          "K", "İ"])
        put(doc, p, o[:i] + ins + o[i:])
        return dump(doc), p, "uni:%r" % ins, False
    if family == "F08":
        p, o = rng.choice(leaves)
        n = rng.choice([40, 400, 900, 980, 2000, 50000])
        if n <= 400:
            put(doc, p, deep(o, n, rng))
            return dump(doc), p, "deep:%d" % n, False
        txt = dump(doc, sentinel=(p, "\x00D\x00"))           # beyond json.dumps' own recursion: built as text
        return txt.replace(b'"\\u0000D\\u0000"', b"[" * n + json.dumps(o).encode() + b"]" * n), p, "deep:%d" % n, False
    if family == "F09":
        lists = [(p, o) for p, o in allp if isinstance(o, list) and o and p]
        if not lists:
            p, o = rng.choice(leaves)
            lists = [(p, [o])]
            put(doc, p, [o])
        p, o = rng.choice(lists)
        n = rng.choice([65, 1000, 20000])
        put(doc, p, (o * (n // len(o) + 1))[:n])
        return dump(doc), p, "list:%d" % n, False
    if family in ("F10", "F11"):
        blobs = [(p, o, blob_kind(o)) for p, o in leaves if blob_kind(o)]
        if family == "F11":
            lists = [(p, o) for p, o in allp if isinstance(o, list) and o and all(blob_kind(x) for x in o) and p]
            if lists:
                p, o = rng.choice(lists)
                op = rng.choice(["dupnode", "reverse", "huge", "insert_junk", "drop"])
                o = list(o)
                if op == "dupnode":
                    i = rng.randrange(len(o))
                    o[i:i] = [o[i]] * rng.choice([1, 3, 30])
                elif op == "reverse":
                    o.reverse()
                elif op == "huge":
                    k = blob_kind(o[0])
                    o[rng.randrange(len(o))] = blob_encode(os.urandom(0) + bytes(rng.randrange(256) for _ in range(4096)) * 64, k, o[0])
                elif op == "insert_junk":
                    k = blob_kind(o[0])
                    o.insert(rng.randrange(len(o) + 1), blob_encode(bytes([0xc0 + rng.randrange(64)]) + bytes(40), k, o[0]))
                else:
                    o.pop(rng.randrange(len(o)))
                put(doc, p, o)
                return dump(doc), p, "proof:" + op, False
        if not blobs:
            return mutate(rng, base_bytes, "F06")
        p, o, k = rng.choice(blobs)
        b, op = mutate_bytes(rng, blob_decode(o, k))
        put(doc, p, blob_encode(b, k, o))
        return dump(doc), p, "blob:%s:%s" % (k, op), False
    raise ValueError(family)


def dump(doc, sentinel=None):
    if sentinel is not None:
        put(doc, sentinel[0], sentinel[1])
    return json.dumps(doc).encode()


# ------------------------------------------------------------------ one case in a forked child
def run_child(path, opts, cpu_cap, mem_cap_mib, scratch, raw=False):
    out_p, err_p = os.path.join(scratch, "stdout"), os.path.join(scratch, "stderr")
    t0 = time.monotonic()
    pid = os.fork()
    if pid == 0:                                                   # child
        try:
            mem = mem_cap_mib << 20
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            hard = int(cpu_cap * 4) + 1
            resource.setrlimit(resource.RLIMIT_CPU, (hard, hard + 1))
            signal.alarm(hard * 2)
            fo = os.open(out_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            fe = os.open(err_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(fo, 1)
            os.dup2(fe, 2)
            sys.stdout = io.TextIOWrapper(os.fdopen(1, "wb", closefd=False), encoding="utf-8")
            import apc_verify
            try:
                if raw:                         # the same bundle through verify_bundle, for the traceback of an `error`
                    cp = opts[opts.index("--l1-checkpoint") + 1] if "--l1-checkpoint" in opts else None
                    try:
                        apc_verify.verify_bundle(apc_verify.strict_json(open(path, "rb").read().decode("utf-8")),
                                                 cp, None, None, "--drafts" in opts)
                    except (apc_verify.Refusal, UnicodeDecodeError):
                        pass
                    os._exit(0)
                code = apc_verify.main(["apc_verify.py"] + opts + [path])
            except BaseException:
                traceback.print_exc()
                sys.stderr.flush()
                os._exit(70 if not isinstance(sys.exc_info()[1], MemoryError) else 71)
            sys.stdout.flush()
            os._exit(code if isinstance(code, int) and 0 <= code < 70 else 72)
        except BaseException:
            os._exit(73)
    _, status, ru = os.wait4(pid, 0)
    wall = time.monotonic() - t0
    out = open(out_p, "rb").read()
    err = open(err_p, "rb").read()[-4000:].decode("utf-8", "replace")
    res = {"cpu": round(ru.ru_utime + ru.ru_stime, 3), "wall": round(wall, 3), "maxrss_mib": round(ru.ru_maxrss / 1024, 1)}
    if os.WIFSIGNALED(status):
        res.update(kind="signal", signal=os.WTERMSIG(status))
        return res, None, err
    code = os.WEXITSTATUS(status)
    res["exit"] = code
    return res, out, err


def classify(res, out, err, base_verdict, base_checks, equivalence, cpu_cap, mem_cap):
    """-> (defect kind or None, verdict, checks)"""
    if res.get("kind") == "signal":
        return ("time" if res["signal"] in (signal.SIGXCPU, signal.SIGALRM, signal.SIGKILL) else "crash"), None, None
    code = res["exit"]
    if code == 71 or "MemoryError" in err:
        return "memory", None, None
    if code in (70, 72, 73):
        return "crash", None, None
    if code not in (0, 1, 2, 3):
        return "exit", None, None
    try:
        rep = json.loads(out)
        verdict, checks = rep["verdict"], rep.get("checks", {})
    except (ValueError, KeyError, TypeError):
        return "exit", None, None
    if CODES.get(verdict, 3) != code:
        return "exit", verdict, checks
    if verdict == "error":                      # SPEC 29.3: the verifier caught its own defect; still a defect
        return "crash", verdict, checks
    if res["cpu"] > cpu_cap:
        return "time", verdict, checks
    if res["maxrss_mib"] > mem_cap:
        return "memory", verdict, checks
    if equivalence and (verdict != base_verdict or checks != base_checks):
        return "equivalence", verdict, checks
    if verdict == "chain_verified" and base_verdict != "chain_verified" \
            and not _absent(checks) > _absent(base_checks):     # SPEC 5: an artifact taken away is listed, not judged
        return "promoted", verdict, checks
    return None, verdict, checks


def _absent(checks):
    return {k for k, v in (checks or {}).items() if isinstance(v, str) and v.startswith("not_evaluated:absent:")}


def signature(kind, err):
    """what makes two defects the same: the kind and, for a crash, the exception type and the innermost apc_ frame"""
    if kind not in ("crash", "memory"):
        return kind
    frames = re.findall(r'File "[^"]*/([^/"]+\.py)", line (\d+)', err)
    ex = (err.strip().splitlines() or ["?"])[-1].split(":")[0]
    own = [f for f in frames if f[0].startswith("apc_")]
    return "%s:%s:%s" % (kind, ex, "%s:%s" % own[-1] if own else "?")


def reduce_case(data, opts, base_verdict, base_checks, sig, scratch, cpu_cap, mem_cap, budget=60):
    """greedy: drop members / list entries of the mutated bundle while the same signature remains"""
    try:
        doc = load(data)
    except ValueError:
        return data
    if not isinstance(doc, dict):
        return data
    p = os.path.join(scratch, "reduce.json")

    def same(d):
        b = json.dumps(d).encode()
        if len(b) > len(data) * 2 + 1000:
            return False
        with open(p, "wb") as fh:
            fh.write(b)
        res, out, err = run_child(p, opts, cpu_cap, mem_cap, scratch)
        k, v, _ = classify(res, out, err, base_verdict, base_checks, False, cpu_cap, mem_cap)
        if v == "error":
            _, _, err = run_child(p, opts, cpu_cap, mem_cap, scratch, raw=True)
        return k is not None and signature(k, err) == sig
    if not same(doc):            # the parsed form does not show it (a text-level case): keep the bytes
        return data
    tries = 0
    changed = True
    while changed and tries < budget:
        changed = False
        for path, o in sorted(nodes(doc), key=lambda x: len(x[0])):
            if tries >= budget:
                break
            if not path:
                continue
            try:
                parent = get(doc, path[:-1])
            except (KeyError, IndexError, TypeError):
                continue
            trial = json.loads(json.dumps(doc))
            tp = get(trial, path[:-1])
            if isinstance(tp, dict):
                del tp[path[-1]]
            elif isinstance(tp, list) and len(tp) > 1:
                tp.pop(path[-1])
            else:
                continue
            tries += 1
            if same(trial):
                doc = trial
                changed = True
                break
            del parent
    return json.dumps(doc, sort_keys=True).encode()


# ------------------------------------------------------------------ seeds for the members the corpus does not carry
def build_seeds(outdir):
    """Bundles built by the test suite's own helpers (tests/), for the parsers no corpus bundle reaches: the HTTP
    exchange (RFC 9421, RFC 9651), MCP and A2A transports, the AP2 mandate (JWS / SD-JWT; needs APC_PULSE_CASES),
    signed offers and receipts (EIP-712 / JWS), builder code (CBOR) and payment-identifier. Written to outdir with an
    index in the row format of regress/VERDICTS.json (verdict and checks computed now, by this apc_verify)."""
    import copy
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import apc_verify as av
    out = []

    def add(name, doc, opts=()):
        b = json.dumps(doc).encode()
        p = os.path.join(outdir, name + ".json")
        with open(p, "wb") as fh:
            fh.write(b)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = av.main(["apc_verify.py"] + list(opts) + [p])
        rep = json.loads(buf.getvalue())
        out.append({"path": p, "options": list(opts), "verdict": rep["verdict"], "checks": rep.get("checks", {}),
                    "exit": code, "bundle_version": doc.get("bundle_version"), "sha256": hashlib.sha256(b).hexdigest()})
    import test_http as th
    add("http_md", th.md_bundle())
    import test_transport as tt
    add("mcp", tt.mcp_bundle())
    add("mcp_fail", tt.mcp_bundle(success=False))
    add("a2a", tt.a2a_bundle())
    import test_offer_receipt as to
    for v in to.VEC[::3]:
        add("or_" + v["id"], to.bundle(v))
    import test_builder_code as tb
    d = tb.load(tb.AW)
    a = av.verify_bundle(copy.deepcopy(d))["builder_code"]["calldata"]["a"]
    add("bc_aw", tb.Bundles.decl(None, d, {"a": a}, {"a": a}))
    import test_payid as tp
    add("payid", tp.with_id(tb.load(tb.AW), required=True))
    if os.path.isfile(os.environ.get("APC_PULSE_CASES", "")):
        import test_ap2 as ta
        valid = [c for c in ta.corpus() if c["expected"]["consistent"]]
        for c in valid[:4]:
            add("ap2_" + c["id"], {"bundle_version": "apc-0.1", "payment_payload": copy.deepcopy(c["x402"]["payload"]),
                                   "mandate": {"profile": "pulse-ap2-x402/0.3", "case": copy.deepcopy(c)}})
    import test_drafts2 as td2
    for v in td2.REF["receipts3186"][:2]:
        add("drafts2_%s" % v.get("id", len(out)), td2.Pr3186.bundle(None, v), ["--drafts"])
    with open(os.path.join(outdir, "index.json"), "w") as fh:
        json.dump({"bundles": out}, fh, indent=0, sort_keys=True)
    return out


# ------------------------------------------------------------------ driver
def bases(path=None):
    rows = json.load(open(path or os.path.join(ROOT, "regress", "VERDICTS.json")))["bundles"]
    return sorted(rows, key=lambda r: r["path"])


def draw(seed, i, rows, families):
    rng = random.Random("%s:%d" % (seed, i))
    base = rows[i % len(rows)] if rng.random() < .5 else rng.choice(rows)
    return rng, base, rng.choice(families)


def main(argv):
    if len(argv) >= 3 and argv[1] == "replay":
        case = json.load(open(argv[2]))
        data = base64.b64decode(case["bundle_b64"])
        with tempfile.TemporaryDirectory() as sc:
            p = os.path.join(sc, "case.json")
            open(p, "wb").write(data)
            res, out, err = run_child(p, case["options"], 5, 2048, sc)
        k, v, _ = classify(res, out, err, case["base_verdict"], case.get("base_checks", {}), case["family"] == "F12", 5, 2048)
        print(json.dumps({"defect": k, "verdict": v, "resources": res, "stderr_tail": err[-800:]}, indent=1))
        return 0
    if len(argv) == 3 and argv[1] == "seeds":
        os.makedirs(argv[2], exist_ok=True)
        rows = build_seeds(argv[2])
        print(json.dumps([(os.path.basename(r["path"]), r["verdict"]) for r in rows]))
        return 0
    if len(argv) < 4 or argv[1] != "run":
        print(__doc__)
        return 64
    seed, n = argv[2], int(argv[3])
    args = argv[4:]

    def opt(name, default):
        if name in args:
            return args[args.index(name) + 1]
        return default
    families = opt("--families", ",".join(FAMILIES)).split(",")
    outdir = opt("--out", os.path.join(ROOT, "fuzz_found"))
    cpu_cap, mem_cap = float(opt("--cpu-cap", "5")), int(opt("--mem-cap", "2048"))
    start = int(opt("--start", "0"))
    os.environ.setdefault("APC_SIGLIB", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "x402-signature-vectors"))
    import apc_verify  # noqa: F401  (imported once, inherited by every child)
    for m in sorted(os.listdir(ROOT)):         # every module a bundle can reach, so a child does not import it again
        if m.startswith("apc_") and m.endswith(".py") and m != "apc_registry.py":
            __import__(m[:-3])
    rows = bases(opt("--bases", None))
    stats = collections.Counter()
    per_family = collections.defaultdict(collections.Counter)
    worst = {"cpu": (0, None), "maxrss_mib": (0, None), "wall": (0, None)}
    defects, sigs, survivors = [], collections.Counter(), collections.Counter()
    t_start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="fuzz_") as sc:
        case_p = os.path.join(sc, "case.json")
        for i in range(start, start + n):
            rng, base, fam = draw(seed, i, rows, families)
            base_bytes = open(os.path.join(ROOT, base["path"]), "rb").read()     # an absolute path is kept as it is
            try:
                data, path, op, equiv = mutate(rng, base_bytes, fam)
            except (IndexError, ValueError, KeyError, TypeError, RecursionError) as e:
                stats["generator_skip"] += 1
                per_family[fam]["skip:" + type(e).__name__] += 1
                continue
            with open(case_p, "wb") as fh:
                fh.write(data)
            opts = list(base["options"])
            if "--drafts" not in opts and rng.random() < .15:     # the draft profiles read the same bundle (SPEC 17)
                opts.append("--drafts")
            res, out, err = run_child(case_p, opts, cpu_cap, mem_cap, sc)
            kind, verdict, checks = classify(res, out, err, base["verdict"], base["checks"], equiv, cpu_cap, mem_cap)
            for k in worst:
                if res.get(k, 0) > worst[k][0]:
                    worst[k] = (res[k], "%s:%d %s %s" % (seed, i, fam, op))
            stats["cases"] += 1
            per_family[fam]["cases"] += 1
            per_family[fam][kind or (verdict or "?")] += 1
            if kind is None and fam in VALUE_FAMILIES and verdict == "chain_verified" and base["verdict"] == "chain_verified":
                survivors["%s %s %s" % (base["bundle_version"], fam, re.sub(r"\d+", "#", "/".join(map(str, path))))] += 1
            if verdict == "error":
                _, _, err = run_child(case_p, opts, cpu_cap, mem_cap, sc, raw=True)
            if kind is not None:
                sig = signature(kind, err)
                sigs[sig] += 1
                stats["defects"] += 1
                if sigs[sig] <= 2:                 # two examples per signature are kept
                    small = reduce_case(data, opts, base["verdict"], base["checks"], sig, sc, cpu_cap, mem_cap) \
                        if kind in ("crash", "memory", "exit") and len(data) < (8 << 20) else data
                    rec = {"seed": seed, "index": i, "family": fam, "op": op, "path": list(map(str, path)),
                           "base": base["path"], "base_verdict": base["verdict"], "base_checks": base["checks"],
                           "options": opts, "defect": kind, "signature": sig, "verdict": verdict, "resources": res,
                           "stderr_tail": err[-1500:], "bundle_sha256": hashlib.sha256(small).hexdigest()}
                    if len(small) <= (1 << 20):
                        rec["bundle_b64"] = base64.b64encode(small).decode()
                    os.makedirs(outdir, exist_ok=True)
                    name = "%s_%s_%d.json" % (re.sub(r"[^A-Za-z0-9]+", "_", sig)[:60], seed, i)
                    with open(os.path.join(outdir, name), "w") as fh:
                        json.dump(rec, fh, indent=1, sort_keys=True)
                    defects.append(name)
                print("DEFECT %s:%d %s %s %s %s" % (seed, i, fam, op, sig, base["path"]), flush=True)
            if stats["cases"] % 200 == 0:
                print("... %d cases, %d defects, %.0f s" % (stats["cases"], stats["defects"], time.monotonic() - t_start),
                      flush=True)
    summary = {"seed": seed, "start": start, "n": n, "families": families, "stats": dict(stats),
               "per_family": {f: dict(c) for f, c in sorted(per_family.items())},
               "worst": {k: {"value": v[0], "case": v[1]} for k, v in worst.items()},
               "defect_signatures": dict(sigs), "saved": defects,
               "survivors": dict(survivors.most_common()),
               "children_cpu_s": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime
                                       + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime, 1),
               "self_cpu_s": round(resource.getrusage(resource.RUSAGE_SELF).ru_utime
                                   + resource.getrusage(resource.RUSAGE_SELF).ru_stime, 1),
               "wall_s": round(time.monotonic() - t_start, 1)}
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 1 if stats["defects"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
