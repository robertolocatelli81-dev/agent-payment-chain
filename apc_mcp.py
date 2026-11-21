"""agent-payment-chain as a local MCP tool server (SPEC 0.6, section 8): JSON-RPC 2.0 over stdio, standard library only,
read-only (it verifies what it is given; it reads no file, opens no connection, writes nothing).

  python3 apc_mcp.py        (an MCP client starts it and speaks on stdin/stdout, one JSON message per line)

MCP revisions (SPEC 8): 2026-07-28 (modern: the version and the client's capabilities in each request's _meta,
server/discover) and 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05 (legacy: initialize first).

Tools: verify_bundle {bundle_json, l1_checkpoint?} -> apc_verify's report; apply_policy {policy_json, bundle_json} ->
the report with P1-P5 (apc_report.py). The bundle is passed as JSON text so that apc_verify's strict parser reads it
(duplicate members, non-JSON numbers and surrogates are refused as on the command line).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_siglib  # noqa: E402
apc_siglib.guard("apc_mcp", __name__ == "__main__")  # SPEC 32.11 (c), 32.12 (f): without the library one line, exit 64, no traceback
import apc_report  # noqa: E402
import apc_verify as av  # noqa: E402

SERVER = {"name": "agent-payment-chain", "version": av.VERSION.split()[-1]}
MODERN = ("2026-07-28",)                                    # SPEC 8: per-request _meta, no handshake
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")    # SPEC 8: the initialize handshake first
PROTOCOLS = MODERN + LEGACY                                 # MCP revisions this server speaks; the newest first
PV = "io.modelcontextprotocol/protocolVersion"
CAPS = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO = "io.modelcontextprotocol/serverInfo"
TTL_MS = 3600000                                            # SPEC 8: the tool list is fixed in this file
SESSION = {"version": None}                                 # the legacy revision initialize negotiated on this stdio
MAX_TEXT = av.MAX_BUNDLE_BYTES
MAX_LINE = 2 * MAX_TEXT + (1 << 20)   # SPEC 29.2: one JSON-RPC message line; longer = refused, never held in memory

TOOLS = {
    "verify_bundle": {
        "description": "Verify an agent-payment-chain bundle (x402 payment evidence: EVM apc-0.1..0.3, Solana apc-0.5) "
                       "offline; returns the JSON report of apc_verify (verdict, checks, notes).",
        "inputSchema": {"type": "object", "required": ["bundle_json"], "additionalProperties": False,
                        "properties": {"bundle_json": {"type": "string", "description": "the bundle as JSON text"},
                                       "l1_checkpoint": {"type": "string",
                                                         "description": "an L1 block hash you trust (SPEC 0.4)"}}}},
    "apply_policy": {
        "description": "Verify a bundle and apply a reader policy (networks, assets, pay_to, max_amount, hosts): "
                       "the report with the checks P1-P5 and policy_verdict.",
        "inputSchema": {"type": "object", "required": ["policy_json", "bundle_json"], "additionalProperties": False,
                        "properties": {"policy_json": {"type": "string"}, "bundle_json": {"type": "string"}}}},
}


def _text(args, k):
    v = args.get(k)
    if not isinstance(v, str) or len(v.encode("utf-8")) > MAX_TEXT:
        raise av.Refusal("%s: not a JSON text of at most %d bytes" % (k, MAX_TEXT))
    return v


def call(name, args):
    """-> (result object, is_error)"""
    # the arguments' shape raises Refusal: -32602 at MCP 2025-06-18 and earlier, a tool execution error (isError)
    # at 2025-11-25 and 2026-07-28 (SPEC 8, _tools_call); what the texts say is the verifier's (a report)
    if not isinstance(args, dict) or set(args) - set(TOOLS[name]["inputSchema"]["properties"]):
        raise av.Refusal("arguments: unknown member(s)")
    texts = {k: _text(args, k) for k in TOOLS[name]["inputSchema"]["required"]}
    cp = args.get("l1_checkpoint")
    if cp is not None and (not isinstance(cp, str) or not av.HASH32.match(cp)):
        raise av.Refusal("l1_checkpoint: not a 32-byte 0x hex hash")
    try:
        doc = av.strict_json(texts["bundle_json"])
        if name == "verify_bundle":
            return av.verify_bundle(doc, cp.lower() if cp else None), False
        policy = apc_report.parse_policy(av.strict_json(texts["policy_json"]))
        return apc_report.apply_policy(policy, doc, av.verify_bundle(doc)), False
    except av.Unsupported as e:
        return {"verifier": av.VERSION, "verdict": "unsupported", "reason": str(e)}, True
    except (av.Refusal, apc_report.Bad) as e:
        return {"verifier": av.VERSION, "verdict": "refused", "reason": str(e)}, True


class DuplicateMember(ValueError):
    """A member name repeated in one object of a message: which value is meant is not decided (RFC 8259 4)."""


def _not_json(name):
    raise ValueError("%s is not JSON (RFC 8259 6)" % name)


def parse_line(text):
    """One message line -> the decoded value. NaN, Infinity and -Infinity, which Python's json module accepts, are not
    JSON (RFC 8259 6): ValueError, so a parse error (-32700) as SPEC section 8 says for a line that is not JSON; until
    2026-11-20 an id NaN was echoed and the reply was not JSON either. A member repeated in one object raises
    DuplicateMember (invalid request, -32600), but only once the whole line has been read as JSON: a line that is not
    JSON is a parse error wherever the repeated member stands. The repeats are found in one pass per object (time
    linear in the line)."""
    repeated = []

    def members(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                repeated.append(k)
            obj[k] = v
        return obj
    value = json.loads(text, parse_constant=_not_json, object_pairs_hook=members)
    if repeated:
        raise DuplicateMember("member repeated: %s" % min(repeated)[:80])
    return value


def valid_id(v):
    """MCP (basic, revisions 2025-06-18 and later): "Requests MUST include a string or integer ID. Unlike base JSON-RPC,
    the ID MUST NOT be null." The same rule SPEC section 16 applies to recorded MCP requests. A boolean is not an
    integer."""
    return isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool))


def handle(msg):
    """One JSON-RPC message in, zero or one out (a notification gets no reply). SPEC 8: a request whose params._meta
    names a protocol version is served as MCP 2026-07-28 (modern), any other by the revision initialize negotiated
    (legacy)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    method, id_ = msg.get("method"), msg.get("id")
    if "id" not in msg:                                  # notifications (notifications/initialized, ...)
        return None
    if not valid_id(id_):                                # JSON-RPC 2.0 section 5: an id not detected is answered null
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "invalid request: the id is not a string or an integer (MCP)"}}

    def ok(r):
        return {"jsonrpc": "2.0", "id": id_, "result": r}

    def err(code, m, data=None):
        e = {"code": code, "message": m}
        if data is not None:
            e["data"] = data
        return {"jsonrpc": "2.0", "id": id_, "error": e}
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    meta = params.get("_meta")
    if isinstance(meta, dict) and PV in meta:
        return _modern(method, params, meta, ok, err)
    return _legacy(method, params, ok, err)


def _tools_call(params, ok, err, validation_is_tool_error, modern):
    name = params.get("name")
    if not isinstance(name, str) or name not in TOOLS:
        return err(-32602, "unknown tool %r" % (name,))
    try:
        out, is_err = call(name, params.get("arguments", {}))
    except av.Refusal as e:
        if not validation_is_tool_error:                 # MCP 2025-06-18 and earlier: a protocol error
            return err(-32602, str(e))
        r = {"content": [{"type": "text", "text": "invalid arguments: %s" % e}], "isError": True}
        return ok(_complete(r) if modern else r)          # MCP 2025-11-25 and later: a tool execution error
    except Exception as e:                               # a defect must not end the server (JSON-RPC 2.0: -32603)
        return err(-32603, "internal error: %s" % type(e).__name__)
    r = {"content": [{"type": "text", "text": json.dumps(out, sort_keys=True)}], "isError": is_err}
    return ok(_complete(r) if modern else r)


def _complete(r):
    """MCP 2026-07-28: every result has resultType, and the server names itself in the result's _meta."""
    return dict(r, resultType="complete", _meta={SERVER_INFO: SERVER})


def _modern(method, params, meta, ok, err):
    v = meta[PV]
    if not isinstance(v, str) or not isinstance(meta.get(CAPS), dict):
        return err(-32602, "invalid params: _meta needs %s, a string, and %s, an object (MCP 2026-07-28)" % (PV, CAPS))
    if v not in MODERN:
        return err(-32022, "Unsupported protocol version", {"supported": list(MODERN), "requested": v})
    tools = [dict(t, name=n) for n, t in TOOLS.items()]
    if method == "server/discover":
        return ok(_complete({"supportedVersions": list(MODERN), "capabilities": {"tools": {}}, "ttlMs": TTL_MS,
                             "cacheScope": "public"}))
    if method == "tools/list":
        return ok(_complete({"tools": tools, "ttlMs": TTL_MS, "cacheScope": "public"}))
    if method == "tools/call":
        return _tools_call(params, ok, err, True, True)
    return err(-32601, "method not found: %s (MCP %s)" % (method, v))


def _legacy(method, params, ok, err):
    if method == "initialize":
        asked = params.get("protocolVersion")
        SESSION["version"] = asked if asked in LEGACY else LEGACY[0]
        return ok({"protocolVersion": SESSION["version"], "capabilities": {"tools": {}}, "serverInfo": SERVER})
    if method == "ping":
        return ok({})
    if SESSION["version"] is None:
        return err(-32600, "invalid request: %s before initialize (MCP %s and earlier); or name revision %s in "
                           "params._meta" % (method, LEGACY[0], MODERN[0]))
    if method == "tools/list":
        return ok({"tools": [dict(t, name=n) for n, t in TOOLS.items()]})
    if method == "tools/call":
        return _tools_call(params, ok, err, SESSION["version"] == "2025-11-25", False)
    return err(-32601, "method not found: %s" % (method,))


BATCHED = "2025-03-26"                                      # SPEC 8: the one revision with JSON-RPC batches


def _modern_meta(m):
    p = m.get("params")
    return isinstance(p, dict) and isinstance(p.get("_meta"), dict) and PV in p["_meta"]


def batch(msgs):
    """SPEC 8: the members of a JSON array on a process whose last initialize negotiated 2025-03-26 ("MUST support
    receiving JSON-RPC batches") -> the replies one by one, in member order: each member answered as it would be alone;
    initialize, or a member naming a protocol version in _meta, is -32600. A generator: the replies are not held, so a
    batch costs the memory of its line and of one reply, as the same messages on lines of their own (SPEC 29.2)."""
    for m in msgs:
        if isinstance(m, dict) and m.get("jsonrpc") == "2.0" and (m.get("method") == "initialize" or _modern_meta(m)):
            if "id" in m:                                # a notification is never answered
                yield {"jsonrpc": "2.0", "id": m["id"] if valid_id(m["id"]) else None,
                       "error": {"code": -32600, "message": "invalid request: not in a batch (MCP %s: initialize is "
                                 "never batched; %s has no batches)" % (BATCHED, MODERN[0])}}
            continue
        r = handle(m)                                    # an object that is not JSON-RPC 2.0: -32600, as alone
        if r is not None:
            yield r


def write_line(msg, out):
    """One decoded line -> its reply on `out`, if it has one. A non-empty array on a 2025-03-26 session is a batch
    (SPEC 8): its replies as one JSON array on one line, byte for byte json.dumps of their list, each written as it
    is made; no reply, nothing written (JSON-RPC 2.0 section 6). Anything else is one message."""
    if isinstance(msg, list) and msg and SESSION["version"] == BATCHED:
        n = 0
        for r in batch(msg):
            out.write(("[" if not n else ", ") + json.dumps(r))
            n += 1
        if n:
            out.write("]\n")
            out.flush()
        return
    if isinstance(msg, list) and SESSION["version"] == BATCHED:
        reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request: an empty batch"}}
    else:
        reply = handle(msg)
    if reply is not None:
        out.write(json.dumps(reply) + "\n")
        out.flush()


def main():
    # bytes, not the locale's text stream: a line that is not UTF-8 (MCP stdio messages are UTF-8) is a parse error,
    # whatever the locale (a strict UTF-8 locale used to raise UnicodeDecodeError here and end the server)
    inp = sys.stdin.buffer
    while True:
        raw = inp.readline(MAX_LINE + 1)
        if not raw:
            break
        if len(raw) > MAX_LINE:                              # SPEC 29.2: the rest of the line is read and dropped
            while raw and not raw.endswith(b"\n"):
                raw = inp.readline(1 << 20)
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32600, "message": "message longer than %d bytes (SPEC 29.2)" % MAX_LINE}}
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
            continue
        if not raw.strip():
            continue
        try:
            msg = parse_line(raw.decode("utf-8"))
        except DuplicateMember as e:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request: %s" % e}}
        except (ValueError, RecursionError):                 # UnicodeDecodeError is a ValueError
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            write_line(msg, sys.stdout)
            continue
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
