"""agent-payment-chain as a local MCP tool server (SPEC 0.6, section 8): JSON-RPC 2.0 over stdio, standard library only,
read-only (it verifies what it is given; it reads no file, opens no connection, writes nothing).

  python3 apc_mcp.py        (an MCP client starts it and speaks on stdin/stdout, one JSON message per line)

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
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")       # MCP revisions this server speaks; the newest first
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
    # the arguments' shape is a protocol matter (error -32602); what the texts say is the verifier's (a report)
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


def handle(msg):
    """One JSON-RPC message in, zero or one out (a notification gets no reply)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    method, id_ = msg.get("method"), msg.get("id")
    if "id" not in msg:                                  # notifications (notifications/initialized, ...)
        return None

    def ok(r):
        return {"jsonrpc": "2.0", "id": id_, "result": r}

    def err(code, m):
        return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": m}}
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    if method == "initialize":
        asked = params.get("protocolVersion")
        return ok({"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                   "capabilities": {"tools": {}}, "serverInfo": SERVER})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": [dict(t, name=n) for n, t in TOOLS.items()]})
    if method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or name not in TOOLS:
            return err(-32602, "unknown tool %r" % (name,))
        try:
            out, is_err = call(name, params.get("arguments", {}))
        except av.Refusal as e:
            return err(-32602, str(e))
        except Exception as e:                           # a defect must not end the server (JSON-RPC 2.0: -32603)
            return err(-32603, "internal error: %s" % type(e).__name__)
        return ok({"content": [{"type": "text", "text": json.dumps(out, sort_keys=True)}], "isError": is_err})
    return err(-32601, "method not found: %s" % (method,))


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
            msg = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):                 # UnicodeDecodeError is a ValueError
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
