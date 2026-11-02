"""SPEC 0.11.1 (section 14): the x402 builder-code attribution in settlement calldata (ERC-8021 Schema 2, x402 4241d56
specs/extensions/builder_code.md, cited BC §). A strict, closed reader of the CBOR map: deterministic encoding (RFC
8949 4.2.1: definite lengths, shortest-form arguments, map keys sorted bytewise by their encoding) inside `m`, and at the top level the order
a, w, s, m that BC states next to it (the two rules disagree when both w and s are present; measured: Base settlements
of the CDP facilitator write w before s), keys a, w, s, m only, codes ^[a-z0-9_]{1,32}$, m as BC "Settlement Metadata". Standard library only; reports, never decides a
payment."""
import re

CODE = re.compile(r"[a-z0-9_]{1,32}\Z")
MAX_DEPTH = 16
TOP = ("a", "w", "s", "m")      # BC "Settlement Metadata": top-level order a, w, s, m


class Malformed(Exception):
    pass


def _arg(b, i, ai):
    if ai < 24:
        return ai, i
    n = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
    if n is None:                       # 28-30 reserved, 31 indefinite length
        raise Malformed("indefinite_or_reserved_length")
    if i + n > len(b):
        raise Malformed("truncated")
    v = int.from_bytes(b[i:i + n], "big")
    if v < (24 if n == 1 else 1 << (8 * n // 2)):
        raise Malformed("not_shortest_form")
    return v, i + n


def _item(b, i, depth):
    """(value, next index). Text strings, unsigned integers, arrays, maps with text keys; anything else is Malformed."""
    if depth > MAX_DEPTH:
        raise Malformed("nested_too_deep")
    if i >= len(b):
        raise Malformed("truncated")
    mt, ai = b[i] >> 5, b[i] & 31
    v, i = _arg(b, i + 1, ai)
    if mt == 0:
        return v, i
    if mt == 3:
        if i + v > len(b):
            raise Malformed("truncated")
        try:
            return b[i:i + v].decode("utf-8"), i + v
        except UnicodeDecodeError:
            raise Malformed("text_not_utf8")
    if mt == 4:
        if v > len(b):
            raise Malformed("truncated")
        out = []
        for _ in range(v):
            x, i = _item(b, i, depth + 1)
            out.append(x)
        return out, i
    if mt == 5:
        if v > len(b):
            raise Malformed("truncated")
        out, last = {}, None
        for _ in range(v):
            k0 = i
            k, i = _item(b, i, depth + 1)
            if not isinstance(k, str):
                raise Malformed("map_key_not_text")
            enc = b[k0:i]
            if depth == 0:                  # BC: "Top-level order is a, w, s, m"
                pos = TOP.index(k) if k in TOP else len(TOP)
                if last is not None and pos <= last:
                    raise Malformed("top_level_keys_not_in_order_a_w_s_m")
                last = pos
            elif last is not None and enc <= last:      # RFC 8949 4.2.1 (also refuses a duplicate key)
                raise Malformed("map_keys_not_sorted_bytewise")
            else:
                last = enc
            out[k], i = _item(b, i, depth + 1)
        return out, i
    raise Malformed("major_type_%d_not_allowed" % mt)   # negative ints, byte strings, tags, floats (BC m rules)


def decode(cbor):
    """The builder-code map from the CBOR bytes of an ERC-8021 Schema 2 suffix: (fields, None) or (None, reason)."""
    try:
        v, end = _item(cbor, 0, 0)
        if end != len(cbor):
            raise Malformed("bytes_after_the_map")
        if not isinstance(v, dict):
            raise Malformed("not_a_map")
        unknown = sorted(set(v) - {"a", "w", "s", "m"})
        if unknown:                     # r (custom registries) is "not supported" by BC; anything else unknown
            raise Malformed("key_not_x402_builder_code:%s" % ",".join(k[:16] for k in unknown))
        for k in ("a", "w"):
            if k in v and not (isinstance(v[k], str) and CODE.match(v[k])):
                raise Malformed("%s_not_a_builder_code" % k)
        if "s" in v:
            s = v["s"] if isinstance(v["s"], list) else [v["s"]]
            if not s or not all(isinstance(x, str) and CODE.match(x) for x in s):
                raise Malformed("s_not_builder_codes")
        if "m" in v:
            if not isinstance(v["m"], dict) or not all(k.startswith("x402") for k in v["m"]):
                raise Malformed("m_key_not_x402")
        if not v:
            raise Malformed("empty_map")
    except Malformed as e:
        return None, str(e)
    return v, None
