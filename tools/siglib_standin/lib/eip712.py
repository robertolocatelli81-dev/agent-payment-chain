"""Stand-in for x402-signature-vectors lib/eip712 (keccak256, signing_digest), written from the Keccak reference
(FIPS 202 permutation, original Keccak padding 0x01) and EIP-712, a second implementation checked in tests/test_standin.py
against known digests and real data; the real library stays the reference. The verifier does not accept it as its library
(apc_verify 0.21.3, SPEC 32.12 (f): only the bytes of tag v1.4.0 at their hashes run; APC_SIGLIB=tools/siglib_standin is exit 64)."""

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    p = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        blk = p[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        a = _f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def _type_str(primary, types):
    return primary + "(" + ",".join("%s %s" % (f["type"], f["name"]) for f in types[primary]) + ")"


def _enc(t, v):
    if t == "string":
        return keccak256(v.encode())
    if t == "bytes":
        return keccak256(v)
    if t == "address":
        return bytes(12) + bytes.fromhex(v[2:])
    if t == "bytes32":
        return bytes.fromhex(v[2:]) if isinstance(v, str) else bytes(v)
    if t.startswith("uint"):
        return int(v).to_bytes(32, "big")
    raise ValueError("type not handled by the stand-in: " + t)


def _struct(primary, types, msg):
    th = keccak256(_type_str(primary, types).encode())
    return keccak256(th + b"".join(_enc(f["type"], msg[f["name"]]) for f in types[primary]))


def signing_digest(domain, primary, types, msg, domain_types):
    ds = _struct("EIP712Domain", {"EIP712Domain": domain_types}, domain)
    return keccak256(b"\x19\x01" + ds + _struct(primary, types, msg))
