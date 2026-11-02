"""SPEC Amendment 0.3.2: does the deployed Base USDC refuse a high-s EIP-3009 signature? eth_call of transferWithAuthorization (value 0, a
throwaway key, nothing is sent): low-s must succeed (positive control), the same signature with s' = n - s and v
flipped must revert. Prints the raw replies.

  APC_SIGLIB=... python3 tools/probe_lows_usdc.py [RPC CHAIN_ID ASSET NAME VERSION]
"""
import json, os, sys, urllib.request, secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import apc_siglib  # noqa: E402
apc_siglib.load()      # SPEC 32.12 (f): x402-signature-vectors v1.4.0 run from the bytes hashed, never by name from a path
from lib.secp256k1 import sign, N, _mul, GX, GY, public_key_to_address  # noqa: E402
from lib.eip712 import signing_digest, keccak256, domain_separator  # noqa: E402
# defaults: USDC on Base mainnet; for another token: RPC CHAIN_ID ASSET NAME VERSION
ARGS = sys.argv[1:] + [os.environ.get("BASE_RPC") or sys.exit("BASE_RPC (or the RPC argument) not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool"), "8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USD Coin", "2"][len(sys.argv[1:]):]
RPC, CHAIN, USDC, NAME, VER = ARGS[0], int(ARGS[1]), ARGS[2].lower(), ARGS[3], ARGS[4]
priv = secrets.randbelow(N - 1) + 1
frm = public_key_to_address(_mul(priv, (GX, GY)), keccak256)
to = "0x" + "11" * 20
msg = {"from": frm, "to": to, "value": 0, "validAfter": 0, "validBefore": 2**40, "nonce": "0x" + secrets.token_hex(32)}
types = {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                          {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
         "TransferWithAuthorization": [{"name": n, "type": t} for n, t in (("from", "address"), ("to", "address"),
         ("value", "uint256"), ("validAfter", "uint256"), ("validBefore", "uint256"), ("nonce", "bytes32"))]}
dom = {"name": NAME, "version": VER, "chainId": CHAIN, "verifyingContract": USDC}
D4 = types["EIP712Domain"]
def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(RPC, body.encode(), {"content-type": "application/json", "user-agent": "curl/8"})
    return json.load(urllib.request.urlopen(req, timeout=30))
live = rpc("eth_call", [{"to": USDC, "data": "0x3644e515"}, "latest"]).get("result")      # DOMAIN_SEPARATOR()
if live is None:    # no public DOMAIN_SEPARATOR() (JPYC): the low-s call below must succeed, or the domain is wrong
    print("DOMAIN_SEPARATOR() not callable; the low-s call is the control of the domain", dom)
else:
    assert domain_separator(dom, D4).hex() == live[2:], "the EIP-712 domain given does not match DOMAIN_SEPARATOR()"
    print("DOMAIN_SEPARATOR", live[2:], "matches", dom)
d = signing_digest(dom, "TransferWithAuthorization", {k: v for k, v in types.items() if k != "EIP712Domain"}, msg, D4)
r, s, rec = sign(d, priv, secrets.randbelow(N - 1) + 1)
sel = keccak256(b"transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)")[:4]
def call(v, r, s):
    data = sel + bytes(12) + bytes.fromhex(frm[2:]) + bytes(12) + bytes.fromhex(to[2:]) + (0).to_bytes(32, "big") \
        + (0).to_bytes(32, "big") + (2**40).to_bytes(32, "big") + bytes.fromhex(msg["nonce"][2:]) + v.to_bytes(32, "big") \
        + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return rpc("eth_call", [{"to": USDC, "data": "0x" + data.hex()}, "latest"])
print("low-s ", call(27 + rec, r, s))
print("high-s", call(27 + (rec ^ 1), r, N - s))
print("bad v ", call(29, r, s))
