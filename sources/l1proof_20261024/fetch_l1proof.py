"""Fetch, at ONE L1 block, everything an L1 state proof of the eight canonical replies needs, plus the eight eth_call
replies at that same block (the positive control: the replies recomputed from storage must equal them).

  python3 fetch_l1proof.py GAME OUT.json [RPC] [BLOCK]

Read-only JSON-RPC (eth_blockNumber, eth_getBlockByNumber, eth_getProof, eth_getCode, eth_call). Standard library.
"""
import json
import os
import sys
import time
import urllib.request

ASR = "0x909f6cf47ed12f010a796527f562bfc26c7f4e72"
DGF = "0x43edb88c4b80fdd2adff2412a7bebf9df42cb40e"
PORTAL_SLOT = "0x4b6c74f9e688cb39801f2112c14a8c57232a3fc5202e1444126d4bce86eb19ac"   # keccak("systemconfig.optimismportal") - 1
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"   # EIP-1967
SEL = {"gameType": "bbdc02db", "rootClaim": "bcef3b55", "extraData": "609d3334", "startingBlockNumber": "70872aa5",
       "status": "200d2ed2", "isGameProper": "496b9c16", "isGameRespected": "04e50fed", "isGameClaimValid": "6c4f4467"}


def rpc(url, method, params, _n=[0]):
    _n[0] += 1
    body = json.dumps({"jsonrpc": "2.0", "id": _n[0], "method": method, "params": params}).encode()
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "apc-l1proof"})
            r = json.load(urllib.request.urlopen(req, timeout=30))
            if "error" in r:
                if "proof window" in str(r["error"]) and attempt < 3:     # another backend behind the balancer
                    time.sleep(1)
                    continue
                raise RuntimeError(f"{method}: {r['error']}")
            return r["result"]
        except (OSError, ValueError):
            if attempt == 3:
                raise
            time.sleep(2 + 2 * attempt)


def keccak(b):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir))
    import apc_siglib      # SPEC 32.12 (f): x402-signature-vectors v1.4.0 run from the bytes hashed (APC_SIGLIB or its default)
    return apc_siglib.load().eip712.keccak256(b)


def word(x):
    return int(x, 16).to_bytes(32, "big")


def main():
    game, out = sys.argv[1].lower(), sys.argv[2]
    url = sys.argv[3] if len(sys.argv) > 3 else (os.environ.get("ETH_RPC") or sys.exit("ETH_RPC (or a URL argument) not set: name the JSON-RPC endpoint you are entitled to use (its terms are yours); none is written in this tool"))
    b = int(sys.argv[4], 0) if len(sys.argv) > 4 else int(rpc(url, "eth_blockNumber", []), 16) - 3
    bh = hex(b)
    header = rpc(url, "eth_getBlockByNumber", [bh, False])
    calls = []
    for name in ("gameType", "rootClaim", "extraData", "startingBlockNumber", "status"):
        calls.append({"name": name, "to": game, "data": "0x" + SEL[name]})
    for name in ("isGameProper", "isGameRespected", "isGameClaimValid"):
        calls.append({"name": name, "to": ASR, "data": "0x" + SEL[name] + "00" * 12 + game[2:]})
    for c in calls:
        c["result"] = rpc(url, "eth_call", [{"to": c["to"], "data": c["data"]}, bh])
    code_game = rpc(url, "eth_getCode", [game, bh])
    impl = "0x" + code_game[2:][code_game[2:].index("3d73") + 4:][:40]
    gt, root, extra = int(calls[0]["result"], 16), word(calls[1]["result"]), bytes.fromhex(calls[2]["result"][2:])
    n = int.from_bytes(extra[32:64], "big")
    extra = extra[64:64 + n]
    enc = gt.to_bytes(32, "big") + root + (96).to_bytes(32, "big") + n.to_bytes(32, "big") \
        + extra + b"\0" * (-n % 32)
    uuid = keccak(enc)
    dgf_key = "0x" + keccak(uuid + (103).to_bytes(32, "big")).hex()
    bl_key = "0x" + keccak(bytes(12) + bytes.fromhex(game[2:]) + (5).to_bytes(32, "big")).hex()
    s = lambda i: "0x" + i.to_bytes(32, "big").hex()
    proofs = {
        "game": rpc(url, "eth_getProof", [game, [s(0), s(1), s(2)], bh]),
        "impl": rpc(url, "eth_getProof", [impl, [], bh]),
        "dgf": rpc(url, "eth_getProof", [DGF, [dgf_key, IMPL_SLOT], bh]),
        "asr": rpc(url, "eth_getProof", [ASR, [s(0), s(1), s(6), bl_key, IMPL_SLOT], bh]),
    }
    sysconf = "0x" + word(proofs["asr"]["storageProof"][0]["value"])[32 - 22:32 - 2].hex()
    proofs["sysconf"] = rpc(url, "eth_getProof", [sysconf, [s(108), PORTAL_SLOT, s(110), IMPL_SLOT], bh])
    supc = "0x" + word(proofs["sysconf"]["storageProof"][0]["value"])[12:].hex()
    portal = word(proofs["sysconf"]["storageProof"][1]["value"])[12:]
    pz = "0x" + keccak(bytes(32) + bytes(32)).hex()
    pp = "0x" + keccak(bytes(12) + portal + bytes(32)).hex()
    proofs["supc"] = rpc(url, "eth_getProof", [supc, [pz, pp, IMPL_SLOT], bh])
    impls = {}
    for k in ("dgf", "asr", "sysconf", "supc"):
        v = word(proofs[k]["storageProof"][-1]["value"])[12:]
        impls[k] = "0x" + v.hex()
        proofs[k + "_impl"] = rpc(url, "eth_getProof", [impls[k], [], bh])
    pins = {
        "game.anchorStateRegistry": rpc(url, "eth_call", [{"to": game, "data": "0x5c0cba33"}, bh]),
        "impl.gameType": rpc(url, "eth_call", [{"to": impl, "data": "0xbbdc02db"}, bh]),
        "asr.disputeGameFinalityDelaySeconds": rpc(url, "eth_call", [{"to": ASR, "data": "0x952b2797"}, bh]),
        "supc.paused0": rpc(url, "eth_call", [{"to": supc, "data": "0x2e48152c" + "00" * 32}, bh]),
        "supc.pausedPortal": rpc(url, "eth_call", [{"to": supc, "data": "0x2e48152c" + "00" * 12 + portal.hex()}, bh]),
        "sysconf.paused": rpc(url, "eth_call", [{"to": sysconf, "data": "0x5c975abb"}, bh]),
        "asr.paused": rpc(url, "eth_call", [{"to": ASR, "data": "0x5c975abb"}, bh]),
        "impl.intermediateOutputRootsCount": rpc(url, "eth_call", [{"to": impl, "data": "0xb74df35a"}, bh]),
        "impl.version": rpc(url, "eth_call", [{"to": impl, "data": "0x54fd4d50"}, bh]),
    }
    for k in ("dgf", "asr", "sysconf", "supc"):
        pins[k + "_impl.version"] = rpc(url, "eth_call", [{"to": impls[k], "data": "0x54fd4d50"}, bh])
    codes = {"game": code_game, "impl": rpc(url, "eth_getCode", [impl, bh])}
    json.dump({"rpc": url, "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "block": bh,
               "header": header, "game": game, "impl": impl, "sysconf": sysconf, "supc": supc, "portal": "0x" + portal.hex(), "impls": impls, "calls": calls,
               "proofs": proofs, "pins": pins, "codes": codes, "uuid": "0x" + uuid.hex()},
              open(out, "w"), indent=1)
    print(out, bh, "impl", impl, "sysconf", sysconf, impls)


if __name__ == "__main__":
    main()
