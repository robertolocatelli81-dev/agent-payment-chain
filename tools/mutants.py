"""Targeted mutants of apc_verify.py: each must make tests/test_apc.py fail. Runs each in a temporary copy (HOME
isolated). Exit 1 on a survivor or on a mutant whose pattern no longer applies.

  python3 tools/mutants.py [NAME_SUBSTRING]   (only the mutants whose name contains it; the control always runs)"""
import os
import shutil
import subprocess
import sys
import tempfile

# Not listed, equivalent: "0.2 indirect without C3" (the line `core = core and res.get("C3") == "verified"` replaced by
# pass). On an indirect call C3 is verified, failed:*, or not_evaluated:indirect_call_needs_log_transfer /
# log_transfer_not_next, never not_evaluated:absent:*, so a C3 that is not verified already fails or blocks the verdict;
# the line stays as a second guard. Checked 2026-10-23: survived on 0aaf2b9 too; on the 97 files with an indirect call
# in bundles/real_v02* (79), real_v03 (9) and real_v03_canonical (the same 9 payments), and on 450 generated alterations
# of them (log_transfer removed or changed, AuthorizationUsed logIndex moved), verdict, checks, failed and not_evaluated
# are the same with and without the line; a known non-equivalent mutant (the line removed and a missing log_transfer
# on an indirect call reported as absent) differs on 34 of 150 (tools/equiv_mutants.py ROOT c3 450).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGLIB = os.environ.get("APC_SIGLIB", os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "x402-signature-vectors"))
M = [
    ("K1 removed", 'res["K1"] = eq(au["to"], acc["pay_to"], "to_payTo")', 'res["K1"] = "verified"'),
    ("K2 at least", 'res["K2"] = eq(au["value"], acc["amount"], "value_amount")',
     'res["K2"] = "verified" if au["value"] >= acc["amount"] else "failed:x"'),
    ("unknown members accepted", '    if unknown:\n        raise Refusal', '    if False:\n        raise Refusal'),
    ("missing members accepted", '    if missing:\n        raise Refusal', '    if False:\n        raise Refusal'),
    ("3-member domain", 'digest = signing_digest(dom, "TransferWithAuthorization", TYPES, msg, DOMAIN4)',
     'digest = signing_digest({k: dom[k] for k in ("name", "version", "chainId")}, "TransferWithAuthorization", TYPES, msg)'),
    ("leading zeros allowed", 'UINT = re.compile(r"(0|[1-9][0-9]*)\\Z")', 'UINT = re.compile(r"[0-9]+\\Z")'),
    ("any tail accepted", '        if suffix is None:\n            CHAIN_NOTES', '        if False:\n            CHAIN_NOTES'),
    ("padding unchecked", 'if len(b) < abi_end or any(b[4 + off + 32 + n: abi_end]):', 'if len(b) < abi_end:'),
    ("log nonce unchecked", 'c2.append("verified" if str(lg["topics"][2]).lower() == au["nonce"] else "failed:log_nonce_mismatch")', 'pass'),
    ("settlement tx unchecked", '% k)\n    if tx_hash is not None:\n        c2.append("verified" if tx["hash"].lower() == tx_hash else "failed:tx_hash_not_settlement_transaction")', '% k)\n    if tx_hash is not None:\n        pass'),
    ("A1 payer unchecked", 'eq(_addr(pm["payer"], "payment.payer"), au["from"], "payer"),', ''),
    ("absent blocks nothing -> present blocks nothing", 'open_ = sorted(k for k, x in res.items() if x.startswith("not_evaluated") and k not in absent)', 'open_ = []'),
    ("K3 always verified", 'res["K3"] = ("verified (by L2.sig)" if res["L2.sig"].startswith("verified")', 'res["K3"] = ("verified (by L2.sig)" if True'),
    ("address padding unchecked", 'if any(_words(b, i)[:12] != bytes(12) for i in (0, 1)):', 'if False:'),
    ("rlp hash unchecked", 'c2.append("verified" if h == tx["hash"].lower() else "failed:tx_hash_not_its_rlp")\n        if int(_q(tx["chainId"], "chain_tx.tx.chainId").hex() or "0", 16) != acc["chain_id"]:\n            c2.append("failed:tx_chainId_not_network")\n        c2.append(_from_is_signer(tx))\n    c2r = ', 'pass\n        if int(_q(tx["chainId"], "chain_tx.tx.chainId").hex() or "0", 16) != acc["chain_id"]:\n            c2.append("failed:tx_chainId_not_network")\n        c2.append(_from_is_signer(tx))\n    c2r = '),
    ("rlp drops the access list", '_d(tx.get("input"), p + "input"), acc,', '_d(tx.get("input"), p + "input"), [],'),
    ("quantities with leading zeros", 're.fullmatch(r"0x(0|[1-9a-f][0-9a-f]{0,63})", v)', 're.fullmatch(r"0x[0-9a-fA-F]{1,64}", v)'),
    ("eip155 malformed is unsupported", '        if v["network"].startswith("eip155:"):', '        if False:'),
    ("0.2 C3 index unchecked", 'i_tr == i_au + 1 or', 'True or'),
    ("0.2 C3 from unchecked", 'lt["topics"][1].lower() == pad + au["from"][2:] or', 'True or'),
    ("0.2 C3 to unchecked", 'lt["topics"][2].lower() == pad + au["to"][2:] or', 'True or'),
    ("0.2 C3 value unchecked", '(len(data) == 32 and int.from_bytes(data, "big") == au["value"]) or', 'True or'),
    ("0.2 C3 value any length", '(len(data) == 32 and int.from_bytes(data, "big") == au["value"])', '(int.from_bytes(data, "big") == au["value"])'),
    ("0.2 C3 block unchecked", 'lt["blockHash"].lower() == lg["blockHash"].lower() or', 'True or'),
    ("0.2 C3 tx unchecked", 'lt["transactionHash"].lower() == tx["hash"].lower() or', 'True or'),
    ("0.2 C3 address unchecked", 'lt["address"].lower() == acc["asset"] or', 'True or'),
    ("0.2 C3 topic unchecked", 'lt["topics"][0].lower() == TRANSFER_TOPIC or', 'True or'),
    ("0.2 indirect allowed in 0.1", '        if not v02:\n            return "failed:tx_not_to_asset"', '        if False:\n            return "failed:tx_not_to_asset"'),
    ("0.2 log_transfer allowed in 0.1", '("log_transfer", "log_forward") if v02 else ()', '("log_transfer", "log_forward")'),
    ("F1 from unchecked", 'lf["topics"][1].lower() == "0x" + "0" * 24 + au["to"][2:] or', 'True or'),
    ("F1 index unchecked", 'i_f == i_t + 1 or "failed:log_forward_not_next"', 'True or "failed:log_forward_not_next"'),
    ("8021 schema0 non-ASCII", 'if n == 0 or len(tail) != n + 18 or any(c > 0x7F for c in tail[:n]):', 'if n == 0 or len(tail) != n + 18:'),
    ("8021 schema0 any length", 'if n == 0 or len(tail) != n + 18 or any(c > 0x7F for c in tail[:n]):', 'if n == 0 or any(c > 0x7F for c in tail[:n]):'),
    ("A2 absent settlement_tx blocks", '        a2 = "not_evaluated:absent:no_settlement_tx"', '        a2 = "not_evaluated:no_settlement_tx"'),
    ("1271 owner unchecked", 'if who == "0x" + owner[12:].hex()', 'if True'),
    ("1271 code list open", 'if keccak256(cb).hex() not in WALLET_PROXY_CODE and not (', 'if False and not ('),
    ("1271 impl list open", 'or ("0x" + ib[12:].hex()) not in WALLET_IMPL:', 'or False:'),
    ("1271 block unchecked", 'if tx_block is not None and blk.lower() != str(tx_block).lower():', 'if False:'),
    ("1271 params unchecked", '        elif g != want:\n            return', '        elif False:\n            return'),
    ("1271 owner index unchecked", 'if int.from_bytes(sig[32:64], "big") != idx:', 'if False:'),
    ("1271 trailing bytes", 'if 32 + end != len(sig):', 'if False:'),
    ("1271 padding unchecked", 'if end > len(b) or any(b[off + 32 + n:end]):', 'if end > len(b):'),
    ("1271 wallet domain name", 'keccak256(b"Coinbase Smart Wallet")', 'keccak256(b"Coinbase Smart Wallet ")'),
    ("1271 passkey treated as address", '    if len(owner) == 64:        # SPEC 28.3', '    if False:        # SPEC 28.3'),
    ("1271 wallet beside 65 bytes", 'res["L2.sig"] = "failed:payer_wallet_with_a_65_byte_signature"', 'pass'),
    ("1271 any 7702 delegate", '"0x" + cb[3:].hex() in WALLET_7702)', 'True)'),
    ("0.2 indirect missing log is absent", '"not_evaluated:indirect_call_needs_log_transfer" if indirect', '"not_evaluated:absent:no_log_transfer" if indirect'),
]


def main():
    src = open(os.path.join(ROOT, "apc_verify.py")).read()
    survivors, stale = [], []
    # control: the unmutated copy, run exactly as the mutants are, must PASS (else "killed" means nothing)
    tmp = tempfile.mkdtemp(prefix="apcmut_")
    shutil.copytree(ROOT, os.path.join(tmp, "w"), ignore=shutil.ignore_patterns(".git", "__pycache__"))
    env = dict(os.environ, HOME=tmp, PYTHONDONTWRITEBYTECODE="1", APC_SIGLIB=SIGLIB)
    env.pop("PYTHONPATH", None)
    r = subprocess.run([sys.executable, "tests/test_apc.py"], cwd=os.path.join(tmp, "w"), env=env, capture_output=True, text=True)
    shutil.rmtree(tmp)
    if r.returncode != 0:
        print("CONTROL FAILED: the unmutated copy does not pass\n", r.stderr[-2000:])
        return 2
    print("control (unmutated copy) passes", flush=True)
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    for name, old, new in M:
        if only not in name:
            continue
        if src.count(old) != 1:
            stale.append(name)
            continue
        tmp = tempfile.mkdtemp(prefix="apcmut_")
        try:
            shutil.copytree(ROOT, os.path.join(tmp, "w"), ignore=shutil.ignore_patterns(".git", "__pycache__"))
            with open(os.path.join(tmp, "w", "apc_verify.py"), "w") as fh:
                fh.write(src.replace(old, new))
            env = dict(os.environ, HOME=tmp, PYTHONDONTWRITEBYTECODE="1", APC_SIGLIB=SIGLIB)
            env.pop("PYTHONPATH", None)
            r = subprocess.run([sys.executable, "tests/test_apc.py", "-f"], cwd=os.path.join(tmp, "w"), env=env,
                               capture_output=True, text=True)
            killed = r.returncode != 0
        finally:
            shutil.rmtree(tmp)
        print("%-50s %s" % (name, "killed" if killed else "SURVIVED"), flush=True)
        if not killed:
            survivors.append(name)
    n = sum(only in name for name, _, _ in M) - len(stale)
    print("MUTANTS %d, killed %d, survivors %s, stale %s" % (n, n - len(survivors), survivors, stale))
    return 1 if survivors or stale else 0


if __name__ == "__main__":
    sys.exit(main())
