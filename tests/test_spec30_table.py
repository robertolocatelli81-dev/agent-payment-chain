"""SPEC 30.2 and 30.4 against apc_verify.EVIDENCE_RULES and EVIDENCE_QUALIFIED, read as text (ast), without importing
the verifier. First written by a second reviewer (clone agent-payment-chain-20261027T194450Z, commit 94f5e82, for 0.19.0);
revised for 0.19.1 (the columns of 30.2: signature, settlement_record, inclusion_proof, finality_proven,
facilitator_reply, highest, without settlement; the closed list of qualified outcomes of 30.4).

Why apart from tests/test_evidence_level.py: that file imports apc_verify, which loads lib.eip712 and
lib.secp256k1 from APC_SIGLIB or its default (apc_siglib, SPEC 32.12), a tree outside this repository. On a clone
without it (measured 2026-10-27 on a reviewer's clone) every test file errors at import and nothing of section 30 is
checked. This test reads SPEC.md and apc_verify.py as files and compares, row by row of the table of 30.2:
  - the set of bundle versions with a row in SPEC 30.2 (first row per version) == the keys of EVIDENCE_RULES;
  - the checks named in the `signature` and `facilitator_reply` cells == the tuples in the code;
  - the checks named in the `settlement_record` cell are a subset of those the code's predicate reads (_evm_chain
    reads C1, C2, C3; apc-0.1's cell names C1 and C2 only, since an indirect call is C1 failed there);
  - an `inclusion_proof` or `finality_proven` cell that is "—" == False in the code, anything else == True;
  - the `highest` cell == the highest level the row can reach;
  - the qualified outcomes of 30.4 (ii), version by version, == those the patterns of EVIDENCE_QUALIFIED match.
Environment: APC_VERIFY_PATH and APC_SPEC_PATH override the files read (positive control: a mutated copy).

  python3 -m unittest tests.test_spec30_table
"""
import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFY = os.environ.get("APC_VERIFY_PATH", os.path.join(ROOT, "apc_verify.py"))
SPEC = os.environ.get("APC_SPEC_PATH", os.path.join(ROOT, "SPEC.md"))
CHECK = re.compile(r"\b(L2\.sig|K\d|T\d|C\d|S\d|G\d|AC\d|R\d+)\b")
AS_VERSION = re.compile(r"as (apc-\d+\.\d+)")
EVM_CHAIN_READS = {"C1", "C2", "C3"}


def rules_from_code(path):
    """EVIDENCE_RULES as {version: (sig set, fac set, rpc set, block_bound bool, canonical bool)} from the source."""
    with open(path, "rb") as fh:
        tree = ast.parse(fh.read().decode("utf-8"), path)
    consts = {}
    rules = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == "EVIDENCE_RULES":
                rules = node.value
            else:
                consts[node.targets[0].id] = node.value
    assert isinstance(rules, ast.Dict), "EVIDENCE_RULES is not a dict literal"

    def tup(node):
        if isinstance(node, ast.Name):
            return tup(consts[node.id])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return tup(node.left) + tup(node.right)
        assert isinstance(node, ast.Tuple), ast.dump(node)
        return tuple(node.elts)

    def names(node):
        assert isinstance(node, ast.Tuple)
        return frozenset(ast.literal_eval(e) for e in node.elts)

    def rpc(node):
        if isinstance(node, ast.Name) and node.id == "_evm_chain":
            return frozenset(EVM_CHAIN_READS)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_all":
            return frozenset(ast.literal_eval(a) for a in node.args)
        raise AssertionError("unknown rpc predicate: %s" % ast.dump(node))

    out = {}
    for k, v in zip(rules.keys, rules.values):
        sig, fac, chain, bb, can = tup(v)
        out[ast.literal_eval(k)] = (names(sig), names(fac), rpc(chain), ast.literal_eval(bb), ast.literal_eval(can))
    return out


def rules_from_spec(path):
    """The first row per version of the table of SPEC 30.2, same shape as rules_from_code."""
    with open(path, "rb") as fh:
        text = fh.read().decode("utf-8")
    start = text.index("\n30.2 ")
    end = text.index("\n30.3 ", start)
    rows = {}
    for line in text[start:end].splitlines():
        if not line.startswith("| apc-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 8, line
        version = cells[0].split()[0]
        if version in rows:
            continue                                     # apc-0.10 ERC-7710: the same checks, not counting (30.2)
        rows[version] = cells
    out = {}

    def resolve(cell, col):
        found = set(CHECK.findall(cell))
        m = AS_VERSION.search(cell)
        if m:
            found |= resolve(rows[m.group(1)][col], col)
        return frozenset(found)

    for version, cells in rows.items():
        out[version] = (resolve(cells[1], 1), resolve(cells[5], 5), resolve(cells[2], 2),
                        not cells[3].startswith("—"), not cells[4].startswith("—"), cells[6])
    return out


def qualified_from_code(path):
    """EVIDENCE_QUALIFIED as {version: {check: (pattern, ...)}}, evaluating only dict(), ** and literals."""
    with open(path, "rb") as fh:
        tree = ast.parse(fh.read().decode("utf-8"), path)
    consts = {n.targets[0].id: n.value for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
              and isinstance(n.targets[0], ast.Name)}

    def ev(node):
        if isinstance(node, ast.Name):
            return ev(consts[node.id])
        if isinstance(node, ast.Dict):
            out = {}
            for k, v in zip(node.keys, node.values):
                if k is None:
                    out.update(ev(v))
                else:
                    out[ast.literal_eval(k)] = ev(v)
            return out
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
            out = {}
            for a in node.args:
                out.update(ev(a))
            for kw in node.keywords:
                if kw.arg is None:
                    out.update(ev(kw.value))
                else:
                    out[kw.arg] = ev(kw.value)
            return out
        return ast.literal_eval(node)
    return ev(consts["EVIDENCE_QUALIFIED"])


def qualified_from_spec(path):
    """SPEC 30.4 (ii): {version: {check: {outcome, ...}}} from its bullets, N and M written as 2000 and 1000."""
    with open(path, "rb") as fh:
        text = fh.read().decode("utf-8")
    start = text.index("\n30.4 ")
    end = text.index("Qualified outcomes the verifier writes in no column", start)
    body = re.sub(r"\s*\n\s*", " ", text[text.index("each matched whole:", start):end])
    out = {}
    for item in body.split(" - ")[1:]:
        head, _, rest = item.partition(":")
        versions = re.findall(r"apc-\d+\.\d+", head)
        forms = {}
        if "those of apc-0.3" in rest:
            forms = {k: set(v) for k, v in out["apc-0.3"].items()}
        for check, form in re.findall(r"(L2\.sig|K\d)? ?`(verified \([^`]*\))`", rest):
            if check:
                cur = check
            forms.setdefault(cur, set()).add(form.replace("N", "2000", 1).replace("M", "1000", 1)
                                             if "maxAmountRequired" in form else form)
        for v in versions:
            out[v] = forms
    return out


class Spec30Table(unittest.TestCase):
    def setUp(self):
        self.code = rules_from_code(VERIFY)
        self.spec = rules_from_spec(SPEC)

    def test_versions(self):
        self.assertEqual(set(self.spec), set(self.code))
        self.assertGreaterEqual(len(self.code), 9)

    def test_signature_and_facilitator_cells(self):
        for version, (sig, fac, _, _, _, _) in self.spec.items():
            self.assertEqual(sig, self.code[version][0], version)
            self.assertEqual(fac, self.code[version][1], version)

    def test_rpc_cells(self):
        for version, (_, _, rpc, _, _, _) in self.spec.items():
            self.assertTrue(rpc, version)
            self.assertLessEqual(rpc, self.code[version][2], version)

    def test_inclusion_and_finality_cells(self):
        for version, (_, _, _, bb, can, highest) in self.spec.items():
            self.assertEqual(bb, self.code[version][3], version)
            self.assertEqual(can, self.code[version][4], version)
            self.assertTrue(bb or not can, version)     # finality without inclusion would be unreachable (30.1)
            self.assertEqual(highest, "finality_proven" if can else "inclusion_proof" if bb else "settlement_record",
                             version)

    def test_qualified_list(self):
        code, spec = qualified_from_code(VERIFY), qualified_from_spec(SPEC)
        self.assertEqual(set(code), set(self.code))
        for version in code:
            want = spec.get(version, {})
            self.assertEqual(set(code[version]), set(want), version)
            for check, pats in code[version].items():
                self.assertEqual(len(pats), len(want[check]), (version, check))
                for form in want[check]:
                    self.assertTrue(any(re.fullmatch(p, form) for p in pats), (version, check, form))

    def test_ladder_names(self):
        with open(VERIFY, "rb") as fh:
            tree = ast.parse(fh.read().decode("utf-8"), VERIFY)
        levels = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                  and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "EVIDENCE_LEVELS"]
        self.assertEqual(levels, [("none", "signature", "settlement_record", "inclusion_proof", "finality_proven")])


if __name__ == "__main__":
    unittest.main()
