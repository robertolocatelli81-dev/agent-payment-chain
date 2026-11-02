"""Run the test classes of the mutation bench, fastest first, stopping at the first failure.

python3 -B tools/run_ordered.py [MUTATED_FILE]

The classes that test MUTATED_FILE directly run first, then every other class by its measured time. Every class of
the modules in MODS runs once, whatever the order, so a mutant is killed or survives exactly as under
`unittest -f` over the same modules; only the time to the first failure changes. A class missing from COST runs last.
"""
import os
import sys
import unittest

sys.path.insert(0, os.getcwd())
MODS = ["test_apc03", "test_removed", "test_l1proof", "test_high_s", "test_failed_but_executed", "test_amend032",
        "test_review032", "test_reverted", "test_self_payment", "test_sender", "test_svm", "test_l1state",
        "test_report", "test_mcp", "test_provenance", "test_ap2", "test_review070",
        # the 0.2 suite and the canonical tool's tests too (25/10: N34 and N35 lived in b14 because the test that
        # kills them was only in test_apc); a mutant lives only if the whole suite lets it live. Not test_standin:
        # it tests only tools/siglib_standin, loaded by file path, which no mutant changes (it runs under `discover`).
        "test_apc", "test_canonical_tool", "test_review071", "test_http", "test_registry", "test_permit2",
        "test_permit2_state", "test_offer_receipt", "test_builder_code", "test_payid",
        "test_transport", "test_drafts", "test_intl", "test_world",
        "test_kanon", "test_xlm", "test_v1",
        "test_report_keys", "test_drafts2", "test_drafts3", "test_authcap", "test_xrp", "test_integration",
        # 26/10: the frozen regression corpus (sample; the full corpus is `tools/regress.py check`) and the real negatives
        "test_regress", "test_negatives",
        # 26/10: SPEC 29, the bundle as hostile input
        "test_hostile",
        # 26/10: SPEC 28, Wycheproof and the passkey owners (branch passkey-wycheproof)
        "test_webauthn", "test_wycheproof",
        # 27/10: SPEC 25 C1, the apc-0.15 logs bind the transaction's block (the author's decision)
        "test_authcap_block",
        # 26/10: the coverage census (branch coverage-net)
        "test_coverage_census",
        # 27/10: SPEC 29.8, the equivalence tools read the real bundles by the closed table
        "test_equiv_tools",
        # 27/10: SPEC 30, the evidence level of a verdict (branch evidence-level)
        "test_evidence_level",
        # 27/10: SPEC 30.2 and 30.4 read as text (the second reviewer's commit 94f5e82, revised for 0.19.1)
        "test_spec30_table",
        # 31/10: SPEC 31, the AP2 mandate as an ap2-evidence-pack 1.7.1 pack (branch mandate-ring; needs APC_AP2EV)
        "test_mandate",
        # 01/11: SPEC 32, payer_state and the ERC-1271 of Circle_SingleOwnerMSCA (branch erc1271-msca); the review of
        # 19b0ecd (R1, R2, R4) and Amendment 0.21.1 (32.10, the anchored block)
        "test_msca", "test_review_msca", "test_msca_anchor",
        # 01/11: SPEC 33, the list of the real corpus and its rebuild (branch corpus-rebuild)
        "test_corpus_manifest",
        # 02/11: SPEC 32.11 (0.21.2), the verifier's environment: sibling pack, cause named, exit 64, the suite skipping;
        # 32.12 (0.21.3), the code run is the code hashed (pack and signature library), APC_REQUIRE_DEPS
        "test_amend0212"]
NEAR = {"apc_svm.py": ["test_mandate", "test_hostile", "test_svm", "test_wycheproof", "test_review070", "test_review071",
                       "test_integration"],
        "apc_solana.py": ["test_hostile", "test_wycheproof", "test_svm", "test_review070", "test_review071"],
        "apc_webauthn.py": ["test_webauthn", "test_hostile"],
        "apc_batch.py": ["test_svm", "test_integration"], "apc_l1proof.py": ["test_l1proof", "test_l1state"],
        "apc_block.py": ["test_hostile", "test_l1proof", "test_l1state"],
        "apc_report.py": ["test_report", "test_report_keys", "test_review070", "test_review071"],
        "apc_ap2.py": ["test_hostile", "test_ap2", "test_review070", "test_review071"],
        "apc_mcp.py": ["test_hostile", "test_mcp", "test_review070", "test_review071"],
        "apc_http.py": ["test_hostile", "test_http"], "apc_registry.py": ["test_registry"],
        "apc_permit2.py": ["test_permit2", "test_permit2_state", "test_integration"],
        "apc_offer.py": ["test_offer_receipt", "test_integration"], "apc_builder.py": ["test_builder_code"],
        "apc_payid.py": ["test_payid"], "apc_transport.py": ["test_transport"],
        "apc_drafts.py": ["test_drafts"], "apc_intl.py": ["test_intl"],
        "apc_assets.py": ["test_world", "test_high_s"],
        "apc_stellar.py": ["test_xlm"], "apc_xlm.py": ["test_xlm", "test_wycheproof", "test_integration"],
        "apc_v1.py": ["test_v1"],
        "apc_drafts2.py": ["test_drafts2", "test_hostile"], "apc_drafts3.py": ["test_drafts3", "test_hostile"],
        "apc_dr3783.py": ["test_hostile", "test_drafts3"],
        "apc_authcap.py": ["test_authcap_block", "test_hostile", "test_authcap", "test_integration"], "apc_xrp.py": ["test_hostile", "test_xrp", "test_integration"],
        "apc_xrpl.py": ["test_hostile", "test_xrp", "test_wycheproof"], "tools/regress.py": ["test_regress"],
        "apc_mandate.py": ["test_mandate", "test_amend0212"], "apc_siglib.py": ["test_amend0212", "test_standin", "test_hostile"],
        "apc_msca.py": ["test_msca", "test_msca_anchor", "test_review_msca", "test_evidence_level", "test_coverage_census"],
        "apc_verify.py": ["test_amend0212", "test_msca", "test_msca_anchor", "test_review_msca", "test_mandate", "test_evidence_level", "test_spec30_table", "test_hostile", "test_webauthn"], "tools/fuzz_bundles.py": ["test_hostile"],
        "tools/make_bundles_negatives.py": ["test_negatives"], "tools/scan_negatives_evm.py": ["test_negatives"],
        "tools/rebuild_corpus.py": ["test_corpus_manifest"], "tools/make_corpus_manifest.py": ["test_corpus_manifest"],
        "tests/real_corpus.py": ["test_corpus_manifest"],
        "tools/coverage_census.py": ["test_coverage_census", "test_msca"],
        "tools/equiv_x04.py": ["test_equiv_tools"], "tools/equiv_mutants.py": ["test_equiv_tools"],
        "tools/equiv_r02.py": ["test_equiv_tools"]}
# Seconds per class on the frozen 0.7.0 copy, one class at a time (measured 2026-10-25).
COST = {
    # test_evidence_level: measured 2026-10-27 (branch evidence-level), one class at a time
    "test_evidence_level.Table": 0.06, "test_evidence_level.ClosedTable": 0.28, "test_evidence_level.RequireLevel": 3.2,
    "test_evidence_level.Drafts": 4.5, "test_evidence_level.Corpus": 6.7, "test_evidence_level.Ladder": 9.4,
    "test_evidence_level.Generative": 31.3,
    # test_hostile: measured 2026-10-26 (SPEC 29 tree), one class at a time
    "test_hostile.Ap2Embedded": 0.32, "test_hostile.AuthCaptureTopics": 0.34, "test_hostile.Base58": 0.06,
    "test_hostile.DeliveryReceiptDraft": 0.0, "test_hostile.ExistingLimits": 0.01, "test_hostile.FuzzCases": 0.28,
    "test_hostile.Harness": 0.01, "test_hostile.HttpLabels": 0.26, "test_hostile.InternalError": 0.0,
    "test_hostile.JsonDepth": 0.30, "test_hostile.KeccakBudget": 0.32, "test_hostile.McpLine": 0.0,
    "test_hostile.Rlp": 0.49, "test_hostile.SolanaMetaTypes": 0.07, "test_hostile.UpperX": 0.97, "test_hostile.Xrpl": 0.16,
    # test_registry: measured 2026-10-26 on the reg-device tree (0.9.1), one class at a time
    "test_registry.Nmea": 0.67,
    "test_registry.Gpsd": 0.66,
    "test_registry.Zone": 5.68,
    "test_registry.Views": 0.64,
    "test_registry.Register": 8.08,
    "test_registry.Timestamp": 0.93,
    "test_registry.Rerun": 5.19,
    "test_registry.Cli": 7.90,
    "test_amend032.UpperX": 1.15,
    "test_amend032.ZeroValueEveryVersion": 1.72,
    "test_ap2.Built": 0.14,
    "test_ap2.Canonical": 0.0,
    "test_ap2.Corpus": 32.04,
    "test_ap2.P256": 0.01,
    "test_apc03.Canonical": 27.29,
    "test_apc03.CanonicalRules": 9.39,
    "test_apc03.CliFiles": 0.64,
    "test_apc03.ConsistentForgeries": 11.31,
    "test_apc03.Erc6492AndZero": 0.18,
    "test_apc03.GenerativeInclusion": 106.04,
    "test_apc03.InclusionMutations": 33.1,
    "test_apc03.Review031": 5.9,
    "test_apc03.ReviewCoverage": 25.2,
    "test_apc03.ReviewGrammar": 13.45,
    "test_apc03.RealInclusion": 97.09,
    "test_apc03.SetChecks": 21.29,
    "test_apc03.SmallerRules": 0.71,
    "test_failed_but_executed.FailedButExecuted": 352.95,
    "test_high_s.HighS": 103.51,
    "test_l1proof.L1Proof": 0.17,
    "test_l1state.Broken": 42.61,
    "test_l1state.Grammar": 7.49,
    "test_l1state.Logic": 10.97,
    "test_l1state.OtherNetwork": 0.17,
    "test_l1state.Real": 10.74,
    "test_mcp.Mcp": 2.02,
    "test_review032.DirectV02": 45.44,
    "test_review032.EmptyHexParam": 0.16,
    "test_review032.HighSAcceptedOnChain": 0.46,
    "test_review032.HighSBoundary": 0.01,
    "test_review032.SettlementReply": 4.39,
    "test_provenance.Provenance": 5.9,
    "test_removed.RemovedLog": 6.0,
    "test_report.Ed25519": 0.02,
    "test_report.Merkle": 1.35,
    "test_report.Policy": 1.8,
    "test_report.Sarif": 3.43,
    "test_report.Signed": 11.0,
    "test_reverted.Reverted": 25.28,
    "test_self_payment.SelfPayment": 67.49,
    "test_sender.Sender": 103.83,
    "test_svm.Batch": 0.38,
    "test_svm.Broken": 0.96,
    "test_svm.Built": 0.09,
    "test_svm.BuiltChain": 0.92,
    "test_svm.Grammar": 7.44,
    "test_svm.Real": 0.39,
    # measured 2026-10-26 on the p2-permit2 tree, one class at a time
    "test_permit2.Constants": 0.16,
    "test_permit2.Built": 1.84,
    "test_permit2.Erc7710": 1.31,
    "test_permit2.Broken": 20.27,
    "test_permit2.Grammar": 44.36,
    "test_permit2.Real": 108.16,
    "test_permit2_state.KernelRule": 4.0,
    "test_permit2_state.DelegatorRule": 5.74,
    "test_permit2_state.ProofForm": 6.56,
    "test_permit2_state.Erc1271Declared": 10.48,
    "test_permit2_state.InclusionCanonicalAcceptance": 16.31,
    "test_permit2_state.RealState": 126.71,
    # measured 2026-10-26 on the passkey-wycheproof tree, one class at a time
    "test_webauthn.CompactOwnerSignature": 1.68,
    "test_webauthn.Generative": 83.27,
    "test_webauthn.RealData": 2.55,
    "test_webauthn.RequireUV": 0.05,
    "test_webauthn.WycheproofP256": 0.61,
    "test_wycheproof.ChainCallSites": 0.14,
    "test_wycheproof.CompressedKeys": 0.05,
    "test_wycheproof.Ed25519": 11.11,
    "test_wycheproof.Ed25519ChainRules": 0.35,
    "test_wycheproof.P256": 1.03,
    "test_wycheproof.Secp256k1Der": 122.77,
    "test_wycheproof.Secp256k1Recovery": 66.83,
    # measured 2026-10-26 on the coverage-net tree, one class at a time
    "test_coverage_census.Grammar": 0.07,
    "test_coverage_census.Wallet": 0.93,
    "test_coverage_census.Census": 2.03,
}


def classes():
    by = {}
    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                walk(t)
            else:
                by.setdefault(type(t).__module__.replace("tests.", "", 1) + "." + type(t).__qualname__, []).append(t)
    import tests  # noqa: F401  (its loader reports a module that skips at import — the real corpus absent — as skipped)
    walk(unittest.defaultTestLoader.loadTestsFromNames(["tests." + m for m in MODS]))
    return by


def main():
    near = NEAR.get(sys.argv[1] if len(sys.argv) > 1 else "", [])
    by = classes()
    order = sorted(by, key=lambda c: (c.split(".")[0] not in near, COST.get(c, float("inf"))))
    suite = unittest.TestSuite(t for c in order for t in by[c])
    r = unittest.TextTestRunner(failfast=True, verbosity=0).run(suite)
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
