# agent-payment-chain

A verifier of payments made by AI agents: one bundle in, one verdict out, offline, trusting neither the party that
produced the bundle nor any service. It checks the authorization (an AP2 mandate as an ap2-evidence-pack), the payment
(x402 schemes: EIP-3009, Permit2, ERC-7710, auth-capture, Solana, XRPL, Stellar), the acceptance record, and the links
between them (amount, asset, payee, time windows, hashes), against the chain data carried in the bundle (headers,
transactions, receipts, inclusion proofs, state proofs). The specification is `SPEC.md` (0.21); the verifier is
`apc_verify.py` (0.21.7) with its modules `apc_*.py`; the tools that built and measured it are in `tools/`; the tests in
`tests/`. Code identifiers and docstrings are in English.

The first commit of this repository (37a506f, 2026-11-02) was built from the author's working tree by a publication
tool, and so were later trees up to 0.21.5 (edec562, from 27bf776); the earlier history is not carried over. The
commits since edec562 are made in this repository. `SPEC.md` is the author's working document: a measure stated "on
this tree" means the author's working tree at the date given, with the real corpus, not this public tree; sections
marked "local" were written before publication.

## Running it

Python 3.9 or later, standard library only (the mandate checks of SPEC 31 and the ML-DSA signatures of X7, SPEC 10.2,
apart: below). Two sibling checkouts by the
same author are read, both public:

- [x402-signature-vectors](https://github.com/robertolocatelli81-dev/x402-signature-vectors) at tag `v1.4.0`
  (`lib/eip712.py`, `lib/secp256k1.py`): path in `APC_SIGLIB` (when set and not empty), default
  `../x402-signature-vectors`. The two files are read and hashed, and only when both have the SHA-256 of that tag are
  those bytes run as the library; nothing else of the folder runs, and the folder is never on `sys.path` (SPEC 32.12).
  Without them, or with files of another version, the verifier does not start: one line on standard error naming the
  path tried (and the hash found), no report, exit 64 (SPEC 32.11; not a verdict);
- [ap2-evidence-pack](https://github.com/robertolocatelli81-dev/ap2-evidence-pack) at tag `v1.7.1`, for the mandate
  checks of SPEC 31: path in `APC_AP2EV`, default `../ap2-evidence-pack` (used only when its two files have the hashes
  of that tag, and only those two files are run; the variable, when set and not empty, wins). It imports the
  `cryptography` package (`pip install cryptography`), the one dependency outside the standard library. Without the
  pack (no `APC_AP2EV` and no sibling), or without that package, those seven checks say
  `not_evaluated:ap2_evidence_pack_unavailable`; files of another version, or an `APC_AP2EV` naming a folder without
  them, `not_evaluated:ap2_evidence_pack_not_1.7.1`; the note names the cause (SPEC 32.11). `tests/test_mandate.py`
  skips in this tree because its corpus set is absent; once `real_svm_mandate` is rebuilt it skips with the reason if
  the pack, `cryptography` or `openssl` is missing.

On Windows (Git for Windows sets `core.autocrlf=true`), or wherever that setting is on, clone the two siblings with
`git -c core.autocrlf=false clone ...`: a checkout that turns LF into CRLF changes the hashed bytes, and the refusal
then says that the line ends are the cause. This repository keeps its own bytes through `.gitattributes` (`* -text`).
The CI workflow (.github/workflows/ci.yml) runs the suite on Linux with Python 3.9 to 3.14 and on macOS and Windows
with Python 3.13, each with and without `cryptography`; a test that needs what a platform lacks skips with the reason.

```
python3 apc_verify.py BUNDLE.json            # verdict on standard output, exit code by SPEC section 5
python3 -m unittest discover -s tests -t .   # the suite; the modules that need the real corpus skip and say why
python3 tools/rebuild_corpus.py --check-manifest
```

## apc_verify 0.21.7, SPEC 32.16 (released 2026-11-24)

- X7 under the sources in force on 2026-11-23: the Web Bot Auth working-group draft
  (draft-ietf-webbotauth-httpsig-protocol-01, which replaced draft-meunier-...-02) is cited in place of -02; its
  vectors E.2.1, E.2.2 and E.2.3 verify (E.1, RSA, is `not_evaluated:algorithm_not_supported`).
- ML-DSA-44/65/87 (IANA registry of 2026-10-23, c2sp.org/httpsig-pq v1.0.1): `--http-keys` takes `ml-dsa-*` keys, and
  their signatures are verified with the `cryptography` package (without it: `not_evaluated:ml_dsa_needs_cryptography`).
- Components: the `key` parameter of a Dictionary field and `@query-param` are built; a derived name or a parameter
  outside the IANA registry, or one that does not apply, is `failed:component_not_valid` (it was not judged); an `alg`
  outside the registry (Visa TAP's `rsa-pss-sha256`) is `failed:algorithm_not_registered`, no alias.
- Each label reports its `tag` and the profile it names (`web-bot-auth`; Visa TAP's `agent-browser-auth`,
  `agent-payer-auth`) with what it lacks; reported only, never a result.
- Hostile input (SPEC 29, hunt of 2026-11-23): X7 joins and parses a field or a query once per check; the authority
  of `target_uri` is read by one grammar on every Python (SPEC 10: an IP literal without zone identifier, a port of
  digits); `apc_block.py` and `apc_batch.py` answer `refused` where they ended with a traceback.
- JSON nesting (SPEC 29.1, 33.11): every reader that relied on the parser's RecursionError (the six named in SPEC
  33.11) now counts the arrays and objects on the text before the parser and refuses past 64 (tools/bench_journal.py
  past 8) with one reason on every Python; the Python 3.14 of the CI does not raise that error at 100,000 levels. The
  register refuses to record an entry that would nest past 64 (SPEC 11.3).
- Line ends (SPEC 32.12): a library or pack file that is the tag's file with CRLF line ends (a checkout with
  `core.autocrlf=true`) is still refused, and the refusal now names that cause; `.gitattributes` keeps this
  repository's bytes as committed on every platform.
- Windows and macOS: where Windows lacks a POSIX facility the code uses its equivalent: the register's writer lock is
  msvcrt.locking (it took no lock there before, SPEC 11.3); tools/fuzz_bundles.py runs each case in a process inside
  a Job Object with the same memory and CPU limits (no fork or setrlimit; the tool did not import before, SPEC 29.5);
  tools/bench_journal.py does not open a directory to fsync it. macOS: the fuzz child's peak memory is read in bytes
  (it was read as KiB). The tests that close standard error use the `sh` on PATH (Git for Windows' on Windows); the
  case of a full standard error skips where there is no /dev/full (Windows, macOS), with that reason.

## apc_verify 0.21.6, SPEC 32.15 (released 2026-11-22, commit 111de70; never tagged)

- The RFC 9421 signatures of `exchange` (X7) and their window, SPEC 10.1: with `--http-keys`, a label whose `expires`
  is less than its `created` is `failed:expires_before_created` (it was `verified`); when the bundle proves the time
  of its block (B1 verified), the signatures follow the order of the exchange, request <= payment <= response: a
  request signed after that time, or a response signed before it or before the request, is `not_evaluated` with the
  reason (a `chain_verified` becomes `chain_incomplete`); the `expires` of a request is not compared with the block
  time (our reading, SPEC 10.1 b). No clock is read. `--http-clock-skew N` (0 to 300 seconds, default 0, with
  `--http-keys`) is the margin of these comparisons; every label reports `block_time_minus_created` and
  `expires_minus_block_time`.
- With `--http-keys`, X7 is in every report that carries checks: `not_evaluated:absent:no_exchange` for a bundle
  without `exchange`, and the keys document is checked for every bundle version; `--require-http-signature` (with
  `--http-keys`) turns a `chain_verified` whose X7 is not `verified`, or whose labels do not cover what profile
  `apc-http-coverage/1` names, into `chain_incomplete`, and lists what is missing (SPEC 10.1 d: a request covers
  `@authority` or `@target-uri` and `payment-signature` and carries `created` and `expires`; a response covers
  `@status` and `payment-response`).
- Verdicts: on the 1123 bundles of the regress list no verdict changes, with or without `--http-keys`; without it no
  check changes either, and with it the 1113 reports that are not refusals gain X7
  `not_evaluated:absent:no_exchange` (SPEC 10.1).
- The MCP server (`apc_mcp.py`) is dual-era: the current revision 2026-07-28 (`server/discover`, the version in each
  request's `_meta`, no `initialize`) and 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05 after `initialize`. A legacy
  request other than `ping` before `initialize` is now refused (-32600); from 2025-11-25 on, invalid tool arguments
  are a tool error (`isError`) instead of -32602; after an `initialize` at 2025-03-26 a JSON-RPC batch (a JSON array)
  is answered as that revision requires. A JSON line nested deeper than 64, or a message that is not a JSON-RPC 2.0
  Request object (`method` not a string, `params` not an array or object), is -32600 with id null, on every Python
  (SPEC section 8).

## The real corpus

The verifier was measured on real payments (SPEC 33). Their list is `corpus/MANIFEST.json`: chain, transaction, block
or ledger, consensus fingerprints and the sha256 of each bundle we built. The bundles (`bundles/`) and the raw RPC
replies they came from (`oracle/`) are NOT in this tree: no reply of a third-party service is redistributed. Whoever
wants the corpus rebuilds it from the chain through an endpoint of their choice, as `corpus/README.md` explains:

```
python3 tools/rebuild_corpus.py --rpc eip155:8453=https://YOUR-BASE-ENDPOINT --only real,real_v02,real_v03
```

You are responsible for the terms of service of the endpoint you name; a node of your own is the recommended one.
Three sets (52 bundles) are `local_only` and are not rebuilt (`corpus/README.md` says why). The tests that read
`bundles/` or `oracle/` skip when they are absent and name what they need; a module that skips whole also prints the
rebuild command, or says that the set is `local_only`. Two
reference-vector files (`tests/data/offer_receipt_ref_vectors.json`, `tests/data/drafts2_ref_vectors.json`, made by the
x402 reference implementation for the paid terms of two real payments) are kept with the corpus for the same reason
and are not in this tree; the tests that read them skip with the reason. The NMEA captures of gpsd that
`tests/test_registry.py` reads are fetched by `python3 tools/fetch_nmea_captures.py` (their headers name the people
who submitted them). The positive controls that extract an older version of the verifier from the git history skip
in this tree, whose history does not hold those versions.

## Addresses, privacy, removal

The bundles, the list and the specification name public on-chain facts: transaction identifiers, block hashes, the
contracts involved (token contracts, EntryPoint, Permit2, escrows, wallet implementations). In this tree the addresses
of third-party ACCOUNTS (payers, payees, the owner of a smart account) and the author's own keys of the test payment
of 2026-10-31 are not written out (the sending keys of facilitators stay as their operators publish them: the x402scan
list in `sources/`, `sources/labels_ours.json`, and one Stellar testnet signer of the x402.org facilitator in
`tests/test_xlm.py`): the text uses stable role labels (`payer-A`, `payee-B`,
`owner-D`, `feepayer-S4`...; the same label always stands for the same account) and the tests use addresses derived
from the author's deterministic test keys. The limit of this pseudonymisation is stated plainly: the transaction
identifiers stay in `corpus/MANIFEST.json` and in the text, and on a public chain a transaction identifier leads to the
accounts that took part in it. `corpus/MANIFEST.json` (format apc-corpus-0.3) names no account: payers and fee payers
are derived from the chain data the rebuild fetches, an MSCA owner is pinned by its keccak256 (SPEC 33.2); the
addresses of contracts stay. No person's name, e-mail or other enrichment is attached to any account address in the
author's files; the third-party lists in `sources/` name the operator (a service) of each facilitator key, as
published by them. The data are used only as a test oracle of a verifier. If you are the holder of an account named here, directly or through a transaction identifier, and want it
removed from the list and the tests, open an issue on this repository titled "removal request" (or write to the
author through the GitHub profile): the case will be taken out of the corpus list and of the tests, and the measures
that depended on it re-run and re-stated.

## Trademarks

x402, AP2, Coinbase, Base, Circle, USDC, EURC, MetaMask, ZeroDev, Uniswap, Permit2, Solana, Stellar, XRP Ledger,
Google, OpenZeppelin, Routescan, Sourcify, x402scan and every other name in this tree belong to their respective
holders. They are used descriptively, to say which formats, contracts and services this verifier checks conformance
with; nothing here is affiliated with, endorsed by or approved by any of them.

## Licence

Copyright 2026 Roberto Locatelli. Licensed under the Apache License, Version 2.0 (`LICENSE`). `sources/` holds
unmodified copies of third-party files, each under its own licence (`NOTICE`, `LICENSES/`). The verifier is a tool of
verification; it is not a payment service and gives no warranty (Apache-2.0, sections 7 and 8).
