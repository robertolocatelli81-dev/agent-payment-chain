# agent-payment-chain

A verifier of payments made by AI agents: one bundle in, one verdict out, offline, trusting neither the party that
produced the bundle nor any service. It checks the authorization (an AP2 mandate as an ap2-evidence-pack), the payment
(x402 schemes: EIP-3009, Permit2, ERC-7710, auth-capture, Solana, XRPL, Stellar), the acceptance record, and the links
between them (amount, asset, payee, time windows, hashes), against the chain data carried in the bundle (headers,
transactions, receipts, inclusion proofs, state proofs). The specification is `SPEC.md` (0.21); the verifier is
`apc_verify.py` (0.21.5) with its modules `apc_*.py`; the tools that built and measured it are in `tools/`; the tests in
`tests/`. Code identifiers and docstrings are in English.

This tree is built from commit 27bf776 of the author's working tree by a publication tool; the earlier history is
not carried over. `SPEC.md` is the author's working document: a measure stated "on this tree" means the author's
working tree at the date given, with the real corpus, not this public tree; sections marked "local" were written before
publication.

## Running it

Python 3.9 or later, standard library only (the mandate checks of SPEC 31 apart: below). Two sibling checkouts by the
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

```
python3 apc_verify.py BUNDLE.json            # verdict on standard output, exit code by SPEC section 5
python3 -m unittest discover -s tests -t .   # the suite; the modules that need the real corpus skip and say why
python3 tools/rebuild_corpus.py --check-manifest
```

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
