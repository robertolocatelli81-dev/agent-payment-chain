# The real corpus, as a list (SPEC section 33)

`MANIFEST.json` (format `apc-corpus-0.3`, SPEC 33.10) lists every real payment the verifier was measured on: the chain, the
transaction, the block or ledger, the consensus fingerprints (block hash, transaction hash and index, receipt digest,
ledger hash, Solana id), what of the bundle is our reconstruction, and the sha256 of the file we built. It carries no
address of a person in clear: payers and the Solana fee payer are derived from the chain, an MSCA owner is pinned by
keccak256 (SPEC 33.2); addresses of contracts stay.
The bundles themselves (`bundles/`) and the raw RPC replies they came from (`oracle/`) are not in this tree: no reply
of a third-party service is redistributed. Whoever wants the corpus rebuilds it from the chain, through an endpoint of
their choice:

```
python3 tools/rebuild_corpus.py --check-manifest
python3 tools/rebuild_corpus.py --rpc eip155:8453=https://YOUR-BASE-ENDPOINT --only real,real_v02,real_v03
python3 tools/rebuild_corpus.py --rpc xrpl:0=https://YOUR-XRPL-SERVER/ --only xrp_real_20261026
python3 tools/rebuild_corpus.py --rpc solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp=https://YOUR-SOLANA-ENDPOINT --only real_svm
```

Every reply is accepted only if the fingerprints of the list recompute from its bytes (a header hashing to the pinned
block hash, a transaction whose RLP hashes to its id, a receipt inside the header's receiptsRoot, a ledger whose SHAMap
root is the header's, a Solana message signed by its fee payer); otherwise it is refused with the reason. Where a
fingerprint cannot be recomputed (the Avalanche header, receipts outside a receiptsRoot, the Solana execution record,
three state replies: SPEC 33.5) the list's own digest is the anchor: you get our bytes, not consensus, and the report
says which anchor held. The report
says, per bundle, whether the file written is byte-identical to ours (`bytes`), identical but for `provenance`
(`content`), or gives the same verdict and checks under `apc_verify` (`verdict`); some sets are `local_only` and say why.

**You are responsible for the terms of service of the endpoint you name** (`--rpc` or `APC_RPC_<CAIP2>` in the
environment); a node of your own is the recommended one. No endpoint is written in the tool; it paces itself (1 request
per second per host by default, backoff on 429/5xx), identifies itself by User-Agent, and never logs or writes a URL
(hosts only). Some sets need an archive endpoint (`eth_getProof`, state reads at old blocks): the list says which.

Two directories of raw replies the tests read are rebuilt the same way, written only when their content is ours
(SPEC 33.8): `python3 tools/rebuild_corpus.py --oracle blocks_v03 --rpc eip155:8453=...` and `--oracle xrpl_20261026
--rpc xrpl:0=...`. The tests that read `bundles/` or `oracle/` skip with the reason when they are absent; a module that
skips whole names the rebuild command when one exists; the regression corpus (`tools/regress.py`) refuses to run without them. Sets declared
`local_only` (52 bundles) and the other `oracle/` directories are not rebuilt: after a complete rebuild (bundles and
the two directories) 31 of the 50 test modules that read the corpus load and 19 skip (11 for a `local_only` set, 6
for a `local_only` directory, 2 for reference vectors and saved replies kept with the corpus), and say so; without
the `cryptography` package tests/test_mandate.py skips too (30 and 20). `tests/test_corpus_manifest.py` runs on the list
alone, without network.
