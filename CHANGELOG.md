# Changelog

The rules and the measurements behind each entry are in `SPEC.md`; each entry names its section.

## 0.21.8 (unreleased; SPEC 32.17)

One verdict changes: a did:jwk with a private member other than `d` is refused (it was read, the member ignored;
no bundle of the author's corpus carries a did:jwk, counted 2026-11-26). Otherwise what changes is what a refusal
says and what the register records. Each change has
a test in `tests/test_secrets.py` (new, permanent): 17 of its 18 tests fail on 0.21.7 (2fdf128); the one left is the
positive control of the search, which passes on both.

- `apc_registry.py record --tsa`: the URL is recorded in the register (`tsa_url`). One with user information
  (`user:password@`), a non-ASCII character, a space, a backslash, an IPv6 address with a zone
  (`[fe80::1%25eth0]`) or a port past 65535 is refused (exit 3) before the
  network and before any file is read, and the reason does not repeat it (RFC 3986 section 3.2.1). Until 0.21.7 such a
  URL was accepted, and when the authority could not be asked the refusal repeated it whole. A scheme not in lower case
  or more than 500 characters after the `//` are refused there too: the register's grammar of `tsa_url` does not hold
  them, and until 0.21.7 the authority was asked first and nothing was written after. The path and the query of the
  URL are recorded with it: they must not carry a credential.
- A time-stamping authority that could not be asked is named by the kinds of the errors and the errno (`--tsa: no
  reply: URLError: ConnectionRefusedError [Errno 111]`); an unforeseen error of the register by its type only.
- A name a reason repeats (a key id of `--http-keys` or `--signer-trust`, a member outside a closed object, a duplicate
  member, an ignored did:jwk member) is repeated up to 32 characters; a longer one is named by its length. Reasons made
  of shorter names are unchanged, byte for byte. The reader of `apc_mcp.py` follows the same rule for a repeated member
  (its reply repeated 80 characters). So do the other reasons and notes that name a member of the
  bundle itself (until 0.21.7 40 or 64 characters, or whole) and `unknown member` of the register (SPEC 32.17 (c)).
- A did:jwk with any private member of RFC 7518 section 6 or RFC 8037 section 2 (`d`, `p`, `q`, `dp`, `dq`, `qi`,
  `oth`, `k`) is refused (until 0.21.7 `d` only). The seed files of `--key` and `apc_report.py sign` are read up to 256
  bytes and no message repeats a byte of them (a decoding error named one).
- The tools that read from an endpoint you name (`tools/fetch_*.py`, `tools/scan_*.py`: 12 of them) write its
  scheme, host and port into their output (`tools/endpoint.py`), no longer the whole URL: the path or the query of a
  JSON-RPC URL is where a provider puts the key, and those outputs are files meant to be kept (`tools/anchor_msca.py`,
  `tools/rebuild_corpus.py` and `fetch_l1proof.py` already did so). The saved files of this tree are unchanged.
- `openssl` is found by `which_absolute` of omega-nucleo-comune 0.1.0 (`nucleo/`, copied by its `nucleo_sync.py`,
  `NOTICE`), never in the current folder; the temporary folders of the register and of the mandate check by its
  `private_tmpdir`.
- Every bounded read goes in pieces of at most 1 MiB: `read(bound + 1)` asked the allocator for the whole bound first,
  and under a data limit a 1-byte bundle ended in MemoryError (measured 2026-11-26, `ulimit -d 60000`). Every JSON
  reader refuses an integer of more than 4300 digits with one reason on every Python (the CI's macOS arm64 and Windows
  run CPython 3.9.13, which reads one whole).
- CI: Linux, macOS and Windows with Python 3.9 to 3.14, each with and without `cryptography` (until 0.21.7 macOS and
  Windows with 3.13 only); a newer push to a `ci-prova-*` branch stops the run it supersedes. Not yet run on GitHub.
- Not in this version: `VERSION` stays `apc_verify 0.21.7` until the release, which sets it and refreezes the regress
  file (as 0.21.7 did); the mandate pack stays ap2-evidence-pack v1.7.1 (SPEC 31, 32.12).

## 0.21.7 (2026-11-24; SPEC 32.16, section 10.2; the amendments of 32.12 and 33.11 of the same date)

The first tagged release. On the 1123 bundles of the regress list (`tools/regress.py check`, 2026-11-24) no verdict,
exit or check changes from 0.21.6; the frozen file is rewritten under 0.21.7, the verifier string the only change.

- X7, the RFC 9421 signatures of `exchange` (section 10.2): the Web Bot Auth working-group draft
  draft-ietf-webbotauth-httpsig-protocol-01 is cited in place of draft-meunier-...-02, which it replaced; its vectors
  E.2.1, E.2.2 and E.2.3 verify (E.1, RSA, is `not_evaluated:algorithm_not_supported`).
- ML-DSA-44/65/87 (IANA "HTTP Message Signature" registry, c2sp.org/httpsig-pq v1.0.1): `--http-keys` takes
  `ml-dsa-*` keys, verified with the `cryptography` package (without it: `not_evaluated:ml_dsa_needs_cryptography`).
- Components: the `key` parameter of a Dictionary field and `@query-param` are built; a derived name or a parameter
  outside the IANA registry, or one that does not apply, is `failed:component_not_valid` (it was not judged); an `alg`
  outside the registry is `failed:algorithm_not_registered`, no alias.
- Each label reports its `tag` and the profile it names (`web-bot-auth`; Visa TAP's `agent-browser-auth`,
  `agent-payer-auth`) with what it lacks; reported only, never a result.
- Hostile input (section 29, hunt of 2026-11-23): X7 parses a field or a query once per check; the authority of
  `target_uri` is read by one grammar on every Python; `apc_block.py` and `apc_batch.py` answer `refused` where they
  ended with a traceback.
- JSON nesting (sections 29.1 and 33.11): every reader that relied on the parser's RecursionError (the six named in
  33.11) counts the arrays
  and objects on the text first, in constant memory, and refuses past 64 (`tools/bench_journal.py` past 8) with one reason
  on every Python (Python 3.14 read 100,000 levels without that error). The register refuses to record an entry it
  could not read back (11.3).
- Line ends (section 32.12): a library or pack file that is the tag's file with CRLF line ends is still refused
  (the library: exit 64; the pack: MP1-MP7 `not_1.7.1`), and the refusal names that cause;
  `.gitattributes` (`* -text`) keeps this repository's bytes as committed on every platform.
- Windows and macOS: the register's writer lock is `msvcrt.locking` on Windows (it took no lock there, 11.3);
  `tools/fuzz_bundles.py` runs each case in a Job Object with the same memory and CPU limits on Windows (it did not
  import there, 29.5); the fuzz child's peak memory is read in bytes on macOS (it was read as KiB).
- Sources: the four Internet-Drafts of `sources/ietf` are removed (cited by no section); `sources/webbotauth_c2sp_20261123`
  added (IETF TLP 5.0, CC BY 4.0; `NOTICE`).
- CI (`.github/workflows/ci.yml`): Python 3.9 to 3.14 on Linux, Python 3.13 on macOS and Windows, each cell also
  without `cryptography`, and gitleaks 8.30.1 on the history and the tree; run 45375267177 on 21116a2, 9 jobs green.
- Release files: this changelog, `SECURITY.md`, `CITATION.cff`, and `.github/workflows/release.yml` (on a `v*` tag:
  the source archives of the tag from `git archive`, their SHA256SUMS, build provenance attested).

## Earlier versions (never tagged)

0.21.0 to 0.21.6 are SPEC section 32 and its Amendments 32.10 to 32.15; the versions before 0.21 are the sections that
the first lines of `SPEC.md` list, each with its date and its measurements.
