# Changelog

The rules and the measurements behind each entry are in `SPEC.md`; each entry names its section.

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
