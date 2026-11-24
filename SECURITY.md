# Security policy

Please report vulnerabilities **privately**, not in a public issue or pull request:
use GitHub's "Report a vulnerability" button on the Security tab of this repository (private vulnerability reporting).

Useful in a report: the file and function, a bundle or input that shows the problem, what you expected and what
happened, and the commit or release you tested.

In scope: a bundle, keys document, register or MCP message that a verifier or tool in this repository accepts when it
should refuse it (or the reverse), a verdict that a bundle's data does not support, a crash, hang or unbounded memory
on untrusted input (SPEC section 29), a signature or proof check that can be bypassed, code run from bytes other than
those hashed (SPEC 32.12).

There is no bug bounty.

Supported versions: the latest release (see `CHANGELOG.md`) and the latest commit of the default branch.

Platforms the CI tests (run 45375267177, 24 November 2026, on commit 21116a2, all 9 jobs green): Linux
(`ubuntu-24.04`) with Python 3.9 to 3.14, macOS (`macos-latest`) and Windows (`windows-latest`) with Python 3.13,
each with and without `cryptography`. Other systems are not tested.
