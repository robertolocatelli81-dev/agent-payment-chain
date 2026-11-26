"""agent-payment-chain, SPEC 32.12 (f): the signature library of x402-signature-vectors, tag v1.4.0, loaded as the bytes
hashed. `lib/eip712.py` and `lib/secp256k1.py` are read from the directory APC_SIGLIB names (non-empty) or from the
default: a sibling checkout ../x402-signature-vectors (tag v1.4.0), as regular files, hashed, and when both hashes are those of the tag THOSE bytes
are compiled and run as the modules `lib.eip712` and `lib.secp256k1` of a package `lib` that holds nothing else. No
import by name: the directory is never put on sys.path, so no `lib/__init__.py`, cached bytecode or other file of the
folder runs. Any other content: SiglibError (an ImportError) naming the path, the file and the hash found, and the two
ways to have the library; apc_verify.py turns it into one line on standard error and exit 64 (SPEC 32.11 (c)).

  import apc_siglib
  lib = apc_siglib.load()          # the package: lib.eip712, lib.secp256k1; afterwards `from lib.eip712 import ...` too
"""
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys

SIGLIB_TAG = "v1.4.0"
SIGLIB_SHA256 = {    # git show v1.4.0:lib/<file> of github.com/robertolocatelli81-dev/x402-signature-vectors (985b46d), 2026-11-02
    "lib/eip712.py": "8f1ae28568fdeab8713c3595631ab313ec9cc14bddc6772e0dd78946b804e608",
    "lib/secp256k1.py": "7e10ceb85840d1049dc2fbdef4c03e14a5af9a29c78eba54d4393695402a1f69",
}
NAMES = ("lib", "lib.eip712", "lib.secp256k1")
GET_LIB = ("clone github.com/robertolocatelli81-dev/x402-signature-vectors at tag %s beside this folder as "
           "../x402-signature-vectors, or set APC_SIGLIB to such a checkout" % SIGLIB_TAG)
MARK = "__apc_siglib_sha256__"


# a quote, a backslash with the character after it, or a bracket: what the count reads, one at a time. Not one pattern
# for a whole string: the regex engine keeps its state for every escape of a string it matches at once (measured
# 2026-11-24: 114 to 144 bytes each on CPython 3.9 to 3.14; a 63 MiB text of escaped quotes ended in MemoryError)
_TOKEN = re.compile(r'[\[\]{}"]|\\.')        # a line end after a backslash is no token either way


def json_too_deep(text, limit):
    """True when the arrays and objects of a JSON text (str, or bytes decoded as json.loads decodes them) open more than
    `limit` deep, counted on the text outside strings before any parser (SPEC 29.1). json.loads raises RecursionError at
    a depth that depends on the interpreter and its stack (994 on CPython 3.9 and 3.11, 9,998 on 3.13, and 100,000 was
    read on the 3.14 of the CI run 45334985210), so every reader bounds the text with this count first: the same answer
    on every Python. Here, not in apc_verify, because this module runs nothing at import (apc_registry reads registers
    without the library). Not a validator: a text within the bound that is not JSON is the parser's to refuse; one
    past the bound is refused as too deep whether or not it is JSON (SPEC 29.1)."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode(json.detect_encoding(text), "surrogatepass")
    depth, in_str = 0, False
    for m in _TOKEN.finditer(text):
        c = m.group()
        if in_str:                      # inside a string only its closing quote counts (an escaped one is a pair)
            in_str = c != '"'
            continue
        if len(c) == 2:                 # outside a string a backslash escapes nothing: the character after it counts
            c = c[1]
        if c == '"':
            in_str = True
        elif c == "[" or c == "{":
            depth += 1
            if depth > limit:
                return True
        elif c == "]" or c == "}":
            depth -= 1
    return False


MAX_INT_DIGITS = 4300       # SPEC 32.17 (0.21.8): CPython's default int_max_str_digits, the same answer on every Python
READ_CHUNK = 1 << 20


def json_int(s):
    """parse_int of every JSON reader (SPEC 32.17): an integer of more than 4300 digits is a ValueError named so. json.loads
    read one whole on Python 3.9 before 3.9.14 and failed with the interpreter's own message after; here the bound is
    counted on the text, on every Python."""
    if len(s) - (s[:1] == "-") > MAX_INT_DIGITS:
        raise ValueError("an integer of more than %d digits" % MAX_INT_DIGITS)
    return int(s)


def read_bounded(fh, limit):
    """At most limit + 1 bytes of a binary file object, read in pieces of at most READ_CHUNK (SPEC 32.17): a read(limit + 1)
    asks the allocator for limit + 1 bytes before it reads one, so a 1-byte file failed with MemoryError under a data
    limit below the bound (measured 2026-11-26: read(64 MiB + 1) under `ulimit -d 60000`)."""
    out = bytearray()
    while len(out) <= limit:
        b = fh.read(min(READ_CHUNK, limit + 1 - len(out)))
        if not b:
            break
        out += b
    return bytes(out)


def nameable(s):
    """A name a message repeats (SPEC 32.17): one longer than 32 characters could be a key put there by mistake and is not
    repeated; its length is."""
    return repr(s) if isinstance(s, str) and len(s) <= 32 else "(a name of %d characters, not repeated)" % len(s) \
        if isinstance(s, str) else "(a name not repeated)"


def bare_name(s):
    """nameable() without quotes, for the reasons that repeat a name bare: a name of at most 32 characters byte for byte."""
    return s if isinstance(s, str) and len(s) <= 32 else nameable(s)


def crlf_note(data, want):
    """Why the bytes differ when they are the expected file with its LF line ends turned into CRLF (a checkout made with
    git core.autocrlf=true, the default of Git for Windows): said in the refusal, so the user knows the fix."""
    if data and b"\r\n" in data and hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest() == want:
        return ("; it is the tag's file with CRLF line ends: the checkout converted them (git core.autocrlf); check it out "
                "again with `git -c core.autocrlf=false clone`")
    return ""


class SiglibError(ImportError):
    """SPEC 32.12 (f): the signature library is absent, not that of tag v1.4.0, or a module of its name was loaded from
    another place: there is no verifier (apc_verify.py: one line on standard error, exit 64)."""


def siglib_dir():
    """The directory tried: APC_SIGLIB when set to a non-empty value (an empty value counts as unset), else the default."""
    return os.environ.get("APC_SIGLIB") or os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "x402-signature-vectors")


def read_regular(path):
    """The bytes of a regular file, or None (absent, unreadable, a directory, a FIFO or a device; opened without blocking,
    so that a FIFO in the folder cannot stall the verifier). SPEC 32.12 (e) and (f)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = None
            return read_bounded(fh, 1 << 22)    # SPEC 32.17: 4 MiB, past any file of the tag; longer is another hash
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _ours(name):
    """The module of that name in sys.modules when it is one this loader made, else None."""
    m = sys.modules.get(name)
    return m if m is not None and getattr(m, MARK, None) is not None else None


def load():
    """The package `lib` with the two modules run from the hashed bytes (SPEC 32.12 (f)); a second call returns the same
    modules. SiglibError otherwise: absent, other bytes, or a module of one of the three names loaded from another place."""
    if all(_ours(n) is not None for n in NAMES):
        return sys.modules["lib"]
    d = siglib_dir()
    for name in NAMES:
        m = sys.modules.get(name)
        if m is not None and getattr(m, MARK, None) is None:
            raise SiglibError("the signature library of x402-signature-vectors cannot be loaded from %s: a module %s was "
                              "already loaded from another place (%s) (SPEC 32.12; no report, exit 64)"
                              % (d, name, getattr(m, "__file__", None)))
    src, found = {}, {}
    for rel, want in SIGLIB_SHA256.items():
        data = read_regular(os.path.join(d, *rel.split("/")))
        src[rel] = data
        found[rel] = None if data is None else hashlib.sha256(data).hexdigest()
    if all(v is None for v in found.values()):
        raise SiglibError("the signature library of x402-signature-vectors (lib/eip712.py, lib/secp256k1.py, tag %s) is "
                          "not at %s: %s (SPEC 32.11; no report, exit 64)" % (SIGLIB_TAG, d, GET_LIB))
    if found != SIGLIB_SHA256:
        bad = ", ".join("%s sha256 %s (expected %s%s)" % (rel, found[rel] or "absent", SIGLIB_SHA256[rel],
                                                          crlf_note(src[rel], SIGLIB_SHA256[rel]))
                        for rel in SIGLIB_SHA256 if found[rel] != SIGLIB_SHA256[rel])
        raise SiglibError("the signature library at %s is not that of x402-signature-vectors tag %s: %s: %s "
                          "(SPEC 32.12; no report, exit 64)" % (d, SIGLIB_TAG, bad, GET_LIB))
    pkg = importlib.util.module_from_spec(importlib.util.spec_from_loader("lib", loader=None, is_package=True))
    pkg.__path__ = []                  # a package that holds nothing but the two modules below: `import lib.other` fails
    setattr(pkg, MARK, dict(SIGLIB_SHA256))
    made = {"lib": pkg}
    for rel, name in (("lib/eip712.py", "lib.eip712"), ("lib/secp256k1.py", "lib.secp256k1")):
        path = os.path.join(d, *rel.split("/"))
        m = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None, origin=path))
        m.__file__ = path
        setattr(m, MARK, SIGLIB_SHA256[rel])
        made[name] = m
    saved = {n: sys.modules.get(n) for n in NAMES}
    try:
        sys.modules.update(made)
        for rel, name in (("lib/eip712.py", "lib.eip712"), ("lib/secp256k1.py", "lib.secp256k1")):
            exec(compile(src[rel], made[name].__file__, "exec", dont_inherit=True), made[name].__dict__)
            setattr(pkg, name.split(".")[1], made[name])
    except BaseException:
        for n, m in saved.items():     # the load failed half-way: sys.modules as it was found
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m
        raise
    return pkg


def guard(program, as_program):
    """load() for the other programs of the verifier (apc_block, apc_ap2, apc_batch, apc_report, apc_mcp; SPEC 32.12 (f)):
    `as_program` is `__name__ == "__main__"` of the caller. Without the library, as the program run: one line
    `<program>: <sentence>` on standard error and exit 64, never a traceback's 1 (apc_batch reads 1 as a failure); standard
    error closed or full, the line is lost and the exit stays 64 (32.12 (g)). Imported as a module: a SiglibError (an
    ImportError) with the same sentence. Any other failure is raised as it is. The same guard as apc_verify.py's own."""
    try:
        return load()
    except SiglibError as e:
        why = program + ": " + str(e)
        if not as_program:
            raise SiglibError(why) from e
        try:
            sys.stderr.write(why + "\n")      # standard error is line-buffered (Python >= 3.9): the write flushes
        except (OSError, AttributeError, ValueError):
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
            except OSError:
                pass
        sys.exit(64)
