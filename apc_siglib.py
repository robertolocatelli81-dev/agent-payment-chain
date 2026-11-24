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


# a JSON string (to its closing quote, or to the end of an unterminated one) or one bracket outside strings
_STRING_OR_BRACKET = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]', re.S)


def json_too_deep(text, limit):
    """True when the arrays and objects of a JSON text (str, or bytes decoded as json.loads decodes them) open more than
    `limit` deep, counted on the text outside strings before any parser (SPEC 29.1). json.loads raises RecursionError at
    a depth that depends on the interpreter and its stack (994 on CPython 3.9 and 3.11, 9,998 on 3.13, and 100,000 was
    read on the 3.14 of the CI run 45334985210), so every reader bounds the text with this count first: the same answer
    on every Python. Here, not in apc_verify, because this module runs nothing at import (apc_registry reads registers
    without the library). Not a validator: a text that is not JSON is the parser's to refuse."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode(json.detect_encoding(text), "surrogatepass")
    depth = 0
    for m in _STRING_OR_BRACKET.finditer(text):
        c = m.group()
        if c == "[" or c == "{":
            depth += 1
            if depth > limit:
                return True
        elif c == "]" or c == "}":
            depth -= 1
    return False


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
            return fh.read()
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
