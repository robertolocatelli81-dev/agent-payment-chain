"""The real corpus is not distributed with the public tree (SPEC section 33): bundles/ holds the fascicles of real
payments, oracle/ the raw RPC replies they were built from. A test that reads them calls `need(...)` at import: when a
named set or raw directory is missing, the whole module is SKIPPED with the reason and the command that rebuilds the
set (never passed in silence on an empty glob). With the corpus present nothing changes. `unittest discover` and
tools/run_ordered.py report such a module as skipped; `python3 -m unittest tests.<name>` alone stops at the SkipTest
message (unittest loads the first module by name before tests/__init__.py can teach its loader), exit 1 with the reason."""
import glob
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REBUILD = "python3 tools/rebuild_corpus.py --only %s --rpc <network>=<your endpoint>"


_MAN = []


def manifest():
    """The list corpus/MANIFEST.json through the closed reader of tools/rebuild_corpus.py, or None when it cannot be read
    (the list is the tests' object elsewhere; here it only names sets, levels and the oracle directories)."""
    if not _MAN:
        try:
            import sys
            sys.path.insert(0, os.path.join(ROOT, "tools"))
            import rebuild_corpus as rc
            _MAN.append(rc.load_manifest())
        except Exception:            # noqa: BLE001
            _MAN.append(None)
    return _MAN[0]


def sets_listed():
    """`need("*")`: every set the list names that is NOT local_only (33.8); a test that reads a local_only set names it."""
    m = manifest()
    if m is None:
        b = os.path.join(ROOT, "bundles")
        return sorted(os.listdir(b)) if os.path.isdir(b) else []
    return sorted(n for n, s in m["sets"].items() if s["rebuild"] != "local_only")


def _local_only():
    """{set: reason} of the sets the list declares local_only (tools/rebuild_corpus.py does not rebuild them)."""
    m = manifest()
    return {} if m is None else {n: s["reason"] for n, s in m["sets"].items() if s["rebuild"] == "local_only"}


def _oracle_listed():
    """{oracle dir or glob: (kind, reason)} as the list declares them (33.8)."""
    m = manifest()
    return {} if m is None else {n: (o["kind"], o.get("reason", "")) for n, o in m["oracle"].items()}


def _pretend_missing():
    """APC_CORPUS_PRETEND_MISSING=set1,set2,oracle/dir: the positive control of this discipline (the module must skip)."""
    return set(filter(None, os.environ.get("APC_CORPUS_PRETEND_MISSING", "").split(",")))


def has_set(name):
    if name in _pretend_missing():
        return False
    d = os.path.join(ROOT, "bundles", name)
    return os.path.isdir(d) and any(f != "MANIFEST.json" for f in glob.glob(os.path.join(d, "**", "*.json"), recursive=True))


def has_oracle(rel):
    if "oracle/" + rel in _pretend_missing():
        return False
    return bool(glob.glob(os.path.join(ROOT, "oracle", rel)))


def missing(sets=(), oracle=()):
    names = []
    for s in sets:
        names.extend(sets_listed() if s == "*" else [s])
    out = ["bundles/%s" % s for s in names if not has_set(s)]
    out += ["oracle/%s" % o for o in oracle if not has_oracle(o)]
    return out, [s for s in names if not has_set(s)]


def unless(*sets, oracle=()):
    """A class/test decorator: skip with the same message as need() when a set or raw directory is missing (for a test
    that reads a local_only set inside a module that otherwise loads on the public tree)."""
    try:
        need(*sets, oracle=oracle)
    except unittest.SkipTest as e:
        return unittest.skip(str(e))
    return lambda obj: obj


def need(*sets, oracle=(), files=()):
    """Raise unittest.SkipTest naming what is missing and how to rebuild it; return silently when all is there."""
    gone, gone_sets = missing(sets, oracle)
    gone += [f for f in files if not os.path.isfile(os.path.join(ROOT, f))]
    if not gone:
        return
    parts = ["real corpus not present: " + ", ".join(gone),
             "(not distributed with the public tree; SPEC section 33)"]
    local = _local_only()
    rebuildable = [s for s in gone_sets if s not in local]
    if rebuildable:
        parts.append("rebuild: " + REBUILD % ",".join(rebuildable))
    for s in gone_sets:
        if s in local:
            parts.append("%s is local_only in the list: not rebuilt by this version (%s)" % (s, local[s]))
    if any(g.startswith(("tests/data/", "sources/")) for g in gone):
        parts.append("files that carry the accounts of real payments (reference vectors signed on the real parties, saved RPC and service replies) are kept with the corpus, not published")
    listed = _oracle_listed()
    for g in gone:
        if not g.startswith("oracle/"):
            continue
        kind, reason = listed.get(g[7:], (None, ""))
        if kind in ("evm_blocks", "xrpl_ledgers"):
            parts.append("rebuild raw replies: python3 tools/rebuild_corpus.py --oracle %s --rpc <network>=<your endpoint>" % g[7:])
        elif kind == "local_only":
            parts.append("%s is local_only in the list: not rebuilt by this version (%s)" % (g, reason))
        else:
            parts.append("%s is not in the list: raw replies of the authors, not rebuilt" % g)
    raise unittest.SkipTest(" ".join(parts))
