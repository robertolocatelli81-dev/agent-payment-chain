"""Crash-safe journal of a bench: every outcome is one hash-chained line, written and fsync'ed before the next step,
so that a machine stop loses at most the step in progress and a resumed bench redoes only what is not recorded.

Line format (closed: any other member, a missing member or a wrong type is a refusal):
  {"seq": int, "prev": hex64, "kind": str, "body": object, "hash": hex64}
hash = sha256 of the canonical JSON (sort_keys, separators (",", ":"), ensure_ascii) of the line without "hash";
prev = hash of the line before, 64 zeros for seq 0. Line 0 has kind "open" and body = the binding: what the outcomes
are about (digest of the frozen tree, of the inputs outside it, the tool and its arguments). A journal is resumed only
under the same binding.

A stop during a write can leave a last line without its newline: that tail is not a record (the writer had not
finished it), it is dropped and the drop is recorded as kind "torn_tail" with the sha256 of the dropped bytes. Any
other damage (a complete line that does not parse or does not chain) is a refusal, never repaired.

  python3 tools/bench_journal.py tree ROOT                 digest of a tree (the one the bench binds)
  python3 tools/bench_journal.py open JOURNAL ROOT [KEY=VALUE ...]
      create JOURNAL bound to the digest of ROOT and the KEY=VALUE pairs, or check that it is bound to them
  python3 tools/bench_journal.py job JOURNAL NAME LOG -- CMD...
      run CMD once (stdout+stderr to LOG) unless JOURNAL already records NAME; record rc and sha256 of LOG
"""
import hashlib
import json
import os
import subprocess
import sys

ZERO = "0" * 64
KEYS = {"seq", "prev", "kind", "body", "hash"}
SKIP_DIRS = {".git", "__pycache__"}


class JournalError(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(root):
    """sha256 over the sorted (relative path, sha256 of the bytes) of every file under ROOT, .git and __pycache__
    left out. A symbolic link (to a file or a directory) enters as (path, "link:" + its target as written): the link
    is bound, what it points to is not (a venv's bin/python3, for one, points outside the tree)."""
    if not os.path.isdir(root):
        raise JournalError("%s is not a directory" % root)
    items = []
    for d, dirs, files in os.walk(root, onerror=lambda e: (_ for _ in ()).throw(e)):
        links = [x for x in dirs if os.path.islink(os.path.join(d, x))]     # os.walk does not descend into them
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for f in files + links:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            items.append([rel, "link:" + os.readlink(p)] if os.path.islink(p) else [rel, file_sha256(p)])
    return hashlib.sha256(canonical(sorted(items))).hexdigest()


def _is_hex64(x):
    return isinstance(x, str) and len(x) == 64 and all(c in "0123456789abcdef" for c in x)


def _check(line, seq, prev):
    if not isinstance(line, dict) or set(line) != KEYS:
        raise JournalError("line %d: members %s, expected %s" % (seq, sorted(line) if isinstance(line, dict)
                                                                    else type(line).__name__, sorted(KEYS)))
    if type(line["seq"]) is not int or line["seq"] != seq:
        raise JournalError("line %d: seq %r" % (seq, line["seq"]))
    if not _is_hex64(line["prev"]) or line["prev"] != prev:
        raise JournalError("line %d: prev does not chain" % seq)
    if not isinstance(line["kind"], str) or not line["kind"] or not isinstance(line["body"], dict):
        raise JournalError("line %d: kind must be a non-empty string and body an object" % seq)
    want = hashlib.sha256(canonical({k: line[k] for k in KEYS - {"hash"}})).hexdigest()
    if line["hash"] != want:
        raise JournalError("line %d: hash does not match its content" % seq)


def read(path):
    """(records, torn) of a journal file; torn = the bytes after the last newline (b"" when the file ends clean).
    Raises JournalError on any damage that is not a torn tail."""
    with open(path, "rb") as fh:
        raw = fh.read()
    cut = raw.rfind(b"\n") + 1
    body, torn = raw[:cut], raw[cut:]
    recs, prev = [], ZERO
    for seq, b in enumerate(body.split(b"\n")[:-1]):
        try:
            line = json.loads(b.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            raise JournalError("line %d: not JSON (%s)" % (seq, type(e).__name__))
        if b != canonical(line):
            raise JournalError("line %d: not in canonical form" % seq)
        _check(line, seq, prev)
        recs.append(line)
        prev = line["hash"]
    if recs and recs[0]["kind"] != "open":
        raise JournalError("line 0: kind %r, expected 'open'" % recs[0]["kind"])
    if any(r["kind"] == "open" for r in recs[1:]):
        raise JournalError("a second 'open' line")
    return recs, torn


class Journal:
    def __init__(self, path, binding):
        if not isinstance(binding, dict):
            raise JournalError("binding must be an object")
        self.path = path
        self.records = []
        if os.path.exists(path):
            recs, torn = read(path)
            if recs and recs[0]["body"] != binding:
                raise JournalError("journal %s belongs to another binding (tree, inputs or arguments changed)" % path)
            self.records = recs
            if torn:
                with open(path, "r+b") as fh:
                    fh.truncate(os.path.getsize(path) - len(torn))
                    fh.flush()
                    os.fsync(fh.fileno())
                if not recs:
                    self.append("open", binding)
                self.append("torn_tail", {"bytes": len(torn), "sha256": hashlib.sha256(torn).hexdigest()})
        if not self.records:
            self.append("open", binding)

    def append(self, kind, body):
        seq = len(self.records)
        line = {"seq": seq, "prev": self.records[-1]["hash"] if self.records else ZERO, "kind": kind, "body": body}
        line["hash"] = hashlib.sha256(canonical(line)).hexdigest()
        new = not os.path.exists(self.path)
        with open(self.path, "ab") as fh:
            fh.write(canonical(line) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        if new:                                    # the directory entry of a new file must reach the disk too
            fd = os.open(os.path.dirname(os.path.abspath(self.path)), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.records.append(line)
        return line

    def done(self, kind):
        """{name: body} of the records of KIND (body["name"]); a name recorded twice is a refusal."""
        out = {}
        for r in self.records:
            if r["kind"] == kind:
                n = r["body"].get("name")
                if not isinstance(n, str) or n in out:
                    raise JournalError("%s record without a name or recorded twice: %r" % (kind, n))
                out[n] = r["body"]
        return out


def job(journal_path, name, log, cmd):
    if not os.path.isfile(journal_path):
        raise JournalError("%s does not exist: open it first, bound to the tree" % journal_path)
    recs, _ = read(journal_path)
    if not recs:
        raise JournalError("%s has no complete 'open' line" % journal_path)
    if os.path.dirname(os.path.abspath(log)) != os.path.dirname(os.path.abspath(journal_path)):
        raise JournalError("the log must be in the folder of the journal (the certificate finds it there)")
    j = Journal(journal_path, recs[0]["body"])
    prior = j.done("job").get(name)
    if prior is not None:
        if not os.path.exists(log) or file_sha256(log) != prior["log_sha256"]:
            raise JournalError("job %s is recorded but its log is missing or changed" % name)
        print("%s: recorded rc %d (journal line kept, not run again)" % (name, prior["rc"]))
        return prior["rc"]
    with open(log, "wb") as fh:
        rc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode
        fh.flush()
        os.fsync(fh.fileno())
    j.append("job", {"name": name, "rc": rc, "log": os.path.basename(log), "log_sha256": file_sha256(log), "cmd": cmd})
    return rc


def main(argv):
    try:
        if len(argv) == 3 and argv[1] == "tree":
            print(tree_digest(argv[2]))
            return 0
        if len(argv) >= 4 and argv[1] == "open":
            extra = dict(a.split("=", 1) for a in argv[4:] if "=" in a)
            if len(extra) != len(argv) - 4 or {"tool", "tree"} & set(extra):
                raise JournalError("arguments after ROOT must be distinct KEY=VALUE, keys other than tool and tree")
            Journal(argv[2], dict(extra, tool="bench", tree=tree_digest(argv[3])))
            return 0
        if len(argv) >= 7 and argv[1] == "job" and argv[5] == "--":
            return job(argv[2], argv[3], argv[4], argv[6:])
    except JournalError as e:
        print("JOURNAL REFUSED:", e)
        return 3
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
