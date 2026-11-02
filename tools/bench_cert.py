"""Certificate of a mutation bench run with APC_MUT_JOURNAL (tools/mutants03.py, tools/bench_journal.py).

  python3 tools/bench_cert.py ROOT JOURNAL... [--jobs JOBS_JOURNAL NAME,NAME,...] [--out CERT.json]

The certificate is issued only when the journals prove a COMPLETE bench of the tree ROOT as it is now:
- every journal chains (bench_journal.read) and ends clean (a torn tail = a run that did not finish);
- every journal is bound to tree_digest(ROOT) and to the same arguments and inputs; their shards i/n are 0..n-1, once;
- the expected set is recomputed here from the mutant list M of ROOT/tools/mutants03.py, with the same selection as
  the driver (APC_MUT_FIRST order, APC_MUT_SET part, name substring, shard), not read from the journals;
- each journal has one control line with rc 0 and exactly one verdict for each mutant of its shard, nothing else
  (a line of another kind, a name outside the shard, a missing name: refusal);
- every line carries its evidence and the evidence is checked against the tree: the sha256 of the mutated file is
  recomputed from ROOT, a STALE count is recounted, the verdict must follow from the exit code and the stderr
  (killed = rc 1 and a "FAIL:"/"ERROR:" line naming the test, SURVIVED = rc 0, anything else INVALID);
- with --jobs, the job journal is bound to the same tree, records each NAME once and its log (next to the journal)
  is unchanged; a job with rc not 0 is listed.
A torn tail dropped and recorded during a resumed run ("torn_tail" line) is allowed and counted in the certificate.
Exit 0: certificate, every mutant killed. Exit 1: certificate, some mutant not killed (listed). Exit 2: no
certificate, the reason is printed.
"""
import collections
import hashlib
import importlib.util
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_journal as bj  # noqa: E402

KINDS = {"open", "control", "mutant", "torn_tail"}
EVIDENCE = {"rc", "stderr_sha256", "stderr_excerpt", "seconds", "utc"}
CONTROL = EVIDENCE | {"name"}
RUN = EVIDENCE | {"name", "verdict", "failed_test", "mutated_sha256"}
STALE = {"name", "verdict", "count"}
FAILED_TEST = re.compile(r"^(?:FAIL|ERROR): \S+ \(.+\)$", re.M)
UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


class Refused(Exception):
    pass


def expected(root, b):
    spec = importlib.util.spec_from_file_location("m03_cert", os.path.join(root, "tools", "mutants03.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    first = set(b["first"])
    chosen = [x for x in sorted(m.M, key=lambda x: x[1] not in first)
              if not b["part"] or (x[1] in first) == (b["part"] == "first")]
    names = [x[1] for x in chosen]
    if len(set(names)) != len(names):
        raise Refused("two mutants share a name in tools/mutants03.py")
    n = b["shard"][1]
    out = collections.defaultdict(list)
    for k, name in enumerate(names):
        if b["only"] in name:
            out[k % n].append(name)
    return out, {x[1]: x for x in chosen}


def check_evidence(p, body, keys):
    """the closed member set and the types of a control or mutant line (the excerpt cannot be checked against the
    recorded sha256 of the whole stderr, which is not kept)"""
    if set(body) != keys:
        raise Refused("%s: line of %r has members %s, expected %s" % (p, body.get("name"), sorted(body), sorted(keys)))
    if type(body["rc"]) is not int or not isinstance(body["stderr_excerpt"], str) or len(body["stderr_excerpt"]) > 2000 \
            or not bj._is_hex64(body["stderr_sha256"]) or type(body["seconds"]) not in (int, float) \
            or not body["seconds"] >= 0 or not isinstance(body["utc"], str) or not UTC.match(body["utc"]):
        raise Refused("%s: evidence of %s has wrong types or values" % (p, body.get("name")))


def check_mutant(p, root, body, m):
    f, name, old, new = m
    with open(os.path.join(root, f)) as fh:
        src = fh.read()
    if body.get("verdict", "").startswith("STALE"):
        if set(body) != STALE or type(body["count"]) is not int or body["count"] != src.count(old) \
                or body["count"] == 1 or body["verdict"] != "STALE(%d)" % body["count"]:
            raise Refused("%s: %s recorded %r, the tree has the pattern %d times" % (p, name, body, src.count(old)))
        return
    check_evidence(p, body, RUN)
    if src.count(old) != 1:
        raise Refused("%s: %s was run, but its pattern is %d times in the tree" % (p, name, src.count(old)))
    if body["mutated_sha256"] != hashlib.sha256(src.replace(old, new).encode()).hexdigest():
        raise Refused("%s: %s: the mutated file recorded is not the mutant of this tree" % (p, name))
    rc, m = body["rc"], FAILED_TEST.match(body["stderr_excerpt"])
    if rc == 0:
        want = ("SURVIVED", "")
    elif rc == 1 and m:
        want = ("killed", m.group(0))
    else:
        want = ("INVALID(%d)" % rc, "")
    if (body["verdict"], body["failed_test"]) != want:
        raise Refused("%s: %s recorded %r with rc %d; its evidence gives %r" % (
            p, name, (body["verdict"], body["failed_test"]), rc, want))


def certify(root, journals, jobs=None, job_names=()):
    tree = bj.tree_digest(root)
    heads, binds, shards = [], [], {}
    for p in journals:
        recs, torn = bj.read(p)
        if torn:
            raise Refused("%s ends with a torn line: that run did not finish (resume it)" % p)
        if not recs:
            raise Refused("%s is empty" % p)
        b = recs[0]["body"]
        if b.get("tool") != "mutants03" or b.get("tree") != tree:
            raise Refused("%s is not a mutants03 journal of this tree (tree now %s)" % (p, tree))
        sh = b.get("shard")
        if not (isinstance(sh, list) and len(sh) == 2 and all(type(x) is int for x in sh)):
            raise Refused("%s: shard %r" % (p, sh))
        if sh[0] in shards:
            raise Refused("shard %d/%d twice (%s, %s)" % (sh[0], sh[1], shards[sh[0]], p))
        shards[sh[0]] = p
        binds.append(dict(b, shard=sh[1]))
        heads.append((p, recs))
    if not binds or any(x != binds[0] for x in binds):
        raise Refused("the journals are not bound to the same arguments and inputs")
    n = binds[0]["shard"]
    if sorted(shards) != list(range(n)):
        raise Refused("shards %s of %d: missing %s" % (sorted(shards), n, sorted(set(range(n)) - set(shards))))
    want, mutants = expected(root, dict(binds[0], shard=[0, n]))
    verdicts, entries = {}, []
    for p, recs in heads:
        i = recs[0]["body"]["shard"][0]
        other = sorted({r["kind"] for r in recs} - KINDS)
        if other:
            raise Refused("%s: lines of unknown kind %s" % (p, other))
        control = [r["body"] for r in recs if r["kind"] == "control"]
        if len(control) != 1 or control[0].get("rc") != 0 or control[0].get("name") != "control":
            raise Refused("%s: %d control lines, expected one with rc 0" % (p, len(control)))
        check_evidence(p, control[0], CONTROL)
        got = {}
        for r in recs:
            if r["kind"] == "mutant":
                body = r["body"]
                if not isinstance(body.get("name"), str) or not isinstance(body.get("verdict"), str):
                    raise Refused("%s line %d: mutant line without name or verdict" % (p, r["seq"]))
                if body["name"] not in mutants:
                    raise Refused("%s: %s is not of this shard" % (p, body["name"]))
                check_mutant(p, root, body, mutants[body["name"]])
                if body["name"] in got:
                    raise Refused("%s: %s recorded twice" % (p, body["name"]))
                got[body["name"]] = body["verdict"]
        if set(got) != set(want[i]):
            raise Refused("%s (shard %d/%d): missing %s, not of this shard %s" % (
                p, i, n, sorted(set(want[i]) - set(got)), sorted(set(got) - set(want[i]))))
        verdicts.update(got)
        entries.append({"journal": os.path.basename(p), "shard": i, "lines": len(recs), "head": recs[-1]["hash"],
                        "sha256": bj.file_sha256(p), "torn_tails": sum(r["kind"] == "torn_tail" for r in recs)})
    cert = {"format": "apc-bench-cert/1", "tree": tree, "binding": dict(binds[0], shard=n),
            "journals": sorted(entries, key=lambda e: e["shard"]), "mutants": len(verdicts),
            "verdicts": dict(collections.Counter(verdicts.values())),
            "not_killed": sorted(k for k, v in verdicts.items() if v != "killed")}
    if jobs:
        recs, torn = bj.read(jobs)
        if torn or not recs:
            raise Refused("%s: torn or empty" % jobs)
        b = recs[0]["body"]
        if b.get("tool") != "bench" or b.get("tree") != tree:
            raise Refused("%s is not a job journal of this tree" % jobs)
        if sorted({r["kind"] for r in recs} - {"open", "job", "torn_tail"}):
            raise Refused("%s: lines of another kind" % jobs)
        done = bj.Journal.__new__(bj.Journal)
        done.records = recs
        try:
            done = done.done("job")
        except bj.JournalError as e:
            raise Refused(str(e))
        if set(done) != set(job_names):
            raise Refused("jobs: missing %s, unexpected %s" % (sorted(set(job_names) - set(done)),
                                                               sorted(set(done) - set(job_names))))
        bad = [k for k, v in done.items() if v["rc"] != 0]
        for k, v in done.items():
            log = os.path.join(os.path.dirname(os.path.abspath(jobs)), v["log"])
            if not os.path.exists(log) or bj.file_sha256(log) != v["log_sha256"]:
                raise Refused("job %s: log %s missing or changed since it was recorded" % (k, log))
        cert["jobs"] = {"journal": os.path.basename(jobs), "head": recs[-1]["hash"], "sha256": bj.file_sha256(jobs),
                        "names": sorted(done), "rc_not_zero": sorted(bad)}
    cert["cert_sha256"] = hashlib.sha256(bj.canonical(cert)).hexdigest()
    return cert


def main(argv):
    args, jobs, names, out = list(argv[1:]), None, (), None
    if "--out" in args:
        k = args.index("--out")
        out = args[k + 1]
        del args[k:k + 2]
    if "--jobs" in args:
        k = args.index("--jobs")
        jobs, names = args[k + 1], tuple(x for x in args[k + 2].split(",") if x)
        del args[k:k + 3]
    if len(args) < 2 or any(a.startswith("--") for a in args):
        print(__doc__)
        return 2
    try:
        cert = certify(args[0], args[1:], jobs, names)
    except (Refused, bj.JournalError) as e:
        print("NO CERTIFICATE:", e)
        return 2
    text = bj.canonical(cert).decode() + "\n"
    if out:
        with open(out, "w") as fh:
            fh.write(text)
    print(text, end="")
    return 1 if cert["not_killed"] or (jobs and cert["jobs"]["rc_not_zero"]) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
