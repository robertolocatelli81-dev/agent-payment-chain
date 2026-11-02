#!/usr/bin/env python3
"""Fetch the five NMEA captures of gpsd that tests/test_registry.py reads (sources/nmea_20261026), from the gpsd
repository at the pinned commit, and keep each only if its sha256 is the one of SHA256SUMS. They are not redistributed
with this tree: the file headers name the people who submitted them (gpsd regression data, BSD-2-Clause; the licence
text is LICENSES/gpsd-COPYING.txt). Standard library only; one request per file, no retries hidden.

  python3 tools/fetch_nmea_captures.py
"""
import hashlib
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR = os.path.join(ROOT, "sources", "nmea_20261026")
COMMIT = "e970bf8d61f0ec75ecbc93adb5ae783c8404892a"
URL = "https://gitlab.com/gpsd/gpsd/-/raw/%s/test/daemon/%s"


def main():
    with open(os.path.join(DIR, "SHA256SUMS")) as fh:
        want = dict(reversed(x.split()) for x in fh if x.strip())
    bad = 0
    for name, digest in sorted(want.items()):
        path = os.path.join(DIR, name)
        if os.path.isfile(path) and hashlib.sha256(open(path, "rb").read()).hexdigest() == digest:
            print(name, "present, sha256 ok")
            continue
        req = urllib.request.Request(URL % (COMMIT, name), headers={"User-Agent": "agent-payment-chain fetch_nmea_captures"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            print(name, "REFUSED: sha256", got, "is not the pinned", digest, file=sys.stderr)
            bad += 1
            continue
        with open(path, "wb") as fh:
            fh.write(data)
        print(name, "fetched, sha256 ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
