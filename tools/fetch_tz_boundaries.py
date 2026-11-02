"""Fetch the pinned time-zone boundary release and convert it to the line file apc_registry.py reads (SPEC section 11).

  python3 tools/fetch_tz_boundaries.py OUT_DIR [--zip LOCAL_ZIP]

Downloads `timezones-with-oceans.geojson.zip` of evansiroky/timezone-boundary-builder release PIN_RELEASE (or reads
LOCAL_ZIP), refuses it unless its SHA-256 is PIN_SHA256 (the digest GitHub publishes for that asset), and writes
OUT_DIR/tz-boundaries-<release>.apc-tzb: line 1 the canonical JSON header, then one line per zone

  min_lon SP min_lat SP max_lon SP max_lat TAB tzid TAB polygons-JSON

with the coordinates exactly as the GeoJSON carries them (Polygon and MultiPolygon both as a list of polygons, each a
list of rings, each a list of [lon, lat]). The conversion is deterministic: the same zip gives the same file, so its
SHA-256 is pinned too (PIN_FILE_SHA256) and apc_registry reports whether the file it read is the pinned one.
The data is ODbL-1.0 (timezone-boundary-builder's licence): it is not put in this repository.
The conversion holds the whole GeoJSON (185 MB) in memory once; the registry reads the line file without doing so.
Exit 0 done, 1 a digest that is not the pinned one, 3 input not readable or not the expected GeoJSON, 64 usage.
"""
import hashlib
import json
import os
import sys
import urllib.request
import zipfile

PIN_RELEASE = "2026e"
PIN_ASSET = "timezones-with-oceans.geojson.zip"
PIN_URL = ("https://github.com/evansiroky/timezone-boundary-builder/releases/download/%s/%s"
           % (PIN_RELEASE, PIN_ASSET))
PIN_SHA256 = "8eefcbc3df102dc3c174983b784bde82fec00fb4a596a1ed63e8f53a92043885"     # GitHub asset digest, 2026-10-26
PIN_MEMBER = "combined-with-oceans.json"
PIN_FILE_SHA256 = "3cfc18cd8a81027591c3a6175f3b6eaec17cdc3deed2d378eaaa09ffcd12e029"   # measured 2026-10-26


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def header(release, source_sha256, n):
    return json.dumps({"apc_tz_boundaries": 1, "release": release, "source_asset": PIN_ASSET,
                       "source_sha256": source_sha256, "zones": n}, sort_keys=True, separators=(",", ":"))


def convert(zpath, out_path):
    with zipfile.ZipFile(zpath) as z:
        if z.namelist() != [PIN_MEMBER]:
            raise ValueError("the zip does not hold exactly %s" % PIN_MEMBER)
        doc = json.loads(z.read(PIN_MEMBER))
    if not isinstance(doc, dict) or doc.get("type") != "FeatureCollection":
        raise ValueError("not a GeoJSON FeatureCollection")
    lines = []
    for f in doc["features"]:
        tzid, g = f["properties"]["tzid"], f["geometry"]
        polys = [g["coordinates"]] if g["type"] == "Polygon" else g["coordinates"] if g["type"] == "MultiPolygon" \
            else None
        if polys is None or not isinstance(tzid, str) or "\t" in tzid or "\n" in tzid:
            raise ValueError("feature %r: not a Polygon or MultiPolygon with a tzid" % (tzid,))
        xs = [p[0] for poly in polys for ring in poly for p in ring]
        ys = [p[1] for poly in polys for ring in poly for p in ring]
        lines.append("%r %r %r %r\t%s\t%s\n" % (min(xs), min(ys), max(xs), max(ys), tzid,
                                                 json.dumps(polys, separators=(",", ":"))))
    lines.sort(key=lambda s: s.split("\t")[1])
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header(PIN_RELEASE, PIN_SHA256, len(lines)) + "\n")
        fh.writelines(lines)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, out_path)


def main(argv):
    args = argv[1:]
    local = None
    if "--zip" in args:
        i = args.index("--zip")
        if i + 1 >= len(args):
            print(__doc__)
            return 64
        local = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1 or args[0].startswith("-"):
        print(__doc__)
        return 64
    out_dir = args[0]
    try:
        os.makedirs(out_dir, exist_ok=True)
        zpath = local or os.path.join(out_dir, PIN_ASSET)
        if local is None and not os.path.exists(zpath):
            urllib.request.urlretrieve(PIN_URL, zpath + ".part")
            os.replace(zpath + ".part", zpath)
        got = sha256_file(zpath)
        if got != PIN_SHA256:
            print(json.dumps({"error": "sha256 %s is not the pinned %s" % (got, PIN_SHA256)}))
            return 1
        out = os.path.join(out_dir, "tz-boundaries-%s.apc-tzb" % PIN_RELEASE)
        convert(zpath, out)
        fsha = sha256_file(out)
    except (OSError, ValueError, KeyError, TypeError, IndexError, zipfile.BadZipFile) as e:
        print(json.dumps({"error": "%s: %s" % (type(e).__name__, e)}))
        return 3
    print(json.dumps({"file": out, "sha256": fsha, "pinned": fsha == PIN_FILE_SHA256, "release": PIN_RELEASE},
                     indent=1))
    return 0 if fsha == PIN_FILE_SHA256 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
