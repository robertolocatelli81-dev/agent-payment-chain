"""Fetch the pinned Natural Earth admin-1 (states, provinces) boundaries and convert them to the line file that
apc_registry.py reads with --admin (SPEC section 11).

  python3 tools/fetch_admin_boundaries.py OUT_DIR [--geojson LOCAL_FILE]

Downloads `geojson/ne_10m_admin_1_states_provinces.geojson` of nvkelso/natural-earth-vector at the commit of tag
v5.1.2 (or reads LOCAL_FILE), refuses it unless its SHA-256 is PIN_SHA256 (measured 2026-10-26; its git blob id
matched the one GitHub lists for that path at that tag), and writes OUT_DIR/admin1-ne-<release>.apc-adm: line 1 the
canonical JSON header, then one line per area

  min_lon SP min_lat SP max_lon SP max_lat TAB adm1_code TAB {"iso_3166_2", "name", "region", "country", "polygons"}

name null when Natural Earth gives none; iso_3166_2 only when Natural Earth's value has the ISO 3166-2 form (Natural Earth also writes its own placeholders,
such as "SY-X01~", and some duplicates): else null; country is iso_a2 when it is two letters, else null; coordinates
unchanged. Deterministic: the same input gives the same file, whose SHA-256 is pinned too (PIN_FILE_SHA256).
Natural Earth is public domain; it is a cartographic dataset (de facto boundaries, Natural Earth's own point of view),
not a legal source. It is not put in this repository.
Exit 0 done, 1 a digest that is not the pinned one, 3 input not readable or not the expected GeoJSON, 64 usage.
"""
import hashlib
import json
import os
import re
import sys
import urllib.request

PIN_RELEASE = "v5.1.2"
PIN_COMMIT = "f1890d9f152c896d250a77557a5751a93d494776"
PIN_ASSET = "ne_10m_admin_1_states_provinces.geojson"
PIN_URL = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/%s/geojson/%s" % (PIN_COMMIT, PIN_ASSET)
PIN_SHA256 = "22d0e3ad85eb3e27f17cabf8ba2d50e554fbc27a87796ff891d958185da62fb5"
PIN_FILE_SHA256 = "3a4a329d5d023d3e86f463e4bdc590148929ef63ec4da0e3ab5406a91653a629"   # measured 2026-10-26, 2 conversions
ISO2 = re.compile(r"[A-Z]{2}-[A-Z0-9]{1,3}\Z")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def header(n):
    return json.dumps({"apc_admin_boundaries": 1, "release": PIN_RELEASE, "source_asset": PIN_ASSET,
                       "source_sha256": PIN_SHA256, "areas": n}, sort_keys=True, separators=(",", ":"))


def _text(v, n):
    return v if isinstance(v, str) and v and len(v) <= n and not re.search(r"[\x00-\x1f\x7f]", v) else None


def convert(src, out_path):
    with open(src, "rb") as fh:
        doc = json.loads(fh.read())
    if not isinstance(doc, dict) or doc.get("type") != "FeatureCollection":
        raise ValueError("not a GeoJSON FeatureCollection")
    lines = []
    for f in doc["features"]:
        p, g = f["properties"], f["geometry"]
        code = p["adm1_code"]
        polys = [g["coordinates"]] if g["type"] == "Polygon" else g["coordinates"] if g["type"] == "MultiPolygon" \
            else None
        if polys is None or not isinstance(code, str) or not re.fullmatch(r"[A-Z0-9]{3}[-+][0-9]{1,5}\??", code):
            raise ValueError("feature %r: not a Polygon or MultiPolygon with an adm1_code" % (code,))
        name = _text(p.get("name"), 128)            # null for a few areas (e.g. ATA+99?)
        iso = p.get("iso_3166_2")
        payload = {"iso_3166_2": iso if isinstance(iso, str) and ISO2.match(iso) else None, "name": name,
                   "region": _text(p.get("region"), 128),
                   "country": p["iso_a2"] if isinstance(p.get("iso_a2"), str) and re.fullmatch(r"[A-Z]{2}",
                                                                                               p["iso_a2"]) else None,
                   "polygons": polys}
        xs = [q[0] for poly in polys for ring in poly for q in ring]
        ys = [q[1] for poly in polys for ring in poly for q in ring]
        lines.append("%r %r %r %r\t%s\t%s\n" % (min(xs), min(ys), max(xs), max(ys), code,
                                                 json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                                            ensure_ascii=False)))
    lines.sort(key=lambda s: s.split("\t")[1])
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header(len(lines)) + "\n")
        fh.writelines(lines)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, out_path)


def main(argv):
    args = argv[1:]
    local = None
    if "--geojson" in args:
        i = args.index("--geojson")
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
        src = local or os.path.join(out_dir, PIN_ASSET)
        if local is None and not os.path.exists(src):
            urllib.request.urlretrieve(PIN_URL, src + ".part")
            os.replace(src + ".part", src)
        got = sha256_file(src)
        if got != PIN_SHA256:
            print(json.dumps({"error": "sha256 %s is not the pinned %s" % (got, PIN_SHA256)}))
            return 1
        out = os.path.join(out_dir, "admin1-ne-%s.apc-adm" % PIN_RELEASE)
        convert(src, out)
        fsha = sha256_file(out)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as e:
        print(json.dumps({"error": "%s: %s" % (type(e).__name__, e)}))
        return 3
    print(json.dumps({"file": out, "sha256": fsha, "pinned": fsha == PIN_FILE_SHA256, "release": PIN_RELEASE},
                     indent=1))
    return 0 if fsha == PIN_FILE_SHA256 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
