"""agent-payment-chain register of checks on an external device (SPEC section 11, SPEC 0.9.1, format apc-reg-0.2).
Python 3.9+ standard library only (zoneinfo; on 3.9 the tz rules come from the system's tzdata or the tzdata
package); `openssl` (the binary) only for the opt-in RFC 3161 time token. Licence: Apache-2.0, as the rest of the work
(the author's decision of 2026-11-02, replacing the open-core split of 2026-10-24).

The place is personal data: nothing is recorded until the user opens a register with `init` (SPEC 11.1). Nothing
leaves the machine unless the user names a time-stamping authority with --tsa: then only the SHA-256 of the entry.

  python3 apc_registry.py init REGISTER
  python3 apc_registry.py record REGISTER (--bundle BUNDLE.json [--l1-checkpoint HASH] [--http-keys KEYS.json]
                                [--report REPORT.json] | --report REPORT.json)
                                [--nmea FILE | --gps DEVICE [--baud N] [--seconds S] | --gpsd-json FILE |
                                 --gpsd PORT [--seconds S]] [--tzdb FILE] [--admin FILE] [--key SEED_FILE]
                                [--tsa URL [--tsa-ca CA.pem]]
  python3 apc_registry.py verify REGISTER [--public-key HEX] [--tsa-ca CA.pem]
  python3 apc_registry.py show REGISTER [--zones Europe/Rome,America/New_York,... | --zones all]

REGISTER is a file on the external device (a USB drive or an SD card path). With --bundle the register runs
apc_verify on the bundle itself (with --l1-checkpoint / --http-keys as apc_verify takes them) and records that report;
a --report given as well must be the same report, else nothing is recorded. --nmea / --gps read NMEA 0183 (a file or
a serial device at 9600 baud unless --baud, up to --seconds, default 5); --gpsd-json / --gpsd read gpsd JSON (a file,
or the gpsd daemon on 127.0.0.1:PORT only). --tzdb and --admin are the line files of tools/fetch_tz_boundaries.py and
tools/fetch_admin_boundaries.py. --key: a file holding one line, a 32-byte Ed25519 seed in hex: the entries since the
last seal are sealed. --tsa: an RFC 3161 token on the SHA-256 of the check entry, verified by openssl against the
FreeTSA root pinned by its SHA-256 (freetsa.org: --tsa-ca must be that root), --tsa-ca, or the system trust store.

Exit codes. init: 0 opened, 3 refused, 64 usage. record: 0 recorded, 1 the register is damaged (nothing written),
3 an input refused (nothing written), 64 usage. verify: 0 intact, 1 damaged, 2 intact but a torn last line not yet
recorded, 3 not readable, 64 usage. show: 0 shown, 1 damaged, 3 not readable, 64 usage. Every refusal is one JSON
line {"error": reason} on stdout; no traceback.
"""
import base64
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apc_solana as sol  # noqa: E402  (Ed25519, RFC 8032, standard library)

VERSION = "apc_registry 0.2.0"
FORMAT = "apc-reg-0.2"
SEAL_DOMAIN = b"apc-register-seal-v1\n"
ZERO = "0" * 64
CONSENT = "place_recorded_as_personal_data"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
UTC_T = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?Z\Z")     # 3.9 fromisoformat: 0 or 6 digits
LOCAL_T = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\Z")
DAY = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
OFFSET = re.compile(r"[+-]\d{2}:\d{2}\Z")
DEG = re.compile(r"-?\d{1,3}\.\d{7}\Z")
ZONE = re.compile(r"[A-Za-z0-9_+\-]+(/[A-Za-z0-9_+\-]+){0,2}\Z")
CC = re.compile(r"[A-Z]{2}\Z")
ADM1 = re.compile(r"[A-Z0-9]{3}[-+][0-9]{1,5}\??\Z")
ISO2 = re.compile(r"[A-Z]{2}-[A-Z0-9]{1,3}\Z")
HDOP = re.compile(r"\d{1,3}(\.\d{1,3})?\Z")
TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,128}\Z")
B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
MAX_LINE = 1 << 22          # 4 MiB: a register line longer than this is refused, not read
MAX_NMEA = 1 << 24          # 16 MiB of GPS input at most
MAX_TOKEN = 1 << 16         # 64 KiB: an RFC 3161 reply longer than this is refused
DEFAULT_ZONES = ("Europe/Rome", "America/New_York", "America/Sao_Paulo", "Africa/Lagos", "Asia/Shanghai",
                 "Asia/Kolkata", "Australia/Sydney", "Pacific/Auckland")
# release -> (sha256 of the release asset, sha256 of the converted line file); tools/fetch_*_boundaries.py
PINNED_BOUNDARIES = {"2026e": ("8eefcbc3df102dc3c174983b784bde82fec00fb4a596a1ed63e8f53a92043885",
                               "3cfc18cd8a81027591c3a6175f3b6eaec17cdc3deed2d378eaaa09ffcd12e029")}
PINNED_ADMIN = {"v5.1.2": ("22d0e3ad85eb3e27f17cabf8ba2d50e554fbc27a87796ff891d958185da62fb5",
                           "3a4a329d5d023d3e86f463e4bdc590148929ef63ec4da0e3ab5406a91653a629")}
# SHA-256 of https://freetsa.org/files/cacert.pem (the PEM file), fetched 2026-10-26; the same value the author's other bench pins
FREETSA_ROOT_SHA256 = "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
TRUST = ("freetsa_pinned", "user_ca", "system_store")


class Bad(Exception):
    """An input outside its grammar (exit 3)."""


class Damaged(Exception):
    """A register that is not intact (exit 1)."""


# ------------------------------------------------------------------ JSON: strict reading, canonical writing
def _no_dups(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Bad("duplicate member %r" % k)
        out[k] = v
    return out


def _no_const(c):
    raise Bad("non-JSON number %s" % c)


def strict_json(text):
    try:
        doc = json.loads(text, object_pairs_hook=_no_dups, parse_constant=_no_const)
    except RecursionError:
        raise Bad("not JSON: nested too deep")
    except json.JSONDecodeError as e:
        raise Bad("not JSON: %s" % e.msg)
    except ValueError as e:                 # e.g. an integer longer than int_max_str_digits
        raise Bad("not JSON: %s" % e)
    return doc


def canonical(v):
    """The canonical form of SPEC 8 (RFC 8785 for strings, integers below 2^53, booleans, null, objects with ASCII
    member names): members sorted, no whitespace, UTF-8. Anything else is refused."""
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            for k in x:
                if not isinstance(k, str) or not k.isascii():
                    raise Bad("a member name that is not ASCII")
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, str):
            try:
                x.encode("utf-8")
            except UnicodeEncodeError:
                raise Bad("a string holds an unpaired UTF-16 surrogate")
        elif isinstance(x, bool) or x is None:
            pass
        elif isinstance(x, int):
            if abs(x) >= 2 ** 53:
                raise Bad("an integer beyond 2^53")
        else:
            raise Bad("a value outside strings, integers, booleans and null")
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def utc_text(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc(s):
    if not isinstance(s, str) or not UTC_T.match(s):
        raise ValueError("not a UTC time")
    return datetime.datetime.fromisoformat(s[:-1]).replace(tzinfo=datetime.timezone.utc)


# ------------------------------------------------------------------ DER, only what an RFC 3161 reply needs (SPEC 11.6)
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
OID_TSTINFO = bytes.fromhex("2a864886f70d0109100104")
OID_SHA256 = bytes.fromhex("608648016503040201")


def _tlvs(b):
    """The TLVs of b (definite lengths, one-byte tags), all of b consumed: [(tag, content)]."""
    out, i = [], 0
    while i < len(b):
        if i + 2 > len(b):
            raise ValueError("DER: truncated")
        tag, n = b[i], b[i + 1]
        i += 2
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 3 or i + k > len(b):
                raise ValueError("DER: length form")
            n = int.from_bytes(b[i:i + k], "big")
            if n < 0x80 or (k > 1 and b[i] == 0):
                raise ValueError("DER: length not minimal")
            i += k
        if i + n > len(b):
            raise ValueError("DER: truncated")
        out.append((tag, b[i:i + n]))
        i += n
    return out


def _one(b, tag):
    t = _tlvs(b)
    if len(t) != 1 or t[0][0] != tag:
        raise ValueError("DER: not one %02x" % tag)
    return t[0][1]


def tsa_reply_fields(der):
    """TimeStampResp (RFC 3161 2.4.2) -> (status, digest bytes, genTime as a UTC datetime). ValueError otherwise."""
    resp = _tlvs(_one(der, 0x30))
    if len(resp) != 2 or resp[0][0] != 0x30 or resp[1][0] != 0x30:
        raise ValueError("TimeStampResp: not status and token")
    st = _tlvs(resp[0][1])
    if not st or st[0][0] != 0x02 or len(st[0][1]) != 1:
        raise ValueError("TimeStampResp: status")
    ci = _tlvs(resp[1][1])
    if len(ci) != 2 or ci[0] != (0x06, OID_SIGNED_DATA) or ci[1][0] != 0xA0:
        raise ValueError("token: not SignedData")
    sd = _tlvs(_one(ci[1][1], 0x30))
    if len(sd) < 4 or sd[0][0] != 0x02 or sd[1][0] != 0x31 or sd[2][0] != 0x30:
        raise ValueError("SignedData: shape")
    eci = _tlvs(sd[2][1])
    if len(eci) != 2 or eci[0] != (0x06, OID_TSTINFO) or eci[1][0] != 0xA0:
        raise ValueError("SignedData: not a TSTInfo")
    tst = _tlvs(_one(_one(eci[1][1], 0x04), 0x30))
    if len(tst) < 5 or tst[0][0] != 0x02 or tst[1][0] != 0x06 or tst[2][0] != 0x30 or tst[3][0] != 0x02 \
            or tst[4][0] != 0x18:
        raise ValueError("TSTInfo: shape")
    mi = _tlvs(tst[2][1])
    if len(mi) != 2 or mi[0][0] != 0x30 or mi[1][0] != 0x04:
        raise ValueError("TSTInfo: messageImprint")
    alg = _tlvs(mi[0][1])
    if not alg or alg[0] != (0x06, OID_SHA256) or alg[1:] not in ([], [(0x05, b"")]):
        raise ValueError("TSTInfo: the imprint is not SHA-256")
    m = re.fullmatch(rb"(\d{14})(?:\.(\d{1,6}))?Z", tst[4][1])
    if not m:
        raise ValueError("TSTInfo: genTime form")
    t = datetime.datetime.strptime(m.group(1).decode(), "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)
    if m.group(2):
        t = t.replace(microsecond=int(m.group(2).decode().ljust(6, "0")))
    return st[0][1][0], mi[1][1], t


# ------------------------------------------------------------------ the closed grammar of a register entry (SPEC 11.2)
def _t(cond, path, what):
    if not cond:
        raise Damaged("%s: %s" % (path, what))


def _members(d, path, required, optional=()):
    _t(isinstance(d, dict), path, "not an object")
    extra = set(d) - set(required) - set(optional)
    _t(not extra, path, "unknown member %s" % ", ".join(sorted(extra)))
    missing = set(required) - set(d)
    _t(not missing, path, "missing member %s" % ", ".join(sorted(missing)))


def _int(x, path, lo=None, hi=None):
    _t(type(x) is int and (lo is None or x >= lo) and (hi is None or x <= hi), path, "not an integer in range")


def _str(x, path, rx=None, enum=None, maxlen=4096):
    _t(isinstance(x, str) and 0 < len(x) <= maxlen, path, "not a non-empty string")
    if rx is not None:
        _t(rx.match(x) is not None, path, "not of the form SPEC 11.2 names")
    if enum is not None:
        _t(x in enum, path, "not one of %s" % ", ".join(str(e) for e in enum))


def _opt(x, f, path, *a, **k):
    if x is not None:
        f(x, path, *a, **k)


def _utc(x, path):
    _str(x, path, UTC_T)
    try:
        parse_utc(x)
    except ValueError:
        raise Damaged("%s: not a valid UTC time" % path)


def _view(v, path):
    _members(v, path, ("local_time", "local_day", "utc_offset", "dst_seconds", "time_kind", "abbreviation"))
    _str(v["local_time"], path + ".local_time", LOCAL_T)
    _str(v["local_day"], path + ".local_day", DAY)
    _t(v["local_time"][:10] == v["local_day"], path, "local_day is not the day of local_time")
    _str(v["utc_offset"], path + ".utc_offset", OFFSET)
    _t(v["local_time"].endswith(v["utc_offset"]), path, "utc_offset is not the offset of local_time")
    _int(v["dst_seconds"], path + ".dst_seconds", -86400, 86400)
    _str(v["time_kind"], path + ".time_kind", enum=("summer_time", "standard_time", "negative_dst"))
    want = "summer_time" if v["dst_seconds"] > 0 else "negative_dst" if v["dst_seconds"] < 0 else "standard_time"
    _t(v["time_kind"] == want, path + ".time_kind", "not the kind its dst_seconds names")
    _str(v["abbreviation"], path + ".abbreviation", maxlen=16)


COUNTS = {"nmea0183": ("lines", "rmc", "gga", "bad_checksum", "unusable", "other"),
          "gpsd_json": ("lines", "tpv", "sky", "unusable", "other")}
SOURCES = {"nmea0183": ("file", "serial"), "gpsd_json": ("file", "socket")}
GPSD_STATUS_OK = (1, 2, 3, 4, 6, 9)


def _gps(g, path):
    _t(isinstance(g, dict) and "status" in g, path, "not an object with a status")
    st = g["status"]
    if st == "no_source":
        _members(g, path, ("status",))
        return
    _t(isinstance(g.get("format"), str) and g["format"] in COUNTS, path + ".format", "not nmea0183 or gpsd_json")
    fmt = g["format"]
    base = ("status", "format", "source", "source_sha256", "counts")
    if st == "no_fix":
        _members(g, path, base + ("reason",))
        _str(g["reason"], path + ".reason", maxlen=256)
    elif st == "fix":
        _members(g, path, base + ("fix_record", "aux_record", "lat", "lon", "time_utc", "fix_mode", "fix_quality",
                                  "satellites", "hdop", "clock_minus_gps_seconds"))
        _str(g["fix_record"], path + ".fix_record", maxlen=4096)
        _opt(g["aux_record"], _str, path + ".aux_record", maxlen=1 << 16)
        _str(g["lat"], path + ".lat", DEG)
        _str(g["lon"], path + ".lon", DEG)
        _t(abs(float(g["lat"])) <= 90 and abs(float(g["lon"])) <= 180, path, "lat/lon out of range")
        _utc(g["time_utc"], path + ".time_utc")
        if fmt == "nmea0183":
            _t(g["fix_record"][3:6] == "RMC", path + ".fix_record", "not an RMC sentence")
            _opt(g["fix_mode"], _str, path + ".fix_mode", enum=("A", "D", "P", "R", "F"))
            _opt(g["fix_quality"], _int, path + ".fix_quality", 1, 5)
        else:
            try:
                tpv = strict_json(g["fix_record"])
            except Bad as e:
                raise Damaged("%s.fix_record: %s" % (path, e))
            _t(isinstance(tpv, dict) and tpv.get("class") == "TPV", path + ".fix_record", "not a TPV object")
            _str(g["fix_mode"], path + ".fix_mode", enum=("2", "3"))
            _opt(g["fix_quality"], _str, path + ".fix_quality", enum=tuple(str(x) for x in GPSD_STATUS_OK))
        _opt(g["satellites"], _int, path + ".satellites", 0, 99)
        _opt(g["hdop"], _str, path + ".hdop", HDOP)
        _int(g["clock_minus_gps_seconds"], path + ".clock_minus_gps_seconds")
    else:
        raise Damaged("%s.status: not no_source, no_fix or fix" % path)
    _str(g["source"], path + ".source", enum=SOURCES[fmt])
    _str(g["source_sha256"], path + ".source_sha256", HEX64)
    _members(g["counts"], path + ".counts", COUNTS[fmt])
    for k in COUNTS[fmt]:
        _int(g["counts"][k], path + ".counts." + k, 0)


PLACE_STATUS = ("established", "at_sea", "ambiguous", "no_zone_in_file", "no_boundary_file")


def _place(p, path, gps_fix):
    _t(isinstance(p, dict) and "status" in p, path, "not an object with a status")
    if p["status"] == "not_established":
        _members(p, path, ("status", "reason"))
        _str(p["reason"], path + ".reason", maxlen=256)
        _t(not gps_fix, path, "not_established with a GPS fix")
        return
    _members(p, path, ("status", "zone", "zone_basis", "candidates", "country", "country_basis"))
    _str(p["status"], path + ".status", enum=PLACE_STATUS)
    _t(gps_fix, path, "a place without a GPS fix")
    _str(p["zone"], path + ".zone", ZONE, maxlen=64)
    _str(p["zone_basis"], path + ".zone_basis", enum=("boundary", "ocean_polygon", "longitude_derived"))
    want = {"established": "boundary", "at_sea": "ocean_polygon"}.get(p["status"], "longitude_derived")
    _t(p["zone_basis"] == want, path + ".zone_basis", "not the basis its status names")
    _t(isinstance(p["candidates"], list) and len(p["candidates"]) <= 16, path + ".candidates", "not a list")
    for i, c in enumerate(p["candidates"]):
        _str(c, "%s.candidates[%d]" % (path, i), ZONE, maxlen=64)
    _t(len(set(p["candidates"])) == len(p["candidates"]), path + ".candidates", "duplicates")
    _t((len(p["candidates"]) >= 2) == (p["status"] == "ambiguous"), path + ".candidates",
       "two or more exactly when ambiguous")
    _opt(p["country"], _str, path + ".country", CC)
    _t((p["country"] is None) == (p["country_basis"] is None), path, "country and country_basis together")
    _opt(p["country_basis"], _str, path + ".country_basis", enum=("zone.tab",))


def _dataset(d, path):
    _members(d, path, ("release", "source_sha256", "file_sha256", "pinned"))
    _str(d["release"], path + ".release", maxlen=32)
    _str(d["source_sha256"], path + ".source_sha256", HEX64)
    _str(d["file_sha256"], path + ".file_sha256", HEX64)
    _t(type(d["pinned"]) is bool, path + ".pinned", "not a boolean")


def _region(r, path, gps_fix):
    _t(isinstance(r, dict) and "status" in r, path, "not an object with a status")
    st = r["status"]
    if st == "not_established":
        _members(r, path, ("status", "reason"))
        _str(r["reason"], path + ".reason", maxlen=256)
        _t(not gps_fix, path, "not_established with a GPS fix")
        return
    _t(gps_fix, path, "a region without a GPS fix")
    if st == "no_admin_file":
        _members(r, path, ("status",))
        return
    _members(r, path, ("status", "areas", "dataset"))
    _str(st, path + ".status", enum=("established", "none", "ambiguous"))
    _t(isinstance(r["areas"], list) and len(r["areas"]) <= 8, path + ".areas", "not a list of at most 8")
    n = len(r["areas"])
    _t({"established": n == 1, "none": n == 0, "ambiguous": n >= 2}[st], path + ".areas",
       "not the count its status names")
    for i, a in enumerate(r["areas"]):
        ap = "%s.areas[%d]" % (path, i)
        _members(a, ap, ("adm1_code", "iso_3166_2", "name", "region", "country"))
        _str(a["adm1_code"], ap + ".adm1_code", ADM1, maxlen=16)
        _opt(a["iso_3166_2"], _str, ap + ".iso_3166_2", ISO2)
        _opt(a["name"], _str, ap + ".name", TEXT)
        _opt(a["region"], _str, ap + ".region", TEXT)
        _opt(a["country"], _str, ap + ".country", CC)
    codes = [a["adm1_code"] for a in r["areas"]]
    _t(codes == sorted(set(codes)), path + ".areas", "not in adm1_code order without duplicates")
    _dataset(r["dataset"], path + ".dataset")


def _local(lo, path):
    _members(lo, path, ("zone", "at_clock", "at_gps"))
    _str(lo["zone"], path + ".zone", ZONE, maxlen=64)
    _view(lo["at_clock"], path + ".at_clock")
    _view(lo["at_gps"], path + ".at_gps")


def _check_body(b, path):
    _members(b, path, ("tool", "proven", "declared", "tz"))
    _str(b["tool"], path + ".tool", maxlen=64)
    pr = b["proven"]
    _members(pr, path + ".proven", ("report", "report_sha256", "verdict", "bundle_sha256", "rerun", "block_time"))
    _t(isinstance(pr["report"], dict), path + ".proven.report", "not an object")
    try:
        rsha = sha256(canonical(pr["report"]))
    except Bad as e:
        raise Damaged("%s.proven.report: %s" % (path, e))
    _str(pr["report_sha256"], path + ".proven.report_sha256", HEX64)
    _t(pr["report_sha256"] == rsha, path + ".proven.report_sha256", "not the SHA-256 of the canonical report")
    _t(pr["verdict"] == pr["report"].get("verdict"), path + ".proven.verdict", "not the report's verdict")
    _str(pr["verdict"], path + ".proven.verdict", maxlen=64)
    _opt(pr["bundle_sha256"], _str, path + ".proven.bundle_sha256", HEX64)
    _t((pr["bundle_sha256"] is None) == (pr["rerun"] is None), path + ".proven.rerun", "present exactly with a bundle")
    if pr["rerun"] is not None:
        rr, rp = pr["rerun"], path + ".proven.rerun"
        _members(rr, rp, ("verifier", "options", "report_sha256", "verdict"))
        _str(rr["verifier"], rp + ".verifier", maxlen=64)
        _t(rr["verifier"] == pr["report"].get("verifier"), rp + ".verifier", "not the report's verifier")
        _members(rr["options"], rp + ".options", ("l1_checkpoint", "http_keys_sha256"))
        _opt(rr["options"]["l1_checkpoint"], _str, rp + ".options.l1_checkpoint", re.compile(r"0x[0-9a-f]{64}\Z"))
        _opt(rr["options"]["http_keys_sha256"], _str, rp + ".options.http_keys_sha256", HEX64)
        _t(rr["report_sha256"] == pr["report_sha256"], rp + ".report_sha256", "not the recorded report's")
        _t(rr["verdict"] == pr["verdict"], rp + ".verdict", "not the recorded verdict")
    if pr["block_time"] is not None:
        _t(pr["bundle_sha256"] is not None, path + ".proven.block_time", "without a bundle")
        _members(pr["block_time"], path + ".proven.block_time", ("utc", "block_bound"))
        _utc(pr["block_time"]["utc"], path + ".proven.block_time.utc")
        _t(pr["block_time"]["block_bound"] is (pr["report"].get("block_bound") is True),
           path + ".proven.block_time.block_bound", "not the report's block_bound")
    d = b["declared"]
    _members(d, path + ".declared", ("clock_utc", "device_zone", "gps", "place", "region", "local"))
    _utc(d["clock_utc"], path + ".declared.clock_utc")
    _opt(d["device_zone"], _str, path + ".declared.device_zone", ZONE, maxlen=64)
    _gps(d["gps"], path + ".declared.gps")
    fix = d["gps"]["status"] == "fix"
    _place(d["place"], path + ".declared.place", fix)
    _region(d["region"], path + ".declared.region", fix)
    if d["place"]["status"] == "not_established":
        _t(d["local"] is None, path + ".declared.local", "a local time without a place")
    else:
        _local(d["local"], path + ".declared.local")
        _t(d["local"]["zone"] == d["place"]["zone"], path + ".declared.local.zone", "not the place's zone")
    t = b["tz"]
    _members(t, path + ".tz", ("tzdata_version", "zone_file_sha256", "boundaries"))
    _str(t["tzdata_version"], path + ".tz.tzdata_version", re.compile(r"(\d{4}[a-z]{1,2}|unknown)\Z"))
    _opt(t["zone_file_sha256"], _str, path + ".tz.zone_file_sha256", HEX64)
    if t["boundaries"] is not None:
        _dataset(t["boundaries"], path + ".tz.boundaries")
    _t((t["boundaries"] is None) == (d["place"]["status"] in ("not_established", "no_boundary_file")),
       path + ".tz.boundaries", "present exactly when a boundary file was read")


def _timestamp_body(b, bp, seq, prev):
    _members(b, bp, ("of_seq", "of_hash", "tsa_url", "token_b64", "gen_time_utc", "trust", "ca_sha256",
                     "openssl"))
    _int(b["of_seq"], bp + ".of_seq", 0)
    _t(b["of_seq"] == seq - 1, bp + ".of_seq", "not the entry before")
    _str(b["of_hash"], bp + ".of_hash", HEX64)
    _t(b["of_hash"] == prev, bp + ".of_hash", "not the hash of the entry before")
    _str(b["tsa_url"], bp + ".tsa_url", re.compile(r"https?://[^\s]{1,500}\Z"), maxlen=512)
    _str(b["token_b64"], bp + ".token_b64", B64, maxlen=MAX_TOKEN * 2)
    _utc(b["gen_time_utc"], bp + ".gen_time_utc")
    _str(b["trust"], bp + ".trust", enum=TRUST)
    _str(b["ca_sha256"], bp + ".ca_sha256", HEX64)
    _t(b["trust"] != "freetsa_pinned" or b["ca_sha256"] == FREETSA_ROOT_SHA256, bp + ".ca_sha256",
       "not the pinned FreeTSA root")
    _str(b["openssl"], bp + ".openssl", maxlen=128)
    try:
        der = base64.b64decode(b["token_b64"], validate=True)
        status, digest, gen = tsa_reply_fields(der)
    except ValueError as e:
        raise Damaged("%s.token_b64: %s" % (bp, e))
    _t(base64.b64encode(der).decode() == b["token_b64"], bp + ".token_b64", "not canonical base64")
    _t(status in (0, 1), bp + ".token_b64", "the reply is not granted")
    _t(digest.hex() == b["of_hash"], bp + ".token_b64", "the token does not stamp of_hash")
    _t(utc_text(gen) == b["gen_time_utc"], bp + ".gen_time_utc", "not the token's genTime")


def check_entry(e, path, seq, prev):
    """The closed grammar of one entry and its place in the chain; Damaged with the path when it is not."""
    _members(e, path, ("apc_register", "seq", "prev", "kind", "body", "hash"))
    _t(e["apc_register"] == FORMAT, path + ".apc_register", "not %s" % FORMAT)
    _int(e["seq"], path + ".seq", 0)
    _t(e["seq"] == seq, path + ".seq", "not %d (an entry missing, added or moved)" % seq)
    _str(e["prev"], path + ".prev", HEX64)
    _t(e["prev"] == prev, path + ".prev", "not the hash of the entry before")
    _str(e["kind"], path + ".kind", enum=("open", "check", "torn_tail", "seal", "timestamp"))
    _t((e["kind"] == "open") == (seq == 0), path + ".kind", "open is the first entry and only the first")
    _str(e["hash"], path + ".hash", HEX64)
    b, bp = e["body"], path + ".body"
    if e["kind"] == "open":
        _members(b, bp, ("created_clock_utc", "consent", "tool"))
        _utc(b["created_clock_utc"], bp + ".created_clock_utc")
        _t(b["consent"] == CONSENT, bp + ".consent", "not %s" % CONSENT)
        _str(b["tool"], bp + ".tool", maxlen=64)
    elif e["kind"] == "torn_tail":
        _members(b, bp, ("dropped_bytes", "dropped_sha256", "found_clock_utc"))
        _int(b["dropped_bytes"], bp + ".dropped_bytes", 1, MAX_LINE)
        _str(b["dropped_sha256"], bp + ".dropped_sha256", HEX64)
        _utc(b["found_clock_utc"], bp + ".found_clock_utc")
    elif e["kind"] == "seal":
        _members(b, bp, ("from_seq", "to_seq", "head", "public_key", "key_id", "signature"))
        _int(b["from_seq"], bp + ".from_seq", 0)
        _int(b["to_seq"], bp + ".to_seq", 0)
        _str(b["head"], bp + ".head", HEX64)
        _str(b["public_key"], bp + ".public_key", HEX64)
        _str(b["key_id"], bp + ".key_id", HEX16)
        _str(b["signature"], bp + ".signature", HEX128)
    elif e["kind"] == "timestamp":
        _timestamp_body(b, bp, seq, prev)
    else:
        _check_body(b, bp)
    want = sha256(canonical({k: v for k, v in e.items() if k != "hash"}))
    _t(e["hash"] == want, path + ".hash", "not the SHA-256 of the canonical entry")


def seal_message(from_seq, to_seq, head, public_key):
    return SEAL_DOMAIN + canonical({"from_seq": from_seq, "to_seq": to_seq, "head": head, "public_key": public_key})


# ------------------------------------------------------------------ reading a register (SPEC 11.3)
def read_register(path, want_key=None):
    """-> (entries, torn) where torn is None or (offset, dropped bytes). Damaged for any other damage, OSError when
    it cannot be read."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        raise Damaged("empty file: not a register (no open entry)")
    end = data.rfind(b"\n") + 1
    torn = (end, data[end:]) if end < len(data) else None
    if torn is not None and len(torn[1]) > MAX_LINE:
        raise Damaged("a last line without its end of line longer than %d bytes" % MAX_LINE)
    entries, prev, last_seal = [], ZERO, -1
    pos = 0
    while pos < end:
        nl = data.index(b"\n", pos)
        raw = data[pos:nl]
        n = len(entries)
        path_n = "line %d" % (n + 1)
        if len(raw) > MAX_LINE:
            raise Damaged("%s: longer than %d bytes" % (path_n, MAX_LINE))
        try:
            e = strict_json(raw.decode("utf-8"))
            canon = canonical(e)
        except (Bad, UnicodeDecodeError) as x:
            raise Damaged("%s: %s" % (path_n, x))
        if canon != raw:
            raise Damaged("%s: not the canonical form of its entry" % path_n)
        check_entry(e, path_n, n, prev)
        if e["kind"] == "timestamp":
            _t(entries[-1]["kind"] == "check", path_n, "a timestamp follows a check and only a check")
        if e["kind"] == "seal":
            b = e["body"]
            _t(b["from_seq"] == last_seal + 1 and b["to_seq"] == n - 1 and b["from_seq"] <= b["to_seq"], path_n,
               "the seal does not cover the entries since the last seal")
            _t(b["head"] == prev, path_n + ".body.head", "not the hash of the entry before the seal")
            pub = bytes.fromhex(b["public_key"])
            _t(b["key_id"] == sha256(pub)[:16], path_n + ".body.key_id", "not the key's id")
            _t(want_key is None or want_key == b["public_key"], path_n + ".body.public_key", "not the key named")
            _t(sol.ed25519_verify(pub, seal_message(b["from_seq"], b["to_seq"], b["head"], b["public_key"]),
                                  bytes.fromhex(b["signature"])), path_n + ".body.signature", "does not hold")
            last_seal = n
        entries.append(e)
        prev = e["hash"]
        pos = nl + 1
    if not entries:
        raise Damaged("no complete line: not a register (no open entry)")
    return entries, torn


# ------------------------------------------------------------------ NMEA 0183 (SPEC 11.4)
SENTENCE = re.compile(r"\$(GP|GN)(RMC|GGA),([^*$]*)\*([0-9A-F]{2})\Z")
ANY_SENTENCE = re.compile(r"[$!][A-Z0-9]{3,6},[^*]*\*[0-9A-Fa-f]{2}\Z")
RMC_OK_MODES = ("A", "D", "P", "R", "F")
GGA_FIX = (1, 2, 3, 4, 5)


def _hhmmss(s):
    m = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\.\d{1,3})?", s)
    if not m:
        raise ValueError("time field")
    h, mi, se = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if se == 60:
        raise ValueError("second 60 (a leap second is not representable; SPEC 11.4)")
    if h > 23 or mi > 59 or se > 59:
        raise ValueError("time field out of range")
    us = int(round(float(m.group(4)) * 1e6)) if m.group(4) else 0
    return h, mi, se, min(us, 999999)


def _deg(x):
    from decimal import Decimal, ROUND_HALF_EVEN
    x = x.quantize(Decimal("0.0000001"), rounding=ROUND_HALF_EVEN)
    return "0.0000000" if x == 0 else "%s" % x


def _coord(v, hemi, lat):
    """ddmm.mmmm / dddmm.mmmm -> degrees, a decimal string with 7 decimals (exact arithmetic, half-even)."""
    from decimal import Decimal
    m = re.fullmatch(r"(\d{2})(\d{2}\.\d{1,8})" if lat else r"(\d{3})(\d{2}\.\d{1,8})", v)
    if not m or hemi not in (("N", "S") if lat else ("E", "W")):
        raise ValueError("coordinate field")
    deg, mins = int(m.group(1)), Decimal(m.group(2))
    if mins >= 60 or deg > (90 if lat else 180) or (deg == (90 if lat else 180) and mins != 0):
        raise ValueError("coordinate out of range")
    x = Decimal(deg) + mins / Decimal(60)
    return _deg(-x if hemi in ("S", "W") else x)


def parse_nmea(data):
    """bytes -> (fix or None, reason, counts). fix: the LAST RMC with a valid fix, with the GGA of the same time if any."""
    counts = dict.fromkeys(COUNTS["nmea0183"], 0)
    rmcs, ggas, reason = [], {}, "no RMC sentence"
    for raw in data.split(b"\n"):
        line = raw.rstrip(b"\r")
        if not line:
            continue
        counts["lines"] += 1
        try:
            s = line.decode("ascii")
        except UnicodeDecodeError:
            counts["other"] += 1
            continue
        m = SENTENCE.match(s)
        if not m:
            if ANY_SENTENCE.match(s) and _checksum(s) is False:
                counts["bad_checksum"] += 1
            else:
                counts["other"] += 1
            continue
        body = s[1:s.index("*")]
        if "%02X" % _xor(body) != m.group(4):
            counts["bad_checksum"] += 1
            continue
        kind, f = m.group(2), m.group(3).split(",")
        counts[kind.lower()] += 1
        try:
            if kind == "RMC":
                if len(f) not in (11, 12, 13):
                    raise ValueError("RMC with %d fields" % len(f))
                mode = f[11] if len(f) >= 12 and f[11] else None
                if f[1] != "A":
                    reason = "RMC status %s (no valid fix)" % (f[1] or "empty")
                    continue
                if mode is not None and mode not in RMC_OK_MODES:
                    reason = "RMC mode %s (not a measured fix)" % mode
                    continue
                h, mi, se, us = _hhmmss(f[0])
                dm = re.fullmatch(r"(\d{2})(\d{2})(\d{2})", f[8])
                if not dm:
                    raise ValueError("date field")
                yy = int(dm.group(3))
                t = datetime.datetime(2000 + yy if yy < 80 else 1900 + yy, int(dm.group(2)), int(dm.group(1)),
                                      h, mi, se, us, tzinfo=datetime.timezone.utc)
                rmcs.append({"rmc": s, "lat": _coord(f[2], f[3], True), "lon": _coord(f[4], f[5], False),
                             "time": t, "tkey": f[0], "mode": mode})
            else:
                if len(f) != 14:
                    raise ValueError("GGA with %d fields" % len(f))
                q = int(f[5]) if f[5].isdigit() else None
                ggas[f[0]] = {"gga": s, "quality": q, "sats": int(f[6]) if f[6].isdigit() else None,
                              "hdop": f[7] if HDOP.match(f[7]) else None,
                              "lat": _coord(f[1], f[2], True) if q in GGA_FIX else None,
                              "lon": _coord(f[3], f[4], False) if q in GGA_FIX else None}
        except ValueError as e:
            counts["unusable"] += 1
            reason = "%s unusable: %s" % (kind, e)
    if not rmcs:
        return None, reason, counts
    r = rmcs[-1]
    g = ggas.get(r["tkey"])
    if g is not None:
        if g["quality"] not in GGA_FIX:
            return None, "GGA of the same time has fix quality %s" % g["quality"], counts
        if (g["lat"], g["lon"]) != (r["lat"], r["lon"]):
            return None, "RMC and GGA of the same time name different places", counts
    return {"fix_record": r["rmc"], "aux_record": g["gga"] if g else None, "lat": r["lat"], "lon": r["lon"],
            "time": r["time"], "fix_mode": r["mode"], "fix_quality": g["quality"] if g else None,
            "satellites": g["sats"] if g and g["sats"] is not None and g["sats"] <= 99 else None,
            "hdop": g["hdop"] if g else None}, None, counts


def _xor(body):
    c = 0
    for ch in body:
        c ^= ord(ch)
    return c


def _checksum(s):
    star = s.rfind("*")
    try:
        return "%02X" % _xor(s[1:star]) == s[star + 1:].upper()
    except ValueError:
        return None


def read_serial(dev, baud, seconds):
    """Read NMEA bytes from a serial device for up to `seconds` (raw mode at `baud` when it is a terminal)."""
    import select
    fd = os.open(dev, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        try:
            import termios
            if os.isatty(fd):
                rates = {4800: termios.B4800, 9600: termios.B9600, 19200: termios.B19200, 38400: termios.B38400,
                         57600: termios.B57600, 115200: termios.B115200}
                a = termios.tcgetattr(fd)
                a[0] = 0
                a[1] = 0
                a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
                a[3] = 0
                a[4] = a[5] = rates[baud]
                termios.tcsetattr(fd, termios.TCSANOW, a)
        except ImportError:
            pass
        buf, end = b"", time.monotonic() + seconds
        while time.monotonic() < end and len(buf) < MAX_NMEA:
            r, _, _ = select.select([fd], [], [], max(0.0, end - time.monotonic()))
            if not r:
                break
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                continue
            if not chunk:
                break
            buf += chunk
            if buf.endswith(b"\n") and b"RMC" in buf:
                fx = parse_nmea(buf)[0]
                if fx is not None and fx["aux_record"] is not None:
                    break
        return buf
    finally:
        os.close(fd)


# ------------------------------------------------------------------ gpsd JSON (SPEC 11.4)
GPSD_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z\Z")


def _num(v):
    return (isinstance(v, (int, float)) and not isinstance(v, bool)) and math.isfinite(v)


def _gpsd_deg(v, lim):
    from decimal import Decimal
    if not _num(v) or abs(v) > lim:
        raise ValueError("coordinate not a number in range")
    return _deg(Decimal(repr(float(v))))


def parse_gpsd(data):
    """bytes (one JSON object per line) -> (fix or None, reason, counts). fix: the LAST TPV with mode 2 or 3, a time,
    lat and lon, and a status (when present) that is a measured fix; the SKY of the same time, else the last SKY
    before that TPV."""
    counts = dict.fromkeys(COUNTS["gpsd_json"], 0)
    tpvs, skies, reason = [], [], "no TPV object"
    for raw in data.split(b"\n"):
        line = raw.rstrip(b"\r")
        if not line:
            continue
        counts["lines"] += 1
        if not line.startswith(b"{"):
            counts["other"] += 1
            continue
        try:
            o = strict_json(line.decode("utf-8"))
        except (Bad, UnicodeDecodeError):
            counts["unusable"] += 1
            continue
        if not isinstance(o, dict) or o.get("class") not in ("TPV", "SKY"):
            counts["other"] += 1
            continue
        s = line.decode("utf-8")
        try:
            if o["class"] == "SKY":
                counts["sky"] += 1
                t = o.get("time") if isinstance(o.get("time"), str) else None
                used = o.get("uSat")
                if type(used) is not int:
                    sats = o.get("satellites")
                    used = sum(1 for x in sats if isinstance(x, dict) and x.get("used") is True) \
                        if isinstance(sats, list) else None
                hd = o.get("hdop")
                hd = repr(float(hd)) if _num(hd) and hd >= 0 else None
                skies.append({"pos": counts["lines"], "line": s, "time": t,
                              "sats": used if used is not None and 0 <= used <= 99 else None,
                              "hdop": hd if hd is not None and HDOP.match(hd) else None})
                continue
            counts["tpv"] += 1
            mode = o.get("mode")
            if type(mode) is not int or not 0 <= mode <= 3:
                raise ValueError("mode not 0..3")
            if mode not in (2, 3):
                reason = "TPV mode %d (no fix)" % mode
                continue
            st = o.get("status")
            if st is not None:
                if type(st) is not int or not 0 <= st <= 9:
                    raise ValueError("status not 0..9")
                if st not in GPSD_STATUS_OK:
                    reason = "TPV status %d (not a measured fix)" % st
                    continue
            if "time" not in o or "lat" not in o or "lon" not in o:
                reason = "TPV without time, lat or lon"
                continue
            m = GPSD_TIME.match(o["time"]) if isinstance(o["time"], str) else None
            if not m:
                raise ValueError("time not ISO 8601 UTC")
            if m.group(6) == "60":
                raise ValueError("second 60 (a leap second is not representable; SPEC 11.4)")
            t = datetime.datetime(*(int(m.group(i)) for i in range(1, 7)),
                                  int((m.group(7) or "0")[:6].ljust(6, "0")), tzinfo=datetime.timezone.utc)
            tpvs.append({"pos": counts["lines"], "line": s, "time": t, "time_text": o["time"],
                         "lat": _gpsd_deg(o["lat"], 90), "lon": _gpsd_deg(o["lon"], 180), "mode": str(mode),
                         "status": None if st is None else str(st)})
        except ValueError as e:
            counts["unusable"] += 1
            reason = "%s unusable: %s" % (o["class"], e)
    if not tpvs:
        return None, reason, counts
    r = tpvs[-1]
    same = [k for k in skies if k["time"] == r["time_text"]]
    before = [k for k in skies if k["pos"] < r["pos"]]
    k = same[-1] if same else before[-1] if before else None
    return {"fix_record": r["line"], "aux_record": k["line"] if k else None, "lat": r["lat"], "lon": r["lon"],
            "time": r["time"], "fix_mode": r["mode"], "fix_quality": r["status"],
            "satellites": k["sats"] if k else None, "hdop": k["hdop"] if k else None}, None, counts


def read_gpsd_socket(port, seconds):
    """The gpsd daemon on 127.0.0.1 only: ?WATCH JSON, read up to `seconds` or until a fix and a SKY."""
    import socket
    end = time.monotonic() + seconds
    s = socket.create_connection(("127.0.0.1", port), timeout=seconds)
    try:
        s.sendall(b'?WATCH={"enable":true,"json":true};\n')
        buf = b""
        while time.monotonic() < end and len(buf) < MAX_NMEA:
            s.settimeout(max(0.01, end - time.monotonic()))
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if buf.endswith(b"\n") and b'"TPV"' in buf:
                fx = parse_gpsd(buf)[0]
                if fx is not None and fx["aux_record"] is not None:
                    break
        return buf
    finally:
        s.close()


def gps_record(data, fmt, source, clock):
    fix, reason, counts = (parse_nmea if fmt == "nmea0183" else parse_gpsd)(data)
    base = {"format": fmt, "source": source, "source_sha256": sha256(data), "counts": counts}
    if fix is None:
        return dict(base, status="no_fix", reason=reason[:256]), None
    if len(fix["fix_record"]) > 4096 or (fix["aux_record"] is not None and len(fix["aux_record"]) > 1 << 16):
        return dict(base, status="no_fix", reason="the fix record is longer than SPEC 11.2 allows"), None
    out = dict(base, status="fix", time_utc=utc_text(fix["time"]),
               clock_minus_gps_seconds=int(math.floor((clock - fix["time"]).total_seconds())),
               **{k: fix[k] for k in ("fix_record", "aux_record", "lat", "lon", "fix_mode", "fix_quality",
                                      "satellites", "hdop")})
    return out, fix


# ------------------------------------------------------------------ boundary files: zone and admin-1 (SPEC 11.5)
def nautical_zone(lon):
    """Etc/GMT zone of the 15-degree band of the longitude (Etc/GMT-N is UTC+N)."""
    n = max(-12, min(12, int(math.floor((lon + 7.5) / 15))))
    return "Etc/GMT" if n == 0 else ("Etc/GMT-%d" % n if n > 0 else "Etc/GMT+%d" % -n)


def _in_ring(x, y, ring):
    inside = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i][0], ring[i][1]
        xj, yj = ring[j][0], ring[j][1]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def _in_polygons(x, y, polys):
    for poly in polys:
        if poly and _in_ring(x, y, poly[0]) and not any(_in_ring(x, y, h) for h in poly[1:]):
            return True
    return False


KINDS = {"tz": ("apc_tz_boundaries", "zones", ZONE), "admin": ("apc_admin_boundaries", "areas", ADM1)}
AREA_KEYS = ("iso_3166_2", "name", "region", "country", "polygons")


def read_boundaries_header(fh, kind="tz"):
    tag, count, _ = KINDS[kind]
    first = fh.readline(1 << 16)
    try:
        h = strict_json(first.decode("utf-8"))
    except (Bad, UnicodeDecodeError) as e:
        raise Bad("%s file header: %s" % (kind, e))
    if not isinstance(h, dict) or set(h) != {tag, "release", "source_asset", "source_sha256", count} \
            or h[tag] != 1 or not isinstance(h["release"], str) or not 0 < len(h["release"]) <= 32 \
            or not isinstance(h["source_sha256"], str) or not HEX64.match(h["source_sha256"]) \
            or type(h[count]) is not int or first != canonical(h) + b"\n":
        raise Bad("%s file header: not an %s 1 header" % (kind, tag))
    return h, first


def _area(payload, n):
    if not isinstance(payload, dict) or set(payload) != set(AREA_KEYS) \
            or not all(payload[k] is None or (isinstance(payload[k], str) and TEXT.match(payload[k]))
                       for k in ("name", "region")) \
            or not (payload["iso_3166_2"] is None or (isinstance(payload["iso_3166_2"], str)
                                                      and ISO2.match(payload["iso_3166_2"]))) \
            or not (payload["country"] is None or (isinstance(payload["country"], str)
                                                   and CC.match(payload["country"]))):
        raise Bad("admin file line %d: not an area object" % n)
    return payload


def boundary_lookup(path, lat, lon, kind="tz"):
    """-> (matches [(key, payload)], header, file sha256). One pass; polygons are parsed only where the bbox holds."""
    x, y = float(lon), float(lat)
    _, count, key_rx = KINDS[kind]
    h = hashlib.sha256()
    matches, n = [], 0
    with open(path, "rb") as fh:
        hdr, first = read_boundaries_header(fh, kind)
        h.update(first)
        for raw in fh:
            h.update(raw)
            n += 1
            try:
                bb, key, rest = raw.decode("utf-8").rstrip("\n").split("\t")
                x0, y0, x1, y1 = (float(v) for v in bb.split(" "))
            except ValueError:
                raise Bad("%s file line %d: not 'bbox TAB key TAB data'" % (kind, n + 1))
            if not key_rx.match(key):
                raise Bad("%s file line %d: not a %s key" % (kind, n + 1, kind))
            if x0 <= x <= x1 and y0 <= y <= y1:
                try:
                    data = json.loads(rest)
                    payload = _area(data, n + 1) if kind == "admin" else None
                    hit = _in_polygons(x, y, data["polygons"] if kind == "admin" else data)
                except (ValueError, TypeError, IndexError, KeyError, ZeroDivisionError):
                    raise Bad("%s file line %d: polygons not readable" % (kind, n + 1))
                if hit:
                    matches.append((key, payload))
    if n != hdr[count]:
        raise Bad("%s file: %d lines, the header says %d" % (kind, n, hdr[count]))
    return sorted(dict(matches).items()), hdr, h.hexdigest()


def zone_lookup(path, lat, lon):
    m, hdr, fsha = boundary_lookup(path, lat, lon, "tz")
    return [k for k, _ in m], hdr, fsha


def _zone_tab(zone):
    """The country code of the zone in zone.tab of the tzdata zoneinfo uses, or None."""
    import zoneinfo
    for d in zoneinfo.TZPATH:
        p = os.path.join(d, "zone.tab")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    f = line.rstrip("\n").split("\t")
                    if len(f) >= 3 and f[2] == zone and CC.match(f[0]):
                        return f[0]
            return None
    return None


def tzdata_info(zone):
    """(version, sha256 of the TZif file zoneinfo reads for `zone`) from the first TZPATH directory holding it, else
    from the tzdata package; ('unknown', None) when neither says."""
    import zoneinfo
    for d in zoneinfo.TZPATH:
        p = os.path.join(d, *zone.split("/"))
        if os.path.isfile(p):
            ver = "unknown"
            zi = os.path.join(d, "tzdata.zi")
            if os.path.isfile(zi):
                with open(zi, encoding="utf-8") as fh:
                    m = re.fullmatch(r"# version (\d{4}[a-z]{1,2})\n", fh.readline())
                    ver = m.group(1) if m else "unknown"
            with open(p, "rb") as fh:
                return ver, sha256(fh.read())
    try:
        import tzdata
        return (tzdata.IANA_VERSION if re.fullmatch(r"\d{4}[a-z]{1,2}", tzdata.IANA_VERSION) else "unknown"), None
    except ImportError:
        return "unknown", None


def view(instant, zone):
    import zoneinfo
    t = instant.astimezone(zoneinfo.ZoneInfo(zone))
    off = int(t.utcoffset().total_seconds())
    dst = int(t.dst().total_seconds()) if t.dst() is not None else 0
    s = "-" if off < 0 else "+"
    return {"local_time": t.replace(microsecond=0).isoformat(), "local_day": t.date().isoformat(),
            "utc_offset": "%s%02d:%02d" % (s, abs(off) // 3600, abs(off) % 3600 // 60), "dst_seconds": dst,
            "time_kind": "summer_time" if dst > 0 else "negative_dst" if dst < 0 else "standard_time",
            "abbreviation": (t.tzname() or "?")[:16]}


def device_zone():
    z = os.environ.get("TZ", "").lstrip(":")
    if not z:
        try:
            link = os.readlink("/etc/localtime")
            z = link.split("zoneinfo/", 1)[1] if "zoneinfo/" in link else ""
        except OSError:
            z = ""
    return z if z and ZONE.match(z) and len(z) <= 64 else None


def _pinned(table, hdr, fsha):
    pin = table.get(hdr["release"])
    return {"release": hdr["release"], "source_sha256": hdr["source_sha256"], "file_sha256": fsha,
            "pinned": pin is not None and pin == (hdr["source_sha256"], fsha)}


def place_record(fix, tzdb):
    """-> (place, boundaries or None)."""
    lat, lon = fix["lat"], fix["lon"]
    if tzdb is None:
        return {"status": "no_boundary_file", "zone": nautical_zone(float(lon)), "zone_basis": "longitude_derived",
                "candidates": [], "country": None, "country_basis": None}, None
    matches, hdr, fsha = zone_lookup(tzdb, lat, lon)
    bnd = _pinned(PINNED_BOUNDARIES, hdr, fsha)
    if len(matches) == 1 and matches[0].startswith("Etc/"):
        st, zone, basis, cand = "at_sea", matches[0], "ocean_polygon", []
    elif len(matches) == 1:
        st, zone, basis, cand = "established", matches[0], "boundary", []
    elif not matches:
        st, zone, basis, cand = "no_zone_in_file", nautical_zone(float(lon)), "longitude_derived", []
    else:
        st, zone, basis, cand = "ambiguous", nautical_zone(float(lon)), "longitude_derived", matches[:16]
    cc = _zone_tab(zone) if basis == "boundary" else None
    return {"status": st, "zone": zone, "zone_basis": basis, "candidates": cand, "country": cc,
            "country_basis": "zone.tab" if cc else None}, bnd


def region_record(fix, admin):
    if admin is None:
        return {"status": "no_admin_file"}
    matches, hdr, fsha = boundary_lookup(admin, fix["lat"], fix["lon"], "admin")
    areas = [{"adm1_code": k, "iso_3166_2": p["iso_3166_2"], "name": p["name"], "region": p["region"],
              "country": p["country"]} for k, p in matches[:8]]
    st = "none" if not areas else "established" if len(areas) == 1 else "ambiguous"
    return {"status": st, "areas": areas, "dataset": _pinned(PINNED_ADMIN, hdr, fsha)}


# ------------------------------------------------------------------ apc_verify run by the register (SPEC 11.6)
def rerun_verify(bundle_path, checkpoint, keys_path):
    """apc_verify's report on the bundle, as `apc_verify.py BUNDLE [--l1-checkpoint] [--http-keys]` prints it."""
    try:
        import apc_verify as av
    except Exception as e:      # noqa: BLE001  the verifier or its signature library cannot be loaded
        raise Bad("--bundle: apc_verify cannot be loaded: %s: %s" % (type(e).__name__, e))
    try:
        try:
            doc = av.strict_json(av.read_bundle_bytes(bundle_path).decode("utf-8"))
        except OSError as e:
            raise av.Refusal("cannot read %s: %s" % (bundle_path, e.strerror or e))
        keys = None
        if keys_path is not None:
            try:
                keys = av.strict_json(av.read_bundle_bytes(keys_path).decode("utf-8"))
            except OSError as e:
                raise av.Refusal("cannot read %s: %s" % (keys_path, e.strerror or e))
        rep = av.verify_bundle(doc, checkpoint, keys)
    except av.Unsupported as e:
        rep = {"verifier": av.VERSION, "verdict": "unsupported", "reason": str(e)}
    except (av.Refusal, UnicodeDecodeError) as e:
        rep = {"verifier": av.VERSION, "verdict": "refused", "reason": str(e)}
    return json.loads(json.dumps(rep))          # the report as its JSON output reads back


# ------------------------------------------------------------------ RFC 3161, opt-in (SPEC 11.6)
def _openssl():
    o = shutil.which("openssl")
    if not o:
        raise Bad("--tsa: the openssl binary is needed for RFC 3161 and is not on PATH")
    return o


def system_bundle():
    for p in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"):
        if os.path.isfile(p):
            return p
    return None


def tsa_trust(url, ca_path):
    """-> (trust, CA file). freetsa.org must come with its pinned root; else the user's CA or the system store."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
    except ValueError:
        raise Bad("--tsa: not a URL")
    if u.scheme not in ("http", "https") or not host or len(url) > 512 or re.search(r"\s", url):
        raise Bad("--tsa: an http or https URL of at most 512 characters")
    if host == "freetsa.org" or host.endswith(".freetsa.org"):
        if ca_path is None or _file_sha256(ca_path) != FREETSA_ROOT_SHA256:
            raise Bad("--tsa freetsa.org: --tsa-ca must be the FreeTSA root of SHA-256 %s" % FREETSA_ROOT_SHA256)
        return "freetsa_pinned", ca_path
    if ca_path is not None:
        return "user_ca", ca_path
    b = system_bundle()
    if b is None:
        raise Bad("--tsa: no system trust store found; give --tsa-ca")
    return "system_store", b


def _file_sha256(p):
    try:
        with open(p, "rb") as fh:
            return sha256(fh.read(1 << 24))
    except OSError as e:
        raise Bad("cannot read %s: %s" % (p, e.strerror or e))


def openssl_verify(der, digest_hex, ca_file, gen):
    """openssl ts -verify of the reply on the digest, at its genTime -> None when it holds, else the reason."""
    o = shutil.which("openssl")
    if not o:
        return "the openssl binary is not on PATH"
    t = tempfile.mkdtemp(prefix="apc_tsr_")
    try:
        p = os.path.join(t, "r.tsr")
        with open(p, "wb") as fh:
            fh.write(der)
        r = subprocess.run([o, "ts", "-verify", "-digest", digest_hex, "-in", p, "-CAfile", ca_file,
                            "-attime", str(int(gen.timestamp()))], capture_output=True, timeout=30)
        out = (r.stdout + r.stderr).decode(errors="replace")
        if r.returncode == 0 and "Verification: OK" in out:
            return None
        return (out.strip().splitlines() or ["exit %d" % r.returncode])[-1][:200]
    except (OSError, subprocess.SubprocessError) as e:
        return "openssl: %s" % type(e).__name__
    finally:
        shutil.rmtree(t, ignore_errors=True)


def tsa_stamp(url, ca_path, digest_hex):
    """Only digest_hex leaves the machine. -> the timestamp entry body; Bad when no verified token comes back."""
    import urllib.request
    trust, ca = tsa_trust(url, ca_path)
    o = _openssl()
    t = tempfile.mkdtemp(prefix="apc_tsq_")
    try:
        q = os.path.join(t, "q.tsq")
        r = subprocess.run([o, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q],
                           capture_output=True, timeout=30)
        if r.returncode:
            raise Bad("--tsa: openssl ts -query failed: %s" % r.stderr.decode(errors="replace")[:160])
        with open(q, "rb") as fh:
            req = urllib.request.Request(url, data=fh.read(), method="POST",
                                         headers={"Content-Type": "application/timestamp-query",
                                                  "User-Agent": VERSION})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                der = resp.read(MAX_TOKEN + 1)
        except (OSError, ValueError) as e:
            raise Bad("--tsa: no reply from %s: %s" % (url, str(e)[:160]))
        ver = subprocess.run([o, "version"], capture_output=True, timeout=30).stdout.decode(errors="replace").strip()
    except subprocess.SubprocessError as e:
        raise Bad("--tsa: openssl: %s" % type(e).__name__)
    finally:
        shutil.rmtree(t, ignore_errors=True)
    if len(der) > MAX_TOKEN:
        raise Bad("--tsa: a reply longer than %d bytes" % MAX_TOKEN)
    try:
        status, digest, gen = tsa_reply_fields(der)
    except ValueError as e:
        raise Bad("--tsa: the reply is not an RFC 3161 TimeStampResp: %s" % e)
    if status not in (0, 1) or digest.hex() != digest_hex:
        raise Bad("--tsa: the reply is not granted for this digest")
    why = openssl_verify(der, digest_hex, ca, gen)
    if why is not None:
        raise Bad("--tsa: the token does not verify (%s): %s" % (trust, why))
    return {"tsa_url": url, "token_b64": base64.b64encode(der).decode(), "gen_time_utc": utc_text(gen),
            "trust": trust, "ca_sha256": _file_sha256(ca), "openssl": (ver or "unknown")[:128]}


# ------------------------------------------------------------------ writing (SPEC 11.3)
def _lock(fh):
    try:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    except (ImportError, OSError):
        pass                    # no POSIX lock on this system: one writer at a time is the user's duty (SPEC 11.3)


def _entry(entries, kind, body):
    """The next entry, checked against the grammar, appended to `entries` in memory only."""
    prev = entries[-1]["hash"] if entries else ZERO
    e = {"apc_register": FORMAT, "seq": len(entries), "prev": prev, "kind": kind, "body": body}
    e["hash"] = sha256(canonical(e))
    try:
        check_entry(e, "new entry", len(entries), prev)     # what is written must read back
    except Damaged as x:
        raise Bad("nothing written: the new entry would be outside the grammar: %s" % x)
    entries.append(e)
    return e


def _write(fh, es):
    for e in es:
        fh.write(canonical(e) + b"\n")
        fh.flush()
        os.fsync(fh.fileno())


def _fsync_dir(path):
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)) or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def cmd_init(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)     # never over a file
    entries = []
    with os.fdopen(fd, "ab") as fh:
        e = _entry(entries, "open", {"created_clock_utc": utc_text(datetime.datetime.now(datetime.timezone.utc)),
                                     "consent": CONSENT, "tool": VERSION})
        _write(fh, [e])
    _fsync_dir(path)
    return {"opened": path, "head": e["hash"]}


def read_seed(path):
    with open(path) as fh:
        line = fh.read().strip().lower()
    if not HEX64.match(line):
        raise Bad("the seed file is not one 32-byte hex line")
    return bytes.fromhex(line)


def build_check(report, bundle, gps_input, tzdb, admin, clock):
    """report: a parsed report or None; bundle: None or (path, bytes, l1 checkpoint, http keys path, keys bytes)."""
    if report is not None and (not isinstance(report, dict) or not isinstance(report.get("verdict"), str)
                               or not isinstance(report.get("verifier"), str)
                               or not report["verifier"].startswith("apc_verify ")):
        raise Bad("--report: not an apc_verify report (an object with verifier and verdict)")
    block_time, bsha, rerun = None, None, None
    if bundle is not None:
        bpath, bbytes, checkpoint, kpath, kbytes = bundle
        bsha = sha256(bbytes)
        rep = rerun_verify(bpath, checkpoint, kpath)
        if sha256(bbytes) != _file_sha256(bpath):
            raise Bad("--bundle: the file changed while it was verified")
        if report is not None and canonical(report) != canonical(rep):
            raise Bad("--report: not the report apc_verify gives on this bundle now (report %s, re-run %s)"
                      % (report.get("verdict"), rep.get("verdict")))
        report = rep
        rerun = {"verifier": rep["verifier"], "options": {"l1_checkpoint": checkpoint,
                                                          "http_keys_sha256": sha256(kbytes) if kbytes else None},
                 "report_sha256": sha256(canonical(rep)), "verdict": rep["verdict"]}
        try:
            doc = strict_json(bbytes.decode("utf-8"))
        except (Bad, UnicodeDecodeError):
            doc = None                                  # a bundle apc_verify refused: no block time read
        inc = doc.get("inclusion") if isinstance(doc, dict) else None
        hdr = inc.get("block_header") if isinstance(inc, dict) else None
        ts = hdr.get("timestamp") if isinstance(hdr, dict) else None
        if ts is not None and rep.get("verdict") not in ("refused", "unsupported"):
            if not isinstance(ts, str) or not re.fullmatch(r"0x(0|[1-9a-f][0-9a-f]{0,15})", ts):
                raise Bad("--bundle: inclusion.block_header.timestamp not a quantity")
            try:
                bt = datetime.datetime.fromtimestamp(int(ts, 16), datetime.timezone.utc)
            except (OverflowError, OSError, ValueError):
                raise Bad("--bundle: inclusion.block_header.timestamp out of range")
            block_time = {"utc": utc_text(bt), "block_bound": rep.get("block_bound") is True}
    if gps_input is None:
        gps, fix = {"status": "no_source"}, None
    else:
        gps, fix = gps_record(gps_input[2], gps_input[0], gps_input[1], clock)
    if fix is None:
        why = "no GPS source given" if gps_input is None else "no GPS fix: " + gps["reason"][:200]
        place = {"status": "not_established", "reason": why}
        region = {"status": "not_established", "reason": why}
        local, bnd, zone = None, None, None
    else:
        place, bnd = place_record(fix, tzdb)
        region = region_record(fix, admin)
        zone = place["zone"]
        import zoneinfo
        try:
            zoneinfo.ZoneInfo(zone)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            raise Bad("the zone %s is not in this system's tzdata (%s): update tzdata, nothing recorded"
                      % (zone, tzdata_info("UTC")[0]))
        local = {"zone": zone, "at_clock": view(clock, zone), "at_gps": view(fix["time"], zone)}
    ver, zsha = tzdata_info(zone or "UTC")
    return {"tool": VERSION,
            "proven": {"report": report, "report_sha256": sha256(canonical(report)), "verdict": report["verdict"],
                       "bundle_sha256": bsha, "rerun": rerun, "block_time": block_time},
            "declared": {"clock_utc": utc_text(clock), "device_zone": device_zone(), "gps": gps, "place": place,
                         "region": region, "local": local},
            "tz": {"tzdata_version": ver, "zone_file_sha256": zsha, "boundaries": bnd}}


def cmd_record(path, report, bundle, gps_input, tzdb, admin, seed, tsa=None):
    """tsa: None or (url, CA path or None). Nothing is written unless every entry of this record can be."""
    clock = datetime.datetime.now(datetime.timezone.utc)
    body = build_check(report, bundle, gps_input, tzdb, admin, clock)    # inputs first: nothing written on a refusal
    if not os.path.isfile(path):
        raise Bad("%s: no register there (open one with init: recording is off until the user opens it)" % path)
    with open(path, "r+b") as fh:
        _lock(fh)
        entries, torn = read_register(path)
        new = []
        if torn is not None:
            new.append(_entry(entries, "torn_tail", {"dropped_bytes": len(torn[1]), "dropped_sha256": sha256(torn[1]),
                                                     "found_clock_utc": utc_text(clock)}))
        e = _entry(entries, "check", body)
        new.append(e)
        out = {"recorded": e["seq"], "head": e["hash"], "torn_tail_recorded": torn is not None,
               "place": body["declared"]["place"]["status"], "region": body["declared"]["region"]["status"],
               "verdict": body["proven"]["verdict"], "rerun": body["proven"]["rerun"] is not None}
        if tsa is not None:
            ts = tsa_stamp(tsa[0], tsa[1], e["hash"])            # only e["hash"] leaves the machine
            s = _entry(entries, "timestamp", dict(ts, of_seq=e["seq"], of_hash=e["hash"]))
            new.append(s)
            out["timestamp"] = {"gen_time_utc": ts["gen_time_utc"], "trust": ts["trust"]}
        if seed is not None:
            pub = sol.ed25519_public(seed).hex()
            last = max([i for i, x in enumerate(entries) if x["kind"] == "seal"], default=-1)
            frm, to = last + 1, len(entries) - 1
            sig = sol.ed25519_sign(seed, seal_message(frm, to, entries[-1]["hash"], pub)).hex()
            new.append(_entry(entries, "seal", {"from_seq": frm, "to_seq": to, "head": entries[-1]["hash"],
                                                "public_key": pub, "key_id": sha256(bytes.fromhex(pub))[:16],
                                                "signature": sig}))
            out["sealed"] = [frm, to]
        out["head"] = entries[-1]["hash"]
        fh.seek(0, os.SEEK_END)
        if torn is not None:
            fh.truncate(torn[0])
            fh.seek(torn[0])
        _write(fh, new)
    return out


def recheck_timestamps(entries, ca_path):
    """openssl again on every token: with the CA file given when its SHA-256 is the recorded one, the system store for
    system_store tokens; -> (rechecked, not rechecked). Damaged when one does not verify."""
    ca_sha = _file_sha256(ca_path) if ca_path else None
    done = skipped = 0
    for e in entries:
        if e["kind"] != "timestamp":
            continue
        b = e["body"]
        ca = ca_path if ca_sha == b["ca_sha256"] else system_bundle() if b["trust"] == "system_store" else None
        if ca is None or not shutil.which("openssl"):
            skipped += 1
            continue
        der = base64.b64decode(b["token_b64"])
        why = openssl_verify(der, b["of_hash"], ca, parse_utc(b["gen_time_utc"]))
        _t(why is None, "line %d.body.token_b64" % (e["seq"] + 1), "openssl: %s" % why)
        done += 1
    return done, skipped


def summary(e, zones, stamped):
    d, pr = e["body"]["declared"], e["body"]["proven"]
    gps_t = d["gps"].get("time_utc")
    instant = parse_utc(gps_t if gps_t else d["clock_utc"])
    other = {}
    import zoneinfo
    for z in zones:
        try:
            other[z] = view(instant, z)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            other[z] = "not_in_this_tzdata"
    return {"seq": e["seq"], "verdict": pr["verdict"], "report_sha256": pr["report_sha256"],
            "rerun": pr["rerun"] is not None, "clock_utc": d["clock_utc"],
            "check_time_proven_not_after": stamped.get(e["seq"]), "gps_time_utc": gps_t,
            "place": d["place"]["status"], "zone": d["place"].get("zone"), "region": d["region"], "local": d["local"],
            "tzdata_version_at_record": e["body"]["tz"]["tzdata_version"],
            "other_zones_at": "gps" if gps_t else "clock", "other_zones": other}


FLAGS = {"init": (), "verify": ("--public-key", "--tsa-ca"), "show": ("--zones",),
         "record": ("--report", "--bundle", "--l1-checkpoint", "--http-keys", "--nmea", "--gps", "--baud",
                    "--seconds", "--gpsd-json", "--gpsd", "--tzdb", "--admin", "--key", "--tsa", "--tsa-ca")}


def _usage_ok(cmd, opts):
    if cmd != "record":
        return cmd != "verify" or "--public-key" not in opts or HEX64.match(opts["--public-key"].lower())
    src = [k for k in ("--nmea", "--gps", "--gpsd-json", "--gpsd") if k in opts]
    return (("--report" in opts or "--bundle" in opts) and len(src) <= 1
            and ("--baud" not in opts or "--gps" in opts)
            and ("--seconds" not in opts or "--gps" in opts or "--gpsd" in opts)
            and (("--l1-checkpoint" not in opts and "--http-keys" not in opts) or "--bundle" in opts)
            and ("--tsa-ca" not in opts or "--tsa" in opts))


def _load(p, what, limit=MAX_LINE):
    try:
        with open(p, "rb") as fh:
            b = fh.read(limit + 1)
    except OSError as e:
        raise Bad("%s: cannot read %s: %s" % (what, p, e.strerror or e))
    if len(b) > limit:
        raise Bad("%s: longer than %d bytes" % (what, limit))
    return b


def _record_inputs(opts):
    tsa = (opts["--tsa"], opts.get("--tsa-ca")) if "--tsa" in opts else None
    if tsa is not None:
        tsa_trust(*tsa)                                  # refused before anything else is read
    report = None
    if "--report" in opts:
        try:
            report = strict_json(_load(opts["--report"], "--report").decode("utf-8"))
        except UnicodeDecodeError:
            raise Bad("--report: not UTF-8")
    bundle = None
    if "--bundle" in opts:
        cp = opts.get("--l1-checkpoint")
        if cp is not None:
            cp = cp.lower()
            if not re.fullmatch(r"0x[0-9a-f]{64}", cp):
                raise Bad("--l1-checkpoint: not a 32-byte 0x hash")
        kp = opts.get("--http-keys")
        bundle = (opts["--bundle"], _load(opts["--bundle"], "--bundle", 1 << 26), cp, kp,
                  _load(kp, "--http-keys") if kp else None)
    secs = 5.0
    if "--seconds" in opts:
        try:
            secs = float(opts["--seconds"])
        except ValueError:
            raise Bad("--seconds: not a number")
        if not 0 < secs <= 60:
            raise Bad("--seconds in (0, 60]")
    gps_input = None
    if "--nmea" in opts:
        gps_input = ("nmea0183", "file", _load(opts["--nmea"], "--nmea", MAX_NMEA))
    elif "--gpsd-json" in opts:
        gps_input = ("gpsd_json", "file", _load(opts["--gpsd-json"], "--gpsd-json", MAX_NMEA))
    elif "--gps" in opts:
        try:
            baud = int(opts.get("--baud", "9600"))
        except ValueError:
            raise Bad("--baud: not a number")
        if baud not in (4800, 9600, 19200, 38400, 57600, 115200):
            raise Bad("--baud one of 4800, 9600, 19200, 38400, 57600, 115200")
        try:
            gps_input = ("nmea0183", "serial", read_serial(opts["--gps"], baud, secs))
        except OSError as e:
            raise Bad("--gps: cannot read %s: %s" % (opts["--gps"], e.strerror or e))
    elif "--gpsd" in opts:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", opts["--gpsd"]) or int(opts["--gpsd"]) > 65535:
            raise Bad("--gpsd: a port 1..65535 (the daemon on 127.0.0.1 only)")
        try:
            gps_input = ("gpsd_json", "socket", read_gpsd_socket(int(opts["--gpsd"]), secs))
        except OSError as e:
            raise Bad("--gpsd: cannot read 127.0.0.1:%s: %s" % (opts["--gpsd"], e.strerror or e))
    for k in ("--tzdb", "--admin"):
        if k in opts and not os.path.isfile(opts[k]):
            raise Bad("%s: %s is not a file" % (k, opts[k]))
    seed = None
    if "--key" in opts:
        try:
            seed = read_seed(opts["--key"])
        except (OSError, UnicodeDecodeError):
            raise Bad("--key: cannot read %s" % opts["--key"])
    return report, bundle, gps_input, opts.get("--tzdb"), opts.get("--admin"), seed, tsa


def main(argv):
    a = argv[1:]
    if not a or a[0] not in FLAGS:
        print(__doc__)
        return 64
    cmd, rest = a[0], a[1:]
    opts, pos = {}, []
    i = 0
    while i < len(rest):
        x = rest[i]
        if x.startswith("-"):
            if x not in FLAGS[cmd] or x in opts or i + 1 >= len(rest) or not rest[i + 1] \
                    or rest[i + 1].startswith("--"):
                print(__doc__)
                return 64
            opts[x] = rest[i + 1]
            i += 2
        else:
            pos.append(x)
            i += 1
    if len(pos) != 1 or not _usage_ok(cmd, opts):
        print(__doc__)
        return 64
    reg = pos[0]
    try:
        if cmd == "init":
            out = cmd_init(reg)
        elif cmd == "record":
            out = cmd_record(reg, *_record_inputs(opts))
        elif cmd == "verify":
            pk = opts.get("--public-key")
            entries, torn = read_register(reg, pk.lower() if pk else None)
            done, skipped = recheck_timestamps(entries, opts.get("--tsa-ca"))
            out = {"intact": True, "entries": len(entries), "head": entries[-1]["hash"],
                   "seals": sum(1 for e in entries if e["kind"] == "seal"),
                   "unsealed_after_last_seal": len(entries) - 1 - max(
                       [i for i, e in enumerate(entries) if e["kind"] == "seal"], default=-1),
                   "timestamps": {"count": done + skipped, "rechecked_by_openssl": done, "not_rechecked": skipped},
                   "torn_tail": None if torn is None else {"bytes": len(torn[1]), "sha256": sha256(torn[1])}}
            print(json.dumps(out, indent=1, sort_keys=True))
            return 2 if torn is not None else 0
        else:
            import zoneinfo
            z = opts.get("--zones")
            if z == "all":
                zones = sorted(zoneinfo.available_timezones())
            elif z is not None:
                zones = z.split(",")
                if not all(ZONE.match(x) and len(x) <= 64 for x in zones) or len(set(zones)) != len(zones):
                    raise Bad("--zones: not a comma-separated list of distinct zone names")
            else:
                zones = list(DEFAULT_ZONES)
            entries, torn = read_register(reg)
            stamped = {e["body"]["of_seq"]: e["body"]["gen_time_utc"] for e in entries if e["kind"] == "timestamp"}
            v, _ = tzdata_info("UTC")
            out = {"tzdata_version_now": v, "head": entries[-1]["hash"], "torn_tail": torn is not None,
                   "checks": [summary(e, zones, stamped) for e in entries if e["kind"] == "check"]}
    except Damaged as e:
        print(json.dumps({"error": "register damaged: %s" % e}))
        return 1
    except FileExistsError:
        print(json.dumps({"error": "%s exists: init never writes over a file" % reg}))
        return 3
    except OSError as e:
        print(json.dumps({"error": "cannot read or write %s: %s" % (getattr(e, "filename", None) or reg,
                                                                   e.strerror or e)}))
        return 3
    except Bad as e:
        print(json.dumps({"error": str(e)}))
        return 3
    except Exception as e:      # noqa: BLE001  never a traceback: an unforeseen error is a refusal with its type
        print(json.dumps({"error": "internal error, nothing more done: %s: %s" % (type(e).__name__, e)}))
        return 3
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
