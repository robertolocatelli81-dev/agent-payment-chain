"""SPEC 0.9.1 (section 11): the register of checks on an external device (apc_registry.py, apc-reg-0.2).
Real NMEA captures of sources/nmea_20261026 and real gpsd JSON of sources/gpsd_json_20261026 (gpsd regression data,
pinned by commit and sha256); the edge cases those do not hold are GENERATED here and marked so. apc_verify is run by
the register on the real bundles of bundles/real_v03. RFC 3161: a local openssl time-stamping authority on 127.0.0.1
made for the tests (no real authority is ever called). Generative tests over the closed format: an unknown member, a
missing member and a wrong type at every level of every entry kind, duplicates, non-canonical lines, forged chains,
torn tails at every offset. The real boundary files (tools/fetch_*_boundaries.py) are used when present at APC_TZDB /
APC_ADMIN (default: a sibling folder ../apc_tzdb/...); otherwise those tests are skipped and say so."""
import copy
import datetime
import functools
import hashlib
import http.server
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests import real_corpus  # noqa: E402
real_corpus.need("real_v03")   # the real corpus is not distributed (SPEC 33): skip with the reason
import apc_registry as rg  # noqa: E402
import apc_solana as sol  # noqa: E402

NMEA = os.path.join(ROOT, "sources", "nmea_20261026")
GPSD = os.path.join(ROOT, "sources", "gpsd_json_20261026")
NMEA_LOGS = ("bu353s4.log", "garmin15x.log", "GPSmap-76S.log", "beidou-gb.log", "neo-m8n.log")
NMEA_OK = all(os.path.isfile(os.path.join(NMEA, n)) for n in NMEA_LOGS)
NMEA_WHY = ("the NMEA captures of gpsd are not redistributed (their headers name the submitters): "
            "python3 tools/fetch_nmea_captures.py fetches them from gpsd and checks SHA256SUMS")
BUNDLE = os.path.join(ROOT, "bundles", "real_v03", "v003_b098_direct_envelope_reconstructed.json")
BUNDLE2 = os.path.join(ROOT, "bundles", "real_v03", "v002_b004_direct_envelope_reconstructed.json")
REAL_TZDB = os.environ.get("APC_TZDB", os.path.join(ROOT, os.pardir, "apc_tzdb", "tz-boundaries-2026e.apc-tzb"))
REAL_ADMIN = os.environ.get("APC_ADMIN", os.path.join(ROOT, os.pardir, "apc_tzdb", "admin1-ne-v5.1.2.apc-adm"))
SEED = hashlib.sha256(b"apc registry test seed").digest()          # a test key, not anyone's
SEED2 = hashlib.sha256(b"apc registry other test seed").digest()
UTC = datetime.timezone.utc
SMALL_REPORT = {"verifier": "apc_verify 0.8.0", "verdict": "chain_verified", "checks": {}}   # GENERATED, grammar tests
OPENSSL = shutil.which("openssl")


def rd(p):
    with open(p, "rb") as fh:
        return fh.read()


def sentence(body):
    """GENERATED: an NMEA sentence with its checksum."""
    c = 0
    for ch in body:
        c ^= ord(ch)
    return "$%s*%02X" % (body, c)


def env():
    e = dict(os.environ)
    e.pop("PYTHONPATH", None)
    return e


def run(*args):
    p = subprocess.run([sys.executable, os.path.join(ROOT, "apc_registry.py")] + list(args), capture_output=True,
                       text=True, env=env(), timeout=120)
    return p.returncode, p.stdout, p.stderr


def nmea_in(b):
    return ("nmea0183", "file", b)


def bundle_in(path=BUNDLE):
    return (path, rd(path), None, None, None)


def _lines_file(path, tag, count, items):
    """GENERATED boundary line file (the format of tools/fetch_*_boundaries.py), not real boundaries."""
    lines = []
    for key, polys, payload in items:
        xs = [p[0] for poly in polys for r in poly for p in r]
        ys = [p[1] for poly in polys for r in poly for p in r]
        data = polys if payload is None else dict(payload, polygons=polys)
        lines.append("%r %r %r %r\t%s\t%s\n" % (min(xs), min(ys), max(xs), max(ys), key,
                                                 json.dumps(data, sort_keys=True, separators=(",", ":"))))
    hdr = json.dumps({tag: 1, "release": "test", "source_asset": "generated", "source_sha256": "0" * 64,
                      count: len(lines)}, sort_keys=True, separators=(",", ":"))
    with open(path, "w") as fh:
        fh.write(hdr + "\n" + "".join(lines))
    return path


def sq(x0, y0, x1, y1):
    return [[x0, y0], [x1, y0], [x1, y1], [x0, y1], [x0, y0]]


def synthetic_tzdb(path):
    return _lines_file(path, "apc_tz_boundaries", "zones", [
        ("Europe/Rome", [[sq(10.0, 40.0, 14.0, 44.0), sq(12.0, 42.0, 12.5, 42.5)]], None),       # with a hole
        ("Etc/GMT-1", [[sq(0.0, 30.0, 9.0, 39.0)]], None),
        ("America/New_York", [[sq(-75.0, 39.0, -73.0, 41.0)]], None),
        ("America/Toronto", [[sq(-74.0, 40.0, -72.0, 42.0)]], None),     # overlaps New_York: ambiguous at -73.5 40.5
        ("Pacific/Auckland", [[sq(174.0, -38.0, 176.0, -36.0)], [sq(178.0, -40.0, 179.0, -39.0)]], None)])


def synthetic_admin(path):
    a = lambda iso, name, reg, cc: {"iso_3166_2": iso, "name": name, "region": reg, "country": cc}   # noqa: E731
    return _lines_file(path, "apc_admin_boundaries", "areas", [
        ("ITA-1", [[sq(10.0, 40.0, 12.0, 44.0)]], a("IT-RM", "Roma", "Lazio", "IT")),
        ("ITA-2", [[sq(11.5, 40.0, 14.0, 44.0)]], a(None, "Rieti", None, "IT")),          # overlaps ITA-1
        ("USA-1", [[sq(-75.0, 39.0, -72.0, 42.0)]], a("US-NY", "New York", "Northeast", "US")),
        ("NZL-1", [[sq(174.0, -38.0, 176.0, -36.0)]], a("NZ-WKO", "Waikato", None, "NZ")),
        ("ATA+99?", [[sq(-10.0, -89.0, 10.0, -80.0)]], a(None, None, None, None))])


def fix_sentences(lat, ns, lon, ew, t="120000.00", d="261026", q="1"):
    """GENERATED RMC + GGA of one fix."""
    return (sentence("GPRMC,%s,A,%s,%s,%s,%s,0.0,0.0,%s,,,A" % (t, lat, ns, lon, ew, d)) + "\r\n"
            + sentence("GPGGA,%s,%s,%s,%s,%s,%s,08,0.9,10.0,M,47.0,M,," % (t, lat, ns, lon, ew, q)) + "\r\n").encode()


def tpv(**k):
    """GENERATED gpsd TPV line (class first, as gpsd writes it)."""
    o = {"class": "TPV"}
    o.update(k)
    return json.dumps(o, separators=(",", ":"))


# ------------------------------------------------------------------ a local openssl TSA on 127.0.0.1 (tests only)
TSA = {}
TSA_CNF = """[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
serial = ./serial
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
[ v3_tsa ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
"""


def _ossl(*a, cwd):
    subprocess.run([OPENSSL] + list(a), cwd=cwd, check=True, capture_output=True, timeout=60)


def _make_ca(d, name):
    os.makedirs(d)
    with open(os.path.join(d, "tsa.cnf"), "w") as fh:
        fh.write(TSA_CNF)
    with open(os.path.join(d, "serial"), "w") as fh:
        fh.write("01\n")
    _ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
          "-out", "ca.pem", "-days", "3650", "-subj", "/CN=%s root" % name, "-addext",
          "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
    _ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "tsa.key", "-out",
          "tsa.csr", "-subj", "/CN=%s tsa" % name, cwd=d)
    _ossl("x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.pem",
          "-days", "3650", "-extfile", "tsa.cnf", "-extensions", "v3_tsa", cwd=d)
    return d


class _TsaHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        q = self.rfile.read(int(self.headers["Content-Length"]))
        TSA["queries"].append(q)
        d, mode = TSA["dir"], TSA["mode"]
        t = tempfile.mkdtemp(dir=TSA["tmp"])
        with open(os.path.join(t, "q"), "wb") as fh:
            fh.write(q)
        if mode == "other_digest":          # a token for another digest
            subprocess.run([OPENSSL, "ts", "-query", "-digest", "11" * 32, "-sha256", "-cert", "-out",
                            os.path.join(t, "q")], capture_output=True, timeout=60)
        subprocess.run([OPENSSL, "ts", "-reply", "-config", os.path.join(d, "tsa.cnf"), "-queryfile",
                        os.path.join(t, "q"), "-signer", os.path.join(d, "tsa.pem"), "-inkey",
                        os.path.join(d, "tsa.key"), "-out", os.path.join(t, "r")], cwd=d, capture_output=True,
                       timeout=60)
        b = rd(os.path.join(t, "r")) if mode != "garbage" else b"\x30\x03\x02\x01\x00"
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def setUpModule():
    if not OPENSSL:
        return
    TSA["tmp"] = tempfile.mkdtemp()
    TSA["dir"] = _make_ca(os.path.join(TSA["tmp"], "ca"), "apc test")
    TSA["other"] = _make_ca(os.path.join(TSA["tmp"], "other"), "apc other")
    TSA["mode"], TSA["queries"] = "ok", []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _TsaHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    TSA["srv"], TSA["url"] = srv, "http://127.0.0.1:%d/tsr" % srv.server_port
    TSA["ca"] = os.path.join(TSA["dir"], "ca.pem")


def tearDownModule():
    if "srv" in TSA:
        TSA["srv"].shutdown()
        TSA["srv"].server_close()


# ------------------------------------------------------------------ GPS input
@unittest.skipUnless(NMEA_OK, NMEA_WHY)
class Nmea(unittest.TestCase):
    def test_sources_pinned(self):
        """the copies are the pinned ones (SHA256SUMS), both folders"""
        for d, n in ((NMEA, 5), (GPSD, 5)):
            with open(os.path.join(d, "SHA256SUMS")) as fh:
                rows = [x.split() for x in fh if x.strip()]
            self.assertEqual(len(rows), n)
            for h, f in rows:
                self.assertEqual(hashlib.sha256(rd(os.path.join(d, f))).hexdigest(), h, f)

    def test_real_checksums_all_hold_and_a_flip_breaks_each(self):
        """positive control of the checksum: every RMC/GGA of the real captures holds; one flipped digit breaks it"""
        total = 0
        for n in ("bu353s4.log", "garmin15x.log", "GPSmap-76S.log", "beidou-gb.log", "neo-m8n.log"):
            data = rd(os.path.join(NMEA, n))
            self.assertEqual(rg.parse_nmea(data)[2]["bad_checksum"], 0, n)
            for line in data.decode("ascii", "replace").splitlines():
                if rg.SENTENCE.match(line):
                    total += 1
                    i = line.index(",") + 1
                    bad = line[:i] + ("1" if line[i] != "1" else "2") + line[i + 1:]
                    self.assertEqual(rg.parse_nmea(bad.encode())[2]["bad_checksum"], 1, bad)
        self.assertGreater(total, 50)

    def test_real_captures(self):
        fx, why, _ = rg.parse_nmea(rd(os.path.join(NMEA, "bu353s4.log")))
        self.assertIsNone(why)
        self.assertTrue(fx["lat"].startswith("-37.78") and fx["lon"].startswith("175.31"), fx)
        self.assertEqual(fx["time"].date(), datetime.date(2014, 12, 31))
        last = [x for x in rd(os.path.join(NMEA, "bu353s4.log")).decode().splitlines()
                if x.startswith("$GPRMC")][-1].split(",")
        self.assertAlmostEqual(float(fx["lat"]), -(int(last[3][:2]) + float(last[3][2:]) / 60), places=7)
        fx, why, _ = rg.parse_nmea(rd(os.path.join(NMEA, "garmin15x.log")))
        self.assertTrue(fx["lon"].startswith("-108.37"))
        self.assertEqual((fx["fix_mode"], fx["fix_quality"]), (None, 2))
        fx, why, c = rg.parse_nmea(rd(os.path.join(NMEA, "GPSmap-76S.log")))
        self.assertIsNone(fx)
        self.assertIn("status V", why)
        fx, why, _ = rg.parse_nmea(rd(os.path.join(NMEA, "beidou-gb.log")))
        self.assertTrue(fx["fix_record"].startswith("$GNRMC"))
        fx, why, _ = rg.parse_nmea(rd(os.path.join(NMEA, "neo-m8n.log")))
        self.assertEqual(fx["fix_mode"], "A")
        self.assertTrue(fx["aux_record"].startswith("$GNGGA"))

    # ---- GENERATED edge cases
    def test_midnight_rollover(self):
        d = fix_sentences("4154.0000", "N", "01229.0000", "E", "235959.50", "311226") + \
            fix_sentences("4154.0000", "N", "01229.0000", "E", "000000.50", "010127")
        fx, _, _ = rg.parse_nmea(d)
        self.assertEqual(fx["time"], datetime.datetime(2027, 1, 1, 0, 0, 0, 500000, UTC))
        self.assertEqual(rg.view(fx["time"], "Europe/Rome")["local_day"], "2027-01-01")
        self.assertEqual(rg.view(fx["time"], "America/New_York")["local_day"], "2026-12-31")

    def test_bad_checksum_not_read(self):
        s = fix_sentences("4154.0000", "N", "01229.0000", "E").decode().split("\r\n")
        rmc = s[0][:-2] + ("00" if s[0][-2:] != "00" else "11")
        fx, why, c = rg.parse_nmea((rmc + "\r\n" + s[1] + "\r\n").encode())
        self.assertIsNone(fx)
        self.assertEqual(c["bad_checksum"], 1)

    def test_gga_vetoes(self):
        fx, why, _ = rg.parse_nmea(fix_sentences("4154.0000", "N", "01229.0000", "E", q="0"))
        self.assertIsNone(fx)
        self.assertIn("quality 0", why)
        d = (sentence("GPRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,A") + "\n"
             + sentence("GPGGA,120000.00,4154.0000,N,01230.0000,E,1,08,0.9,10.0,M,47.0,M,,") + "\n").encode()
        self.assertIn("different places", rg.parse_nmea(d)[1])

    def test_modes_not_measured(self):
        for m in ("E", "M", "S", "N"):
            d = sentence("GPRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,%s" % m).encode()
            fx, why, _ = rg.parse_nmea(d)
            self.assertIsNone(fx, m)
            self.assertIn("mode " + m, why)

    def test_unusable_fields(self):
        cases = ["GPRMC,120060.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,A",      # leap second
                 "GPRMC,240000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,A",
                 "GPRMC,120000.00,A,9100.0000,N,01229.0000,E,0.0,0.0,261026,,,A",
                 "GPRMC,120000.00,A,4160.0000,N,01229.0000,E,0.0,0.0,261026,,,A",
                 "GPRMC,120000.00,A,4154.0000,X,01229.0000,E,0.0,0.0,261026,,,A",
                 "GPRMC,120000.00,A,4154.0000,N,18100.0000,E,0.0,0.0,261026,,,A",
                 "GPRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,321026,,,A",
                 "GPRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,2610,,,A",
                 "GPRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,A,V,extra",
                 "GPRMC,120000.00,A,,,,,0.0,0.0,261026,,,A"]
        for b in cases:
            fx, why, c = rg.parse_nmea(sentence(b).encode())
            self.assertIsNone(fx, b)
            self.assertEqual(c["unusable"], 1, b)
        self.assertIn("leap second", rg.parse_nmea(sentence(cases[0]).encode())[1])

    def test_other_talkers_lowercase_and_zero(self):
        s = sentence("GPRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,A")
        self.assertIsNone(rg.parse_nmea(s.lower().encode())[0])
        fx, _, c = rg.parse_nmea(sentence("GLRMC,120000.00,A,4154.0000,N,01229.0000,E,0.0,0.0,261026,,,A").encode())
        self.assertEqual((fx, c["other"]), (None, 1))
        fx, _, _ = rg.parse_nmea(fix_sentences("0000.0000", "S", "00000.0000", "W"))
        self.assertEqual((fx["lat"], fx["lon"]), ("0.0000000", "0.0000000"))


class Gpsd(unittest.TestCase):
    @unittest.skipUnless(NMEA_OK, NMEA_WHY)
    def test_real_gpsd_json(self):
        fx, why, c = rg.parse_gpsd(rd(os.path.join(GPSD, "bu353s4.log.chk")))
        self.assertIsNone(why)
        self.assertEqual((fx["lat"], fx["lon"], fx["fix_mode"]), ("-37.7847950", "175.3149017", "3"))
        self.assertEqual(fx["time"], datetime.datetime(2014, 12, 31, 3, 7, 43, tzinfo=UTC))
        self.assertGreater(c["other"], 0)                       # the NMEA lines gpsd's regression output holds
        fx, why, _ = rg.parse_gpsd(rd(os.path.join(GPSD, "garmin15x.log.chk")))
        self.assertEqual((fx["fix_quality"], fx["satellites"], fx["hdop"]), ("2", 8, "1.1"))
        fx, why, _ = rg.parse_gpsd(rd(os.path.join(GPSD, "GPSmap-76S.log.chk")))
        self.assertIsNone(fx)
        self.assertIn("mode 1", why)
        fx, _, _ = rg.parse_gpsd(rd(os.path.join(GPSD, "neo-m8n.log.chk")))
        self.assertEqual(fx["time"].year, 2034)                 # the decoder's date, not the capture's: DECLARED
        nm, _, _ = rg.parse_nmea(rd(os.path.join(NMEA, "neo-m8n.log")))
        self.assertEqual(nm["time"].year, 2015)
        fx, _, _ = rg.parse_gpsd(rd(os.path.join(GPSD, "beidou-gb.log.chk")))
        self.assertEqual(fx["lat"], "31.2480350")

    def test_generated_cases(self):
        good = tpv(mode=3, time="2026-10-26T12:00:00.000Z", lat=41.9, lon=12.5)
        fx, _, _ = rg.parse_gpsd(good.encode())
        self.assertEqual((fx["lat"], fx["lon"], fx["aux_record"]), ("41.9000000", "12.5000000", None))
        for st in (5, 7, 8):
            fx, why, _ = rg.parse_gpsd(tpv(mode=3, status=st, time="2026-10-26T12:00:00Z", lat=1, lon=1).encode())
            self.assertIsNone(fx)
            self.assertIn("status %d" % st, why)
        for m in (0, 1):
            self.assertIsNone(rg.parse_gpsd(tpv(mode=m, time="2026-10-26T12:00:00Z", lat=1, lon=1).encode())[0])
        self.assertIn("without", rg.parse_gpsd(tpv(mode=3, lat=1, lon=1).encode())[1])
        self.assertIn("leap second", rg.parse_gpsd(tpv(mode=3, time="2026-10-26T12:00:60Z", lat=1, lon=1).encode())[1])
        for bad in (tpv(mode="3", time="2026-10-26T12:00:00Z", lat=1, lon=1),
                    tpv(mode=True, time="2026-10-26T12:00:00Z", lat=1, lon=1),
                    tpv(mode=3, status=10, time="2026-10-26T12:00:00Z", lat=1, lon=1),
                    tpv(mode=3, status=2.0, time="2026-10-26T12:00:00Z", lat=1, lon=1),
                    tpv(mode=3, time="2026-10-26T12:00:60Z", lat=1, lon=1),
                    tpv(mode=3, time="2026-10-26 12:00:00Z", lat=1, lon=1),
                    tpv(mode=3, time="2026-10-26T12:00:00Z", lat=91, lon=1),
                    tpv(mode=3, time="2026-10-26T12:00:00Z", lat="1", lon=1),
                    tpv(mode=3, time="2026-10-26T12:00:00Z", lat=True, lon=1),
                    tpv(mode=3, time="2026-10-26T12:00:00Z", lat=1, lon=181),
                    '{"class":"TPV","mode":3,"mode":3,"time":"2026-10-26T12:00:00Z","lat":1,"lon":1}',
                    '{"class":"TPV","mode":3,"time":"2026-10-26T12:00:00Z","lat":NaN,"lon":1}'):
            fx, why, c = rg.parse_gpsd(bad.encode())
            self.assertIsNone(fx, bad)
            self.assertEqual(c["unusable"], 1, bad)

    def test_sky_association(self):
        a = '{"class":"SKY","time":"2026-10-26T12:00:01Z","uSat":9,"hdop":0.8}'
        b = '{"class":"SKY","uSat":5,"hdop":1.5}'
        c = '{"class":"SKY","satellites":[{"used":true},{"used":false},{"used":true}],"hdop":2}'
        t = tpv(mode=3, time="2026-10-26T12:00:01Z", lat=1, lon=1)
        fx, _, _ = rg.parse_gpsd("\n".join([b, t, a]).encode())          # same time wins, even after
        self.assertEqual((fx["aux_record"], fx["satellites"], fx["hdop"]), (a, 9, "0.8"))
        fx, _, _ = rg.parse_gpsd("\n".join([b, t]).encode())             # else the last before
        self.assertEqual((fx["satellites"], fx["hdop"]), (5, "1.5"))
        fx, _, _ = rg.parse_gpsd("\n".join([c, t]).encode())
        self.assertEqual((fx["satellites"], fx["hdop"]), (2, "2.0"))
        fx, _, _ = rg.parse_gpsd("\n".join([t, b]).encode())             # a later SKY of another time: none
        self.assertIsNone(fx["aux_record"])

    def test_socket_localhost(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        got = []

        def serve():
            c, _ = srv.accept()
            got.append(c.recv(200))
            c.sendall(rd(os.path.join(GPSD, "garmin15x.log.chk")))
            c.close()
        th = threading.Thread(target=serve)
        th.start()
        try:
            data = rg.read_gpsd_socket(port, 5)
        finally:
            th.join()
            srv.close()
        self.assertTrue(got[0].startswith(b'?WATCH={"enable":true,"json":true}'))
        fx, why, _ = rg.parse_gpsd(data)
        self.assertEqual(fx["fix_quality"], "2")


# ------------------------------------------------------------------ zone and region
class Zone(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = synthetic_tzdb(os.path.join(cls.tmp, "tz.apc-tzb"))
        cls.adm = synthetic_admin(os.path.join(cls.tmp, "adm.apc-adm"))

    def place(self, lat, lon):
        return rg.place_record({"lat": lat, "lon": lon}, self.db)

    def test_statuses(self):
        p, b = self.place("41.0000000", "11.0000000")
        self.assertEqual((p["status"], p["zone"], p["zone_basis"], p["country"]),
                         ("established", "Europe/Rome", "boundary", "IT"))
        self.assertFalse(b["pinned"])
        p, _ = self.place("42.2500000", "12.2500000")            # in the hole
        self.assertEqual((p["status"], p["zone"]), ("no_zone_in_file", "Etc/GMT-1"))
        p, _ = self.place("35.0000000", "5.0000000")
        self.assertEqual((p["status"], p["zone"], p["zone_basis"], p["country"]),
                         ("at_sea", "Etc/GMT-1", "ocean_polygon", None))
        p, _ = self.place("40.5000000", "-73.5000000")
        self.assertEqual((p["status"], p["candidates"], p["zone_basis"], p["zone"]),
                         ("ambiguous", ["America/New_York", "America/Toronto"], "longitude_derived", "Etc/GMT+5"))
        p, _ = self.place("-39.5000000", "178.5000000")           # the second polygon of a MultiPolygon
        self.assertEqual(p["zone"], "Pacific/Auckland")
        p, b = rg.place_record({"lat": "41.0000000", "lon": "11.0000000"}, None)
        self.assertEqual((p["status"], p["zone"], b), ("no_boundary_file", "Etc/GMT-1", None))

    def test_region(self):
        fx = {"lat": "41.0000000", "lon": "11.0000000"}
        r = rg.region_record(fx, self.adm)
        self.assertEqual((r["status"], r["areas"][0]["iso_3166_2"], r["areas"][0]["region"]),
                         ("established", "IT-RM", "Lazio"))
        r = rg.region_record({"lat": "41.0000000", "lon": "11.8000000"}, self.adm)    # in the overlap
        self.assertEqual((r["status"], [a["adm1_code"] for a in r["areas"]]), ("ambiguous", ["ITA-1", "ITA-2"]))
        r = rg.region_record({"lat": "0.0000000", "lon": "0.0000000"}, self.adm)
        self.assertEqual((r["status"], r["areas"]), ("none", []))
        r = rg.region_record({"lat": "-85.0000000", "lon": "0.0000000"}, self.adm)
        self.assertEqual(r["areas"][0], {"adm1_code": "ATA+99?", "iso_3166_2": None, "name": None, "region": None,
                                         "country": None})
        self.assertEqual(rg.region_record(fx, None), {"status": "no_admin_file"})

    def test_pinned_needs_both_digests(self):
        """GENERATED pin table: pinned only when release, source digest AND file digest are the pinned ones"""
        for table, path, fn in ((rg.PINNED_BOUNDARIES, self.db, lambda: self.place("41.0000000", "11.0000000")[1]),
                                (rg.PINNED_ADMIN, self.adm,
                                 lambda: rg.region_record({"lat": "41.0000000", "lon": "11.0000000"},
                                                          self.adm)["dataset"])):
            fsha = hashlib.sha256(rd(path)).hexdigest()
            saved = dict(table)
            try:
                for pin, want in ((("0" * 64, fsha), True), (("0" * 64, "1" * 64), False), (("1" * 64, fsha), False)):
                    table["test"] = pin
                    self.assertEqual(fn()["pinned"], want, pin)
            finally:
                table.clear()
                table.update(saved)

    def test_nautical(self):
        import zoneinfo
        for lon, z in ((0, "Etc/GMT"), (7.4999, "Etc/GMT"), (7.5, "Etc/GMT-1"), (-7.5, "Etc/GMT"),
                       (-7.5001, "Etc/GMT+1"), (180, "Etc/GMT-12"), (-180, "Etc/GMT+12"), (172.5, "Etc/GMT-12"),
                       (-112.5, "Etc/GMT+7")):
            self.assertEqual(rg.nautical_zone(lon), z, lon)
            zoneinfo.ZoneInfo(z)

    def test_bad_files(self):
        good, agood = rd(self.db), rd(self.adm)
        cases = {"header": (b'{"x":1}\n' + good.split(b"\n", 1)[1], "tz"),
                 "count": (good.replace(b'"zones":5', b'"zones":6'), "tz"),
                 "line": (good + b"garbage\n", "tz"),
                 "zone": (good.replace(b"\tEurope/Rome\t", b"\tEurope/Rome?\t"), "tz"),
                 "polys": (good.replace(b"[[[[10.0,40.0]", b"[[[[10.0,40.0"), "tz"),
                 "noncanonical header": (good.replace(b'{"apc_tz_boundaries":1,', b'{"apc_tz_boundaries": 1,'), "tz"),
                 "tz file as admin": (good, "admin"), "admin file as tz": (agood, "tz"),
                 "area member": (agood.replace(b'"country":"IT"', b'"country":"IT","x":1', 1), "admin"),
                 "area iso": (agood.replace(b'"IT-RM"', b'"IT-RM~"'), "admin"),
                 "area name control": (agood.replace(b'"Roma"', b'"Ro\\u0001ma"'), "admin"),
                 "area key": (agood.replace(b"\tITA-1\t", b"\tITA_1\t"), "admin")}
        for name, (b, kind) in cases.items():
            p = os.path.join(self.tmp, "bad")
            with open(p, "wb") as fh:
                fh.write(b)
            with self.assertRaises(rg.Bad, msg=name):
                rg.boundary_lookup(p, "41.0000000", "11.0000000", kind)

    @unittest.skipUnless(os.path.isfile(REAL_TZDB), "real tz boundary file not present (tools/fetch_tz_boundaries.py)")
    def test_real_boundaries(self):
        for lat, lon, z, st in (("41.9028000", "12.4964000", "Europe/Rome", "established"),
                                ("43.9356000", "12.4473000", "Europe/San_Marino", "established"),
                                ("40.7128000", "-74.0060000", "America/New_York", "established"),
                                ("33.4484000", "-112.0740000", "America/Phoenix", "established"),
                                ("-37.7870000", "175.2793000", "Pacific/Auckland", "established"),
                                ("53.3498000", "-6.2603000", "Europe/Dublin", "established"),
                                ("40.0000000", "-40.0000000", "Etc/GMT+3", "at_sea")):
            p, b = rg.place_record({"lat": lat, "lon": lon}, REAL_TZDB)
            self.assertEqual((p["zone"], p["status"]), (z, st), (lat, lon))
            self.assertTrue(b["pinned"])

    @unittest.skipUnless(os.path.isfile(REAL_ADMIN), "real admin-1 file not present (tools/fetch_admin_boundaries.py)")
    def test_real_admin(self):
        for lat, lon, iso in (("41.9028000", "12.4964000", "IT-RM"), ("45.4642000", "9.1900000", "IT-MI"),
                              ("40.7128000", "-74.0060000", "US-NY"), ("-37.7870000", "175.2793000", "NZ-WKO"),
                              ("32.6485383", "-108.3742667", "US-NM")):
            r = rg.region_record({"lat": lat, "lon": lon}, REAL_ADMIN)
            self.assertEqual((r["status"], r["areas"][0]["iso_3166_2"]), ("established", iso), (lat, lon))
            self.assertTrue(r["dataset"]["pinned"])
        self.assertEqual(rg.region_record({"lat": "40.0000000", "lon": "-40.0000000"}, REAL_ADMIN)["status"], "none")


class Views(unittest.TestCase):
    def at(self, s):
        return datetime.datetime.fromisoformat(s).replace(tzinfo=UTC)

    def test_dst_cases(self):
        """the owner's probe of 24/10 (tzdata 2026e) and the negative-DST zones"""
        for t, z, off, kind in (("2026-10-24T09:00:00", "Europe/Rome", "+02:00", "summer_time"),
                                ("2026-10-25T00:59:59", "Europe/Rome", "+02:00", "summer_time"),
                                ("2026-10-25T01:00:00", "Europe/Rome", "+01:00", "standard_time"),
                                ("2026-07-01T12:00:00", "America/Phoenix", "-07:00", "standard_time"),
                                ("2026-07-01T12:00:00", "America/Denver", "-06:00", "summer_time"),
                                ("2026-12-01T12:00:00", "Australia/Sydney", "+11:00", "summer_time"),
                                ("2026-10-24T09:00:00", "Asia/Kolkata", "+05:30", "standard_time"),
                                ("2026-01-15T12:00:00", "Europe/Dublin", "+00:00", "negative_dst"),
                                ("2026-07-15T12:00:00", "Europe/Dublin", "+01:00", "standard_time")):
            v = rg.view(self.at(t), z)
            self.assertEqual((v["utc_offset"], v["time_kind"]), (off, kind), (t, z))
        self.assertEqual(rg.view(self.at("2026-10-24T09:00:00.500000"), "Pacific/Auckland")["local_time"],
                         "2026-10-24T22:00:00+13:00")

    def test_tzdata_version(self):
        self.assertRegex(rg.tzdata_info("Europe/Rome")[0], r"^(\d{4}[a-z]{1,2}|unknown)$")


# ------------------------------------------------------------------ the register
@functools.lru_cache(maxsize=None)
def _verify_cached(pub, msg, sig):
    return _REAL_VERIFY(pub, msg, sig)


@functools.lru_cache(maxsize=None)
def _sign_cached(seed, msg):
    return sol.ed25519_sign(seed, msg)


_REAL_VERIFY = sol.ed25519_verify


class Register(unittest.TestCase):
    """A register with every entry kind, built in-process. Ed25519 results are cached by their exact inputs (the
    same function, computed once per distinct input) so the generative tests stay fast."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = synthetic_tzdb(os.path.join(cls.tmp, "tz.apc-tzb"))
        cls.adm = synthetic_admin(os.path.join(cls.tmp, "adm.apc-adm"))
        cls.reg = os.path.join(cls.tmp, "reg.jsonl")
        rg.cmd_init(cls.reg)
        tsa = (TSA["url"], TSA["ca"]) if OPENSSL else None
        rg.cmd_record(cls.reg, None, bundle_in(), nmea_in(fix_sentences("4100.0000", "N", "01100.0000", "E")),
                      cls.db, cls.adm, SEED, tsa)                                       # 1 check, 2 timestamp, 3 seal
        with open(cls.reg, "ab") as fh:
            fh.write(b'{"apc_reg')                                                       # a torn line
        rg.cmd_record(cls.reg, SMALL_REPORT, None,
                      ("gpsd_json", "file", (tpv(mode=3, status=2, time="2026-10-26T12:00:00.000Z", lat=40.5,
                                                 lon=-73.5) + "\n" + '{"class":"SKY","uSat":7,"hdop":0.9}\n').encode()),
                      cls.db, cls.adm, None)                                             # 4 torn, 5 ambiguous zone
        rg.cmd_record(cls.reg, SMALL_REPORT, None, nmea_in(fix_sentences("3500.0000", "N", "00500.0000", "E")),
                      cls.db, cls.adm, SEED)                                             # 6 at sea, region none; 7 seal
        rg.cmd_record(cls.reg, SMALL_REPORT, None, nmea_in(b"$GPRMC,junk*00\n"), cls.db, None, None)   # 8 no fix
        rg.cmd_record(cls.reg, SMALL_REPORT, None, None, None, None, None)              # 9 no source
        with open(cls.reg, "rb") as fh:
            cls.lines = [json.loads(x) for x in fh.read().splitlines()]
        cls.ts = 2 if OPENSSL else None
        cls.patch = mock.patch.object(sol, "ed25519_verify", _verify_cached)
        cls.patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()

    def test_built(self):
        kinds = [e["kind"] for e in self.lines]
        want = ["open", "check", "timestamp", "seal", "torn_tail", "check", "check", "seal", "check", "check"]
        if not OPENSSL:
            want.remove("timestamp")
        self.assertEqual(kinds, want)
        self.assertIsNone(rg.read_register(self.reg)[1])
        c = self.get_check(1)
        self.assertEqual((c["declared"]["place"]["zone"], c["declared"]["region"]["areas"][0]["iso_3166_2"]),
                         ("Europe/Rome", "IT-RM"))
        self.assertEqual(c["proven"]["bundle_sha256"], hashlib.sha256(rd(BUNDLE)).hexdigest())
        self.assertEqual(c["proven"]["rerun"]["report_sha256"], c["proven"]["report_sha256"])
        self.assertIsNotNone(c["proven"]["block_time"])
        c = self.get_check(5)
        self.assertEqual((c["declared"]["gps"]["format"], c["declared"]["gps"]["fix_quality"],
                          c["declared"]["place"]["status"], c["declared"]["region"]["status"]),
                         ("gpsd_json", "2", "ambiguous", "established"))
        self.assertEqual(self.get_check(6)["declared"]["region"]["status"], "none")
        self.assertEqual(self.get_check(8)["declared"]["region"]["status"], "not_established")
        self.assertEqual(self.get_check(9)["declared"]["gps"], {"status": "no_source"})

    def get_check(self, n):
        k = [e for e in self.lines if e["kind"] == "check"]
        return {1: k[0], 5: k[1], 6: k[2], 8: k[3], 9: k[4]}[n]["body"]

    # ---- the re-chainer: what the generative tests change is ONLY the mutation, the chain is made right again
    def rechain(self, lines, start=0, hold=False):
        """hold: the entry at `start` keeps its prev, head, signature and timestamp link (the mutation may be there)"""
        out = copy.deepcopy(lines)
        prev = out[start - 1]["hash"] if start else rg.ZERO
        for i in range(start, len(out)):
            e = out[i]
            if isinstance(e, dict):
                keep = hold and i == start
                if "prev" in e and not keep:
                    e["prev"] = prev
                b = e.get("body") if isinstance(e.get("body"), dict) else {}
                if e.get("kind") == "seal" and "signature" in b and not keep:
                    b["head"] = prev
                    b["signature"] = _sign_cached(SEED, rg.seal_message(b["from_seq"], b["to_seq"], prev,
                                                                        b["public_key"])).hex()
                e.pop("hash", None)
                e["hash"] = hashlib.sha256(rg.canonical(e)).hexdigest()
                prev = e["hash"]
        return out

    def write(self, lines, raw=None):
        p = os.path.join(self.tmp, "m.jsonl")
        with open(p, "wb") as fh:
            fh.write(raw if raw is not None else b"".join(rg.canonical(e) + b"\n" for e in lines))
        return p

    def refused(self, lines, why, raw=None):
        with self.assertRaises(rg.Damaged, msg=why):
            rg.read_register(self.write(lines, raw))

    def refused_at(self, i, e, why):
        """the register up to entry i, with entry i replaced by e (re-hashed): refused AT line i + 1, so a later entry
        that no longer links (a timestamp, a seal) cannot hide a mutation that entry i's grammar lets through"""
        e = copy.deepcopy(e)
        if isinstance(e, dict):
            e.pop("hash", None)
            try:
                e["hash"] = hashlib.sha256(rg.canonical(e)).hexdigest()
            except rg.Bad:
                e["hash"] = "0" * 64
            line = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        else:
            line = json.dumps(e).encode()
        raw = b"".join(rg.canonical(x) + b"\n" for x in self.lines[:i]) + line + b"\n"
        with self.assertRaises(rg.Damaged, msg=why) as cm:
            rg.read_register(self.write(None, raw))
        self.assertTrue(str(cm.exception).startswith("line %d" % (i + 1)), "%s: %s" % (why, cm.exception))

    def test_rechain_positive_control(self):
        """the re-chainer gives an intact register on unmutated entries, so a refusal below is the mutation's"""
        p = self.write(self.rechain(self.lines))
        rg.read_register(p)
        self.assertEqual(rd(p), rd(self.reg))

    def paths(self, x, path=()):
        yield path, x
        if isinstance(x, dict):
            if path[-1:] == ("report",):
                for k in sorted(x):
                    yield path + (k,), x[k]          # inside the carried report: its top level only
                return
            for k in sorted(x):
                yield from self.paths(x[k], path + (k,))
        elif isinstance(x, list):
            for i, v in enumerate(x):
                yield from self.paths(v, path + (i,))

    @staticmethod
    def get(e, path):
        for k in path:
            e = e[k]
        return e

    @staticmethod
    def swaps(v):
        if v is None:
            return [True, 10 ** 6, [], {}]          # 10**6: outside every nullable integer's range
        if isinstance(v, bool):
            return [1, 0, "x", []]
        if isinstance(v, int):
            return [True, "x", [], str(v)]
        if isinstance(v, str):
            return [True, 7, [], {}]
        if isinstance(v, list):
            return [True, 7, "x", {}]
        return [True, 7, "x", []]

    def test_generative_closed_grammar(self):
        """every entry, every level: an unknown member, each member removed, each value of a wrong type"""
        for i in range(len(self.lines)):                   # positive control of refused_at: the entry as it is reads
            p = self.write(None, b"".join(rg.canonical(x) + b"\n" for x in self.lines[:i + 1]))
            rg.read_register(p)
        n = 0
        for i, e in enumerate(self.lines):
            for path, v in list(self.paths(e)):
                if isinstance(v, dict):
                    for extra in ("x", "Hash"):
                        m = copy.deepcopy(e)
                        self.get(m, path)[extra] = 1
                        self.refused_at(i, m, "unknown %s at %d %s" % (extra, i, path))
                        n += 1
                    for k in list(v):
                        if path == () and k == "hash":
                            continue
                        m = copy.deepcopy(e)
                        del self.get(m, path)[k]
                        self.refused_at(i, m, "missing %s at %d %s" % (k, i, path))
                        n += 1
                if path and path != ("hash",):
                    for s in self.swaps(v):
                        m = copy.deepcopy(e)
                        self.get(m, path[:-1])[path[-1]] = s
                        self.refused_at(i, m, "type %r at %d %s" % (s, i, path))
                        n += 1
        self.assertGreater(n, 1000)

    def mutate(self, i, path, v):
        m = copy.deepcopy(self.lines[i])
        self.get(m, path[:-1])[path[-1]] = v
        return m

    def test_values_outside_the_grammar(self):
        """GENERATED: values of the right type that the grammar does not allow"""
        k = {e: j for j, e in enumerate(i for i, x in enumerate(self.lines) if x["kind"] == "check")}
        c1, c5, c6, c8, c9 = sorted(k)
        g, d, pr = ("body", "declared", "gps"), ("body", "declared"), ("body", "proven")
        cases = [(c1, g + ("lat",), "41.000000"), (c1, g + ("lat",), "91.0000000"), (c1, g + ("fix_mode",), "S"),
                 (c1, g + ("fix_quality",), 0), (c1, g + ("fix_quality",), 6), (c1, g + ("fix_quality",), "2"),
                 (c1, g + ("time_utc",), "2026-02-30T00:00:00Z"), (c1, g + ("time_utc",), "2026-10-26T12:00:00.5Z"),
                 (c1, g + ("format",), "gpsd_json"), (c1, g + ("source",), "socket"),
                 (c1, g + ("fix_record",), "$GPGGA,1"), (c1, g + ("counts",), dict.fromkeys(rg.COUNTS["gpsd_json"], 0)),
                 (c5, g + ("fix_mode",), "1"), (c5, g + ("fix_quality",), "8"), (c5, g + ("fix_quality",), 2),
                 (c5, g + ("fix_record",), '{"class":"SKY"}'), (c5, g + ("fix_record",), "TPV"),
                 (c5, g + ("source",), "serial"), (c5, g + ("hdop",), "0.9000"),
                 (c1, d + ("place", "zone_basis"), "ocean_polygon"), (c1, d + ("place", "country_basis"), None),
                 (c1, d + ("local", "zone"), "Europe/Paris"),
                 (c1, d + ("local", "at_gps", "time_kind"), "summer_time"),
                 (c1, d + ("local", "at_gps", "local_day"), "2000-01-01"),
                 (c1, d + ("local", "at_gps", "utc_offset"), "+05:00"),
                 (c1, d + ("region", "status"), "none"), (c1, d + ("region", "status"), "no_admin_file"),
                 (c1, d + ("region", "areas", 0, "iso_3166_2"), "IT-RM~"),
                 (c1, d + ("region", "areas", 0, "name"), "a\tb"), (c1, d + ("region", "areas", 0, "adm1_code"), "ITA"),
                 (c5, d + ("region", "areas"), []), (c6, d + ("region", "status"), "established"),
                 (c5, d + ("region",), dict(self.lines[c5]["body"]["declared"]["region"], areas=[
                     dict(self.lines[c5]["body"]["declared"]["region"]["areas"][0], adm1_code="ITA-%d" % j)
                     for j in range(1, 10)])),
                 (c5, g + ("counts",), dict(self.lines[c5]["body"]["declared"]["gps"]["counts"], rmc=0)),
                 (c8, d + ("region", "status"), "no_admin_file"), (c9, d + ("region",), {"status": "no_admin_file"}),
                 (c1, pr + ("verdict",), "chain_failed"), (c1, pr + ("bundle_sha256",), None),
                 (c1, pr + ("rerun",), None), (c6, pr + ("rerun",), {"verifier": "apc_verify 0.8.0", "options": {
                     "l1_checkpoint": None, "http_keys_sha256": None}, "report_sha256": "0" * 64,
                     "verdict": "chain_verified"}),
                 (c1, pr + ("rerun", "verdict"), "chain_failed"), (c1, pr + ("rerun", "report_sha256"), "0" * 64),
                 (c1, pr + ("rerun", "verifier"), "apc_verify 9"),
                 (c1, pr + ("rerun", "options", "l1_checkpoint"), "0x" + "A" * 64),
                 (c1, pr + ("block_time", "block_bound"), not self.lines[c1]["body"]["proven"]["block_time"][
                     "block_bound"]),
                 (c1, ("body", "tz", "boundaries"), None), (c1, ("body", "tz", "tzdata_version"), "26e"),
                 (c8, ("body", "tz", "boundaries"), {"release": "x", "source_sha256": "0" * 64,
                                                     "file_sha256": "0" * 64, "pinned": False}),
                 (c5, d + ("place", "candidates"), ["America/New_York"]),
                 (c5, d + ("place", "candidates"), ["America/New_York", "America/New_York"]),
                 (c8, d + ("local",), {}), (c9, g + ("status",), "fix"),
                 (0, ("body", "consent"), "yes"), (0, ("kind",), "check"), (c1, ("kind",), "open"),
                 (0, ("apc_register",), "apc-reg-0.1"), (4 if OPENSSL else 3, ("body", "dropped_bytes"), 0)]
        seal = 3 if OPENSSL else 2
        cases += [(seal, ("body", "key_id"), "0" * 16), (seal, ("body", "from_seq"), 1),
                  (seal, ("body", "to_seq"), 1), (seal, ("body", "public_key"), sol.ed25519_public(SEED2).hex())]
        if OPENSSL:
            t = ("body",)
            tok = self.lines[2]["body"]["token_b64"]
            cases += [(2, t + ("of_seq",), 0), (2, t + ("of_hash",), "0" * 64), (2, t + ("trust",), "freetsa_pinned"),
                      (2, t + ("gen_time_utc",), "2000-01-01T00:00:00.000000Z"), (2, t + ("token_b64",), tok + "="),
                      (2, t + ("token_b64",), tok[:-8]), (2, t + ("token_b64",), "MAMCAQA="),
                      (2, t + ("tsa_url",), "ftp://x"), (2, t + ("kind",), "check"),
                      (2, t + ("token_b64",), self.token_with(lambda der: der.replace(
                          b"\x30\x03\x02\x01\x00", b"\x30\x03\x02\x01\x02", 1)))]
            if tok.endswith("="):                     # the same bytes in a non-canonical base64 (padding bits set)
                alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                j = len(tok.rstrip("=")) - 1
                alt = tok[:j] + alpha[alpha.index(tok[j]) ^ 1] + tok[j + 1:]
                import base64
                self.assertEqual(base64.b64decode(alt), base64.b64decode(tok))
                cases.append((2, t + ("token_b64",), alt))
        for i, path, v in cases:
            self.refused_at(i, self.mutate(i, path, v), "%d %s %r" % (i, path, v))

    def token_with(self, change):
        import base64
        return base64.b64encode(change(base64.b64decode(self.lines[2]["body"]["token_b64"]))).decode()

    def test_token_of_another_entry(self):
        """a real token on another digest: refused as of_hash != prev, and as not stamping of_hash"""
        if not OPENSSL:
            self.skipTest("openssl not on PATH")
        other = rg.tsa_stamp(TSA["url"], TSA["ca"], "22" * 32)
        e = copy.deepcopy(self.lines[2])
        e["body"].update(other)
        e["body"]["of_hash"] = "22" * 32                        # stamped, but not the check before
        self.refused_at(2, e, "of_hash not prev")
        e["body"]["of_hash"] = self.lines[1]["hash"]            # the check before, but the token stamps another
        self.refused_at(2, e, "token not of of_hash")
        der = bytearray(__import__("base64").b64decode(self.lines[2]["body"]["token_b64"]))
        k = bytes(der).rindex(rg.OID_SHA256, 0, bytes(der).index(bytes.fromhex(self.lines[1]["hash"])))   # the imprint's
        der[k + len(rg.OID_SHA256) - 1] = 3                     # sha512's OID, same length
        with self.assertRaises(ValueError):
            rg.tsa_reply_fields(bytes(der))

    def test_timestamp_position(self):
        """a timestamp after something other than a check, or of another entry, is damage"""
        if not OPENSSL:
            self.skipTest("openssl not on PATH")
        m = copy.deepcopy(self.lines[:5])                      # open, check, timestamp, seal, torn_tail
        body = rg.tsa_stamp(TSA["url"], TSA["ca"], m[4]["hash"])  # a real token on the torn_tail entry
        e = {"apc_register": rg.FORMAT, "seq": 5, "prev": m[4]["hash"], "kind": "timestamp",
             "body": dict(body, of_seq=4, of_hash=m[4]["hash"])}
        e["hash"] = hashlib.sha256(rg.canonical(e)).hexdigest()
        rg.check_entry(e, "x", 5, m[4]["hash"])                # the entry itself is in the grammar ...
        with self.assertRaises(rg.Damaged) as cm:
            rg.read_register(self.write(m + [e]))
        self.assertIn("follows a check", str(cm.exception))   # ... its place is not

    def test_negative_dst_entry(self):
        """an entry in Europe/Dublin in January (tzdata: dst -1 h) reads; calling it summer time does not"""
        m = copy.deepcopy(self.lines)
        d = m[1]["body"]["declared"]
        jan = datetime.datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
        d["place"]["zone"], d["place"]["country"] = "Europe/Dublin", "IE"
        d["local"] = {"zone": "Europe/Dublin", "at_clock": rg.view(jan, "Europe/Dublin"),
                      "at_gps": rg.view(jan, "Europe/Dublin")}
        self.assertEqual(d["local"]["at_gps"]["time_kind"], "negative_dst")
        if OPENSSL:
            del m[2]                                           # the token stamps the old entry
            for j in range(2, len(m)):
                m[j]["seq"] = j
            m[2]["body"]["from_seq"], m[2]["body"]["to_seq"] = 0, 1
            m[6]["body"]["from_seq"], m[6]["body"]["to_seq"] = 3, 5
        rg.read_register(self.write(self.rechain(m, 1)))
        for kind in ("summer_time", "standard_time"):
            m2 = copy.deepcopy(m)
            m2[1]["body"]["declared"]["local"]["at_clock"]["time_kind"] = kind
            self.refused(self.rechain(m2, 1), kind)

    def test_seal_by_another_key_and_named_key(self):
        rg.read_register(self.reg, sol.ed25519_public(SEED).hex())
        with self.assertRaises(rg.Damaged):
            rg.read_register(self.reg, sol.ed25519_public(SEED2).hex())
        seal = 3 if OPENSSL else 2
        m = copy.deepcopy(self.lines)
        b = m[seal]["body"]
        pub = sol.ed25519_public(SEED2).hex()
        b["public_key"], b["key_id"] = pub, hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:16]
        self.refused(self.rechain(m, seal), "signature by another key")

    def test_duplicates_every_object(self):
        """a member written twice, in every object of every entry, is refused by the strict reader"""
        def dump(x, target, path=()):
            if isinstance(x, dict):
                parts = [json.dumps(k) + ":" + dump(v, target, path + (k,)) for k, v in sorted(x.items())]
                if path == target and parts:
                    parts.append(parts[0])
                return "{" + ",".join(parts) + "}"
            if isinstance(x, list):
                return "[" + ",".join(dump(v, target, path + (i,)) for i, v in enumerate(x)) + "]"
            return json.dumps(x, ensure_ascii=False)
        n = 0
        canon = [rg.canonical(x) for x in self.lines]
        for i, e in enumerate(self.lines):
            for path, v in self.paths(e):
                if isinstance(v, dict) and v:
                    raw = b"".join((dump(x, path).encode() if j == i else canon[j]) + b"\n"
                                   for j, x in enumerate(self.lines))
                    with self.assertRaises(rg.Damaged) as cm:
                        rg.read_register(self.write(None, raw))
                    self.assertIn("duplicate", str(cm.exception))
                    n += 1
        self.assertGreater(n, 40)

    def test_non_canonical_lines(self):
        base = b"".join(rg.canonical(e) + b"\n" for e in self.lines).split(b"\n")
        for i in range(len(self.lines)):
            for bad in (base[i].replace(b":", b": ", 1), base[i] + b" ", b" " + base[i],
                        base[i].replace(b"{", b"{ ", 1), base[i] + b"\r",
                        base[i].replace(b'"seq":%d' % i, b'"seq":%d.0' % i),
                        base[i].replace(b'"seq":%d' % i, b'"seq":%de0' % i),
                        base[i].replace(b'"apc_register":"apc-reg-0.2"', b'"apc_register":"apc-reg-0.\\u0032"')):
                raw = b"\n".join(base[:i] + [bad] + base[i + 1:])
                self.refused(None, "non canonical line %d" % i, raw)

    def test_forged_chain(self):
        good = self.lines
        self.refused(good[:2] + good[3:], "a middle line removed")
        self.refused(good[:2] + [good[3], good[2]] + good[4:], "two lines swapped")
        self.refused(good[:5] + [good[5]] + good[5:], "a line repeated")
        self.refused(self.rechain(good[:5] + good[6:]), "a line removed, re-chained: seq")
        m = copy.deepcopy(good)
        m[1]["body"]["declared"]["clock_utc"] = "2026-10-26T00:00:00.000000Z"
        self.refused(m, "a body changed without the hash")
        self.refused(self.rechain(m, 1), "a check changed and re-hashed: its token and seal no longer hold")
        self.refused([dict(good[0], seq=1)] + good[1:], "first seq")
        raw = rd(self.reg)
        rnd = random.Random(20261026)
        for _ in range(300):
            k = rnd.randrange(len(raw) - 1)
            b = bytearray(raw)
            b[k] ^= 1 << rnd.randrange(8)
            self.refused(None, "bit flip at %d" % k, bytes(b))

    def test_torn_tail_every_offset(self):
        raw = rd(self.reg)
        last = raw[:-1].rfind(b"\n") + 1
        for cut in range(last + 1, len(raw)):
            entries, torn = rg.read_register(self.write(None, raw[:cut]))
            self.assertEqual((len(entries), torn), (len(self.lines) - 1, (last, raw[last:cut])))
        self.assertIsNone(rg.read_register(self.write(None, raw[:last]))[1])     # whole lines gone: SPEC 11.3 limit
        self.refused(None, "empty", b"")
        self.refused(None, "only torn", b'{"apc')
        self.refused(None, "torn tail too long", raw + b"x" * (rg.MAX_LINE + 1))
        self.refused(None, "binary", b"\xff\xfe\n")


# ------------------------------------------------------------------ RFC 3161 with the local authority
@unittest.skipUnless(OPENSSL, "openssl not on PATH")
class Timestamp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.reg = os.path.join(self.tmp, "reg.jsonl")
        rg.cmd_init(self.reg)
        TSA["mode"], TSA["queries"] = "ok", []

    def tearDown(self):
        TSA["mode"] = "ok"

    def test_only_the_digest_leaves(self):
        out = rg.cmd_record(self.reg, SMALL_REPORT, None, nmea_in(fix_sentences("4100.0000", "N", "01100.0000", "E")),
                            None, None, None, (TSA["url"], TSA["ca"]))
        entries, _ = rg.read_register(self.reg)
        self.assertEqual([e["kind"] for e in entries], ["open", "check", "timestamp"])
        self.assertEqual(len(TSA["queries"]), 1)
        q = TSA["queries"][0]
        self.assertIn(bytes.fromhex(entries[1]["hash"]), q)          # the digest is in the request ...
        self.assertNotIn(b"41.0", q)                                 # ... and nothing of the check itself
        self.assertLess(len(q), 120)
        self.assertEqual(out["timestamp"]["trust"], "user_ca")
        self.assertEqual(rg.recheck_timestamps(entries, TSA["ca"]), (1, 0))
        other = os.path.join(TSA["other"], "ca.pem")
        self.assertEqual(rg.recheck_timestamps(entries, other), (0, 1))

    def test_refusals_write_nothing(self):
        before = rd(self.reg)
        args = (self.reg, SMALL_REPORT, None, None, None, None, None)
        for mode in ("garbage", "other_digest"):
            TSA["mode"] = mode
            with self.assertRaises(rg.Bad):
                rg.cmd_record(*args, (TSA["url"], TSA["ca"]))
        TSA["mode"] = "ok"
        with self.assertRaises(rg.Bad):                              # a token by a TSA the given root does not sign
            rg.cmd_record(*args, (TSA["url"], os.path.join(TSA["other"], "ca.pem")))
        with self.assertRaises(rg.Bad):                              # nobody listens there
            rg.cmd_record(*args, ("http://127.0.0.1:1/", TSA["ca"]))
        self.assertEqual(rd(self.reg), before)

    def test_stdlib_digest_guard_and_attime(self):
        """the reply's digest is checked before openssl (openssl stubbed out here), and openssl verifies at genTime"""
        TSA["mode"] = "other_digest"
        with mock.patch.object(rg, "openssl_verify", lambda *a: None):
            with self.assertRaises(rg.Bad) as cm:
                rg.cmd_record(self.reg, SMALL_REPORT, None, None, None, None, None, (TSA["url"], TSA["ca"]))
        self.assertIn("not granted for this digest", str(cm.exception))
        TSA["mode"] = "ok"
        seen = []
        real = subprocess.run

        def spy(args, **k):
            seen.append(list(args))
            return real(args, **k)
        with mock.patch.object(rg.subprocess, "run", spy):
            rg.cmd_record(self.reg, SMALL_REPORT, None, None, None, None, None, (TSA["url"], TSA["ca"]))
        gen = rg.parse_utc(rg.read_register(self.reg)[0][-1]["body"]["gen_time_utc"])
        v = [x for x in seen if x[1:3] == ["ts", "-verify"]]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0][v[0].index("-attime") + 1], str(int(gen.timestamp())))

    def test_trust_selection(self):
        with self.assertRaises(rg.Bad):
            rg.tsa_trust("https://freetsa.org/tsr", None)
        with self.assertRaises(rg.Bad):
            rg.tsa_trust("https://www.freetsa.org/tsr", TSA["ca"])          # not the pinned root
        with mock.patch.object(rg, "FREETSA_ROOT_SHA256", hashlib.sha256(rd(TSA["ca"])).hexdigest()):
            self.assertEqual(rg.tsa_trust("https://freetsa.org/tsr", TSA["ca"]), ("freetsa_pinned", TSA["ca"]))
        self.assertEqual(rg.tsa_trust("http://127.0.0.1:9/", TSA["ca"])[0], "user_ca")
        if rg.system_bundle():
            self.assertEqual(rg.tsa_trust("http://127.0.0.1:9/", None), ("system_store", rg.system_bundle()))
        for bad in ("ftp://x/", "http:///x", "http://a b/", "x" * 600, "http://[bad/"):
            with self.assertRaises(rg.Bad, msg=bad):
                rg.tsa_trust(bad, TSA["ca"])

    def test_forged_token_caught_by_openssl(self):
        """a token whose signature bytes are changed passes the stdlib grammar and fails openssl"""
        rg.cmd_record(self.reg, SMALL_REPORT, None, None, None, None, None, (TSA["url"], TSA["ca"]))
        entries, _ = rg.read_register(self.reg)
        import base64
        der = bytearray(base64.b64decode(entries[2]["body"]["token_b64"]))
        der[-5] ^= 0x01                                           # inside the ECDSA signature at the end
        entries[2]["body"]["token_b64"] = base64.b64encode(bytes(der)).decode()
        entries[2].pop("hash")
        entries[2]["hash"] = hashlib.sha256(rg.canonical(entries[2])).hexdigest()
        p = os.path.join(self.tmp, "forged.jsonl")
        with open(p, "wb") as fh:
            fh.write(b"".join(rg.canonical(e) + b"\n" for e in entries))
        es, _ = rg.read_register(p)
        with self.assertRaises(rg.Damaged):
            rg.recheck_timestamps(es, TSA["ca"])

    def test_der_reader(self):
        rg.cmd_record(self.reg, SMALL_REPORT, None, None, None, None, None, (TSA["url"], TSA["ca"]))
        import base64
        entries, _ = rg.read_register(self.reg)
        der = base64.b64decode(entries[2]["body"]["token_b64"])
        st, dg, gen = rg.tsa_reply_fields(der)
        self.assertEqual((st, dg.hex()), (0, entries[1]["hash"]))
        txt = subprocess.run([OPENSSL, "ts", "-reply", "-in", "/dev/stdin", "-text"], input=der, capture_output=True,
                             timeout=30).stdout.decode()
        self.assertIn(gen.strftime("%b %e %H:%M:%S %Y").replace("  ", " "), " ".join(txt.split()))
        for cut in (1, 10, len(der) // 2, len(der) - 1):
            with self.assertRaises(ValueError):
                rg.tsa_reply_fields(der[:cut])
        with self.assertRaises(ValueError):
            rg.tsa_reply_fields(der + b"\x00")
        with self.assertRaises(ValueError):
            rg.tsa_reply_fields(b"\x30\x81\x05" + der[2:7])        # non-minimal length


# ------------------------------------------------------------------ apc_verify run by the register
class Rerun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.reg = os.path.join(self.tmp, "reg.jsonl")
        rg.cmd_init(self.reg)

    def test_report_must_be_the_rerun(self):
        rep = rg.rerun_verify(BUNDLE, None, None)
        rg.cmd_record(self.reg, rep, bundle_in(), None, None, None, None)
        other = rg.rerun_verify(BUNDLE2, None, None)
        before = rd(self.reg)
        with self.assertRaises(rg.Bad) as cm:
            rg.cmd_record(self.reg, other, bundle_in(), None, None, None, None)
        self.assertIn("not the report", str(cm.exception))
        changed = dict(rep, notes=rep["notes"] + ["x"])
        with self.assertRaises(rg.Bad):
            rg.cmd_record(self.reg, changed, bundle_in(), None, None, None, None)
        self.assertEqual(rd(self.reg), before)

    def test_bundle_changed_while_verified(self):
        with self.assertRaises(rg.Bad) as cm:
            rg.cmd_record(self.reg, None, (BUNDLE, b"{}", None, None, None), None, None, None, None)
        self.assertIn("changed", str(cm.exception))

    def test_refused_bundle_recorded_as_refused(self):
        p = os.path.join(self.tmp, "b.json")
        with open(p, "w") as fh:
            fh.write('{"bundle_version":"apc-0.3","x":1,"inclusion":{"block_header":{"timestamp":"0x10"}}}')
        rg.cmd_record(self.reg, None, bundle_in(p), None, None, None, None)
        e = rg.read_register(self.reg)[0][-1]
        self.assertEqual(e["body"]["proven"]["verdict"], "refused")
        self.assertIsNone(e["body"]["proven"]["block_time"])

    def test_rerun_is_apc_verify_cli(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), BUNDLE], capture_output=True,
                           text=True, env=env(), timeout=120)
        self.assertEqual(rg.canonical(json.loads(r.stdout)), rg.canonical(rg.rerun_verify(BUNDLE, None, None)))


# ------------------------------------------------------------------ the command line
class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = synthetic_tzdb(os.path.join(cls.tmp, "tz.apc-tzb"))
        cls.adm = synthetic_admin(os.path.join(cls.tmp, "adm.apc-adm"))
        cls.rep = os.path.join(cls.tmp, "rep.json")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "apc_verify.py"), BUNDLE], capture_output=True,
                           text=True, env=env(), timeout=120)
        with open(cls.rep, "w") as fh:
            fh.write(r.stdout)
        cls.nmea = os.path.join(cls.tmp, "fix.nmea")
        with open(cls.nmea, "wb") as fh:
            fh.write(fix_sentences("4100.0000", "N", "01100.0000", "E"))
        cls.seed = os.path.join(cls.tmp, "seed")
        with open(cls.seed, "w") as fh:
            fh.write(SEED.hex() + "\n")

    def setUp(self):
        self.reg = os.path.join(tempfile.mkdtemp(dir=self.tmp), "reg.jsonl")

    def ok(self, code, out, err, want=0):
        self.assertEqual(code, want, out + err)
        self.assertEqual(err, "")
        return json.loads(out)

    def test_flow(self):
        self.assertEqual(run("record", self.reg, "--report", self.rep)[0], 3)       # recording off until init
        self.assertFalse(os.path.exists(self.reg))
        self.ok(*run("init", self.reg))
        self.assertIn("exists", self.ok(*run("init", self.reg), want=3)["error"])
        extra = ["--tsa", TSA["url"], "--tsa-ca", TSA["ca"]] if OPENSSL else []
        out = self.ok(*run("record", self.reg, "--bundle", BUNDLE, "--report", self.rep, "--nmea", self.nmea,
                           "--tzdb", self.db, "--admin", self.adm, "--key", self.seed, *extra))
        self.assertEqual((out["recorded"], out["place"], out["region"], out["rerun"]),
                         (1, "established", "established", True))
        v = self.ok(*run("verify", self.reg, "--public-key", sol.ed25519_public(SEED).hex(),
                         *(["--tsa-ca", TSA["ca"]] if OPENSSL else [])))
        self.assertEqual((v["seals"], v["head"], v["timestamps"]["rechecked_by_openssl"]),
                         (1, out["head"], 1 if OPENSSL else 0))
        self.ok(*run("verify", self.reg, "--public-key", sol.ed25519_public(SEED2).hex()), want=1)
        s = self.ok(*run("show", self.reg, "--zones", "Europe/Rome,America/Phoenix,Nowhere/Zone"))
        c = s["checks"][0]
        self.assertEqual((c["zone"], c["other_zones_at"], c["other_zones"]["Nowhere/Zone"]),
                         ("Europe/Rome", "gps", "not_in_this_tzdata"))
        self.assertEqual(c["other_zones"]["Europe/Rome"]["local_time"], "2026-10-26T13:00:00+01:00")
        self.assertEqual(c["check_time_proven_not_after"] is not None, bool(OPENSSL))
        self.assertEqual(len(self.ok(*run("show", self.reg))["checks"][0]["other_zones"]), 8)
        torn = b'{"apc_register":"apc-r'
        with open(self.reg, "ab") as fh:
            fh.write(torn)
        self.assertEqual(self.ok(*run("verify", self.reg), want=2)["torn_tail"]["bytes"], len(torn))
        self.assertTrue(self.ok(*run("record", self.reg, "--report", self.rep))["torn_tail_recorded"])
        self.ok(*run("verify", self.reg))
        with open(self.reg, "r+b") as fh:
            fh.seek(40)
            fh.write(b"X")
        before = rd(self.reg)
        self.assertIn("damaged", self.ok(*run("record", self.reg, "--report", self.rep), want=1)["error"])
        self.assertEqual(rd(self.reg), before)                                    # nothing written
        self.ok(*run("verify", self.reg), want=1)
        self.ok(*run("show", self.reg), want=1)

    def test_refusals_never_a_traceback(self):
        self.ok(*run("init", self.reg))
        bad = os.path.join(self.tmp, "bad")

        def put(b):
            with open(bad, "wb") as fh:
                fh.write(b)
            return bad
        for args in (["--report", put(b"not json")], ["--report", put(b'{"verifier":"apc_verify x","verdict":1.5}')],
                     ["--report", put(b'{"verdict":"x"}')], ["--report", put(b'[1]')],
                     ["--report", put(b'{"a":1,"a":2}')], ["--report", put(b"\xff")],
                     ["--report", os.path.join(self.tmp, "absent")],
                     ["--bundle", os.path.join(self.tmp, "absent")],
                     ["--bundle", BUNDLE, "--l1-checkpoint", "0x12"],
                     ["--bundle", BUNDLE, "--http-keys", os.path.join(self.tmp, "absent")],
                     ["--bundle", BUNDLE2, "--report", self.rep],
                     ["--report", self.rep, "--nmea", os.path.join(self.tmp, "absent")],
                     ["--report", self.rep, "--gpsd-json", os.path.join(self.tmp, "absent")],
                     ["--report", self.rep, "--gpsd", "0"], ["--report", self.rep, "--gpsd", "70000"],
                     ["--report", self.rep, "--gpsd", "1"],
                     ["--report", self.rep, "--nmea", self.nmea, "--tzdb", put(b"\x00\x01")],
                     ["--report", self.rep, "--nmea", self.nmea, "--admin", put(b"\x00\x01")],
                     ["--report", self.rep, "--nmea", self.nmea, "--tzdb", self.tmp],
                     ["--report", self.rep, "--nmea", self.nmea, "--admin", self.db],
                     ["--report", self.rep, "--key", put(b"short")],
                     ["--report", self.rep, "--gps", os.path.join(self.tmp, "absent")],
                     ["--report", self.rep, "--gps", "/dev/null", "--baud", "1200"],
                     ["--report", self.rep, "--gps", "/dev/null", "--seconds", "x"],
                     ["--report", self.rep, "--tsa", "https://freetsa.org/tsr"],
                     ["--report", self.rep, "--tsa", "ftp://example/"],
                     ["--report", self.rep, "--tsa", "http://127.0.0.1:1/", "--tsa-ca", os.path.join(self.tmp, "x")]):
            out = self.ok(*run("record", self.reg, *args), want=3)
            self.assertIn("error", out, args)
        self.assertEqual(self.ok(*run("verify", self.reg))["entries"], 1)            # nothing was written
        self.ok(*run("verify", os.path.join(self.tmp, "absent")), want=3)
        self.ok(*run("verify", self.tmp), want=3)
        self.ok(*run("verify", self.reg, "--tsa-ca", os.path.join(self.tmp, "absent")), want=3)
        self.ok(*run("show", self.reg, "--zones", "a,,b"), want=3)
        for args in ([], ["nope"], ["record", self.reg], ["record", self.reg, "--report"],
                     ["record", self.reg, "--report", self.rep, "--nmea", self.nmea, "--gps", "/dev/null"],
                     ["record", self.reg, "--report", self.rep, "--nmea", self.nmea, "--gpsd-json", self.nmea],
                     ["record", self.reg, "--report", self.rep, "--baud", "9600"],
                     ["record", self.reg, "--report", self.rep, "--seconds", "1"],
                     ["record", self.reg, "--report", self.rep, "--l1-checkpoint", "0x" + "0" * 64],
                     ["record", self.reg, "--report", self.rep, "--http-keys", self.rep],
                     ["record", self.reg, "--report", self.rep, "--tsa-ca", self.rep],
                     ["verify", self.reg, "--zones", "x"], ["verify", self.reg, "--public-key", "zz"],
                     ["verify"], ["show", self.reg, self.reg], ["record", self.reg, "--report", self.rep,
                                                               "--report", self.rep]):
            code, out, err = run(*args)
            self.assertEqual((code, err), (64, ""), args)

    def test_serial_pty(self):
        """--gps on a pseudo-terminal: the serial reader in raw mode"""
        import pty
        mfd, sfd = pty.openpty()
        dev = os.ttyname(sfd)
        data = fix_sentences("4100.0000", "N", "01100.0000", "E")

        def feed():
            for _ in range(3):
                os.write(mfd, data)
        t = threading.Thread(target=feed)
        t.start()
        try:
            got = rg.read_serial(dev, 9600, 3)
        finally:
            t.join()
            os.close(sfd)
            os.close(mfd)
        fx, why, _ = rg.parse_nmea(got)
        self.assertIsNone(why)
        self.assertEqual(fx["lat"], "41.0000000")


if __name__ == "__main__":
    unittest.main()
