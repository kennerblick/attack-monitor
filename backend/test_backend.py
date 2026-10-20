"""Unit-Tests: python3 -m unittest -v (im Verzeichnis backend/)."""
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

import honeypot_ftp
import honeypot_mysql
import honeypot_ssh
import paramiko
import intel
import parsers
import stats
import visits
from server import mask
from store import Store

NOW = time.mktime((2026, 10, 20, 12, 0, 0, 0, 0, -1))


class ParserTests(unittest.TestCase):
    def test_portsentry(self):
        ev = parsers.parse_syslog("Oct 19 18:29:40 3lis portsentry[593]: attackalert: TCP SYN/Normal scan "
                                  "from host: 94.31.119.184/94.31.119.184 to TCP port: 22", NOW)
        self.assertEqual((ev["type"], ev["port"], ev["ip"]), ("Port-Scan", 22, "94.31.119.184"))

    def test_portsentry_block_lines_ignored(self):
        self.assertIsNone(parsers.parse_syslog(
            'Oct 19 18:29:40 3lis portsentry[593]: attackalert: Host 1.2.3.4 has been blocked via wrappers', NOW))

    def test_ssh_invalid_user(self):
        ev = parsers.parse_auth("Oct 18 00:00:24 3lis sshd[1395421]: Invalid user alice from 223.17.1.118 port 38198", NOW)
        self.assertEqual(ev["type"], "SSH-Brute")
        self.assertIn("alice", ev["detail"])

    def test_f2b_ban_but_not_unban_or_restore(self):
        base = "2026-10-19 19:27:21,163 fail2ban.actions        [503]: NOTICE  [sshd] "
        self.assertEqual(parsers.parse_f2b(base + "Ban 107.174.82.77")["jail"], "sshd")
        self.assertIsNone(parsers.parse_f2b(base + "Unban 107.174.82.77"))
        self.assertIsNone(parsers.parse_f2b(base + "Restore Ban 107.174.82.77"))

    def test_nginx_probe_and_normal_request(self):
        probe = ('213.165.53.216 - - [20/Oct/2026:07:53:29 +0200] "GET /vendor/phpunit/eval-stdin.php HTTP/1.1" '
                 '404 153 "-" "libredtail-http"')
        self.assertEqual(parsers.parse_nginx_access(probe)["type"], "SQLi/RCE")
        normal = '1.2.3.4 - - [20/Oct/2026:07:53:29 +0200] "GET /strudel/ HTTP/2.0" 200 9 "-" "Mozilla"'
        self.assertIsNone(parsers.parse_nginx_access(normal))
        own = '1.2.3.4 - - [20/Oct/2026:07:53:29 +0200] "GET /assets/vendor/globe.gl.min.js HTTP/2.0" 200 9 "-" "Mozilla"'
        self.assertIsNone(parsers.parse_nginx_access(own))

    def test_nginx_ssl_error(self):
        ev = parsers.parse_nginx_error("2026/10/20 01:39:08 [crit] 549#549: *10928 SSL_do_handshake() failed "
                                       "(SSL: error:0A00006C:SSL routines::bad key share) while SSL handshaking, "
                                       "client: 118.194.251.101, server: 0.0.0.0:443")
        self.assertEqual((ev["type"], ev["detail"]), ("SSL-Scan", "TLS-Handshake: bad key share"))

    def test_syslog_year_rollover(self):
        jan = time.mktime((2027, 1, 1, 0, 10, 0, 0, 0, -1))
        ts = parsers.syslog_ts("Dec 31 23:59:00", jan)
        self.assertLess(ts, jan)


class StoreStatsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        now = time.time()
        self.store.add_events([
            parsers.event(now - 10, "1.2.3.4", "Port-Scan", "med", "portsentry", 22, "TCP SYN"),
            parsers.event(now - 20, "1.2.3.4", "Port-Scan", "med", "portsentry", 22, "TCP SYN"),
            parsers.event(now - 30, "5.6.7.8", "SSH-Brute", "high", "sshd", 22022, "Login-Versuch als „root“"),
        ])
        self.store.save_geo([("1.2.3.4", 1, 2, "DE", "Germany", "Berlin", "ISP", "AS1", now, "Org", 1, 0, 0)])

    def test_feed_joins_geo(self):
        feed = self.store.feed()
        self.assertEqual(len(feed), 3)
        self.assertEqual([e["cc"] for e in feed], ["DE", "DE", None])  # neueste (nach ts) zuerst
        self.assertEqual(self.store.ips_without_geo(), ["5.6.7.8"])

    def test_stats(self):
        s = stats.compute(self.store, "1h")
        self.assertEqual((s["total"], s["uniqueIps"], s["countries"]), (3, 2, 1))
        self.assertEqual(s["portsTop"], [{"port": 22, "n": 2}])
        self.assertEqual(s["usersTop"], [{"type": "SSH-Brute", "user": "root", "n": 1}])
        self.assertEqual(sum(sum(row) for row in s["heatmap"]), 3)
        de = s["byCountry"]["DE"]
        self.assertEqual((de["n"], de["ips"], de["types"]), (2, 1, {"Port-Scan": 2}))
        self.assertEqual((s["hotspots"][0]["city"], s["hotspots"][0]["ips"]), ("Berlin", 1))


    def test_old_geo_rows_are_refetched(self):
        self.store.save_geo([("1.2.3.4", 1, 2, "DE", "Germany", "Berlin", "ISP", "AS1", time.time())])
        self.assertIn("1.2.3.4", self.store.ips_without_geo())

    def test_events_where_and_profile(self):
        since = time.time() - 3600
        self.assertEqual(self.store.events_where("cc", "DE", since)[0], 2)
        self.assertEqual(self.store.events_where("user", "root", since)[0], 1)
        self.assertEqual(self.store.events_where("port", "22", since)[0], 2)
        first_id = self.store.feed()[0]["id"]
        self.assertEqual(self.store.events_where("ip", first_id, since)[0], 2)
        with self.assertRaises(KeyError):
            self.store.events_where("1=1; --", "x", since)
        ip, prof = self.store.ip_profile(first_id)
        self.assertEqual((ip, prof["n"], prof["types"], prof["geo"]["hosting"]), ("1.2.3.4", 2, {"Port-Scan": 2}, 1))


class IntelTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(intel.classify("scanner-1.censys-scanner.com", None, None, 1, 0, 0)["name"], "Censys")
        self.assertEqual(intel.classify(None, "Some Telecom", None, False, False, False)["category"], "residential")
        self.assertEqual(intel.classify(None, "X", None, True, False, False)["category"], "cloud")
        gcp = intel.classify("x.1.2.3.bc.googleusercontent.com", "Google LLC", "Google Cloud (europe-west1)", 1, 0, 0)
        self.assertEqual((gcp["name"], gcp["category"]), ("Google Cloud", "cloud"))

    def test_mask_host(self):
        self.assertEqual(intel.mask_host("1-2-3-4.dsl.example.net", "1.2.3.4"), "1-2-3-x.dsl.example.net")
        self.assertEqual(intel.mask_host("4.3.2.1.in-addr.example", "1.2.3.4"), "x.3.2.1.in-addr.example")


class VisitsTests(unittest.TestCase):
    UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"

    def line(self, path, ip="5.6.7.8", ua=UA, status=200, ref="-", day="20"):
        return f'{ip} - - [{day}/Oct/2026:09:00:00 +0200] "GET {path} HTTP/2.0" {status} 9 "{ref}" "{ua}"'

    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "strudel"))
        self.store = Store(":memory:")
        self.counter = visits.Visits(self.store)

    def test_parse_filters(self):
        parse = lambda line, mixed=False: visits.parse(line, mixed, self.root)
        self.assertEqual(parse(self.line("/strudel/index.html?x=1", ref="https://www.google.com/"))[4:],
                         ("/strudel/", "google.com"))
        self.assertIsNone(parse(self.line("/.env")))
        self.assertIsNone(parse(self.line("/gibtsnicht/")))
        self.assertIsNone(parse(self.line("/assets/js/main.js")))
        self.assertIsNone(parse(self.line("/", status=404)))
        self.assertIsNone(parse(self.line("/", ua="Mozilla/5.0 (compatible; Googlebot/2.1)")))
        self.assertIsNone(parse(self.line("/", ua="curl/8.0")))
        self.assertIsNotNone(parse(self.line("/", ref="https://home.3lis.de/")))
        self.assertIsNone(parse(self.line("/", ref="https://home.3lis.de/"), mixed=True))
        self.assertIsNone(parse(self.line("/x.css", ref="https://home.3lis.de/")))
        self.assertIsNone(parse(self.line("/x.css", ref="https://3lis.de/"))[4])  # Ressource -> Browser-Beleg
        self.assertIsNone(parse(self.line("/", ref="http://178.254.36.104/"))[5])

    def test_summary_counts_daily_visitors(self):
        self.store.add_events([parsers.event(NOW, "9.9.9.9", "Port-Scan", "low", "syslog", 22, "x")])
        own = "https://3lis.de/"
        self.counter.ingest([self.line("/"), self.line("/strudel/"), self.line("/", ip="1.1.1.1"),
                             self.line("/", day="19"), self.line("/", ip="9.9.9.9"), self.line("/", ip="2.2.2.2"),
                             # nur wer Ressourcen nachlädt, zählt; 2.2.2.2 holt nur das HTML
                             self.line("/api/feed", ref=own), self.line("/x.css", ip="1.1.1.1", ref=own),
                             self.line("/api/feed", day="19", ref=own), self.line("/api/feed", ip="9.9.9.9", ref=own)],
                            root=self.root)
        s = self.counter.summary(today=visits.date(2026, 10, 20))
        self.assertEqual(s["daily"], [{"day": "2026-10-19", "visitors": 1, "views": 1},
                                      {"day": "2026-10-20", "visitors": 2, "views": 3}])
        self.assertEqual(s["monthly"], [{"period": "2026-10", "visitors": 3, "views": 4}])
        self.assertEqual(s["pages"][0], ("/", 3))


class HoneypotBase(unittest.TestCase):
    def start(self, pot):
        self.store, self.pot = pot.store, pot
        ready = threading.Event()
        threading.Thread(target=pot.serve, args=(ready,), daemon=True).start()
        ready.wait(5)

    def wait_events(self, n):
        for _ in range(100):
            rows = self.store.query("SELECT type, sev, detail FROM events ORDER BY id")
            if len(rows) >= n:
                return rows
            time.sleep(0.05)
        return rows


class MySQLHoneypotTests(HoneypotBase):
    def setUp(self):
        self.start(honeypot_mysql.MySQLHoneypot(Store(":memory:"), port=0, host="127.0.0.1"))

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.pot.port), timeout=5)
        _, greeting = honeypot_mysql._read_packet(sock)
        self.assertIn(b"MariaDB", greeting)
        return sock

    def test_login_is_recorded_and_denied(self):
        login = (struct.pack("<I", 0x0008A20F) + struct.pack("<I", 1 << 24) + b"\x21" + b"\0" * 23
                 + b"root\0" + bytes([20]) + b"x" * 20 + b"wordpress\0" + b"mysql_native_password\0")
        with self.connect() as sock:
            sock.sendall(honeypot_mysql.packet(1, login))
            seq, reply = honeypot_mysql._read_packet(sock)
        self.assertEqual((seq, reply[:1], reply[3:9]), (2, b"\xff", b"#28000"))
        self.assertEqual(self.wait_events(1), [("MySQL-Probe", "high", "Login-Versuch als „root“ · DB „wordpress“")])
        self.assertEqual(stats.compute(self.store, "24h")["usersTop"][0]["user"], "root")

    def test_scan_without_login(self):
        self.connect().close()
        self.assertEqual(self.wait_events(1)[0][1:], ("low", "Verbindung ohne Login (Server-Erkennung)"))


class FTPHoneypotTests(HoneypotBase):
    def setUp(self):
        self.start(honeypot_ftp.FTPHoneypot(Store(":memory:"), port=0, host="127.0.0.1"))

    def test_login_is_recorded_and_denied(self):
        with socket.create_connection(("127.0.0.1", self.pot.port), timeout=5) as sock:
            lines = sock.makefile("rb")
            self.assertTrue(lines.readline().startswith(b"220"))
            sock.sendall("USER admin\r\nPASS 123„456“\r\nQUIT\r\n".encode())
            replies = [lines.readline()[:3] for _ in range(3)]
        self.assertEqual(replies, [b"331", b"530", b"221"])
        self.assertEqual(self.wait_events(1), [("FTP-Probe", "high", 'Login-Versuch als „admin“ · Passwort „123"456"“')])
        s = stats.compute(self.store, "24h")
        self.assertEqual(s["passwordsTop"], [{"password": '123"456"', "n": 1}])
        self.assertEqual(self.store.events_where("password", '123"456"', 0)[0], 1)


class SSHHoneypotTests(HoneypotBase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.start(honeypot_ssh.SSHHoneypot(Store(":memory:"), port=0, host="127.0.0.1",
                                            key_path=os.path.join(self.tmp.name, "key")))

    def tearDown(self):
        self.tmp.cleanup()

    def test_password_and_key_are_recorded_and_denied(self):
        client = paramiko.Transport(("127.0.0.1", self.pot.port))
        client.start_client(timeout=10)
        self.assertEqual(client.remote_version, honeypot_ssh.VERSION)
        with self.assertRaises(paramiko.AuthenticationException):
            client.auth_password("root", "toor")
        key = paramiko.RSAKey.generate(1024)
        with self.assertRaises(paramiko.AuthenticationException):
            client.auth_publickey("root", key)  # Benutzerwechsel je Verbindung lehnt SSH ab
        client.close()
        rows = self.wait_events(2)
        self.assertEqual(rows[0], ("SSH-Probe", "high", "Login-Versuch als „root“ · Passwort „toor“"))
        self.assertEqual(rows[1][2], f"Login-Versuch als „root“ · Schlüssel ssh-rsa {honeypot_ssh.fingerprint(key)}")
        self.assertEqual(len(rows), 2)  # kein zusätzliches "ohne Login"-Event
        self.assertEqual(stats.compute(self.store, "24h")["passwordsTop"], [{"password": "toor", "n": 1}])

    def test_host_key_is_kept(self):
        again = honeypot_ssh.host_key(os.path.join(self.tmp.name, "key"))
        self.assertEqual(again.asbytes(), self.pot.key.asbytes())


class MaskTests(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask("from 223.17.1.118 port 1"), "from 223.17.1.x port 1")


if __name__ == "__main__":
    unittest.main()
