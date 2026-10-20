"""Unit-Tests: python3 -m unittest -v (im Verzeichnis backend/)."""
import time
import unittest

import intel
import parsers
import stats
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
        self.assertEqual(s["usersTop"], [{"user": "root", "n": 1}])
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


class MaskTests(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask("from 223.17.1.118 port 1"), "from 223.17.1.x port 1")


if __name__ == "__main__":
    unittest.main()
