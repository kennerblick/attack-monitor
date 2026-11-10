"""Nachrichtenbezug: eigene Beobachtungen (7 Tage) über Themen-Stichwörter mit aktuellen Meldungen verknüpfen.

Deterministisch, ohne LLM: Die Payloads enthalten praktisch nie CVE-Nummern, aber erkennbare Ziele
(WordPress-Login, .env-Dateien, Spring Actuator, MySQL-Erpressung …). Jedes Thema hat eine SQL-Bedingung für die
eigenen Events und ein Stichwort-Muster für Meldungen. Feeds holt der Server stündlich (KEV täglich) und legt
sie in insights (kind "feed") ab; Quellen, die nicht mehr in FEEDS stehen, werden ignoriert; Besucher laden nichts von dort, sie bekommen nur Titel und Link.
"""
import email.utils
import html
import json
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse

from intel import mask

UA = "3lis.de-threat-monitor/1.0 (+https://3lis.de/)"
FEEDS = {  # Name -> (Format, URL, Abrufintervall s, erlaubte Link-Domain)
    "heise Security": ("rss", "https://www.heise.de/security/feed.xml", 3600, "heise.de"),
    "BleepingComputer": ("rss", "https://www.bleepingcomputer.com/feed/", 3600, "bleepingcomputer.com"),
    "BSI WID": ("rss", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", 3600, "cert-bund.de"),
    "Mastodon #threatintel": ("mastodon", "https://mastodon.social/api/v1/timelines/tag/threatintel?limit=40", 3600, "mastodon.social"),
    "CISA KEV": ("kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 86400, "nvd.nist.gov"),
}
MAX_BYTES = 5 * 1024 * 1024
NEWS_AGE = 14 * 86400
KEV_AGE = 60 * 86400
MIN_EVENTS = 20
PER_TOPIC = 3

# (Schlüssel, Anzeige, Bedingung auf events, Muster für Titel/Text der Meldungen)
TOPICS = [
    ("wordpress", "WordPress-Logins & -Plugins", "detail LIKE '%wp-login%' OR detail LIKE '%xmlrpc.php%' OR detail LIKE '%wp-admin%' "
     "OR detail LIKE '%wp-content%'", r"\bwordpress\b|\bwp-"),
    ("secrets", "Suche nach .env, Cloud- und Git-Zugangsdaten", "detail LIKE '%/.env%' OR detail LIKE '%/.aws/%' "
     "OR detail LIKE '%.git-credentials%' OR detail LIKE '%/.docker/config%'",
     r"\.env\b|exposed (credentials|secrets)|secrets? (leak|expos)|leaked (credentials|secrets|api keys?)|credential theft"),
    ("git", "Offene .git-Verzeichnisse", "detail LIKE '%/.git/%'", r"exposed \.?git\b|\.git director|git repositor"),
    ("spring", "Spring Boot Actuator", "detail LIKE '%/actuator%'", r"\bspring( boot| framework)?\b|actuator"),
    ("phpunit", "PHPUnit-RCE", "detail LIKE '%phpunit%'", r"phpunit"),
    ("php", "PHP-Angriffe", "type='PHP-Probe' OR detail LIKE '%php-cgi%'", r"\bphp\b"),
    ("mysql-ransom", "Datenbank-Erpressung", "detail LIKE '%RECOVER_YOUR_DATA%' OR detail LIKE '%README_TO_RECOVER%' "
     "OR detail LIKE '%PLEASE_READ%'", r"(mysql|mariadb|mongodb|postgres\w*|elasticsearch)\b.{0,60}(ransom|extort|wip)|(ransom|extort)\w*\b.{0,60}(mysql|mariadb|mongodb|postgres|elasticsearch)"),
    ("mysql", "MySQL/MariaDB", "type='MySQL-Probe'", r"\bmysql\b|\bmariadb\b"),
    ("postgres", "PostgreSQL", "type='Postgres-Probe'", r"\bpostgres(ql)?\b"),
    ("ssh", "SSH-Brute-Force", "type IN ('SSH-Probe','SSH-Brute')", r"\bssh\b|openssh"),
    ("iot", "IoT-Botnetze (Telnet, Mirai)", "type='Telnet-Probe' OR detail LIKE '%mirai%' OR detail LIKE '%busybox%'",
     r"\bmirai\b|\bbotnet|\biot\b|\btelnet\b"),
    ("miner", "Krypto-Miner", "detail LIKE '%xmrig%' OR detail LIKE '%minerd%' OR detail LIKE '%stratum+tcp%' "
     "OR detail LIKE '%c3pool%'", r"xmrig|crypto ?min|cryptojack|\bmonero\b"),
    ("router", "Router & Embedded-Geräte", "detail LIKE '%boaform%' OR detail LIKE '%GponForm%' OR detail LIKE '%HNAP1%' "
     "OR detail LIKE '%/cgi-bin/%' OR detail LIKE '%/goform/%'", r"\brouter|d-link|tp-link|zyxel|\bgpon\b|netgear|draytek|four-faith"),
    ("vpn", "VPN- und Edge-Gateways", "detail LIKE '%/remote/%' OR detail LIKE '%/dana-na/%' OR detail LIKE '%global-protect%' "
     "OR detail LIKE '%/+CSCOE+%' OR detail LIKE '%/vpn/%'", r"fortinet|fortigate|fortios|ivanti|palo alto|globalprotect|"
     r"citrix|netscaler|cisco asa|sonicwall"),
    ("rdp", "RDP & VNC", "type='Port-Scan' AND port IN (3389, 5900)", r"\brdp\b|remote desktop|\bvnc\b"),
    ("redis", "Redis", "type='Port-Scan' AND port=6379", r"\bredis\b"),
]


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read(MAX_BYTES)


def _plain(text, limit=300):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text or "")).split())[:limit]


def _ts(value):
    for parse in (lambda v: email.utils.parsedate_to_datetime(v).timestamp(),
                  lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()):
        try:
            return parse(value)
        except (TypeError, ValueError, IndexError):
            continue
    return None


def parse_rss(data):
    """RSS 2.0 und Atom -> [{title, url, date, text}]."""
    root, atom = ET.fromstring(data), "{http://www.w3.org/2005/Atom}"
    items = []
    for it in root.iter("item"):
        items.append({"title": it.findtext("title"), "url": it.findtext("link"),
                      "date": _ts(it.findtext("pubDate")), "text": it.findtext("description")})
    for it in root.iter(atom + "entry"):
        link = it.find(atom + "link")
        items.append({"title": it.findtext(atom + "title"), "url": link.get("href") if link is not None else None,
                      "date": _ts(it.findtext(atom + "updated") or it.findtext(atom + "published")),
                      "text": it.findtext(atom + "summary") or it.findtext(atom + "content")})
    return items


def parse_mastodon(data):
    out = []
    for s in json.loads(data):
        text = _plain(s.get("content"), 400)
        out.append({"title": text[:140] + ("…" if len(text) > 140 else ""), "text": text, "date": _ts(s.get("created_at")),
                    "url": f"https://mastodon.social/@{s['account']['acct']}/{s['id']}"})  # lokale Ansicht, kein Fremdlink
    return out


def parse_kev(data, now):
    out = []
    for v in json.loads(data).get("vulnerabilities", []):
        date = _ts(v.get("dateAdded", "") + "T00:00:00+00:00")
        if date and now - date <= KEV_AGE and re.fullmatch(r"CVE-\d{4}-\d{4,7}", v.get("cveID", "")):
            out.append({"title": f"{v['cveID']}: {v.get('vendorProject', '')} {v.get('product', '')} – {v.get('vulnerabilityName', '')}",
                        "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", "date": date, "text": v.get("shortDescription", "")})
    return out


def _safe(items, domain):
    """Nur https-Links auf die Domain der Quelle, Text ohne HTML, IPs gekürzt (Fremd-Posts nennen volle Angreifer-IPs);
    Titel und Link sind alles, was ausgeliefert wird."""
    out = []
    for it in items:
        host = urlparse(it.get("url") or "").hostname or ""
        if it.get("title") and it.get("date") and (it["url"] or "").startswith("https://") \
                and (host == domain or host.endswith("." + domain)):
            out.append({**it, "title": mask(_plain(it["title"], 200)), "text": mask(_plain(it.get("text")))})
    return out


def fetch(store, now):
    fetched = {r["key"]: r["ts"] for r in store.insights("feed", limit=100)}
    for name, (fmt, url, every, domain) in FEEDS.items():
        if now - fetched.get(name, 0) < every:
            continue
        try:
            data = _get(url)
            items = parse_kev(data, now) if fmt == "kev" else parse_mastodon(data) if fmt == "mastodon" else parse_rss(data)
            store.put_insight("feed", name, now, _safe(items, domain))
        except Exception as exc:  # Quelle offline oder Format geändert: alte Einträge bleiben
            print(f"news {name}: {type(exc).__name__}: {exc}", flush=True)


def evidence(store, now):
    out = {}
    for key, _, cond, _ in TOPICS:
        n, ips = store.query(f"SELECT COUNT(*), COUNT(DISTINCT ip) FROM events WHERE ts>=? AND ({cond})", (now - 7 * 86400,))[0]
        if n >= MIN_EVENTS:
            out[key] = (n, ips)
    return out


def match(feeds, seen, now):
    """Je beobachtetem Thema die neuesten passenden Meldungen. Bei Nachrichten zählt nur der Titel (Teaser-Texte
    erwähnen vieles am Rand), bei KEV und Mastodon auch der Text."""
    result = []
    for key, label, _, pattern in TOPICS:
        if key not in seen:
            continue
        rx, hits, titles = re.compile(pattern, re.I), [], set()
        for source, items in feeds.items():
            fmt = FEEDS.get(source, ("rss",))[0]
            max_age = KEV_AGE if fmt == "kev" else NEWS_AGE
            for it in items:
                haystack = it["title"] if fmt == "rss" else f"{it['title']} {it['text']}"
                if now - it["date"] <= max_age and it["title"] not in titles and rx.search(haystack):
                    titles.add(it["title"])
                    hits.append({"source": source, "title": it["title"], "url": it["url"], "date": it["date"]})
        if hits:
            hits.sort(key=lambda h: -h["date"])
            n, ips = seen[key]
            result.append({"topic": key, "label": label, "events": n, "ips": ips, "matches": hits[:PER_TOPIC]})
    return sorted(result, key=lambda r: -r["events"])


def update(store, now):
    fetch(store, now)
    feeds = {r["key"]: r["data"] for r in store.insights("feed", limit=100) if r["key"] in FEEDS}
    store.put_insight("related", "current", now, match(feeds, evidence(store, now), now))


def related(store):
    row = store.insights("related", limit=1)
    return row[0]["data"] if row else []
