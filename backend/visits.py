"""Besucherstatistik für 3lis.de aus dem nginx-Zugriffslog – ohne Cookies und ohne Tracking-Skript.

Gezählt werden Seitenaufrufe (HTML-Seiten des eigenen Webroots) von echten Browsern. Echt heißt:
derselbe Besucher lädt am selben Tag auch Ressourcen mit Referer 3lis.de nach (CSS, JS, API).
Die allermeisten Abrufe mit Browser-User-Agent sind Bots, die nur das HTML holen (~97 %).
Ein Besucher ist ein Hash aus IP und User-Agent mit einem Tages-Salt, der nur im RAM liegt:
nach Tageswechsel lässt sich kein Hash mehr einer IP zuordnen, und Besucher werden nicht
über Tage hinweg verfolgt (Besucher pro Monat/Jahr = Summe der Tageswerte).

LOG ist das eigene Log des 3lis.de-Vhosts. Die alten Logs davor mischen alle Vhosts; dort
fallen Aufrufe mit Referer einer anderen *.3lis.de-Subdomain heraus (siehe parse()).
"""
import glob
import gzip
import hashlib
import os
import re
import secrets
import time
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

LOG = "/var/log/nginx/3lis.access.log"
MIXED_LOG = "/var/log/nginx/access.log"
WEBROOT = "/var/www/lernseite"
SITE = "3lis.de"

SCHEMA = """
CREATE TABLE IF NOT EXISTS visits (day TEXT NOT NULL, ts REAL NOT NULL, visitor TEXT NOT NULL,
    path TEXT NOT NULL, ref TEXT);
CREATE INDEX IF NOT EXISTS visits_day ON visits(day);
CREATE TABLE IF NOT EXISTS humans (day TEXT NOT NULL, visitor TEXT NOT NULL, PRIMARY KEY (day, visitor));
"""

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "([^"]*)" "([^"]*)"')
PAGE = re.compile(r'^/(?:[\w.-]+/)*(?:[\w-]+\.(?:html|php))?$')
HIDDEN = ("assets", "api", "attack-monitor", "besucher", "logs", "portsentry")  # keine Inhaltsseiten
BOT = re.compile(r'bot|crawl|spider|slurp|scan|research|checker|monitor|uptime|preview|fetch|headless|'
                 r'python|curl|wget|httpclient|okhttp|go-http|java/|zgrab|nmap|palo alto|lighthouse', re.I)

_salts = {}


def visitor_id(day, ip, agent):
    if day not in _salts:
        for old in [d for d in _salts if d < day]:
            del _salts[old]  # vergangene Salts vergessen -> alte Hashes nicht mehr zuordenbar
        _salts[day] = secrets.token_bytes(16)
    return hashlib.sha256(_salts[day] + f"{ip}|{agent}".encode()).hexdigest()[:16]


def page(path, root=WEBROOT):
    """Normalisierter Seitenpfad oder None, wenn es keine Inhaltsseite des Webroots ist."""
    path = path.split("?", 1)[0]
    if not PAGE.match(path) or path.split("/")[1] in HIDDEN:
        return None
    path = re.sub(r'index\.(html|php)$', '', path)
    return path if os.path.exists(os.path.join(root, path.lstrip("/"))) else None


def referrer(ref):
    host = (urlparse(ref).hostname or "").removeprefix("www.")
    return host if host and host != SITE and not re.fullmatch(r"[\d.:]+", host) else None


def parse(line, mixed=False, root=WEBROOT):
    """Logzeile -> (day, ts, ip, agent, path, ref); path None = Ressource einer 3lis.de-Seite.
    None, wenn die Zeile weder Seitenaufruf noch Ressource eines Browsers ist."""
    m = LINE.match(line)
    if not m:
        return None
    ip, stamp, method, path, status, ref, agent = m.groups()
    if method != "GET" or status not in ("200", "304") or "Mozilla/" not in agent or BOT.search(agent):
        return None
    stamp = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
    day, ts = stamp.strftime("%Y-%m-%d"), stamp.timestamp()
    if urlparse(ref).hostname == SITE and not page(path, root):
        return day, ts, ip, agent, None, None
    ref_host = referrer(ref)
    if mixed and ref_host and ref_host.endswith("." + SITE):
        return None  # im gemischten Log vermutlich ein Aufruf der Subdomain selbst
    path = page(path, root)
    return (day, ts, ip, agent, path, ref_host) if path else None


class Visits:
    def __init__(self, store):
        self.store = store
        with store.lock:
            store.db.executescript(SCHEMA)

    def is_empty(self):
        return self.store.query("SELECT COUNT(*) FROM visits")[0][0] == 0

    def query(self, sql, args=()):
        """sql liest aus "v": nur Seitenaufrufe von Besuchern, die sich als Browser erwiesen haben."""
        return self.store.query("WITH v AS (SELECT * FROM visits WHERE (day, visitor) IN "
                                "(SELECT day, visitor FROM humans)) " + sql, args)

    def ingest(self, lines, mixed=False, before=None, root=WEBROOT):
        rows, humans = [], set()
        for line in lines:
            hit = parse(line, mixed, root)
            if not hit or (before and hit[1] >= before):
                continue
            day, ts, ip, agent, path, ref = hit
            if path is None:
                humans.add((day, visitor_id(day, ip, agent)))
                continue
            # IPs, die schon als Angreifer auffielen, tarnen sich nur als Browser
            if self.store.query("SELECT 1 FROM events WHERE ip=? LIMIT 1", (ip,)):
                continue
            rows.append((day, ts, visitor_id(day, ip, agent), path, ref))
        with self.store.lock, self.store.db:
            self.store.db.executemany("INSERT INTO visits VALUES (?,?,?,?,?)", rows)
            self.store.db.executemany("INSERT OR IGNORE INTO humans VALUES (?,?)", humans)

    def seed(self):
        """Einmalig alle vorhandenen (gemischten) Logs bis zum Beginn des eigenen Logs nachlesen."""
        before = time.time()
        try:
            with open(LOG, errors="ignore") as fh:
                m = LINE.match(fh.readline())
            if m:
                before = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except OSError:
            pass
        files = sorted(glob.glob(MIXED_LOG + ".*"), key=os.path.getmtime) + [MIXED_LOG]
        for f in files:
            opener = gzip.open if f.endswith(".gz") else open
            try:
                with opener(f, "rt", errors="ignore") as fh:
                    self.ingest(fh, mixed=True, before=before)
            except OSError as exc:
                print(f"visits seed {f}: {exc}", flush=True)

    def summary(self, today=None):
        today = today or date.today()
        q = self.query
        days = {d: (v, n) for d, v, n in q(
            "SELECT day, COUNT(DISTINCT visitor), COUNT(*) FROM v GROUP BY day")}
        first = min(days, default=today.isoformat())
        span = (today - date.fromisoformat(first)).days + 1
        daily = [{"day": d, "visitors": days.get(d, (0, 0))[0], "views": days.get(d, (0, 0))[1]}
                 for d in ((today - timedelta(days=i)).isoformat() for i in reversed(range(span)))]
        group = lambda key: [{"period": k, "visitors": v, "views": n} for k, v, n in q(
            f"SELECT {key} k, SUM(v), SUM(n) FROM (SELECT day, COUNT(DISTINCT visitor) v, COUNT(*) n "
            "FROM v GROUP BY day) GROUP BY k ORDER BY k DESC")]
        top = lambda col, since: q(
            f"SELECT {col}, COUNT(*) n FROM v WHERE day>=? AND {col} IS NOT NULL "
            f"GROUP BY {col} ORDER BY n DESC LIMIT 15", (since,))
        since30 = (today - timedelta(days=29)).isoformat()
        return {"since": first, "daily": daily, "monthly": group("substr(day, 1, 7)"),
                "yearly": group("substr(day, 1, 4)"),
                "pages": top("path", since30), "referrers": top("ref", since30), "ts": time.time()}
