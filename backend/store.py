"""SQLite-Ablage für Events, Geo-Daten und Lese-Offsets der Logdateien.

Persistenz statt RAM-Deque: Statistiken über 7 Tage überleben so jeden
Neustart, und Geo-Lookups werden pro IP nur einmal bei ip-api.com angefragt.
"""
import sqlite3
import threading
import time

RETENTION = 8 * 86400

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, ip TEXT NOT NULL, type TEXT NOT NULL,
    sev TEXT, src TEXT, port INTEGER, detail TEXT, jail TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_ip ON events(ip);
CREATE TABLE IF NOT EXISTS geo (
    ip TEXT PRIMARY KEY, lat REAL, lon REAL, cc TEXT, country TEXT,
    city TEXT, isp TEXT, asn TEXT, fetched REAL, org TEXT, hosting INTEGER, proxy INTEGER, mobile INTEGER);
CREATE TABLE IF NOT EXISTS offsets (path TEXT PRIMARY KEY, inode INTEGER, pos INTEGER);
"""

FEED_COLUMNS = ("id", "ts", "ip", "type", "sev", "src", "port", "detail", "jail",
                "lat", "lon", "cc", "country", "city", "isp", "asn")
FEED_SELECT = (f"SELECT e.{', e.'.join(FEED_COLUMNS[:9])}, g.lat, g.lon, g.cc, g.country, g.city, g.isp, g.asn "
               "FROM events e LEFT JOIN geo g ON g.ip=e.ip ")
GEO_EXTRA = ("org", "hosting", "proxy", "mobile")  # später ergänzte Spalten -> Migration in __init__

# Login-Versuche (sshd und Honeypots), Detail jeweils "Login-Versuch als „name“ …" (honeypot.attempt)
LOGIN_TYPES = "('SSH-Brute','MySQL-Probe','SSH-Probe','FTP-Probe','Telnet-Probe','Postgres-Probe')"
LOGINS = f"type IN {LOGIN_TYPES} AND detail LIKE 'Login-Versuch als „%'"
LOGIN_USER = "substr(detail, instr(detail, '„') + 1, instr(detail, '“') - instr(detail, '„') - 1)"
# SSH-/FTP-/Telnet-/Postgres-Honeypot hängen " · Passwort „pw“" als letzten Teil an; 12 = len('· Passwort „')
PASSWORDS = "type IN ('SSH-Probe','FTP-Probe','Telnet-Probe','Postgres-Probe') AND detail LIKE '%· Passwort „%'"
LOGIN_PW = "substr(detail, instr(detail, '· Passwort „') + 12, length(detail) - instr(detail, '· Passwort „') - 12)"
# Fake-Shell von SSH-/Telnet-Honeypot und SQL der Datenbank-Honeypots: Detail "Befehl „…“" (Honeypot.command); 8 = len('Befehl „')
COMMANDS = "type IN ('SSH-Probe','Telnet-Probe','MySQL-Probe','Postgres-Probe') AND detail LIKE 'Befehl „%'"
COMMAND = "substr(detail, 9, length(detail) - 9)"

# Drilldown aus den Top-Listen: Art -> WHERE-Bedingung (Werte immer als Parameter)
FILTERS = {
    "type": "e.type=?", "cc": "g.cc=?", "asn": "g.asn=?", "jail": "e.jail=?",
    "port": "e.type='Port-Scan' AND e.port=?",
    "user": f"e.type IN {LOGIN_TYPES} AND e.detail LIKE 'Login-Versuch als „' || ? || '“%'",
    "login": f"e.type IN {LOGIN_TYPES} AND e.detail LIKE ? || '%'",
    "password": f"{PASSWORDS} AND {LOGIN_PW}=?",
    "command": f"{COMMANDS} AND {COMMAND}=?",
    "path": "e.type IN ('Web-Probe','SQLi/RCE') AND e.detail LIKE ? || ' → %'",
}


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode=WAL")
        have = {r[1] for r in self.db.execute("PRAGMA table_info(geo)")}
        for col in GEO_EXTRA:
            if col not in have:
                self.db.execute(f"ALTER TABLE geo ADD COLUMN {col} {'TEXT' if col == 'org' else 'INTEGER'}")
        self.lock = threading.Lock()

    def query(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def is_empty(self):
        return self.query("SELECT COUNT(*) FROM events")[0][0] == 0

    def add_events(self, events):
        if not events:
            return
        rows = [(e["ts"], e["ip"], e["type"], e["sev"], e["src"], e["port"], e["detail"], e["jail"])
                for e in events]
        with self.lock, self.db:
            self.db.executemany(
                "INSERT INTO events(ts,ip,type,sev,src,port,detail,jail) VALUES (?,?,?,?,?,?,?,?)", rows)

    # --- Offsets der Logdateien (Fortsetzen nach Neustart ohne Duplikate) ---
    def get_offset(self, path):
        row = self.query("SELECT inode, pos FROM offsets WHERE path=?", (path,))
        return row[0] if row else (None, 0)

    def set_offset(self, path, inode, pos):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO offsets VALUES (?,?,?)", (path, inode, pos))

    # --- Geo ---
    def ips_without_geo(self, limit=100):
        # auch alte Einträge ohne hosting-Feld (vor der Erweiterung geholt) einmal nachladen
        return [r[0] for r in self.query(
            "SELECT e.ip FROM events e LEFT JOIN geo g ON g.ip=e.ip "
            "WHERE g.ip IS NULL OR (g.cc IS NOT NULL AND g.hosting IS NULL) "
            "GROUP BY e.ip ORDER BY MAX(e.id) DESC LIMIT ?", (limit,))]

    def save_geo(self, rows):
        with self.lock, self.db:
            self.db.executemany(
                "INSERT OR REPLACE INTO geo(ip,lat,lon,cc,country,city,isp,asn,fetched,org,hosting,proxy,mobile) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [tuple(r) + (None,) * (13 - len(r)) for r in rows])

    # --- Lesen ---
    def feed(self, since_id=0, limit=80):
        rows = self.query(FEED_SELECT + "WHERE e.id>? ORDER BY e.ts DESC, e.id DESC LIMIT ?", (since_id, limit))
        return [dict(zip(FEED_COLUMNS, r)) for r in rows]

    def events_where(self, kind, value, since, limit=200):
        """Einzelne Vorgänge zu einem Eintrag der Top-Listen; kind="ip" erwartet eine Event-ID."""
        if kind == "ip":
            cond, value = "e.ip=(SELECT ip FROM events WHERE id=?)", int(value)
        else:
            cond = FILTERS[kind]  # KeyError -> 400
        total = self.query(f"SELECT COUNT(*) FROM events e LEFT JOIN geo g ON g.ip=e.ip WHERE e.ts>=? AND {cond}",
                           (since, value))[0][0]
        rows = self.query(FEED_SELECT + f"WHERE e.ts>=? AND {cond} ORDER BY e.ts DESC, e.id DESC LIMIT ?",
                          (since, value, limit))
        return total, [dict(zip(FEED_COLUMNS, r)) for r in rows]

    def ip_profile(self, event_id):
        """Verhalten der IP hinter einem Event über die ganze Aufbewahrungszeit (ohne die IP selbst)."""
        row = self.query("SELECT ip FROM events WHERE id=?", (event_id,))
        if not row:
            return None
        ip = row[0][0]
        n, first, last, days = self.query(
            "SELECT COUNT(*), MIN(ts), MAX(ts), COUNT(DISTINCT date(ts, 'unixepoch')) FROM events WHERE ip=?", (ip,))[0]
        top = lambda sql: self.query(sql + " ORDER BY n DESC LIMIT 8", (ip,))
        geo = self.query("SELECT cc, country, city, isp, asn, org, hosting, proxy, mobile FROM geo WHERE ip=?", (ip,))
        net = ".".join(ip.split(".")[:3]) + ".%"
        return ip, {
            "n": n, "first": first, "last": last, "days": days,
            "types": dict(top("SELECT type, COUNT(*) n FROM events WHERE ip=? GROUP BY type")),
            "ports": top("SELECT port, COUNT(*) n FROM events WHERE ip=? AND type='Port-Scan' GROUP BY port"),
            "users": top(f"SELECT {LOGIN_USER} u, COUNT(*) n FROM events WHERE ip=? AND {LOGINS} GROUP BY u"),
            "passwords": top(f"SELECT {LOGIN_PW} p, COUNT(*) n FROM events WHERE ip=? AND {PASSWORDS} GROUP BY p"),
            "commands": top(f"SELECT {COMMAND} c, COUNT(*) n FROM events WHERE ip=? AND {COMMANDS} GROUP BY c"),
            "paths": [(d.split(" → ")[0], c) for d, c in top(
                "SELECT detail, COUNT(*) n FROM events WHERE ip=? AND type IN ('Web-Probe','SQLi/RCE') "
                "GROUP BY substr(detail, 1, instr(detail, ' → '))")],
            "jails": top("SELECT jail, COUNT(*) n FROM events WHERE ip=? AND jail IS NOT NULL GROUP BY jail"),
            # Nachbarn im selben /24: viele Absender aus einem Netz deuten auf Scan-Farmen hin
            "subnetIps": self.query("SELECT COUNT(DISTINCT ip) FROM events WHERE ip LIKE ?", (net,))[0][0],
            "geo": dict(zip(("cc", "country", "city", "isp", "asn", "org", "hosting", "proxy", "mobile"), geo[0]))
            if geo else {},
        }
    def prune(self):
        with self.lock, self.db:
            self.db.execute("DELETE FROM events WHERE ts<?", (time.time() - RETENTION,))
            self.db.execute("DELETE FROM geo WHERE ip NOT IN (SELECT DISTINCT ip FROM events)")
