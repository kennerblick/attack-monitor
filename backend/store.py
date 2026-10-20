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
    city TEXT, isp TEXT, asn TEXT, fetched REAL);
CREATE TABLE IF NOT EXISTS offsets (path TEXT PRIMARY KEY, inode INTEGER, pos INTEGER);
"""

FEED_COLUMNS = ("id", "ts", "ip", "type", "sev", "src", "port", "detail", "jail",
                "lat", "lon", "cc", "country", "city", "isp", "asn")


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode=WAL")
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
        return [r[0] for r in self.query(
            "SELECT e.ip FROM events e LEFT JOIN geo g ON g.ip=e.ip WHERE g.ip IS NULL "
            "GROUP BY e.ip ORDER BY MAX(e.id) DESC LIMIT ?", (limit,))]

    def save_geo(self, rows):
        with self.lock, self.db:
            self.db.executemany("INSERT OR REPLACE INTO geo VALUES (?,?,?,?,?,?,?,?,?)", rows)

    # --- Lesen ---
    def feed(self, since_id=0, limit=80):
        rows = self.query(
            f"SELECT e.{', e.'.join(FEED_COLUMNS[:9])}, g.lat, g.lon, g.cc, g.country, g.city, g.isp, g.asn "
            "FROM events e LEFT JOIN geo g ON g.ip=e.ip WHERE e.id>? ORDER BY e.ts DESC, e.id DESC LIMIT ?",
            (since_id, limit))
        return [dict(zip(FEED_COLUMNS, r)) for r in rows]

    def prune(self):
        with self.lock, self.db:
            self.db.execute("DELETE FROM events WHERE ts<?", (time.time() - RETENTION,))
            self.db.execute("DELETE FROM geo WHERE ip NOT IN (SELECT DISTINCT ip FROM events)")
