"""Aggregierte Kennzahlen für ein Zeitfenster (1h / 24h / 7d)."""
import re
import time

from store import COMMAND, COMMANDS, LOCAL_SENSOR, LOGIN_PW, LOGIN_USER, LOGINS, PASSWORDS, SAMPLE_HASH, SAMPLES, SENSOR

# Fenster -> (Sekunden, Bucket-Größe der Zeitleiste)
RANGES = {"1h": (3600, 60), "24h": (86400, 1800), "7d": (7 * 86400, 3 * 3600)}


def _top(store, sql, since, limit=10):
    return store.query(sql + " ORDER BY n DESC LIMIT ?", (since, limit))


class _Scoped:
    """Alle Abfragen auf einen Sensor beschränken, ohne jede SQL-Zeile anzufassen. Der Name ist geprüft
    (SENSOR_NAME), nur deshalb darf er als Literal ins SQL."""

    def __init__(self, store, sensor):
        self.store = store
        self.table = f"FROM (SELECT * FROM events WHERE COALESCE(sensor,'{LOCAL_SENSOR}')='{sensor}')"

    def query(self, sql, args=()):
        return self.store.query(sql.replace("FROM events", self.table), args)


SENSOR_NAME = re.compile(r"[a-z0-9_-]{1,32}")


def compute(store, range_key, sensor=None):
    """sensor=None: alle Sensoren; sonst nur Events dieses Sensors (nicht in "sensors", die Karten zeigen immer alle)."""
    if sensor is not None and not SENSOR_NAME.fullmatch(sensor):
        raise ValueError(sensor)
    all_sensors, store = store, (store if sensor is None else _Scoped(store, sensor))
    span, bucket = RANGES.get(range_key, RANGES["24h"])
    now = time.time()
    since = now - span
    join = "FROM events e LEFT JOIN geo g ON g.ip=e.ip WHERE e.ts>=?"

    total, ips, countries = store.query(
        f"SELECT COUNT(*), COUNT(DISTINCT e.ip), COUNT(DISTINCT g.cc) {join}", (since,))[0]
    by_type = store.query("SELECT type, COUNT(*) n FROM events WHERE ts>=? GROUP BY type ORDER BY n DESC", (since,))

    first_bucket = int(since // bucket)
    timeline = {}
    for b, typ, n in store.query(
            "SELECT CAST(ts/? AS INTEGER) b, type, COUNT(*) FROM events WHERE ts>=? GROUP BY b, type",
            (bucket, since)):
        timeline.setdefault(b, {})[typ] = n
    buckets = [{"t": b * bucket, "counts": timeline.get(b, {})}
               for b in range(first_bucket, int(now // bucket) + 1)]

    return {
        "range": range_key if range_key in RANGES else "24h",
        "total": total, "uniqueIps": ips, "countries": countries,
        "perMinute": round(total / (span / 60), 2),
        "byType": [{"type": t, "n": n} for t, n in by_type],
        "countriesTop": [{"cc": cc, "country": c, "n": n} for cc, c, n in _top(
            store, f"SELECT g.cc, g.country, COUNT(*) n {join} AND g.cc IS NOT NULL GROUP BY g.cc", since)],
        "asnTop": [{"asn": a, "isp": i, "n": n} for a, i, n in _top(
            store, f"SELECT g.asn, MAX(g.isp), COUNT(*) n {join} AND g.asn IS NOT NULL AND g.asn!='' GROUP BY g.asn", since)],
        "portsTop": [{"port": p, "n": n} for p, n in _top(
            store, "SELECT port, COUNT(*) n FROM events WHERE ts>=? AND type='Port-Scan' GROUP BY port", since)],
        "usersTop": [{"type": t, "user": u, "n": n} for t, u, n in _top(
            store, f"SELECT type, {LOGIN_USER} u, COUNT(*) n FROM events WHERE ts>=? AND {LOGINS} GROUP BY type, u",
            since, 8)],
        # Top 8 zeigt nur einen Bruchteil, weil die meisten Namen nur einmal probiert werden
        "usersAll": dict(zip(("names", "n"), store.query(
            f"SELECT COUNT(DISTINCT type || {LOGIN_USER}), COUNT(*) FROM events WHERE ts>=? AND {LOGINS}", (since,))[0])),
        "passwordsTop": [{"password": p, "n": n} for p, n in _top(
            store, f"SELECT {LOGIN_PW} p, COUNT(*) n FROM events WHERE ts>=? AND {PASSWORDS} GROUP BY p", since)],
        "commandsTop": [{"command": c, "n": n} for c, n in _top(
            store, f"SELECT {COMMAND} c, COUNT(*) n FROM events WHERE ts>=? AND {COMMANDS} GROUP BY c", since)],
        "pathsTop": [{"path": d.split(" → ")[0], "n": n} for d, n in _top(
            store, "SELECT detail, COUNT(*) n FROM events WHERE ts>=? AND type IN ('Web-Probe','SQLi/RCE') "
                   "GROUP BY substr(detail, 1, instr(detail, ' → '))", since, 8)],
        "sensors": [{"sensor": x, "n": n, "ips": ips, "last": last} for x, n, ips, last in _top(
            all_sensors, f"SELECT {SENSOR} x, COUNT(*) n, COUNT(DISTINCT e.ip), MAX(e.ts) FROM events e WHERE e.ts>=? "
                         "GROUP BY x", since)],
        "samplesTop": samples_top(store, since),
        "jailsTop": [{"jail": j, "n": n} for j, n in _top(
            store, "SELECT jail, COUNT(*) n FROM events WHERE ts>=? AND jail IS NOT NULL GROUP BY jail", since)],
        # Herkunftsorte auf ~1°-Raster gebündelt, für die Säulen auf dem Globus
        "hotspots": [{"lat": la, "lon": lo, "cc": cc, "city": city, "n": n, "ips": ips, "last": last}
                     for la, lo, cc, city, n, ips, last in store.query(
            f"SELECT ROUND(g.lat), ROUND(g.lon), MAX(g.cc), MAX(g.city), COUNT(*) n, COUNT(DISTINCT e.ip), MAX(e.ts) "
            f"{join} AND g.lat IS NOT NULL GROUP BY 1, 2 ORDER BY n DESC LIMIT 400", (since,))],
        "byCountry": by_country(store, join, since),
        "timeline": {"bucket": bucket, "buckets": buckets},
        "heatmap": heatmap(store, now),
    }


def samples_top(store, since, limit=8):
    """Je Hash: Anzahl, Quell-IPs, zuletzt, Größe/Art/Quelle aus dem jüngsten Detail (siehe Honeypot.sample)."""
    # SQLite: die nackte Spalte detail stammt aus der Zeile mit MAX(ts), also dem jüngsten Fund
    rows = store.query(f"SELECT {SAMPLE_HASH} h, COUNT(*) n, COUNT(DISTINCT ip), MAX(ts), detail FROM events "
                       f"WHERE ts>=? AND {SAMPLES} GROUP BY h ORDER BY n DESC, MAX(ts) DESC LIMIT ?", (since, limit))
    out = []
    for digest, n, ips, last, detail in rows:
        size, kind, source = (detail.split(" · ") + ["", "", ""])[1:4]
        out.append({"hash": digest, "n": n, "ips": ips, "last": last, "size": size, "kind": kind, "source": source})
    return out


def by_country(store, join, since):
    """Alle Länder des Fensters mit Anzahl, IPs, letzter Zeit und Verteilung der Angriffsarten (Globus-Tooltips)."""
    out = {cc: {"country": c, "n": n, "ips": ips, "last": last, "types": {}} for cc, c, n, ips, last in store.query(
        f"SELECT g.cc, MAX(g.country), COUNT(*), COUNT(DISTINCT e.ip), MAX(e.ts) {join} AND g.cc IS NOT NULL "
        "GROUP BY g.cc", (since,))}
    for cc, typ, n in store.query(f"SELECT g.cc, e.type, COUNT(*) {join} AND g.cc IS NOT NULL GROUP BY 1, 2", (since,)):
        out[cc]["types"][typ] = n
    return out


def heatmap(store, now):
    """Wochentag x Stunde über die letzten 7 Tage (Ortszeit des Servers)."""
    rows = store.query(
        "SELECT CAST(strftime('%w', ts, 'unixepoch', 'localtime') AS INTEGER), "
        "CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER), COUNT(*) "
        "FROM events WHERE ts>=? GROUP BY 1, 2", (now - 7 * 86400,))
    grid = [[0] * 24 for _ in range(7)]
    for weekday, hour, n in rows:
        grid[(weekday + 6) % 7][hour] = n  # Montag zuerst
    return grid
