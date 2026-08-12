#!/usr/bin/env python3
"""Live Attack Monitor API for 3lis.de"""
import json, time, re, os, threading, queue, ipaddress, urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque, Counter
from datetime import datetime

LOGS = {
    "nginx": "/var/log/nginx/access.log",
    "auth":  "/var/log/auth.log",
    "f2b":   "/var/log/fail2ban.log",
}

ATTACKS = deque(maxlen=300)
STATS = Counter()
SEEN = set()

PATTERNS = [
    (r'\.env|\.git|wp-login|wp-admin|phpmyadmin|xmlrpc|adminer|\.sql|\.bak', "Web-Probe", "high"),
    (r'union.*select|eval\(|base64_decode|/etc/passwd|cmd=|shell', "SQLi/RCE", "crit"),
    (r'Invalid user|Failed password|authentication failure', "SSH-Brute", "high"),
    (r'Ban |Banned|Restore Ban', "fail2ban-Ban", "med"),
    (r'SSL_do_handshake|bad key share', "SSL-Scan", "low"),
    (r'limiting requests|excess:', "Rate-Limit", "med"),
]

# ------------------------------------------------------------------
# IP-Geolocation (ip-api.com, kostenlos, kein Key nötig)
#
# Läuft komplett asynchron über eine Queue + eigenen Worker-Thread,
# damit das Log-Tailing niemals auf einen Netzwerk-Request wartet.
# Ergebnis wird pro IP dauerhaft gecacht. Bei neu gesehenen IPs ist
# die Geo-Position beim allerersten Treffer noch leer und füllt sich
# erst danach (spätestens beim nächsten Treffer derselben IP).
# ------------------------------------------------------------------
GEO_CACHE = {}          # ip -> {"lat","lon","country","countryCode"} oder None
GEO_QUEUED = set()
GEO_LOCK = threading.Lock()
GEO_QUEUE = queue.Queue(maxsize=500)
GEO_LOOKUP_INTERVAL = 1.4  # ~43 req/min, unter dem 45/min Free-Limit von ip-api.com

SERVER_LOCATION = {"lat": None, "lon": None, "name": "Server"}


def geo_fetch(url, timeout=4):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def detect_server_location():
    try:
        data = geo_fetch("http://ip-api.com/json/?fields=status,lat,lon,city,country", timeout=4)
        if data.get("status") == "success":
            SERVER_LOCATION["lat"] = data["lat"]
            SERVER_LOCATION["lon"] = data["lon"]
            SERVER_LOCATION["name"] = ", ".join(filter(None, [data.get("city"), data.get("country")])) or "Server"
    except Exception:
        pass


def geo_worker():
    url = "http://ip-api.com/json/{}?fields=status,lat,lon,country,countryCode"
    while True:
        ip = GEO_QUEUE.get()
        try:
            data = geo_fetch(url.format(ip))
            if data.get("status") == "success":
                result = {
                    "lat": data["lat"], "lon": data["lon"],
                    "country": data.get("country"), "countryCode": data.get("countryCode"),
                }
            else:
                result = None  # von ip-api selbst abgelehnt (z.B. reservierter Bereich) -> dauerhaft cachen
            with GEO_LOCK:
                GEO_CACHE[ip] = result
        except Exception:
            # Netzwerkfehler/Timeout/Rate-Limit: nicht dauerhaft cachen, später erneut versuchen
            with GEO_LOCK:
                GEO_QUEUED.discard(ip)
        time.sleep(GEO_LOOKUP_INTERVAL)


def geolocate(ip):
    """Nicht-blockierend: liefert gecachte Geo-Daten oder None und stößt bei
    unbekannten IPs im Hintergrund einen Lookup an."""
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return None
    except ValueError:
        return None
    with GEO_LOCK:
        if ip in GEO_CACHE:
            return GEO_CACHE[ip]
        if ip not in GEO_QUEUED:
            GEO_QUEUED.add(ip)
            try:
                GEO_QUEUE.put_nowait(ip)
            except queue.Full:
                GEO_QUEUED.discard(ip)
    return None


def parse_line(line, source):
    m = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
    if not m:
        return
    ip = m.group(0)
    key = f"{ip}:{line[:80]}"
    if key in SEEN:
        return
    SEEN.add(key)
    if len(SEEN) > 5000:
        SEEN.clear()

    for pat, typ, sev in PATTERNS:
        if re.search(pat, line, re.I):
            geo = geolocate(ip)
            ATTACKS.appendleft({
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": ip,
                "type": typ,
                "sev": sev,
                "src": source,
                "raw": line.strip()[:140],
                "lat": geo["lat"] if geo else None,
                "lon": geo["lon"] if geo else None,
                "country": geo["country"] if geo else None,
                "countryCode": geo["countryCode"] if geo else None,
            })
            STATS[typ] += 1
            break

def tail_logs():
    pos = {}
    for name, path in LOGS.items():
        try:
            pos[name] = os.path.getsize(path)
        except OSError:
            pos[name] = 0

    while True:
        for name, path in LOGS.items():
            try:
                with open(path, "r", errors="ignore") as f:
                    f.seek(pos[name])
                    for line in f:
                        parse_line(line, name)
                    pos[name] = f.tell()
            except Exception:
                pass
        time.sleep(1.2)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/attacks"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            data = {
                "attacks": list(ATTACKS)[:60],
                "stats": dict(STATS),
                "total": sum(STATS.values()),
                "server": SERVER_LOCATION,
                "ts": datetime.now().isoformat(),
            }
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    detect_server_location()
    threading.Thread(target=geo_worker, daemon=True).start()
    threading.Thread(target=tail_logs, daemon=True).start()
    print("Attack Monitor API listening on 127.0.0.1:8099")
    HTTPServer(("127.0.0.1", 8099), Handler).serve_forever()
