#!/usr/bin/env python3
"""Live Attack Monitor API for 3lis.de"""
import json, time, re, os, threading, queue, ipaddress, urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque, Counter, defaultdict
from datetime import datetime

LOGS = {
    "nginx": "/var/log/nginx/access.log",
    "auth":  "/var/log/auth.log",
    "f2b":   "/var/log/fail2ban.log",
}

ATTACKS = deque(maxlen=300)
STATS = Counter()
SEEN = set()
NEXT_ID = 0

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
# Ergebnis wird pro IP dauerhaft gecacht. Die meisten Angreifer-IPs
# treten aber nur EINMAL im Log auf (Scanner ziehen weiter) - wenn wir
# beim ersten Treffer nur den damaligen Cache-Stand einfrieren würden,
# bekäme so ein Angriff nie eine Position auf der Karte, weil der
# Lookup erst Sekunden später fertig wird. Deshalb wird das bereits im
# Feed sichtbare Attack-Dict in PENDING_GEO registriert und vom
# Worker-Thread nachträglich in-place mit lat/lon aktualisiert, sobald
# das Ergebnis da ist (das Frontend fragt das per Attack-ID erneut ab).
# ------------------------------------------------------------------
GEO_CACHE = {}          # ip -> {"lat","lon","country","countryCode"} oder None
GEO_QUEUED = set()
PENDING_GEO = defaultdict(list)  # ip -> Liste noch unaufgelöster Attack-Dicts
GEO_LOCK = threading.Lock()
GEO_QUEUE = queue.Queue(maxsize=500)
GEO_LOOKUP_INTERVAL = 1.4   # ~43 req/min, unter dem 45/min Free-Limit von ip-api.com
GEO_RETRY_DELAY = 10        # Sekunden bis zu einem erneuten Versuch nach Netzwerkfehler

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


def _enqueue(ip):
    if ip not in GEO_QUEUED:
        GEO_QUEUED.add(ip)
        try:
            GEO_QUEUE.put_nowait(ip)
        except queue.Full:
            GEO_QUEUED.discard(ip)


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
                pending = PENDING_GEO.pop(ip, [])
            if result:
                for attack in pending:
                    attack["lat"] = result["lat"]
                    attack["lon"] = result["lon"]
                    attack["country"] = result["country"]
                    attack["countryCode"] = result["countryCode"]
        except Exception:
            # Netzwerkfehler/Timeout/Rate-Limit: nicht dauerhaft cachen, später erneut versuchen
            with GEO_LOCK:
                GEO_QUEUED.discard(ip)
                still_wanted = ip in PENDING_GEO
            if still_wanted:
                threading.Timer(GEO_RETRY_DELAY, _retry, args=(ip,)).start()
        time.sleep(GEO_LOOKUP_INTERVAL)


def _retry(ip):
    with GEO_LOCK:
        if ip in PENDING_GEO and ip not in GEO_CACHE:
            _enqueue(ip)


def geolocate(ip):
    """Nicht-blockierend: liefert (geo, pending).
    geo ist die gecachte Geo-Position oder None. pending ist True, wenn die
    IP grundsätzlich auflösbar ist und ein Lookup dafür läuft/angestoßen
    wurde - nur dann lohnt es sich, das Attack-Dict für ein späteres
    In-place-Update vorzumerken (siehe register_pending)."""
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return None, False
    except ValueError:
        return None, False
    with GEO_LOCK:
        if ip in GEO_CACHE:
            return GEO_CACHE[ip], False
        _enqueue(ip)
    return None, True


def register_pending(ip, attack):
    """Merkt ein bereits ausgeliefertes Attack-Dict vor, damit es in-place mit
    lat/lon aktualisiert wird, sobald der asynchrone Geo-Lookup fertig ist."""
    with GEO_LOCK:
        if ip in GEO_CACHE:
            return  # zwischen geolocate() und hier bereits aufgelöst worden
        PENDING_GEO[ip].append(attack)


def parse_line(line, source):
    global NEXT_ID
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
            NEXT_ID += 1
            geo, pending = geolocate(ip)
            attack = {
                "id": NEXT_ID,
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
            }
            ATTACKS.appendleft(attack)
            if pending:
                register_pending(ip, attack)
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
