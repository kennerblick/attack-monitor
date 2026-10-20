#!/usr/bin/env python3
"""Live Attack Monitor API für 3lis.de.

Endpoints (alle JSON, nur lesend):
  /api/feed?since=<id>   neueste Events (max. 80), optional nur neuer als <id>
  /api/stats?range=1h|24h|7d   Kennzahlen, Top-Listen, Zeitleiste, Heatmap
  /api/status            Server-Standort, aktive fail2ban-Bans, Sperrliste
  /api/events?kind=type|cc|asn|port|user|path|jail|ip&value=..&range=..   Vorgänge zu einem Top-Listen-Eintrag
  /api/ip?id=<event-id>  Profil der IP hinter einem Event (Verlauf, Verhalten, rDNS, Einstufung, Sperrstatus)
Angreifer-IPs werden vor der Auslieferung auf /24 gekürzt (DSGVO).
"""
import ast
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import geo
import intel
import stats
import tail
from store import Store

DB_PATH = os.environ.get("ATTACK_DB", "/var/lib/attack-monitor/events.db")
LISTEN = ("127.0.0.1", int(os.environ.get("ATTACK_PORT", "8099")))
HOSTS_DENY = "/etc/hosts.deny"
IPV4 = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b')

_cache = {}


def cached(key, ttl, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    value = fn()
    _cache[key] = (time.time(), value)
    return value


def mask(text):
    return IPV4.sub(r'\1.x', text) if text else text


def masked(events):
    for e in events:
        e["ip"] = mask(e["ip"])
        e["detail"] = mask(e["detail"])
    return events


def f2b_banned():
    """Jail -> Liste gesperrter IPs (nur intern, nie ausgeliefert)."""
    try:
        out = subprocess.run(["fail2ban-client", "banned"], capture_output=True, text=True, timeout=5).stdout
        return {jail: ips for entry in ast.literal_eval(out) for jail, ips in entry.items()}
    except Exception:
        return {}


def denied_ips():
    try:
        with open(HOSTS_DENY, errors="ignore") as fh:
            return {line.split(":", 1)[1].strip() for line in fh if line.startswith("ALL:")}
    except OSError:
        return set()


def ip_profile(store, event_id):
    found = store.ip_profile(event_id)
    if not found:
        return None
    ip, p = found
    g = p["geo"]
    host = intel.ptr(ip)
    cls = intel.classify(host, g.get("isp"), g.get("org"), g.get("hosting"), g.get("proxy"), g.get("mobile"))
    banned = [j for j, ips in cached("banned", 30, f2b_banned).items() if ip in ips]
    p["users"] = [(mask(u), n) for u, n in p["users"]]
    p["paths"] = [(mask(x), n) for x, n in p["paths"]]
    p.update(ip=mask(ip), host=intel.mask_host(host, ip), cls=cls, verdict=intel.verdict(cls, p),
             banned=banned, denied=ip in cached("denied", 300, denied_ips))
    return p


def blocklist_size():
    return len(cached("denied", 300, denied_ips))


def make_handler(store, server_location):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlparse(self.path)
            q = parse_qs(url.query)
            try:
                if url.path == "/api/feed":
                    body = {"events": masked(store.feed(int(q.get("since", ["0"])[0] or 0))), "ts": time.time()}
                elif url.path == "/api/events":
                    span = stats.RANGES.get(q.get("range", ["24h"])[0], stats.RANGES["24h"])[0]
                    total, events = store.events_where(q["kind"][0], q["value"][0], time.time() - span)
                    body = {"total": total, "events": masked(events)}
                elif url.path == "/api/ip":
                    body = ip_profile(store, int(q["id"][0]))
                    if body is None:
                        return self.send_error(404)
                elif url.path == "/api/stats":
                    key = q.get("range", ["24h"])[0]
                    key = key if key in stats.RANGES else "24h"  # begrenzt auch die Cache-Schlüssel
                    body = cached(f"stats-{key}", 10, lambda: stats.compute(store, key))
                elif url.path == "/api/status":
                    bans = {j: len(ips) for j, ips in cached("banned", 30, f2b_banned).items()}
                    body = {"server": server_location, "bans": bans, "bansTotal": sum(bans.values()),
                            "blocklist": cached("blocklist", 300, blocklist_size), "ts": time.time()}
                else:
                    return self.send_error(404)
            except (ValueError, KeyError, IndexError):
                return self.send_error(400)
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass
    return Handler


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    store = Store(DB_PATH)
    threading.Thread(target=geo.worker, args=(store,), daemon=True).start()
    threading.Thread(target=tail.run, args=(store,), daemon=True).start()
    print(f"Attack Monitor API listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    ThreadingHTTPServer(LISTEN, make_handler(store, geo.server_location())).serve_forever()
