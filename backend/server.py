#!/usr/bin/env python3
"""Live Attack Monitor API for 3lis.de"""
import json, time, re, os
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque, Counter
from datetime import datetime
import threading

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
            ATTACKS.appendleft({
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": ip,
                "type": typ,
                "sev": sev,
                "src": source,
                "raw": line.strip()[:140],
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
                "ts": datetime.now().isoformat(),
            }
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    threading.Thread(target=tail_logs, daemon=True).start()
    print("Attack Monitor API listening on 127.0.0.1:8099")
    HTTPServer(("127.0.0.1", 8099), Handler).serve_forever()
