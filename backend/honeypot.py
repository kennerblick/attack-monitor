"""Gemeinsame Basis der Honeypots (MySQL, Postgres, SSH, FTP, Telnet): Port belegen, Verbindungen begrenzen,
Login-Versuche, Befehle und Malware-Samples als Event speichern. Ausgeführt wird nie etwas (Telnet/SSH: fakeshell.py,
MySQL/Postgres: feste Antworten); Downloads und hochgeladene Dateien landen nur als Datei in samples.py.

Nur IPv4, weil die API-Kürzung (/24) nur IPv4 kennt.
"""
import re
import socket
import threading
import time

import fakeshell
import samples
from parsers import event

TIMEOUT = 5
MAX_CONN = 50
PER_IP_PER_MIN = 30  # Flut einer einzelnen IP nicht vollständig speichern
NO_LOGIN = "Connection without login (service detection)"
SAMPLE_TYPE = "Malware-Sample"


def clean(value, limit=40):
    """Angreifer-Text für Detail und Top-Listen: “” sind dort Trennzeichen (und „ aus dem Altformat), Länge begrenzt."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = re.sub("[„“”]", '"', value or "")
    return "".join(c if c.isprintable() else "?" for c in value)[:limit] or None


def attempt(user, label=None, value=None):
    """Detailtext "Login attempt as “user” · label “value”"; store.py liest Benutzer und Passwort daraus."""
    text = f"Login attempt as “{clean(user) or '(empty)'}”"
    return text + (f" · {label} “{clean(value) or '(empty)'}”" if label else "")


class Honeypot:
    """Unterklassen setzen PORT und TYPE und implementieren handle(sock, ip, login)."""
    PORT = None
    TYPE = None

    def __init__(self, store, port=None, host="0.0.0.0"):
        self.store, self.host = store, host
        self.port = self.PORT if port is None else port
        self.slots = threading.BoundedSemaphore(MAX_CONN)
        self.recent = {}  # ip -> Zeitstempel der letzten Events (Flut-Bremse)

    def record(self, ip, sev, detail):
        now = time.time()
        times = [t for t in self.recent.get(ip, []) if now - t < 60]
        if len(times) >= PER_IP_PER_MIN:
            return
        self.recent[ip] = times + [now]
        if len(self.recent) > 10000:
            self.recent.clear()
        self.store.add_events([event(now, ip, self.TYPE, sev, "honeypot", self.PORT, detail)])

    def command(self, ip, line):
        """Befehl aus der Fake-Shell; store.py liest ihn aus dem Detail."""
        self.record(ip, "crit", f"Command “{clean(line, 100)}”")

    def sample(self, ip, data, source):
        """Datei eines Angreifers ablegen (samples.py). Das Event umgeht die Flutbremse: Samples sind selten,
        aber genau das, was wir sammeln wollen. store.py liest den Hash aus dem Detail."""
        digest, stored = samples.save(data)
        detail = (f"Sample “{digest}” · {len(data)} B · {samples.kind(data)} · {clean(source, 100)}"
                  + ("" if stored else " · not stored (storage full)"))
        self.store.add_events([event(time.time(), ip, SAMPLE_TYPE, "crit", "honeypot", self.PORT, detail)])

    def fetch(self, ip, url):
        """Download, den ein Bot in der Fake-Shell anstößt, selbst ausführen (gedrosselt, nur öffentliche Ziele)."""
        samples.fetch(url, lambda data: self.sample(ip, data, url))

    def shell(self, ip, run):
        """Fake-Shell-Sitzung beobachten: run(on_line) läuft die Sitzung; jede Zeile wird protokolliert, angestoßene
        Downloads geladen, per echo geschriebene Programme am Ende (auch nach Abbruch) als Sample gesichert."""
        drops = fakeshell.Drops()

        def on_line(line):
            self.command(ip, line)
            for url in fakeshell.downloads(line):
                self.fetch(ip, url)
            drops.feed(line)
        try:
            run(on_line)
        finally:
            for name, data in drops.files.items():
                if samples.looks_executable(data):
                    self.sample(ip, data, f"echo > {name}")

    def session(self, sock, ip):
        logins = 0

        def login(detail):
            nonlocal logins
            logins += 1
            self.record(ip, "high", detail)

        with sock:
            sock.settimeout(TIMEOUT)
            try:
                self.handle(sock, ip, login)
            except Exception:  # Angreifer schicken beliebigen Müll; die Verbindung endet dann still
                pass
            finally:
                if not logins:
                    self.record(ip, "low", NO_LOGIN)
                self.slots.release()

    def serve(self, ready=None):
        """Wartet, bis der Port frei ist (z. B. nach dem Abschalten eines echten Dienstes)."""
        while True:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, self.port))
                srv.listen(64)
                break
            except OSError as exc:
                print(f"honeypot {self.TYPE}: Port {self.port} belegt ({exc}), neuer Versuch in 60 s", flush=True)
                time.sleep(60)
        self.port = srv.getsockname()[1]
        if ready:
            ready.set()
        while True:
            sock, (ip, _) = srv.accept()
            if not self.slots.acquire(blocking=False):
                sock.close()
                continue
            threading.Thread(target=self.session, args=(sock, ip), daemon=True).start()
