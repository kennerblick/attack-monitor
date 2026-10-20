"""Gemeinsame Basis der Honeypots (MySQL, Postgres, SSH, FTP, Telnet): Port belegen, Verbindungen begrenzen,
Login-Versuche und Befehle als Event speichern. Ausgeführt wird nie etwas (Telnet/SSH: fakeshell.py, MySQL/Postgres: feste Antworten).

Nur IPv4, weil die API-Kürzung (/24) nur IPv4 kennt.
"""
import socket
import threading
import time

from parsers import event

TIMEOUT = 5
MAX_CONN = 50
PER_IP_PER_MIN = 30  # Flut einer einzelnen IP nicht vollständig speichern
NO_LOGIN = "Verbindung ohne Login (Server-Erkennung)"


def clean(value, limit=40):
    """Angreifer-Text für Detail und Top-Listen: „“ sind dort Trennzeichen, Länge begrenzt."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = (value or "").replace("„", '"').replace("“", '"')
    return "".join(c if c.isprintable() else "?" for c in value)[:limit] or None


def attempt(user, label=None, value=None):
    """Detailtext "Login-Versuch als „user“ · Label „value“"; store.py liest Benutzer und Passwort daraus."""
    text = f"Login-Versuch als „{clean(user) or '(leer)'}“"
    return text + (f" · {label} „{clean(value) or '(leer)'}“" if label else "")


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
        self.record(ip, "crit", f"Befehl „{clean(line, 100)}“")

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
