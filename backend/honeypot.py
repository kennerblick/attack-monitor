"""MySQL-Honeypot auf Port 3306: spielt die Begrüßung eines MariaDB-Servers, liest das
Login-Paket mit (Benutzer, Datenbank) und lehnt jeden Login mit "Access denied" ab.

Es gibt keine Datenbank und keine Befehlsausführung – nur Mitschnitt als Event "MySQL-Probe".
Passwörter sieht der Honeypot nicht: Clients schicken bei mysql_native_password nur einen Hash.
Nur IPv4, weil die API-Kürzung (/24) nur IPv4 kennt.
"""
import os
import socket
import struct
import threading
import time

from parsers import event

PORT = 3306
TIMEOUT = 5
MAX_CONN = 50
MAX_PACKET = 4096
PER_IP_PER_MIN = 30  # Flut einer einzelnen IP nicht vollständig speichern
VERSION = b"5.5.5-10.11.6-MariaDB-0+deb12u1"
# LONG_PASSWORD | FOUND_ROWS | LONG_FLAG | CONNECT_WITH_DB | PROTOCOL_41 | TRANSACTIONS | SECURE_CONNECTION
# | PLUGIN_AUTH; bewusst ohne SSL, damit Clients das Login-Paket im Klartext senden
CAPS = 0x0008A20F
CONNECT_WITH_DB = 0x8


def packet(seq, payload):
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def greeting(conn_id):
    salt = os.urandom(20)
    return packet(0, b"\x0a" + VERSION + b"\0" + struct.pack("<I", conn_id) + salt[:8] + b"\0"
                  + struct.pack("<H", CAPS & 0xFFFF) + b"\x21" + struct.pack("<H", 2)
                  + struct.pack("<H", CAPS >> 16) + bytes([21]) + b"\0" * 10 + salt[8:] + b"\0"
                  + b"mysql_native_password\0")


def access_denied(seq, user, ip):
    msg = f"Access denied for user '{user}'@'{ip}' (using password: YES)".encode(errors="replace")
    return packet(seq, b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg)


def parse_login(payload):
    """HandshakeResponse41 -> (user, db); None, wenn es kein Login-Paket ist."""
    if len(payload) < 33:
        return None  # z. B. SSL-Request oder Müll
    caps = struct.unpack("<I", payload[:4])[0]
    rest = payload[32:]
    user, _, rest = rest.partition(b"\0")
    db = None
    if rest:
        auth_len = rest[0]
        rest = rest[1 + auth_len:]
        if caps & CONNECT_WITH_DB and rest:
            db = rest.partition(b"\0")[0]
    clean = lambda b: b.decode("utf-8", "replace")[:40] if b else None
    return clean(user) or "(leer)", clean(db)


def _read_packet(sock):
    head = sock.recv(4)
    if len(head) < 4:
        return None, None
    length = int.from_bytes(head[:3], "little")
    if length > MAX_PACKET:
        return None, None
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return head[3], data


class Honeypot:
    def __init__(self, store, port=PORT, host="0.0.0.0"):
        self.store, self.port, self.host = store, port, host
        self.slots = threading.BoundedSemaphore(MAX_CONN)
        self.recent = {}  # ip -> Zeitstempel der letzten Events (Flut-Bremse)
        self.conn_id = 1000

    def record(self, ip, sev, detail):
        now = time.time()
        times = [t for t in self.recent.get(ip, []) if now - t < 60]
        if len(times) >= PER_IP_PER_MIN:
            return
        self.recent[ip] = times + [now]
        if len(self.recent) > 10000:
            self.recent.clear()
        self.store.add_events([event(now, ip, "MySQL-Probe", sev, "honeypot", PORT, detail)])

    def handle(self, sock, ip):
        with sock:
            sock.settimeout(TIMEOUT)
            try:
                self.conn_id += 1
                sock.sendall(greeting(self.conn_id))
                seq, payload = _read_packet(sock)
                login = parse_login(payload) if payload else None
                if not login:
                    self.record(ip, "low", "Verbindung ohne Login (Server-Erkennung)")
                    return
                user, db = login
                self.record(ip, "high", f"Login-Versuch als „{user}“" + (f" · DB „{db}“" if db else ""))
                sock.sendall(access_denied((seq + 1) % 256, user, ip))
            except OSError:
                self.record(ip, "low", "Verbindung ohne Login (Server-Erkennung)")
            finally:
                self.slots.release()

    def serve(self, ready=None):
        """Wartet, bis der Port frei ist (z. B. nach dem Abschalten der echten MariaDB)."""
        while True:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, self.port))
                srv.listen(64)
                break
            except OSError as exc:
                print(f"honeypot: Port {self.port} belegt ({exc}), neuer Versuch in 60 s", flush=True)
                time.sleep(60)
        self.port = srv.getsockname()[1]
        if ready:
            ready.set()
        while True:
            sock, (ip, _) = srv.accept()
            if not self.slots.acquire(blocking=False):
                sock.close()
                continue
            threading.Thread(target=self.handle, args=(sock, ip), daemon=True).start()
