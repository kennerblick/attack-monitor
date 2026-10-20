"""MySQL-Honeypot auf Port 3306: spielt die Begrüßung eines MariaDB-Servers, liest das
Login-Paket mit (Benutzer, Datenbank) und lehnt jeden Login mit "Access denied" ab.

Passwörter sieht er nicht: Clients schicken bei mysql_native_password nur einen Hash.
"""
import os
import struct

from honeypot import Honeypot, attempt, clean

MAX_PACKET = 4096
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


class MySQLHoneypot(Honeypot):
    PORT = 3306
    TYPE = "MySQL-Probe"
    conn_id = 1000

    def handle(self, sock, ip, login):
        self.conn_id += 1
        sock.sendall(greeting(self.conn_id))
        seq, payload = _read_packet(sock)
        parsed = parse_login(payload) if payload else None
        if not parsed:
            return
        user, db = parsed
        login(attempt(user, "DB", db) if db else attempt(user))
        sock.sendall(access_denied((seq + 1) % 256, user, ip))
