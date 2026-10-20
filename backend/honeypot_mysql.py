"""MySQL-Honeypot auf Port 3306: spielt die Begrüßung eines MariaDB-Servers, liest das
Login-Paket mit (Benutzer, Datenbank), nimmt jeden Login an und schneidet die SQL-Abfragen mit.
Es gibt keine Datenbank: Antworten kommen aus festen Tabellen, alles andere bekommt "OK".

Passwörter sieht er nicht: Clients schicken bei mysql_native_password nur einen Hash.
"""
import os
import struct

from fakeshell import MAX_COMMANDS
from honeypot import Honeypot, attempt, clean

MAX_PACKET = 4096
MAX_DISCARD = 1 << 20  # größere Pakete (z. B. UDF-Upload als Hex) lesen, aber nur den Anfang behalten
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


def ok(seq):
    return packet(seq, b"\x00\x00\x00\x02\x00\x00\x00")


def eof(seq):
    return packet(seq, b"\xfe\x00\x00\x02\x00")


def lenenc(value):
    data = value.encode(errors="replace")
    return bytes([len(data)]) + data  # Werte bleiben unter 251 Bytes


def result(seq, column, rows):
    """Textprotokoll-Ergebnis mit einer Spalte (ohne CLIENT_DEPRECATE_EOF, also mit EOF-Paketen)."""
    coldef = (lenenc("def") + lenenc("") * 3 + lenenc(column) * 2 + b"\x0c" + struct.pack("<HIBHB", 0x21, 1024, 0xFD, 0, 0)
              + b"\0\0")
    out = [packet(seq, b"\x01"), packet(seq + 1, coldef), eof(seq + 2)]
    out += [packet(seq + 3 + i, lenenc(r)) for i, r in enumerate(rows)]
    out.append(eof(seq + 3 + len(rows)))
    return b"".join(out)


def answer(query, user, ip, db):
    """Feste Antwort auf typische Bot-Abfragen: (Spaltenname, Zeilen) oder None für OK."""
    q = " ".join(query.lower().split()).rstrip(";")
    if "@@version_comment" in q:
        return "@@version_comment", ["Debian 12"]
    if "version()" in q or "@@version" in q:
        return "version()", [VERSION.decode()[6:]]
    if q in ("show databases", "show schemas"):
        return "Database", ["information_schema", "mysql", "performance_schema", "wordpress"]
    if "user()" in q:
        return "user()", [f"{user}@{ip}"]
    if "database()" in q:
        return "database()", [db or "wordpress"]
    if q == "show tables":
        return "Tables_in_wordpress", ["wp_options", "wp_posts", "wp_users"]
    return None


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
    if length > MAX_DISCARD:
        return None, None
    data, got = b"", 0
    while got < length:
        chunk = sock.recv(min(65536, length - got))
        if not chunk:
            break
        got += len(chunk)
        data += chunk[:MAX_PACKET - len(data)]
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
        sock.sendall(ok((seq + 1) % 256))
        for _ in range(MAX_COMMANDS):
            _, payload = _read_packet(sock)
            if not payload or payload[0] == 0x01:  # COM_QUIT
                return
            text = clean(payload[1:], MAX_PACKET)
            if payload[0] == 0x02:  # COM_INIT_DB
                db = text
                self.command(ip, f"USE {text}")
            elif payload[0] == 0x03 and text:  # COM_QUERY
                self.command(ip, text)
                reply = answer(text, user, ip, db)
                sock.sendall(result(1, *reply) if reply else ok(1))
                continue
            sock.sendall(ok(1))  # PING, INIT_DB und alles andere
