"""PostgreSQL-Honeypot auf Port 5432: verlangt das Passwort im Klartext (AuthenticationCleartextPassword,
libpq & Co. schicken es ohne Rückfrage), nimmt jeden Login an und schneidet die SQL-Abfragen mit.
Es gibt keine Datenbank: Antworten kommen aus festen Tabellen. Typischer Angriff ist
COPY … FROM PROGRAM (Kinsing-Miner) – das wird nur protokolliert, nie ausgeführt.
"""
import os
import struct

from fakeshell import MAX_COMMANDS
from honeypot import Honeypot, attempt, clean

MAX_MESSAGE = 4096
MAX_DISCARD = 1 << 20  # größere Nachrichten lesen, aber nur den Anfang behalten
SSL_REQUEST, GSS_REQUEST, PROTOCOL_3 = 80877103, 80877104, 196608
VERSION = "16.4 (Debian 16.4-1.pgdg120+1)"
PARAMS = {"server_version": VERSION.split()[0], "server_encoding": "UTF8", "client_encoding": "UTF8",
          "DateStyle": "ISO, MDY", "integer_datetimes": "on", "standard_conforming_strings": "on"}


def message(kind, payload=b""):
    return kind + struct.pack("!I", len(payload) + 4) + payload


def cstr(value):
    return value.encode(errors="replace") + b"\0"


def ready():
    return message(b"Z", b"I")


def complete(tag):
    return message(b"C", cstr(tag))


def rows(column, values):
    """RowDescription (eine Text-Spalte), DataRows, CommandComplete."""
    out = message(b"T", struct.pack("!H", 1) + cstr(column) + struct.pack("!IHIhih", 0, 0, 25, -1, -1, 0))
    for v in values:
        data = v.encode(errors="replace")
        out += message(b"D", struct.pack("!HI", 1, len(data)) + data)
    return out + complete(f"SELECT {len(values)}")


def tag(query):
    """Plausibler CommandComplete-Tag für Abfragen ohne Ergebnis."""
    word = (query.split() or ["SELECT"])[0].upper()
    return {"INSERT": "INSERT 0 1", "SELECT": "SELECT 0", "UPDATE": "UPDATE 0", "DELETE": "DELETE 0",
            "COPY": "COPY 0"}.get(word, word)


def answer(query, user, db):
    """Feste Antwort auf typische Bot-Abfragen als Nachrichtenfolge."""
    q = " ".join(query.lower().split()).rstrip(";")
    if "version()" in q:
        return rows("version", [f"PostgreSQL {VERSION} on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) "
                                "12.2.0, 64-bit"])
    if "current_user" in q or q.startswith("select user"):
        return rows("current_user", [user])
    if "current_database()" in q:
        return rows("current_database", [db])
    if "from pg_database" in q:
        return rows("datname", ["postgres", "template1", "template0", db] if db != "postgres" else
                    ["postgres", "template1", "template0"])
    return complete(tag(query))


def _read(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError
        data += chunk
    return data


def _read_body(sock, length):
    """Nachrichteninhalt lesen; mehr als MAX_MESSAGE Bytes werden verworfen."""
    if not 0 <= length <= MAX_DISCARD:
        raise ConnectionError
    data, got = b"", 0
    while got < length:
        chunk = _read(sock, min(65536, length - got))
        got += len(chunk)
        data += chunk[:MAX_MESSAGE - len(data)]
    return data


def read_startup(sock):
    """Startup-Paket -> Parameter (user, database, …); SSL/GSS werden abgelehnt, dann neuer Versuch."""
    for _ in range(3):
        length, code = struct.unpack("!II", _read(sock, 8))
        body = _read_body(sock, length - 8)
        if code in (SSL_REQUEST, GSS_REQUEST):
            sock.sendall(b"N")  # kein TLS: Login folgt im Klartext
            continue
        if code != PROTOCOL_3:
            return None
        parts = body.split(b"\0")
        return {clean(k): clean(v, 63) for k, v in zip(parts[::2], parts[1::2]) if k}
    return None


def read_message(sock):
    kind, length = struct.unpack("!cI", _read(sock, 5))
    return kind, _read_body(sock, length - 4)


class PostgresHoneypot(Honeypot):
    PORT = 5432
    TYPE = "Postgres-Probe"

    def handle(self, sock, ip, login):
        params = read_startup(sock)
        if not params:
            return
        user = params.get("user") or "(leer)"
        db = params.get("database") or user
        sock.sendall(message(b"R", struct.pack("!I", 3)))  # AuthenticationCleartextPassword
        kind, body = read_message(sock)
        if kind != b"p":
            return
        login(attempt(user, "Passwort", body.rstrip(b"\0")))
        status = b"".join(message(b"S", cstr(k) + cstr(v)) for k, v in PARAMS.items())
        sock.sendall(message(b"R", struct.pack("!I", 0)) + status
                     + message(b"K", struct.pack("!I", os.getpid() % 30000 + 1000) + os.urandom(4)) + ready())
        self.session_loop(sock, ip, user, db)

    def session_loop(self, sock, ip, user, db):
        for _ in range(MAX_COMMANDS):
            kind, body = read_message(sock)
            if kind == b"X":  # Terminate
                return
            if kind == b"Q":  # Simple Query
                query = clean(body.rstrip(b"\0"), MAX_MESSAGE)
                if query:
                    self.command(ip, query)
                sock.sendall((answer(query, user, db) if query else message(b"I")) + ready())
            elif kind == b"P":  # Extended Query: Parse(name, query, …) – nur mitschneiden
                self.command(ip, clean(body.split(b"\0")[1], MAX_MESSAGE) or "")
                sock.sendall(message(b"1"))
            elif kind == b"B":
                sock.sendall(message(b"2"))
            elif kind == b"D":
                sock.sendall(message(b"n"))
            elif kind == b"E":
                sock.sendall(complete("SELECT 0"))
            elif kind == b"S":
                sock.sendall(ready())
