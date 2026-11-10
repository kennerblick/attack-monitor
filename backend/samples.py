"""Malware-Samples der Honeypots: hochgeladene Dateien (scp, „cat > datei“, echo-Dropper) und Downloads, die Bots
per wget/curl/tftp anstoßen. Abgelegt als <sha256> mit 0400 – nie ausgeführt, nie über das Web ausgeliefert,
nicht im Backup (Malware im Google Drive gefährdet den Account; die Metadaten stehen als Event in der DB).

Downloads nur von öffentlichen IPv4-Adressen, sonst wäre der Honeypot ein Sprungbrett ins VPN/Homelab.
"""
import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import struct
import threading
import time
from urllib.parse import urljoin, urlsplit

DIR = os.environ.get("ATTACK_SAMPLES", "/var/lib/attack-monitor/samples")
MAX_SIZE = 10 * 1024 * 1024
MAX_TOTAL = 2 * 1024 ** 3  # danach nur noch Hash und Event, damit Uploads die Platte nicht füllen
TIMEOUT = 15
MAX_REDIRECTS = 3
FETCH_PER_HOUR = 60
USER_AGENT = "Wget/1.21.3"
ARCH = {2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 42: "SuperH",
        43: "SPARC64", 62: "x86-64", 183: "ARM64", 243: "RISC-V"}

_parallel = threading.BoundedSemaphore(4)
_lock = threading.Lock()
_fetched = []  # Zeitpunkte der Downloads der letzten Stunde
_urls = {}  # url -> Zeitpunkt; dieselbe URL höchstens einmal pro Stunde laden


def kind(data):
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        machine = struct.unpack("<H" if data[5] == 1 else ">H", data[18:20])[0]
        return f"ELF {ARCH.get(machine, machine)}"
    if data[:2] == b"#!":
        return "script"
    if data[:2] == b"MZ":
        return "Windows-EXE"
    return "data"


def looks_executable(data):
    """Dropper schreiben auch Testdateien („echo AK > .t“); nur Programme und Skripte sind Samples."""
    return kind(data) != "data" or len(data) >= 1024


def _used():
    return sum(e.stat().st_size for e in os.scandir(DIR) if e.is_file()) if os.path.isdir(DIR) else 0


def save(data):
    """Legt das Sample ab (gleiche Inhalte nur einmal); liefert (sha256, gespeichert?)."""
    digest = hashlib.sha256(data).hexdigest()
    path = os.path.join(DIR, digest)
    with _lock:
        if os.path.exists(path):
            return digest, True
        if _used() + len(data) > MAX_TOTAL:
            return digest, False
        os.makedirs(DIR, mode=0o750, exist_ok=True)
        tmp = path + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400), "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    return digest, True


def public_ip(host):
    ip = socket.gethostbyname(host or "")
    if not ipaddress.ip_address(ip).is_global:
        raise ValueError(f"keine öffentliche Adresse: {ip}")
    return ip


def _http(url, hops=0):
    parts = urlsplit(url)
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    # Mit der geprüften IP verbinden statt erneut aufzulösen (DNS-Rebinding ins interne Netz)
    sock = socket.create_connection((public_ip(parts.hostname), port), TIMEOUT)
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # Malware-Server haben selten gültige Zertifikate
        sock = ctx.wrap_socket(sock, server_hostname=parts.hostname)
    conn = http.client.HTTPConnection(parts.hostname, port, timeout=TIMEOUT)
    conn.sock = sock
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers={"User-Agent": USER_AGENT})
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308) and hops < MAX_REDIRECTS:
            return _http(urljoin(url, resp.getheader("Location", "")), hops + 1)
        if resp.status != 200:
            return None
        data = resp.read(MAX_SIZE + 1)
        return data if len(data) <= MAX_SIZE else None
    finally:
        conn.close()


def _tftp(url):
    parts = urlsplit(url)
    ip, port = public_ip(parts.hostname), parts.port or 69
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(b"\0\1" + parts.path.lstrip("/").encode() + b"\0octet\0", (ip, port))
        data, block = b"", 1
        while len(data) <= MAX_SIZE:
            packet, peer = sock.recvfrom(516)
            if peer[0] != ip:
                continue
            op, number = struct.unpack("!HH", packet[:4])
            if op != 3:  # 5 = Fehler des Servers
                return None
            if number == block:
                data, block = data + packet[4:], (block + 1) & 0xFFFF
            sock.sendto(struct.pack("!HH", 4, number), peer)
            if len(packet) < 516:
                return data
    return None


def _allowed(url):
    now = time.time()
    with _lock:
        _fetched[:] = [t for t in _fetched if now - t < 3600]
        if len(_fetched) >= FETCH_PER_HOUR or now - _urls.get(url, 0) < 3600:
            return False
        if len(_urls) > 10000:
            _urls.clear()
        _fetched.append(now)
        _urls[url] = now
    return True


def fetch(url, done):
    """Lädt url (http/https/tftp) im Hintergrund und ruft done(data) auf; Fehler bleiben still."""
    if urlsplit(url).scheme not in ("http", "https", "tftp") or not _allowed(url):
        return

    def run():
        with _parallel:
            try:
                data = _tftp(url) if url.startswith("tftp:") else _http(url)
            except (OSError, ValueError, http.client.HTTPException):
                return
            if data:
                done(data)

    threading.Thread(target=run, daemon=True).start()
