"""SSH-Honeypot auf Port 22 (das echte sshd läuft auf 22022): gibt sich als OpenSSH aus, schneidet
Benutzer, Passwörter und angebotene Schlüssel mit und lehnt jede Anmeldung ab. Es gibt keine Shell.
scp und sftp laufen über SSH und starten erst nach der Anmeldung, sie landen also ebenfalls hier.
"""
import base64
import hashlib
import logging
import os

import paramiko

from honeypot import Honeypot, attempt

VERSION = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
KEY_PATH = os.environ.get("ATTACK_SSH_KEY", "/var/lib/attack-monitor/ssh_host_rsa_key")
SESSION_TIME = 30  # Bots probieren mehrere Passwörter je Verbindung; danach auflegen

# paramiko loggt sonst jeden abgebrochenen Handshake mit Traceback ins Journal
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def host_key(path):
    """Einmal erzeugen und behalten: ein wechselnder Host-Key verrät den Honeypot."""
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(path)  # paramiko legt die Datei mit 0600 an
    return key


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class _DenyAll(paramiko.ServerInterface):
    def __init__(self, login):
        self.login = login

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_password(self, username, password):
        self.login(attempt(username, "Passwort", password))
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.login(f"{attempt(username)} · Schlüssel {key.get_name()} {fingerprint(key)}")
        return paramiko.AUTH_FAILED


class SSHHoneypot(Honeypot):
    PORT = 22
    TYPE = "SSH-Probe"

    def __init__(self, store, port=None, host="0.0.0.0", key_path=KEY_PATH):
        super().__init__(store, port, host)
        self.key = host_key(key_path)

    def handle(self, sock, ip, login):
        transport = paramiko.Transport(sock)
        try:
            transport.local_version = VERSION
            transport.add_server_key(self.key)
            transport.start_server(server=_DenyAll(login))
            transport.join(SESSION_TIME)  # Transport-Thread endet, wenn der Client aufgibt
        finally:
            transport.close()
