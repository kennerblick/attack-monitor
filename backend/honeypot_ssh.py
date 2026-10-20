"""SSH-Honeypot auf Port 22 (das echte sshd läuft auf 22022): gibt sich als OpenSSH aus, schneidet
Benutzer, Passwörter und angebotene Schlüssel mit, nimmt jedes Passwort an und protokolliert die
Befehle in der Fake-Shell (fakeshell.py). scp/sftp-Uploads werden nicht angenommen.
"""
import base64
import hashlib
import logging
import os
import threading

import paramiko

import fakeshell
from honeypot import Honeypot, attempt

VERSION = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
KEY_PATH = os.environ.get("ATTACK_SSH_KEY", "/var/lib/attack-monitor/ssh_host_rsa_key")
SESSION_TIME = 30  # Zeit bis zum ersten Kanal (Anmeldung); danach gilt SHELL_TIMEOUT je Eingabe
SHELL_TIMEOUT = 20

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


class _Server(paramiko.ServerInterface):
    """Passwort wird angenommen, Schlüssel abgelehnt (Bots weichen dann aufs Passwort aus).
    Nur Session-Kanäle: Port-Forwarding bleibt verboten, sonst wäre der Honeypot ein offener Proxy."""

    def __init__(self, login):
        self.login, self.pty, self.command = login, False, None
        self.ready = threading.Event()

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_password(self, username, password):
        self.login(attempt(username, "Passwort", password))
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.login(f"{attempt(username)} · Schlüssel {key.get_name()} {fingerprint(key)}")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        self.pty = True
        return True

    def check_channel_shell_request(self, channel):
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode("utf-8", "replace")
        self.ready.set()
        return True


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
            server = _Server(login)
            transport.start_server(server=server)
            chan = transport.accept(SESSION_TIME)  # None, wenn der Client nach Fehlversuchen aufgibt
            if chan is None or not server.ready.wait(SHELL_TIMEOUT):
                return
            chan.settimeout(SHELL_TIMEOUT)
            send = lambda text: chan.sendall(text.encode())
            if server.command is not None:  # ssh host 'befehl' bzw. scp
                self.command(ip, server.command)
                send(fakeshell.respond(server.command) or "")
                chan.send_exit_status(0)
            else:
                fakeshell.run_shell(fakeshell.Lines(lambda n: self._recv(chan, n, server.pty)), send,
                                    lambda line: self.command(ip, line))
            chan.close()
        finally:
            transport.close()

    @staticmethod
    def _recv(chan, n, echo):
        data = chan.recv(n)
        if echo:  # mit PTY erwartet der Client das Echo vom Server
            chan.sendall(data.replace(b"\r", b"\r\n"))
        return data
