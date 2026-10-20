"""Telnet-Honeypot auf Port 23: Login-Prompt eines BusyBox-Routers, nimmt jede Anmeldung an und
schneidet Benutzer, Passwort und die Befehle in der Fake-Shell mit (fakeshell.py).
"""
import re

import fakeshell
from honeypot import Honeypot, attempt

SHELL_TIMEOUT = 20  # Bots antworten schnell; Menschen dürfen etwas länger tippen
# Telnet-Optionsverhandlung (IAC …) entfernen, sonst landet sie im Benutzernamen
IAC = re.compile(rb"\xff\xfa.*?\xff\xf0|\xff[\xfb-\xfe].|\xff.", re.S)


class TelnetHoneypot(Honeypot):
    PORT = 23
    TYPE = "Telnet-Probe"

    def handle(self, sock, ip, login):
        sock.settimeout(SHELL_TIMEOUT)
        send = lambda text: sock.sendall(text.encode())
        lines = fakeshell.Lines(sock.recv, lambda data: IAC.sub(b"", data))
        send("\r\nrouter login: ")
        user = lines.next()
        if user is None:
            return
        send("Password: ")
        password = lines.next()
        if password is None:
            return
        login(attempt(user, "Passwort", password))
        fakeshell.run_shell(lines, send, lambda line: self.command(ip, line))
