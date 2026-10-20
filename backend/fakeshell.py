"""Fake-Shell für Telnet- und SSH-Honeypot: plausibel genug, dass Bots ihre Befehlskette weiter
abarbeiten. Nichts wird ausgeführt oder heruntergeladen; die Antworten kommen aus festen Tabellen.
"""
import re

MAX_COMMANDS = 25  # + Login bleibt unter der Flutbremse von 30 Events pro IP und Minute
MAX_LINE = 4096
BANNER = "\r\n\r\nBusyBox v1.30.1 () built-in shell (ash)\r\n\r\n"
PROMPT = "root@router:~# "

OUTPUT = {
    "uname": "Linux", "uname -a": "Linux router 4.14.180 #1 SMP PREEMPT armv7l GNU/Linux",
    "uname -m": "armv7l", "uname -r": "4.14.180", "whoami": "root", "id": "uid=0(root) gid=0(root)",
    "pwd": "/root", "hostname": "router", "nproc": "1", "ls": "", "ps": "  PID USER       VSZ STAT COMMAND\r\n"
    "    1 root      1544 S    init", "uptime": " 12:01:33 up 41 days,  3:12,  load average: 0.08, 0.03, 0.01",
}
FILES = {
    "/proc/cpuinfo": "processor\t: 0\r\nmodel name\t: ARMv7 Processor rev 5 (v7l)\r\nBogoMIPS\t: 48.00",
    "/proc/mounts": "rootfs / rootfs rw 0 0\r\ntmpfs /tmp tmpfs rw,relatime 0 0",
}
# Befehle ohne Ausgabe; Mirai & Co. schicken enable/system/shell/sh, um aus Router-CLIs auszubrechen
SILENT = {"enable", "system", "shell", "sh", "linuxshell", "cd", "chmod", "rm", "cp", "mv", "mkdir", "export",
          "history", "unset", "kill", "pkill", "killall", "dd", "sleep", "ulimit", "crontab", "touch", "true"}
DOWNLOADERS = {"wget", "curl", "tftp", "ftpget"}
APPLETS = SILENT | DOWNLOADERS | {"echo", "cat", "ls", "ps", "uname", "nproc", "id", "whoami", "hostname"}


def _echo(words):
    text = " ".join(w.strip("'\"") for w in words if w not in ("-e", "-n", "-ne", "-en"))
    try:  # Bots prüfen mit echo -e '\x41\x4b', ob die Shell Escapes auswertet
        return text.encode("latin-1", "replace").decode("unicode_escape")
    except UnicodeDecodeError:
        return text


def _one(words):
    if words[0].rsplit("/", 1)[-1] == "busybox" and len(words) > 1:
        words = words[1:]
        if words[0] not in APPLETS:
            return f"{words[0]}: applet not found\r\n"  # Mirai erkennt BusyBox genau an dieser Antwort
    name = words[0].rsplit("/", 1)[-1]
    cmd = " ".join([name] + words[1:])
    if cmd in OUTPUT:
        return OUTPUT[cmd] + "\r\n" if OUTPUT[cmd] else ""
    if name == "echo":
        return _echo(words[1:]) + "\r\n"
    if name == "cat":
        return "".join(FILES[f] + "\r\n" if f in FILES else f"cat: {f}: No such file or directory\r\n"
                       for f in words[1:])
    if name in DOWNLOADERS:
        return f"{name}: download timed out\r\n"
    if name in SILENT:
        return ""
    return f"sh: {name}: not found\r\n"


def respond(line):
    """Ausgabe zu einer Befehlszeile; None bei exit/logout."""
    out = []
    for part in re.split(r";|&&|\|\||\|", line):
        words = part.split()
        if not words:
            continue
        if words[0] in ("exit", "logout", "quit"):
            return None
        out.append(_one(words))
    return "".join(out)


class Lines:
    """Zeilen aus einem Byte-Strom; \\r, \\n und \\0 beenden eine Zeile, leere Zeilen entfallen."""

    def __init__(self, recv, strip=None):
        self.recv, self.strip, self.buf, self.pending = recv, strip, b"", []

    def next(self):
        while not self.pending:
            data = self.recv(1024)
            if not data:
                return None
            self.buf += self.strip(data) if self.strip else data
            *done, self.buf = re.split(rb"[\r\n\0]+", self.buf)
            self.pending = [line for line in done if line.strip()]
            if len(self.buf) > MAX_LINE:
                return None
        return self.pending.pop(0).decode("utf-8", "replace").strip()


def run_shell(lines, send, on_command):
    send(BANNER)
    for _ in range(MAX_COMMANDS):
        send(PROMPT)
        line = lines.next()
        if line is None:
            return
        on_command(line)
        out = respond(line)
        if out is None:
            return
        send(out)
