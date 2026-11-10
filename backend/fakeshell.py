"""Fake-Shell für Telnet- und SSH-Honeypot: plausibel genug, dass Bots ihre Befehlskette weiter
abarbeiten. Nichts wird ausgeführt; die Antworten kommen aus festen Tabellen. downloads() und Drops liefern
nur, was der Honeypot als Malware-Sample sichert (samples.py lädt, honeypot.py speichert).
"""
import re
import shlex

MAX_COMMANDS = 25  # + Login bleibt unter der Flutbremse von 30 Events pro IP und Minute
MAX_LINE = 4096


def _cpuinfo(cores, model):
    return "\r\n\r\n".join(f"processor\t: {i}\r\nmodel name\t: {model}\r\ncpu cores\t: {cores}" for i in range(cores))


# Telnet: BusyBox-Router (Mirai & Co. suchen ARM/MIPS). SSH: Debian-VPS mit 4 Kernen, passend zur SSH-Version
# in honeypot_ssh.py; Miner-Dropper laden erst, wenn uname/cpuinfo/free nach lohnender x86-Hardware aussehen.
ROUTER = {
    "banner": "\r\n\r\nBusyBox v1.30.1 () built-in shell (ash)\r\n\r\n", "prompt": "root@router:~# ",
    "missing": "sh: {}: not found",
    "uname": {"s": "Linux", "n": "router", "r": "4.14.180", "v": "#1 SMP PREEMPT", "m": "armv7l", "o": "GNU/Linux"},
    "output": {"nproc": "1", "ps": "  PID USER       VSZ STAT COMMAND\r\n    1 root      1544 S    init",
               "free": "              total        used        free      shared  buff/cache   available\r\n"
                       "Mem:         124580       38212       61340        1204       25028       80112\r\n"
                       "Swap:             0           0           0"},
    "files": {"/proc/cpuinfo": _cpuinfo(1, "ARMv7 Processor rev 5 (v7l)") + "\r\nBogoMIPS\t: 48.00",
              "/proc/mounts": "rootfs / rootfs rw 0 0\r\ntmpfs /tmp tmpfs rw,relatime 0 0"},
}
_FREE_M = ("               total        used        free      shared  buff/cache   available\r\n"
           "Mem:            7941        1187        4519          12        2235        6497\r\n"
           "Swap:           2047           0        2047")
_XEON = "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"
SERVER = {
    "banner": "Linux web01 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64\r\n\r\n"
              "Last login: Mon Nov  3 08:14:52 2025 from 10.0.0.5\r\n",
    "prompt": "root@web01:~# ", "missing": "-bash: {}: command not found",
    "uname": {"s": "Linux", "n": "web01", "r": "6.1.0-28-amd64", "v": "#1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 "
              "(2024-11-22)", "m": "x86_64", "p": "unknown", "i": "unknown", "o": "GNU/Linux"},
    "output": {
        "nproc": "4", "free -m": _FREE_M, "free": _FREE_M.replace("7941", "8131904").replace("1187", "1215488"),
        "free -h": _FREE_M.replace("7941 ", "7.8Gi").replace("1187 ", "1.2Gi").replace("4519 ", "4.4Gi"),
        "lscpu": f"Architecture:            x86_64\r\nCPU(s):                  4\r\nModel name:              {_XEON}\r\n"
                 "Thread(s) per core:      1\r\nCore(s) per socket:      4",
        "df -h": "Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/vda1        79G   18G   58G  24% /",
        "w": " 12:01:33 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
             "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT",
        "ps": "    PID TTY          TIME CMD\r\n   1873 pts/0    00:00:00 bash",
    },
    "files": {"/proc/cpuinfo": _cpuinfo(4, _XEON),
              "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\r\nNAME="Debian GNU/Linux"\r\n'
                                 'VERSION_ID="12"\r\nID=debian',
              "/proc/mounts": "/dev/vda1 / ext4 rw,relatime 0 0"},
}
COMMON = {"whoami": "root", "id": "uid=0(root) gid=0(root) groups=0(root)", "pwd": "/root", "ls": "",
          "uptime": " 12:01:33 up 41 days,  3:12,  load average: 0.08, 0.03, 0.01", "crontab -l": "no crontab for root"}
# Befehle ohne Ausgabe; Mirai & Co. schicken enable/system/shell/sh, um aus Router-CLIs auszubrechen
SILENT = {"enable", "system", "shell", "sh", "bash", "linuxshell", "cd", "chmod", "rm", "cp", "mv", "mkdir", "export",
          "history", "unset", "ls", "kill", "pkill", "killall", "dd", "sleep", "ulimit", "crontab", "touch", "true",
          "chattr", "chpasswd", "passwd", "nohup", "setsid", "disown"}
DOWNLOADERS = {"wget", "curl", "tftp", "ftpget"}
FILTERS = {"grep", "wc", "head", "tail", "awk", "sort", "uniq"}
APPLETS = SILENT | DOWNLOADERS | FILTERS | {"echo", "cat", "ls", "ps", "uname", "nproc", "id", "whoami", "hostname",
                                            "which", "free", "uptime"}
UNAME_ORDER = "snrvmpio"


def _echo(words):
    text = " ".join(w.strip("'\"") for w in words if w not in ("-e", "-n", "-ne", "-en"))
    try:  # Bots prüfen mit echo -e '\x41\x4b', ob die Shell Escapes auswertet
        return text.encode("latin-1", "replace").decode("unicode_escape")
    except UnicodeDecodeError:
        return text


def _redirect(words):
    """echo … > datei bzw. >> datei: (Wörter ohne Umleitung, Datei, anhängen?) oder None."""
    for i, w in enumerate(words):
        if w.startswith(">"):
            append = w.startswith(">>")
            name = w.lstrip(">") or (words[i + 1] if i + 1 < len(words) else "")
            return words[:i], name, append
    return None


def _uname(args, profile):
    fields = profile["uname"]
    flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    if "a" in flags:  # wie GNU/BusyBox: -a lässt unbekannte Felder (p, i) weg
        return " ".join(fields[k] for k in UNAME_ORDER if k in fields and fields[k] != "unknown")
    return " ".join(fields.get(k, "unknown") for k in UNAME_ORDER if k in flags) or fields["s"]


def _one(words, profile=ROUTER):
    if words[0].rsplit("/", 1)[-1] == "busybox" and len(words) > 1:
        words = words[1:]
        if words[0] not in APPLETS:
            return f"{words[0]}: applet not found\r\n"  # Mirai erkennt BusyBox genau an dieser Antwort
    name = words[0].rsplit("/", 1)[-1]
    redirected = _redirect(words)
    if redirected and name != "echo":  # befehl > /dev/null: Ausgabe verschwindet
        words = redirected[0] or words[:1]
    words = [w for w in words if w not in ("2>&1", "2>/dev/null")]
    cmd = " ".join([name] + words[1:])
    output = {**COMMON, **profile["output"]}
    if cmd in output:
        text = output[cmd]
    elif name == "echo":
        return "" if redirected else _echo(words[1:]) + "\r\n"
    elif name == "uname":
        text = _uname(words[1:], profile)
    elif name == "hostname":
        text = profile["uname"]["n"]
    elif name == "cat":
        files = {**ROUTER["files"], **profile["files"]} if profile is ROUTER else profile["files"]
        return "".join(files[f] + "\r\n" if f in files else f"cat: {f}: No such file or directory\r\n"
                       for f in words[1:])
    elif name == "which":
        known = APPLETS | {c.split()[0] for c in output}
        text = "\r\n".join(f"/usr/bin/{w}" for w in words[1:] if w in known)
    elif name in DOWNLOADERS:
        text = f"{name}: download timed out"
    elif name in SILENT:
        text = ""
    else:
        text = profile["missing"].format(name)
    return "" if redirected or not text else text + "\r\n"


def _filter(part, text):
    """grep/wc/head/tail/awk/sort/uniq auf die Ausgabe der vorigen Stufe: Bots zählen so Kerne und RAM."""
    try:
        argv = shlex.split(part)
    except ValueError:
        argv = part.split()
    name, args = argv[0].rsplit("/", 1)[-1], argv[1:]
    lines = [line for line in text.split("\r\n") if line]
    flags = "".join(a[1:] for a in args if a.startswith("-") and not a[1:].isdigit())
    plain = [a for a in args if not a.startswith("-")]
    if name == "grep":
        pattern = plain[0] if plain else ""
        hit = lambda line: (pattern.lower() in line.lower()) if "i" in flags else (pattern in line)
        lines = [line for line in lines if hit(line) != ("v" in flags)]
        if "c" in flags:
            lines = [str(len(lines))]
    elif name == "wc":
        lines = [str(len(lines))] if "l" in flags else [f"{len(lines)} {len(text.split())} {len(text)}"]
    elif name in ("head", "tail"):
        n = next((int(a[1:]) for a in args if a[1:].isdigit() and a.startswith("-")), None)
        n = n or next((int(a) for a in plain if a.isdigit()), 10)
        lines = lines[:n] if name == "head" else lines[-n:]
    elif name == "awk":
        lines = _awk(" ".join(plain), lines)
    elif name == "sort":
        lines = sorted(lines, reverse="r" in flags)
    elif name == "uniq":
        lines = [line for i, line in enumerate(lines) if i == 0 or lines[i - 1] != line]
    return "".join(line + "\r\n" for line in lines)


AWK = re.compile(r"^\s*(?:F?NR\s*==\s*(\d+)\s*)?\{\s*print\s*([^};]*);?\s*\}\s*$")


def _awk(program, lines):
    """Nur die Form, die Bots benutzen: [NR == n] {print $a, $b, …}."""
    m = AWK.match(program)
    if not m:
        return lines
    row, items = m.group(1), [i.strip() for i in m.group(2).split(",") if i.strip()] or ["$0"]
    out = []
    for nr, line in enumerate(lines, 1):
        if row and nr != int(row):
            continue
        fields = line.split()
        pick = lambda i: line if i == "$0" else fields[-1] if i == "$NF" and fields else \
            (fields[int(i[1:]) - 1] if i[1:].isdigit() and 0 < int(i[1:]) <= len(fields) else "")
        out.append(" ".join(pick(i) for i in items))
    return out


def _pipeline(part, profile):
    out = ""
    for i, stage in enumerate(s for s in _split(part) if s.strip()):
        name = stage.split()[0].rsplit("/", 1)[-1]
        out = _filter(stage, out) if i and name in FILTERS else _one(stage.split(), profile)
    return out


SEPARATORS = re.compile(r"""'[^']*'|"[^"]*"|(&&|\|\||;|\|)""")


def _split(line, pipes=True):
    """Teilt an ; && || (und |), aber nicht in Anführungszeichen: awk '{print $1;}' bleibt ganz."""
    parts, last = [], 0
    for m in SEPARATORS.finditer(line):
        if m.group(1) and (pipes or m.group(1) != "|"):
            parts.append(line[last:m.start()])
            last = m.end()
    return parts + [line[last:]]


def _parts(line):
    for part in _split(line):
        words = part.split()
        if words and words[0].rsplit("/", 1)[-1] == "busybox":
            words = words[1:]
        if words:
            yield words


def downloads(line):
    """URLs, die wget/curl/tftp in der Zeile laden würden (nur http, https, tftp)."""
    urls = []
    for words in _parts(line):
        name, args = words[0].rsplit("/", 1)[-1], [w.strip("'\"") for w in words[1:]]
        if name in ("wget", "curl"):
            skip = {"-O", "-o", "--output", "--output-document", "-P", "-U", "--user-agent", "-H"}
            urls += [a if "://" in a else "http://" + a for i, a in enumerate(args)
                     if not a.startswith("-") and (i == 0 or args[i - 1] not in skip) and ("/" in a or "." in a)]
        elif name == "tftp":
            # BusyBox: tftp -g -r datei host [port]; klassisch: tftp host -c get datei
            plain = [a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] not in ("-r", "-l"))]
            remote = args[args.index("-r") + 1] if "-r" in args[:-1] else (args[-1] if "get" in args else None)
            host = next((a for a in plain if a not in ("get", remote)), None)
            if host and remote:
                urls.append(f"tftp://{host}/{remote}")
    return [u for u in urls if u.split("://", 1)[0] in ("http", "https", "tftp")]


class Drops:
    """Dateien, die ein Bot per echo -ne '\\x7f\\x45…' > datei Stück für Stück schreibt (Dropper ohne Download)."""

    def __init__(self):
        self.files = {}

    def feed(self, line):
        for words in _parts(line):
            target = _redirect(words) if words[0].rsplit("/", 1)[-1] == "echo" else None
            if target is None:
                continue
            args, name, append = target
            data = _echo(args[1:]).encode("latin-1", "replace")
            self.files[name] = (self.files.get(name, b"") if append else b"") + data
            if sum(map(len, self.files.values())) > 1024 * 1024:  # mehr schreibt kein echo-Dropper
                self.files.clear()


def respond(line, profile=ROUTER):
    """Ausgabe zu einer Befehlszeile; None bei exit/logout."""
    out = []
    for part in _split(line, pipes=False):
        words = part.split()
        if not words:
            continue
        if words[0] in ("exit", "logout", "quit"):
            return None
        out.append(_pipeline(part, profile))
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


def run_shell(lines, send, on_command, profile=ROUTER):
    send(profile["banner"])
    for _ in range(MAX_COMMANDS):
        send(profile["prompt"])
        line = lines.next()
        if line is None:
            return
        on_command(line)
        out = respond(line, profile)
        if out is None:
            return
        send(out)
