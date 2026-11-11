"""Shell-Syntax der Fake-Shell (fakeshell.py): Variablen, $((…)), printf und die Filter hinter einer Pipe.
Bots prüfen damit, ob sie in einer echten Shell sitzen („check_<hash>“-Bot: $$, $((a*b+c)), set --, Funktionen,
sh -c, printf). Ausgeführt wird nichts; $(…) liefert die Antwort der Fake-Shell selbst.
"""
import ast
import operator
import re
import shlex

PID = "1873"  # passt zur ps-Ausgabe im Serverprofil
ENV = {"HOME": "/root", "USER": "root", "LOGNAME": "root", "SHELL": "/bin/bash", "PWD": "/root",
       "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "?": "0", "$": PID}
QUOTED = re.compile(r"""'[^']*'|"(?:\\.|[^"\\])*"|[^'"]+|['"]""")
VARIABLE = re.compile(r"\$\(\((.{1,200}?)\)\)|\$\(([^()]*)\)|`([^`]*)`|\$\{?([$#@*?]|\d|[A-Za-z_]\w*)\}?")
OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
       ast.Mod: operator.mod, ast.USub: operator.neg, ast.UAdd: operator.pos}


def words(text):
    return shlex.split(text)


def arith(expr):
    """$((…)) nur mit Ganzzahlen und + - * / %; alles andere ergibt 0 wie in der Shell bei Unsinn."""
    def ev(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in OPS:
            return OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
            return OPS[type(node.op)](ev(node.operand))
        raise ValueError
    try:
        value = ev(ast.parse(expr.replace("/", "//"), mode="eval").body)
    except (ValueError, SyntaxError, ZeroDivisionError, RecursionError):
        return "0"
    return str((value + 2 ** 63) % 2 ** 64 - 2 ** 63)  # 64-Bit-Überlauf wie bash


def expand(text, args, run):
    """$$, $1…, $#, $@, $VAR, $((…)), $(…) und `…` ersetzen, außer in einfachen Anführungszeichen.
    run(cmd) liefert die Ausgabe der Fake-Shell für Befehlsersetzung."""
    def sub(m):
        math, command, backtick, name = m.groups()
        if math is not None:
            return arith(math)
        if command is not None or backtick is not None:
            return run(command if command is not None else backtick).rstrip("\r\n")
        if name.isdigit():
            return "-bash" if name == "0" else (args[int(name) - 1] if int(name) <= len(args) else "")
        if name == "#":
            return str(len(args))
        if name in "@*":
            return " ".join(args)
        return ENV.get(name, "")
    return "".join(part if part.startswith("'") else VARIABLE.sub(sub, part) for part in QUOTED.findall(text))


def unescape(text):
    try:
        return text.encode("latin-1", "replace").decode("unicode_escape")
    except UnicodeDecodeError:
        return text


def printf(args):
    """printf FORMAT ARGS…: %s/%d/%b/%c, Format wird wiederholt, solange Argumente übrig sind (wie bash)."""
    if not args:
        return ""
    fmt, args, out = unescape(args[0]), args[1:], ""
    while True:
        used = 0

        def fill(m):
            nonlocal used
            if m.group(0) == "%%":
                return "%"
            value = args[used] if used < len(args) else ""
            used += 1
            if m.group(1) == "d":
                return value if value.lstrip("-").isdigit() else "0"
            return unescape(value) if m.group(1) == "b" else value
        out += re.sub(r"%%|%[-+ 0-9.]*([sdbc])", fill, fmt)
        args = args[used:]
        if not args or not used:
            return out.replace("\r\n", "\n").replace("\n", "\r\n")


def filter_output(part, text):
    """grep/wc/head/tail/awk/sort/uniq auf die Ausgabe der vorigen Stufe: Bots zählen so Kerne und RAM."""
    try:
        argv = words(part)
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
        lines = awk(" ".join(plain), lines)
    elif name == "sort":
        lines = sorted(lines, reverse="r" in flags)
    elif name == "uniq":
        lines = [line for i, line in enumerate(lines) if i == 0 or lines[i - 1] != line]
    return "".join(line + "\r\n" for line in lines)


AWK = re.compile(r"^\s*(?:F?NR\s*==\s*(\d+)\s*)?\{\s*print\s*([^};]*);?\s*\}\s*$")


def awk(program, lines):
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


