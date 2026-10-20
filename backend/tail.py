"""Liest die Logdateien fortlaufend und schreibt erkannte Events in den Store.

Beim allerersten Start (leere DB) werden auch die rotierten Dateien der
letzten 7 Tage eingelesen, damit Statistiken sofort gefüllt sind. Danach
setzt jeder Start am gespeicherten Offset fort - keine Duplikate.
"""
import glob
import gzip
import os
import time

from parsers import PARSERS

LOGS = {
    "nginx": "/var/log/nginx/access.log",
    "nginx-error": "/var/log/nginx/error.log",
    "auth": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "f2b": "/var/log/fail2ban.log",
}
HISTORY = 7 * 86400
POLL = 1.0


def _parse_lines(source, lines, min_ts=0):
    parse = PARSERS[source]
    events = []
    for line in lines:
        try:
            ev = parse(line)
        except ValueError:
            continue
        if ev and ev["ts"] >= min_ts:
            events.append(ev)
    return events


def _rotated(path):
    """Rotierte Dateien (.1, .2.gz, ...) der letzten 7 Tage, älteste zuerst."""
    cutoff = time.time() - HISTORY - 86400
    files = [f for f in glob.glob(path + ".*") if os.path.getmtime(f) >= cutoff]
    return sorted(files, key=os.path.getmtime)


def seed_history(store):
    min_ts = time.time() - HISTORY
    for source, path in LOGS.items():
        for f in _rotated(path):
            opener = gzip.open if f.endswith(".gz") else open
            try:
                with opener(f, "rt", errors="ignore") as fh:
                    store.add_events(_parse_lines(source, fh, min_ts))
            except OSError as exc:
                print(f"seed {f}: {exc}", flush=True)


def _read_new(store, source, path):
    try:
        st = os.stat(path)
    except OSError:
        return
    inode, pos = store.get_offset(path)
    if inode != st.st_ino or pos > st.st_size:
        pos = 0  # rotiert oder gekürzt -> von vorn
    if pos == st.st_size and inode == st.st_ino:
        return
    with open(path, "r", errors="ignore") as fh:
        fh.seek(pos)
        lines = fh.readlines()
        new_pos = fh.tell()
    store.add_events(_parse_lines(source, lines, time.time() - HISTORY))
    store.set_offset(path, st.st_ino, new_pos)


def run(store):
    if store.is_empty():
        seed_history(store)
    last_prune = 0
    while True:
        for source, path in LOGS.items():
            try:
                _read_new(store, source, path)
            except Exception as exc:  # eine kaputte Quelle darf die anderen nicht stoppen
                print(f"tail {source}: {exc}", flush=True)
        if time.time() - last_prune > 3600:
            store.prune()
            last_prune = time.time()
        time.sleep(POLL)
