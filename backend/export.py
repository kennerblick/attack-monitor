"""Erzwungener SSH-Befehl auf dem Außensensor (authorized_keys: command="…/export.py",restrict).
3lis.de ruft `ssh <sensor> <letzte_id>` auf und bekommt JSON-Zeilen: zuerst {"max": <höchste id>},
dann je Event {"id": …, …}. `ssh <sensor> sample <sha256>` liefert die Bytes eines Malware-Samples (samples.py).
Der Schlüssel kann nichts anderes, als diese Events und Samples zu lesen.
"""
import json
import os
import re
import sys

import samples
from store import Store

DB_PATH = os.environ.get("ATTACK_DB", "/var/lib/attack-monitor/events.db")
SAMPLE_ARG = re.compile(r"sample ([0-9a-f]{64})")  # nur ein Hash, kein Pfad: Eingabe kommt vom Client


def main(arg):
    m = SAMPLE_ARG.fullmatch(arg)
    if m:
        with open(os.path.join(samples.DIR, m.group(1)), "rb") as fh:
            sys.stdout.buffer.write(fh.read(samples.MAX_SIZE))
        return
    last_id = int(arg) if arg.isdigit() else 0  # Eingabe kommt vom Client: nur eine Zahl akzeptieren
    store = Store(DB_PATH)
    print(json.dumps({"max": store.query("SELECT COALESCE(MAX(id), 0) FROM events")[0][0]}))
    for event_id, ev in store.events_after(last_id):
        print(json.dumps({"id": event_id, **ev}, ensure_ascii=False))


if __name__ == "__main__":
    main(os.environ.get("SSH_ORIGINAL_COMMAND", sys.argv[1] if len(sys.argv) > 1 else "").strip())
