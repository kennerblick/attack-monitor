"""Erzwungener SSH-Befehl auf dem Außensensor (authorized_keys: command="…/export.py",restrict).
3lis.de ruft `ssh <sensor> <letzte_id>` auf und bekommt JSON-Zeilen: zuerst {"max": <höchste id>},
dann je Event {"id": …, …}. Der Schlüssel kann nichts anderes, als diese Events zu lesen.
"""
import json
import os
import sys

from store import Store

DB_PATH = os.environ.get("ATTACK_DB", "/var/lib/attack-monitor/events.db")


def main(arg):
    last_id = int(arg) if arg.isdigit() else 0  # Eingabe kommt vom Client: nur eine Zahl akzeptieren
    store = Store(DB_PATH)
    print(json.dumps({"max": store.query("SELECT COALESCE(MAX(id), 0) FROM events")[0][0]}))
    for event_id, ev in store.events_after(last_id):
        print(json.dumps({"id": event_id, **ev}, ensure_ascii=False))


if __name__ == "__main__":
    main(os.environ.get("SSH_ORIGINAL_COMMAND", sys.argv[1] if len(sys.argv) > 1 else "").strip())
