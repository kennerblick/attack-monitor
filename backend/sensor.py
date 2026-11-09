"""Einstieg eines Außensensors (z. B. oci-worker, attack-sensor.service): dieselben Honeypots wie auf 3lis.de
plus die Web-Probes aus dem eigenen nginx-Log, alles in eine lokale DB. 3lis.de holt die Events über
export.py ab (sensors.py); der Sensor selbst hat keinen Zugang zu 3lis.de.
"""
import os
import time

import honeypots
import tail
from store import Store

DB_PATH = os.environ.get("ATTACK_DB", "/var/lib/attack-monitor/events.db")
LOGS = {source: tail.LOGS[source] for source in ("nginx", "nginx-error")}

if __name__ == "__main__":
    store = Store(DB_PATH)
    honeypots.start(store)
    readers = {path: lambda lines, s=source: store.add_events(tail._parse_lines(s, lines))
               for source, path in LOGS.items()}
    last_prune = 0
    while True:
        for path, handle in readers.items():
            try:
                tail._read_new(store, path, handle)
            except Exception as exc:  # z. B. Log rotiert gerade
                print(f"tail {path}: {exc}", flush=True)
        if time.time() - last_prune > 3600:
            store.prune()
            last_prune = time.time()
        time.sleep(tail.POLL)
