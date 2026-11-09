"""Holt die Events der Außensensoren (sensor.py) jede Minute per SSH ab und speichert sie mit Sensor-Namen.

Pull statt Push: Ein kompromittierter Sensor hat so keinen Weg zu 3lis.de. Konfiguration in ATTACK_SENSORS
(JSON-Liste: name, ssh, port, lat, lon, label), Schlüssel in ATTACK_SENSOR_KEY; der Sensor erzwingt export.py.
Die zuletzt übernommene Event-ID je Sensor steht in der offsets-Tabelle (path "sensor:<name>").
"""
import json
import os
import subprocess
import time

CONFIG = os.environ.get("ATTACK_SENSORS", "/etc/attack-monitor/sensors.json")
KEY = os.environ.get("ATTACK_SENSOR_KEY", "/etc/attack-monitor/sensor_key")
KNOWN_HOSTS = os.environ.get("ATTACK_SENSOR_KNOWN_HOSTS", "/var/lib/attack-monitor/sensor_known_hosts")
INTERVAL = 60
FIELDS = ("ts", "ip", "type", "sev", "src", "port", "detail", "jail")


def load():
    try:
        with open(CONFIG) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return []


def public(sensors):
    """Für /api/status: Standort und Beschriftung, nie die SSH-Ziele."""
    return [{k: s.get(k) for k in ("name", "lat", "lon", "label")} for s in sensors]


def ingest(store, name, lines):
    """JSON-Zeilen von export.py übernehmen; gibt die neue letzte ID zurück (None = nichts geändert)."""
    key = f"sensor:{name}"
    _, last_id = store.get_offset(key)
    head, events, new_last = json.loads(lines[0]), [], last_id
    if head["max"] < last_id:  # Sensor-DB neu angelegt: von vorn
        last_id = new_last = 0
    for line in lines[1:]:
        d = json.loads(line)
        if d["id"] <= last_id:
            continue
        ev = {k: d.get(k) for k in FIELDS}
        if not isinstance(ev["ip"], str) or not isinstance(ev["ts"], (int, float)):
            continue  # Daten vom Sensor sind nicht vertrauenswürdig
        events.append({**ev, "sensor": name})
        new_last = d["id"]
    store.add_events(events)
    if new_last != store.get_offset(key)[1]:
        store.set_offset(key, 0, new_last)
        return new_last
    return None


def fetch(sensor, last_id):
    out = subprocess.run(
        ["ssh", "-i", KEY, "-p", str(sensor.get("port", 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
         sensor["ssh"], str(last_id)], capture_output=True, text=True, timeout=120, check=True).stdout
    return out.splitlines()


def worker(store, sensors):
    while True:
        for s in sensors:
            try:
                ingest(store, s["name"], fetch(s, store.get_offset(f"sensor:{s['name']}")[1]))
            except Exception as exc:  # Sensor offline: beim nächsten Durchlauf erneut
                print(f"sensor {s['name']}: {exc}", flush=True)
        time.sleep(INTERVAL)
