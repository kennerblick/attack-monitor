"""Holt die Events der Außensensoren (sensor.py) jede Minute per SSH ab und speichert sie mit Sensor-Namen.

Pull statt Push: Ein kompromittierter Sensor hat so keinen Weg zu 3lis.de. Konfiguration in ATTACK_SENSORS
(JSON-Liste: name, ssh, port, lat, lon, label), Schlüssel in ATTACK_SENSOR_KEY; der Sensor erzwingt export.py.
Die zuletzt übernommene Event-ID je Sensor steht in der offsets-Tabelle (path "sensor:<name>").
Malware-Samples, die ein Sensor gespeichert hat, werden danach einzeln geholt und lokal abgelegt (samples.save),
damit sie auf 3lis.de zur Analyse bereitliegen; der Hash wird geprüft, der Sensor ist nicht vertrauenswürdig.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time

import samples
from store import SAMPLE_HASH, SAMPLES

CONFIG = os.environ.get("ATTACK_SENSORS", "/etc/attack-monitor/sensors.json")
KEY = os.environ.get("ATTACK_SENSOR_KEY", "/etc/attack-monitor/sensor_key")
KNOWN_HOSTS = os.environ.get("ATTACK_SENSOR_KNOWN_HOSTS", "/var/lib/attack-monitor/sensor_known_hosts")
INTERVAL = 60
FIELDS = ("ts", "ip", "type", "sev", "src", "port", "detail", "jail")
SEVERITIES = {"crit", "high", "med", "low"}
LABEL = re.compile(r"[\w/.-]{1,40}")  # type, src, jail: Bezeichner, nie Markup


def valid(ev):
    """Sensor-Events strikt prüfen: ein übernommener Sensor soll weder Markup noch Fremdformate einschleusen."""
    try:
        ipaddress.IPv4Address(ev["ip"])
    except (ValueError, TypeError):
        return False
    return (isinstance(ev["ts"], (int, float)) and ev["sev"] in SEVERITIES
            and all(isinstance(ev[k], str) and LABEL.fullmatch(ev[k]) for k in ("type", "src"))
            and (ev["jail"] is None or isinstance(ev["jail"], str) and LABEL.fullmatch(ev["jail"]))
            and (ev["port"] is None or type(ev["port"]) is int and 0 <= ev["port"] <= 65535)
            and isinstance(ev["detail"], str))


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
        if not valid(ev):
            continue  # Daten vom Sensor sind nicht vertrauenswürdig
        events.append({**ev, "detail": ev["detail"][:2000], "sensor": name})
        new_last = d["id"]
    store.add_events(events)
    if new_last != store.get_offset(key)[1]:
        store.set_offset(key, 0, new_last)
        return new_last
    return None


def ssh(sensor, command):
    return subprocess.run(
        ["ssh", "-i", KEY, "-p", str(sensor.get("port", 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
         sensor["ssh"], command], capture_output=True, timeout=120, check=True).stdout


def fetch(sensor, last_id):
    return ssh(sensor, str(last_id)).decode().splitlines()


def missing_samples(store, name, failed):
    """Hashes gespeicherter Sensor-Samples, die lokal fehlen („not stored“ = auch auf dem Sensor nicht vorhanden)."""
    rows = store.query(f"SELECT DISTINCT {SAMPLE_HASH} FROM events WHERE {SAMPLES} AND sensor=? "
                       "AND detail NOT LIKE '%· not stored%'", (name,))
    return [h for (h,) in rows if re.fullmatch(r"[0-9a-f]{64}", h or "") and h not in failed
            and not os.path.exists(os.path.join(samples.DIR, h))]


def pull_samples(store, sensor, failed, get=ssh):
    for digest in missing_samples(store, sensor["name"], failed):
        try:
            data = get(sensor, f"sample {digest}")
        except Exception as exc:  # fehlt auf dem Sensor o. Ä.: in diesem Prozess nicht erneut versuchen
            print(f"sensor {sensor['name']}: Sample {digest[:12]}: {type(exc).__name__}", flush=True)
            failed.add(digest)
            continue
        if hashlib.sha256(data).hexdigest() != digest:
            failed.add(digest)
            continue
        samples.save(data)


def worker(store, sensors):
    failed = set()
    while True:
        for s in sensors:
            try:
                ingest(store, s["name"], fetch(s, store.get_offset(f"sensor:{s['name']}")[1]))
                pull_samples(store, s, failed)
            except Exception as exc:  # Sensor offline: beim nächsten Durchlauf erneut
                print(f"sensor {s['name']}: {exc}", flush=True)
        time.sleep(INTERVAL)
