"""Geolokalisierung über den Batch-Endpoint von ip-api.com (kostenlos, ohne Key).

Der Worker sucht sich selbst die IPs ohne Geo-Eintrag aus der Datenbank,
so braucht das Log-Tailing nie auf das Netz zu warten. Limit: 15 Batch-
Requests pro Minute mit je bis zu 100 IPs.
"""
import ipaddress
import json
import time
import urllib.request

BATCH_URL = "http://ip-api.com/batch?fields=status,query,lat,lon,countryCode,country,city,isp,org,as,mobile,proxy,hosting"
SELF_URL = "http://ip-api.com/json/?fields=status,lat,lon,city,country"
INTERVAL = 4.5        # Sekunden zwischen Batches -> ~13/min, unter dem Limit
IDLE_INTERVAL = 10


def _post(url, payload, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def server_location():
    try:
        with urllib.request.urlopen(SELF_URL, timeout=4) as r:
            d = json.loads(r.read().decode())
        if d.get("status") == "success":
            return {"lat": d["lat"], "lon": d["lon"], "name": f"{d.get('city')}, {d.get('country')}"}
    except Exception:
        pass
    return {"lat": 52.52, "lon": 13.40, "name": "Berlin, Germany"}


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup_batch(ips):
    """Liefert Zeilen für die geo-Tabelle. Nicht öffentliche oder von ip-api
    abgelehnte IPs bekommen eine leere Zeile, damit sie nicht erneut angefragt werden."""
    now = time.time()
    rows = [(ip, None, None, None, None, None, None, None, now) for ip in ips if not _is_public(ip)]
    public = [ip for ip in ips if _is_public(ip)]
    if public:
        for d in _post(BATCH_URL, public):
            ok = d.get("status") == "success"
            asn = (d.get("as") or "").split(" ", 1)[0] if ok else None
            rows.append((d["query"], d.get("lat") if ok else None, d.get("lon") if ok else None,
                         d.get("countryCode") if ok else None, d.get("country") if ok else None,
                         d.get("city") if ok else None, d.get("isp") if ok else None, asn, now,
                         d.get("org") if ok else None, d.get("hosting") if ok else None,
                         d.get("proxy") if ok else None, d.get("mobile") if ok else None))
    return rows


def worker(store):
    while True:
        ips = store.ips_without_geo(100)
        if not ips:
            time.sleep(IDLE_INTERVAL)
            continue
        try:
            store.save_geo(lookup_batch(ips))
        except Exception:
            # Netzwerkfehler/Rate-Limit: nichts cachen, im nächsten Durchlauf erneut
            time.sleep(30)
        time.sleep(INTERVAL)
