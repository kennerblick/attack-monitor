"""Kampagnen und Wellen erkennen (deterministisch, ohne LLM).

Kampagne = mindestens MIN_IPS Absender mit identischem Fingerabdruck im Fenster (24 h):
  commands  dieselben Fake-Shell-/SQL-Befehle in derselben Reihenfolge (jeder nur beim ersten Auftreten, damit eine
            wiederholte Sitzung denselben Schlüssel behält; Binär-Müll von Protokoll-Scannern zählt nicht)
  creds     dieselbe Menge probierter Benutzer/Passwort-Paare (mind. MIN_CREDS), nur für IPs ohne Befehls-Kampagne
Welle = ASN, dessen Events der letzten Stunde das WAVE_FACTOR-fache seines Stundenmittels der Woche übersteigen.
Der Schlüssel ist ein Hash des Fingerabdrucks: dieselbe Kampagne behält über Tage ihren Namen (insights.py).
"""
import hashlib

from intel import mask
from store import COMMAND, COMMANDS, LOGIN_PW, LOGIN_USER, PASSWORDS

WINDOW = 86400
MIN_IPS = 3
MIN_CREDS = 3
MAX_SEQ = 20
WAVE_FACTOR = 5
WAVE_MIN = 100


def key(kind, fingerprint):
    return hashlib.sha1(f"{kind}\n{fingerprint!r}".encode()).hexdigest()[:12]


def meaningful(cmd):
    """Echte Befehle statt Bytes von TLS-/Protokoll-Scannern, die der Honeypot als Zeile liest („?“, „�“)."""
    text = cmd.strip()
    if len(text) < 2 or set(text) <= set("?/.-"):
        return False
    return sum(c.isprintable() and c != "\ufffd" for c in text) / len(text) > 0.9


def command_prints(store, since, until=None, ip=None):
    """IP -> Folge eindeutiger Befehle (Tupel), optional nur für eine IP."""
    cond, args = "ts>=? AND ts<=?", [since, until or 1e12]
    if ip:
        cond, args = cond + " AND ip=?", args + [ip]
    seqs = {}
    for addr, cmd in store.query(f"SELECT ip, {COMMAND} FROM events WHERE {cond} AND {COMMANDS} ORDER BY ip, ts, id", args):
        seq = seqs.setdefault(addr, [])
        if len(seq) < MAX_SEQ and meaningful(cmd) and cmd not in seq:
            seq.append(cmd)
    return {addr: tuple(seq) for addr, seq in seqs.items() if seq}


def cred_prints(store, since, exclude):
    creds = {}
    for ip, user, pw in store.query(
            f"SELECT ip, {LOGIN_USER}, {LOGIN_PW} FROM events WHERE ts>=? AND {PASSWORDS}", (since,)):
        if ip not in exclude:
            creds.setdefault(ip, set()).add((user, pw))
    return {ip: tuple(sorted(c)) for ip, c in creds.items() if len(c) >= MIN_CREDS}


def group(prints):
    groups = {}
    for ip, fp in prints.items():
        groups.setdefault(fp, []).append(ip)
    return {fp: ips for fp, ips in groups.items() if len(ips) >= MIN_IPS}


def ip_facts(store, since):
    return {ip: r for ip, *r in store.query(
        "SELECT e.ip, COUNT(*), MIN(e.ts), MAX(e.ts), MAX(g.cc), MAX(g.asn), MAX(g.isp), GROUP_CONCAT(DISTINCT e.type) "
        "FROM events e LEFT JOIN geo g ON g.ip=e.ip WHERE e.ts>=? GROUP BY e.ip", (since,))}


def _top(counter, n):
    return sorted(counter.items(), key=lambda kv: -kv[1])[:n]


def summarize(kind, fingerprint, ips, facts):
    rows = [facts[ip] for ip in ips if ip in facts]
    countries, asns, types = {}, {}, set()
    for _, _, _, cc, asn, isp, typ in rows:
        if cc:
            countries[cc] = countries.get(cc, 0) + 1
        if asn:
            asns[(asn, isp)] = asns.get((asn, isp), 0) + 1
        types.update((typ or "").split(","))
    if kind == "commands":
        sample = [mask(c) for c in fingerprint[:6]]
        drill = {"kind": "command", "value": fingerprint[0]}
    else:
        sample = [f"{mask(u)} / {mask(p)}" for u, p in fingerprint[:6]]
        drill = {"kind": "password", "value": fingerprint[0][1]}
    return {
        "key": key(kind, fingerprint), "kind": kind, "ips": len(ips), "size": len(fingerprint),
        "events": sum(r[0] for r in rows), "first": min(r[1] for r in rows), "last": max(r[2] for r in rows),
        "types": sorted(t for t in types if t), "countries": _top(countries, 5),
        "asns": [[a, i, n] for (a, i), n in _top(asns, 3)], "sample": sample, "drill": drill,
    }


def waves(store, now):
    """ASN-Häufungen der letzten Stunde gegenüber dem Stundenmittel der Woche."""
    out = []
    for asn, isp, last, total, ips, cc in store.query(
            "SELECT g.asn, MAX(g.isp), SUM(e.ts>=?), COUNT(*), COUNT(DISTINCT CASE WHEN e.ts>=? THEN e.ip END), MAX(g.cc) "
            "FROM events e JOIN geo g ON g.ip=e.ip WHERE e.ts>=? AND g.asn IS NOT NULL AND g.asn!='' GROUP BY g.asn",
            (now - 3600, now - 3600, now - 7 * 86400)):
        mean = (total - last) / (7 * 24 - 1)
        if last >= WAVE_MIN and last > WAVE_FACTOR * mean:
            hour = int(now) // 3600
            out.append({"key": key("wave", (asn, hour // 24)), "kind": "wave", "ips": ips, "events": last,
                        "first": now - 3600, "last": now, "types": [], "countries": [[cc, ips]] if cc else [],
                        "asns": [[asn, isp, ips]], "sample": [], "factor": round(last / mean, 1) if mean else None,
                        "drill": {"kind": "asn", "value": asn}})
    return out


def detect(store, now):
    since = now - WINDOW
    facts = ip_facts(store, since)
    found = []
    by_cmd = group(command_prints(store, since))
    for fp, ips in by_cmd.items():
        found.append(summarize("commands", fp, ips, facts))
    taken = {ip for ips in by_cmd.values() for ip in ips}
    for fp, ips in group(cred_prints(store, since, taken)).items():
        found.append(summarize("creds", fp, ips, facts))
    return sorted(found + waves(store, now), key=lambda c: -c["events"])
