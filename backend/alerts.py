"""Telegram-Alarm bei neuer Kampagne, neuer ASN-Welle oder einer Angreifer-Sitzung, die das LLM als „high“ einstuft.

Konfiguration /etc/attack-monitor/alert.json: {"telegram_token": "<SECRET>", "chat_id": "<id>"}. Fehlt sie, ist der
Alarm aus. Läuft am Ende jeder insights-Runde und schickt höchstens eine Sammelmeldung je Runde (alle 15 min).
Gemeldete Schlüssel stehen in insights (kind "alert") und verfallen mit RETENTION (8 Tage); eine Welle hat je ASN und
Tag einen eigenen Schlüssel. Der erste Lauf vermerkt nur den Bestand, damit nach dem Einschalten kein Schwall kommt.
Klartext ohne parse_mode: Kampagnennamen und Befehle stammen (über das LLM) von Angreifern.
"""
import json
import os
import urllib.parse
import urllib.request

from intel import mask

CONFIG = os.environ.get("ATTACK_ALERT", "/etc/attack-monitor/alert.json")
MAX_ITEMS = 8
SEEDED = "_seeded"


def load():
    try:
        with open(CONFIG) as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return None
    return cfg if cfg.get("telegram_token") and cfg.get("chat_id") else None


def _short(text, limit=90):
    text = " ".join(mask(str(text)).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def campaign_text(c):
    if c["kind"] == "wave":
        asn, isp, _ = c["asns"][0]
        factor = f" ×{c['factor']}" if c.get("factor") else ""
        return f"Attack wave{factor} from {_short(isp, 40)} ({asn}): {c['events']} events from {c['ips']} IPs in the last hour"
    name = c["label"]["name"] if c.get("label") else (
        "Command sequence" if c["kind"] == "commands" else "Password list")
    sample = f"\n  {_short(' ; '.join(c['sample'][:3]))}" if c["sample"] else ""
    return f"New campaign: {_short(name, 60)} – {c['ips']} IPs, {c['events']} events{sample}"


def high_risk_sessions(store, now):
    for row in store.insights("session", since=now - 86400, limit=500):
        analysis = json.loads(row["text"]) if row["text"] else {}
        if analysis.get("risk") == "high":
            commands = row["data"]["commands"]
            yield f"session:{row['key']}", (
                f"High-risk session ({row['data']['ips']} IPs): {_short(analysis.get('summary', ''), 160)}"
                f"\n  {_short(' ; '.join(commands[:3]))}")


def findings(store, now, campaigns):
    """(Schlüssel, Text) aller aktuell meldewürdigen Funde."""
    found = [(f"{'wave' if c['kind'] == 'wave' else 'campaign'}:{c['key']}", campaign_text(c)) for c in campaigns]
    return found + list(high_risk_sessions(store, now))


def message(items):
    lines = [f"• {text}" for _, text in items[:MAX_ITEMS]]
    if len(items) > MAX_ITEMS:
        lines.append(f"… and {len(items) - MAX_ITEMS} more")
    return "3lis.de threat monitor\n\n" + "\n\n".join(lines) + "\n\nhttps://3lis.de/"


def send(cfg, text):
    data = urllib.parse.urlencode({"chat_id": cfg["chat_id"], "text": text,
                                   "disable_web_page_preview": "true"}).encode()
    url = f"https://api.telegram.org/bot{str(cfg['telegram_token']).strip()}/sendMessage"
    with urllib.request.urlopen(url, data, timeout=15) as resp:
        resp.read()


def run(store, cfg, now, campaigns, sender=send):
    alerted = {r["key"] for r in store.insights("alert", limit=100000)}
    new = [(k, t) for k, t in findings(store, now, campaigns) if k not in alerted]
    if SEEDED in alerted and new:
        try:
            sender(cfg, message(new))
        except Exception as exc:  # nur Typ und HTTP-Code loggen: InvalidURL u. Ä. enthalten die URL samt Token
            print(f"alerts: Senden fehlgeschlagen ({type(exc).__name__} {getattr(exc, 'code', '')})", flush=True)
            return  # nicht als gemeldet vermerken, nächste Runde erneut
    for k, _ in new + [(SEEDED, None)]:
        store.put_insight("alert", k, now, None)
