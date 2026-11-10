"""KI-Erklärung von Angreifer-Sitzungen (Fake-Shell, Fake-Datenbank, PHP-Payloads) für das IP-Profil.

Schlüssel = Fingerabdruck der Befehlsfolge (campaigns.command_prints/key): jede Folge wird nur einmal erklärt,
egal wie viele IPs sie ausführen. Ablage in insights (kind "session"), text = JSON summary/intent/risk.
"""
import json

import campaigns
import llm
from intel import mask

PER_RUN = 3
WINDOW = 86400
RISKS = ("low", "medium", "high")


def prompt(commands, intents):
    return ("Explain what this attacker session on our honeypot does (fake shell or fake database; nothing was really "
            "executed). Be concrete about tools, files and goals, e.g. botnet malware, miner, SSH key persistence, "
            "database ransom note. Reply as JSON with keys \"summary\" (max 3 sentences), "
            f"\"intent\" (one of: {', '.join(intents)}), \"risk\" (low, medium or high, if it had been a real system).\n"
            "DATA (commands in order):\n" + json.dumps([mask(c)[:300] for c in commands], ensure_ascii=False))


def parse(text, intents):
    try:
        d = json.loads(text)
    except ValueError:
        return None
    if not isinstance(d, dict) or not d.get("summary"):
        return None
    intent, risk = str(d.get("intent", "")).strip().lower(), str(d.get("risk", "")).strip().lower()
    return {"summary": llm.clean(d["summary"], 420), "intent": intent if intent in intents else "other",
            "risk": risk if risk in RISKS else None}


def explain_new(store, cfg, now, intents, system):
    """Bis zu PER_RUN noch unerklärte Folgen der letzten 24 h, häufigste (meiste IPs) zuerst."""
    known = {r[0] for r in store.query("SELECT key FROM insights WHERE kind='session' AND text IS NOT NULL")}
    groups = {}
    for ip, seq in campaigns.command_prints(store, now - WINDOW).items():
        groups.setdefault(seq, []).append(ip)
    todo = sorted(((campaigns.key("commands", seq), seq, len(ips)) for seq, ips in groups.items()), key=lambda t: -t[2])
    for k, seq, ips in [t for t in todo if t[0] not in known][:PER_RUN]:
        text, model = llm.ask(cfg, system, prompt(seq, intents), as_json=True, max_tokens=220)
        analysis = parse(text, intents)
        if analysis:
            store.put_insight("session", k, now, {"commands": [mask(c) for c in seq], "ips": ips},
                              json.dumps(analysis, ensure_ascii=False), model)


def for_ip(store, ip):
    """Befehle der IP (24 h vor ihrem letzten Befehl) und, falls vorhanden, die Erklärung dazu."""
    last = store.query(f"SELECT MAX(ts) FROM events WHERE ip=? AND {campaigns.COMMANDS}", (ip,))[0][0]
    if last is None:
        return None
    seq = campaigns.command_prints(store, last - WINDOW, last, ip).get(ip)
    if not seq:
        return None
    row = store.query("SELECT text, model FROM insights WHERE kind='session' AND key=?", (campaigns.key("commands", seq),))
    analysis = json.loads(row[0][0]) if row and row[0][0] else None
    return {"commands": [mask(c) for c in seq], "analysis": analysis, "model": row[0][1] if analysis else None}
