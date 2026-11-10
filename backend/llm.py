"""LLM-Zugriff für insights.py: per SSH auf den Proxy auf oci-worker (deploy/sensor/llm-proxy.py, erzwungener Befehl).

Konfiguration /etc/attack-monitor/llm.json: {"ssh": "attack-llm@<host>", "port": 22022}. Fehlt sie, laufen die
Insights ohne LLM. Schlüssel und known_hosts teilt sich der Zugang mit sensors.py.
Die Eingaben stammen teils von Angreifern (Passwörter, Befehle): IPs werden gekürzt und die Ausgabe gefiltert,
weil sie öffentlich angezeigt wird (Prompt-Injection könnte sonst Links oder Werbung einschleusen).
"""
import json
import os
import re
import subprocess

from intel import mask
from sensors import KEY, KNOWN_HOSTS

CONFIG = os.environ.get("ATTACK_LLM", "/etc/attack-monitor/llm.json")
TIMEOUT = 900  # Kaltstart des 7B-Modells bis ~95 s, danach ~3,7 Token/s auf 2 ARM-Kernen
LINK = re.compile(r"(?i)\b(?:https?://|ftp://|www\.)\S+|\b[\w-]+(?:\.[\w-]+)*\.(?:com|net|org|io|xyz|top|ru|cn|info|biz|ly|gg|me|sh|app|link|click)\b\S*")
CONTROL = re.compile(r"[^\S\n]+|[\x00-\x09\x0b-\x1f\x7f]")
MARKDOWN = re.compile(r"[*_`#>]+")


class Busy(Exception):
    """oci-worker rendert gerade; die Runde wird übersprungen."""


def load():
    try:
        with open(CONFIG) as fh:
            cfg = json.load(fh)
        return cfg if cfg.get("ssh") else None
    except (OSError, ValueError):
        return None


def ask(cfg, system, prompt, as_json=False, max_tokens=300):
    """Gibt (Antworttext, Modellname) zurück; Busy, wenn der Proxy ablehnt."""
    req = json.dumps({"system": system, "prompt": mask(prompt), "json": as_json, "max_tokens": max_tokens})
    out = subprocess.run(
        ["ssh", "-i", KEY, "-p", str(cfg.get("port", 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", cfg["ssh"]],
        input=req, capture_output=True, text=True, timeout=TIMEOUT)
    try:
        resp = json.loads(out.stdout)
    except ValueError:
        raise RuntimeError(f"llm-proxy: {out.stderr.strip()[:200] or 'keine Antwort'}")
    if resp.get("busy"):
        raise Busy()
    if "text" not in resp:
        raise RuntimeError(f"llm-proxy: {resp.get('error', 'unbekannter Fehler')}")
    return resp["text"], resp.get("model", "?")


def clean(text, limit=700):
    """Öffentlich anzeigbarer Klartext: keine Links, keine Steuerzeichen/Markdown, IPs gekürzt, Länge begrenzt."""
    text = MARKDOWN.sub("", LINK.sub("[link removed]", mask(str(text or ""))))
    text = "\n".join(" ".join(CONTROL.sub(" ", line).split()) for line in text.splitlines()).strip()
    if len(text) > limit:
        cut = text[:limit]
        text = cut[:cut.rfind(". ") + 1] if ". " in cut else cut.rstrip() + "…"
    return text
