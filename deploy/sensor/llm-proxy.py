#!/usr/bin/env python3
"""Erzwungener SSH-Befehl auf oci-worker für 3lis.de (authorized_keys: command="…/llm-proxy.py",restrict).

Liest eine Anfrage {"system", "prompt", "json", "max_tokens"} als JSON von stdin und reicht sie mit festem Modell
und festen Optionen an Ollama (127.0.0.1:11434) weiter. Antwort: {"text", "model"}, {"busy": true} oder {"error"}.
Abwechselnd mit dem Rendering (12 GB, kein Swap): Ist das Modell nicht geladen und der Rechner ausgelastet oder
der Speicher knapp, lehnt der Proxy ab, statt Render-Läufe zu verdrängen.
"""
import json
import sys
import urllib.request

OLLAMA = "http://127.0.0.1:11434"
MODEL = "qwen2.5:7b"
NEED_KB = 6 * 1024 * 1024  # 7B-Modell ~5,1 GB + Reserve
MAX_LOAD = 1.0             # 2 Kerne: darüber läuft ein Render-Lauf
MAX_REQUEST = 64 * 1024
MAX_PROMPT = 16000
MAX_TOKENS = 500


def http(path, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(urllib.request.Request(OLLAMA + path, data=data), timeout=timeout) as r:
        return json.load(r)


def loaded():
    return any(m.get("name") == MODEL for m in http("/api/ps").get("models", []))


def busy():
    if loaded():
        return False
    with open("/proc/loadavg") as fh:
        load1 = float(fh.read().split()[0])
    with open("/proc/meminfo") as fh:
        avail = next(int(line.split()[1]) for line in fh if line.startswith("MemAvailable:"))
    return load1 > MAX_LOAD or avail < NEED_KB


def main():
    req = json.loads(sys.stdin.read(MAX_REQUEST))
    if busy():
        return {"busy": True}
    body = {"model": MODEL, "stream": False, "system": str(req.get("system", ""))[:2000],
            "prompt": str(req.get("prompt", ""))[:MAX_PROMPT],
            "options": {"temperature": 0.3, "num_ctx": 4096,
                        "num_predict": max(16, min(int(req.get("max_tokens", 300)), MAX_TOKENS))}}
    if req.get("json"):
        body["format"] = "json"
    resp = http("/api/generate", body, timeout=840)
    return {"text": resp.get("response", ""), "model": MODEL}


if __name__ == "__main__":
    try:
        print(json.dumps(main()))
    except Exception as exc:  # Fehlertext ohne Interna an 3lis.de
        print(json.dumps({"error": type(exc).__name__}))
        sys.exit(1)
