# KI-Insights für den Threat Monitor (Ollama auf oci-worker)

**Datum:** 2026-11-10 · **Status:** beschlossen, Umsetzung offen

## Kontext
Der Monitor zeigt Rohereignisse und Statistiken. Er soll dynamischer werden: Trends, Vorhersagen, Wellen und
Kampagnen sowie verständliche Erklärungen. Auf oci-worker läuft Ollama, siehe KB `20-Server/oci-worker.md`.

## Entscheidung
**Grundsatz:** Python rechnet alle Zahlen deterministisch, das LLM schreibt nur Texte (benennen, erklären,
zusammenfassen). Ein lokales 7B-Modell rechnet und prognostiziert unzuverlässig.

**Architektur**
- Neues Modul `backend/insights.py` auf 3lis.de, als Thread im Hauptdienst wie `geo.py`/`sensors.py`.
- Ergebnisse in neuer Tabelle `insights(id, ts, kind, key, data_json, text, model)`, Ausgabe über `/api/insights`.
- LLM-Zugang: SSH von 3lis.de zu oci-worker:22022. Neuer Benutzer `attack-llm` mit fest vorgegebenem Befehl
  (`deploy/sensor/llm-proxy.py`): Anfrage-JSON über stdin, Modell und Optionen fest im Proxy,
  `http://127.0.0.1:11434`. Analog zu `attack-export`.
- Modell `qwen2.5:7b`, **Ausgabe Englisch** (beste Qualität), `temperature` 0.2–0.3, Ausgabelänge begrenzt.
  Kaltstart bis ~95 s, danach ~3,7 tok/s; Timeouts entsprechend großzügig.
- **Abwechselnd mit dem Rendering:** Der Proxy meldet `busy`, solange ein Render-Lauf aktiv ist
  (casi-render/securitypulse-render, z. B. per CPU-Last des Containers oder Lock-Datei). Der Job überspringt dann die Runde.

**Ausbaustufe 1**
1. **Trends & Vorhersage** (ohne LLM, alle 15 min): Erwartungswert je Wochenstunde aus der Historie mit Band
   (Median ± MAD o. ä.), Prognose für die nächsten 24 h, Ausreißer als Anomalie markieren.
   Anzeige: Prognose gestrichelt mit Band in `charts.js`, Hinweise wie „+340 % über Erwartung“.
2. **Wellen/Kampagnen** (Erkennung ohne LLM alle 15 min, Benennung mit LLM): Häufungen je ASN, Land und Typ;
   Gruppierung über gleiche Zugangsdaten-Listen und Befehlsfolgen über mehrere IPs. LLM liefert Name und
   kurze Beschreibung je neuer Kampagne (einmal je Kampagne, zwischengespeichert). Anzeige: Kampagnen-Karten.
3. **Lagebericht** (LLM, stündlich): 24-h-Zusammenfassung aus den Kennzahlen von 1 und 2 (neu, auffällig, Lage).
   Anzeige: Lagebericht-Kasten auf der Startseite mit Zeitstempel und Modellname.

**Ausbaustufe 2 (später)**
- **Befehls-Analyse:** LLM erklärt Fake-Shell-Sitzungen, Absicht als Plakette im Drawer; Ergebnis je Sitzungs-Hash zwischenspeichern.
- **Nachrichtenbezug:** RSS heise Security, BSI/CERT-Bund, CISA KEV (JSON), Mastodon-Hashtags (öffentliche API);
  Abgleich von CVE-Nummern, Produkten und Pfaden mit beobachteten Probes.
  Instagram/X: nein, keine brauchbare öffentliche Such-API.

## Sicherheit
- Prompt-Injection: Passwörter, Befehle, User-Agents und SQL kommen vom Angreifer. Im Prompt klar als Daten
  abgrenzen; Ausgabe nur als `textContent`, URLs/Links entfernen, Länge begrenzen, nur ASCII/übliche Unicode-Zeichen.
- Nur gekürzte IPs (/24) in den Prompt, nie volle Adressen.
- Keine externen Dienste für Besucher. Feeds holt der Server. Datenschutzerklärung bleibt unverändert.

## Alternativen
- Externe LLM-API: verworfen, kostet pro Anfrage und gibt Daten an Dritte weiter.
- Ollama dauerhaft geladen: verworfen, seit Pay As You Go keine Leerlauf-Rückforderung mehr; RAM wird fürs Rendering gebraucht.
- `qwen2.5:3b`: verworfen, Erklärungen zu oberflächlich (Test: Mirai-Dropper nur als „Exploit“ erkannt, 7b nennt Mirai/ARM7/Cleanup).

## Auswirkungen
Neue Tabelle, neuer API-Endpunkt und neues Frontend-Modul (z. B. `insights.js`), neuer Benutzer und Proxy auf oci-worker,
Projektkarte und README anpassen. Tests für Trend-/Kampagnen-Logik und Ausgabefilter.
