# KI-Insights für den Threat Monitor (Ollama auf oci-worker)

**Datum:** 2026-11-10 · **Status:** Ausbaustufen 1 und 2 umgesetzt (2026-11-10)

## Kontext
Der Monitor zeigt Rohereignisse und Statistiken. Er soll dynamischer werden: Trends, Vorhersagen, Wellen und
Kampagnen sowie verständliche Erklärungen. Auf oci-worker läuft Ollama, siehe KB `20-Server/oci-worker.md`.

## Entscheidung
**Grundsatz:** Python rechnet alle Zahlen deterministisch, das LLM schreibt nur Texte (benennen, erklären,
zusammenfassen). Ein lokales 7B-Modell rechnet und prognostiziert unzuverlässig.

**Architektur**
- Neues Modul `backend/insights.py` auf 3lis.de, als Thread im Hauptdienst wie `geo.py`/`sensors.py`.
- Ergebnisse in neuer Tabelle `insights(kind, key, ts, data, text, model)`, Ausgabe über `/api/insights`.
- LLM-Zugang: SSH von 3lis.de zu oci-worker:22022. Neuer Benutzer `attack-llm` mit fest vorgegebenem Befehl
  (`deploy/sensor/llm-proxy.py`): Anfrage-JSON über stdin, Modell und Optionen fest im Proxy,
  `http://127.0.0.1:11434`. Analog zu `attack-export`.
- Modell `qwen2.5:7b`, **Ausgabe Englisch** (beste Qualität), `temperature` 0.2–0.3, Ausgabelänge begrenzt.
  Kaltstart bis ~95 s, danach ~3,7 tok/s; Timeouts entsprechend großzügig.
- **Abwechselnd mit dem Rendering:** Der Proxy meldet `busy`, solange ein Render-Lauf aktiv ist
  (umgesetzt: Modell nicht geladen **und** Load > 1 oder < 6 GB RAM frei). Der Job überspringt dann die Runde.
- Trendwerte gehen als fertige Aussagen ins Prompt („5.3 times the usual …“), weil das 7B-Modell Rohprozente verliest.

**Ausbaustufe 1**
1. **Trends & Vorhersage** (ohne LLM, alle 15 min): Erwartungswert je **Tagesstunde** (Median der 7 Tage, Band ± 2σ
   per MAD; je Wochenstunde gäbe es bei 8 Tagen Aufbewahrung nur einen Wert), Prognose für die nächsten 24 h,
   Ausreißer als Spitze markieren. Anzeige: eigenes Diagramm „Trend & Prognose“, Hinweise wie „+340 % über Erwartung“.
2. **Wellen/Kampagnen** (Erkennung ohne LLM alle 15 min, Benennung mit LLM): Häufungen je ASN, Land und Typ;
   Gruppierung über gleiche Zugangsdaten-Listen und Befehlsfolgen über mehrere IPs. LLM liefert Name und
   kurze Beschreibung je neuer Kampagne (einmal je Kampagne, zwischengespeichert). Anzeige: Kampagnen-Karten.
3. **Lagebericht** (LLM, stündlich): 24-h-Zusammenfassung aus den Kennzahlen von 1 und 2 (neu, auffällig, Lage).
   Anzeige: Lagebericht-Kasten auf der Startseite mit Zeitstempel und Modellname.

**Ausbaustufe 2** (umgesetzt; Abweichungen: Fingerabdruck = eindeutige Befehle in Reihenfolge, Binär-Müll ignoriert, Zufalls-IDs ≥ 16 Hex-Zeichen → „‹hex›“;
Mastodon nur mastodon.social #threatintel, weil andere Instanzen Tag-Abfragen nur mit Login erlauben und #honeypot-Bots
volle fremde IPs posten; Abgleich über Themen statt CVEs, weil die Payloads keine CVE-Nummern enthalten)
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
