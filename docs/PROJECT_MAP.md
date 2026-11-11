# Projektkarte

## Datenfluss
Logs (syslog, auth, nginx access/error, fail2ban) und Honeypots :3306/:5432/:22/:21/:23 und `*.php` (nginx → :8098) → `tail.py`/`honeypot_*.py` (Offsets in DB), Außensensoren über `sensors.py` → `parsers.py` → SQLite
`events` ← `geo.py` (ip-api Batch, füllt `geo`) → `server.py` (`/api/feed`, `/api/stats`, `/api/status`,
`/api/events` Drilldown, `/api/ip?id=` IP-Profil, IP-Kürzung) → nginx `/api/` → Browser
(`assets/js/main.js` pollt Feed 2 s, Stats 15 s, Status 30 s, Insights 60 s; `drawer.js` lädt Drilldown/Profil bei Klick).
Insights: `insights.py` (alle 15 min) ← `trends.py` + `campaigns.py` + `news.py` (Feeds) aus `events`; Texte per `llm.py` → SSH →
oci-worker `llm-proxy.py` → Ollama; Ergebnis in Tabelle `insights` → `/api/insights`.

## Backend (`backend/`, stdlib + `python3-paramiko`)
Zwei Prozesse, eine SQLite-Datei (WAL, Gruppe `attack-monitor`): `server.py` als root (Logs, fail2ban),
`honeypots.py` als `attack-honeypot` mit nur `CAP_NET_BIND_SERVICE` und systemd-Sandbox.
| Datei | Zweck |
|---|---|
| `server.py` | HTTP-API, IP-Maskierung, fail2ban-/Sperrlisten-Status, Einstieg Hauptdienst |
| `honeypots.py` | Einstieg Honeypot-Dienst: startet alle Honeypots (`start()`, auch für sensor.py) |
| `sensor.py` | Einstieg Außensensor (oci-worker): Honeypots + nginx-Web-Probes in lokale DB |
| `export.py` | erzwungener SSH-Befehl auf dem Sensor: Events ab ID als JSON-Zeilen |
| `sensors.py` | 3lis.de: holt Sensor-Events minütlich per SSH (Pull), Offset je Sensor in `offsets` |
| `intel.py` | IP-Profil: rDNS mit Timeout, Einstufung (bekannte Scanner/Clouds/VPN, hosting/mobile), Einschätzung |
| `tail.py` | Logs fortlaufend lesen, 7-Tage-Seed beim ersten Start, stündliches Prune |
| `parsers.py` | ein Parser je Quelle → Event-Dict (Zeitstempel aus der Logzeile) |
| `store.py` | SQLite-Schema (+ Spalten-Migration, `user_version` 1 = Event-Texte englisch; `modernize()` übersetzt Altformat auch beim Einfügen), Feed, Drilldown-Filter (`FILTERS`), IP-Profil-Abfragen |
| `trends.py` | Stundenzählung, Erwartung je Tagesstunde (Median/MAD), 24-h-Prognose, Spitzen |
| `campaigns.py` | Kampagnen (gleiche Befehlsfolge/Passwortliste über ≥ 3 IPs) und ASN-Wellen, stabiler Schlüssel je Fingerabdruck |
| `llm.py` | SSH-Aufruf des LLM-Proxys (`Busy` bei Rendering), Ausgabefilter `clean()` |
| `sessions.py` | LLM-Erklärung je Befehlsfolge (Fingerabdruck wie Kampagnen), `for_ip()` fürs IP-Profil |
| `alerts.py` | Telegram-Sammelmeldung je insights-Runde: neue Kampagnen/Wellen, Sitzungen mit Risiko „high“; gemeldet = insights kind `alert` |
| `news.py` | Feeds holen (RSS/Atom, Mastodon, CISA KEV) und über `TOPICS` mit eigenen Events verknüpfen |
| `insights.py` | Worker: Trend, Kampagnen, LLM-Namen (max. 3/Runde), stündlicher Lagebericht; `payload()` für die API |
| `stats.py` | Aggregation je Zeitfenster 1h/24h/7d, Hotspots, `byCountry`, Zeitleiste, Heatmap, Samples |
| `geo.py` | ip-api-Batch-Worker, Serverstandort |
| `honeypot.py` | Basis der Honeypots: Port belegen, Verbindungs-/Flutlimit, `attempt()`/`command()`-Detailtexte (Benutzer, Passwort, Befehl), `shell()` beobachtet Fake-Shell-Sitzungen, `payloads()` lädt Downloads und sichert Hex-/base64-Payloads (Shell und SQL), `sample()` → `Malware-Sample` |
| `samples.py` | Malware-Samples: Ablage `<sha256>` (0400, Quota), Art (ELF-Arch/Skript/EXE), gedrosselte Downloads nur von öffentlichen IPs |
| `honeypot_mysql.py` | MySQL :3306 (MariaDB-Begrüßung, Login annehmen, SQL mitschneiden, feste Antworten) → `MySQL-Probe` |
| `honeypot_postgres.py` | Postgres :5432 (Klartext-Passwort anfordern, Login annehmen, SQL mitschneiden) → `Postgres-Probe` |
| `honeypot_ssh.py` | SSH :22 via paramiko (Schlüssel abgelehnt, Passwort angenommen → Fake-Shell/Exec, nur Session-Kanäle; Uploads per `scp -t` und `cat >`) → `SSH-Probe` |
| `honeypot_telnet.py` | Telnet :23 (Router-Login, IAC filtern, jede Anmeldung → Fake-Shell) → `Telnet-Probe` |
| `honeypot_php.py` | PHP hinter nginx (127.0.0.1:8098, X-Real-IP): PHP 8.2.34 vortäuschen, WordPress-Login und Payloads mitschneiden → `PHP-Probe` |
| `shelltext.py` | Shell-Syntax der Fake-Shell: Variablen/`$((…))`/`$(…)` expandieren, `printf`, Filter hinter Pipes (`grep`, `wc`, `awk` …) |
| `fakeshell.py` | Fake-Shell: Profile `ROUTER` (Telnet) / `SERVER` (SSH), feste Antworten, `uname`-Flags, Pipes mit Filtern, Zeilenleser, Sitzungsschleife; Befehle als Event `Command “…”` (crit); `MAX_COMMANDS` gilt auch für SQL; `downloads()` (wget/curl/tftp-URLs), `Drops` (echo-Dropper) |
| `honeypot_ftp.py` | FTP :21 (vsftpd-Banner, USER/PASS mitlesen, „530“) → `FTP-Probe` |
| `visits.py` | Besucherstatistik aus `3lis.access.log` (Seitenaufruf + Browser-Beleg, Tages-Salt-Hash), `/api/visits` |
| `test_backend.py`, `test_insights.py` | Unit-Tests (`python3 -m unittest`) |

DB-Schema: `events(id, ts, ip, type, sev, src, port, detail, jail, sensor)` (sensor NULL = 3lis.de),
`geo(ip, lat, lon, cc, country, city, isp, asn, fetched, org, hosting, proxy, mobile)`, `offsets(path, inode, pos)`,
`visits(day, ts, visitor, path, ref)`, `humans(day, visitor)` (Besucher mit Ressourcen-Abruf),
`insights(kind, key, ts, data, text, model)` (kind trend/campaign/report/session/feed/related; data JSON, text = LLM, bei Kampagnen/Sitzungen JSON).

## Frontend (`frontend/` → `/var/www/lernseite/`)
| Pfad | Zweck |
|---|---|
| `index.html` | Startseite = Threat Monitor |
| `assets/css/base.css` | gemeinsame Tokens, Kopf-/Fußzeile, Textseiten |
| `assets/css/monitor.css` | Layout Monitor |
| `assets/js/main.js` | Polling, Zustand, Filter, Replay ruhiger Phasen |
| `assets/js/globe.js` | globe.gl: Länder-Färbung, Säulen, Bögen, Ringe, Tooltips, Klick, Ebenen/Drehung |
| `assets/js/iso-numeric.js` | ISO numerisch → Alpha-2 (Länder-IDs von world-atlas, generiert) |
| `assets/js/panels.js` | KPIs, Top-Listen (klickbar), Feed, Toast |
| `assets/js/sensors.js` | Sensoren: feste Farbe je Sensor, Plakette (Feed, Toast, Detail, Globus-Titel) |
| `assets/js/drawer.js` | Schublade: Vorgangslisten, Event + IP-Profil, Land; mit Zurück-Verlauf |
| `assets/js/charts.js` | SVG-Zeitleiste (gestapelt), Heatmap und Trend/Prognose mit Tooltips |
| `assets/js/insights.js` | Lagebild: Lagebericht, Trend-Hinweis, Kampagnen-Karten (Klick = Vorgänge 24 h), „In the news“; `sessionBlock()` fürs IP-Profil |
| `assets/js/format.js` | Typ-Farben (validierte Palette), Formatierung, Port-Dienste |
| `assets/vendor/` | globe.gl 2.46.2, topojson-client 3.1.0, world-atlas 2.0.2, @strudel/web 1.3.0 (+ clockworker) |
| `strudel/` | Groove Machine: `genres/` (je Genre 12 Spuren + Varianten/Subgenres, `index.js`), `code.js` (Code-Generator: Anzeige mit festen Werten, gespielt mit `grooveFx`), `fx.js` (Echtzeit-FX über `withValue`/`ref`: DJ-Filter, Regler, Halte-Effekte), `live.js` (Live-Code-Markierung über `hap.context.locations`), `app.js` (UI, Start/Stopp über `repl.stop()`), `samples.js` (eigene Samples: Dateien in IndexedDB, Bank-URLs in localStorage, Spur „Eigene Samples“) |
| `besucher/` | interne Besucherstatistik (hinter Authelia): KPIs, Tages-Chart, Monat/Jahr, Seiten, Herkunft |
| `lernen/index.php` | Übersicht der Lernseiten (liest `../*/index.html`) |
| `attack-monitor/` | Weiterleitung alter Links auf `/` |
| `impressum.html`, `datenschutz.html` | Rechtstexte |

## Deploy
`deploy/deploy.sh` (root), `deploy/sensor/` (Außensensor: Unit, nginx, `deploy-sensor.sh`; LLM-Zugang: `llm-proxy.py`, `deploy-llm.sh`), systemd-Units `deploy/attack-monitor.service` und `deploy/attack-honeypots.service` (gehärtet), fail2ban-Filter in `deploy/`,
nginx-Snippets `deploy/nginx-3lis-besucher.conf` (eigenes Log + Authelia-Schutz für `/besucher/`, `/api/visits`)
und `deploy/nginx-3lis-php-honeypot.conf` (`.php` → Honeypot, nur echte Skripte an php-fpm).
