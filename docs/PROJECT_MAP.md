# Projektkarte

## Datenfluss
Logs (syslog, auth, nginx access/error, fail2ban) und Honeypots :3306/:5432/:22/:21/:23 → `tail.py`/`honeypot_*.py` (Offsets in DB) → `parsers.py` → SQLite
`events` ← `geo.py` (ip-api Batch, füllt `geo`) → `server.py` (`/api/feed`, `/api/stats`, `/api/status`,
`/api/events` Drilldown, `/api/ip?id=` IP-Profil, IP-Kürzung) → nginx `/api/` → Browser
(`assets/js/main.js` pollt Feed 2 s, Stats 15 s, Status 30 s; `drawer.js` lädt Drilldown/Profil bei Klick).

## Backend (`backend/`, stdlib + `python3-paramiko`, läuft als root wegen Log-Rechten und Port 21/22)
| Datei | Zweck |
|---|---|
| `server.py` | HTTP-API, IP-Maskierung, fail2ban-/Sperrlisten-Status, Einstieg |
| `intel.py` | IP-Profil: rDNS mit Timeout, Einstufung (bekannte Scanner/Clouds/VPN, hosting/mobile), Einschätzung |
| `tail.py` | Logs fortlaufend lesen, 7-Tage-Seed beim ersten Start, stündliches Prune |
| `parsers.py` | ein Parser je Quelle → Event-Dict (Zeitstempel aus der Logzeile) |
| `store.py` | SQLite-Schema (+ Spalten-Migration), Feed, Drilldown-Filter (`FILTERS`), IP-Profil-Abfragen |
| `stats.py` | Aggregation je Zeitfenster 1h/24h/7d, Hotspots, `byCountry`, Zeitleiste, Heatmap |
| `geo.py` | ip-api-Batch-Worker, Serverstandort |
| `honeypot.py` | Basis der Honeypots: Port belegen, Verbindungs-/Flutlimit, `attempt()`/`command()`-Detailtexte (Benutzer, Passwort, Befehl) |
| `honeypot_mysql.py` | MySQL :3306 (MariaDB-Begrüßung, Login annehmen, SQL mitschneiden, feste Antworten) → `MySQL-Probe` |
| `honeypot_postgres.py` | Postgres :5432 (Klartext-Passwort anfordern, Login annehmen, SQL mitschneiden) → `Postgres-Probe` |
| `honeypot_ssh.py` | SSH :22 via paramiko (Schlüssel abgelehnt, Passwort angenommen → Fake-Shell/Exec, nur Session-Kanäle) → `SSH-Probe` |
| `honeypot_telnet.py` | Telnet :23 (Router-Login, IAC filtern, jede Anmeldung → Fake-Shell) → `Telnet-Probe` |
| `fakeshell.py` | Fake-Shell: feste Antworten, Zeilenleser, Sitzungsschleife; Befehle als Event „Befehl „…““ (crit); `MAX_COMMANDS` gilt auch für SQL |
| `honeypot_ftp.py` | FTP :21 (vsftpd-Banner, USER/PASS mitlesen, „530“) → `FTP-Probe` |
| `visits.py` | Besucherstatistik aus `3lis.access.log` (Seitenaufruf + Browser-Beleg, Tages-Salt-Hash), `/api/visits` |
| `test_backend.py` | Unit-Tests (`python3 -m unittest`) |

DB-Schema: `events(id, ts, ip, type, sev, src, port, detail, jail)`,
`geo(ip, lat, lon, cc, country, city, isp, asn, fetched, org, hosting, proxy, mobile)`, `offsets(path, inode, pos)`,
`visits(day, ts, visitor, path, ref)`, `humans(day, visitor)` (Besucher mit Ressourcen-Abruf).

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
| `assets/js/drawer.js` | Schublade: Vorgangslisten, Event + IP-Profil, Land; mit Zurück-Verlauf |
| `assets/js/charts.js` | SVG-Zeitleiste (gestapelt) und Heatmap mit Tooltips |
| `assets/js/format.js` | Typ-Farben (validierte Palette), Formatierung, Port-Dienste |
| `assets/vendor/` | globe.gl 2.46.2, topojson-client 3.1.0, world-atlas 2.0.2, @strudel/web 1.3.0 (+ clockworker) |
| `strudel/` | Groove Machine: `genres/` (je Genre 12 Spuren + Varianten/Subgenres, `index.js`), `code.js` (Code-Generator: Anzeige mit festen Werten, gespielt mit `grooveFx`), `fx.js` (Echtzeit-FX über `withValue`/`ref`: DJ-Filter, Regler, Halte-Effekte), `live.js` (Live-Code-Markierung über `hap.context.locations`), `app.js` (UI, Start/Stopp über `repl.stop()`), `samples.js` (eigene Samples: Dateien in IndexedDB, Bank-URLs in localStorage, Spur „Eigene Samples“) |
| `besucher/` | interne Besucherstatistik (hinter Authelia): KPIs, Tages-Chart, Monat/Jahr, Seiten, Herkunft |
| `lernen/index.php` | Übersicht der Lernseiten (liest `../*/index.html`) |
| `attack-monitor/` | Weiterleitung alter Links auf `/` |
| `impressum.html`, `datenschutz.html` | Rechtstexte |

## Deploy
`deploy/deploy.sh` (root), systemd-Unit `deploy/attack-monitor.service`, fail2ban-Filter in `deploy/`,
nginx-Snippet `deploy/nginx-3lis-besucher.conf` (eigenes Log + Authelia-Schutz für `/besucher/`, `/api/visits`).
