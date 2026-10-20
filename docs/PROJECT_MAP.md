# Projektkarte

## Datenfluss
Logs (syslog, auth, nginx access/error, fail2ban) → `tail.py` (Offsets in DB) → `parsers.py` → SQLite
`events` ← `geo.py` (ip-api Batch, füllt `geo`) → `server.py` (`/api/feed`, `/api/stats`, `/api/status`,
`/api/events` Drilldown, `/api/ip?id=` IP-Profil, IP-Kürzung) → nginx `/api/` → Browser
(`assets/js/main.js` pollt Feed 2 s, Stats 15 s, Status 30 s; `drawer.js` lädt Drilldown/Profil bei Klick).

## Backend (`backend/`, stdlib only, läuft als root wegen Log-Rechten)
| Datei | Zweck |
|---|---|
| `server.py` | HTTP-API, IP-Maskierung, fail2ban-/Sperrlisten-Status, Einstieg |
| `intel.py` | IP-Profil: rDNS mit Timeout, Einstufung (bekannte Scanner/Clouds/VPN, hosting/mobile), Einschätzung |
| `tail.py` | Logs fortlaufend lesen, 7-Tage-Seed beim ersten Start, stündliches Prune |
| `parsers.py` | ein Parser je Quelle → Event-Dict (Zeitstempel aus der Logzeile) |
| `store.py` | SQLite-Schema (+ Spalten-Migration), Feed, Drilldown-Filter (`FILTERS`), IP-Profil-Abfragen |
| `stats.py` | Aggregation je Zeitfenster 1h/24h/7d, Hotspots, `byCountry`, Zeitleiste, Heatmap |
| `geo.py` | ip-api-Batch-Worker, Serverstandort |
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
| `strudel/` | Groove Machine: `genres.js` (Presets), `code.js` (Code-Generator), `live.js` (Live-Code mit Markierung über `hap.context.locations`), `app.js` (UI, Start/Stopp über `repl.stop()`) |
| `besucher/` | interne Besucherstatistik (hinter Authelia): KPIs, Tages-Chart, Monat/Jahr, Seiten, Herkunft |
| `lernen/index.php` | Übersicht der Lernseiten (liest `../*/index.html`) |
| `attack-monitor/` | Weiterleitung alter Links auf `/` |
| `impressum.html`, `datenschutz.html` | Rechtstexte |

## Deploy
`deploy/deploy.sh` (root), systemd-Unit `deploy/attack-monitor.service`, fail2ban-Filter in `deploy/`,
nginx-Snippet `deploy/nginx-3lis-besucher.conf` (eigenes Log + Authelia-Schutz für `/besucher/`, `/api/visits`).
