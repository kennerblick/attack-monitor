# 3lis.de – Website mit Live Threat Monitor

Die Website von 3lis.de. Startseite ist ein Echtzeit-Lagebild aller Angriffe auf den Server:
ein interaktiver 3D-Globus (Länder nach Angriffen eingefärbt, Herde als Säulen, Live-Bögen, Tooltips,
Klick öffnet Land/Angriff), ein Live-Feed, Kennzahlen, Top-Listen (Arten, Länder, ASN, Ports,
SSH-Benutzernamen, Pfade, Jails), eine Zeitleiste und eine Wochen-Heatmap. Jeder Top-Listen-Eintrag
öffnet die einzelnen Vorgänge; jeder Vorgang ein IP-Profil (Verlauf, Verhalten, rDNS, Hosting/Proxy/
Mobilfunk, Einstufung bekannter Scan-Dienste und Clouds, Sperrstatus). Dazu kommen die Musikseite
**Strudel Groove Machine** (6 Genres mit je 6–8 Varianten/Subgenres und 12 genre-eigenen Spuren, Live-FX in Echtzeit, Live-Code-Ansicht mit Markierung der gerade klingenden Stellen), die
Übersicht der Lernseiten unter `/lernen/` sowie Impressum und Datenschutz.

## Schnellstart

```bash
cd backend && python3 -m unittest -v      # Tests
sudo deploy/deploy.sh                      # Backend + Website ausrollen
```

Das Deploy-Skript kopiert das Backend nach `/opt/attack-monitor` und startet den Dienst neu. Die
Website legt es in `/var/www/lernseite` ab. Die alte `index.php` wird nach `/var/backups/` verschoben,
weil nginx `index.php` vor `index.html` bevorzugt. Die anderen Lernseiten im Webroot bleiben unberührt.

## Datenquellen

| Quelle | Log | Event-Typ |
|---|---|---|
| portsentry | `/var/log/syslog` | Port-Scan (mit Zielport) |
| sshd | `/var/log/auth.log` | SSH-Brute (Benutzername) |
| nginx | `access.log` / `error.log` | Web-Probe, SQLi/RCE, Rate-Limit, TLS-Scan |
| fail2ban | `/var/log/fail2ban.log` | fail2ban-Ban (nur `Ban`, nicht `Unban` und nicht `Restore Ban`) |

Die Events liegen in SQLite (`/var/lib/attack-monitor/events.db`) und werden nach 8 Tagen gelöscht.
Beim ersten Start mit leerer DB liest das Backend die rotierten Logs der letzten 7 Tage nach.
Danach setzt es an gespeicherten Offsets fort.

## Besucherstatistik (intern)

`https://3lis.de/besucher/` hinter Authelia (Zwei-Faktor). Zeigt Besucher und Aufrufe pro Tag,
Monat und Jahr, den Trend (7 und 30 Tage, gleitender 7-Tage-Schnitt), Top-Seiten und die Herkunft.
Quelle ist das eigene Log `/var/log/nginx/3lis.access.log`. Beim ersten Start liest das Backend
einmalig die alten gemischten `access.log*` nach, bis zum Beginn des eigenen Logs (`backend/visits.py`).

- Ein Aufruf zählt nur, wenn er von einem Browser kommt, der am selben Tag auch Ressourcen mit Referer
  3lis.de nachlädt. Rund 97 % der Abrufe mit Browser-Kennung sind Bots, die nur das HTML holen.
  IPs, die schon als Angreifer erfasst sind, fallen ebenfalls heraus.
- Ein Besucher ist ein Hash aus IP und User-Agent mit einem Tages-Salt, der nur im RAM liegt. Es gibt
  keine Cookies. Ein Neustart am selben Tag kann einen Besucher doppelt zählen. Monats- und
  Jahreswerte sind die Summe der Tageswerte.
- nginx: `deploy/nginx-3lis-besucher.conf` ist im Vhost `default` eingebunden
  (`include /etc/nginx/snippets/3lis-besucher.conf;`). Authelia braucht die Regel für die Domain
  `3lis.de` mit den Ressourcen `^/besucher/` und `^/api/visits$`.

## Konfiguration

| Variable | Default | Zweck |
|---|---|---|
| `ATTACK_DB` | `/var/lib/attack-monitor/events.db` | SQLite-Datei |
| `ATTACK_PORT` | `8099` | API-Port (nur 127.0.0.1) |

nginx leitet `/api/` an `127.0.0.1:8099` weiter (vhost `/etc/nginx/sites-enabled/default`).

## Datenschutz und externe Dienste

- Angreifer-IPs werden in der API auf /24 gekürzt (`1.2.3.x`), auch in Detailtexten.
- Geolokalisierung über den Batch-Endpoint von `ip-api.com`: kostenlos, ohne Key, pro IP nur einmal
  (inkl. `hosting`/`proxy`/`mobile`/`org`). rDNS fürs IP-Profil über den lokalen Resolver, 24 h gecacht;
  Hostnamen, die die IP enthalten, werden ebenfalls gekürzt. Keine externen Threat-Intel-APIs.
- Alle Bibliotheken (globe.gl, topojson, Länderdaten, @strudel/web) liegen versioniert in
  `frontend/assets/vendor/`. Es gibt keine CDNs und keine Google Fonts.
- Einzige externe Quelle im Browser: Strudel lädt Samples von `raw.githubusercontent.com`.

## Struktur

Siehe [docs/PROJECT_MAP.md](docs/PROJECT_MAP.md).

## Test im Browser

Der Strudel-Klang lässt sich headless prüfen: Playwright/Puppeteer mit
`--autoplay-policy=no-user-gesture-required` aufrufen und `getAnalyzerData('frequency', 1)` auslesen.
Das Pattern wird mit `.analyze(1)` erzeugt. Lokal: API mit Kopie der DB auf Port 8199 starten
(siehe `CLAUDE.md`) und `frontend/` mit einem Proxy für `/api/` ausliefern. Der Globus braucht
headless `--use-gl=swiftshader --enable-unsafe-swiftshader`.

## Lizenz

MIT. Mitgelieferte Bibliotheken behalten ihre eigene Lizenz: Strudel AGPL-3.0, globe.gl MIT.
