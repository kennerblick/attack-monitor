# 3lis.de – Website mit Live Threat Monitor

Die Website von 3lis.de. Startseite ist ein Echtzeit-Lagebild aller Angriffe auf den Server:
ein 3D-Globus mit Angriffsherden und Live-Bögen, ein Live-Feed mit Detailansicht, Kennzahlen,
Top-Listen (Länder, ASN, Ports, SSH-Benutzernamen, Pfade, Jails), eine Zeitleiste und eine
Wochen-Heatmap. Dazu kommen die Musikseite **Strudel Groove Machine**, die Übersicht der
Lernseiten unter `/lernen/` sowie Impressum und Datenschutz.

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

## Konfiguration

| Variable | Default | Zweck |
|---|---|---|
| `ATTACK_DB` | `/var/lib/attack-monitor/events.db` | SQLite-Datei |
| `ATTACK_PORT` | `8099` | API-Port (nur 127.0.0.1) |

nginx leitet `/api/` an `127.0.0.1:8099` weiter (vhost `/etc/nginx/sites-enabled/default`).

## Datenschutz und externe Dienste

- Angreifer-IPs werden in der API auf /24 gekürzt (`1.2.3.x`), auch in Detailtexten.
- Geolokalisierung über den Batch-Endpoint von `ip-api.com`: kostenlos, ohne Key, pro IP nur einmal.
- Alle Bibliotheken (globe.gl, topojson, Länderdaten, @strudel/web) liegen versioniert in
  `frontend/assets/vendor/`. Es gibt keine CDNs und keine Google Fonts.
- Einzige externe Quelle im Browser: Strudel lädt Samples von `raw.githubusercontent.com`.

## Struktur

Siehe [docs/PROJECT_MAP.md](docs/PROJECT_MAP.md).

## Test im Browser

Der Strudel-Klang lässt sich headless prüfen: Puppeteer mit
`--autoplay-policy=no-user-gesture-required` aufrufen und `getAnalyzerData('frequency', 1)` auslesen.
Das Pattern wird mit `.analyze(1)` erzeugt.

## Lizenz

MIT. Mitgelieferte Bibliotheken behalten ihre eigene Lizenz: Strudel AGPL-3.0, globe.gl MIT.
