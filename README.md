# 3lis.de – Website mit Live Threat Monitor

Die Website von 3lis.de. Startseite ist ein Echtzeit-Lagebild aller Angriffe auf den Server:
ein interaktiver 3D-Globus (Länder nach Angriffen eingefärbt, Herde als Säulen, Live-Bögen, Tooltips,
Klick öffnet Land/Angriff), ein Live-Feed, Kennzahlen, Top-Listen (Arten, Länder, ASN, Ports,
Login-Benutzernamen, Passwörter, Befehle, Pfade, Jails), eine Zeitleiste und eine Wochen-Heatmap. Jeder Top-Listen-Eintrag
öffnet die einzelnen Vorgänge; jeder Vorgang ein IP-Profil (Verlauf, Verhalten, rDNS, Hosting/Proxy/
Mobilfunk, Einstufung bekannter Scan-Dienste und Clouds, Sperrstatus). Dazu kommen die Musikseite
**Strudel Groove Machine** (6 Genres inkl. Paul-Kalkbrenner-Stil mit je 6–9 Varianten/Subgenres und 12 genre-eigenen Spuren, Live-FX in Echtzeit, Live-Code-Ansicht mit Markierung der gerade klingenden Stellen, eigene Samples aus dem Browser oder per Sample-Bank-URL), die
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
| MySQL-Honeypot | Port 3306 (`backend/honeypot_mysql.py`) | MySQL-Probe (Benutzer, Datenbank) |
| SSH-Honeypot | Port 22 (`backend/honeypot_ssh.py`) | SSH-Probe (Benutzer, Passwort bzw. Schlüssel-Fingerprint, Befehle) |
| FTP-Honeypot | Port 21 (`backend/honeypot_ftp.py`) | FTP-Probe (Benutzer, Passwort) |
| Telnet-Honeypot | Port 23 (`backend/honeypot_telnet.py`) | Telnet-Probe (Benutzer, Passwort, Befehle) |

Ausgeführt wird nie etwas; Verbindungen ohne Login zählen als „Server-Erkennung“. MySQL und FTP lehnen
jede Anmeldung ab. SSH (nur Passwort, Schlüssel werden abgelehnt) und Telnet nehmen jede Anmeldung an und
führen in eine Fake-Shell (`backend/fakeshell.py`): BusyBox-Router mit festen Antworten (`uname`,
`/proc/cpuinfo`, `busybox X` → „applet not found“, Downloads schlagen fehl). Jede Befehlszeile wird ein
Event (Schwere kritisch, gekürzt auf 100 Zeichen), höchstens 25 je Sitzung, 20 s Timeout je Eingabe.
SSH erlaubt nur Session-Kanäle, kein Port-Forwarding (sonst offener Proxy).
- MySQL spielt die MariaDB-Begrüßung. Passwörter sieht er nicht, weil Clients nur einen Hash schicken.
  Die echte MariaDB ist deshalb abgeschaltet.
- SSH nutzt paramiko (`python3-paramiko`), meldet sich als OpenSSH 9.2 und hält einen festen RSA-Host-Key
  in `/var/lib/attack-monitor/ssh_host_rsa_key`. Das echte sshd läuft auf 22022.
- FTP spielt vsftpd und liest `USER`/`PASS` im Klartext, höchstens 20 Befehle je Verbindung.

- Telnet spielt den Login-Prompt eines Routers und filtert die Telnet-Optionsverhandlung heraus.
  portsentry überwacht die Ports 21, 22 und 23 nicht mehr, weil sie belegt sind.

Passwörter und Befehle erscheinen öffentlich (Detail, Top 10, IP-Profil), Passwörter gekürzt auf 40 Zeichen. Alle Honeypots
lauschen nur auf IPv4 (die /24-Kürzung kennt nur IPv4), nehmen je höchstens 50 gleichzeitige
Verbindungen an und speichern höchstens 30 Events pro IP und Minute. Ist ein Port belegt, versuchen
sie es jede Minute erneut.

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
| `ATTACK_SSH_KEY` | `/var/lib/attack-monitor/ssh_host_rsa_key` | Host-Key des SSH-Honeypots (wird beim ersten Start erzeugt) |

nginx leitet `/api/` an `127.0.0.1:8099` weiter (vhost `/etc/nginx/sites-enabled/default`).

## Datenschutz und externe Dienste

- Angreifer-IPs werden in der API auf /24 gekürzt (`1.2.3.x`), auch in Detailtexten.
- Geolokalisierung über den Batch-Endpoint von `ip-api.com`: kostenlos, ohne Key, pro IP nur einmal
  (inkl. `hosting`/`proxy`/`mobile`/`org`). rDNS fürs IP-Profil über den lokalen Resolver, 24 h gecacht;
  Hostnamen, die die IP enthalten, werden ebenfalls gekürzt. Keine externen Threat-Intel-APIs.
- Alle Bibliotheken (globe.gl, topojson, Länderdaten, @strudel/web) liegen versioniert in
  `frontend/assets/vendor/`. Es gibt keine CDNs und keine Google Fonts.
- Einzige externe Quelle im Browser: Strudel lädt Samples von `raw.githubusercontent.com`. Eigene Samples
  bleiben im Browser (IndexedDB); selbst eingetragene Sample-Bänke lädt der Browser direkt von dort.
- Konzept zum Umwandeln echter Songs in Patterns: [docs/song-konvertierung.md](docs/song-konvertierung.md).

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
