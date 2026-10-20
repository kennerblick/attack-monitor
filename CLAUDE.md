# CLAUDE.md

## Projekt
- **Zweck:** Website 3lis.de – Startseite Live Threat Monitor, Strudel Groove Machine, Lernseiten-Übersicht, Impressum/Datenschutz
- **Stack:** Python 3.11 stdlib + SQLite (Backend) / Vanilla JS-Module, globe.gl, @strudel/web (Frontend, Bibliotheken vendored)
- **Befehle:** `test`: `cd backend && python3 -m unittest -v` · `run` (lokal): `ATTACK_DB=/tmp/x.db ATTACK_PORT=8199 python3 backend/server.py` · `deploy`: `sudo deploy/deploy.sh`
- **Projektkarte:** siehe `docs/PROJECT_MAP.md`
- **Besonderheiten / No-Gos:** Angreifer-IPs nie ungekürzt über die API ausliefern. Keine CDNs/Google Fonts (Datenschutz). Webroot `/var/www/lernseite` enthält fremde Lernseiten – nur die eigenen Pfade überschreiben. Strudel-Bundle braucht `assets/vendor/assets/clockworker-*.js` und `initAudio()` vor dem ersten `evaluate`.
