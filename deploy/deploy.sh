#!/bin/bash
# Deployt Backend und Website auf 3lis.de. Als root ausführen: sudo deploy/deploy.sh
# Webroot-Unterseiten anderer Projekte (cell, elements, microscope, optik) bleiben unberührt.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WEB=/var/www/lernseite
APP=/opt/attack-monitor
STAMP=$(date +%Y%m%d-%H%M%S)

# Backend
# Honeypots laufen als eigener Benutzer; Datenbank und Host-Key teilt nur die Gruppe attack-monitor
getent group attack-monitor >/dev/null || groupadd -r attack-monitor
id attack-honeypot >/dev/null 2>&1 || useradd -r -g attack-monitor -d /nonexistent -s /usr/sbin/nologin attack-honeypot
install -d -m 755 "$APP"
install -d -m 2770 -o root -g attack-monitor /var/lib/attack-monitor
for f in /var/lib/attack-monitor/events.db{,-wal,-shm}; do [ -e "$f" ] && chgrp attack-monitor "$f" && chmod 660 "$f"; done
[ -e /var/lib/attack-monitor/ssh_host_rsa_key ] && chown attack-honeypot:attack-monitor /var/lib/attack-monitor/ssh_host_rsa_key
dpkg -s python3-paramiko >/dev/null 2>&1 || apt-get install -y python3-paramiko  # SSH-Honeypot
install -m 644 "$REPO"/backend/{server,parsers,store,stats,geo,tail,intel,visits,honeypots,honeypot,honeypot_mysql,honeypot_postgres,honeypot_ssh,honeypot_ftp,honeypot_telnet,honeypot_php,fakeshell}.py "$APP"/
install -m 644 "$REPO"/deploy/{attack-monitor,attack-honeypots}.service /etc/systemd/system/
systemctl daemon-reload

# nginx: eigenes 3lis.de-Log und geschützte Besucherseite (Snippet ist im Vhost "default" eingebunden)
install -m 644 "$REPO/deploy/nginx-3lis-besucher.conf" /etc/nginx/snippets/3lis-besucher.conf
install -m 644 "$REPO/deploy/nginx-3lis-php-honeypot.conf" /etc/nginx/snippets/3lis-php-honeypot.conf
for s in 3lis-besucher 3lis-php-honeypot; do
  grep -q "snippets/$s.conf" /etc/nginx/sites-available/default || { echo "include $s fehlt im Vhost default" >&2; exit 1; }
done
nginx -t && systemctl reload nginx
systemctl restart attack-monitor  # gibt die Honeypot-Ports frei, falls noch die alte Version lief
systemctl enable -q attack-honeypots && systemctl restart attack-honeypots

# Website: alte Übersicht sichern, sie lebt jetzt unter /lernen/
if [ -f "$WEB/index.php" ]; then
  mv "$WEB/index.php" "/var/backups/lernseite-index.php.$STAMP"
fi
if [ -f "$WEB/strudel/index.html" ] && [ ! -f "$WEB/strudel/app.js" ]; then
  cp -a "$WEB/strudel/index.html" "/var/backups/strudel-index.html.$STAMP"
fi
cp -r "$REPO"/frontend/{index.html,impressum.html,datenschutz.html,assets,strudel,lernen,attack-monitor,besucher} "$WEB"/
chown -R www-data:www-data "$WEB"/{index.html,impressum.html,datenschutz.html,assets,strudel,lernen,attack-monitor,besucher}

sleep 2
systemctl is-active attack-monitor attack-honeypots
curl -fsS -o /dev/null -w "API /api/status: %{http_code}\n" http://127.0.0.1:8099/api/status
curl -fsS -o /dev/null -w "Startseite: %{http_code}\n" https://3lis.de/
