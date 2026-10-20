#!/bin/bash
# Deployt Backend und Website auf 3lis.de. Als root ausführen: sudo deploy/deploy.sh
# Webroot-Unterseiten anderer Projekte (cell, elements, microscope, optik) bleiben unberührt.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WEB=/var/www/lernseite
APP=/opt/attack-monitor
STAMP=$(date +%Y%m%d-%H%M%S)

# Backend
install -d -m 755 "$APP" /var/lib/attack-monitor
dpkg -s python3-paramiko >/dev/null 2>&1 || apt-get install -y python3-paramiko  # SSH-Honeypot
install -m 644 "$REPO"/backend/{server,parsers,store,stats,geo,tail,intel,visits,honeypot,honeypot_mysql,honeypot_ssh,honeypot_ftp}.py "$APP"/
install -m 644 "$REPO/deploy/attack-monitor.service" /etc/systemd/system/
systemctl daemon-reload

# nginx: eigenes 3lis.de-Log und geschützte Besucherseite (Snippet ist im Vhost "default" eingebunden)
install -m 644 "$REPO/deploy/nginx-3lis-besucher.conf" /etc/nginx/snippets/3lis-besucher.conf
grep -q "snippets/3lis-besucher.conf" /etc/nginx/sites-available/default || { echo "include fehlt im Vhost default" >&2; exit 1; }
nginx -t && systemctl reload nginx
systemctl restart attack-monitor

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
systemctl is-active attack-monitor
curl -fsS -o /dev/null -w "API /api/status: %{http_code}\n" http://127.0.0.1:8099/api/status
curl -fsS -o /dev/null -w "Startseite: %{http_code}\n" https://3lis.de/
