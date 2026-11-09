#!/bin/bash
# Richtet einen Außensensor ein bzw. aktualisiert ihn. Auf dem Sensor als root, im entpackten Repo-Stand:
#   sudo deploy/sensor/deploy-sensor.sh "<öffentlicher Schlüssel von /etc/attack-monitor/sensor_key.pub auf 3lis.de>"
# Voraussetzung: echtes sshd lauscht schon auf 22022 (sonst belegt der SSH-Honeypot nie Port 22, siehe docs).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
APP=/opt/attack-monitor
PULL_KEY="${1:?öffentlicher Schlüssel von 3lis.de fehlt}"
PORTS="21 22 23 80 443 3306 5432 22022"

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-paramiko nginx >/dev/null
getent group attack-monitor >/dev/null || groupadd -r attack-monitor
id attack-honeypot >/dev/null 2>&1 || useradd -r -g attack-monitor -d /nonexistent -s /usr/sbin/nologin attack-honeypot
# Abholer für 3lis.de: braucht eine Shell für den erzwungenen Befehl, sonst nichts (restrict)
id attack-export >/dev/null 2>&1 || useradd -r -g attack-monitor -m -d /var/lib/attack-export -s /bin/sh attack-export
install -d -m 700 -o attack-export -g attack-monitor /var/lib/attack-export/.ssh
echo "command=\"/usr/bin/python3 $APP/export.py\",restrict $PULL_KEY" > /var/lib/attack-export/.ssh/authorized_keys
chown attack-export:attack-monitor /var/lib/attack-export/.ssh/authorized_keys
chmod 600 /var/lib/attack-export/.ssh/authorized_keys

install -d -m 755 "$APP"
install -d -m 2770 -o root -g attack-monitor /var/lib/attack-monitor
install -m 644 "$REPO"/backend/{sensor,export,honeypots,honeypot,honeypot_mysql,honeypot_postgres,honeypot_ssh,honeypot_ftp,honeypot_telnet,honeypot_php,fakeshell,parsers,store,tail,visits}.py "$APP"/
install -m 644 "$REPO/deploy/sensor/attack-sensor.service" /etc/systemd/system/

[ -f /etc/nginx/sensor.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=localhost" \
  -keyout /etc/nginx/sensor.key -out /etc/nginx/sensor.crt 2>/dev/null
install -m 644 "$REPO/deploy/sensor/nginx-sensor.conf" /etc/nginx/sites-available/sensor
ln -sf /etc/nginx/sites-available/sensor /etc/nginx/sites-enabled/sensor
rm -f /etc/nginx/sites-enabled/default
nginx -t -q && systemctl reload nginx

# Oracle-Images: INPUT endet mit REJECT, nur 22 offen -> Honeypot-Ports davor freigeben (live und dauerhaft)
for p in $PORTS; do
  iptables -C INPUT -p tcp --dport "$p" -m state --state NEW -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 5 -p tcp --dport "$p" -m state --state NEW -j ACCEPT
  grep -q -- "--dport $p -j ACCEPT" /etc/iptables/rules.v4 \
    || sed -i "/--dport 22 -j ACCEPT/a -A INPUT -p tcp -m state --state NEW -m tcp --dport $p -j ACCEPT" /etc/iptables/rules.v4
done

systemctl daemon-reload
systemctl enable -q attack-sensor && systemctl restart attack-sensor
sleep 2
systemctl is-active attack-sensor nginx
ss -ltn | awk 'NR>1 {print $4}' | sort -u | tr '\n' ' '; echo
