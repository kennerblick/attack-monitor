#!/bin/bash
# Richtet auf oci-worker den LLM-Zugang für 3lis.de ein (Ollama läuft dort schon, ~/ollama/compose.yml). Als root:
#   sudo deploy/sensor/deploy-llm.sh "<öffentlicher Schlüssel von /etc/attack-monitor/sensor_key.pub auf 3lis.de>"
# Danach auf 3lis.de: /etc/attack-monitor/llm.json = {"ssh": "attack-llm@<host>", "port": 22022} und Dienst neu starten.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PULL_KEY="${1:?öffentlicher Schlüssel von 3lis.de fehlt}"
HOME_DIR=/var/lib/attack-llm

# Eigener Benutzer: der Schlüssel kann nur den Proxy aufrufen (restrict: kein Forwarding, kein PTY)
id attack-llm >/dev/null 2>&1 || useradd -r -m -d "$HOME_DIR" -s /bin/sh attack-llm
install -d -m 700 -o attack-llm -g attack-llm "$HOME_DIR/.ssh"
echo "command=\"/usr/bin/python3 /opt/attack-monitor/llm-proxy.py\",restrict $PULL_KEY" > "$HOME_DIR/.ssh/authorized_keys"
chown attack-llm:attack-llm "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"
install -d -m 755 /opt/attack-monitor
install -m 755 "$REPO/deploy/sensor/llm-proxy.py" /opt/attack-monitor/

curl -fsS -o /dev/null -w "Ollama: %{http_code}\n" http://127.0.0.1:11434/api/tags
