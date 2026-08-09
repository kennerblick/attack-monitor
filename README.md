# 3lis.de – Live Attack Monitor

Modernes Live-Dashboard für Angriffe auf den Server (analog zur [Elements-Lernapp](https://github.com/kennerblick/elements)).

## Features

- Live-Feed (IP, Typ, Status) aus nginx + auth.log + fail2ban
- Weltkarte mit Angriffsherden
- Statistik-Karten + Diagramme
- fail2ban-Jails für SSH (Port 22022) + Web-Probes
- Reine Client-Seite + kleines Python-Backend

## Struktur

```
attack-monitor/
├── frontend/index.html
├── backend/server.py
├── deploy/
│   ├── jail.local
│   ├── nginx-botsearch.conf
│   ├── nginx-req-limit.conf
│   └── attack-monitor.service
└── README.md
```

## Installation (Debian 11 / Ubuntu)

```bash
git clone https://github.com/kennerblick/attack-monitor.git
cd attack-monitor

# Backend
sudo mkdir -p /opt/attack-monitor
sudo cp backend/server.py /opt/attack-monitor/
sudo cp deploy/attack-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attack-monitor

# fail2ban
sudo cp deploy/nginx-botsearch.conf /etc/fail2ban/filter.d/
sudo cp deploy/nginx-req-limit.conf /etc/fail2ban/filter.d/
sudo cp deploy/jail.local /etc/fail2ban/jail.local
sudo systemctl restart fail2ban

# Frontend
sudo mkdir -p /var/www/html/attack-monitor
sudo cp frontend/index.html /var/www/html/attack-monitor/
```

### nginx (in den 443-Server-Block)

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:8099/api/;
}
location /attack-monitor/ {
    alias /var/www/html/attack-monitor/;
}
location ~ /\.git {
    deny all;
    return 404;
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Test

```bash
curl -s http://127.0.0.1:8099/api/attacks | head -c 200
curl -s https://3lis.de/api/attacks | head -c 200
sudo fail2ban-client status
```

Dashboard: `https://3lis.de/attack-monitor/`

## Lizenz

MIT
