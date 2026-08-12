# 3lis.de – Live Attack Monitor

Modernes Live-Dashboard für Angriffe auf den Server (analog zur [Elements-Lernapp](https://github.com/kennerblick/elements)).

## Features

- Live-Feed (IP, Typ, Status) aus nginx + auth.log + fail2ban
- Echte Weltkarte (Leaflet + dunkle CartoDB-Kacheln), zoom- und pan-bar
- Angriffe werden per IP-Geolokalisierung (ip-api.com, im Backend gecacht) an ihrer echten Position angezeigt, inkl. animiertem Bogen zum Zielserver
- Statistik-Karten + Diagramme
- fail2ban-Jails für SSH (Port 22022) + Web-Probes
- Reine Client-Seite + kleines Python-Backend

## Externe Abhängigkeiten

- **Frontend** lädt Leaflet (JS/CSS) sowie Kartenkacheln von `unpkg.com` und `basemaps.cartocdn.com` per CDN.
- **Backend** ruft für neu gesehene Angreifer-IPs `ip-api.com` auf (kostenlos, kein Key, ~45 Req/Min-Limit, Anfragen laufen asynchron über eine Queue und werden dauerhaft pro IP gecacht). Beim Start ermittelt es außerdem einmalig die eigene Standort-Position für den Zielserver-Marker auf der Karte.
- Damit werden Angreifer-IPs an einen externen Drittanbieter (ip-api.com) übertragen. Falls das nicht gewünscht ist, `geolocate()` in `backend/server.py` deaktivieren (liefert dann `None`, die Karte zeigt nur noch die Demo-Simulation für nicht lokalisierte Events).

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
