"""IP-Profil für die Detailansicht: Verlauf, Verhalten, rDNS und Einstufung des Absenders.

Die Einstufung arbeitet nur mit eigenen Daten (rDNS, ISP/Org, ASN aus ip-api) und einer
Liste bekannter Scan-Dienste, Suchmaschinen und Clouds. Keine externen Threat-Intel-APIs:
die vollständige IP verlässt den Server nur für Geo (ip-api) und rDNS.
"""
import re
import socket
import threading
import time

# (Muster in rDNS/ISP/Org, Name, Kategorie, Beschreibung)
KNOWN = [
    (r"censys", "Censys", "research", "Internet-weiter Scan-Dienst (Censys Search), sammelt Banner für Sicherheitsforschung"),
    (r"shodan", "Shodan", "research", "Suchmaschine für vernetzte Geräte, scannt das gesamte Internet"),
    (r"shadowserver", "Shadowserver", "research", "Gemeinnützige Stiftung, meldet verwundbare Systeme an CERTs/Provider"),
    (r"binaryedge", "BinaryEdge", "research", "Kommerzieller Internet-Scanner (Coalition)"),
    (r"stretchoid", "Stretchoid", "research", "Scan-Projekt, scannt aggressiv viele Ports"),
    (r"internet-?census|internet-?measurement|driftnet", "Driftnet / internet-measurement.com", "research", "Internet-Vermessungsprojekt"),
    (r"onyphe", "ONYPHE", "research", "Französische Cyber-Defense-Suchmaschine"),
    (r"leakix", "LeakIX", "research", "Sucht offene Datenbanken und Fehlkonfigurationen"),
    (r"criminalip|aispera", "Criminal IP", "research", "Threat-Intel-Suchmaschine (AI Spera)"),
    (r"expanse|paloalto|palo alto", "Palo Alto Cortex Xpanse", "research", "Attack-Surface-Management, scannt im Kundenauftrag"),
    (r"bitsight", "BitSight", "research", "Security-Rating, bewertet Angriffsflächen von Firmen"),
    (r"rapid7|sonar", "Rapid7 Project Sonar", "research", "Internet-weite Scan-Studien von Rapid7"),
    (r"modat", "Modat", "research", "Internet-Scanner / Device-Search"),
    (r"alphastrike|alpha strike", "Alpha Strike Labs", "research", "Security-Forschung, Internet-Scans"),
    (r"recyber", "ReCyber", "research", "Internet-Scan-Projekt"),
    (r"netcraft", "Netcraft", "research", "Web-Survey und Phishing-Erkennung"),
    (r"securitytrails|recorded ?future", "Recorded Future / SecurityTrails", "research", "Threat-Intel-Anbieter"),
    (r"cyber ?resilience|cyberresilience", "Cyber Resilience Scan", "research", "Forschungs-Scanner"),
    # Kunden-VMs der Konzern-Clouds vor den Konzernen selbst prüfen: das sind gemietete Server
    (r"googleusercontent|google ?cloud", "Google Cloud", "cloud", "Gemietete VM in der Google Cloud – nicht Google selbst"),
    (r"azure|cloudapp\.net", "Microsoft Azure", "cloud", "Gemietete VM in Azure – nicht Microsoft selbst"),
    (r"googlebot|1e100\.net|google ?llc|google\.com", "Google", "search", "Google selbst (Crawler/Dienste)"),
    (r"bingbot|search\.msn|microsoft", "Microsoft", "search", "Microsoft selbst (Bing-Crawler/Dienste)"),
    (r"amazon|aws|ec2", "Amazon AWS", "cloud", "Cloud-Server bei Amazon, typ. gemietete VM"),
    (r"digitalocean", "DigitalOcean", "cloud", "Cloud-VPS, häufig für Scanner und Bots genutzt"),
    (r"ovh", "OVH", "cloud", "Hoster/Cloud (Frankreich)"),
    (r"hetzner", "Hetzner", "cloud", "Hoster/Cloud (Deutschland)"),
    (r"linode|akamai", "Akamai / Linode", "cloud", "Cloud-VPS"),
    (r"vultr|choopa|constant", "Vultr", "cloud", "Cloud-VPS"),
    (r"tencent", "Tencent Cloud", "cloud", "Chinesische Cloud"),
    (r"alibaba|aliyun", "Alibaba Cloud", "cloud", "Chinesische Cloud"),
    (r"huawei", "Huawei Cloud", "cloud", "Chinesische Cloud"),
    (r"oracle", "Oracle Cloud", "cloud", "Cloud-Server bei Oracle"),
    (r"m247|datacamp|cdn77", "M247 / Datacamp", "vpn", "Rechenzentren, häufig von VPN-Anbietern genutzt"),
    (r"tor-?exit|torproject", "Tor-Exit", "vpn", "Ausgang des Tor-Anonymisierungsnetzes"),
]
CATEGORY = {"research": "Bekannter Scan-Dienst", "search": "Suchmaschine/Konzern", "cloud": "Cloud/Hoster",
            "vpn": "VPN/Anonymisierer", "residential": "Privatanschluss", "mobile": "Mobilfunk", "unknown": "Unbekannt"}

_ptr_cache = {}
_ptr_lock = threading.Lock()


def ptr(ip, timeout=2.0):
    """Reverse-DNS mit Timeout (gethostbyaddr kennt keinen), Ergebnis 24 h gecacht."""
    with _ptr_lock:
        hit = _ptr_cache.get(ip)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    result = []
    t = threading.Thread(target=lambda: result.append(_resolve(ip)), daemon=True)
    t.start()
    t.join(timeout)
    name = result[0] if result else None
    with _ptr_lock:
        if len(_ptr_cache) > 5000:
            _ptr_cache.clear()
        _ptr_cache[ip] = (time.time(), name)
    return name


def _resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def mask_host(host, ip):
    """rDNS-Namen kürzen, wenn sie die IP enthalten (z. B. 1-2-3-4.dsl.example.net -> 1-2-3-x...)."""
    if not host:
        return None
    octets = ip.split(".")
    groups = re.findall(r"\d+", host)
    if len(octets) == 4 and all(o in groups for o in octets):
        return re.sub(rf"(?<!\d){octets[3]}(?!\d)", "x", host, count=1 if octets[3] in octets[:3] else 0)
    return host


def classify(host, isp, org, hosting, proxy, mobile):
    hay = " ".join(x for x in (host, isp, org) if x).lower()
    for pattern, name, cat, desc in KNOWN:
        if re.search(pattern, hay):
            return {"name": name, "category": cat, "label": CATEGORY[cat], "desc": desc}
    if proxy:
        return {"name": None, "category": "vpn", "label": CATEGORY["vpn"], "desc": "Laut ip-api Proxy, VPN oder Tor"}
    if mobile:
        return {"name": None, "category": "mobile", "label": CATEGORY["mobile"],
                "desc": "Mobilfunknetz – oft infizierte Smartphones/Router (Botnetz)"}
    if hosting:
        return {"name": None, "category": "cloud", "label": CATEGORY["cloud"],
                "desc": "Rechenzentrum: gemieteter Server, typisch für Scanner, Bots oder kompromittierte VMs"}
    if hosting is False:
        return {"name": None, "category": "residential", "label": CATEGORY["residential"],
                "desc": "Privat-/Firmenanschluss – meist ein infiziertes Gerät in einem Botnetz (z. B. Mirai)"}
    return {"name": None, "category": "unknown", "label": CATEGORY["unknown"], "desc": "Noch keine Einstufung möglich"}


def verdict(cls, profile):
    """Kurze, menschenlesbare Einschätzung aus Einstufung und Verhalten."""
    if cls["category"] in ("research", "search"):
        return "Vermutlich harmlos: bekannter Dienst, der das Internet systematisch vermisst."
    types = profile["types"]
    if types.get("SQLi/RCE"):
        return "Gezielter Angriff: versucht Code-/SQL-Injection – eindeutig bösartig."
    if types.get("SSH-Brute", 0) >= 10:
        return "Passwort-Raten auf SSH in Serie – typisches Botnetz-Verhalten."
    if types.get("MySQL-Probe") or types.get("Postgres-Probe"):
        return "Sucht offene Datenbanken: Kontakt mit dem MySQL-/Postgres-Honeypot auf Port 3306/5432."
    if types.get("PHP-Probe"):
        return "Greift PHP an: Exploit-/Webshell-Payloads oder WordPress-Logins am PHP-Honeypot."
    if types.get("Telnet-Probe"):
        return "Telnet-Login mit Befehlen – typisch für Mirai-artige IoT-Botnetze."
    if types.get("SSH-Probe") or types.get("FTP-Probe"):
        return "Probiert Zugangsdaten am SSH-/FTP-Honeypot (Port 22/21) – typisches Botnetz-Verhalten."
    if any(port in (23, 2323) for port, _ in profile["ports"]):
        return "Sucht Telnet (Port 23/2323) – typisch für Mirai-artige IoT-Botnetze."
    if profile["n"] >= 1000:
        return f"Dauerbeschuss: {profile['n']} Vorgänge an {profile['days']} Tagen – automatisiert und hartnäckig."
    if profile["days"] > 2:
        return f"Wiederkehrender Absender: an {profile['days']} Tagen aktiv."
    if profile["n"] == 1:
        return "Einzelner Kontakt – meist Massen-Scan, der zufällig vorbeikam."
    return "Automatisierter Scanner/Bot ohne bekannte Zuordnung."
