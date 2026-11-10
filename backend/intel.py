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
    (r"censys", "Censys", "research", "Internet-wide scan service (Censys Search), collects banners for security research"),
    (r"shodan", "Shodan", "research", "Search engine for connected devices, scans the entire internet"),
    (r"shadowserver", "Shadowserver", "research", "Non-profit foundation, reports vulnerable systems to CERTs/providers"),
    (r"binaryedge", "BinaryEdge", "research", "Commercial internet scanner (Coalition)"),
    (r"stretchoid", "Stretchoid", "research", "Scan project, aggressively scans many ports"),
    (r"internet-?census|internet-?measurement|driftnet", "Driftnet / internet-measurement.com", "research", "Internet measurement project"),
    (r"onyphe", "ONYPHE", "research", "French cyber-defense search engine"),
    (r"leakix", "LeakIX", "research", "Searches for open databases and misconfigurations"),
    (r"criminalip|aispera", "Criminal IP", "research", "Threat-intel search engine (AI Spera)"),
    (r"expanse|paloalto|palo alto", "Palo Alto Cortex Xpanse", "research", "Attack surface management, scans on behalf of customers"),
    (r"bitsight", "BitSight", "research", "Security rating, assesses companies' attack surfaces"),
    (r"rapid7|sonar", "Rapid7 Project Sonar", "research", "Internet-wide scan studies by Rapid7"),
    (r"modat", "Modat", "research", "Internet-Scanner / Device-Search"),
    (r"alphastrike|alpha strike", "Alpha Strike Labs", "research", "Security research, internet scans"),
    (r"recyber", "ReCyber", "research", "Internet scan project"),
    (r"netcraft", "Netcraft", "research", "Web survey and phishing detection"),
    (r"securitytrails|recorded ?future", "Recorded Future / SecurityTrails", "research", "Threat-intel provider"),
    (r"cyber ?resilience|cyberresilience", "Cyber Resilience Scan", "research", "Research scanner"),
    # Kunden-VMs der Konzern-Clouds vor den Konzernen selbst prüfen: das sind gemietete Server
    (r"googleusercontent|google ?cloud", "Google Cloud", "cloud", "Rented VM in Google Cloud – not Google itself"),
    (r"azure|cloudapp\.net", "Microsoft Azure", "cloud", "Rented VM in Azure – not Microsoft itself"),
    (r"googlebot|1e100\.net|google ?llc|google\.com", "Google", "search", "Google itself (crawlers/services)"),
    (r"bingbot|search\.msn|microsoft", "Microsoft", "search", "Microsoft itself (Bing crawler/services)"),
    (r"amazon|aws|ec2", "Amazon AWS", "cloud", "Cloud server at Amazon, usually a rented VM"),
    (r"digitalocean", "DigitalOcean", "cloud", "Cloud VPS, often used for scanners and bots"),
    (r"ovh", "OVH", "cloud", "Hosting/cloud (France)"),
    (r"hetzner", "Hetzner", "cloud", "Hosting/cloud (Germany)"),
    (r"linode|akamai", "Akamai / Linode", "cloud", "Cloud-VPS"),
    (r"vultr|choopa|constant", "Vultr", "cloud", "Cloud-VPS"),
    (r"tencent", "Tencent Cloud", "cloud", "Chinese cloud"),
    (r"alibaba|aliyun", "Alibaba Cloud", "cloud", "Chinese cloud"),
    (r"huawei", "Huawei Cloud", "cloud", "Chinese cloud"),
    (r"oracle", "Oracle Cloud", "cloud", "Cloud server at Oracle"),
    (r"m247|datacamp|cdn77", "M247 / Datacamp", "vpn", "Data centers, often used by VPN providers"),
    (r"tor-?exit|torproject", "Tor-Exit", "vpn", "Exit of the Tor anonymity network"),
]
CATEGORY = {"research": "Known scan service", "search": "Search engine/corporation", "cloud": "Cloud/hosting",
            "vpn": "VPN/anonymizer", "residential": "Residential", "mobile": "Mobile network", "unknown": "Unknown"}

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


IPV4 = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b')


def mask(text):
    """IPv4-Adressen in Texten auf /24 kürzen (DSGVO); gilt für alles, was ausgeliefert oder ans LLM gegeben wird."""
    return IPV4.sub(r'\1.x', text) if text else text


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
        return {"name": None, "category": "vpn", "label": CATEGORY["vpn"], "desc": "Proxy, VPN or Tor according to ip-api"}
    if mobile:
        return {"name": None, "category": "mobile", "label": CATEGORY["mobile"],
                "desc": "Mobile network – often infected smartphones/routers (botnet)"}
    if hosting:
        return {"name": None, "category": "cloud", "label": CATEGORY["cloud"],
                "desc": "Data center: rented server, typical for scanners, bots or compromised VMs"}
    if hosting is False:
        return {"name": None, "category": "residential", "label": CATEGORY["residential"],
                "desc": "Home/business line – usually an infected device in a botnet (e.g. Mirai)"}
    return {"name": None, "category": "unknown", "label": CATEGORY["unknown"], "desc": "No classification yet"}


def verdict(cls, profile):
    """Kurze, menschenlesbare Einschätzung aus Einstufung und Verhalten."""
    if cls["category"] in ("research", "search"):
        return "Probably harmless: a known service that systematically maps the internet."
    types = profile["types"]
    if types.get("SQLi/RCE"):
        return "Targeted attack: attempts code/SQL injection – clearly malicious."
    if types.get("SSH-Brute", 0) >= 10:
        return "Serial SSH password guessing – typical botnet behavior."
    if types.get("MySQL-Probe") or types.get("Postgres-Probe"):
        return "Looking for open databases: contacted the MySQL/Postgres honeypot on port 3306/5432."
    if types.get("PHP-Probe"):
        return "Attacks PHP: exploit/webshell payloads or WordPress logins at the PHP honeypot."
    if types.get("Telnet-Probe"):
        return "Telnet login with commands – typical for Mirai-style IoT botnets."
    if types.get("SSH-Probe") or types.get("FTP-Probe"):
        return "Tries credentials at the SSH/FTP honeypot (port 22/21) – typical botnet behavior."
    if any(port in (23, 2323) for port, _ in profile["ports"]):
        return "Looking for Telnet (port 23/2323) – typical for Mirai-style IoT botnets."
    if profile["n"] >= 1000:
        return f"Sustained barrage: {profile['n']} events on {profile['days']} days – automated and persistent."
    if profile["days"] > 2:
        return f"Recurring sender: active on {profile['days']} days."
    if profile["n"] == 1:
        return "Single contact – usually a mass scan passing by."
    return "Automated scanner/bot without known attribution."
