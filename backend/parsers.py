"""Wandelt einzelne Logzeilen in Angriffs-Events um.

Jede Quelle hat ihren eigenen Parser, der ein Event-Dict oder None liefert.
Der Zeitstempel kommt immer aus der Logzeile selbst, nicht aus der Uhr beim
Einlesen - sonst landen beim Nachladen alter Logs alle Events auf "jetzt".
"""
import re
import time
from datetime import datetime

IPV4 = r'(?:\d{1,3}\.){3}\d{1,3}'
SSH_PORT = 22022
OWN_PATHS = ("/assets/", "/strudel/", "/lernen/", "/api/")

WEB_RCE = re.compile(r'union.*select|eval\(|eval-stdin|base64_decode|/etc/passwd|cmd=|shell|\$\{jndi', re.I)
WEB_PROBE = re.compile(
    r'\.env|\.git|wp-login|wp-admin|wp-content|phpmyadmin|xmlrpc|adminer|\.sql|\.bak|'
    r'/cgi-bin/|/boaform|/actuator|/vendor/|\.aws|config\.json|/owa/|/hnap1', re.I)

NGINX_ACCESS = re.compile(
    rf'^({IPV4}) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{{3}}) \S+ "[^"]*" "([^"]*)"')
NGINX_ERROR = re.compile(rf'^(\d{{4}}/\d\d/\d\d \d\d:\d\d:\d\d) .*client: ({IPV4})')
SYSLOG_TS = re.compile(r'^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)')
PORTSENTRY = re.compile(rf'attackalert: (TCP|UDP) (\S+) ?\S* scan from host: ({IPV4})/\S+ to (?:TCP|UDP) port: (\d+)')
SSH_INVALID = re.compile(rf'sshd\[\d+\]: Invalid user (\S*) from ({IPV4}) port')
SSH_AUTHFAIL = re.compile(rf'sshd\[\d+\]: Connection closed by authenticating user (\S+) ({IPV4}) port \d+ \[preauth\]')
F2B_BAN = re.compile(rf'^(\d{{4}}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ .*\[([\w-]+)\] Ban ({IPV4})')


def syslog_ts(stamp, now=None):
    """Syslog-Zeitstempel haben kein Jahr - liegt das Ergebnis in der Zukunft,
    stammt die Zeile aus dem Vorjahr (Jahreswechsel)."""
    now = now or time.time()
    year = datetime.fromtimestamp(now).year
    ts = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S").timestamp()
    return ts if ts <= now + 86400 else ts - 365 * 86400


def event(ts, ip, typ, sev, src, port=None, detail="", jail=None):
    return {"ts": ts, "ip": ip, "type": typ, "sev": sev, "src": src,
            "port": port, "detail": detail[:160], "jail": jail}


def parse_nginx_access(line):
    m = NGINX_ACCESS.match(line)
    if not m:
        return None
    ip, stamp, method, path, status, agent = m.groups()
    if path.startswith(OWN_PATHS):
        return None  # eigene Seiten/Assets (z. B. /assets/vendor/) sind keine Probes
    if WEB_RCE.search(path):
        typ, sev = "SQLi/RCE", "crit"
    elif WEB_PROBE.search(path):
        typ, sev = "Web-Probe", "high"
    else:
        return None
    ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    return event(ts, ip, typ, sev, "nginx", 443, f"{method} {path} → {status} · {agent[:60]}")


def parse_nginx_error(line):
    m = NGINX_ERROR.match(line)
    if not m:
        return None
    stamp, ip = m.groups()
    ts = datetime.strptime(stamp, "%Y/%m/%d %H:%M:%S").timestamp()
    if "limiting requests" in line:
        return event(ts, ip, "Rate-Limit", "med", "nginx", 443, "Request-Limit überschritten")
    if "SSL_do_handshake" in line:
        reason = re.search(r'routines::([^)]+)\)', line)
        return event(ts, ip, "SSL-Scan", "low", "nginx", 443,
                     f"TLS-Handshake: {reason.group(1) if reason else 'fehlgeschlagen'}")
    return None


def parse_syslog(line, now=None):
    m = PORTSENTRY.search(line)
    ts = SYSLOG_TS.match(line)
    if not (m and ts):
        return None
    proto, kind, ip, port = m.groups()
    return event(syslog_ts(ts.group(1), now), ip, "Port-Scan", "med", "portsentry",
                 int(port), f"{proto} {kind} auf Port {port}")


def parse_auth(line, now=None):
    ts = SYSLOG_TS.match(line)
    m = SSH_INVALID.search(line) or SSH_AUTHFAIL.search(line)
    if not (m and ts):
        return None
    user, ip = m.groups()
    return event(syslog_ts(ts.group(1), now), ip, "SSH-Brute", "high", "sshd",
                 SSH_PORT, f"Login-Versuch als „{user or '(leer)'}“")


def parse_f2b(line):
    # "Restore Ban" beim fail2ban-Start und "Unban" sind keine neuen Angriffe.
    m = F2B_BAN.match(line)
    if not m or "Restore Ban" in line:
        return None
    stamp, jail, ip = m.groups()
    ts = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").timestamp()
    return event(ts, ip, "fail2ban-Ban", "med", "fail2ban", None, f"Gebannt durch Jail {jail}", jail)


PARSERS = {
    "nginx": parse_nginx_access,
    "nginx-error": parse_nginx_error,
    "auth": parse_auth,
    "syslog": parse_syslog,
    "f2b": parse_f2b,
}
