// Gemeinsame Formatierung und die feste Farbzuordnung der Angriffsarten.
// Reihenfolge = validierte Kategorienpalette (dark), Farbe folgt der Art, nie dem Rang.
export const TYPES = [
  { key: "Port-Scan", label: "Port-Scan", color: "#3987e5" },
  { key: "Web-Probe", label: "Web-Probe", color: "#d95926" },
  { key: "SSH-Brute", label: "SSH-Brute-Force", color: "#199e70" },
  { key: "fail2ban-Ban", label: "fail2ban-Ban", color: "#c98500" },
  { key: "SQLi/RCE", label: "SQLi / RCE", color: "#d55181" },
  { key: "Rate-Limit", label: "Rate-Limit", color: "#008300" },
  { key: "SSL-Scan", label: "TLS-Scan", color: "#9085e9" },
  { key: "MySQL-Probe", label: "MySQL-Honeypot", color: "#a3a948" },
  { key: "SSH-Probe", label: "SSH-Honeypot", color: "#e66767" },
  { key: "FTP-Probe", label: "FTP-Honeypot", color: "#b5835a" },
  { key: "Telnet-Probe", label: "Telnet-Honeypot", color: "#8aa0b8" },
  { key: "Postgres-Probe", label: "Postgres-Honeypot", color: "#4fb3bf" },
];
const BY_KEY = Object.fromEntries(TYPES.map(t => [t.key, t]));
export const typeInfo = key => BY_KEY[key] || { key, label: key, color: "#6b7894" };

export const SEVERITY = { crit: "kritisch", high: "hoch", med: "mittel", low: "niedrig" };

const nf = new Intl.NumberFormat("de-DE");
export const num = n => (n == null ? "–" : nf.format(n));

export function flag(cc) {
  if (!cc || cc.length !== 2) return "🏳️";
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1f1a5 + c.charCodeAt(0)));
}

export const time = ts => new Date(ts * 1000).toLocaleTimeString("de-DE");
export const dateTime = ts => new Date(ts * 1000).toLocaleString("de-DE");

export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Bekannte Dienste hinter häufig gescannten Ports
const SERVICES = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP-Alt", 110: "POP3",
  111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 139: "SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP",
  443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE/VPN", 502: "Modbus", 587: "Submission", 993: "IMAPS",
  995: "POP3S", 1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
  5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 22022: "SSH (3lis)",
};
export const service = port => SERVICES[port] || "";
