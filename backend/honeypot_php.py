"""PHP-Honeypot hinter nginx: jede .php-Anfrage außer den echten Skripten (deploy/nginx-3lis-php-honeypot.conf)
landet hier. Gibt sich als ungepatchtes PHP 8.2 aus (Köder für PHP2Shell, CVE-2026-109618/-109619), liest
WordPress-Logins und Payloads (Query, Body) mit und führt nie etwas aus.

Reine Scans ohne Parameter stehen schon als Web-Probe im nginx-Log und werden hier nicht doppelt gezählt.
Lauscht nur auf 127.0.0.1, deshalb ist X-Real-IP von nginx vertrauenswürdig.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus, urlsplit

from honeypot import TIMEOUT, Honeypot, attempt

LISTEN_PORT = 8098
VERSION = "8.2.34"  # letzte Version vor dem Fix, damit Scanner uns für verwundbar halten
MAX_BODY = 64 * 1024
PHPINFO = {"phpinfo.php", "info.php", "php.php", "test.php", "i.php"}
LOGIN_PAGE = """<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><title>Anmelden &lsaquo; WordPress</title></head>
<body class="login">{error}<form name="loginform" id="loginform" action="wp-login.php" method="post">
<p><label for="user_login">Benutzername oder E-Mail-Adresse</label><input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Passwort</label><input type="password" name="pwd" id="user_pass"></p>
<p><input type="submit" name="wp-submit" value="Anmelden"></p></form></body></html>"""
LOGIN_ERROR = '<div id="login_error"><strong>Fehler:</strong> Das Passwort ist nicht korrekt.</div>'
PHPINFO_PAGE = f"""<!DOCTYPE html><html><head><title>PHP {VERSION} - phpinfo()</title></head><body>
<h1 class="p">PHP Version {VERSION}</h1><table>
<tr><td class="e">System</td><td class="v">Linux web01 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 x86_64</td></tr>
<tr><td class="e">Server API</td><td class="v">FPM/FastCGI</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/8.2/fpm/php.ini</td></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td></tr>
<tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">memory_limit</td><td class="v">128M</td></tr>
</table></body></html>"""


class PHPHoneypot(Honeypot):
    PORT = 443  # im Event: so erreicht der Angreifer den Honeypot, nginx reicht intern an LISTEN_PORT weiter
    TYPE = "PHP-Probe"

    def __init__(self, store, port=None, host="127.0.0.1"):
        super().__init__(store, LISTEN_PORT if port is None else port, host)

    def serve(self, ready=None):
        srv = ThreadingHTTPServer((self.host, self.port), type("Handler", (Handler,), {"pot": self}))
        srv.daemon_threads = True
        self.port = srv.server_address[1]
        if ready:
            ready.set()
        srv.serve_forever()


class Handler(BaseHTTPRequestHandler):
    pot = None
    timeout = TIMEOUT
    server_version = "nginx"  # nginx ersetzt den Header ohnehin, X-Powered-By reicht es durch
    sys_version = ""

    def log_message(self, *args):
        """Kein stderr-Log: alles Relevante steht als Event in der DB."""

    def do_GET(self):
        ip = self.headers.get("X-Real-IP") or self.client_address[0]
        url = urlsplit(self.path)
        try:
            length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else ""
        page = url.path.rsplit("/", 1)[-1].lower()
        if page == "wp-login.php" and self.command == "POST":
            form = parse_qs(body)
            self.pot.record(ip, "high", attempt(form.get("log", [""])[0], "Passwort", form.get("pwd", [""])[0]))
            return self.reply(LOGIN_PAGE.format(error=LOGIN_ERROR))
        payload = " ".join(p for p in (unquote_plus(url.query), unquote_plus(body)) if p)
        if payload:
            self.pot.command(ip, f"{self.command} {url.path} {payload}")
        if page in PHPINFO:
            return self.reply(PHPINFO_PAGE)
        self.reply(LOGIN_PAGE.format(error="") if page == "wp-login.php" else "")

    do_POST = do_PUT = do_HEAD = do_GET

    def reply(self, html):
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("X-Powered-By", f"PHP/{VERSION}")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
