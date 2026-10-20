"""FTP-Honeypot auf Port 21: gibt sich als vsftpd aus, liest USER/PASS im Klartext mit und
lehnt jeden Login mit "530 Login incorrect." ab. Es gibt keine Dateien und keine Befehle.
"""
from honeypot import Honeypot, attempt

BANNER = b"220 (vsFTPd 3.0.3)\r\n"
MAX_COMMANDS = 20  # danach auflegen, manche Bots probieren sonst endlos in derselben Verbindung
MAX_LINE = 512


class FTPHoneypot(Honeypot):
    PORT = 21
    TYPE = "FTP-Probe"

    def handle(self, sock, ip, login):
        sock.sendall(BANNER)
        user = None
        with sock.makefile("rb") as lines:
            for _ in range(MAX_COMMANDS):
                line = lines.readline(MAX_LINE)
                if not line:
                    return
                cmd, _, arg = line.decode("utf-8", "replace").strip().partition(" ")
                cmd = cmd.upper()
                if cmd == "QUIT":
                    sock.sendall(b"221 Goodbye.\r\n")
                    return
                if cmd == "USER":
                    user = arg
                    sock.sendall(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    login(attempt(user, "Passwort", arg))
                    sock.sendall(b"530 Login incorrect.\r\n")
                else:
                    sock.sendall(b"530 Please login with USER and PASS.\r\n")
