"""Einstieg der Honeypots als eigener Dienst (attack-honeypots.service): läuft unprivilegiert,
darf nur die Ports binden und in die Event-Datenbank schreiben. So gibt ein Fehler im Protokoll-Code
höchstens diesen Benutzer preis, nicht root (Logs und fail2ban bleiben im Hauptprozess server.py).
"""
import os
import threading

from honeypot_ftp import FTPHoneypot
from honeypot_mysql import MySQLHoneypot
from honeypot_php import PHPHoneypot
from honeypot_postgres import PostgresHoneypot
from honeypot_ssh import SSHHoneypot
from honeypot_telnet import TelnetHoneypot
from store import Store

DB_PATH = os.environ.get("ATTACK_DB", "/var/lib/attack-monitor/events.db")

POTS = [MySQLHoneypot, PostgresHoneypot, SSHHoneypot, FTPHoneypot, TelnetHoneypot, PHPHoneypot]


def start(store):
    threads = [threading.Thread(target=pot(store).serve, daemon=True) for pot in POTS]
    for t in threads:
        t.start()
    print("Honeypots gestartet: " + ", ".join(p.TYPE for p in POTS), flush=True)
    return threads


if __name__ == "__main__":
    for t in start(Store(DB_PATH)):
        t.join()
