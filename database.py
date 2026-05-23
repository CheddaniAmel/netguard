import sqlite3
import json
from datetime import datetime

DB_PATH = "netguard.db"

def init_db():
    """Crée les tables si elles n'existent pas."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table des scans (chaque lancement = 1 scan)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            network     TEXT NOT NULL,
            scan_date   TEXT NOT NULL,
            total_hosts INTEGER DEFAULT 0,
            total_risks INTEGER DEFAULT 0
        )
    """)

    # Table des hôtes découverts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            ip          TEXT NOT NULL,
            hostname    TEXT,
            risk_level  TEXT,
            scan_time   TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # Table des ports ouverts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id       INTEGER NOT NULL,
            port          INTEGER NOT NULL,
            service       TEXT,
            dangerous     INTEGER DEFAULT 0,
            danger_reason TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Base de données initialisée")

def save_scan(network: str, hosts: list) -> int:
    """Sauvegarde un scan complet en base de données."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Compter les hôtes à risque
    risks = sum(1 for h in hosts if h["risk_level"] in ["CRITIQUE", "ELEVE"])

    # Créer l'entrée du scan
    cursor.execute("""
        INSERT INTO scans (network, scan_date, total_hosts, total_risks)
        VALUES (?, ?, ?, ?)
    """, (network, datetime.now().isoformat(), len(hosts), risks))

    scan_id = cursor.lastrowid

    # Sauvegarder chaque hôte
    for host in hosts:
        cursor.execute("""
            INSERT INTO hosts (scan_id, ip, hostname, risk_level, scan_time)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, host["ip"], host["hostname"],
              host["risk_level"], host["scan_time"]))

        host_id = cursor.lastrowid

        # Sauvegarder les ports de cet hôte
        for port_info in host["open_ports"]:
            cursor.execute("""
                INSERT INTO ports (host_id, port, service, dangerous, danger_reason)
                VALUES (?, ?, ?, ?, ?)
            """, (host_id, port_info["port"], port_info["service"],
                  1 if port_info["dangerous"] else 0,
                  port_info["danger_reason"]))

    conn.commit()
    conn.close()
    print(f"💾 Scan #{scan_id} sauvegardé — {len(hosts)} hôtes enregistrés")
    return scan_id

def get_all_scans() -> list:
    """Récupère tous les scans effectués."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scan_date DESC")
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return scans

def get_scan_details(scan_id: int) -> dict:
    """Récupère le détail complet d'un scan avec ses hôtes et ports."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Infos du scan
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = dict(cursor.fetchone())

    # Hôtes du scan
    cursor.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,))
    hosts = []
    for host_row in cursor.fetchall():
        host = dict(host_row)
        # Ports de cet hôte
        cursor.execute("SELECT * FROM ports WHERE host_id = ?", (host["id"],))
        host["ports"] = [dict(p) for p in cursor.fetchall()]
        hosts.append(host)

    scan["hosts"] = hosts
    conn.close()
    return scan

def get_stats() -> dict:
    """Statistiques globales pour le dashboard."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM hosts")
    total_hosts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ports WHERE dangerous = 1")
    total_dangers = cursor.fetchone()[0]

    cursor.execute("""
        SELECT risk_level, COUNT(*) as count
        FROM hosts GROUP BY risk_level
    """)
    risks = {row[0]: row[1] for row in cursor.fetchall()}

    conn.close()
    return {
        "total_scans": total_scans,
        "total_hosts": total_hosts,
        "total_dangers": total_dangers,
        "risks": risks
    }
