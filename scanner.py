import socket
import subprocess
import concurrent.futures
from datetime import datetime
import platform

# ─── Ports à scanner et leur signification ───────────────────────────────────
PORTS_TO_SCAN = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    443:  "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

DANGEROUS_PORTS = {
    21:   "FTP transmet les données en clair",
    23:   "Telnet non chiffré — très dangereux",
    3306: "Base de données MySQL exposée",
    5432: "Base de données PostgreSQL exposée",
    6379: "Redis sans authentification par défaut",
    27017:"MongoDB souvent sans auth par défaut",
}

def ping_host(ip: str) -> bool:
    """Vérifie si un hôte répond au ping — compatible Windows et Linux."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def scan_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Teste si un port TCP est ouvert."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_hostname(ip: str) -> str:
    """Résout le nom d'hôte depuis l'IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Inconnu"

def calculate_risk(open_ports: list) -> str:
    dangerous = [p for p in open_ports if p["dangerous"]]
    if len(dangerous) >= 2:
        return "CRITIQUE"
    elif len(dangerous) == 1:
        return "ELEVE"
    elif (any(p["port"] == 80 for p in open_ports) and
          not any(p["port"] == 443 for p in open_ports)):
        return "MOYEN"
    elif open_ports:
        return "FAIBLE"
    return "OK"

def scan_host(ip: str) -> dict:
    """Scan complet d'un hôte."""
    if not ping_host(ip):
        return None

    hostname = get_hostname(ip)
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in PORTS_TO_SCAN}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append({
                    "port": port,
                    "service": PORTS_TO_SCAN[port],
                    "dangerous": port in DANGEROUS_PORTS,
                    "danger_reason": DANGEROUS_PORTS.get(port, "")
                })

    return {
        "ip": ip,
        "hostname": hostname,
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
        "scan_time": datetime.now().isoformat(),
        "risk_level": calculate_risk(open_ports)
    }

def generate_ip_range(network: str) -> list:
    """Génère la liste d'IPs depuis une notation CIDR simple."""
    base = network.replace(".0/24", "").replace("/24", "")
    parts = base.split(".")
    base = ".".join(parts[:3])
    return [f"{base}.{i}" for i in range(1, 255)]

def scan_network(network: str) -> list:
    """Scan complet d'un réseau."""
    print(f"\n Démarrage du scan : {network}")
    ip_range = generate_ip_range(network)
    results = []
    for ip in ip_range:
        result = scan_host(ip)
        if result:
            results.append(result)
            print(f"  OK {ip} ({result['hostname']}) — {len(result['open_ports'])} ports — Risque: {result['risk_level']}")
    print(f"\n Scan termine : {len(results)} hotes actifs")
    return results
