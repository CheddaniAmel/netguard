from datetime import datetime
from database import get_scan_details

def generate_report(scan_id: int) -> str:
    """Génère un rapport de sécurité structuré style ITIL/DORA."""
    scan = get_scan_details(scan_id)
    now = datetime.now().strftime("%d/%m/%Y %H:%M")

    # Compter les niveaux de risque
    risks = {"CRITIQUE": [], "ELEVE": [], "MOYEN": [], "FAIBLE": [], "OK": []}
    for host in scan["hosts"]:
        risks[host["risk_level"]].append(host)

    lines = []
    lines.append("=" * 60)
    lines.append("       RAPPORT D'AUDIT SÉCURITÉ RÉSEAU — NETGUARD")
    lines.append("=" * 60)
    lines.append(f"  Réseau analysé  : {scan['network']}")
    lines.append(f"  Date du scan    : {scan['scan_date'][:19]}")
    lines.append(f"  Date du rapport : {now}")
    lines.append(f"  Référence       : NETGUARD-{scan_id:04d}")
    lines.append("=" * 60)

    lines.append("\n── RÉSUMÉ EXÉCUTIF ──────────────────────────────────────")
    lines.append(f"  Hôtes découverts  : {scan['total_hosts']}")
    lines.append(f"  Hôtes à risque    : {scan['total_risks']}")
    lines.append(f"  Hôtes CRITIQUES   : {len(risks['CRITIQUE'])}")
    lines.append(f"  Hôtes ÉLEVÉS      : {len(risks['ELEVE'])}")

    # Score de conformité
    if scan['total_hosts'] > 0:
        score = int((1 - scan['total_risks'] / scan['total_hosts']) * 100)
    else:
        score = 100
    lines.append(f"\n  ➤ SCORE DE CONFORMITÉ : {score}%")

    if score >= 90:
        lines.append("  ➤ STATUT : ✅ CONFORME")
    elif score >= 70:
        lines.append("  ➤ STATUT : ⚠️  ATTENTION REQUISE")
    else:
        lines.append("  ➤ STATUT : 🔴 NON CONFORME — ACTION IMMÉDIATE")

    # Détail des hôtes critiques
    if risks["CRITIQUE"] or risks["ELEVE"]:
        lines.append("\n── HÔTES À RISQUE ───────────────────────────────────────")
        for level in ["CRITIQUE", "ELEVE"]:
            for host in risks[level]:
                lines.append(f"\n  [{level}] {host['ip']} ({host['hostname']})")
                dangerous_ports = [p for p in host["ports"] if p["dangerous"]]
                for port in dangerous_ports:
                    lines.append(f"    ⚠ Port {port['port']} ({port['service']}) : {port['danger_reason']}")

    # Recommandations
    lines.append("\n── RECOMMANDATIONS ──────────────────────────────────────")
    lines.append("  1. Fermer immédiatement les ports dangereux exposés")
    lines.append("  2. Remplacer Telnet/FTP par SSH/SFTP")
    lines.append("  3. Restreindre l'accès aux bases de données au réseau interne")
    lines.append("  4. Activer HTTPS sur tous les services web (port 443)")
    lines.append("  5. Planifier un re-scan dans 30 jours (conforme ITIL)")

    lines.append("\n── CONFORMITÉ RÉGLEMENTAIRE ─────────────────────────────")
    lines.append("  ☐ DORA Art.24 — Tests de résilience effectués")
    lines.append("  ☐ ISO 27001  — Inventaire des actifs mis à jour")
    lines.append("  ☐ ITIL       — Incident enregistré si risque CRITIQUE")

    lines.append("\n" + "=" * 60)
    lines.append("  Rapport généré automatiquement par NETGUARD v1.0")
    lines.append("=" * 60)

    return "\n".join(lines)

def save_report(scan_id: int, filepath: str = None):
    """Sauvegarde le rapport dans un fichier texte."""
    report = generate_report(scan_id)
    if not filepath:
        filepath = f"rapport_scan_{scan_id}.txt"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"📄 Rapport sauvegardé : {filepath}")
    return filepath
