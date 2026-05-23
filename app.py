from flask import Flask, render_template, request, redirect, url_for, jsonify
from database import init_db, save_scan, get_all_scans, get_scan_details, get_stats
from scanner import scan_network
from report import generate_report
import threading

app = Flask(__name__)
scan_status = {"running": False, "message": ""}

@app.route("/")
def index():
    stats = get_stats()
    scans = get_all_scans()
    return render_template("index.html", stats=stats, scans=scans)

@app.route("/scan", methods=["POST"])
def launch_scan():
    network = request.form.get("network", "192.168.1.0/24")

    def run_scan():
        scan_status["running"] = True
        scan_status["message"] = f"Scan de {network} en cours..."
        hosts = scan_network(network)
        if hosts:
            save_scan(network, hosts)
        scan_status["running"] = False
        scan_status["message"] = f"Scan terminé — {len(hosts)} hôtes trouvés"

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    return redirect(url_for("index"))

@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan = get_scan_details(scan_id)
    return render_template("detail.html", scan=scan)

@app.route("/report/<int:scan_id>")
def report(scan_id):
    content = generate_report(scan_id)
    return f"<pre style='font-family:monospace;padding:20px;background:#111;color:#0f0'>{content}</pre>"

@app.route("/status")
def status():
    return jsonify(scan_status)

if __name__ == "__main__":
    init_db()
    print("\n🚀 NETGUARD démarré → http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
