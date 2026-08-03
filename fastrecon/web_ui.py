"""
FastRecon Web UI v3.1 — Flask-based web interface with full data management.
Target management, scan triggering, real-time progress, result browsing,
subdomain search & bulk delete, scan purging, and CSV/JSON export.
"""

import asyncio
import csv
import io
import json
import os
import time
import threading
import queue
from datetime import datetime

from flask import Flask, render_template, request, jsonify, Response, send_file
from fastrecon.engine import ReconEngine
from fastrecon.reporter import generate_html_report, generate_csv_report
from fastrecon.db import ScanDatabase
from fastrecon import __version__
from fastrecon.validation import is_safe_target


app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)

# Database instance for persistent storage
db = ScanDatabase()

# Store scan results and progress (in-memory for active scan)
scan_store = {
    "current_scan": None,
    "progress_queue": queue.Queue(),
    "results": {},  # in-memory cache for active scan results
}


def run_scan_async(target, mode, skip_cloud, skip_ports, skip_vulns, skip_endpoints, scan_id):
    """Run a scan in a background thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    progress_updates = scan_store["progress_queue"]

    def progress_callback(update):
        update["scanId"] = scan_id
        update["timestamp"] = datetime.utcnow().isoformat()
        progress_updates.put(json.dumps(update))

    try:
        progress_callback({
            "phase": "Initializing", "phaseNum": 0, "totalPhases": 10,
            "status": "running", "target": target,
        })

        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"scan_{scan_id}.json")

        engine = ReconEngine(
            target=target,
            output_file=output_file,
            mode=mode,
            skip_cloud=skip_cloud,
            skip_ports=skip_ports,
            skip_vulns=skip_vulns,
            skip_endpoints=skip_endpoints,
            report_format="both",
            progress_callback=progress_callback,
        )

        report = loop.run_until_complete(engine.run())

        # Store results in memory cache
        scan_store["results"][scan_id] = report

        progress_callback({
            "phase": "Complete", "phaseNum": 10, "totalPhases": 10,
            "status": "complete", "target": target,
            "riskLevel": report.get("riskLevel", "N/A"),
            "riskScore": report.get("riskScore", 0),
        })

    except Exception as e:
        progress_callback({
            "phase": "Error", "phaseNum": 0, "totalPhases": 10,
            "status": "error", "target": target,
            "error": str(e),
        })
    finally:
        scan_store["current_scan"] = None
        loop.close()


# ──────────────────────────────────────────────
#  Pages
# ──────────────────────────────────────────────

@app.route("/")
def index():
    """Main page — scan launcher & dashboard."""
    return render_template("index.html", version=__version__)


@app.route("/results/<scan_id>")
def results_page(scan_id):
    """Results page for a specific scan."""
    result = scan_store["results"].get(scan_id)
    if not result:
        # Try loading from database
        result = db.get_scan_report(scan_id)
    return render_template("results.html", scan_id=scan_id, result=result, version=__version__)


# ──────────────────────────────────────────────
#  Scan API
# ──────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    if scan_store["current_scan"]:
        return jsonify({"error": "A scan is already running", "scanId": scan_store["current_scan"]}), 409

    data = request.json or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Target domain is required"}), 400

    # Clean target (remove protocol, trailing slashes)
    target = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]

    # SSRF prevention: validate target is a safe public domain
    if not is_safe_target(target):
        return jsonify({"error": "Invalid or disallowed target"}), 400

    mode = data.get("mode", "normal")
    skip_cloud = data.get("skipCloud", False)
    skip_ports = data.get("skipPorts", False)
    skip_vulns = data.get("skipVulns", False)
    skip_endpoints = data.get("skipEndpoints", False)

    scan_id = f"{target.replace('.', '_')}_{int(time.time())}"
    scan_store["current_scan"] = scan_id

    # Clear progress queue
    while not scan_store["progress_queue"].empty():
        try:
            scan_store["progress_queue"].get_nowait()
        except queue.Empty:
            break

    thread = threading.Thread(
        target=run_scan_async,
        args=(target, mode, skip_cloud, skip_ports, skip_vulns, skip_endpoints, scan_id),
        daemon=True,
    )
    thread.start()

    return jsonify({"scanId": scan_id, "target": target, "mode": mode})


@app.route("/api/progress")
def scan_progress():
    """Server-Sent Events endpoint for real-time scan progress."""
    def generate():
        while True:
            try:
                msg = scan_store["progress_queue"].get(timeout=30)
                yield f"data: {msg}\n\n"

                data = json.loads(msg)
                if data.get("status") in ("complete", "error"):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'status': 'heartbeat'})}\n\n"

    return Response(generate(), mimetype="text/event-stream")


# ──────────────────────────────────────────────
#  Results API
# ──────────────────────────────────────────────

@app.route("/api/results/<scan_id>")
def get_results(scan_id):
    """Get scan results as JSON."""
    result = scan_store["results"].get(scan_id)
    if not result:
        result = db.get_scan_report(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)


@app.route("/api/report/<scan_id>")
def get_html_report(scan_id):
    """Get scan results as a downloadable HTML report."""
    result = scan_store["results"].get(scan_id)
    if not result:
        result = db.get_scan_report(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    html = generate_html_report(result)
    return Response(html, mimetype="text/html")


# ──────────────────────────────────────────────
#  History API (backed by SQLite)
# ──────────────────────────────────────────────

@app.route("/api/history")
def get_history():
    """Get scan history from database."""
    target = request.args.get("target")
    limit = int(request.args.get("limit", 50))
    scans = db.get_scans(target=target, limit=limit)
    # Convert to frontend format
    history = []
    for s in scans:
        history.append({
            "id": s["id"],
            "target": s["target"],
            "mode": s["mode"],
            "timestamp": s["started_at"],
            "riskLevel": s["risk_level"],
            "riskScore": s["risk_score"],
            "totalAlerts": s["total_alerts"],
            "newSubdomains": s.get("new_subdomains", 0),
            "duration": s.get("duration", ""),
        })
    return jsonify(history)


@app.route("/api/stats")
def get_stats():
    """Get aggregate scan statistics."""
    stats = db.get_scan_stats()
    return jsonify(stats)


# ──────────────────────────────────────────────
#  Target Management API
# ──────────────────────────────────────────────

@app.route("/api/targets", methods=["GET"])
def list_targets():
    """List all saved targets."""
    targets = db.get_targets()
    return jsonify(targets)


@app.route("/api/targets", methods=["POST"])
def add_target():
    """Save a new target domain."""
    data = request.json or {}
    domain = data.get("domain", "").strip()
    notes = data.get("notes", "")

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    domain = domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    db.save_target(domain, notes=notes)
    return jsonify({"status": "ok", "domain": domain})


@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
def delete_target(target_id):
    """Delete a target and all its subdomains."""
    deleted = db.delete_target(target_id)
    if deleted:
        return jsonify({"status": "ok"})
    return jsonify({"error": "Target not found"}), 404


# ──────────────────────────────────────────────
#  Subdomain Data Management API
# ──────────────────────────────────────────────

@app.route("/api/subdomains/<target>")
def list_subdomains(target):
    """List stored subdomains for a target with optional search."""
    search = request.args.get("search", "")
    limit = int(request.args.get("limit", 500))
    offset = int(request.args.get("offset", 0))

    subdomains = db.get_subdomains(target, search=search or None, limit=limit, offset=offset)
    total = db.count_subdomains(target)
    return jsonify({"subdomains": subdomains, "total": total})


@app.route("/api/subdomains", methods=["DELETE"])
def bulk_delete_subdomains():
    """Bulk delete subdomains by IDs."""
    data = request.json or {}
    ids = data.get("ids", [])

    if not ids:
        return jsonify({"error": "No IDs provided"}), 400

    db.bulk_delete_subdomains(ids)
    return jsonify({"status": "ok", "deleted": len(ids)})


# ──────────────────────────────────────────────
#  Scan Management API
# ──────────────────────────────────────────────

@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """Delete a scan and its data."""
    db.delete_scan(scan_id)
    # Also remove from in-memory cache
    scan_store["results"].pop(scan_id, None)
    return jsonify({"status": "ok"})


@app.route("/api/scans/purge", methods=["POST"])
def purge_old_scans():
    """Purge scans older than N days."""
    data = request.json or {}
    days = int(data.get("days", 30))
    count = db.purge_old_scans(days=days)
    return jsonify({"status": "ok", "purged": count})


# ──────────────────────────────────────────────
#  Export API
# ──────────────────────────────────────────────

@app.route("/api/export/<scan_id>/csv")
def export_csv(scan_id):
    """Export scan results as CSV (alerts, subdomains, endpoints)."""
    result = scan_store["results"].get(scan_id)
    if not result:
        result = db.get_scan_report(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404

    csv_data = generate_csv_report(result)

    # Combine all CSVs into a single response with headers
    combined = io.StringIO()
    for filename, content in csv_data.items():
        combined.write(f"# === {filename} ===\n")
        combined.write(content)
        combined.write("\n\n")

    response = Response(combined.getvalue(), mimetype="text/csv")
    target = result.get("target", "unknown").replace(".", "_")
    response.headers["Content-Disposition"] = f"attachment; filename={target}_export.csv"
    return response


@app.route("/api/export/<scan_id>/json")
def export_json(scan_id):
    """Export scan results as timestamped JSON download."""
    result = scan_store["results"].get(scan_id)
    if not result:
        result = db.get_scan_report(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404

    response = Response(
        json.dumps(result, indent=4, ensure_ascii=False),
        mimetype="application/json",
    )
    target = result.get("target", "unknown").replace(".", "_")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    response.headers["Content-Disposition"] = f"attachment; filename={target}_{ts}.json"
    return response


# ──────────────────────────────────────────────
#  Startup
# ──────────────────────────────────────────────

def start_web_ui(host="0.0.0.0", port=5000, debug=False):
    """Start the Flask web UI."""
    print(f"\n{'='*60}")
    print(f"  ⚡ FastRecon Web UI v{__version__}")
    print(f"  🌐 Open http://localhost:{port} in your browser")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")
    app.run(host=host, port=port, debug=debug, threaded=True)
