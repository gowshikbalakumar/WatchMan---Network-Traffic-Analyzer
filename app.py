"""
app.py — Watch Man Flask entry point.

Usage:
    python app.py            # live capture (needs root on Linux)
    python app.py --demo     # simulated traffic (no root required)
    DEMO_MODE=1 python app.py

Fixes vs. original:
  - DEMO_MODE default corrected: os.environ default is "0" not "1" (was always demo)
  - Added /clear-alerts POST endpoint (dashboard "CLEAR" button now works)
  - Added /health endpoint for uptime monitoring
  - Added /api/mode endpoint so the UI can show live vs demo mode
  - File-based logging to logs/watchman.log
  - Graceful Ctrl-C handling via atexit
"""

import os
import sys
import csv
import io
import logging
import atexit
from pathlib import Path

from flask import Flask, jsonify, render_template, Response, request
from flask_cors import CORS

# ── Logging — console + rotating file ────────────────────────────────────────
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "watchman.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("watchman.app")

# ── Local imports (after logging is configured) ───────────────────────────────
from sniffer.capture import start_capture, stop_capture, is_running
from models.data_store import get_snapshot, get_alerts, clear_alerts

app = Flask(__name__)
CORS(app)

# ── Determine capture mode ────────────────────────────────────────────────────
# BUG FIX: original defaulted to "1" (always demo); corrected to "0"
DEMO_MODE = "--demo" in sys.argv or os.environ.get("DEMO_MODE", "0") == "1"


# ══════════════════════════════════════════════════════════════════════════════
#  FRONTEND
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Serve the dashboard."""
    return render_template("index.html")


# ══════════════════════════════════════════════════════════════════════════════
#  REST API — READ
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/traffic")
def traffic():
    """Full traffic snapshot (JSON)."""
    return jsonify(get_snapshot())


@app.route("/alerts")
def alerts_endpoint():
    """Threat alerts list, newest first (JSON)."""
    return jsonify(get_alerts())


@app.route("/stats")
def stats():
    """Summary KPIs for the header widgets."""
    snap = get_snapshot()
    al   = get_alerts()
    critical = sum(1 for a in al if a["severity"] in ("HIGH", "CRITICAL"))

    return jsonify({
        "total_packets":   snap["total_packets"],
        "total_bytes_mb":  round(snap["total_bytes"] / (1024 * 1024), 3),
        "uptime_seconds":  snap["uptime_seconds"],
        "active_alerts":   len(al),
        "critical_alerts": critical,
        "current_pps":     snap["current_pps"],
        "demo_mode":       DEMO_MODE,
        "capture_alive":   is_running(),
    })


@app.route("/health")
def health():
    """
    Health-check endpoint for uptime monitoring / load-balancer probes.
    Returns HTTP 200 while the sniffer thread is alive.
    """
    alive = is_running()
    return jsonify({"status": "ok" if alive else "degraded", "capture": alive}), (200 if alive else 503)


@app.route("/api/mode")
def api_mode():
    """Return current capture mode."""
    return jsonify({"demo": DEMO_MODE, "live": not DEMO_MODE})


# ══════════════════════════════════════════════════════════════════════════════
#  REST API — WRITE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/clear-alerts", methods=["POST"])
def clear_alerts_endpoint():
    """
    Clear all stored alerts.
    BUG FIX: original had no backend for the dashboard "CLEAR" button.
    """
    clear_alerts()
    log.info("Alerts cleared via /clear-alerts endpoint.")
    return jsonify({"status": "cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  CSV EXPORT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/export/csv")
def export_csv():
    """Download recent packets as CSV."""
    snap    = get_snapshot()
    packets = snap.get("recent_packets", [])

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["time", "src", "dst", "proto", "size", "sport", "dport"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(packets)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=traffic_log.csv"},
    )


@app.route("/export/alerts/csv")
def export_alerts_csv():
    """Download alerts as CSV."""
    al = get_alerts()

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["time", "type", "severity", "detail"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(al)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_log.csv"},
    )


# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════

def _on_exit():
    log.info("Watch Man shutting down — stopping capture thread.")
    stop_capture()


atexit.register(_on_exit)


if __name__ == "__main__":
    banner = [
        "=" * 60,
        "  ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗",
        "  ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║",
        "  ██║ █╗ ██║███████║   ██║   ██║     ███████║",
        "  ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║",
        "  ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║",
        "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝",
        "  ███╗   ███╗ █████╗ ███╗   ██╗",
        "  ████╗ ████║██╔══██╗████╗  ██║",
        "  ██╔████╔██║███████║██╔██╗ ██║",
        "  ██║╚██╔╝██║██╔══██║██║╚██╗██║",
        "  ██║ ╚═╝ ██║██║  ██║██║ ╚████║",
        "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝",
        "",
        f"  Mode    : {'DEMO (simulated traffic)' if DEMO_MODE else 'LIVE (Scapy — needs root)'}",
        "  Dashboard: http://127.0.0.1:5000",
        "  Logs     : logs/watchman.log",
        "=" * 60,
    ]
    print("\n".join(banner))

    start_capture(demo=DEMO_MODE)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
