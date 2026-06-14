"""
app.py - Flask application entry point and route definitions
Web Vulnerability Scanner
"""

import logging
import json
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from urllib.parse import urlparse
from scanner import run_scan

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "change-this-in-production-please"  # Replace with os.urandom(32) in prod

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# In-memory scan history (resets on restart; use a DB for persistence)
scan_history = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate that the submitted URL is well-formed and uses http/https.
    Returns (is_valid, error_message).
    """
    if not url:
        return False, "URL cannot be empty."

    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url  # auto-prefix for convenience

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL could not be parsed."

    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https URLs are supported."

    # Basic hostname check
    hostname = parsed.hostname or ""
    if not hostname or "." not in hostname:
        return False, "Please enter a valid domain name."

    # Block private/localhost targets
    private_patterns = [
        r"^localhost$", r"^127\.", r"^10\.", r"^192\.168\.",
        r"^172\.(1[6-9]|2\d|3[01])\.", r"^::1$"
    ]
    for pattern in private_patterns:
        if re.match(pattern, hostname):
            return False, "Scanning private/local addresses is not permitted."

    return True, url  # Return normalized URL


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the main scanner UI."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    POST /api/scan
    Body: { "url": "https://example.com" }
    Returns JSON scan results.
    """
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()

    logger.info(f"Scan requested for: {raw_url!r}")

    # Validate
    is_valid, result = validate_url(raw_url)
    if not is_valid:
        return jsonify({"success": False, "error": result}), 400

    url = result  # normalized URL

    # Run scan
    try:
        scan_result = run_scan(url)
    except Exception as e:
        logger.exception(f"Unhandled error scanning {url}")
        return jsonify({"success": False, "error": "An internal error occurred. Please try again."}), 500

    if not scan_result.get("success"):
        return jsonify(scan_result), 502

    # Store in history (keep last 20)
    history_entry = {
        "id": len(scan_history) + 1,
        "url": url,
        "timestamp": scan_result["timestamp"],
        "risk_label": scan_result["risk_label"],
        "risk_score": scan_result["risk_score"],
        "total_vulnerabilities": scan_result["total_vulnerabilities"],
    }
    scan_history.append(history_entry)
    if len(scan_history) > 20:
        scan_history.pop(0)

    return jsonify(scan_result), 200


@app.route("/api/history", methods=["GET"])
def api_history():
    """GET /api/history — Return recent scan history."""
    return jsonify({"history": list(reversed(scan_history))}), 200


@app.route("/api/export", methods=["POST"])
def api_export():
    """
    POST /api/export
    Body: scan result JSON
    Returns the same JSON as a downloadable file.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400

    from flask import Response
    export_json = json.dumps(data, indent=2)
    return Response(
        export_json,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=scan_report.json"},
    )


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Suppress urllib3 insecure request warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    app.run(debug=True, host="0.0.0.0", port=5000)
