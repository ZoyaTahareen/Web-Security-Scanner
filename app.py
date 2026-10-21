"""
app.py
Flask application entry point for the Automated Web Security Scanner.

Routes:
  GET  /              Dashboard / home page
  POST /scan          Run a security scan; returns JSON results
  GET  /report/json   Download JSON report for the last scan
  GET  /report/csv    Download CSV report for the last scan
  GET  /report/pdf    Download PDF report for the last scan
"""

import os

from flask import (
    Flask,
    jsonify,
    make_response,
    render_template,
    request,
    session,
)

from scanner import scan as run_scan
from scanner.report_generator import generate_csv, generate_json, generate_pdf

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Secret key for session signing.
# In production, set SECRET_KEY in the environment.
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

# Store one scan result per browser session (no database required).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request limit


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the main dashboard."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Accept a URL, run a full security scan, and return JSON results.

    Expected JSON body: { "url": "https://example.com" }
    Returns:            200 with scan result dict, or 4xx with error message.
    """
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please provide a URL to scan."}), 400

    try:
        result = run_scan(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001 – catch-all for unexpected errors
        app.logger.exception("Unexpected error during scan of %s", url)
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500

    # Persist result in the session (serialised by Flask's session cookie).
    # Store only the data the report endpoints need.
    session["last_scan"] = result
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# Report download routes
# ---------------------------------------------------------------------------

@app.route("/report/json")
def report_json():
    result = _get_last_scan()
    if result is None:
        return _no_scan_error()
    try:
        data = generate_json(result)
    except Exception as exc:
        app.logger.exception("JSON report generation failed")
        return jsonify({"error": "Report generation failed."}), 500
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = 'attachment; filename="security_report.json"'
    return resp


@app.route("/report/csv")
def report_csv():
    result = _get_last_scan()
    if result is None:
        return _no_scan_error()
    try:
        data = generate_csv(result)
    except Exception as exc:
        app.logger.exception("CSV report generation failed")
        return jsonify({"error": "Report generation failed."}), 500
    resp = make_response(data)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8-sig"
    resp.headers["Content-Disposition"] = 'attachment; filename="security_report.csv"'
    return resp


@app.route("/report/pdf")
def report_pdf():
    result = _get_last_scan()
    if result is None:
        return _no_scan_error()
    try:
        data = generate_pdf(result)
    except Exception as exc:
        app.logger.exception("PDF report generation failed")
        return jsonify({"error": "Report generation failed."}), 500
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="security_report.pdf"'
    return resp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_last_scan() -> dict | None:
    """Retrieve the last scan result from the session."""
    return session.get("last_scan")


def _no_scan_error():
    return (
        jsonify({"error": "No scan results found. Please run a scan before downloading a report."}),
        400,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Local development only — not used by Gunicorn in production.
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=port, debug=debug)
