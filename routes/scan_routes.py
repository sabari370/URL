"""
PhishGuard AI - URL Scanning & API Routes
Provides user interface for URL input, QR code upload, and public REST API endpoints.
"""
import os
import tempfile
import logging
from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from ml.predict import is_model_available
from services.qr_service import decode_qr_from_image
from services.url_analyzer import analyze_url
from utils.validators import allowed_file

scan_bp = Blueprint("scan", __name__)
logger = logging.getLogger("phishguard.scan")


def _get_db():
    return current_app.db


# =============================================================================
# Web Interface Endpoints
# =============================================================================

@scan_bp.route("/scan", methods=["GET", "POST"])
def scan():
    """Renders URL submission form and processes analysis."""
    if request.method == "POST":
        target_url = request.form.get("url", "").strip()

        if not target_url:
            flash("Please enter a valid URL to analyze.", "warning")
            return render_template("scan.html")

        thresholds = current_app.config.get("RISK_THRESHOLDS", {"low": 30, "suspicious": 60})
        analysis = analyze_url(target_url, thresholds=thresholds)

        if not analysis.get("success", False):
            flash(analysis.get("error", "URL analysis failed."), "danger")
            return render_template("scan.html", entered_url=target_url)

        # Save to database if user is logged in
        user_id = session.get("user_id")
        db = _get_db()
        if user_id and db and db.is_connected():
            scan_id = db.save_scan(
                user_id=user_id,
                url=analysis["url"],
                classification=analysis["classification"],
                risk_score=analysis["risk_score"],
                probability=analysis["probability"],
                features=analysis["features"]
            )
            analysis["scan_id"] = scan_id

        # Cache last scan in session for result page reload
        session["last_result"] = analysis
        return render_template("result.html", result=analysis)

    return render_template("scan.html")


@scan_bp.route("/result")
def result():
    """Renders the most recent scan result or redirects to scanner."""
    last_result = session.get("last_result")
    if not last_result:
        flash("No active scan result found. Please submit a URL.", "info")
        return redirect(url_for("scan.scan"))
    return render_template("result.html", result=last_result)


@scan_bp.route("/qr-scan", methods=["GET", "POST"])
def qr_scan():
    """Handles QR code image upload and decoding."""
    if request.method == "POST":
        if "qr_image" not in request.files:
            flash("No file part provided in the request.", "danger")
            return render_template("qr_scanner.html")

        file = request.files["qr_image"]
        if file.filename == "":
            flash("Please select an image file to upload.", "warning")
            return render_template("qr_scanner.html")

        allowed_exts = current_app.config.get("ALLOWED_EXTENSIONS", {"png", "jpg", "jpeg", "gif", "bmp", "webp"})
        if not allowed_file(file.filename, allowed_exts):
            flash("Invalid file format. Supported formats: PNG, JPG, JPEG, GIF, BMP, WEBP.", "danger")
            return render_template("qr_scanner.html")

        # Save temporarily for processing
        filename = secure_filename(file.filename)
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"phishguard_qr_{filename}")

        try:
            file.save(temp_path)
            qr_res = decode_qr_from_image(temp_path)
        finally:
            # Secure cleanup
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

        if not qr_res.get("success", False):
            flash(qr_res.get("error", "Failed to decode QR code."), "danger")
            return render_template("qr_scanner.html")

        decoded_data = qr_res.get("decoded_data", "")
        is_url = qr_res.get("is_url", False)

        if not is_url:
            flash(f"Decoded QR content is text, not a web URL: '{decoded_data}'", "info")
            return render_template("qr_scanner.html", non_url_content=decoded_data)

        # Run URL through standard detection pipeline
        thresholds = current_app.config.get("RISK_THRESHOLDS", {"low": 30, "suspicious": 60})
        analysis = analyze_url(decoded_data, thresholds=thresholds)

        if not analysis.get("success", False):
            flash(f"Extracted URL ({decoded_data}) could not be analyzed: {analysis.get('error')}", "danger")
            return render_template("qr_scanner.html")

        # Record scan if authenticated
        user_id = session.get("user_id")
        db = _get_db()
        if user_id and db and db.is_connected():
            scan_id = db.save_scan(
                user_id=user_id,
                url=analysis["url"],
                classification=analysis["classification"],
                risk_score=analysis["risk_score"],
                probability=analysis["probability"],
                features=analysis["features"]
            )
            analysis["scan_id"] = scan_id

        analysis["qr_source"] = True
        session["last_result"] = analysis
        return render_template("result.html", result=analysis)

    return render_template("qr_scanner.html")


# =============================================================================
# REST API Endpoints
# =============================================================================

@scan_bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Public REST API endpoint for URL analysis.
    Request body (JSON): {"url": "https://example.com"}
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Request content-type must be application/json."
        }), 400

    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({
            "success": False,
            "error": "Missing required field 'url'."
        }), 400

    thresholds = current_app.config.get("RISK_THRESHOLDS", {"low": 30, "suspicious": 60})
    result_data = analyze_url(target_url, thresholds=thresholds)

    if not result_data.get("success", False):
        return jsonify(result_data), 400

    return jsonify(result_data), 200


@scan_bp.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint reporting database and model status."""
    db = _get_db()
    db_status = "connected" if (db and db.is_connected()) else "disconnected"
    model_status = "loaded" if is_model_available() else "not_trained"

    overall_status = "healthy" if (db_status == "connected" and model_status == "loaded") else "degraded"

    return jsonify({
        "status": overall_status,
        "database": db_status,
        "model": model_status,
        "service": "PhishGuard AI Phishing Detection API"
    }), 200


@scan_bp.route("/api/history", methods=["GET"])
def api_history():
    """Returns recent scans for the authenticated user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({
            "success": False,
            "error": "Unauthorized. Authentication session required."
        }), 401

    db = _get_db()
    if not db or not db.is_connected():
        return jsonify({
            "success": False,
            "error": "Database service is currently unavailable."
        }), 503

    scans = db.get_user_scans(user_id=user_id, limit=20)
    return jsonify({
        "success": True,
        "scans": scans
    }), 200
