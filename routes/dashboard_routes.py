"""
PhishGuard AI - Dashboard Routes
Handles user dashboard, scan history, and profile pages.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId
from bson.errors import InvalidId
from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------
dashboard_bp = Blueprint("dashboard", __name__)

logger = logging.getLogger("phishguard.dashboard")

# Number of scan history items per page
HISTORY_PAGE_SIZE = 20


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_db():
    """Return the DatabaseService attached to the current app."""
    return current_app.db  # type: ignore[attr-defined]


def _build_chart_data(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build chart-ready data from a list of scan documents.

    Args:
        scans: List of scan dicts (each must have ``scanned_at`` and
               ``classification`` keys).

    Returns:
        A dict with:
        - ``daily_counts``  : labels + datasets for a 7-day bar/line chart.
        - ``class_dist``    : labels + values for a doughnut/pie chart.
    """
    today = datetime.utcnow().date()
    day_labels: List[str] = []
    # Pre-fill 7-day buckets keyed by date string "Mon DD"
    daily: Dict[str, Dict[str, int]] = {}
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        label = day.strftime("%b %d")
        day_labels.append(label)
        daily[label] = {"Likely Safe": 0, "Suspicious": 0, "Likely Phishing": 0}

    class_totals: Dict[str, int] = {
        "Likely Safe": 0,
        "Suspicious": 0,
        "Likely Phishing": 0,
    }

    for scan in scans:
        ts: Optional[datetime] = scan.get("scanned_at")
        classification: str = scan.get("classification", "")
        if not isinstance(ts, datetime):
            continue
        label = ts.date().strftime("%b %d")
        if label in daily and classification in daily[label]:
            daily[label][classification] += 1
        if classification in class_totals:
            class_totals[classification] += 1

    safe_data = [daily[d]["Likely Safe"] for d in day_labels]
    suspicious_data = [daily[d]["Suspicious"] for d in day_labels]
    phishing_data = [daily[d]["Likely Phishing"] for d in day_labels]

    return {
        "daily_counts": {
            "labels": day_labels,
            "datasets": {
                "safe": safe_data,
                "suspicious": suspicious_data,
                "phishing": phishing_data,
            },
        },
        "class_dist": {
            "labels": list(class_totals.keys()),
            "values": list(class_totals.values()),
        },
    }


def _parse_object_id(scan_id: str) -> ObjectId:
    """
    Parse a hex string into a :class:`bson.ObjectId`.

    Raises:
        werkzeug.exceptions.NotFound: If the string is not a valid ObjectId.
    """
    try:
        return ObjectId(scan_id)
    except (InvalidId, TypeError):
        abort(404)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@dashboard_bp.route("/dashboard")
def dashboard():
    """
    User dashboard — requires an active login session.

    Fetches:
    - Aggregate scan statistics for the current user.
    - Recent scans (up to 10) for the activity feed.
    - Chart data covering the last 7 days.

    Renders:
        templates/dashboard.html
    """
    user_id: Optional[str] = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login", next=request.path))

    db = _get_db()

    try:
        # Aggregate stats (total, safe, suspicious, phishing)
        stats: Dict[str, int] = db.get_user_scan_stats(user_id)

        # Recent 10 scans for the activity timeline
        recent_scans: List[Dict[str, Any]] = db.get_user_scans(
            user_id=user_id,
            page=1,
            page_size=10,
            search=None,
            filter_classification=None,
        )

        # Build chart payload (uses all of the last 7 days' data from DB)
        week_scans: List[Dict[str, Any]] = db.get_user_scans_since(
            user_id=user_id,
            since=datetime.utcnow() - timedelta(days=7),
        )
        chart_data: Dict[str, Any] = _build_chart_data(week_scans)

    except Exception:
        logger.exception("Error loading dashboard for user_id=%s", user_id)
        stats = {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "phishing": 0,
        }
        recent_scans = []
        chart_data = _build_chart_data([])

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans,
        chart_data=chart_data,
    )


@dashboard_bp.route("/history")
def history():
    """
    Paginated scan history for the logged-in user.

    Query parameters:
        page (int):   Page number, 1-indexed. Defaults to 1.
        search (str): Free-text search over the URL field.
        filter (str): Restrict results to a specific classification label,
                      e.g. ``"Likely Phishing"``, ``"Suspicious"``,
                      ``"Likely Safe"``.

    Renders:
        templates/history.html
    """
    user_id: Optional[str] = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login", next=request.path))

    # --- Query parameter parsing ---
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    search: Optional[str] = request.args.get("search", "").strip() or None
    filter_classification: Optional[str] = (
        request.args.get("filter", "").strip() or None
    )

    db = _get_db()

    try:
        scans: List[Dict[str, Any]] = db.get_user_scans(
            user_id=user_id,
            page=page,
            page_size=HISTORY_PAGE_SIZE,
            search=search,
            filter_classification=filter_classification,
        )
        total_count: int = db.count_user_scans(
            user_id=user_id,
            search=search,
            filter_classification=filter_classification,
        )
    except Exception:
        logger.exception("Error fetching history for user_id=%s", user_id)
        scans = []
        total_count = 0

    total_pages = max(1, -(-total_count // HISTORY_PAGE_SIZE))  # ceiling division

    return render_template(
        "history.html",
        scans=scans,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
        search=search or "",
        filter_classification=filter_classification or "",
    )


@dashboard_bp.route("/history/<scan_id>")
def scan_detail(scan_id: str):
    """
    View the full result page for a single scan.

    Only the scan's owner may view it.

    Args:
        scan_id: Hex-encoded MongoDB ObjectId of the scan document.

    Renders:
        templates/scan_detail.html
    """
    user_id: Optional[str] = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login", next=request.path))

    oid = _parse_object_id(scan_id)
    db = _get_db()

    try:
        scan: Optional[Dict[str, Any]] = db.get_scan_by_id(str(oid))
    except Exception:
        logger.exception("Error fetching scan_id=%s", scan_id)
        abort(500)

    if scan is None:
        abort(404)

    # Ownership check — users may only see their own scans
    if str(scan.get("user_id")) != user_id:
        abort(403)

    return render_template("scan_detail.html", scan=scan)


@dashboard_bp.route("/history/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    """
    AJAX endpoint — delete the caller's own scan record.

    Only the scan's owner may delete it; admins may use the admin panel.

    Args:
        scan_id: Hex-encoded MongoDB ObjectId of the scan document.

    Returns:
        JSON ``{"success": true}`` on success, or an error payload with an
        appropriate HTTP status code on failure.
    """
    user_id: Optional[str] = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    oid = _parse_object_id(scan_id)
    db = _get_db()

    try:
        scan: Optional[Dict[str, Any]] = db.get_scan_by_id(str(oid))
    except Exception:
        logger.exception("Error fetching scan_id=%s for deletion", scan_id)
        return jsonify({"success": False, "error": "Internal server error"}), 500

    if scan is None:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    if str(scan.get("user_id")) != user_id:
        return jsonify({"success": False, "error": "Forbidden"}), 403

    try:
        deleted: bool = db.delete_scan(str(oid))
    except Exception:
        logger.exception("Error deleting scan_id=%s", scan_id)
        return jsonify({"success": False, "error": "Internal server error"}), 500

    if deleted:
        logger.info("Scan %s deleted by user_id=%s", scan_id, user_id)
        return jsonify({"success": True}), 200

    return jsonify({"success": False, "error": "Delete operation failed"}), 500


@dashboard_bp.route("/security-tips")
def security_tips():
    """
    Public page with phishing-awareness and security tips.

    No authentication required — intentionally accessible to all visitors.

    Renders:
        templates/security_tips.html
    """
    return render_template("security_tips.html")
