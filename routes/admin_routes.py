"""
PhishGuard AI - Admin Routes
Admin-only dashboard and management. Requires admin role.
"""

import logging
import os
from typing import Any, Dict, List, Optional

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
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

logger = logging.getLogger("phishguard.admin")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_db():
    """Return the DatabaseService attached to the current app."""
    return current_app.db  # type: ignore[attr-defined]


def _admin_required(f):
    """
    Inline guard used within each view so that ``admin_required`` from
    ``auth_routes`` can be imported at the app level without creating a
    circular import here.  This module stays import-free of auth_routes.
    """
    import functools

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user_id: Optional[str] = session.get("user_id")
        role: Optional[str] = session.get("role")
        if not user_id:
            return redirect(url_for("auth.login", next=request.path))
        if role != "admin":
            abort(403)
        return f(*args, **kwargs)

    return decorated


def _safe_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strip all sensitive fields from a user document before rendering.

    Fields removed: ``password``, ``password_hash``, ``hashed_password``,
    and any field whose key contains the substring ``"secret"``.

    Args:
        user: Raw MongoDB user document.

    Returns:
        A new dict safe for template/JSON rendering.
    """
    sensitive_keys = {"password", "password_hash", "hashed_password"}
    return {
        k: v
        for k, v in user.items()
        if k not in sensitive_keys and "secret" not in k.lower()
    }


def _parse_object_id(value: str) -> ObjectId:
    """
    Parse a hex string into a :class:`bson.ObjectId`.

    Raises:
        werkzeug.exceptions.NotFound: If the string is not a valid ObjectId.
    """
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        abort(404)


def _model_file_exists() -> bool:
    """
    Check whether the trained model artefact exists on disk.

    Reads the model path from ``current_app.config`` so that it respects
    environment-specific overrides.

    Returns:
        ``True`` if the file is present and readable, ``False`` otherwise.
    """
    model_path: str = current_app.config.get("MODEL_PATH", "models/phishing_model.pkl")
    # Resolve relative paths from the project root (app root dir)
    if not os.path.isabs(model_path):
        model_path = os.path.join(current_app.root_path, model_path)
    return os.path.isfile(model_path)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@admin_bp.route("")
@admin_bp.route("/dashboard")
@_admin_required
def admin_dashboard():
    """
    Admin overview dashboard.

    Displays:
    - Global aggregate statistics across all users and scans.
    - The 20 most recent scans (from any user).
    - Stored ML model metadata (accuracy, training date, etc.).
    - Whether the trained model artefact file is present on disk.

    Renders:
        templates/admin_dashboard.html
    """
    db = _get_db()

    try:
        global_stats: Dict[str, int] = db.get_global_scan_stats()
        recent_scans: List[Dict[str, Any]] = db.get_all_scans(page=1, page_size=20)
        model_metadata: Optional[Dict[str, Any]] = db.get_model_metadata()
    except Exception:
        logger.exception("Error loading admin dashboard")
        global_stats = {
            "total_users": 0,
            "total_scans": 0,
            "phishing_count": 0,
            "safe_count": 0,
            "suspicious_count": 0,
        }
        recent_scans = []
        model_metadata = None

    model_file_present: bool = _model_file_exists()

    return render_template(
        "admin_dashboard.html",
        stats=global_stats,
        recent_scans=recent_scans,
        model_metadata=model_metadata,
        model_file_present=model_file_present,
    )


@admin_bp.route("/users")
@_admin_required
def list_users():
    """
    List all registered users.

    Password hashes and secret fields are **never** included in the rendered
    context — they are stripped by :func:`_safe_user` before reaching the
    template.

    Renders:
        templates/admin_users.html
    """
    db = _get_db()

    try:
        raw_users: List[Dict[str, Any]] = db.get_all_users()
    except Exception:
        logger.exception("Error fetching user list")
        raw_users = []

    # Strip sensitive fields from every user document
    safe_users: List[Dict[str, Any]] = [_safe_user(u) for u in raw_users]

    return render_template("admin_users.html", users=safe_users)


@admin_bp.route("/users/<user_id>/toggle-role", methods=["POST"])
@_admin_required
def toggle_user_role(user_id: str):
    """
    Toggle a user's role between ``'user'`` and ``'admin'``.

    Self-demotion is not allowed — an admin cannot demote their own account
    to prevent accidental lock-out.

    Args:
        user_id: Hex-encoded MongoDB ObjectId of the target user.

    Returns:
        JSON ``{"success": true, "new_role": "<role>"}`` on success, or an
        error payload with an appropriate HTTP status code.
    """
    current_admin_id: Optional[str] = session.get("user_id")

    # Prevent self-demotion
    if user_id == current_admin_id:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "You cannot change your own role.",
                }
            ),
            400,
        )

    oid = _parse_object_id(user_id)
    db = _get_db()

    try:
        user: Optional[Dict[str, Any]] = db.get_user_by_id(str(oid))
    except Exception:
        logger.exception("Error fetching user_id=%s for role toggle", user_id)
        return jsonify({"success": False, "error": "Internal server error"}), 500

    if user is None:
        return jsonify({"success": False, "error": "User not found"}), 404

    current_role: str = user.get("role", "user")
    new_role: str = "user" if current_role == "admin" else "admin"

    try:
        updated: bool = db.update_user_role(str(oid), new_role)
    except Exception:
        logger.exception(
            "Error updating role for user_id=%s to %s", user_id, new_role
        )
        return jsonify({"success": False, "error": "Internal server error"}), 500

    if updated:
        logger.info(
            "Admin %s toggled user %s role: %s → %s",
            current_admin_id,
            user_id,
            current_role,
            new_role,
        )
        return jsonify({"success": True, "new_role": new_role}), 200

    return jsonify({"success": False, "error": "Role update failed"}), 500
