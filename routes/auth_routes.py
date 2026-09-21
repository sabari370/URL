"""
PhishGuard AI - Authentication Routes & Access Control
Manages user registration, session authentication, logout, and role authorization.
"""
from functools import wraps
import logging
import re
from typing import Optional
import bcrypt
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
logger = logging.getLogger("phishguard.auth")


def _get_db():
    return current_app.db


def login_required(f):
    """Ensures user has an active authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Ensures user is signed in with 'admin' role privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access administrative functions.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if session.get("role") != "admin":
            flash("Access denied. Administrator privileges required.", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user registration."""
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation checks
        if not name or len(name) < 2:
            flash("Full name must be at least 2 characters long.", "danger")
            return render_template("register.html", name=name, email=email)

        email_regex = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"
        if not email or not re.match(email_regex, email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", name=name, email=email)

        if not password or len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("register.html", name=name, email=email)

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template("register.html", name=name, email=email)

        db = _get_db()
        if not db or not db.is_connected():
            flash("Database connection unavailable. Please ensure MongoDB is running.", "danger")
            return render_template("register.html", name=name, email=email)

        # Check existing email
        existing_user = db.find_user_by_email(email)
        if existing_user:
            flash("An account with this email address is already registered.", "warning")
            return render_template("register.html", name=name, email=email)

        # Hash password with bcrypt
        hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))
        hashed_str = hashed_bytes.decode("utf-8")

        # First registered user can optionally become admin if collection is empty
        role = "user"
        if db.get_user_count() == 0:
            role = "admin"
            logger.info(f"First user '{email}' created as system Administrator.")

        user_id = db.create_user(name=name, email=email, password_hash=hashed_str, role=role)
        if user_id:
            logger.info(f"New user registered: {email} (ID: {user_id}, Role: {role})")
            flash("Registration successful! You may now sign in.", "success")
            return redirect(url_for("auth.login"))
        else:
            flash("An error occurred during account creation. Please try again.", "danger")

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticates existing users and creates sessions."""
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please provide both email and password.", "danger")
            return render_template("login.html", email=email)

        db = _get_db()
        if not db or not db.is_connected():
            flash("Database connection unavailable. Please check MongoDB status.", "danger")
            return render_template("login.html", email=email)

        user = db.find_user_by_email(email)
        if not user:
            flash("Invalid email or password.", "danger")
            return render_template("login.html", email=email)

        pwd_hash = user.get("password_hash", "")
        # Verify bcrypt password
        try:
            matched = bcrypt.checkpw(password.encode("utf-8"), pwd_hash.encode("utf-8"))
        except Exception as e:
            logger.error(f"Password verification error for {email}: {e}")
            matched = False

        if matched:
            session.clear()
            session.permanent = True
            session["user_id"] = str(user["_id"])
            session["name"] = user.get("name", "User")
            session["email"] = user.get("email", email)
            session["role"] = user.get("role", "user")

            logger.info(f"Successful login for user '{email}' (role: {session['role']})")
            flash(f"Welcome back, {session['name']}!", "success")

            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard.dashboard"))
        else:
            logger.warning(f"Failed login attempt for user '{email}'")
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    """Clears user session and logs out."""
    user_email = session.get("email", "Anonymous")
    session.clear()
    logger.info(f"User '{user_email}' signed out.")
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("index"))
