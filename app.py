"""
PhishGuard AI - Application Factory and Main Server
Initializes Flask app, registers blueprints, configures error handlers,
and wires up database and ML services.
"""
from datetime import datetime
import os
import sys
from flask import Flask, render_template, session

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import config
from ml.predict import is_model_available
from routes.admin_routes import admin_bp
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.scan_routes import scan_bp
from services.database_service import DatabaseService
from utils.logger import setup_logger

logger = setup_logger("phishguard.app", os.path.join(PROJECT_ROOT, "logs", "phishguard.log"))


def create_app(config_name: str = None) -> Flask:
    """
    Flask Application Factory.
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app_config = config.get(config_name, config["default"])
    app.config.from_object(app_config)

    # Initialize Database Service
    mongo_uri = app.config.get("MONGO_URI", "mongodb://localhost:27017/")
    mongo_db_name = app.config.get("MONGO_DB_NAME", "phishguard")
    app.db = DatabaseService(mongo_uri=mongo_uri, db_name=mongo_db_name)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)

    # Global Context Processor for Templates
    @app.context_processor
    def inject_template_globals():
        current_user = None
        if "user_id" in session:
            current_user = {
                "id": session.get("user_id"),
                "name": session.get("name", "User"),
                "email": session.get("email", ""),
                "role": session.get("role", "user")
            }
        return {
            "current_user": current_user,
            "model_available": is_model_available(),
            "current_year": datetime.now().year
        }

    # Root Home Landing Route
    @app.route("/")
    def index():
        return render_template("index.html")

    # Error Handlers
    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template("404.html", error_code=400, error_title="Bad Request",
                               error_message="The request could not be processed due to invalid parameters."), 400

    @app.errorhandler(401)
    def unauthorized_error(error):
        return render_template("404.html", error_code=401, error_title="Unauthorized",
                               error_message="Authentication credentials are required to view this resource."), 401

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template("404.html", error_code=403, error_title="Forbidden",
                               error_message="You do not have administrative privileges to access this area."), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("404.html", error_code=404, error_title="Page Not Found",
                               error_message="The requested destination or security resource does not exist."), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.exception("Uncaught server exception encountered.")
        return render_template("404.html", error_code=500, error_title="Internal Error",
                               error_message="A server-side error occurred. Technical details have been logged securely."), 500

    logger.info(f"PhishGuard AI initialized in '{config_name}' environment.")
    return app


if __name__ == "__main__":
    flask_app = create_app()
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", 5000))
    print("\n" + "="*60)
    print("  PHISHGUARD AI - APPLICATION STARTED")
    print(f"  Access local URL: http://{host}:{port}")
    print("="*60 + "\n")
    flask_app.run(host=host, port=port, debug=flask_app.config.get("DEBUG", False))
