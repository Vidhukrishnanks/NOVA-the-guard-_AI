"""
URLGuard AI - Flask application entry point.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from __future__ import annotations

import logging
import os
import re
import secrets
from pathlib import Path

from flask import Flask, render_template, request, session
from flask_wtf.csrf import CSRFError, CSRFProtect

import database
from config import Config, secret_key_for
from model_utils import ModelService
from threat_intel import ThreatIntel

csrf = CSRFProtect()
OWNER_RE = re.compile(r"^[0-9a-f]{32}$")

NAV_ITEMS = [
    ("main.home", "Home", "home"),
    ("main.check", "Check URL", "search"),
    ("batch.batch", "Batch Analysis", "layers"),
    ("main.threat_intel", "Threat Intelligence", "radar"),
    ("main.model_performance", "Model Performance", "chart"),
    ("main.history", "Scan History", "clock"),
    ("reports.index", "Cybercrime Reporting", "flag"),
    ("main.info", "Dataset & Model Info", "database"),
    ("main.settings", "Settings", "gear"),
]


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    inst = Path(app.config["INSTANCE_DIR"])
    app.config.setdefault("DATABASE_PATH", str(inst / "urlguard.sqlite3"))
    app.config.setdefault("EVIDENCE_DIR", inst / "evidence")
    app.config.setdefault("BATCH_DIR", inst / "batch_results")
    for d in (inst, app.config["EVIDENCE_DIR"], app.config["BATCH_DIR"]):
        Path(d).mkdir(parents=True, exist_ok=True)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = secret_key_for(inst)

    # Privacy-conscious logging: never log full URLs or form contents.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    csrf.init_app(app)
    database.init_db(app)
    app.extensions["model_service"] = ModelService(app.config["MODEL_DIR"])
    app.extensions["threat_intel"] = ThreatIntel(app.config.get("SAFE_BROWSING_API_KEY"),
                                                 client_version=app.config["APP_VERSION"])
    if not app.extensions["model_service"].ready:
        app.logger.warning(app.extensions["model_service"].load_error)

    from routes.batch import bp as batch_bp
    from routes.main import bp as main_bp
    from routes.reports import bp as reports_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(batch_bp)
    app.register_blueprint(reports_bp)

    @app.before_request
    def ensure_owner():
        session.permanent = True
        if not OWNER_RE.match(str(session.get("owner", ""))):
            session["owner"] = secrets.token_hex(16)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.endpoint and not request.endpoint.startswith("static"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject_globals():
        ms = app.extensions["model_service"]
        owner = session.get("owner", "")
        settings = database.get_settings(owner) if OWNER_RE.match(str(owner)) else {}
        return {
            "nav_items": NAV_ITEMS,
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "model_ready": ms.ready,
            "model_error": ms.load_error,
            "model_info": ms.info,
            "user_settings": settings,
        }

    @app.template_filter("dt")
    def fmt_dt(value):
        """'2026-10-14T05:17:17+00:00' -> '2026-10-14 05:17'"""
        v = str(value or "")
        return v[:16].replace("T", " ") if len(v) >= 16 else v

    def _error(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(400)
    def bad_request(_e):
        return _error(400, "Bad request", "The request could not be understood.")

    @app.errorhandler(CSRFError)
    def csrf_error(_e):
        return _error(400, "Session expired", "Your form expired or was missing a security token. "
                                              "Go back, refresh the page and try again.")

    @app.errorhandler(403)
    def forbidden(_e):
        return _error(403, "Not allowed", "You do not have access to this item.")

    @app.errorhandler(404)
    def not_found(_e):
        return _error(404, "Not found", "That page or item does not exist (or belongs to another browser session).")

    @app.errorhandler(413)
    def too_large(_e):
        return _error(413, "File too large", "The upload is larger than the allowed limit.")

    @app.errorhandler(500)
    def server_error(_e):
        return _error(500, "Something went wrong", "An unexpected error occurred. No details were stored.")

    return app


app = create_app() if os.environ.get("URLGUARD_NO_AUTOAPP") != "1" else None

if __name__ == "__main__":
    # Bind to localhost only: the app is meant to run on your own computer.
    host = os.environ.get("URLGUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("URLGUARD_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"\n  URLGuard AI running at  http://{host}:{port}\n  Press CTRL+C to stop.\n")
    app.run(host=host, port=port, debug=debug)
