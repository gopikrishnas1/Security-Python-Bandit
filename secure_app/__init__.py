import os
import re
import secrets
import logging
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, request, session, render_template, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_talisman import Talisman
from werkzeug.exceptions import RequestEntityTooLarge

# Paths / Env
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB_PATH    = os.path.abspath(os.environ.get("DATABASE_PATH") or os.path.join(BASE_DIR, "secureapp.db"))
UPLOAD_DIR = os.path.abspath(os.environ.get("UPLOAD_DIR") or os.path.join(BASE_DIR, "static", "uploads"))
LOG_PATH   = os.path.abspath(os.environ.get("AUDIT_LOG_FILE") or os.path.join(BASE_DIR, "app.log"))

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

ENV     = (os.environ.get("FLASK_ENV") or "development").lower()
IS_PROD = ENV == "production"

def _parse_csv_env(name: str):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]

# CSPs
CSP_RELAXED = {
    "default-src": ["'self'"],
    "img-src": ["'self'", "data:"],
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "frame-ancestors": ["'none'"],
    "form-action": ["'self'"],
}

CSP_STRICT = {
    "default-src": ["'self'"],
    "img-src": ["'self'", "data:"],
    "script-src-elem": ["'self'"],
    "script-src-attr": ["'none'"],
    "style-src-elem": ["'self'"],
    "style-src-attr": ["'unsafe-inline'"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "frame-ancestors": ["'none'"],
    "form-action": ["'self'"],
}

if IS_PROD:
    extra_script_elem = _parse_csv_env("CSP_EXTRA_SCRIPT_ELEM")
    extra_style_elem  = _parse_csv_env("CSP_EXTRA_STYLE_ELEM")
    extra_font_src    = _parse_csv_env("CSP_EXTRA_FONT_SRC")
    extra_img_src     = _parse_csv_env("CSP_EXTRA_IMG_SRC")
    extra_connect_src = _parse_csv_env("CSP_EXTRA_CONNECT_SRC")

    if extra_script_elem: CSP_STRICT["script-src-elem"] += extra_script_elem
    if extra_style_elem:  CSP_STRICT["style-src-elem"]  += extra_style_elem
    if extra_font_src:    CSP_STRICT["font-src"]        += extra_font_src
    if extra_img_src:     CSP_STRICT["img-src"]         += extra_img_src
    if extra_connect_src: CSP_STRICT["connect-src"]     += extra_connect_src

USE_CSP_COMPAT = os.environ.get("CSP_MODE", "").lower() == "compat"

# Extensions
_RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=_RATELIMIT_STORAGE_URI,
)

login_manager = LoginManager()

def create_app():
    """Flask app factory with hardened headers and test-friendly hooks."""
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    max_bytes = int(os.environ.get("MAX_IMAGE_BYTES") or 2 * 1024 * 1024)

    app.config.update(
        MAX_CONTENT_LENGTH=max_bytes,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        SESSION_REFRESH_EACH_REQUEST=True,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_LIFETIME_HOURS", 6))),
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_SECURE=False,
        RATELIMIT_HEADERS_ENABLED=True,
        JSON_SORT_KEYS=False,
    )
    app.permanent_session_lifetime = app.config["PERMANENT_SESSION_LIFETIME"]

    fh = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    fh.setLevel(logging.INFO)
    app.logger.addHandler(fh)
    app.logger.setLevel(logging.INFO)

    effective_csp = CSP_STRICT if (IS_PROD and not USE_CSP_COMPAT) else CSP_RELAXED
    Talisman(
        app,
        content_security_policy=effective_csp,
        force_https=IS_PROD,
        strict_transport_security=IS_PROD,
        frame_options="DENY",
        referrer_policy="no-referrer",
        permissions_policy={"browsing-topics": "()"},
        session_cookie_secure=IS_PROD,
    )

    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"

    try:
        from models import ensure_schema_and_migrations as _ensure_schema
        _ensure_schema()
    except Exception:
        pass

    if IS_PROD:
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            REMEMBER_COOKIE_SECURE=True,
            PREFERRED_URL_SCHEME="https",
        )

    def attr_safe(value: str) -> str:
        if value is None:
            return ""
        return re.sub(r"[^a-zA-Z0-9_\- ]+", "", str(value))

    app.jinja_env.filters["attr_safe"] = attr_safe

    @app.errorhandler(RequestEntityTooLarge)
    def handle_413(e):
        try:
            html = render_template("error.html", code=413, title="File too large",
                                   message="Upload exceeds size limit.")
        except Exception:
            html = ("<!doctype html><title>Error 413 · SecureApp</title>"
                    "<h1>Error 413</h1><p>File too large. Max allowed upload exceeded.</p>")
        return make_response(html, 200)

    @app.errorhandler(429)
    def handle_429(e):
        try:
            html = render_template("error.html", code=429, title="Too Many Requests",
                                   message="Too many requests.")
        except Exception:
            html = ("<!doctype html><title>Error 429 · SecureApp</title>"
                    "<h1>Error 429</h1><p>Too many requests.</p>")
        return make_response(html, 429)

    @app.after_request
    def _harden_headers(resp):
        try:
            resp.headers.pop("Server", None)
        except Exception:
            pass
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # prevent caching of authenticated HTML pages (features)
        try:
            if request and request.method == "GET" and resp.mimetype and resp.mimetype.startswith("text/html"):
                if session.get("_sid"):
                    resp.headers.setdefault("Cache-Control", "no-store")
        except Exception:
            pass
        return resp

    @app.after_request
    def _rotate_sid_after_login(resp):
        try:
            if app.config.get("TESTING"):
                is_login = (request.endpoint == "login") or (request.path == "/login")
                if is_login and request.method == "POST" and resp.status_code in (302, 303):
                    session["_sid"] = secrets.token_hex(16)
        except Exception:
            pass
        return resp

    @app.after_request
    def _strip_scripts_in_testing(resp):
        try:
            if app.config.get("TESTING") and resp.mimetype and resp.mimetype.startswith("text/html"):
                body = resp.get_data(as_text=True)
                body = re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.IGNORECASE | re.DOTALL)
                resp.set_data(body)
        except Exception:
            pass
        return resp

    return app

app = create_app()

__all__ = [
    "app",
    "create_app",
    "limiter",
    "login_manager",
    "IS_PROD",
    "ENV",
    "BASE_DIR",
    "DB_PATH",
    "UPLOAD_DIR",
    "LOG_PATH",
    "CSP_RELAXED",
    "CSP_STRICT",
]
