"""WebRecon: authorized web reconnaissance and security-posture scanner."""
from datetime import timedelta
from types import SimpleNamespace

from flask import Flask, g, jsonify, render_template, request

from . import auth, cli, scanner
from .findings import TOP10_URLS
from .config import load_config
from .db import Database
from .jobs import JobQueue
from .ratelimit import RateLimiter

__version__ = "2.0.0"

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; "
       "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


def create_app(overrides=None):
    overrides = dict(overrides or {})
    runner = overrides.pop("RUNNER", None) or scanner.run_scan
    cfg = load_config(overrides)

    app = Flask(__name__)
    app.config.update(SECRET_KEY=cfg["SECRET_KEY"], SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=cfg["SECURE_COOKIES"], PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
                      MAX_CONTENT_LENGTH=64 * 1024, TESTING=bool(cfg.get("TESTING")))
    if cfg["BEHIND_PROXY"]:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db = Database(cfg["DB_PATH"])
    jobs = JobQueue(cfg, db, runner)
    app.extensions["webrecon"] = SimpleNamespace(cfg=cfg, db=db, limiter=RateLimiter(), jobs=jobs)

    from .api import bp as api_bp
    from .web import bp as web_bp
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)
    cli.register(app)
    app.jinja_env.globals["csrf_token"] = auth.csrf_token
    app.jinja_env.globals["TOP10_URLS"] = TOP10_URLS

    @app.before_request
    def _before():
        if request.endpoint == "static":
            return
        auth.load_user(db)
        auth.check_csrf()

    @app.context_processor
    def _ctx():
        return {"user": g.get("user"), "version": __version__}

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if cfg["SECURE_COOKIES"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def _error(code, message):
        if request.path.startswith("/api/"):
            return jsonify(error=message), code
        return render_template("error.html", code=code, message=message), code

    for code, text in ((400, "Bad request."), (403, "Forbidden."), (404, "Not found."),
                       (405, "Method not allowed."), (413, "Request too large."), (500, "Internal server error.")):
        app.register_error_handler(code, lambda e, c=code, t=text: _error(c, getattr(e, "description", t) if c == 400 else t))

    if cfg["ADMIN_USER"] and cfg["ADMIN_PASSWORD"] and not db.one("SELECT 1 FROM users LIMIT 1"):
        auth.create_user(db, cfg["ADMIN_USER"], cfg["ADMIN_PASSWORD"], "admin")

    if not cfg["DISABLE_WORKERS"]:
        jobs.start()
    return app
