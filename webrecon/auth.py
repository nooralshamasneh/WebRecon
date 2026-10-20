"""Authentication: users (scrypt/pbkdf2 hashes), session login, API tokens, CSRF."""
import hashlib
import secrets
from functools import wraps

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import utcnow

MIN_PASSWORD = 12


class AuthError(ValueError):
    pass


def create_user(db, username, password, role="user"):
    username = (username or "").strip()
    if not username or len(username) > 64 or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise AuthError("Username must be 1-64 characters: letters, digits, '.', '_' or '-'.")
    if len(password or "") < MIN_PASSWORD:
        raise AuthError(f"Password must be at least {MIN_PASSWORD} characters.")
    if role not in ("user", "admin"):
        raise AuthError("Role must be 'user' or 'admin'.")
    if db.one("SELECT 1 FROM users WHERE username = ?", (username,)):
        raise AuthError("That username already exists.")
    cur = db.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
                     (username, generate_password_hash(password), role, utcnow()))
    return cur.lastrowid


def authenticate(db, username, password):
    row = db.one("SELECT * FROM users WHERE username = ?", (username or "",))
    if row is None:
        generate_password_hash("dummy-password-for-timing")  # keep timing similar for unknown users
        return None
    if row["disabled"] or not check_password_hash(row["password_hash"], password or ""):
        return None
    return row


def hash_token(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(db, user_id, name):
    raw = "wr_" + secrets.token_urlsafe(32)
    db.execute("INSERT INTO api_tokens(user_id, name, token_hash, created_at) VALUES (?,?,?,?)",
               (user_id, (name or "token")[:64], hash_token(raw), utcnow()))
    return raw  # shown once; only the hash is stored


def _user_from_bearer(db):
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    row = db.one("SELECT u.*, t.id AS token_id FROM api_tokens t JOIN users u ON u.id = t.user_id "
                 "WHERE t.token_hash = ? AND t.revoked = 0 AND u.disabled = 0", (hash_token(header[7:].strip()),))
    if row:
        db.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (utcnow(), row["token_id"]))
    return row


def load_user(db):
    g.user, g.via_token = None, False
    user = _user_from_bearer(db)
    if user:
        g.user, g.via_token = user, True
        return
    uid = session.get("uid")
    if uid:
        row = db.one("SELECT * FROM users WHERE id = ? AND disabled = 0", (uid,))
        g.user = row


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    """Cookie-authenticated unsafe requests must carry the CSRF token. Bearer-token requests are exempt."""
    if request.method in ("GET", "HEAD", "OPTIONS") or g.get("via_token"):
        return
    if request.path.startswith("/api/") and g.get("user") is None:
        return  # let the API answer 401 instead of a CSRF error
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf", "")
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400, description="Invalid or missing CSRF token.")


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("web.login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("web.login", next=request.path))
        if g.user["role"] != "admin":
            abort(403)
        return fn(*a, **kw)
    return wrapper


def api_auth_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            return jsonify(error="Authentication required."), 401
        wr = current_app.extensions["webrecon"]
        limit, window = wr.cfg["RATE_API"]
        ok, retry = wr.limiter.allow(f"api:{g.user['id']}", limit, window)
        if not ok:
            resp = jsonify(error="Rate limit exceeded.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry)
            return resp
        return fn(*a, **kw)
    return wrapper
