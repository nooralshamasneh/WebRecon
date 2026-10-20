"""HTML interface."""
import json
import re

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request,
                   session, url_for)

from . import audit, auth, ownership
from .compare import compare_scans
from .netsafe import UnsafeTarget
from .report import build_pdf
from .scans import ServiceError, submit_scan

bp = Blueprint("web", __name__)


def wr():
    return current_app.extensions["webrecon"]


def _safe_next(value):
    return value if value and value.startswith("/") and not value.startswith("//") else url_for("web.dashboard")


def get_scan_row(scan_id):
    row = wr().db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if row is None or (row["user_id"] != g.user["id"] and g.user["role"] != "admin"):
        return None
    return row


def load_result(row):
    return json.loads(row["result_json"]) if row["result_json"] else None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        ip = request.remote_addr or "?"
        limit, window = wr().cfg["RATE_LOGIN"]
        ok1, _ = wr().limiter.allow(f"login:{ip}:{username.lower()}", limit, window)
        ok2, _ = wr().limiter.allow(f"login-ip:{ip}", limit * 4, window)
        if not (ok1 and ok2):
            audit.record(wr().db, "login.blocked", username, None, ip)
            return render_template("login.html"), 429
        row = auth.authenticate(wr().db, username, request.form.get("password", ""))
        if row:
            session.clear()
            session["uid"] = row["id"]
            session.permanent = True
            wr().limiter.reset(f"login:{ip}:{username.lower()}")
            audit.record(wr().db, "login.success", "", row, ip)
            return redirect(_safe_next(request.args.get("next")))
        audit.record(wr().db, "login.failed", username, None, ip)
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.post("/logout")
def logout():
    if g.user:
        audit.record(wr().db, "logout", "", g.user, request.remote_addr)
    session.clear()
    return redirect(url_for("web.login"))


@bp.get("/")
@auth.login_required
def dashboard():
    scans = wr().db.all("SELECT id, target, status, stage, progress, grade, score, created_at FROM scans "
                        "WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", (g.user["id"],))
    return render_template("dashboard.html", scans=scans, public_targets=wr().cfg["PUBLIC_TARGETS"])


@bp.post("/scans")
@auth.login_required
def create_scan():
    try:
        scan_id = submit_scan(wr(), g.user, request.form.get("target", ""), request.remote_addr)
    except ServiceError as exc:
        flash(exc.message, "error")
        return redirect(url_for("web.dashboard")), 303
    return redirect(url_for("web.scan_detail", scan_id=scan_id))


@bp.get("/scans/<scan_id>")
@auth.login_required
def scan_detail(scan_id):
    row = get_scan_row(scan_id)
    if row is None:
        abort(404)
    return render_template("scan.html", scan=row, result=load_result(row))


@bp.get("/scans/<scan_id>/report.pdf")
@auth.login_required
def scan_pdf(scan_id):
    row = get_scan_row(scan_id)
    result = load_result(row) if row else None
    if result is None:
        abort(404)
    audit.record(wr().db, "report.pdf", scan_id, g.user, request.remote_addr)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", result["target"])
    return Response(build_pdf(result), mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="WebRecon_{name}.pdf"'})


@bp.get("/scans/<scan_id>/result.json")
@auth.login_required
def scan_json(scan_id):
    row = get_scan_row(scan_id)
    if row is None or not row["result_json"]:
        abort(404)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", row["target"])
    return Response(row["result_json"], mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="WebRecon_{name}.json"'})


@bp.post("/scans/<scan_id>/delete")
@auth.login_required
def scan_delete(scan_id):
    row = get_scan_row(scan_id)
    if row is None:
        abort(404)
    wr().db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    audit.record(wr().db, "scan.deleted", scan_id, g.user, request.remote_addr)
    return redirect(url_for("web.dashboard"))


@bp.get("/compare")
@auth.login_required
def compare():
    a, b = request.args.get("a"), request.args.get("b")
    scans = wr().db.all("SELECT id, target, created_at, grade FROM scans WHERE user_id=? AND status='completed' "
                        "ORDER BY created_at DESC LIMIT 100", (g.user["id"],))
    diff = None
    if a and b:
        ra, rb = get_scan_row(a), get_scan_row(b)
        if not (ra and rb and ra["result_json"] and rb["result_json"]):
            abort(404)
        older, newer = sorted([ra, rb], key=lambda r: r["created_at"])
        diff = compare_scans(load_result(older), load_result(newer))
        diff["ids"] = {"a": older["id"], "b": newer["id"]}
    return render_template("compare.html", scans=scans, diff=diff)


@bp.route("/targets", methods=["GET", "POST"])
@auth.login_required
def targets():
    db = wr().db
    if request.method == "POST":
        try:
            host, token = ownership.create_challenge(db, g.user["id"], request.form.get("target", ""))
            audit.record(db, "target.challenge", host, g.user, request.remote_addr)
            flash(f"Challenge created for {host}. Complete one of the steps below, then press Verify.", "info")
        except UnsafeTarget as exc:
            flash(str(exc), "error")
        return redirect(url_for("web.targets"))
    rows = db.all("SELECT * FROM verifications WHERE user_id = ? ORDER BY created_at DESC", (g.user["id"],))
    items = [{"row": r, "how": ownership.instructions(r["target"], r["token"])} for r in rows]
    return render_template("targets.html", items=items, public_targets=wr().cfg["PUBLIC_TARGETS"])


@bp.post("/targets/<int:vid>/verify")
@auth.login_required
def target_verify(vid):
    result = ownership.verify(wr().db, vid, g.user["id"], wr().cfg["VERIFICATION_TTL_DAYS"], wr().cfg["ALLOW_PRIVATE"])
    if result is None:
        abort(404)
    audit.record(wr().db, "target.verify", f"id={vid} ok={result}", g.user, request.remote_addr)
    flash("Ownership verified." if result else "Challenge not found yet. DNS changes can take a few minutes.",
          "info" if result else "error")
    return redirect(url_for("web.targets"))


@bp.post("/targets/<int:vid>/delete")
@auth.login_required
def target_delete(vid):
    wr().db.execute("DELETE FROM verifications WHERE id = ? AND user_id = ?", (vid, g.user["id"]))
    return redirect(url_for("web.targets"))


@bp.route("/account", methods=["GET", "POST"])
@auth.login_required
def account():
    db, new_token = wr().db, None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            new_token = auth.create_token(db, g.user["id"], request.form.get("name", "token"))
            audit.record(db, "token.created", "", g.user, request.remote_addr)
        elif action == "revoke":
            db.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ?",
                       (request.form.get("id", type=int), g.user["id"]))
            audit.record(db, "token.revoked", "", g.user, request.remote_addr)
    tokens = db.all("SELECT id, name, created_at, last_used_at, revoked FROM api_tokens WHERE user_id = ? ORDER BY id DESC",
                    (g.user["id"],))
    return render_template("account.html", tokens=tokens, new_token=new_token)


@bp.get("/admin/audit")
@auth.admin_required
def audit_view():
    return render_template("audit.html", entries=audit.recent(wr().db, 300))
