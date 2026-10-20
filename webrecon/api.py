"""REST API v1 (see docs/API.md). Authenticate with `Authorization: Bearer <token>` or a session cookie."""
import json

from flask import Blueprint, Response, current_app, g, jsonify, request, url_for

from . import audit, auth, ownership
from .compare import compare_scans
from .netsafe import UnsafeTarget
from .report import build_pdf
from .scans import ServiceError, submit_scan

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def wr():
    return current_app.extensions["webrecon"]


def _row(scan_id):
    row = wr().db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if row is None or (row["user_id"] != g.user["id"] and g.user["role"] != "admin"):
        return None
    return row


def _scan_dict(row, full=False):
    out = {"id": row["id"], "target": row["target"], "status": row["status"], "stage": row["stage"],
           "progress": row["progress"], "grade": row["grade"], "score": row["score"], "error": row["error"],
           "created_at": row["created_at"], "started_at": row["started_at"], "finished_at": row["finished_at"],
           "links": {"self": url_for("api.get_scan", scan_id=row["id"]),
                     "report_pdf": url_for("api.report", scan_id=row["id"])}}
    if full and row["result_json"]:
        out["result"] = json.loads(row["result_json"])
    return out


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@bp.get("/health")
def health():
    return jsonify(status="ok")


@bp.post("/scans")
@auth.api_auth_required
def create_scan():
    try:
        scan_id = submit_scan(wr(), g.user, _json_body().get("target", ""), request.remote_addr)
    except ServiceError as exc:
        return jsonify(error=exc.message), exc.status
    resp = jsonify(_scan_dict(_row(scan_id)))
    resp.status_code = 202
    resp.headers["Location"] = url_for("api.get_scan", scan_id=scan_id)
    return resp


@bp.get("/scans")
@auth.api_auth_required
def list_scans():
    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    offset = max(request.args.get("offset", 0, type=int), 0)
    sql, params = "SELECT * FROM scans WHERE user_id = ?", [g.user["id"]]
    if request.args.get("target"):
        sql += " AND target = ?"
        params.append(request.args["target"].lower())
    if request.args.get("status"):
        sql += " AND status = ?"
        params.append(request.args["status"])
    rows = wr().db.all(sql + " ORDER BY created_at DESC LIMIT ? OFFSET ?", params + [limit, offset])
    return jsonify(scans=[_scan_dict(r) for r in rows], limit=limit, offset=offset)


@bp.get("/scans/<scan_id>")
@auth.api_auth_required
def get_scan(scan_id):
    row = _row(scan_id)
    if row is None:
        return jsonify(error="Scan not found."), 404
    return jsonify(_scan_dict(row, full=True))


@bp.delete("/scans/<scan_id>")
@auth.api_auth_required
def delete_scan(scan_id):
    if _row(scan_id) is None:
        return jsonify(error="Scan not found."), 404
    wr().db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    audit.record(wr().db, "scan.deleted", scan_id, g.user, request.remote_addr)
    return "", 204


@bp.get("/scans/<scan_id>/report.pdf")
@auth.api_auth_required
def report(scan_id):
    row = _row(scan_id)
    if row is None or not row["result_json"]:
        return jsonify(error="No completed scan with that id."), 404
    return Response(build_pdf(json.loads(row["result_json"])), mimetype="application/pdf")


@bp.get("/compare")
@auth.api_auth_required
def compare():
    ra, rb = _row(request.args.get("a", "")), _row(request.args.get("b", ""))
    if not (ra and rb and ra["result_json"] and rb["result_json"]):
        return jsonify(error="Both scans must exist and be completed."), 404
    older, newer = sorted([ra, rb], key=lambda r: r["created_at"])
    return jsonify(compare_scans(json.loads(older["result_json"]), json.loads(newer["result_json"])))


@bp.get("/targets")
@auth.api_auth_required
def list_targets():
    rows = wr().db.all("SELECT id, target, status, method, created_at, verified_at, expires_at FROM verifications "
                       "WHERE user_id = ? ORDER BY id DESC", (g.user["id"],))
    return jsonify(targets=[dict(r) for r in rows])


@bp.post("/targets")
@auth.api_auth_required
def add_target():
    try:
        host, token = ownership.create_challenge(wr().db, g.user["id"], _json_body().get("target", ""))
    except UnsafeTarget as exc:
        return jsonify(error=str(exc)), 400
    audit.record(wr().db, "target.challenge", host, g.user, request.remote_addr)
    row = wr().db.one("SELECT id FROM verifications WHERE user_id=? AND target=?", (g.user["id"], host))
    return jsonify(id=row["id"], target=host, challenge=ownership.instructions(host, token)), 201


@bp.post("/targets/<int:vid>/verify")
@auth.api_auth_required
def verify_target(vid):
    ok = ownership.verify(wr().db, vid, g.user["id"], wr().cfg["VERIFICATION_TTL_DAYS"], wr().cfg["ALLOW_PRIVATE"])
    if ok is None:
        return jsonify(error="Target not found."), 404
    audit.record(wr().db, "target.verify", f"id={vid} ok={ok}", g.user, request.remote_addr)
    return jsonify(verified=bool(ok)), 200 if ok else 409


@bp.get("/audit")
@auth.api_auth_required
def audit_log():
    if g.user["role"] != "admin":
        return jsonify(error="Admin only."), 403
    return jsonify(entries=audit.recent(wr().db, request.args.get("limit", 100, type=int)))
