"""Scan submission service shared by the web UI and the REST API."""
import uuid

from . import audit, ownership
from .db import utcnow
from .netsafe import ScanContext, UnsafeTarget, normalize_target


class ServiceError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def submit_scan(wr, user, raw_target, ip):
    """Validate, authorise, rate-limit and enqueue a scan. Returns the scan id."""
    cfg, db = wr.cfg, wr.db
    try:
        host, _ = normalize_target(raw_target)
        ScanContext(cfg["ALLOW_PRIVATE"]).pin(host)  # early SSRF check; the worker pins again
    except UnsafeTarget as exc:
        audit.record(db, "scan.rejected", f"{raw_target!r}: {exc}", user, ip)
        raise ServiceError(400, str(exc))
    if not ownership.is_authorized(db, user, host, cfg):
        audit.record(db, "scan.denied", f"ownership not verified for {host}", user, ip)
        raise ServiceError(403, f"Ownership of {host} is not verified. Add it under 'Targets' and complete the DNS or file challenge.")
    limit, window = cfg["RATE_SCANS"]
    allowed, retry = wr.limiter.allow(f"scan:{user['id']}", limit, window)
    if not allowed:
        raise ServiceError(429, f"Scan limit reached. Try again in {retry} seconds.")
    pending = db.one("SELECT COUNT(*) c FROM scans WHERE user_id=? AND status IN ('queued','running')", (user["id"],))["c"]
    if pending >= cfg["MAX_PENDING_PER_USER"]:
        raise ServiceError(429, "Too many scans are already queued or running.")
    scan_id = uuid.uuid4().hex
    db.execute("INSERT INTO scans(id, user_id, target, status, created_at) VALUES (?,?,?, 'queued', ?)",
               (scan_id, user["id"], host, utcnow()))
    audit.record(db, "scan.queued", f"{scan_id} target={host}", user, ip)
    return scan_id
