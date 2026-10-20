"""Audit log: every security-relevant action is stored in SQLite and logged."""
import logging
import re

from .db import utcnow

log = logging.getLogger("webrecon.audit")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value, limit=500):
    return _CONTROL.sub(" ", str(value or ""))[:limit]  # prevents log injection


def record(db, action, detail="", user=None, ip=None):
    uid = user["id"] if user else None
    username = user["username"] if user else None
    db.execute("INSERT INTO audit_log(ts, user_id, username, ip, action, detail) VALUES (?,?,?,?,?,?)",
               (utcnow(), uid, username, _clean(ip, 64), _clean(action, 64), _clean(detail)))
    log.info("action=%s user=%s ip=%s detail=%s", _clean(action, 64), username, _clean(ip, 64), _clean(detail))


def recent(db, limit=200):
    rows = db.all("SELECT ts, username, ip, action, detail FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]
