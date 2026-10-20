"""Proof of ownership: a DNS TXT record or a token file on the target.

DNS:   _webrecon-challenge.<domain>  TXT  "webrecon-verification=<token>"
File:  http(s)://<target>/.well-known/webrecon-verification.txt  containing the token
Verification of a domain also authorises its subdomains.
"""
import secrets
from datetime import datetime, timedelta, timezone

from . import dnsutil
from .db import utcnow
from .netsafe import SafeFetcher, ScanContext, UnsafeTarget, normalize_target

TXT_PREFIX = "webrecon-verification="
FILE_PATH = "/.well-known/webrecon-verification.txt"


def instructions(target, token):
    return {"dns": {"name": f"_webrecon-challenge.{target}", "type": "TXT", "value": f"{TXT_PREFIX}{token}"},
            "file": {"url": f"http://{target}{FILE_PATH}", "content": token}}


def create_challenge(db, user_id, raw_target):
    host, _ = normalize_target(raw_target)
    token = secrets.token_urlsafe(24)
    db.execute("INSERT INTO verifications(user_id, target, token, status, created_at) VALUES (?,?,?,'pending',?) "
               "ON CONFLICT(user_id, target) DO UPDATE SET token=excluded.token, status='pending', "
               "verified_at=NULL, expires_at=NULL, method=NULL, created_at=excluded.created_at",
               (user_id, host, token, utcnow()))
    return host, token


def _check_dns(host, token):
    return any(r.strip().strip('"') == f"{TXT_PREFIX}{token}" for r in dnsutil.txt_records(f"_webrecon-challenge.{host}"))


def _check_file(host, token, allow_private=False):
    fetcher = SafeFetcher(ScanContext(allow_private), timeout=6)
    for scheme in ("https", "http"):
        try:
            resp = fetcher.get(f"{scheme}://{host}{FILE_PATH}", max_bytes=2048)
        except (UnsafeTarget, Exception):
            continue
        if resp.status_code == 200 and resp.text.strip() == token:
            return True
    return False


def verify(db, verification_id, user_id, ttl_days=30, allow_private=False):
    row = db.one("SELECT * FROM verifications WHERE id=? AND user_id=?", (verification_id, user_id))
    if row is None:
        return None
    method = None
    if not _is_ip(row["target"]) and _check_dns(row["target"], row["token"]):
        method = "dns"
    elif _check_file(row["target"], row["token"], allow_private):
        method = "file"
    if method is None:
        return False
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat(timespec="seconds")
    db.execute("UPDATE verifications SET status='verified', method=?, verified_at=?, expires_at=? WHERE id=?",
               (method, utcnow(), expires, row["id"]))
    return True


def _is_ip(host):
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _candidates(host):
    if _is_ip(host):
        return [host]
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]  # never the bare TLD


def is_authorized(db, user, host, cfg):
    if not cfg["REQUIRE_VERIFICATION"] or host in cfg["PUBLIC_TARGETS"]:
        return True
    now = utcnow()
    for cand in _candidates(host):
        row = db.one("SELECT 1 FROM verifications WHERE user_id=? AND target=? AND status='verified' AND expires_at > ?",
                     (user["id"], cand, now))
        if row:
            return True
    return False
