"""Probe a handful of well-known sensitive paths, ignoring catch-all / soft-404 responses."""
import re
import secrets

from ..findings import make
from ..netsafe import UnsafeTarget


def _env_valid(r):
    return r.status_code == 200 and "<html" not in r.text[:300].lower() and re.search(r"^[A-Z][A-Z0-9_]*=", r.text, re.M)


PROBES = [
    (".git/HEAD", "WR-PATH-001", lambda r: r.status_code == 200 and r.text.startswith("ref:"), "Git HEAD readable"),
    (".env", "WR-PATH-002", _env_valid, "KEY=value pairs readable"),
    ("admin/", "WR-PATH-003", lambda r: r.status_code == 200, "Admin path answers 200"),
    ("phpinfo.php", "WR-PATH-004", lambda r: r.status_code == 200 and "phpinfo()" in r.text, "phpinfo() output"),
    ("server-status", "WR-PATH-004", lambda r: r.status_code == 200 and "Apache Server Status" in r.text, "Apache server-status"),
    ("actuator/env", "WR-PATH-004", lambda r: r.status_code == 200 and "propertySources" in r.text, "Spring actuator /env"),
    (".DS_Store", "WR-PATH-005", lambda r: r.status_code == 200 and r.content[:8] == b"\x00\x00\x00\x01Bud1", ".DS_Store file"),
]
INFO_PATHS = ["robots.txt", "sitemap.xml", ".well-known/security.txt"]


def check(fetcher, base_url):
    base = base_url.rstrip("/")

    def get(path):
        try:
            return fetcher.get(f"{base}/{path}", follow=False, max_bytes=200_000)
        except (UnsafeTarget, Exception):
            return None

    baseline = get(f"{secrets.token_hex(8)}/")
    b_status = baseline.status_code if baseline is not None else None
    b_len = len(baseline.content) if baseline is not None else 0

    def catch_all(r):
        return r.status_code == b_status and abs(len(r.content) - b_len) <= max(50, b_len * 0.05)

    paths, grouped = [], {}
    for path, fid, validator, note in PROBES:
        r = get(path)
        if r is None or catch_all(r):
            continue
        if validator(r):
            grouped.setdefault(fid, []).append(f"/{path} ({r.status_code}): {note}")
            paths.append({"path": f"/{path}", "status": r.status_code, "note": note, "kind": "finding"})
        elif path == "admin/" and r.status_code in (401, 403):
            paths.append({"path": f"/{path}", "status": r.status_code, "note": "exists but access-controlled", "kind": "info"})
    for path in INFO_PATHS:
        r = get(path)
        if r is not None and r.status_code == 200 and not catch_all(r) and "<html" not in r.text[:200].lower():
            paths.append({"path": f"/{path}", "status": 200, "note": "publicly reachable", "kind": "info"})
    return {"paths": paths, "findings": [make(fid, ev) for fid, ev in grouped.items()]}
