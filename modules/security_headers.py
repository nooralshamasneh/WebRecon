# modules/security_headers.py
"""Pure analysis of HTTP response headers (no network I/O)."""

# name, description, penalty if missing, suggested fix, https_only
CHECKS = [
    ("Strict-Transport-Security", "HSTS: forces HTTPS, blocks protocol downgrade", 15,
     "Strict-Transport-Security: max-age=31536000; includeSubDomains", True),
    ("Content-Security-Policy", "CSP: mitigates XSS and data injection", 15,
     "Content-Security-Policy: default-src 'self'; script-src 'self'  (test before enforcing)", False),
    ("X-Frame-Options", "Clickjacking protection", 10,
     "X-Frame-Options: SAMEORIGIN", False),
    ("X-Content-Type-Options", "Prevents MIME sniffing", 10,
     "X-Content-Type-Options: nosniff", False),
    ("Referrer-Policy", "Limits referrer information leaking to other sites", 5,
     "Referrer-Policy: strict-origin-when-cross-origin", False),
]

LEAKY = ("Server", "X-Powered-By")


def check_security_headers(headers, is_https=True):
    """Return a list of dicts: name, status (ok/missing/leak/info), value, description, penalty, fix."""
    results = []
    csp = headers.get("Content-Security-Policy", "").lower()

    for name, desc, penalty, fix, https_only in CHECKS:
        value = headers.get(name)
        if name == "X-Frame-Options" and not value and "frame-ancestors" in csp:
            value = "(covered by CSP frame-ancestors)"
        if https_only and not is_https:
            results.append({"name": name, "status": "info", "value": "n/a (site served over HTTP)",
                            "description": desc, "penalty": 0, "fix": fix})
        elif value:
            results.append({"name": name, "status": "ok", "value": value,
                            "description": desc, "penalty": 0, "fix": ""})
        else:
            results.append({"name": name, "status": "missing", "value": "",
                            "description": desc, "penalty": penalty, "fix": fix})

    for name in LEAKY:
        value = headers.get(name)
        if not value:
            continue
        has_version = any(ch.isdigit() for ch in value)
        results.append({
            "name": name,
            "status": "leak" if has_version else "info",
            "value": value,
            "description": "Discloses software and version" if has_version else "Server banner",
            "penalty": 3 if has_version else 0,
            "fix": f"Remove or genericise the {name} header" if has_version else "",
        })
    return results