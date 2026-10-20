"""HTTP response analysis: security headers, cookies, CORS. Pure functions (no network I/O)."""
import re

from ..findings import make

_VERSION = re.compile(r"\d")


def set_cookie_headers(resp):
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except AttributeError:
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []


def _csp_directives(csp):
    out = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            out[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return out


def _hsts_max_age(value):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    return int(m.group(1)) if m else 0


def analyze(headers, cookies, is_https, cors_headers=None, probe_origin="https://webrecon-probe.invalid"):
    """Return {"table": [...], "findings": [...]}.

    cors_headers: response headers of a request that carried `Origin: probe_origin` (optional).
    """
    h = {k.lower(): v for k, v in headers.items()}
    table, findings = [], []

    def row(name, status, value, desc):
        table.append({"name": name, "status": status, "value": value or "", "description": desc})

    hsts = h.get("strict-transport-security")
    if not is_https:
        row("Strict-Transport-Security", "info", "n/a (site not served over HTTPS)", "Forces HTTPS")
    elif not hsts:
        row("Strict-Transport-Security", "missing", "", "Forces HTTPS")
        findings.append(make("WR-HDR-001"))
    elif _hsts_max_age(hsts) < 15552000:
        row("Strict-Transport-Security", "weak", hsts, "Forces HTTPS")
        findings.append(make("WR-HDR-002", [f"Strict-Transport-Security: {hsts}"]))
    else:
        row("Strict-Transport-Security", "ok", hsts, "Forces HTTPS")

    csp = h.get("content-security-policy", "")
    directives = _csp_directives(csp) if csp else {}
    if not csp:
        row("Content-Security-Policy", "missing", "", "Restricts script/style sources")
        findings.append(make("WR-HDR-003"))
    else:
        script_src = directives.get("script-src") or directives.get("default-src") or []
        bad = [t for t in script_src if t in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:")]
        if bad:
            row("Content-Security-Policy", "weak", csp[:200], "Restricts script/style sources")
            findings.append(make("WR-HDR-004", [f"script sources allow: {', '.join(bad)}"]))
        else:
            row("Content-Security-Policy", "ok", csp[:200], "Restricts script/style sources")

    xfo = h.get("x-frame-options")
    if xfo or "frame-ancestors" in directives:
        row("X-Frame-Options / frame-ancestors", "ok", xfo or "CSP frame-ancestors", "Clickjacking protection")
    else:
        row("X-Frame-Options / frame-ancestors", "missing", "", "Clickjacking protection")
        findings.append(make("WR-HDR-005"))

    if h.get("x-content-type-options", "").lower() == "nosniff":
        row("X-Content-Type-Options", "ok", "nosniff", "Prevents MIME sniffing")
    else:
        row("X-Content-Type-Options", "missing", h.get("x-content-type-options", ""), "Prevents MIME sniffing")
        findings.append(make("WR-HDR-006"))
    if h.get("referrer-policy"):
        row("Referrer-Policy", "ok", h["referrer-policy"], "Limits referrer leakage")
    else:
        row("Referrer-Policy", "missing", "", "Limits referrer leakage")
        findings.append(make("WR-HDR-007"))
    if h.get("permissions-policy") or h.get("feature-policy"):
        row("Permissions-Policy", "ok", h.get("permissions-policy") or h.get("feature-policy"), "Restricts browser features")
    else:
        row("Permissions-Policy", "missing", "", "Restricts browser features")
        findings.append(make("WR-HDR-008"))

    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if h.get(name) and _VERSION.search(h[name]):
            leaks.append(f"{name}: {h[name]}")
            row(name.title(), "leak", h[name], "Discloses software version")
        elif h.get(name):
            row(name.title(), "info", h[name], "Banner")
    if leaks:
        findings.append(make("WR-HDR-009", leaks))

    no_secure, no_httponly, no_samesite = [], [], []
    for raw in cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0]
        attrs = {p.split("=")[0].lower() for p in parts[1:]}
        if is_https and "secure" not in attrs:
            no_secure.append(name)
        if "httponly" not in attrs:
            no_httponly.append(name)
        if "samesite" not in attrs:
            no_samesite.append(name)
    for fid, names in (("WR-HDR-010", no_secure), ("WR-HDR-011", no_httponly), ("WR-HDR-012", no_samesite)):
        if names:
            findings.append(make(fid, [f"Cookie: {n}" for n in names[:5]]))

    if cors_headers is not None:
        c = {k.lower(): v for k, v in cors_headers.items()}
        acao, acac = c.get("access-control-allow-origin", ""), c.get("access-control-allow-credentials", "").lower()
        if acao == probe_origin:
            findings.append(make("WR-HDR-013", [f"Arbitrary Origin reflected: {acao}", f"Allow-Credentials: {acac or 'absent'}"],
                                 severity="high" if acac == "true" else "medium"))
        elif acao == "*":
            findings.append(make("WR-HDR-013", ["Access-Control-Allow-Origin: *"], severity="low"))

    return {"table": table, "findings": findings}
