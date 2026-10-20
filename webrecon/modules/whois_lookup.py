"""WHOIS data (python-whois). Failures return an empty dict, never raise."""
from datetime import datetime, timezone


def _first(value):
    return value[0] if isinstance(value, (list, tuple)) and value else value


def _iso(value):
    value = _first(value)
    return value.isoformat() if isinstance(value, datetime) else (str(value) if value else None)


def days_until(expiry):
    value = _first(expiry)
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (value - datetime.now(timezone.utc)).days


def get_whois(domain):
    try:
        import whois
        w = whois.whois(domain)
    except Exception:
        return {}
    emails = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
    return {
        "domain": str(_first(w.domain_name) or domain),
        "registrar": w.registrar,
        "created": _iso(w.creation_date),
        "expires": _iso(w.expiration_date),
        "days_to_expiry": days_until(w.expiration_date),
        "emails": sorted(set(emails)),
        "dnssec": str(w.dnssec) if getattr(w, "dnssec", None) else None,
    }
