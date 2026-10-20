"""Collect e-mail addresses published on a few public pages (through the pinned fetcher)."""
import re

from ..netsafe import UnsafeTarget

EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I)
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".js", ".css", ".woff", ".woff2")
PAGES = ["", "contact", "contact-us", "about", "about-us"]


def extract_emails(fetcher, base_url, limit=50):
    base = base_url.rstrip("/")
    found = set()
    for page in PAGES:
        try:
            resp = fetcher.get(f"{base}/{page}", max_bytes=500_000)
        except (UnsafeTarget, Exception):
            continue
        if resp.status_code != 200:
            continue
        for email in EMAIL_RE.findall(resp.text):
            email = email.lower()
            if not email.endswith(SKIP_SUFFIXES) and "@2x" not in email:
                found.add(email)
    return sorted(found)[:limit]
