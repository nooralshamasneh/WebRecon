"""Runtime configuration: environment variables with safe defaults."""
import os
import secrets
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def _bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _secret_key(data_dir):
    key = os.environ.get("WEBRECON_SECRET_KEY")
    if key:
        return key
    path = data_dir / "secret_key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_hex(32)
    path.write_text(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def load_config(overrides=None):
    overrides = dict(overrides or {})
    data_dir = Path(overrides.get("DATA_DIR") or os.environ.get("WEBRECON_DATA_DIR", "instance")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    cfg = {
        "DATA_DIR": data_dir,
        "DB_PATH": data_dir / "webrecon.db",
        "SECRET_KEY": _secret_key(data_dir),
        "HOST": os.environ.get("WEBRECON_HOST", "127.0.0.1"),
        "PORT": _int("WEBRECON_PORT", 8080),
        "REQUIRE_VERIFICATION": _bool("WEBRECON_REQUIRE_VERIFICATION", True),
        "PUBLIC_TARGETS": [t.strip().lower() for t in
                           os.environ.get("WEBRECON_PUBLIC_TARGETS", "scanme.nmap.org").split(",") if t.strip()],
        "VERIFICATION_TTL_DAYS": _int("WEBRECON_VERIFICATION_TTL_DAYS", 30),
        "ALLOW_PRIVATE": _bool("WEBRECON_ALLOW_PRIVATE", False),
        "WORKERS": _int("WEBRECON_WORKERS", 2),
        "DISABLE_WORKERS": False,
        "SCAN_TIMEOUT": _int("WEBRECON_SCAN_TIMEOUT", 900),
        "MAX_PENDING_PER_USER": _int("WEBRECON_MAX_PENDING", 3),
        "RATE_SCANS": (_int("WEBRECON_RATE_SCANS", 10), 3600),
        "RATE_API": (_int("WEBRECON_RATE_API", 120), 60),
        "RATE_LOGIN": (5, 300),
        "NVD_ENABLED": _bool("WEBRECON_NVD", True),
        "NVD_API_KEY": os.environ.get("NVD_API_KEY", ""),
        "PASSIVE_SOURCES": _bool("WEBRECON_PASSIVE_SOURCES", True),
        "WORDLIST": os.environ.get("WEBRECON_WORDLIST", str(PACKAGE_DIR / "data" / "subdomains.txt")),
        "WORDLIST_LIMIT": _int("WEBRECON_WORDLIST_LIMIT", 5000),
        "SECURE_COOKIES": _bool("WEBRECON_HTTPS", False),
        "BEHIND_PROXY": _bool("WEBRECON_BEHIND_PROXY", False),
        "ADMIN_USER": os.environ.get("WEBRECON_ADMIN_USER", ""),
        "ADMIN_PASSWORD": os.environ.get("WEBRECON_ADMIN_PASSWORD", ""),
    }
    cfg.update(overrides)
    if "DB_PATH" not in overrides:
        cfg["DB_PATH"] = Path(cfg["DATA_DIR"]) / "webrecon.db"
    return cfg
