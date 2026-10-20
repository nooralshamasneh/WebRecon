"""Target validation and SSRF protection.

* normalize_target(): strict parsing of user input (domain, IP or URL host only).
* ScanContext: resolves every hostname ONCE per scan and pins the result, so DNS
  rebinding cannot swap a public address for an internal one mid-scan.
* SafeFetcher: HTTP client that connects to the pinned IP, sends the original
  Host header/SNI, and validates every redirect hop with the same rules.
"""
import ipaddress
import re
import socket
import threading
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # certificates are inspected, not trusted

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f;|&$`'\"<>\\(){}*,]")
_BLOCKED_V6 = [ipaddress.ip_network(n) for n in ("64:ff9b::/96", "2002::/16", "2001::/32")]
REDIRECT_CODES = (301, 302, 303, 307, 308)


class UnsafeTarget(ValueError):
    """Raised when a target or redirect is invalid or not allowed."""


def is_public_ip(ip):
    ip = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_ip(ip.ipv4_mapped)
        if any(ip in net for net in _BLOCKED_V6):
            return False
    return ip.is_global and not ip.is_multicast


def normalize_target(raw):
    """Return (host, is_ip). Accepts a domain, an IP, or a http(s) URL without port/credentials."""
    value = (raw or "").strip().lower()
    if not value or len(value) > 300:
        raise UnsafeTarget("Enter a domain name or an IP address.")
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        return str(ipaddress.ip_address(candidate)), True
    except ValueError:
        pass
    if _FORBIDDEN.search(value):
        raise UnsafeTarget("The target contains characters that are not allowed.")
    try:
        parts = urlparse(value if "://" in value else f"//{value}")
        if parts.scheme not in ("", "http", "https"):
            raise ValueError
        if parts.username or parts.password or parts.port is not None:
            raise UnsafeTarget("Credentials and ports are not allowed in the target.")
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        raise UnsafeTarget("That does not look like a valid domain name or IP address.")
    try:
        return str(ipaddress.ip_address(host)), True
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise UnsafeTarget("Invalid internationalised domain name.")
    if not DOMAIN_RE.match(host):
        raise UnsafeTarget("That does not look like a valid domain name or IP address.")
    return host, False


def resolve_host(host):
    """Resolve a hostname to a de-duplicated list of IP strings (separate for easy mocking)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise UnsafeTarget(f"{host} could not be resolved.")
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def resolve_public(host, allow_private=False):
    ips = resolve_host(host)
    if not ips:
        raise UnsafeTarget(f"{host} could not be resolved.")
    if not allow_private and any(not is_public_ip(ip) for ip in ips):
        raise UnsafeTarget("Scanning private, loopback, link-local or reserved addresses is not allowed.")
    return sorted(ips, key=lambda i: ":" in i)  # prefer IPv4


class ScanContext:
    """Per-scan DNS pinning: first resolution wins for the whole scan."""

    def __init__(self, allow_private=False):
        self.allow_private = allow_private
        self.pins = {}
        self._lock = threading.Lock()

    def pin(self, host):
        host = host.lower().rstrip(".").strip("[]")
        with self._lock:
            if host in self.pins:
                return self.pins[host]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ips = resolve_public(host, self.allow_private)
        else:
            if not self.allow_private and not is_public_ip(ip):
                raise UnsafeTarget("Scanning private, loopback, link-local or reserved addresses is not allowed.")
            ips = [str(ip)]
        with self._lock:
            return self.pins.setdefault(host, ips[0])


class _PinnedAdapter(HTTPAdapter):
    """Connect to an IP but present the original hostname for TLS SNI."""

    def __init__(self, sni=None, **kw):
        self._sni = sni
        super().__init__(**kw)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self._sni:
            pool_kwargs["server_hostname"] = self._sni  # certificate is not verified (verify=False)
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class SafeFetcher:
    USER_AGENT = "WebRecon/2.0 (authorized security assessment)"

    def __init__(self, ctx, timeout=6, max_redirects=5):
        self.ctx = ctx
        self.timeout = timeout
        self.max_redirects = max_redirects

    def get(self, url, headers=None, follow=True, max_bytes=2_000_000):
        """GET a URL through the pinned IP. Returns a requests.Response.

        resp.redirect_blocked is set when a redirect was refused (unsafe host / too many hops).
        """
        current = url
        hops = 0
        while True:
            parts = urlparse(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise UnsafeTarget("Unsupported URL.")
            host = parts.hostname.lower()
            ip = self.ctx.pin(host)  # raises UnsafeTarget for non-public addresses
            netloc = f"[{ip}]" if ":" in ip else ip
            if parts.port:
                netloc += f":{parts.port}"
            ip_url = parts._replace(netloc=netloc).geturl()
            host_header = f"[{host}]" if ":" in host else host
            if parts.port and parts.port not in (80, 443):
                host_header += f":{parts.port}"

            session = requests.Session()
            session.trust_env = False  # never let proxy env vars bypass the pin
            adapter = _PinnedAdapter(sni=None if _is_ip(host) else host)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            req_headers = {"User-Agent": self.USER_AGENT, "Accept": "*/*", **(headers or {}), "Host": host_header}
            try:
                resp = session.get(ip_url, headers=req_headers, allow_redirects=False, verify=False,
                                   timeout=self.timeout, stream=True)
                body = bytearray()
                for chunk in resp.iter_content(8192):
                    body.extend(chunk)
                    if len(body) >= max_bytes:
                        break
                resp._content = bytes(body)
                resp._content_consumed = True
                resp.close()
            finally:
                session.close()
            resp.url = current
            resp.redirect_blocked = None

            location = resp.headers.get("Location")
            if follow and resp.status_code in REDIRECT_CODES and location:
                nxt = urljoin(current, location)
                if hops >= self.max_redirects:
                    resp.redirect_blocked = "too many redirects"
                    return resp
                try:
                    nparts = urlparse(nxt)
                    if nparts.scheme not in ("http", "https") or not nparts.hostname:
                        raise UnsafeTarget("redirect to unsupported URL")
                    self.ctx.pin(nparts.hostname)
                except UnsafeTarget as exc:
                    resp.redirect_blocked = f"{nxt} ({exc})"
                    return resp
                current = nxt
                hops += 1
                continue
            return resp
