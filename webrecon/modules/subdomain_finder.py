"""Subdomain discovery: several passive sources + wildcard-aware wordlist brute force.

Passive sources send the domain name (never scan results) to third-party public APIs:
crt.sh, CertSpotter, HackerTarget, AlienVault OTX and Anubis. Disable with WEBRECON_PASSIVE_SOURCES=0.
"""
import re
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

import requests

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
UA = {"User-Agent": "WebRecon/2.0 (passive subdomain lookup)"}


def _clean(name, domain):
    name = (name or "").strip().lower().rstrip(".")
    if not name or "*" in name or name == domain or not name.endswith("." + domain):
        return None
    return name if HOST_RE.match(name) else None


def parse_crtsh(data, domain):
    out = set()
    for entry in data or []:
        for sub in str(entry.get("name_value", "")).split("\n"):
            if (c := _clean(sub, domain)):
                out.add(c)
    return out


def parse_certspotter(data, domain):
    out = set()
    for entry in data or []:
        for sub in entry.get("dns_names", []) or []:
            if (c := _clean(sub, domain)):
                out.add(c)
    return out


def parse_hackertarget(text, domain):
    out = set()
    lines = (text or "").splitlines()
    if not lines or lines[0].lower().startswith("error") or "api count exceeded" in text.lower():
        return out
    for line in text.splitlines():
        if (c := _clean(line.split(",")[0], domain)):
            out.add(c)
    return out


def parse_otx(data, domain):
    out = set()
    for entry in (data or {}).get("passive_dns", []) or []:
        if (c := _clean(entry.get("hostname"), domain)):
            out.add(c)
    return out


def parse_anubis(data, domain):
    return {c for c in (_clean(x, domain) for x in (data or []) if isinstance(x, str)) if c}


SOURCES = [
    ("crt.sh", "https://crt.sh/?q=%25.{d}&output=json", "json", parse_crtsh),
    ("certspotter", "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names",
     "json", parse_certspotter),
    ("hackertarget", "https://api.hackertarget.com/hostsearch/?q={d}", "text", parse_hackertarget),
    ("otx", "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", "json", parse_otx),
    ("anubis", "https://jldc.me/anubis/subdomains/{d}", "json", parse_anubis),
]


def _fetch_source(source, domain):
    name, url, kind, parser = source
    try:
        resp = requests.get(url.format(d=domain), timeout=15, headers=UA)
        if resp.status_code != 200:
            return name, set(), f"{name}: HTTP {resp.status_code}"
        data = resp.json() if kind == "json" else resp.text
        return name, parser(data, domain), None
    except (requests.RequestException, ValueError) as exc:
        return name, set(), f"{name}: {type(exc).__name__}"


def _resolve(name):
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    return sorted({i[4][0].split("%")[0] for i in infos})


def find_subdomains(domain, wordlist, passive=True, max_workers=30):
    """Return {"subdomains": [{name, ips, sources}], "notes": [...]} (only names that resolve)."""
    notes = []
    sources_by_name = {}

    if passive:
        with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
            for name, found, err in pool.map(lambda s: _fetch_source(s, domain), SOURCES):
                if err:
                    notes.append(f"Passive source unavailable ({err}).")
                for sub in found:
                    sources_by_name.setdefault(sub, set()).add(name)

    wildcard_ips = set()
    for _ in range(2):
        ips = _resolve(f"{secrets.token_hex(8)}.{domain}")
        if ips:
            wildcard_ips.update(ips)
    if wildcard_ips:
        notes.append("Wildcard DNS detected: names resolving only to the wildcard address are ignored.")

    for word in wordlist:
        word = word.strip().lower()
        if word and re.fullmatch(r"[a-z0-9-]{1,63}", word):
            sources_by_name.setdefault(f"{word}.{domain}", set()).add("wordlist")

    names = sorted(sources_by_name)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for name, ips in zip(names, pool.map(_resolve, names)):
            if not ips:
                continue
            if wildcard_ips and set(ips) <= wildcard_ips:
                continue
            results.append({"name": name, "ips": ips, "sources": sorted(sources_by_name[name])})
    return {"subdomains": results, "notes": notes}
