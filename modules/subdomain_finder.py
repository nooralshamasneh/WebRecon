# modules/subdomain_finder.py
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

import requests


def _resolves(name):
    try:
        socket.gethostbyname(name)
        return True
    except OSError:
        return False


def _from_crtsh(domain):
    """Passive discovery from certificate transparency logs."""
    found = set()
    try:
        resp = requests.get("https://crt.sh/",
                            params={"q": f"%.{domain}", "output": "json"}, timeout=15)
        if resp.status_code == 200:
            for entry in resp.json():
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub and sub.endswith("." + domain):
                        found.add(sub)
    except (requests.RequestException, ValueError) as exc:
        print(f"[-] crt.sh query failed: {exc}")
    return found


def find_subdomains(domain, wordlist, max_workers=20):
    """Return (sorted_subdomains, notes). Only names that currently resolve are kept."""
    notes = []
    candidates = _from_crtsh(domain)

    # A random label that resolves means wildcard DNS: brute force would be all false positives.
    wildcard = _resolves(f"{secrets.token_hex(8)}.{domain}")
    if wildcard:
        notes.append("Wildcard DNS detected: wordlist brute-force skipped and "
                     "certificate-log names are unverified.")
        return sorted(candidates), notes

    candidates |= {f"{w.strip().lower()}.{domain}" for w in wordlist if w.strip()}
    names = sorted(candidates)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        resolved = [n for n, ok in zip(names, pool.map(_resolves, names)) if ok]
    return resolved, notes