"""CVE correlation through the NVD API 2.0 (https://nvd.nist.gov/developers/vulnerabilities).

Uses CPE names (from nmap service detection and technology fingerprints). Results are cached in
SQLite for 24 h. Without an API key NVD allows ~5 requests per 30 s, so calls are spaced.
Matching is version-based: distribution back-ports can create false positives (confidence=tentative).
"""
import json
import re
import threading
import time

import requests

from ..findings import make

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 24 * 3600
_lock = threading.Lock()
_last_call = [0.0]
MAX_CPES_PER_SCAN = 8


def cpe_from_nmap(uri):
    """cpe:/a:openbsd:openssh:6.6.1p1  ->  cpe:2.3:a:openbsd:openssh:6.6.1p1  (application CPEs with a version only)."""
    m = re.match(r"^cpe:/a:([^:]+):([^:]+):([^:]+)", uri or "")
    return f"cpe:2.3:a:{m.group(1)}:{m.group(2)}:{m.group(3)}" if m else None


def severity_for(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def parse_nvd(data, limit=10):
    items = []
    for v in (data or {}).get("vulnerabilities", []):
        cve = v.get("cve", {})
        metrics, score = cve.get("metrics", {}), None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"].get("baseScore")
                break
        summary = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        items.append({"id": cve.get("id"), "cvss": score, "published": (cve.get("published") or "")[:10],
                      "summary": summary[:220]})
    items.sort(key=lambda i: -(i["cvss"] or 0))
    return {"total": len(items), "top": items[:limit], "max_cvss": items[0]["cvss"] if items and items[0]["cvss"] else None}


def lookup(cpe, db=None, api_key="", session=None, now=None):
    now = now if now is not None else time.time()
    if db is not None:
        row = db.one("SELECT fetched_at, payload FROM cve_cache WHERE key = ?", (cpe,))
        if row and now - row["fetched_at"] < CACHE_TTL:
            return json.loads(row["payload"])
    with _lock:  # polite spacing between live calls
        wait = (0.7 if api_key else 6.5) - (time.time() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.time()
        http = session or requests
        resp = http.get(NVD_URL, params={"virtualMatchString": cpe, "noRejected": "", "resultsPerPage": 200},
                        headers={"apiKey": api_key} if api_key else {}, timeout=30)
    resp.raise_for_status()
    parsed = parse_nvd(resp.json())
    if db is not None:
        db.execute("INSERT OR REPLACE INTO cve_cache(key, fetched_at, payload) VALUES (?,?,?)",
                   (cpe, now, json.dumps(parsed)))
    return parsed

def correlate(cpes, db=None, api_key="", lookup_fn=lookup):
    """Return {"results": {cpe: parsed}, "findings": [...], "errors": [...]}.

    All products are reported in ONE finding (WR-VULN-001) whose severity is the highest CVSS found,
    so the score does not depend on how many products were detected.
    """
    results, evidence, errors, worst = {}, [], [], 0.0
    for cpe in list(dict.fromkeys(cpes))[:MAX_CPES_PER_SCAN]:
        try:
            parsed = lookup_fn(cpe, db=db, api_key=api_key)
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"{cpe}: {type(exc).__name__}")
            continue
        results[cpe] = parsed
        if parsed["total"]:
            evidence.append(f"{cpe}: {parsed['total']} CVEs (max CVSS {parsed['max_cvss']})")
            evidence += [f"  {c['id']} (CVSS {c['cvss']}): {c['summary'][:100]}" for c in parsed["top"][:3]]
            worst = max(worst, parsed["max_cvss"] or 0)
    findings = []
    if evidence:
        findings.append(make("WR-VULN-001", evidence, severity=severity_for(worst), confidence="tentative"))
    return {"results": results, "findings": findings, "errors": errors}
