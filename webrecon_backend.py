"""WebRecon - scanning engine."""
import ipaddress
import logging
import os
import re
import secrets
import socket
from datetime import datetime
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import requests
import urllib3
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer

from modules import (dns_lookup, email_extractor, port_scanner, security_headers,
                     subdomain_finder, whois_lookup)

log = logging.getLogger("webrecon")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(BASE_DIR, "wordlists", "subdomains.txt")
HTTP_HEADERS = {"User-Agent": "WebRecon/1.0 (authorized security assessment)"}
ALLOW_PRIVATE = os.environ.get("WEBRECON_ALLOW_PRIVATE") == "1"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# port -> (label, penalty)
RISKY_PORTS = {
    21: ("FTP", 15), 23: ("Telnet", 25), 110: ("POP3 (plaintext)", 5), 143: ("IMAP (plaintext)", 5),
    445: ("SMB", 20), 3306: ("MySQL", 15), 3389: ("RDP", 20), 5432: ("PostgreSQL", 10),
    6379: ("Redis", 20), 27017: ("MongoDB", 20),
}


# ---------------------------------------------------------------- input validation
class InvalidTarget(ValueError):
    pass


def normalize_target(raw):
    """Return (host, is_ip). Accepts a domain, IP, or URL; rejects anything else."""
    value = (raw or "").strip().lower()
    if not value or len(value) > 300:
        raise InvalidTarget("Enter a domain name or an IP address.")
    try:
        return str(ipaddress.ip_address(value.strip("[]"))), True
    except ValueError:
        pass
    try:
        host = urlparse(value if "://" in value else f"//{value}").hostname or ""
    except ValueError:
        host = ""
    host = host.rstrip(".")
    try:
        return str(ipaddress.ip_address(host)), True
    except ValueError:
        pass
    if not DOMAIN_RE.match(host):
        raise InvalidTarget("That does not look like a valid domain name or IP address.")
    return host, False


def assert_public(host):
    """Block loopback / private / link-local targets (SSRF protection)."""
    if ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise InvalidTarget("The domain could not be resolved.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise InvalidTarget("Scanning private, loopback or reserved addresses is not allowed.")


# ---------------------------------------------------------------- helpers
def load_wordlist(path):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def fetch_homepage(host):
    """Try HTTPS first, then HTTP. Returns (response, is_https) or (None, False)."""
    for scheme in ("https", "http"):
        try:
            res = requests.get(f"{scheme}://{host}", timeout=6, verify=False, headers=HTTP_HEADERS)
            return res, res.url.startswith("https://")
        except requests.RequestException:
            continue
    return None, False


def detect_technologies(response):
    techs, notes = [], []
    headers = response.headers
    html = response.text[:500_000].lower()
    server = headers.get("Server", "")

    if "cf-ray" in headers or "cloudflare" in server.lower():
        techs.append("Cloudflare WAF / CDN")
    if server and "cloudflare" not in server.lower():
        techs.append(f"Server: {server}")
    if "apache" in server.lower():
        notes.append("Apache detected: keep it patched and review enabled modules.")
    powered = headers.get("X-Powered-By")
    if powered:
        techs.append(f"X-Powered-By: {powered}")
        if "php" in powered.lower():
            notes.append("PHP version disclosed via X-Powered-By: hide the header (expose_php=Off).")
            techs.append("PHP backend")
    if "wp-content" in html or "wp-includes" in html:
        techs.append("WordPress CMS")
        notes.append("WordPress detected: check for outdated plugins and exposed xmlrpc.php.")
    if any(m in html for m in ("data-reactroot", "__next_data__", "react-dom", "react.production")):
        techs.append("React")
    if re.search(r"bootstrap[^\"']*\.(?:min\.)?(?:css|js)", html):
        techs.append("Bootstrap")
    if not techs:
        techs.append("No specific technology detected")
    return techs, notes


def check_sensitive_paths(host, is_https):
    """Probe a few well-known paths, ignoring catch-all / soft-404 responses."""
    base = f"{'https' if is_https else 'http'}://{host}"
    findings = []

    def get(path):
        try:
            return requests.get(f"{base}/{path}", timeout=4, verify=False,
                                headers=HTTP_HEADERS, allow_redirects=False)
        except requests.RequestException:
            return None

    baseline = get(f"{secrets.token_hex(8)}/")
    base_status = baseline.status_code if baseline is not None else None
    base_len = len(baseline.content) if baseline is not None else 0

    def looks_like_catch_all(res):
        return (base_status == res.status_code
                and abs(len(res.content) - base_len) <= max(50, base_len * 0.05))

    probes = ["robots.txt", "sitemap.xml", "admin/", "login/", ".git/HEAD", ".env", "api/"]
    for path in probes:
        res = get(path)
        if res is None or looks_like_catch_all(res):
            continue
        code, text = res.status_code, res.text[:2000]
        if path == ".git/HEAD":
            if code == 200 and text.startswith("ref:"):
                findings.append({"path": "/.git/HEAD", "status": code, "severity": "critical",
                                 "note": "Git repository exposed: source code can be downloaded."})
        elif path == ".env":
            if code == 200 and "<html" not in text[:300].lower() and re.search(r"^[A-Z0-9_]+=", text, re.M):
                findings.append({"path": "/.env", "status": code, "severity": "critical",
                                 "note": "Environment file exposed: may contain secrets."})
        elif path == "admin/":
            if code == 200:
                findings.append({"path": "/admin/", "status": code, "severity": "medium",
                                 "note": "Admin area reachable: verify it requires authentication."})
            elif code in (401, 403):
                findings.append({"path": "/admin/", "status": code, "severity": "info",
                                 "note": "Admin area exists but is access-controlled."})
        elif code == 200:
            findings.append({"path": f"/{path}", "status": code, "severity": "info",
                             "note": "Publicly reachable."})
    return findings


def build_risk_notes(tech_notes, services):
    notes = list(tech_notes)
    for svc in services:
        if svc.get("product") and svc.get("version"):
            notes.append(f"{svc['product']} {svc['version']} on port {svc['port']}: "
                         f"check this version for known CVEs on nvd.nist.gov.")
    return notes


def calculate_security_grade(results):
    breakdown = []
    for h in results["security_headers"]:
        if h["penalty"]:
            label = "missing" if h["status"] == "missing" else "discloses version"
            breakdown.append({"reason": f"{h['name']} {label}", "points": h["penalty"]})
    for port in results["open_ports"]:
        if port in RISKY_PORTS:
            name, pts = RISKY_PORTS[port]
            breakdown.append({"reason": f"{name} exposed (port {port})", "points": pts})
    for p in results["sensitive_paths"]:
        pts = {"critical": 30, "medium": 5}.get(p["severity"], 0)
        if pts:
            breakdown.append({"reason": f"{p['path']}: {p['note']}", "points": pts})

    score = max(0, 100 - sum(b["points"] for b in breakdown))
    if score >= 90:
        grade = "A (Excellent)"
    elif score >= 80:
        grade = "B (Good)"
    elif score >= 70:
        grade = "C (Moderate risk)"
    elif score >= 50:
        grade = "D (Weak)"
    else:
        grade = "F (Critical risk)"
    return grade, score, breakdown


# ---------------------------------------------------------------- PDF
def generate_pdf_report(results, path):
    doc = SimpleDocTemplate(path, pagesize=letter, title="WebRecon Security Report")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("T", parent=styles["Heading1"], fontSize=20,
                                 textColor=colors.HexColor("#c71585"), spaceAfter=12)
    mono = ParagraphStyle("Mono", parent=styles["Code"], fontSize=7, leading=9)

    def para(text):
        return Paragraph(escape(str(text)).replace("\n", "<br/>"), styles["Normal"])

    story = [
        Paragraph("WebRecon Security Report", title_style),
        para(f"Target: {results['target']}"),
        para(f"Scan time: {results['scan_time']}"),
        para(f"Security grade: {results['security_grade']} (score {results['security_score']}/100, higher is better)"),
        Spacer(1, 12),
    ]

    def section(title, body):
        story.append(Paragraph(escape(title), styles["Heading2"]))
        if isinstance(body, Preformatted):
            story.append(body)
        else:
            story.append(para(body))
        story.append(Spacer(1, 8))

    mark = {"ok": "[OK]", "missing": "[MISSING]", "leak": "[LEAK]", "info": "[INFO]"}
    section("Score breakdown", "\n".join(f"-{b['points']}: {b['reason']}" for b in results["score_breakdown"])
            or "No deductions.")
    section("Open ports", ", ".join(map(str, results["open_ports"])) or "None found")
    story.append(Preformatted(results["service_info"] or "", mono))
    section("Technologies", "\n".join(results["technologies"]))
    section("Risk notes (heuristic)", "\n".join(results["risk_notes"]) or "None")
    section("Remediations", "\n".join(f"{r['header']}: {r['fix']}" for r in results["remediations"]) or "None")
    section("Sensitive paths", "\n".join(f"{p['path']} ({p['status']}): {p['note']}"
                                         for p in results["sensitive_paths"]) or "None found")
    section("Security headers", "\n".join(f"{mark[h['status']]} {h['name']}: {h['value'] or '-'}"
                                          for h in results["security_headers"]) or "Not available")
    if not results["is_ip"]:
        section("DNS records", results["dns_records"])
        section("WHOIS", results["whois"])
        section(f"Subdomains ({len(results['subdomains'])})", "\n".join(results["subdomains"]) or "None found")
        section(f"Emails ({len(results['emails'])})", "\n".join(results["emails"]) or "None found")
    if results["notes"]:
        section("Notes", "\n".join(results["notes"]))
    doc.build(story)


# ---------------------------------------------------------------- main entry
def scan_target(raw_target, scan_id, report_path):
    host, is_ip = normalize_target(raw_target)
    assert_public(host)

    results = {
        "scan_id": scan_id, "target": host, "is_ip": is_ip,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "whois": "Skipped (target is an IP)", "dns_records": "Skipped (target is an IP)",
        "subdomains": [], "emails": [], "open_ports": [], "service_info": "",
        "security_headers": [], "technologies": [], "risk_notes": [], "remediations": [],
        "sensitive_paths": [], "security_grade": "N/A", "security_score": 100,
        "score_breakdown": [], "notes": [],
    }

    if not is_ip:
        try:
            results["whois"] = whois_lookup.get_whois(host)
        except Exception:
            log.warning("WHOIS failed", exc_info=True)
            results["whois"] = "WHOIS lookup failed"
        try:
            results["dns_records"] = dns_lookup.get_dns_records(host)
        except Exception:
            log.warning("DNS failed", exc_info=True)
            results["dns_records"] = "DNS lookup failed"
        try:
            subs, notes = subdomain_finder.find_subdomains(host, load_wordlist(WORDLIST_PATH))
            results["subdomains"] = subs
            results["notes"] += notes
        except Exception:
            log.warning("Subdomain search failed", exc_info=True)
        try:
            results["emails"] = email_extractor.extract_emails(host)
        except Exception:
            log.warning("Email extraction failed", exc_info=True)

    scan = {"open_ports": [], "services": [], "service_info": "Port scan failed"}
    try:
        scan = port_scanner.scan(host)
    except Exception:
        log.warning("Port scan failed", exc_info=True)
    results["open_ports"] = scan["open_ports"]
    results["service_info"] = scan["service_info"]

    response, is_https = fetch_homepage(host)
    tech_notes = []
    if response is None:
        results["notes"].append("No web service answered on HTTP/HTTPS: header and path checks skipped.")
        results["technologies"] = ["No web service detected"]
    else:
        results["security_headers"] = security_headers.check_security_headers(response.headers, is_https)
        results["technologies"], tech_notes = detect_technologies(response)
        results["remediations"] = [{"header": h["name"], "fix": h["fix"]}
                                   for h in results["security_headers"]
                                   if h["status"] in ("missing", "leak") and h["fix"]]
        results["sensitive_paths"] = check_sensitive_paths(host, is_https)
        if not is_https:
            results["notes"].append("Site is served over plain HTTP.")
    results["risk_notes"] = build_risk_notes(tech_notes, scan["services"])

    grade, score, breakdown = calculate_security_grade(results)
    results.update(security_grade=grade, security_score=score, score_breakdown=breakdown)

    try:
        generate_pdf_report(results, report_path)
    except Exception:
        log.warning("PDF generation failed", exc_info=True)
        results["notes"].append("PDF report could not be generated.")
    return results