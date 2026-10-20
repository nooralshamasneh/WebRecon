"""Scan orchestration: runs every module, collects findings, and computes the assessment."""
import ipaddress
import logging
import time
from urllib.parse import urlparse

from . import scoring
from .db import utcnow
from .findings import SEVERITIES, make
from .modules import (dns_lookup, email_auth, email_extractor, nvd, port_scanner, security_headers,
                      sensitive_paths, subdomain_finder, tech_fingerprint, tls_analysis, whois_lookup)
from .netsafe import SafeFetcher, ScanContext, normalize_target

log = logging.getLogger("webrecon.scanner")
WEB_PORTS = {80, 443, 8080, 8443}
PROBE_ORIGIN = "https://webrecon-probe.invalid"


class ScanTimeout(Exception):
    pass


def load_wordlist(path, limit):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            words = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError:
        return []
    return words[:limit]


def run_scan(cfg, db, target, progress=lambda stage, pct: None):
    host, is_ip = normalize_target(target)
    ctx = ScanContext(cfg["ALLOW_PRIVATE"])
    ip = ctx.pin(host)
    fetcher = SafeFetcher(ctx)
    deadline = time.monotonic() + cfg["SCAN_TIMEOUT"]
    started = utcnow()

    findings, notes, data = [], [], {}
    status = {}

    def stage(name, pct, fn):
        progress(name, pct)
        if time.monotonic() > deadline:
            raise ScanTimeout("The scan exceeded the time limit.")
        t0 = time.monotonic()
        try:
            value = fn()
            status[name] = {"status": "ok", "error": None, "seconds": round(time.monotonic() - t0, 1)}
            return value
        except Exception as exc:
            log.warning("module %s failed", name, exc_info=True)
            status[name] = {"status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:160]}",
                            "seconds": round(time.monotonic() - t0, 1)}
            return None


    if not is_ip:
        def dns_stage():
            data["dns"] = dns_lookup.get_dns_records(host)
            data["whois"] = whois_lookup.get_whois(host)
            days = data["whois"].get("days_to_expiry")
            if days is not None and days <= 30:
                findings.append(make("WR-DNS-002", [f"Expires in {days} days ({data['whois'].get('expires')})"]))
        stage("dns", 10, dns_stage)

        def sub_stage():
            words = load_wordlist(cfg["WORDLIST"], cfg["WORDLIST_LIMIT"])
            res = subdomain_finder.find_subdomains(host, words, passive=cfg["PASSIVE_SOURCES"])
            data["subdomains"] = res["subdomains"]
            notes.extend(res["notes"])
            private = []
            for sub in res["subdomains"]:
                if any(not ipaddress.ip_address(i).is_global for i in sub["ips"]):
                    private.append(f"{sub['name']} -> {', '.join(sub['ips'])}")
            if private:
                findings.append(make("WR-DNS-001", private[:10]))
        stage("subdomains", 30, sub_stage)

    def ports_stage():
        data["ports"] = port_scanner.scan(ip)
        findings.extend(port_scanner.port_findings(data["ports"]["open_ports"]))
    stage("ports", 50, ports_stage)
    open_ports = (data.get("ports") or {}).get("open_ports", [])

    web = {"resp": None, "https": False, "base": None}

    def http_stage():
        for scheme in ("https", "http"):
            try:
                resp = fetcher.get(f"{scheme}://{host}/")
            except Exception:
                continue
            web.update(resp=resp, https=resp.url.startswith("https://"))
            break
        resp = web["resp"]
        if resp is None:
            return
        parts = urlparse(resp.url)
        web["base"] = f"{parts.scheme}://{parts.netloc}"
        cors = None
        try:
            cors = fetcher.get(resp.url, headers={"Origin": PROBE_ORIGIN}, follow=False, max_bytes=50_000).headers
        except Exception:
            pass
        cookies = security_headers.set_cookie_headers(resp)
        analysis = security_headers.analyze(resp.headers, cookies, web["https"], cors, PROBE_ORIGIN)
        findings.extend(analysis["findings"])
        techs = tech_fingerprint.detect(resp.headers, cookies, resp.text)
        if not web["https"]:
            findings.append(make("WR-HTTP-001", [f"Final URL: {resp.url}"]))
        else:
            try:
                plain = fetcher.get(f"http://{host}/", follow=False, max_bytes=50_000)
                if plain.status_code == 200:
                    findings.append(make("WR-HTTP-002", ["http:// answered 200 instead of redirecting"]))
            except Exception:
                pass
        paths = sensitive_paths.check(fetcher, web["base"])
        findings.extend(paths["findings"])
        data["http"] = {"url": resp.url, "status": resp.status_code, "https": web["https"],
                        "headers": analysis["table"], "technologies": techs, "paths": paths["paths"],
                        "redirect_blocked": getattr(resp, "redirect_blocked", None)}
        if data["http"]["redirect_blocked"]:
            notes.append(f"A redirect was not followed: {data['http']['redirect_blocked']}")
        if not is_ip:
            data["emails"] = email_extractor.extract_emails(fetcher, web["base"])
    stage("http", 70, http_stage)

    tls_applicable = 443 in open_ports or web["https"]
    if tls_applicable:
        def tls_stage():
            data["tls"] = tls_analysis.analyze(ctx, host)
            findings.extend(tls_analysis.tls_findings(data["tls"]))
            if not data["tls"]["reachable"]:
                raise RuntimeError(data["tls"].get("error") or "TLS handshake failed")
        stage("tls", 80, tls_stage)

    if not is_ip:
        def mail_stage():
            res = email_auth.analyze(host)
            data["email_auth"] = res["info"]
            findings.extend(res["findings"])
        stage("email_auth", 86, mail_stage)

    if cfg["NVD_ENABLED"]:
        cpes = []
        for svc in (data.get("ports") or {}).get("services", []):
            cpes += [c for c in (nvd.cpe_from_nmap(u) for u in svc.get("cpe", [])) if c]
        cpes += [t["cpe"] for t in (data.get("http") or {}).get("technologies", []) if t.get("cpe")]
        if cpes:
            def cve_stage():
                res = nvd.correlate(cpes, db=db, api_key=cfg["NVD_API_KEY"])
                data["cve"] = res["results"]
                findings.extend(res["findings"])
                if res["errors"]:
                    notes.append("NVD lookup incomplete: " + "; ".join(res["errors"][:3]))
            stage("cve", 95, cve_stage)

    if web["resp"] is not None:
        http_status = "ok"
    elif WEB_PORTS & set(open_ports):
        http_status = "failed"
    else:
        http_status = "na"
    modules = {
        "ports": "ok" if status.get("ports", {}).get("status") == "ok" else "failed",
        "http": http_status,
        "tls": ("ok" if status.get("tls", {}).get("status") == "ok" else "failed") if tls_applicable else "na",
        "dns_mail": "na" if is_ip else ("ok" if status.get("email_auth", {}).get("status") == "ok" else "failed"),
    }
    responded = bool(open_ports) or web["resp"] is not None or bool((data.get("tls") or {}).get("reachable"))
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["id"]))
    summary = scoring.assess(findings, modules, responded)
    if not responded:
        notes.append("No open port or web service answered, so no grade can be given.")

    progress("done", 100)
    return {"schema": 1, "target": host, "ip": ip, "is_ip": is_ip, "started_at": started, "finished_at": utcnow(),
            "summary": summary, "findings": findings, "modules": status, "coverage_modules": modules,
            "data": data, "notes": notes}
