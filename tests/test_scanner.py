import shutil
import tempfile
import unittest

from webrecon import netsafe, scanner
from webrecon.config import load_config
from webrecon.db import Database
from webrecon.modules import (dns_lookup, email_auth, email_extractor, port_scanner, subdomain_finder, tls_analysis,
                              whois_lookup)


class FakeResp:
    def __init__(self, url, status=200, headers=None, text="<html></html>"):
        self.url, self.status_code, self.headers, self.text = url, status, headers or {}, text
        self.content = text.encode()
        self.redirect_blocked = None


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = load_config({"DATA_DIR": self.tmp, "NVD_ENABLED": False, "PASSIVE_SOURCES": False})
        self.db = Database(self.cfg["DB_PATH"])
        self.saved = {}
        self.patch(netsafe, "resolve_host", lambda h: ["93.184.216.34"])

    def tearDown(self):
        for (obj, name), value in self.saved.items():
            setattr(obj, name, value)
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def patch(self, obj, name, value):
        self.saved.setdefault((obj, name), getattr(obj, name))
        setattr(obj, name, value)

    def stub_domain_modules(self):
        self.patch(dns_lookup, "get_dns_records", lambda d: {"A": ["93.184.216.34"]})
        self.patch(whois_lookup, "get_whois", lambda d: {"registrar": "X", "days_to_expiry": 10, "expires": "soon"})
        self.patch(subdomain_finder, "find_subdomains", lambda d, w, passive=True: {"subdomains": [
            {"name": "internal.example.com", "ips": ["10.0.0.5"], "sources": ["wordlist"]}], "notes": []})
        self.patch(email_auth, "analyze", lambda d: {"info": {"has_mx": False, "spf": None, "dmarc": None, "dkim_selectors": []}, "findings": []})

    def test_unresponsive_target_is_not_graded(self):
        self.patch(port_scanner, "scan", lambda ip: {"tool": "socket", "open_ports": [], "services": [], "text": ""})

        class Down:
            def __init__(self, ctx, **kw): pass
            def get(self, *a, **kw): raise ConnectionError("down")
        self.patch(scanner, "SafeFetcher", Down)
        result = scanner.run_scan(self.cfg, self.db, "8.8.8.8")
        self.assertEqual(result["summary"]["status"], "not_assessed")
        self.assertEqual(result["summary"]["grade"], "N/A")
        self.assertIsNone(result["summary"]["score"])

    def test_domain_scan_collects_findings_from_all_modules(self):
        self.stub_domain_modules()
        self.patch(port_scanner, "scan", lambda ip: {"tool": "nmap", "open_ports": [21, 443], "text": "x", "services": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "product": "", "version": "", "extrainfo": "", "cpe": []}]})
        seen_pins = []

        class Fake:
            def __init__(self, ctx, **kw): self.ctx = ctx
            def get(self, url, headers=None, follow=True, max_bytes=0):
                seen_pins.append(self.ctx.pin("example.com"))
                if url.startswith("http://"):
                    return FakeResp(url, 200)
                if url.endswith("/.git/HEAD"):
                    return FakeResp(url, 200, text="ref: refs/heads/main")
                return FakeResp(url, 200, {"Server": "nginx/1.24.0"}, "<html>contact a@example.com</html>")
        self.patch(scanner, "SafeFetcher", Fake)
        self.patch(tls_analysis, "analyze", lambda ctx, host: {"reachable": True, "certificate": None, "protocols": {}, "weak_ciphers": []})
        self.patch(email_extractor, "extract_emails", lambda f, b: ["a@example.com"])
        progress = []
        result = scanner.run_scan(self.cfg, self.db, "https://Example.com/", lambda s, p: progress.append((s, p)))
        ids = {f["id"] for f in result["findings"]}
        self.assertTrue({"WR-PORT-002", "WR-HDR-003", "WR-HDR-009", "WR-HTTP-002", "WR-DNS-001", "WR-DNS-002"} <= ids)
        self.assertEqual(result["summary"]["status"], "assessed")
        self.assertNotEqual(result["summary"]["grade"], "A")
        self.assertEqual(set(seen_pins), {"93.184.216.34"})  # one pinned IP for the whole scan
        self.assertEqual(progress[-1], ("done", 100))
        self.assertEqual(result["modules"]["ports"]["status"], "ok")
        sev_order = [f["severity"] for f in result["findings"]]
        self.assertEqual(sev_order, sorted(sev_order, key=["critical", "high", "medium", "low", "info"].index))

    def test_module_failure_is_isolated_and_lowers_coverage(self):
        self.stub_domain_modules()
        self.patch(port_scanner, "scan", lambda ip: {"tool": "nmap", "open_ports": [443], "text": "x", "services": []})

        class Fake:
            def __init__(self, ctx, **kw): pass
            def get(self, url, **kw): return FakeResp(url, 200, {"Strict-Transport-Security": "max-age=31536000"})
        self.patch(scanner, "SafeFetcher", Fake)

        def broken(ctx, host):
            raise RuntimeError("handshake exploded")
        self.patch(tls_analysis, "analyze", broken)
        result = scanner.run_scan(self.cfg, self.db, "example.com")
        self.assertEqual(result["modules"]["tls"]["status"], "failed")
        self.assertEqual(result["coverage_modules"]["tls"], "failed")
        self.assertLess(result["summary"]["coverage"], 100)

    def test_private_target_rejected(self):
        with self.assertRaises(netsafe.UnsafeTarget):
            scanner.run_scan(self.cfg, self.db, "127.0.0.1")

    def test_real_pipeline_offline(self):
        """Documentation/reserved ranges are refused before any packet is sent."""
        with self.assertRaises(netsafe.UnsafeTarget):
            scanner.run_scan(self.cfg, self.db, "192.0.2.1")  # documentation range is not routable: refused


if __name__ == "__main__":
    unittest.main()
