import json
import tempfile
import unittest
from pathlib import Path

from webrecon import dnsutil, findings as F, scoring
from webrecon.db import Database
from webrecon.modules import (email_auth, nvd, port_scanner, security_headers, sensitive_paths, subdomain_finder,
                              tech_fingerprint, tls_analysis)


class FakeResp:
    def __init__(self, status=200, text="", content=None):
        self.status_code, self.text = status, text
        self.content = content if content is not None else text.encode()


class FakeFetcher:
    def __init__(self, routes):
        self.routes = routes

    def get(self, url, **kw):
        path = url.split("/", 3)[-1]
        return self.routes.get(path, FakeResp(404, "Not found page"))


class HeaderTests(unittest.TestCase):
    def ids(self, headers, cookies=(), https=True, cors=None):
        return {f["id"] for f in security_headers.analyze(headers, list(cookies), https, cors)["findings"]}

    def test_good_configuration(self):
        h = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
             "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}
        self.assertEqual(self.ids(h), set())

    def test_missing_and_weak(self):
        ids = self.ids({"Server": "nginx/1.24.0", "Strict-Transport-Security": "max-age=60",
                        "Content-Security-Policy": "script-src 'unsafe-inline'"})
        self.assertTrue({"WR-HDR-002", "WR-HDR-004", "WR-HDR-005", "WR-HDR-006", "WR-HDR-007", "WR-HDR-009"} <= ids)

    def test_hsts_not_required_over_http(self):
        self.assertNotIn("WR-HDR-001", self.ids({}, https=False))
        self.assertIn("WR-HDR-001", self.ids({}, https=True))

    def test_cookie_flags(self):
        ids = self.ids({}, ["sid=1; Path=/"])
        self.assertTrue({"WR-HDR-010", "WR-HDR-011", "WR-HDR-012"} <= ids)
        self.assertFalse({"WR-HDR-010", "WR-HDR-011", "WR-HDR-012"} & self.ids({}, ["sid=1; Secure; HttpOnly; SameSite=Lax"]))

    def test_cors(self):
        probe = "https://webrecon-probe.invalid"
        res = security_headers.analyze({}, [], True, {"Access-Control-Allow-Origin": probe, "Access-Control-Allow-Credentials": "true"}, probe)
        cors = [f for f in res["findings"] if f["id"] == "WR-HDR-013"][0]
        self.assertEqual(cors["severity"], "high")


class PathTests(unittest.TestCase):
    def test_detects_real_exposures_only(self):
        fetcher = FakeFetcher({".git/HEAD": FakeResp(200, "ref: refs/heads/main\n"), ".env": FakeResp(200, "DB_PASSWORD=secret\n"),
                               "admin/": FakeResp(403, "Forbidden"), "robots.txt": FakeResp(200, "User-agent: *")})
        res = sensitive_paths.check(fetcher, "https://x.test")
        ids = {f["id"] for f in res["findings"]}
        self.assertEqual(ids, {"WR-PATH-001", "WR-PATH-002"})
        self.assertTrue(any(p["path"] == "/robots.txt" for p in res["paths"]))

    def test_soft_404_catch_all_is_ignored(self):
        page = FakeResp(200, "<html>Welcome home</html>")
        class CatchAll:
            def get(self, url, **kw):
                return page
        res = sensitive_paths.check(CatchAll(), "https://x.test")
        self.assertEqual(res["findings"], [])

    def test_git_403_is_not_a_finding(self):
        res = sensitive_paths.check(FakeFetcher({".git/HEAD": FakeResp(403, "Forbidden")}), "https://x.test")
        self.assertEqual(res["findings"], [])


class FingerprintTests(unittest.TestCase):
    def test_versions_and_cpe(self):
        html = '<meta name="generator" content="WordPress 6.4.2"><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>'
        found = {t["name"]: t for t in tech_fingerprint.detect({"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1.2"}, [], html)}
        self.assertEqual(found["nginx"]["cpe"], "cpe:2.3:a:nginx:nginx:1.24.0")
        self.assertEqual(found["WordPress"]["version"], "6.4.2")
        self.assertEqual(found["jQuery"]["version"], "3.6.0")
        self.assertEqual(found["PHP"]["cpe"], "cpe:2.3:a:php:php:8.1.2")

    def test_no_react_false_positive_from_text(self):
        names = [t["name"] for t in tech_fingerprint.detect({}, [], "<p>We react quickly to customer needs</p>")]
        self.assertNotIn("React", names)


class SubdomainParserTests(unittest.TestCase):
    def test_parsers(self):
        d = "example.com"
        self.assertEqual(subdomain_finder.parse_crtsh([{"name_value": "a.example.com\n*.example.com\nevil.com"}], d), {"a.example.com"})
        self.assertEqual(subdomain_finder.parse_certspotter([{"dns_names": ["b.example.com", "example.com"]}], d), {"b.example.com"})
        self.assertEqual(subdomain_finder.parse_hackertarget("c.example.com,1.2.3.4\nerror check", d), {"c.example.com"})
        self.assertEqual(subdomain_finder.parse_otx({"passive_dns": [{"hostname": "d.example.com"}]}, d), {"d.example.com"})
        self.assertEqual(subdomain_finder.parse_anubis(["e.example.com", "x.other.com"], d), {"e.example.com"})

    def test_wildcard_filtering(self):
        orig = subdomain_finder._resolve
        subdomain_finder._resolve = lambda name: ["1.1.1.1"] if name == "real.example.com" else ["9.9.9.9"]
        try:
            res = subdomain_finder.find_subdomains("example.com", ["real", "fake"], passive=False)
        finally:
            subdomain_finder._resolve = orig
        self.assertEqual([s["name"] for s in res["subdomains"]], ["real.example.com"])
        self.assertTrue(any("Wildcard" in n for n in res["notes"]))


NMAP_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="6.6.1p1"><cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe></service></port>
<port protocol="tcp" portid="23"><state state="closed"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.7"/></port>
</ports></host></nmaprun>"""


class PortTests(unittest.TestCase):
    def test_parse_xml(self):
        services = port_scanner.parse_nmap_xml(NMAP_XML)
        self.assertEqual([s["port"] for s in services], [22, 80])
        self.assertEqual(services[0]["cpe"], ["cpe:/a:openbsd:openssh:6.6.1p1"])

    def test_risky_ports(self):
        ids = {f["id"] for f in port_scanner.port_findings([21, 22, 80, 3306, 3389, 23])}
        self.assertEqual(ids, {"WR-PORT-001", "WR-PORT-002", "WR-PORT-003", "WR-PORT-004"})


class NvdTests(unittest.TestCase):
    SAMPLE = {"vulnerabilities": [
        {"cve": {"id": "CVE-2020-0001", "published": "2020-01-01T00:00:00", "descriptions": [{"lang": "en", "value": "bad bug"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-2019-0002", "descriptions": [], "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.3}}]}}}]}

    def test_parse_and_severity(self):
        parsed = nvd.parse_nvd(self.SAMPLE)
        self.assertEqual((parsed["total"], parsed["max_cvss"], parsed["top"][0]["id"]), (2, 9.8, "CVE-2020-0001"))
        self.assertEqual([nvd.severity_for(x) for x in (9.8, 7.5, 5, 2)], ["critical", "high", "medium", "low"])

    def test_cpe_conversion(self):
        self.assertEqual(nvd.cpe_from_nmap("cpe:/a:openbsd:openssh:6.6.1p1"), "cpe:2.3:a:openbsd:openssh:6.6.1p1")
        self.assertIsNone(nvd.cpe_from_nmap("cpe:/o:linux:linux_kernel"))
        self.assertIsNone(nvd.cpe_from_nmap("cpe:/a:vendor:product"))

    def test_correlate_creates_tentative_finding(self):
        res = nvd.correlate(["cpe:2.3:a:x:y:1.0"], lookup_fn=lambda cpe, **kw: nvd.parse_nvd(self.SAMPLE))
        f = res["findings"][0]
        self.assertEqual((f["id"], f["severity"], f["confidence"]), ("WR-VULN-001", "critical", "tentative"))

    def test_cache_hit_avoids_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.db")
            db.execute("INSERT INTO cve_cache(key, fetched_at, payload) VALUES (?,?,?)",
                       ("cpe:2.3:a:x:y:1.0", 1000.0, json.dumps({"total": 0, "top": [], "max_cvss": None})))
            self.assertEqual(nvd.lookup("cpe:2.3:a:x:y:1.0", db=db, now=1100.0)["total"], 0)
            db.close()


class EmailAuthTests(unittest.TestCase):
    def setUp(self):
        self.orig = (dnsutil.lookup, dnsutil.txt_records)

    def tearDown(self):
        dnsutil.lookup, dnsutil.txt_records = self.orig

    def use(self, records):
        dnsutil.lookup = lambda n, t, lifetime=5: records.get(n, {}).get(t, [])
        dnsutil.txt_records = lambda n: dnsutil.lookup(n, "TXT")

    def test_weak_configuration(self):
        self.use({"example.com": {"TXT": ["v=spf1 +all"], "MX": ["10 mx.example.com"]}, "_dmarc.example.com": {"TXT": ["v=DMARC1; p=none"]}})
        ids = {f["id"] for f in email_auth.analyze("example.com")["findings"]}
        self.assertTrue({"WR-MAIL-002", "WR-MAIL-007", "WR-MAIL-008"} <= ids)

    def test_good_configuration(self):
        self.use({"example.com": {"TXT": ["v=spf1 mx -all"], "MX": ["10 mx.example.com"]},
                  "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]},
                  "google._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=abc"]}})
        self.assertEqual(email_auth.analyze("example.com")["findings"], [])

    def test_missing_everything_and_no_mx_is_lower_severity(self):
        self.use({})
        res = {f["id"]: f["severity"] for f in email_auth.analyze("example.com")["findings"]}
        self.assertEqual((res["WR-MAIL-001"], res["WR-MAIL-006"]), ("low", "low"))

    def test_spf_lookup_limit(self):
        includes = " ".join(f"include:s{i}.example.com" for i in range(11))
        self.use({"example.com": {"TXT": [f"v=spf1 {includes} -all"], "MX": ["10 m"]}})
        self.assertIn("WR-MAIL-004", {f["id"] for f in email_auth.analyze("example.com")["findings"]})

    def test_multiple_spf(self):
        self.use({"example.com": {"TXT": ["v=spf1 -all", "v=spf1 mx -all"]}})
        self.assertIn("WR-MAIL-005", {f["id"] for f in email_auth.analyze("example.com")["findings"]})


class ScoringTests(unittest.TestCase):
    OK = {"ports": "ok", "http": "ok", "tls": "ok", "dns_mail": "ok"}

    def test_unresponsive_target_is_not_graded(self):
        s = scoring.assess([], {"ports": "ok", "http": "na", "tls": "na", "dns_mail": "ok"}, responded=False)
        self.assertEqual((s["grade"], s["score"], s["status"]), ("N/A", None, "not_assessed"))

    def test_clean_target_gets_a(self):
        self.assertEqual(scoring.assess([], self.OK, True)["grade"], "A")

    def test_critical_caps_grade(self):
        s = scoring.assess([F.make("WR-PATH-001")], self.OK, True)
        self.assertEqual((s["score"], s["grade"]), (70, "D"))

    def test_high_caps_grade_at_c(self):
        self.assertEqual(scoring.assess([F.make("WR-TLS-003")], self.OK, True)["grade"], "C")

    def test_tentative_counts_half(self):
        f = F.make("WR-VULN-001", severity="high", confidence="tentative")
        self.assertEqual(scoring.assess([f], self.OK, True)["score"], 92)  # 100 - 7.5, rounded down

    def test_low_coverage_caps_at_b(self):
        s = scoring.assess([], {"ports": "ok", "http": "failed", "tls": "ok", "dns_mail": "ok"}, True)
        self.assertEqual((s["coverage"], s["grade"]), (70, "B"))

    def test_every_catalog_entry_is_mapped(self):
        for fid, entry in F.CATALOG.items():
            self.assertIn(entry["owasp"], F.OWASP_TOP10, fid)
            self.assertIn(entry["severity"], F.SEVERITIES, fid)


class TlsHelperTests(unittest.TestCase):
    def test_hostname_matching(self):
        self.assertTrue(tls_analysis.hostname_matches(["*.example.com"], "a.example.com"))
        self.assertFalse(tls_analysis.hostname_matches(["*.example.com"], "a.b.example.com"))
        self.assertFalse(tls_analysis.hostname_matches(["*.example.com"], "example.com"))
        self.assertTrue(tls_analysis.hostname_matches(["Example.com"], "example.com"))

    def test_findings_from_result(self):
        r = {"reachable": True, "certificate": {"days_remaining": -3, "not_after": "x", "key_type": "RSA", "key_bits": 1024,
             "signature_hash": "sha1", "names": ["other.com"], "self_signed": False}, "hostname_match": False, "trusted": False,
             "verify_error": "unable to get local issuer", "protocols": {"TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": None},
             "weak_ciphers": ["3DES"]}
        ids = {f["id"] for f in tls_analysis.tls_findings(r)}
        self.assertEqual(ids, {"WR-TLS-001", "WR-TLS-003", "WR-TLS-004", "WR-TLS-005", "WR-TLS-007", "WR-TLS-008", "WR-TLS-009"})


if __name__ == "__main__":
    unittest.main()
