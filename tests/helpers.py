import shutil
import tempfile
import unittest

from webrecon import create_app, findings as F, scoring


def fake_result(target="scanme.nmap.org", with_extras=True):
    fs = [F.make("WR-HDR-003"), F.make("WR-TLS-004", ["self-signed certificate"]),
          F.make("WR-VULN-001", ["cpe:2.3:a:openbsd:openssh:6.6.1p1: 3 CVEs"], severity="high", confidence="tentative")]
    modules = {"ports": "ok", "http": "ok", "tls": "ok", "dns_mail": "ok"}
    data = {"ports": {"tool": "nmap", "open_ports": [22, 80], "text": "PORT SERVICE\n22/tcp ssh", "services": []}}
    if with_extras:
        data.update({
            "dns": {"A": ["45.33.32.156"]}, "whois": {"registrar": "X"}, "emails": ["a@b.com"],
            "subdomains": [{"name": "www." + target, "ips": ["1.2.3.4"], "sources": ["crt.sh"]}],
            "http": {"url": f"https://{target}/", "status": 200, "https": True,
                     "headers": [{"name": "Content-Security-Policy", "status": "missing", "value": "", "description": ""}],
                     "technologies": [{"name": "nginx", "category": "web-server", "version": "1.24.0", "evidence": "server", "cpe": None}],
                     "paths": [{"path": "/robots.txt", "status": 200, "note": "publicly reachable", "kind": "info"}],
                     "redirect_blocked": None},
            "tls": {"reachable": True, "certificate": {"subject": "CN=x", "issuer": "CN=x", "not_after": "2030-01-01",
                    "days_remaining": 400, "key_type": "RSA", "key_bits": 2048, "signature_hash": "sha256", "names": ["x"],
                    "self_signed": True}, "trusted": False, "verify_error": "self-signed", "hostname_match": True,
                    "negotiated": {"version": "TLSv1.3", "cipher": "X"}, "protocols": {"TLSv1.2": True, "TLSv1.0": None},
                    "untested": ["RC4"], "weak_ciphers": []},
            "email_auth": {"has_mx": True, "spf": {"record": "v=spf1 -all", "total_lookups": 0}, "dmarc": None, "dkim_selectors": []},
            "cve": {"cpe:2.3:a:openbsd:openssh:6.6.1p1": {"total": 3, "max_cvss": 7.5,
                    "top": [{"id": "CVE-2020-1", "cvss": 7.5, "summary": "demo", "published": "2020-01-01"}]}},
        })
    return {"schema": 1, "target": target, "ip": "45.33.32.156", "is_ip": False, "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:01:00+00:00", "summary": scoring.assess(fs, modules, True), "findings": fs,
            "modules": {"ports": {"status": "ok", "error": None, "seconds": 1.0}}, "coverage_modules": modules,
            "data": data, "notes": ["demo note"]}


def fake_runner(cfg, db, target, progress):
    progress("ports", 50)
    return fake_result(target)


class AppTestCase(unittest.TestCase):
    overrides = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = {"DATA_DIR": self.tmp, "DISABLE_WORKERS": True, "TESTING": True, "RUNNER": fake_runner}
        cfg.update(self.overrides)
        self.app = create_app(cfg)
        self.wr = self.app.extensions["webrecon"]
        self.client = self.app.test_client()

    def tearDown(self):
        self.wr.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_user(self, name="alice", role="user"):
        from webrecon import auth
        return auth.create_user(self.wr.db, name, "correct-horse-battery", role)

    def csrf(self, client=None):
        import re
        html = (client or self.client).get("/login").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def login(self, name="alice", client=None):
        client = client or self.client
        token = self.csrf(client)
        return client.post("/login", data={"username": name, "password": "correct-horse-battery", "csrf_token": token})

    def token_for(self, name="alice"):
        from webrecon import auth
        uid = self.wr.db.one("SELECT id FROM users WHERE username=?", (name,))["id"]
        return {"Authorization": "Bearer " + auth.create_token(self.wr.db, uid, "t")}
