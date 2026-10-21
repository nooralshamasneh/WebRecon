import json
import time
import unittest

from webrecon import auth, netsafe, ownership
from webrecon.compare import compare_scans
from webrecon.report import build_pdf
from .helpers import AppTestCase, fake_result


class PublicIP:
    """Make scanme.nmap.org 'resolve' to a public address so tests need no DNS."""
    def __enter__(self):
        self.orig = netsafe.resolve_host
        netsafe.resolve_host = lambda host: ["45.33.32.156"]

    def __exit__(self, *a):
        netsafe.resolve_host = self.orig


class AuthWebTests(AppTestCase):
    def test_requires_login(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/api/v1/scans").status_code, 401)

    def test_login_needs_csrf_token(self):
        self.make_user()
        resp = self.client.post("/login", data={"username": "alice", "password": "correct-horse-battery"})
        self.assertEqual(resp.status_code, 400)

    def test_login_and_logout(self):
        self.make_user()
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)
        token = self.csrf()
        self.client.post("/logout", data={"csrf_token": token})
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_wrong_password_and_lockout(self):
        self.make_user()
        token = self.csrf()
        codes = [self.client.post("/login", data={"username": "alice", "password": "wrong", "csrf_token": token}).status_code
                 for _ in range(7)]
        self.assertEqual(codes[0], 401)
        self.assertEqual(codes[-1], 429)

    def test_open_redirect_is_blocked(self):
        self.make_user()
        token = self.csrf()
        resp = self.client.post("/login?next=//evil.com", data={"username": "alice", "password": "correct-horse-battery", "csrf_token": token})
        self.assertNotIn("evil.com", resp.headers["Location"])

    def test_security_headers_present(self):
        h = self.client.get("/login").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertIn("HttpOnly", self.client.get("/login").headers.get("Set-Cookie", "HttpOnly"))

    def test_weak_passwords_rejected(self):
        with self.assertRaises(auth.AuthError):
            auth.create_user(self.wr.db, "bob", "short")


class ScanFlowTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.headers = self.token_for()
        self.ip = PublicIP()
        self.ip.__enter__()

    def tearDown(self):
        self.ip.__exit__()
        super().tearDown()

    def post_scan(self, target, headers=None):
        return self.client.post("/api/v1/scans", json={"target": target}, headers=headers or self.headers)

    def test_public_target_runs_through_queue(self):
        resp = self.post_scan("scanme.nmap.org")
        self.assertEqual(resp.status_code, 202)
        scan_id = resp.get_json()["id"]
        self.assertEqual(self.client.get(f"/api/v1/scans/{scan_id}", headers=self.headers).get_json()["status"], "queued")
        jobs = self.wr.jobs
        row = jobs.claim()
        self.assertEqual(row["id"], scan_id)
        self.assertIsNone(jobs.claim())  # already claimed: no double execution
        jobs.run_one(row)
        data = self.client.get(f"/api/v1/scans/{scan_id}", headers=self.headers).get_json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["result"]["target"], "scanme.nmap.org")
        self.assertTrue(data["grade"])

    def test_failed_scan_is_recorded(self):
        def boom(cfg, db, target, progress):
            raise RuntimeError("kaboom")
        self.wr.jobs.runner = boom
        scan_id = self.post_scan("scanme.nmap.org").get_json()["id"]
        self.wr.jobs.run_one(self.wr.jobs.claim())
        data = self.client.get(f"/api/v1/scans/{scan_id}", headers=self.headers).get_json()
        self.assertEqual(data["status"], "failed")
        self.assertIn("kaboom", data["error"])

    def test_heartbeat_is_refreshed_during_a_long_stage(self):
        seen = {}

        def slow(cfg, db, target, progress):
            time.sleep(0.4)
            seen["hb"] = db.one("SELECT heartbeat FROM scans WHERE status='running'")["heartbeat"]
            return fake_result(target)
        jobs = self.wr.jobs
        jobs.runner, jobs.heartbeat_interval = slow, 0.05
        scan_id = self.post_scan("scanme.nmap.org").get_json()["id"]
        row = jobs.claim()
        self.wr.db.execute("UPDATE scans SET heartbeat = 1 WHERE id = ?", (scan_id,))  # looks stale at first
        jobs.run_one(row)
        self.assertGreater(seen["hb"], time.time() - 5)  # refreshed by the helper thread, not by a stage start

    def test_stale_running_jobs_are_recovered(self):
        scan_id = self.post_scan("scanme.nmap.org").get_json()["id"]
        self.wr.jobs.claim()
        self.wr.db.execute("UPDATE scans SET heartbeat = 1 WHERE id = ?", (scan_id,))
        self.assertEqual(self.wr.jobs.recover(), 1)

    def test_internal_targets_rejected(self):
        for bad in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "localhost", "2130706433", "0x7f.1", "evil.com;ls"]:
            with self.subTest(bad=bad):
                self.assertEqual(self.post_scan(bad).status_code, 400)

    def test_unverified_target_forbidden(self):
        self.assertEqual(self.post_scan("example.org").status_code, 403)

    def test_rate_limit_and_pending_cap(self):
        self.wr.cfg["MAX_PENDING_PER_USER"] = 2
        self.assertEqual(self.post_scan("scanme.nmap.org").status_code, 202)
        self.assertEqual(self.post_scan("scanme.nmap.org").status_code, 202)
        self.assertEqual(self.post_scan("scanme.nmap.org").status_code, 429)

    def test_scan_quota(self):
        self.wr.cfg["RATE_SCANS"] = (1, 3600)
        self.assertEqual(self.post_scan("scanme.nmap.org").status_code, 202)
        self.assertEqual(self.post_scan("scanme.nmap.org").status_code, 429)

    def test_users_cannot_read_each_others_scans(self):
        scan_id = self.post_scan("scanme.nmap.org").get_json()["id"]
        self.make_user("mallory")
        other = self.token_for("mallory")
        self.assertEqual(self.client.get(f"/api/v1/scans/{scan_id}", headers=other).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/v1/scans/{scan_id}", headers=other).status_code, 404)

    def test_web_pages_render_with_full_result(self):
        self.login()
        scan_id = self.post_scan("scanme.nmap.org").get_json()["id"]
        self.wr.jobs.run_one(self.wr.jobs.claim())
        page = self.client.get(f"/scans/{scan_id}")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        for needle in ["Findings (3)", "A02:2025", "tentative", "How the score was calculated", "TLS", "E-mail authentication", "CVE correlation"]:
            self.assertIn(needle, html)
        self.assertNotIn("<script>", html)  # CSP: no inline scripts
        for path in ("/", "/targets", "/account", "/compare"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertTrue(self.client.get(f"/scans/{scan_id}/report.pdf").data.startswith(b"%PDF"))
        self.assertEqual(json.loads(self.client.get(f"/scans/{scan_id}/result.json").data)["target"], "scanme.nmap.org")

    def test_progress_page_while_queued(self):
        self.login()
        scan_id = self.post_scan("scanme.nmap.org").get_json()["id"]
        self.assertIn("progress", self.client.get(f"/scans/{scan_id}").get_data(as_text=True))

    def test_compare_endpoint(self):
        ids = []
        for _ in range(2):
            ids.append(self.post_scan("scanme.nmap.org").get_json()["id"])
            self.wr.jobs.run_one(self.wr.jobs.claim())
        resp = self.client.get(f"/api/v1/compare?a={ids[0]}&b={ids[1]}", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["new_findings"], [])

    def test_csrf_enforced_for_cookie_api_calls(self):
        self.login()
        self.assertEqual(self.client.post("/api/v1/scans", json={"target": "scanme.nmap.org"}).status_code, 400)

    def test_audit_log_written_and_admin_only(self):
        self.post_scan("example.org")
        self.assertEqual(self.client.get("/api/v1/audit", headers=self.headers).status_code, 403)
        self.make_user("root", "admin")
        entries = self.client.get("/api/v1/audit", headers=self.token_for("root")).get_json()["entries"]
        self.assertIn("scan.denied", [e["action"] for e in entries])

    def test_audit_detail_is_sanitised(self):
        from webrecon import audit
        audit.record(self.wr.db, "x", "line1\nFAKE LOG ENTRY")
        self.assertNotIn("\n", audit.recent(self.wr.db, 1)[0]["detail"])

    def test_revoked_token_rejected(self):
        self.wr.db.execute("UPDATE api_tokens SET revoked = 1")
        self.assertEqual(self.client.get("/api/v1/scans", headers=self.headers).status_code, 401)


class OwnershipTests(AppTestCase):
    def test_challenge_verification_and_subdomain_scope(self):
        uid = self.make_user()
        user = {"id": uid}
        cfg = self.wr.cfg
        self.assertFalse(ownership.is_authorized(self.wr.db, user, "shop.example.org", cfg))
        host, token = ownership.create_challenge(self.wr.db, uid, "Example.org")
        vid = self.wr.db.one("SELECT id FROM verifications")["id"]
        orig = (ownership._check_dns, ownership._check_file)
        try:
            ownership._check_dns = lambda h, t: False
            ownership._check_file = lambda h, t, allow_private=False: False
            self.assertFalse(ownership.verify(self.wr.db, vid, uid))
            self.assertFalse(ownership.is_authorized(self.wr.db, user, "example.org", cfg))
            ownership._check_dns = lambda h, t: t == token
            self.assertTrue(ownership.verify(self.wr.db, vid, uid))
        finally:
            ownership._check_dns, ownership._check_file = orig
        self.assertTrue(ownership.is_authorized(self.wr.db, user, "example.org", cfg))
        self.assertTrue(ownership.is_authorized(self.wr.db, user, "shop.example.org", cfg))
        self.assertFalse(ownership.is_authorized(self.wr.db, user, "other.org", cfg))
        self.assertFalse(ownership.is_authorized(self.wr.db, {"id": uid + 1}, "example.org", cfg))

    def test_other_users_cannot_verify_my_challenge(self):
        uid = self.make_user()
        other = self.make_user("mallory")
        ownership.create_challenge(self.wr.db, uid, "example.org")
        vid = self.wr.db.one("SELECT id FROM verifications")["id"]
        self.assertIsNone(ownership.verify(self.wr.db, vid, other))

    def test_expired_verification_is_not_valid(self):
        uid = self.make_user()
        ownership.create_challenge(self.wr.db, uid, "example.org")
        self.wr.db.execute("UPDATE verifications SET status='verified', expires_at='2000-01-01T00:00:00+00:00'")
        self.assertFalse(ownership.is_authorized(self.wr.db, {"id": uid}, "example.org", self.wr.cfg))

    def test_token_file_check_uses_safe_fetcher(self):
        # a private host can never be verified (and therefore never scanned) unless lab mode is on
        self.assertFalse(ownership._check_file("127.0.0.1", "token"))


class ReportAndCompareTests(unittest.TestCase):
    def test_pdf_is_generated_for_full_and_minimal_results(self):
        self.assertTrue(build_pdf(fake_result()).startswith(b"%PDF"))
        r = fake_result(with_extras=False)
        r["summary"] = {"status": "not_assessed", "grade": "N/A", "label": "Not assessed", "score": None, "coverage": 0,
                        "caps": ["no response"], "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "breakdown": []}
        self.assertTrue(build_pdf(r).startswith(b"%PDF"))

    def test_pdf_escapes_markup(self):
        r = fake_result()
        r["findings"][0]["evidence"] = ["<b>injected</b> & <script>"]
        self.assertTrue(build_pdf(r).startswith(b"%PDF"))

    def test_compare(self):
        a, b = fake_result(), fake_result()
        b["findings"] = b["findings"][:1]
        b["data"]["ports"]["open_ports"] = [22, 443]
        diff = compare_scans(a, b)
        self.assertEqual(len(diff["resolved_findings"]), 2)
        self.assertEqual(diff["ports"], {"opened": [443], "closed": [80]})


if __name__ == "__main__":
    unittest.main()
