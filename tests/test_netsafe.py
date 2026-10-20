import http.server
import socketserver
import threading
import unittest

from webrecon import netsafe as n


class NormalizeTests(unittest.TestCase):
    def test_accepts_valid(self):
        self.assertEqual(n.normalize_target("Example.COM"), ("example.com", False))
        self.assertEqual(n.normalize_target("https://example.com/path"), ("example.com", False))
        self.assertEqual(n.normalize_target("8.8.8.8"), ("8.8.8.8", True))
        self.assertEqual(n.normalize_target("[::1]"), ("::1", True))
        self.assertEqual(n.normalize_target("bücher.de"), ("xn--bcher-kva.de", False))

    def test_rejects_hostile_input(self):
        for bad in ["", "localhost", "2130706433", "0x7f.1", "evil.com;ls", "[evil.com](http://evil.com/);ls",
                    "-oN /tmp/x", "a b.com", "http://user@evil.com", "evil.com:22", "ftp://evil.com", "$(id).com",
                    "a" * 400, "evil.com\nx.com", "evil..com", "-evil.com"]:
            with self.subTest(bad=bad), self.assertRaises(n.UnsafeTarget):
                n.normalize_target(bad)


class PublicIpTests(unittest.TestCase):
    def test_classification(self):
        for ip in ["127.0.0.1", "10.0.0.5", "172.16.1.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
                   "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "64:ff9b::7f00:1", "224.0.0.1"]:
            with self.subTest(ip=ip):
                self.assertFalse(n.is_public_ip(ip))
        for ip in ["8.8.8.8", "45.33.32.156", "2001:4860:4860::8888"]:
            with self.subTest(ip=ip):
                self.assertTrue(n.is_public_ip(ip))


class PinningTests(unittest.TestCase):
    def setUp(self):
        self._orig = n.resolve_host

    def tearDown(self):
        n.resolve_host = self._orig

    def test_private_resolution_is_blocked(self):
        n.resolve_host = lambda h: ["10.0.0.1"]
        with self.assertRaises(n.UnsafeTarget):
            n.ScanContext().pin("internal.example.com")

    def test_mixed_resolution_is_blocked(self):
        n.resolve_host = lambda h: ["8.8.8.8", "127.0.0.1"]
        with self.assertRaises(n.UnsafeTarget):
            n.ScanContext().pin("mixed.example.com")

    def test_rebinding_is_ignored_after_first_resolution(self):
        answers = iter([["8.8.8.8"], ["127.0.0.1"]])
        n.resolve_host = lambda h: next(answers)
        ctx = n.ScanContext()
        self.assertEqual(ctx.pin("rebind.example.com"), "8.8.8.8")
        self.assertEqual(ctx.pin("rebind.example.com"), "8.8.8.8")  # second DNS answer is never consulted

    def test_ip_literal_checked(self):
        with self.assertRaises(n.UnsafeTarget):
            n.ScanContext().pin("127.0.0.1")
        self.assertEqual(n.ScanContext().pin("8.8.8.8"), "8.8.8.8")


class FetcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hosts = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cls.hosts.append(self.headers.get("Host"))
                if self.path == "/redirect-internal":
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello")

            def log_message(self, *a):
                pass

        cls.server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_connects_to_pinned_ip_with_original_host_header(self):
        ctx = n.ScanContext(allow_private=True)
        ctx.pins["site.test"] = "127.0.0.1"
        resp = n.SafeFetcher(ctx).get(f"http://site.test:{self.port}/")
        self.assertEqual((resp.status_code, resp.text), (200, "hello"))
        self.assertEqual(self.hosts[-1], f"site.test:{self.port}")

    def test_redirect_to_internal_address_is_refused(self):
        ctx = n.ScanContext(allow_private=False)
        ctx.pins["site.test"] = "127.0.0.1"  # simulate an already pinned public target
        resp = n.SafeFetcher(ctx).get(f"http://site.test:{self.port}/redirect-internal")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("169.254.169.254", resp.redirect_blocked)

    def test_non_http_scheme_rejected(self):
        with self.assertRaises(n.UnsafeTarget):
            n.SafeFetcher(n.ScanContext(True)).get("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
