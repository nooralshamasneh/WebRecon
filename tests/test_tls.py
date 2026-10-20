import datetime
import os
import shutil
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from webrecon import netsafe
from webrecon.modules import tls_analysis


class LocalTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=10))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("fake.test")]), False).sign(key, hashes.SHA256()))
        cls.tmp = tempfile.mkdtemp()
        cert_path, key_path = os.path.join(cls.tmp, "c.pem"), os.path.join(cls.tmp, "k.pem")
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cert_path, key_path)
        cls.srv = socket.socket()
        cls.srv.bind(("127.0.0.1", 0))
        cls.srv.listen(32)
        cls.port = cls.srv.getsockname()[1]

        def serve():
            while True:
                try:
                    conn, _ = cls.srv.accept()
                except OSError:
                    return
                try:
                    sctx.wrap_socket(conn, server_side=True).close()
                except Exception:
                    conn.close()
        threading.Thread(target=serve, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def analyze(self, host="fake.test"):
        ctx = netsafe.ScanContext(allow_private=True)
        ctx.pins[host] = "127.0.0.1"
        return tls_analysis.analyze(ctx, host, port=self.port, timeout=3)

    def test_self_signed_certificate_is_reported(self):
        r = self.analyze()
        self.assertTrue(r["reachable"])
        self.assertFalse(r["trusted"])
        self.assertTrue(r["certificate"]["self_signed"])
        self.assertTrue(r["hostname_match"])
        self.assertEqual(r["certificate"]["key_bits"], 2048)
        self.assertTrue(r["protocols"]["TLSv1.2"] and r["protocols"]["TLSv1.3"])
        ids = {f["id"] for f in tls_analysis.tls_findings(r)}
        self.assertIn("WR-TLS-004", ids)
        self.assertIn("WR-TLS-002", ids)  # expires in ~10 days

    def test_hostname_mismatch(self):
        ids = {f["id"] for f in tls_analysis.tls_findings(self.analyze("other.test"))}
        self.assertIn("WR-TLS-003", ids)

    def test_closed_port_does_not_crash(self):
        ctx = netsafe.ScanContext(allow_private=True)
        ctx.pins["fake.test"] = "127.0.0.1"
        r = tls_analysis.analyze(ctx, "fake.test", port=1, timeout=1)
        self.assertFalse(r["reachable"])
        self.assertEqual(tls_analysis.tls_findings(r), [])


if __name__ == "__main__":
    unittest.main()
