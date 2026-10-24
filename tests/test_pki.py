import subprocess

from tailnet_ops import pki
from tests.helpers import TempDirTest


def host_key_and_csr(tmp, curve=True):
    """Make a key and CSR the way the control host does."""
    key = tmp / "server.key"
    if curve:
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-out", str(key)], check=True, capture_output=True)
    else:
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(key)], check=True, capture_output=True)
    csr = subprocess.run(["openssl", "req", "-new", "-key", str(key), "-subj", "/CN=tailnet-ops cn control"],
                         check=True, capture_output=True, text=True).stdout
    return key, csr


def x509_text(pem):
    return subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem, capture_output=True, text=True,
                          check=True).stdout


class PKITest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.pki = self.tmp / "pki"

    def test_ca(self):
        created, pem = pki.ensure_ca(self.pki, "example")
        self.assertTrue(created)
        key, crt = pki.ca_paths(self.pki)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.pki.stat().st_mode & 0o777, 0o700)
        text = x509_text(pem)
        self.assertIn("CA:TRUE", text)
        self.assertIn("tailnet-ops example CA", text)
        self.assertRegex(text, r"prime256v1|P-256")
        again, pem2 = pki.ensure_ca(self.pki, "example")
        self.assertFalse(again)
        self.assertEqual(pem, pem2)
        self.assertEqual(sorted(p.name for p in self.pki.iterdir()), ["ca.crt", "ca.key"])

    def test_sign_server_cert(self):
        pki.ensure_ca(self.pki, "example")
        _key, csr = host_key_and_csr(self.tmp)
        pem = pki.sign(self.pki, csr, ["203.0.113.20", "198.51.100.10"])
        text = x509_text(pem)
        self.assertIn("TLS Web Server Authentication", text)
        self.assertIn("CA:FALSE", text)
        self.assertEqual(pki.cert_ips(pem), ["198.51.100.10", "203.0.113.20"])
        days = subprocess.run(["openssl", "x509", "-noout", "-checkend", str(824 * 86400)], input=pem,
                              capture_output=True, text=True)
        self.assertEqual(days.returncode, 0)
        beyond = subprocess.run(["openssl", "x509", "-noout", "-checkend", str(826 * 86400)], input=pem,
                                capture_output=True, text=True)
        self.assertNotEqual(beyond.returncode, 0)
        verify = subprocess.run(["openssl", "verify", "-CAfile", str(pki.ca_paths(self.pki)[1])], input=pem,
                                capture_output=True, text=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_cert_is_current(self):
        pki.ensure_ca(self.pki, "example")
        _key, csr = host_key_and_csr(self.tmp)
        pem = pki.sign(self.pki, csr, ["198.51.100.10"])
        self.assertTrue(pki.cert_is_current(self.pki, pem, csr, ["198.51.100.10"]))
        self.assertFalse(pki.cert_is_current(self.pki, pem, csr, ["198.51.100.11"]))
        other = self.tmp / "other"
        other.mkdir()
        _k2, csr2 = host_key_and_csr(other)
        self.assertFalse(pki.cert_is_current(self.pki, pem, csr2, ["198.51.100.10"]))

    def test_rejects_non_p256(self):
        pki.ensure_ca(self.pki, "example")
        _key, csr = host_key_and_csr(self.tmp, curve=False)
        with self.assertRaises(pki.PKIError):
            pki.sign(self.pki, csr, ["198.51.100.10"])
