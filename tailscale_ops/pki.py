"""The site CA. Its key never leaves the site directory; server keys never reach it."""

import ipaddress
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

from . import pins
from .site import ensure_private_dir, write_private


class PKIError(Exception):
    pass


def _openssl(*args, input=None):
    p = subprocess.run(["openssl", *args], input=input, capture_output=True, text=True)
    if p.returncode != 0:
        raise PKIError(f"openssl {args[0]} failed: {p.stderr.strip()}")
    return p.stdout


def ca_paths(pki_dir):
    pki_dir = Path(pki_dir)
    return pki_dir / "ca.key", pki_dir / "ca.crt"


def ca_exists(pki_dir):
    key, crt = ca_paths(pki_dir)
    return key.exists() and crt.exists()


CA_CONF = """[req]
distinguished_name = dn
prompt = no
[dn]
CN = {cn}
[tn_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""

SERVER_EXT = """[tn_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = {sans}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def ensure_ca(pki_dir, site_name):
    """Create the site CA (EC P-256, 10 years) unless it exists. Returns (created, ca_pem)."""
    key, crt = ca_paths(pki_dir)
    if key.exists() and crt.exists():
        return False, crt.read_text()
    if key.exists() or crt.exists():
        raise PKIError(f"half a CA in {pki_dir}: need both ca.key and ca.crt")
    ensure_private_dir(pki_dir)
    with tempfile.TemporaryDirectory(dir=pki_dir) as tmp:
        conf = Path(tmp) / "ca.cnf"
        conf.write_text(CA_CONF.format(cn=f"tailnet-ops {site_name} CA"))
        tmp_key = Path(tmp) / "ca.key"
        old = os.umask(0o077)
        try:
            _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(tmp_key))
        finally:
            os.umask(old)
        pem = _openssl(
            "req", "-x509", "-new", "-key", str(tmp_key), "-sha256", "-days", str(pins.CA_DAYS),
            "-config", str(conf), "-extensions", "tn_ca",
        )
        write_private(key, tmp_key.read_bytes())
    write_private(crt, pem)
    return True, pem


def csr_public_key(csr_pem):
    _openssl("req", "-noout", "-verify", input=csr_pem)
    text = _openssl("req", "-noout", "-text", input=csr_pem)
    if "prime256v1" not in text and "P-256" not in text:
        raise PKIError("the CSR key is not EC P-256")
    return _openssl("req", "-noout", "-pubkey", input=csr_pem)


def sign(pki_dir, csr_pem, ips, days=pins.SERVER_CERT_DAYS):
    """Sign a server CSR for the given IP SANs. Returns the certificate PEM."""
    for ip in ips:
        ipaddress.ip_address(ip)
    csr_public_key(csr_pem)
    key, crt = ca_paths(pki_dir)
    with tempfile.TemporaryDirectory(dir=pki_dir) as tmp:
        csr = Path(tmp) / "server.csr"
        csr.write_text(csr_pem)
        ext = Path(tmp) / "server.ext"
        ext.write_text(SERVER_EXT.format(sans=", ".join(f"IP:{ip}" for ip in ips)))
        return _openssl(
            "x509", "-req", "-in", str(csr), "-CA", str(crt), "-CAkey", str(key),
            "-set_serial", "0x" + secrets.token_hex(16), "-days", str(days), "-sha256",
            "-extfile", str(ext), "-extensions", "tn_server",
        )


def cert_ips(cert_pem):
    text = _openssl("x509", "-noout", "-text", input=cert_pem)
    m = re.search(r"X509v3 Subject Alternative Name:.*?\n\s*(.+)", text)
    if not m:
        return []
    return sorted(part.strip()[len("IP Address:"):] for part in m.group(1).split(",") if "IP Address:" in part)


def cert_is_current(pki_dir, cert_pem, csr_pem, ips, renew_days=pins.CERT_RENEW_DAYS):
    """True when cert_pem is ours, for the same key and SANs, and not close to expiry."""
    _key, crt = ca_paths(pki_dir)
    with tempfile.TemporaryDirectory(dir=pki_dir) as tmp:
        cert = Path(tmp) / "server.crt"
        cert.write_text(cert_pem)
        if subprocess.run(["openssl", "verify", "-CAfile", str(crt), str(cert)], capture_output=True).returncode:
            return False
        if subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-checkend", str(renew_days * 86400)],
            capture_output=True,
        ).returncode:
            return False
    if cert_ips(cert_pem) != sorted(ips):
        return False
    return _openssl("x509", "-noout", "-pubkey", input=cert_pem) == csr_public_key(csr_pem)
