"""The site CA certificate on a machine other than the one that made it.

`tn control apply` makes the site CA on one machine, and ca.key never leaves it. Any other machine
that runs tn needs only ca.crt, which every control host keeps in /etc/headscale/tls/ca.crt. Read
over SSH as root, it must be the same on every control host that answers, and it must authenticate
their TLS, before tn uses it and keeps a copy in pki/.
"""

import re
import ssl
import urllib.error
import urllib.request

from . import scripts
from .site import ensure_private_dir, write_private

CA_CERT = 'cat "$ETC/tls/ca.crt" 2>/dev/null\n'
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n?", re.S)


def path(site):
    return site.pki_dir / "ca.crt"


def local(site):
    p = path(site)
    return p.read_text() if p.exists() else None


def missing(site, region):
    return (f"no site CA here ({path(site)}): copy ca.crt from the machine that ran `tn control apply` "
            f"(never ca.key), or run `tn control apply {region.name}` if the site has no control plane yet")


def authenticates(pem, url, opener=None):
    """None if pem authenticates url's TLS, else why not. A network error is not the CA's fault."""
    context = ssl.create_default_context(cadata=pem)
    try:
        (opener or urllib.request.urlopen)(f"{url}/health", context=context, timeout=10).close()
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            return str(e.reason)
    except ssl.SSLCertVerificationError as e:
        return str(e)
    return None


def fetch(site, runner, regions, opener=None):
    """(pem, host it came from), or (None, why not)."""
    got = {}
    for r in regions:
        result = runner.run(r.control_host, scripts.wrap(scripts.control_prelude(site, r), CA_CERT),
                            privileged=True, check=False, echo=False)
        m = PEM_RE.search(result.output) if result.rc == 0 else None
        if m:
            got[r.control_host] = m.group().strip() + "\n"
    if not got:
        return None, "no control host answered with it"
    if len(set(got.values())) > 1:
        return None, f"the control hosts keep different CAs ({', '.join(got)})"
    pem = next(iter(got.values()))
    try:
        ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        return None, "what the control host keeps is not a certificate"
    for r in regions:
        problem = authenticates(pem, r.server_url, opener)
        if problem:
            return None, f"the CA from {next(iter(got))} does not authenticate {r.server_url}: {problem}"
    return pem, next(iter(got))


def save(site, pem):
    ensure_private_dir(site.pki_dir)
    write_private(path(site), pem)
