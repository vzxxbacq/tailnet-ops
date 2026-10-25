"""The site CA certificate on a machine other than the one that made it.

`tn control apply` makes the site CA on one machine, and ca.key never leaves it. Any other machine
that runs tn needs only ca.crt, which every control host keeps in /etc/headscale/tls/ca.crt. Read
over SSH as root, it must be the same on every control host that answers, and it must authenticate
their TLS, before tn uses it and keeps a copy in pki/. A machine that cannot log in takes a copy
the user prints elsewhere and pastes, checked against the login servers' TLS the same way.
"""

import re
import shlex
import ssl
import urllib.error
import urllib.request

from . import render, scripts
from .site import DEFAULT_SITE_DIR, ensure_private_dir, write_private

CA_CERT = 'cat "$ETC/tls/ca.crt" 2>/dev/null\n'
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n?", re.S)


def path(site):
    return site.pki_dir / "ca.crt"


def local(site):
    p = path(site)
    return p.read_text() if p.exists() else None


def missing(site, region):
    return (f"no site CA here ({path(site)}): copy ca.crt from the machine that ran `tn control apply` "
            f"(never ca.key), or save there what `{commands(region)[0][1]}` prints on {region.control_host}, "
            f"or run tn join in a terminal to paste it, or run `tn control apply {region.name}` if the site has "
            "no control plane yet")


def commands(region):
    """[(where, command)] that print ca.crt by hand. It is public; ca.key never leaves its machine."""
    show = f"sudo cat {render.ETC}/tls/ca.crt"
    return [(f"on {region.control_host}, the Headscale of {region.name}", show),
            (f"or on a machine that can SSH to it (your alias for {region.control_host} there)",
             f"ssh {region.control_host} {shlex.quote(show)}"),
            ("or on the machine that ran `tn control apply`", f"cat {DEFAULT_SITE_DIR}/pki/ca.crt")]


UNREACHABLE = "unreachable"


def _probe(pem, url, opener=None):
    """None if pem authenticates url's TLS, UNREACHABLE on a network error, else why not."""
    context = ssl.create_default_context(cadata=pem)
    try:
        (opener or urllib.request.urlopen)(f"{url}/health", context=context, timeout=10).close()
    except urllib.error.HTTPError as e:
        e.close()
        return None                              # TLS held; only the answer was an error
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            return str(e.reason)
        return UNREACHABLE
    except ssl.SSLCertVerificationError as e:
        return str(e)
    except OSError:
        return UNREACHABLE
    return None


def authenticates(pem, url, opener=None):
    """None if pem authenticates url's TLS, else why not. A network error is not the CA's fault."""
    problem = _probe(pem, url, opener)
    return None if problem == UNREACHABLE else problem


def pasted(text, regions, opener=None):
    """(pem, None) for one pasted certificate that authenticates at least one login server and is
    refused by none, else (None, why not)."""
    found = PEM_RE.findall(text.replace("\r", "").strip() + "\n")
    if len(found) != 1:
        return None, "paste exactly one certificate, from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----"
    pem = found[0].strip() + "\n"
    try:
        ssl.create_default_context(cadata=pem)
    except (ValueError, ssl.SSLError):
        return None, "that is not a certificate"
    reached = 0
    for r in regions:
        problem = _probe(pem, r.server_url, opener)
        if problem == UNREACHABLE:
            continue
        if problem:
            return None, f"it does not authenticate {r.server_url}: {problem}"
        reached += 1
    if not reached:
        return None, (f"cannot reach {', '.join(r.server_url for r in regions)} to check it; "
                      "is Clash (TUN) or another VPN in the way?")
    return pem, None


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
