"""What a Mac with the Tailscale app (the standalone build) needs, as files it reads.

- A configuration profile (.mobileconfig): the site CA as a trusted root, and the app's system
  policies: its name, subnet routes and DNS always on, start at login, and who manages it. It
  holds no secret.
  It cannot name the login servers: the LoginURL policy would force every account onto one
  server, and a personal device needs an account in each region.
- A block to paste into Terminal: the app's own CLI logs in to each region as an account named
  after the region, with a single-use key, and ends on the home region.
- A Clash Verge extension script, so that Clash in TUN mode leaves the tailnet alone.
"""

import hashlib
import plistlib
import shlex
import ssl
import uuid

from . import pins
from .privacy import CGNAT

APP = "/Applications/Tailscale.app"
APP_CLI = f"{APP}/Contents/MacOS/Tailscale"
APP_DOMAIN = "io.tailscale.ipn.macsys"           # the standalone build's policy domain
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
NETWORK_EXTENSION = "io.tailscale.ipn.macsys.network-extension"


def identifier(site, name):
    return f"tailnet-ops.{site.name.lower().replace(' ', '-')}.{name}"


def _uuid(ident):
    """Stable, so that installing a new profile for the same device replaces the old one."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, ident)).upper()


def servers(site):
    return [(r.name, r.server_url) for r in site.regions.values()]


def profile(site, name, label, ca_pem):
    """The .mobileconfig as bytes."""
    ident = identifier(site, name)
    where = "; ".join(f"{region} {url}" for region, url in servers(site))
    ca = {
        "PayloadType": "com.apple.security.root",
        "PayloadIdentifier": f"{ident}.ca",
        "PayloadUUID": _uuid(f"{ident}.ca"),
        "PayloadVersion": 1,
        "PayloadDisplayName": f"tailnet-ops {site.name} CA",
        "PayloadCertificateFileName": f"tailnet-ops-{site.name}-ca.cer",
        "PayloadContent": ssl.PEM_cert_to_DER_cert(ca_pem),
    }
    app = {
        "PayloadType": APP_DOMAIN,
        "PayloadIdentifier": f"{ident}.tailscale",
        "PayloadUUID": _uuid(f"{ident}.tailscale"),
        "PayloadVersion": 1,
        "PayloadEnabled": True,
        "PayloadDisplayName": "Tailscale settings",
        "Hostname": label,
        "UseTailscaleSubnets": "always",
        "UseTailscaleDNSSettings": "always",
        "TailscaleStartOnLogin": True,
        "AppIntroShown": True,                   # no welcome window: tn logs the accounts in
        "ManagedByOrganizationName": f"tailnet-ops {site.name}",
        "ManagedByCaption": f"Servers: {where}. Switch region in the account menu.",
    }
    top = {
        "PayloadType": "Configuration",
        "PayloadIdentifier": ident,
        "PayloadUUID": _uuid(ident),
        "PayloadVersion": 1,
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": False,
        "PayloadDisplayName": f"tailnet-ops {site.name}: {name}",
        "PayloadDescription": (f"Trusts the {site.name} site CA for TLS and sets up the Tailscale app as {label}: "
                               f"subnet routes and DNS on. Login servers: {where}."),
        "PayloadContent": [ca, app],
    }
    return plistlib.dumps(top, sort_keys=False)


def app_lines():
    """Shell lines that make the Tailscale app ready: install the pinned official package when the app
    is missing (checked against its sha256 and its signer), open it, and wait until it answers, which
    it does once you allow its system extension and VPN configuration."""
    return [
        f"T={shlex.quote(APP_CLI)}",
        'if [ ! -x "$T" ]; then',
        f'  echo "Installing Tailscale {pins.TAILSCALE_APP_VERSION}, the official package signed by Tailscale Inc.; '
        'sudo asks for your password."',
        "  d=$(mktemp -d /tmp/tn-tailscale-app.XXXXXX)",
        f'  curl -fsSL --max-time 600 -o "$d/Tailscale.pkg" {shlex.quote(pins.TAILSCALE_APP_URL)} '
        '|| { rm -rf "$d"; echo "download failed"; exit 1; }',
        f'  [ "$(shasum -a 256 "$d/Tailscale.pkg" | cut -d" " -f1)" = {pins.TAILSCALE_APP_SHA256} ] '
        '|| { rm -rf "$d"; echo "the package does not match its pinned sha256"; exit 1; }',
        f'  pkgutil --check-signature "$d/Tailscale.pkg" | grep -qF {shlex.quote(pins.TAILSCALE_APP_SIGNER)} '
        '|| { rm -rf "$d"; echo "the package is not signed by Tailscale Inc."; exit 1; }',
        '  sudo installer -pkg "$d/Tailscale.pkg" -target / || { rm -rf "$d"; exit 1; }',
        '  rm -rf "$d"',
        "fi",
        "open -a Tailscale",
        "asked=no",
        "for _ in $(seq 1 150); do",
        '  "$T" status --json >/dev/null 2>&1 && break',
        '  if [ "$asked" = no ]; then',
        '    echo "When macOS asks, allow Tailscale\'s system extension (System Settings → General → Login Items &'
        ' Extensions) and its VPN configuration. Skip the app\'s own Log in: tn adds the accounts. Waiting up to'
        ' 5 minutes."',
        "    asked=yes",
        "  fi",
        "  sleep 2",
        "done",
        '"$T" status --json >/dev/null 2>&1 || { echo "Tailscale did not start: allow its system extension and VPN '
        'configuration, then run this again."; exit 1; }',
        'echo "the Tailscale app is ready"',
    ]


def trust_lines(site, ca_pem):
    """Shell lines that make macOS trust the site CA for TLS, system-wide, as the app's network
    extension needs: the CA inside a profile alone is not enough. Skipped when it is trusted already."""
    urls = " ".join(shlex.quote(r.server_url) for r in site.regions.values())
    return [
        f'trusted() {{ local u; for u in {urls}; do security verify-cert "$u" >/dev/null 2>&1 || return 1; done; }}',
        'if trusted; then echo "macOS trusts the site CA"',
        "else",
        '  echo "Trusting the site CA for TLS in the System keychain; sudo and macOS ask for your password."',
        "  ca=$(mktemp /tmp/tn-site-ca.XXXXXX)",
        "  cat > \"$ca\" <<'TN_PEM'",
        ca_pem.strip(),
        "TN_PEM",
        f'  sudo security add-trusted-cert -d -r trustRoot -p ssl -k {SYSTEM_KEYCHAIN} "$ca" '
        '|| { rm -f "$ca"; echo "macOS did not trust the site CA"; exit 1; }',
        '  rm -f "$ca"',
        '  trusted || { echo "macOS still does not trust the login servers"; exit 1; }',
        '  echo "macOS trusts the site CA"',
        "fi",
    ]


def trust_block(site, ca_pem):
    """Shell text that makes this Mac trust the site CA."""
    return "\n".join(["/bin/bash <<'TN_EOF'", *trust_lines(site, ca_pem), "TN_EOF"]) + "\n"


def untrust_command(ca_pem):
    """The command that drops the site CA from the System keychain again."""
    sha1 = hashlib.sha1(ssl.PEM_cert_to_DER_cert(ca_pem)).hexdigest().upper()
    return f"sudo security delete-certificate -Z {sha1} {SYSTEM_KEYCHAIN}"


def app_block():
    """Shell text that makes the Tailscale app ready on this Mac."""
    return "\n".join(["/bin/bash <<'TN_EOF'", *app_lines(), "TN_EOF"]) + "\n"


def login_block(site, regions, keys, home, ca_pem=None):
    """Shell text to paste into Terminal on the Mac: the site CA trusted (with ca_pem), the app made
    ready (installed if missing), an account per region, then the home region. keys: {region name:
    pre-auth key}. Accounts that are there already are left alone."""
    lines = [
        "/bin/bash <<'TN_EOF'",
        *(trust_lines(site, ca_pem) if ca_pem else []),
        *app_lines(),
        # Before logging in, say plainly why it cannot work: the CA not trusted yet, or no way through.
        "account() {",
        '  if "$T" switch --list --json 2>/dev/null | grep -q "\\"nickname\\": \\"$1\\""; then echo "$1: already there"; return 0; fi',
        '  if ! security verify-cert "$2" >/dev/null 2>&1; then',
        '    if curl -sk --max-time 10 -o /dev/null "$2/health"; then',
        '      echo "$1: macOS does not trust $2 yet. Run this again and let it trust the site CA."',
        '    else echo "$1: this Mac cannot reach $2. Is Clash (TUN) or another VPN in the way?"; fi',
        "    return 1",
        "  fi",
        '  echo "$1: logging in to $2 (up to 60 s)"',
        '  if "$T" login --login-server="$2" --nickname="$1" --auth-key="$3" --timeout=60s; then echo "$1: joined"',
        '  else echo "$1: did not join"; return 1; fi',
        "}",
        "ok=yes",
    ]
    for r in regions:
        lines.append(f"account {shlex.quote(r.name)} {shlex.quote(r.server_url)} {shlex.quote(keys[r.name])} || ok=no")
    lines += [f'"$T" switch {shlex.quote(home.name)} >/dev/null 2>&1 || true', '[ "$ok" = yes ]', "TN_EOF"]
    return "\n".join(lines) + "\n"


def logout_block(site):
    """Shell text for the Mac after a rollback: leave every region's account."""
    names = " ".join(shlex.quote(r.name) for r in site.regions.values())
    return "\n".join([
        "/bin/bash <<'TN_EOF'",
        f"T={shlex.quote(APP_CLI)}",
        f'for a in {names}; do "$T" switch "$a" >/dev/null 2>&1 && "$T" logout && echo "left $a"; done',
        "TN_EOF",
    ]) + "\n"


def tailnet_nets(site):
    nets = [str(CGNAT)]
    nets += [str(r.alias_net) for r in site.regions.values() if r.alias_net is not None]
    return nets


def clash_script(site):
    """A Clash Verge global extension script: the tailnet's ranges and names, and Tailscale's own
    traffic, go DIRECT and stay out of the TUN device; .vlan names are not faked."""
    nets = tailnet_nets(site)
    controls = sorted({r.public_ipv4 for r in site.regions.values()})
    rules = [f"IP-CIDR,{n},DIRECT,no-resolve" for n in nets]
    rules += [f"IP-CIDR,{ip}/32,DIRECT,no-resolve" for ip in controls]
    rules += [f"DOMAIN-SUFFIX,{site.dns_suffix},DIRECT", f"PROCESS-NAME,{NETWORK_EXTENSION},DIRECT",
              "PROCESS-NAME,Tailscale,DIRECT"]
    js = lambda v: "[" + ", ".join(f'"{x}"' for x in v) + "]"  # noqa: E731
    return f"""// tailnet-ops {site.name}: let the tailnet bypass Clash. Clash Verge -> Profiles -> Global Extend Script.
function main(config) {{
  const nets = {js(nets)};
  const rules = {js(rules)};
  const add = (list, more) => [...new Set([...(list || []), ...more])];
  config.rules = [...rules, ...(config.rules || []).filter((r) => !rules.includes(r))];
  config.tun = Object.assign({{}}, config.tun);
  config.tun["route-exclude-address"] = add(config.tun["route-exclude-address"], nets);
  config.dns = Object.assign({{}}, config.dns);
  config.dns["fake-ip-filter"] = add(config.dns["fake-ip-filter"], ["+.{site.dns_suffix}"]);
  config.dns["nameserver-policy"] = Object.assign({{}}, config.dns["nameserver-policy"],
                                                  {{"+.{site.dns_suffix}": "100.100.100.100"}});
  return config;
}}
"""


def clash_bypass(site):
    """For Clash Verge's system proxy bypass setting."""
    return ",".join([f"*.{site.dns_suffix}"] + tailnet_nets(site))
