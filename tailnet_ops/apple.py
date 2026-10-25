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

import plistlib
import shlex
import ssl
import uuid

from .privacy import CGNAT

APP = "/Applications/Tailscale.app"
APP_CLI = f"{APP}/Contents/MacOS/Tailscale"
APP_DOMAIN = "io.tailscale.ipn.macsys"           # the standalone build's policy domain
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


def login_block(site, regions, keys, home):
    """Shell text to paste into Terminal on the Mac: an account per region, then the home region.
    keys: {region name: pre-auth key}. Accounts that are there already are left alone."""
    lines = [
        "/bin/bash <<'TN_EOF'",
        f"T={shlex.quote(APP_CLI)}",
        '[ -x "$T" ] || { echo "Install the Tailscale app first: https://tailscale.com/download/mac"; exit 1; }',
        "open -a Tailscale",
        'for _ in 1 2 3 4 5 6 7 8 9 10; do "$T" status --json >/dev/null 2>&1 && break; sleep 1; done',
        '"$T" status --json >/dev/null 2>&1 || { echo "Open Tailscale, allow its system extension and VPN '
        'configuration, then paste this again."; exit 1; }',
        "account() {",
        '  if "$T" switch --list --json 2>/dev/null | grep -q "\\"nickname\\": \\"$1\\""; then echo "$1: already there"',
        '  else "$T" login --login-server="$2" --nickname="$1" --auth-key="$3" --timeout=60s && echo "$1: joined"; fi',
        "}",
    ]
    for r in regions:
        lines.append(f"account {shlex.quote(r.name)} {shlex.quote(r.server_url)} {shlex.quote(keys[r.name])}")
    lines += [f'"$T" switch {shlex.quote(home.name)}', "TN_EOF"]
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
