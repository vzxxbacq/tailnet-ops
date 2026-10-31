"""A Let's Encrypt certificate for a region's login server, when the region has a domain.

acme.sh, pinned and checked, answers the DNS-01 challenge through Cloudflare's API, so no port has to
be opened: 80 and 443 often belong to other services, or the provider passes only a few ports. It
lives in /etc/headscale/acme with its ACME account key, its data and the Cloudflare API token, all
root only. A timer runs it daily; when it renews the certificate, a hook gives the new files to
Headscale and restarts it. Every device trusts the certificate already, so joins need no site CA.
"""

import re

from . import pins, render

DIR = f"{render.ETC}/acme"
TOKEN_FILE = f"{DIR}/cloudflare.env"
HOOK = f"{DIR}/installed.sh"
SERVICE = "/etc/systemd/system/headscale-cert.service"
TIMER = "/etc/systemd/system/headscale-cert.timer"
# A Cloudflare API token: letters, digits and a few URL-safe marks; nothing a shell would interpret.
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{20,200}$")


def token_problem(token):
    return None if TOKEN_RE.match(token.strip()) else "that does not look like a Cloudflare API token"


# --- read-only: what the host has -----------------------------------------------------

STATE = r"""sum() { if [ -f "$1" ]; then sha256sum "$1" | cut -d' ' -f1; else echo none; fi; }
echo "TN-FACT acme_sh=$(sum "$ACME/acme.sh")"
echo "TN-FACT dns_cf=$(sum "$ACME/dnsapi/dns_cf.sh")"
if [ -s "$ACME/cloudflare.env" ]; then echo "TN-FACT token=yes"; else echo "TN-FACT token=no"; fi
"""


# --- acme.sh, uploaded from this machine's cache ------------------------------------------

STAGE = r"""d=$(mktemp -d /tmp/tn-acme.XXXXXXXX)
echo "TN-FACT stage=$d"
"""


def staged_name(path):
    """The file's name in the staging directory: acme.sh, dns_cf.sh."""
    return path.rsplit("/", 1)[-1]


def install():
    checks = "\n".join(f"check {staged_name(p)} {want}" for p, want in pins.ACME_SH_SHA256.items())
    return f"""stage=${{1:?staging directory}}
case "$stage" in /tmp/tn-acme.*) ;; *) die "unexpected staging path $stage" ;; esac
ours_etc || die "$ETC is missing or not ours"
check() {{
  if [ "$(sha256sum "$stage/$1" | cut -d' ' -f1)" != "$2" ]; then
    rm -rf "$stage"
    die "checksum mismatch for $1 on the host"
  fi
}}
{checks}
install -d -o root -g root -m 0700 "$ACME" "$ACME/dnsapi"
install -o root -g root -m 0700 "$stage/acme.sh" "$ACME/acme.sh"
install -o root -g root -m 0600 "$stage/dns_cf.sh" "$ACME/dnsapi/dns_cf.sh"
rm -rf "$stage"
echo "installed acme.sh {pins.ACME_SH_VERSION} in $ACME"
"""


# --- the API token, on stdin: never in a script, a log or this machine's disk -----------

SAVE_TOKEN = r"""umask 077
[ -d "$1" ] || { echo "tn: $1 is missing" >&2; exit 1; }
IFS= read -r t || true
case "$t" in ""|*[!A-Za-z0-9._~+/=-]*) echo "tn: that is not a Cloudflare API token" >&2; exit 1 ;; esac
printf "export CF_Token='%s'\n" "$t" > "$1/cloudflare.env.tn-new"
mv -f "$1/cloudflare.env.tn-new" "$1/cloudflare.env"
echo "saved the Cloudflare API token in $1/cloudflare.env (root only)"
"""


def save_token_argv():
    """Runs as root with the token on stdin."""
    return ["sh", "-c", SAVE_TOKEN, "sh", DIR]


# --- issue, install, renew ----------------------------------------------------------------


def hook(region):
    """Runs after acme.sh installs a certificate: during apply it leaves the restart to the start
    step; from the renewal timer it restarts Headscale, which reads its certificate only at start."""
    return f"""#!/bin/sh
# {render.marker(region)}: acme.sh runs this after it installs a certificate
set -eu
chown root:headscale {render.ETC}/tls/server.key
chmod 0640 {render.ETC}/tls/server.key
chmod 0644 {render.ETC}/tls/server.crt
sum=$(sha256sum {render.ETC}/tls/server.crt | cut -d' ' -f1)
if [ "$sum" = "$(cat {DIR}/installed.sum 2>/dev/null || true)" ]; then exit 0; fi
echo "$sum" > {DIR}/installed.sum
if [ -n "${{TN_DEFER_RESTART:-}}" ]; then
  touch {render.ETC}/.restart-needed
elif systemctl is-active --quiet headscale; then
  systemctl restart headscale
fi
"""


def service_unit(region):
    return f"""# {render.marker(region)}
[Unit]
Description=Renew the Headscale certificate for {region.domain} (tailnet-ops)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={DIR}/acme.sh --cron --home {DIR} --config-home {DIR}/data
"""


def timer_unit(region):
    return f"""# {render.marker(region)}
[Unit]
Description=Renew the Headscale certificate for {region.domain} daily (tailnet-ops)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
"""


def issue(region):
    return f"""ours_etc || die "$ETC is missing or not ours"
[ -x "$ACME/acme.sh" ] || die "acme.sh is not installed in $ACME"
[ -s "$ACME/cloudflare.env" ] || die "no Cloudflare API token in $ACME"
cat > "$ACME/installed.sh.tn-new" <<'TN_EOF'
{hook(region).rstrip()}
TN_EOF
chmod 0700 "$ACME/installed.sh.tn-new"
mv -f "$ACME/installed.sh.tn-new" "$ACME/installed.sh"
# A certificate for another name would be renewed and installed over this one.
for d in "$ACME"/data/*_ecc; do
  [ -d "$d" ] || continue
  n=${{d##*/}}
  n=${{n%_ecc}}
  if [ "$n" != "$DOMAIN" ]; then rm -rf "$d"; echo "dropped the certificate for $n"; fi
done
acme() {{ "$ACME/acme.sh" --home "$ACME" --config-home "$ACME/data" "$@"; }}
rc=0
# The token reaches acme.sh only, which keeps a copy in its account.conf for renewals.
( . "$ACME/cloudflare.env"
  acme --issue --server {pins.ACME_SERVER} --dns dns_cf -d "$DOMAIN" --keylength ec-256 --dnssleep {pins.ACME_DNS_SLEEP} ) || rc=$?
case "$rc" in
  0) echo "issued a certificate for $DOMAIN" ;;
  2) echo "the certificate for $DOMAIN is current; kept it" ;;
  *) die "acme.sh could not get a certificate for $DOMAIN (exit $rc); see above" ;;
esac
export TN_DEFER_RESTART=1
acme --install-cert -d "$DOMAIN" --ecc --key-file "$ETC/tls/server.key" \\
  --fullchain-file "$ETC/tls/server.crt" --reloadcmd "$ACME/installed.sh"
# The site CA certificate from before is not used here any more.
rm -f "$ETC/tls/ca.crt"
for u in "$CERT_SERVICE" "$CERT_TIMER"; do
  if [ -e "$u" ] && [ "$(head -n 1 "$u")" != "# $MARK" ]; then die "$u exists and is not ours"; fi
done
put_unit() {{
  cat > "$1.tn-new"
  chmod 0644 "$1.tn-new"
  if cmp -s "$1.tn-new" "$1"; then rm -f "$1.tn-new"; else mv -f "$1.tn-new" "$1"; echo "wrote $1"; fi
}}
put_unit "$CERT_SERVICE" <<'TN_EOF'
{service_unit(region).rstrip()}
TN_EOF
put_unit "$CERT_TIMER" <<'TN_EOF'
{timer_unit(region).rstrip()}
TN_EOF
systemctl daemon-reload
systemctl enable --now "${{CERT_TIMER##*/}}"
echo "renewal: ${{CERT_TIMER##*/}} $(systemctl is-active "${{CERT_TIMER##*/}}")"
openssl x509 -in "$ETC/tls/server.crt" -noout -subject -issuer -enddate
"""
