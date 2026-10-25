"""`tn join`: add a host to the tailnet.

A server joins its region with a tagged key. A personal device joins every region as the
owner, one Tailscale profile per region, and switches between them with `tailscale switch`.
Linux hosts get a pinned static Tailscale build under systemd or OpenRC; macOS hosts get Homebrew's
tailscale under launchd (see macos.py).
"""

import datetime
import ipaddress
import json
import time
import re
import shlex
import tarfile

from . import macos, names, pins, render, scripts, siteca, targets
from .procedure import Action, Procedure, Step, StepError, fetch_pinned, sha256_file
from .site import dns_label, ensure_private_dir, write_private

TS_BIN = "/usr/local/bin/tailscale"
TSD_BIN = "/usr/local/sbin/tailscaled"
TS_UNIT = "/etc/systemd/system/tailscaled.service"
TS_INIT = "/etc/init.d/tailscaled"            # OpenRC (Alpine)
ALPINE_PACKAGES = "bash curl ca-certificates iproute2 tar iptables"
TS_STATE = "/var/lib/tailscale"
TS_CACHE = "/var/cache/tailscale"
CA_DIR = "/usr/local/share/ca-certificates"

CA_PLACEHOLDER = "<site CA certificate from pki/ca.crt>"


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "site"


def ca_file(site):
    return f"{CA_DIR}/tailnet-ops-{slug(site.name)}.crt"


def marker(region, alias, personal=False):
    if personal:
        return f"tailnet-ops join personal host={alias}"
    return f"tailnet-ops join region={region.name} host={alias}"


def host_prelude(site, alias, port, logins, mark):
    sums = pins.TAILSCALE_BIN_SHA256
    return f"""set -euo pipefail
umask 022
{scripts._vars([
    ("HOST", alias),
    ("LOGIN", logins[0]),
    ("LOGINS", " ".join(logins)),
    ("TS_PORT", port),
    ("TS_BIN", TS_BIN),
    ("TSD_BIN", TSD_BIN),
    ("TS_UNIT", TS_UNIT),
    ("TS_INIT", TS_INIT),
    ("ALPINE_PACKAGES", ALPINE_PACKAGES),
    ("TS_STATE", TS_STATE),
    ("TS_CACHE", TS_CACHE),
    ("CA_FILE", ca_file(site)),
    ("SUM_TS_AMD64", sums["amd64"]["tailscale"]),
    ("SUM_TS_ARM64", sums["arm64"]["tailscale"]),
    ("SUM_TSD_AMD64", sums["amd64"]["tailscaled"]),
    ("SUM_TSD_ARM64", sums["arm64"]["tailscaled"]),
    ("MARK", mark),
])}
die() {{ echo "tn: $*" >&2; exit 1; }}
want_sum() {{
  case "$1:$(uname -m)" in
    tailscale:x86_64) echo "$SUM_TS_AMD64" ;;
    tailscale:aarch64|tailscale:arm64) echo "$SUM_TS_ARM64" ;;
    tailscaled:x86_64) echo "$SUM_TSD_AMD64" ;;
    tailscaled:aarch64|tailscaled:arm64) echo "$SUM_TSD_ARM64" ;;
    *) echo none ;;
  esac
}}
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
ours_bin() {{
  [ -f "$1" ] || return 1
  local sum
  sum=$(sha256sum "$1" | cut -d' ' -f1)
  case "$sum" in "$SUM_TS_AMD64"|"$SUM_TS_ARM64"|"$SUM_TSD_AMD64"|"$SUM_TSD_ARM64") return 0 ;; esac
  return 1
}}
ours_unit() {{ [ -f "$TS_UNIT" ] && [ "$(head -n 1 "$TS_UNIT")" = "# $MARK" ]; }}
ours_init() {{ [ -f "$TS_INIT" ] && [ "$(sed -n 2p "$TS_INIT")" = "# $MARK" ]; }}
ours_service() {{ ours_unit || ours_init; }}
ours_state() {{ [ -f "$TS_STATE/.tailnet-ops" ] && [ "$(cat "$TS_STATE/.tailnet-ops")" = "$MARK" ]; }}"""


# --- step 1: preflight (read-only) ------------------------------------------------


def preflight(ca_pem):
    return scripts.ca_function(ca_pem) + r"""
fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }
note() { printf '  note  %s\n' "$*"; }

os=$( (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null || echo unknown)
if [ "$(uname -s)" = Linux ]; then pass "OS: $os"; else flag "OS: not Linux ($(uname -s)); join it with --os macos"; fi
echo "TN-FACT os=$os"
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) arch="" ;;
esac
if [ -n "$arch" ]; then pass "arch: $(uname -m)"; else flag "arch: $(uname -m) has no pinned Tailscale build"; fi
echo "TN-FACT arch=${arch:-none}"
echo "TN-FACT machine=$(uname -m)"
if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then pass "systemd"; init=systemd
elif command -v openrc-run >/dev/null && command -v rc-service >/dev/null; then pass "OpenRC"; init=openrc
else flag "neither systemd nor OpenRC runs here"; init=none; fi
echo "TN-FACT init=$init"
if [ -c /dev/net/tun ]; then pass "/dev/net/tun"; else flag "/dev/net/tun is missing"; fi
missing=""
for c in curl sha256sum tar install update-ca-certificates ip ss; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [ -z "$missing" ]; then pass "tools: curl sha256sum tar install update-ca-certificates ip ss"
elif [ -f /etc/alpine-release ]; then flag "missing tools:$missing; on Alpine: apk add $ALPINE_PACKAGES"
else flag "missing tools:$missing"; fi
if ! command -v iptables >/dev/null && ! command -v nft >/dev/null; then
  note "neither iptables nor nft is installed; tailscaled sets firewall rules by default: install iptables, or join with --netfilter off"
fi

lines=$(ss -H -lunp "sport = :$TS_PORT" 2>/dev/null || true)
if [ -z "$lines" ]; then pass "udp/$TS_PORT free (Tailscale)"; echo "TN-FACT port=free"
elif ! printf '%s\n' "$lines" | grep -qv '"tailscaled"' && ours_service; then
  pass "udp/$TS_PORT already used by our tailscaled"; echo "TN-FACT port=ours"
else flag "udp/$TS_PORT is in use: $(printf '%s' "$lines" | tr -s ' ' | tr '\n' ' ' | cut -c1-160)"; echo "TN-FACT port=busy"; fi

for p in /usr/bin/tailscale /usr/sbin/tailscaled; do
  if [ -e "$p" ]; then flag "another Tailscale is installed at $p"; fi
done
if command -v dpkg-query >/dev/null && dpkg-query -W -f='${Status}' tailscale 2>/dev/null | grep -q 'ok installed'; then
  flag "a tailscale package is installed"
fi
for p in "$TS_BIN" "$TSD_BIN"; do
  if [ ! -e "$p" ]; then pass "$p absent"
  elif ours_bin "$p"; then pass "$p is the pinned build"
  else flag "$p exists and is not the pinned build"; fi
done
echo "TN-FACT tailscale=$( [ -f "$TS_BIN" ] && sha256sum "$TS_BIN" | cut -d' ' -f1 || echo none)"
echo "TN-FACT tailscaled=$( [ -f "$TSD_BIN" ] && sha256sum "$TSD_BIN" | cut -d' ' -f1 || echo none)"
if [ ! -e "$TS_UNIT" ]; then pass "$TS_UNIT absent"
elif ours_unit; then pass "$TS_UNIT exists and is ours"
else flag "$TS_UNIT exists and is not ours"; fi
if [ ! -e "$TS_INIT" ]; then pass "$TS_INIT absent"
elif ours_init; then pass "$TS_INIT exists and is ours"
else flag "$TS_INIT exists and is not ours"; fi
if [ ! -e "$TS_STATE" ]; then pass "$TS_STATE absent"
elif ours_state; then pass "$TS_STATE exists and is ours"
else flag "$TS_STATE exists and is not ours"; fi
if ip link show tailscale0 >/dev/null 2>&1 && ! ours_service; then flag "a tailscale0 interface exists outside our service"; fi
if pgrep -x tailscaled >/dev/null && ! ours_service; then flag "a tailscaled process runs outside our service"; fi

login=ok
for url in $LOGINS; do
  if out=$(curl -fsS --max-time 10 --cacert <(ca) "$url/health" 2>&1); then
    pass "reaches $url over TLS with the site CA"
  else
    flag "cannot reach $url with the site CA: $out"; login=fail
  fi
done
echo "TN-FACT login=$login"
if ours_service; then echo "TN-FACT joined=ours"; else echo "TN-FACT joined=no"; fi
# Only when programs ask systemd-resolved's stub (127.0.0.53) does accept-dns hand just the tailnet
# suffix to MagicDNS. Where /etc/resolv.conf names upstream servers directly, programs bypass
# resolved, and tailscaled may rewrite the file, so tailnet-ops leaves DNS alone there.
if systemctl is-active --quiet systemd-resolved && [ "$(readlink -f /etc/resolv.conf)" = /run/systemd/resolve/stub-resolv.conf ]; then
  echo "TN-FACT resolved=yes"
else
  echo "TN-FACT resolved=no"
fi

if [ "$fail" != 0 ]; then die "preflight failed; nothing was changed"; fi
echo "preflight passed; nothing was changed"
"""


# --- step 2: binaries ---------------------------------------------------------------

STAGE = r"""d=$(mktemp -d /tmp/tn-tailscale.XXXXXXXX)
echo "TN-FACT stage=$d"
"""

# The host fetches the pinned archive itself: uploading it from the operator's machine can be slow.
# A failed download is not an error (this machine then uploads it); a wrong one is.
DOWNLOAD = r"""stage=${1:?staging directory}
url=${2:?archive url}
want=${3:?archive sha256}
folder=${4:?folder inside the archive}
case "$stage" in /tmp/tn-tailscale.*) ;; *) die "unexpected staging path $stage" ;; esac
echo "downloading $url"
if ! curl -fsSL --max-time 600 --retry 2 -o "$stage/tailscale.tgz" "$url"; then
  rm -f "$stage/tailscale.tgz"
  echo "TN-FACT download=failed"
  exit 0
fi
got=$(sha256sum "$stage/tailscale.tgz" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  rm -rf "$stage"
  die "the download does not match its pinned sha256: $got"
fi
# Plain tar options only, so busybox's tar (Alpine) does as well as GNU tar.
tar -xzf "$stage/tailscale.tgz" -C "$stage" "$folder/tailscale" "$folder/tailscaled"
mv "$stage/$folder/tailscale" "$stage/$folder/tailscaled" "$stage/"
rmdir "$stage/$folder"
rm -f "$stage/tailscale.tgz"
echo "archive sha256 ok"
echo "TN-FACT download=ok"
"""

INSTALL_BINARIES = r"""stage=${1:?staging directory}
case "$stage" in /tmp/tn-tailscale.*) ;; *) die "unexpected staging path $stage" ;; esac
for name in tailscale tailscaled; do
  got=$(sha256sum "$stage/$name" | cut -d' ' -f1)
  if [ "$got" != "$(want_sum "$name")" ]; then
    rm -rf "$stage"
    die "checksum mismatch for $name on the host: $got"
  fi
done
install -d -m 0755 "$(dirname "$TS_BIN")" "$(dirname "$TSD_BIN")"
install -o root -g root -m 0755 "$stage/tailscale" "$TS_BIN.tn-new"
install -o root -g root -m 0755 "$stage/tailscaled" "$TSD_BIN.tn-new"
mv -f "$TS_BIN.tn-new" "$TS_BIN"
mv -f "$TSD_BIN.tn-new" "$TSD_BIN"
rm -rf "$stage"
"$TS_BIN" version 2>/dev/null | head -n 1 || true
"""

ROLLBACK_BINARIES = r"""for p in "$TS_BIN" "$TSD_BIN"; do
  if [ ! -e "$p" ]; then echo "$p: absent"
  elif ours_bin "$p"; then rm -f "$p"; echo "removed $p"
  else echo "skip: $p is not the pinned build"; fi
done
for d in /tmp/tn-tailscale.*; do
  if [ -d "$d" ]; then rm -rf "$d"; echo "removed the staging directory $d"; fi
done
"""

# Read-only: everything join can leave on a host, one `TN-LEFT` line per item still there.
LEFTOVERS = r"""for p in "$TS_BIN" "$TSD_BIN" "$TS_UNIT" "$TS_INIT" "$TS_STATE" "$TS_CACHE" "$CA_FILE" /run/tailscale \
         /etc/systemd/system/multi-user.target.wants/tailscaled.service /etc/runlevels/default/tailscaled \
         /tmp/tn-tailscale.*; do
  if [ -e "$p" ]; then echo "TN-LEFT $p"; fi
done
if ip link show tailscale0 >/dev/null 2>&1; then echo "TN-LEFT interface tailscale0"; fi
if pgrep -x tailscaled >/dev/null; then echo "TN-LEFT a running tailscaled"; fi
if ip rule show 2>/dev/null | grep -q 'lookup 52'; then echo "TN-LEFT ip rules for table 52"; fi
"""

PREAUTH_KEYS_JSON = '"$BIN" preauthkeys list -o json 2>/dev/null\n'


# --- step 3: site CA in the system trust store ---------------------------------------


def install_ca(ca_pem):
    return f"""cat > "$CA_FILE.tn-new" <<'TN_PEM'
{ca_pem.strip()}
TN_PEM
chmod 0644 "$CA_FILE.tn-new"
if cmp -s "$CA_FILE.tn-new" "$CA_FILE"; then
  rm -f "$CA_FILE.tn-new"
  echo "unchanged $CA_FILE"
else
  mv -f "$CA_FILE.tn-new" "$CA_FILE"
  update-ca-certificates
fi
for url in $LOGINS; do
  curl -fsS --max-time 10 "$url/health" >/dev/null || die "the system trust store does not accept $url yet"
done
echo "the system trust store accepts $LOGINS"
"""


def rollback_ca(ca_pem):
    return scripts.ca_function(ca_pem) + """
if [ ! -e "$CA_FILE" ]; then echo "$CA_FILE: absent"
elif cmp -s "$CA_FILE" <(ca); then
  rm -f "$CA_FILE"
  update-ca-certificates --fresh >/dev/null 2>&1 || update-ca-certificates >/dev/null 2>&1
  echo "removed $CA_FILE and rebuilt the trust store"
else echo "skip: $CA_FILE is not this site's CA"; fi
"""


# --- step 4: tailscaled service --------------------------------------------------------


def unit(mark, tailnets, port):
    return f"""# {mark}
[Unit]
Description=Tailscale node agent for tailnet {tailnets} (tailnet-ops)
Documentation=https://tailscale.com/docs/
Wants=network-pre.target
After=network-pre.target NetworkManager.service systemd-resolved.service

[Service]
ExecStart={TSD_BIN} --state={TS_STATE}/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port={port} --no-logs-no-support
ExecStopPost={TSD_BIN} --cleanup
Restart=on-failure
RuntimeDirectory=tailscale
RuntimeDirectoryMode=0755
StateDirectory=tailscale
StateDirectoryMode=0700
CacheDirectory=tailscale
CacheDirectoryMode=0750
Type=notify

[Install]
WantedBy=multi-user.target
"""


def service(unit_text):
    return f"""if [ -e "$TS_UNIT" ] && ! ours_unit; then die "$TS_UNIT exists and is not ours"; fi
if [ -e "$TS_STATE" ] && ! ours_state; then die "$TS_STATE exists and is not ours"; fi
install -d -m 0700 "$TS_STATE"
printf '%s\\n' "$MARK" > "$TS_STATE/.tailnet-ops"
was_active=no
if systemctl is-active --quiet tailscaled; then was_active=yes; fi
changed=no
cat > "$TS_UNIT.tn-new" <<'TN_EOF'
{unit_text.rstrip()}
TN_EOF
chmod 0644 "$TS_UNIT.tn-new"
if cmp -s "$TS_UNIT.tn-new" "$TS_UNIT"; then rm -f "$TS_UNIT.tn-new"; echo "unchanged $TS_UNIT"
else mv -f "$TS_UNIT.tn-new" "$TS_UNIT"; echo "wrote $TS_UNIT"; changed=yes; fi
systemctl daemon-reload
systemctl enable --now tailscaled
if [ "$was_active" = yes ] && [ "$changed" = yes ]; then systemctl restart tailscaled; echo "restarted tailscaled"; fi
for _ in $(seq 1 20); do
  if "$TS_BIN" status --json >/dev/null 2>&1; then echo "tailscaled is up"; return 0; fi
  sleep 1
done
journalctl -u tailscaled -n 30 --no-pager || true
die "tailscaled did not answer within 20 s"
"""


def openrc_script(mark, tailnets, port):
    """An OpenRC service, supervised: it starts at boot and is restarted if it dies."""
    return f"""#!/sbin/openrc-run
# {mark}
description="Tailscale node agent for tailnet {tailnets} (tailnet-ops)"
supervisor=supervise-daemon
command={TSD_BIN}
command_args="--state={TS_STATE}/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port={port} --no-logs-no-support"
output_logger="logger -t tailscaled -p daemon.info"
error_logger="logger -t tailscaled -p daemon.err"
respawn_delay=5
respawn_max=0

depend() {{
	need net
	after firewall
	use logger
}}

start_pre() {{
	checkpath --directory --mode 0755 /run/tailscale
	checkpath --directory --mode 0700 {TS_STATE}
	checkpath --directory --mode 0750 {TS_CACHE}
}}

stop_post() {{
	{TSD_BIN} --cleanup
}}
"""


def openrc_service(script_text):
    return f"""if [ -e "$TS_INIT" ] && ! ours_init; then die "$TS_INIT exists and is not ours"; fi
if [ -e "$TS_STATE" ] && ! ours_state; then die "$TS_STATE exists and is not ours"; fi
install -d -m 0700 "$TS_STATE"
printf '%s\\n' "$MARK" > "$TS_STATE/.tailnet-ops"
changed=no
cat > "$TS_INIT.tn-new" <<'TN_EOF'
{script_text.rstrip()}
TN_EOF
chmod 0755 "$TS_INIT.tn-new"
if cmp -s "$TS_INIT.tn-new" "$TS_INIT"; then rm -f "$TS_INIT.tn-new"; echo "unchanged $TS_INIT"
else mv -f "$TS_INIT.tn-new" "$TS_INIT"; echo "wrote $TS_INIT"; changed=yes; fi
rc-update add tailscaled default >/dev/null
if rc-service tailscaled status >/dev/null 2>&1; then
  if [ "$changed" = yes ]; then rc-service tailscaled restart; echo "restarted tailscaled"; fi
else
  rc-service tailscaled start
fi
for _ in $(seq 1 20); do
  if "$TS_BIN" status --json >/dev/null 2>&1; then echo "tailscaled is up"; return 0; fi
  sleep 1
done
(grep tailscaled /var/log/messages 2>/dev/null | tail -n 30) || true
die "tailscaled did not answer within 20 s"
"""


# Either init system: a rollback may run without knowing which one the host has.
ROLLBACK_SERVICE = r"""gone=yes
if [ -e "$TS_UNIT" ]; then
  if ours_unit; then
    systemctl disable --now tailscaled
    rm -f "$TS_UNIT"
    systemctl daemon-reload
    echo "stopped tailscaled (it cleans up its routes and rules on stop) and removed $TS_UNIT"
  else echo "skip: $TS_UNIT is not ours"; gone=no; fi
fi
if [ -e "$TS_INIT" ]; then
  if ours_init; then
    rc-service tailscaled stop || true
    rc-update del tailscaled default >/dev/null 2>&1 || true
    rm -f "$TS_INIT"
    echo "stopped tailscaled (it cleans up its routes and rules on stop) and removed $TS_INIT"
  else echo "skip: $TS_INIT is not ours"; gone=no; fi
fi
if [ "$gone" = yes ] && [ ! -e "$TS_UNIT" ] && [ ! -e "$TS_INIT" ]; then echo "tailscaled service: none left"; fi
if [ ! -e "$TS_STATE" ]; then echo "$TS_STATE: absent"
elif ours_state; then rm -rf "$TS_STATE" "$TS_CACHE"; echo "removed $TS_STATE (the node key) and $TS_CACHE"
else echo "skip: $TS_STATE is not ours"; fi
"""


# --- step 5: join ------------------------------------------------------------------------


def preauth_key(tags):
    return f"""# Prints only the key, on stdout, which goes straight into `tailscale up` on the host.
"$BIN" preauthkeys create --expiration {pins.PREAUTH_KEY_EXPIRY} --tags {shlex.quote(",".join(tags))}
"""


def user_key(user_id, expiry=pins.PREAUTH_KEY_EXPIRY):
    """A key owned by a user, without tags: a personal device belongs to the owner."""
    return f"""# Prints only the key, on stdout, which goes straight into `tailscale login` on the device.
"$BIN" preauthkeys create --expiration {expiry} --user {user_id}
"""


CODE_RE = re.compile(r"^(?:hskey-auth-[A-Za-z0-9_-]{8,}|[0-9a-f]{48})$")
CONTROL_PING = '"$BIN" version >/dev/null\n'


def code_problem(code):
    """None if code looks like a Headscale pre-auth key."""
    return None if CODE_RE.match(code.strip()) else "a link code looks like hskey-auth-…"


def code_commands(site, region, tags):
    """[(where, command)] that make a link code by hand: on the control host, or over SSH to it."""
    if tags:
        make = f"sudo {render.BIN} preauthkeys create --expiration {pins.JOIN_CODE_EXPIRY} --tags {','.join(tags)}"
    else:
        user = (f"$(sudo {render.BIN} users list --name {shlex.quote(site.owner_user)} -o json"
                " | grep -m1 '\"id\"' | tr -dc 0-9)")
        make = f'sudo {render.BIN} preauthkeys create --expiration {pins.JOIN_CODE_EXPIRY} --user "{user}"'
    return [(f"on {region.control_host}, the Headscale of {region.name}", make),
            (f"or on a machine that can SSH to it (your alias for {region.control_host} there)",
             f"ssh {region.control_host} {shlex.quote(make)}")]


def _flag(value):
    return "true" if value else "false"


def up_argv(region, alias, netfilter_mode, accept_routes=False, accept_dns=False, ts_bin=TS_BIN,
            verb="up", nickname=None):
    """`tailscale up`, or `tailscale login` for a new profile; the key comes on stdin."""
    argv = [ts_bin, verb, f"--login-server={region.server_url}", "--auth-key=file:/dev/stdin",
            f"--hostname={dns_label(alias)}", f"--accept-dns={_flag(accept_dns)}",
            f"--accept-routes={_flag(accept_routes)}", "--timeout=60s"]
    if nickname:
        argv.append(f"--nickname={nickname}")
    if netfilter_mode:
        argv.append(f"--netfilter-mode={netfilter_mode}")
    return argv


# stderr is dropped: netcheck prints a format warning and log lines there, which would break the JSON.
def set_prefs(accept_routes, accept_dns):
    return (f'"$TS_BIN" set --accept-routes={_flag(accept_routes)} --accept-dns={_flag(accept_dns)}\n'
            f'echo "accept-routes {_flag(accept_routes)}, accept-dns {_flag(accept_dns)}"\n')


STATUS_JSON = '"$TS_BIN" status --json 2>/dev/null\n'
NETCHECK_JSON = '"$TS_BIN" netcheck --format=json 2>/dev/null\n'
NODES_JSON = '"$BIN" nodes list -o json 2>/dev/null\n'
USERS_JSON = '"$BIN" users list -o json 2>/dev/null\n'
PROFILES_JSON = '"$TS_BIN" switch --list --json 2>/dev/null || echo "[]"\n'

# With arguments: the nicknames of the profiles to log out of, one per region.
LOGOUT = r"""if [ -x "$TS_BIN" ] && "$TS_BIN" status --json >/dev/null 2>&1; then
  if [ "$#" = 0 ]; then
    "$TS_BIN" logout || true
    echo "logged out"
  fi
  for nick in "$@"; do
    if "$TS_BIN" switch "$nick" >/dev/null 2>&1; then "$TS_BIN" logout || true; echo "logged out of $nick"; fi
  done
else
  echo "tailscaled is not running; nothing to log out"
fi
"""


def switch(region):
    return f'"$TS_BIN" switch {shlex.quote(region.name)} >/dev/null\necho "on profile {region.name}"\n'


def delete_node(node_id):
    return f'"$BIN" nodes delete -i {int(node_id)} --force\n'


def delete_preauth_key(key_id):
    return f'"$BIN" preauthkeys delete -i {int(key_id)}\n'


def _expired(key):
    stamp = key.get("expiration")
    if not stamp:
        return False
    if isinstance(stamp, dict):  # protobuf timestamp as {"seconds": ...}
        return int(stamp.get("seconds", 0)) < time.time()
    try:
        return datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp() < time.time()
    except ValueError:
        return False


def _json(text, what):
    """Parse the JSON in a command's output, ignoring any lines printed before it."""
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    try:
        return json.JSONDecoder().raw_decode(text[min(starts):])[0] if starts else json.loads(text)
    except ValueError:
        raise StepError(f"could not read {what} as JSON") from None


class LocalOps:
    """The Tailscale download cache and the site CA on the operator's machine."""

    def __init__(self, site, out=print):
        self.site = site
        self.out = out

    def ca_pem(self):
        path = self.site.pki_dir / "ca.crt"
        return path.read_text() if path.exists() else None

    def binaries(self, arch):
        """Return {name: path} for tailscale and tailscaled from the pinned .tgz."""
        cache = ensure_private_dir(self.site.cache_dir)
        tgz = fetch_pinned(pins.tailscale_url(arch), cache / pins.tailscale_asset(arch),
                           pins.TAILSCALE_SHA256[arch], self.out)
        folder = ensure_private_dir(cache / f"tailscale_{pins.TAILSCALE_VERSION}_{arch}")
        out = {}
        for name, want in pins.TAILSCALE_BIN_SHA256[arch].items():
            path = folder / name
            if not path.exists() or sha256_file(path) != want:
                with tarfile.open(tgz) as t:
                    member = t.getmember(f"tailscale_{pins.TAILSCALE_VERSION}_{arch}/{name}")
                    data = t.extractfile(member).read()
                write_private(path, data)
                if sha256_file(path) != want:
                    path.unlink()
                    raise StepError(f"{name} in {tgz.name} does not match its pinned sha256")
            out[name] = path
        return out


class Join(Procedure):
    command = "join"

    def __init__(self, site, alias=None, runner=None, ops=None, out=print, member=None):
        """member: a targets.Target; without one, alias is a host that site.toml names."""
        self.site = site
        self.member = member or targets.from_site(site, alias)
        m = self.member
        self.alias = m.alias          # how the runner reaches it
        self.label = dns_label(m.name)
        self.subject = m.name
        self.target = m.name
        self.macos = m.os == "macos"
        self.local = m.local
        self.personal = m.personal
        # A server's region; for a personal device, the region it starts on.
        self.region = site.region(m.region)
        self.regions = [self.region] + ([r for r in site.regions.values() if r.name != self.region.name]
                                        if self.personal else [])
        self.tags = [] if self.personal else site.host_tags(self.alias, self.region)
        self.port = m.port or pins.DEFAULT_TAILSCALE_PORT
        self.netfilter_mode = None if self.macos else m.netfilter_mode
        self.lines_here = render.line_peers(site, self.region)
        self.accept_routes = self.routes_in(self.region)
        self.dns_setting = m.accept_dns
        self.control = self.region.control_host
        self.runner = runner
        self.out = out
        self.ops = ops or LocalOps(site, out)
        self.mark = marker(self.region, m.name, self.personal)
        logins = [r.server_url for r in self.regions]
        if self.macos:
            self.prelude = macos.prelude(self.mark, m.name, logins, self.port, f"tailnet-ops-{slug(site.name)}-ca.crt")
        else:
            self.prelude = host_prelude(site, m.name, self.port, logins, self.mark)
        self.remember = self.forget = None   # set by the CLI: record the join, drop the record
        self.ask_code = None                  # set by the CLI: (region, commands) -> a pasted link code
        self._ca_pem = None
        self.ca_from = None                   # the control host the CA came from, when pki/ has none
        self._reach = {}
        self.control_prelude = scripts.control_prelude(site, self.region)
        self.facts = {}
        if not self.tags and not self.personal:
            raise StepError(f"{alias}: no tags; its region {self.region.name} needs a tag ending in -server")

    def routes_in(self, region):
        """Members take the alias routes the region's border advertises, so they reach the other
        region; a border does not, or it would route the alias range to itself through tailscale0."""
        return bool(render.line_peers(self.site, region)) and not self.site.is_line_end(self.alias)

    @property
    def ts_bin(self):
        """The tailscale CLI: pinned on Linux; on macOS where Homebrew put it, as preflight found."""
        if not self.macos:
            return TS_BIN
        return self.facts.get("ts_bin") or macos.DEFAULT_TS_BIN

    # --- running --------------------------------------------------------------------

    def _host(self, body, args=(), privileged=True, echo=True):
        return self.runner.run(self.alias, scripts.wrap(self.prelude, body), args=args,
                               privileged=privileged, echo=echo)

    def _on_control(self, body, echo=True, region=None, check=True):
        region = region or self.region
        prelude = self.control_prelude if region is self.region else scripts.control_prelude(self.site, region)
        return self.runner.run(region.control_host, scripts.wrap(prelude, body), privileged=True, echo=echo,
                               check=check)

    def can_reach(self, region):
        """Whether this machine can run Headscale as root on the region's control host."""
        if region.name not in self._reach:
            try:
                rc = self._on_control(CONTROL_PING, echo=False, region=region, check=False).rc
            except self.errors:
                rc = 1
            self._reach[region.name] = rc == 0
        return self._reach[region.name]

    def unreachable(self):
        return [r for r in self.regions if not self.can_reach(r)]

    def site_ca(self):
        """(pem, why not): pki/ca.crt, else the copy on the control hosts (checked against their TLS)."""
        if self._ca_pem is None:
            self._ca_pem = self.ops.ca_pem()
        if self._ca_pem is None and self.runner is not None:
            pem, source = siteca.fetch(self.site, self.runner, self.regions)
            if pem is None:
                return None, f"{siteca.missing(self.site, self.region)}; from the control hosts: {source}"
            self._ca_pem, self.ca_from = pem, source
        if self._ca_pem is None:
            return None, siteca.missing(self.site, self.region)
        return self._ca_pem, None

    def _ca(self):
        ca, problem = self.site_ca()
        if ca is None:
            raise StepError(problem)
        return ca

    def _preflight_script(self, ca):
        return macos.preflight(ca) if self.macos else preflight(ca)

    def _run_preflight(self):
        self.facts.update(self._host(self._preflight_script(self._ca())).facts())

    def check(self):
        """Run the read-only preflight and return {"facts", "fails"} for the short plan."""
        ca, problem = self.site_ca()
        if ca is None:
            return {"facts": {}, "fails": [problem]}
        result = self.runner.run(self.alias, scripts.wrap(self.prelude, self._preflight_script(ca)), privileged=True,
                                 check=False, echo=False)
        fails = [line.split("FAIL", 1)[1].strip() for line in result.output.splitlines()
                 if line.lstrip().startswith("FAIL ")]
        self.facts.update(result.facts())
        if result.rc == 255 or (result.rc != 0 and not fails and "TN-FACT machine=" not in result.output):
            last = result.output.strip().splitlines()[-1:] or ["no answer"]
            how = "run as root on this machine (sudo)" if self.local else "log in over SSH as root"
            fails = [f"cannot {how}: {last[0]}"]
        notes = [line.split("note", 1)[1].strip() for line in result.output.splitlines()
                 if line.lstrip().startswith("note ")]
        return {"facts": result.facts(), "fails": fails, "notes": notes,
                "codes": [r.name for r in self.unreachable()]}

    def _dns_text(self):
        if self.dns_setting is not None:
            return f"accept-dns {'on' if self.dns_setting else 'off'} ([hosts.{self.alias}])"
        suffix = self.region.base_domain
        if self.macos:
            return f"accept-dns on (only .{suffix} goes to MagicDNS, through /etc/resolver)"
        if "resolved" not in self.facts:
            return "accept-dns on if the host runs systemd-resolved"
        return ("accept-dns on (systemd-resolved: only ." + suffix + " goes to MagicDNS)"
                if self.accept_dns else "accept-dns off (programs do not use systemd-resolved's stub; DNS stays as it is)")

    def _routes_text(self):
        if self.site.is_line_end(self.alias):
            return "accept-routes off (a line border)"
        if not self.personal:
            if not self.lines_here:
                return "accept-routes off"
            return "accept-routes on: " + "; ".join(f"{o.name} at {o.alias_net}" for _l, o in self.lines_here)
        parts = [f"in {r.name} to " + ", ".join(f"{o.name} at {o.alias_net}" for _l, o in render.line_peers(self.site, r))
                 for r in self.regions if render.line_peers(self.site, r)]
        return f"accept-routes on ({'; '.join(parts)})" if parts else "accept-routes off"

    def region_reason(self):
        if self.alias == self.region.control_host:
            return "its control host"
        if self.alias == self.region.check_from:
            return "its checker host"
        h = self.site.host_settings.get(self.alias)
        if h and h.region == self.region.name:
            return f"[hosts.{self.alias}] region"
        return "chosen"

    def _run_binaries(self):
        if self.macos:
            self._host(macos.INSTALL)
            return
        arch = self.facts.get("arch")
        if arch not in pins.TAILSCALE_BIN_SHA256:
            raise StepError("preflight did not report a supported architecture")
        want = pins.TAILSCALE_BIN_SHA256[arch]
        if all(self.facts.get(name) == want[name] for name in want):
            self.out("    the pinned Tailscale build is already installed; nothing to upload")
            return
        stage = self._host(STAGE, privileged=False).facts().get("stage", "")
        if not stage.startswith("/tmp/tn-tailscale."):
            raise StepError(f"unexpected staging directory {stage!r}")
        self.out(f"    {self.alias} downloads Tailscale {pins.TAILSCALE_VERSION} itself")
        got = self._host(DOWNLOAD, privileged=False, args=[
            stage, pins.tailscale_url(arch), pins.TAILSCALE_SHA256[arch], f"tailscale_{pins.TAILSCALE_VERSION}_{arch}"])
        if got.facts().get("download") != "ok":
            self.out(f"    {self.alias} could not download it; this machine downloads it and uploads it instead")
            for name, path in self.ops.binaries(arch).items():
                self.out(f"    uploading {name} to {stage}/")
                self.runner.upload(self.alias, path, f"{stage}/{name}")
        self._host(INSTALL_BINARIES, args=[stage])

    def _install_ca(self, ca):
        return macos.install_ca(ca) if self.macos else install_ca(ca)

    def _rollback_ca(self, ca):
        return macos.rollback_ca(ca) if self.macos else rollback_ca(ca)

    @property
    def openrc(self):
        """The host runs OpenRC (Alpine), as preflight found; else systemd."""
        return not self.macos and self.facts.get("init") == "openrc"

    def _service(self):
        if self.macos:
            return macos.SERVICE
        tailnets = ", ".join(r.name for r in self.regions)
        if self.openrc:
            return openrc_service(openrc_script(self.mark, tailnets, self.port))
        return service(unit(self.mark, tailnets, self.port))

    def _run_ca(self):
        self._host(self._install_ca(self._ca()))

    def _run_service(self):
        self._host(self._service())

    def _status(self):
        return _json(self._host(STATUS_JSON, echo=False).output, "tailscale status")

    @property
    def accept_dns(self):
        """[hosts] accept_dns; else on on macOS, which sends only the suffix to MagicDNS, and on
        Linux where preflight found systemd-resolved."""
        if self.dns_setting is not None:
            return self.dns_setting
        return self.macos or self.facts.get("resolved") == "yes"

    def _argv(self, region, verb="up"):
        return up_argv(region, self.label, None if self.macos else self.netfilter_mode, self.routes_in(region),
                       self.accept_dns, self.ts_bin, verb, region.name if self.personal else None)

    def _run_join(self):
        if self.personal:
            self._join_personal()
            return
        status = self._status()
        if status.get("BackendState") == "Running":
            self.out("    already joined; no new key made; bringing its settings in line with the plan")
            self._host(set_prefs(self.accept_routes, self.accept_dns))
            return
        self._log_in(self.region, "up", preauth_key(self.tags))

    def _log_in(self, region, verb, key_script):
        """`tailscale up` or `login` with a key: straight from the control host when this machine can
        log in to it, else from a link code the user makes elsewhere and pastes."""
        argv = self._argv(region, verb)
        whose = f"user {self.site.owner_user}" if self.personal else ", ".join(self.tags)
        if self.can_reach(region):
            self.out(f"    {region.name}: a single-use, {pins.PREAUTH_KEY_EXPIRY} key for {whose} goes from "
                     f"{region.control_host} straight into `tailscale {verb}` on {self.alias}; it is never shown "
                     "or stored here")
            self.runner.pipe(region.control_host, scripts.wrap(scripts.control_prelude(self.site, region), key_script),
                             self.alias, argv)
            return
        commands = code_commands(self.site, region, self.tags)
        if self.ask_code is None:
            raise StepError(f"cannot log in to {region.control_host}; make a link code where you can with "
                            f"`{commands[0][1]}` and run tn join in a terminal to paste it")
        code = self.ask_code(region, commands)
        self.out(f"    {region.name}: the link code goes into `tailscale {verb}` on {self.alias}; it is not stored")
        self.runner.feed(self.alias, argv, code)

    def _run_names(self):
        missing = [r for r in self.site.regions.values() if not self.can_reach(r)]
        if missing:
            self.out(f"    skipped: this machine cannot log in to {', '.join(r.control_host for r in missing)}. "
                     "Run `tn dns sync` on a machine that can; until then the other regions do not know this name.")
            return
        names.Names(self.site, self.runner, self.out).sync()

    def _profiles(self):
        """The device's Tailscale profiles by nickname; a personal device has one per region."""
        found = _json(self._host(PROFILES_JSON, echo=False).output, "tailscale switch --list") or []
        return {p.get("nickname"): p for p in found if isinstance(p, dict)}

    def _owner_id(self, region):
        users = _json(self._on_control(USERS_JSON, echo=False, region=region).output or "[]",
                      "headscale users list") or []
        found = [u.get("id") for u in users if u.get("name") == self.site.owner_user]
        if not found:
            raise StepError(f"{region.control_host} has no Headscale user {self.site.owner_user}; "
                            f"run `tn control apply {region.name}`")
        return int(found[0])

    def _join_personal(self):
        profiles = self._profiles()
        for r in self.regions:
            verb = "login"
            if r.name in profiles:
                self._host(switch(r), echo=False)
                if self._status().get("BackendState") == "Running":
                    self.out(f"    {r.name}: already joined; no new key made; bringing its settings in line with the plan")
                    self._host(set_prefs(self.routes_in(r), self.accept_dns))
                    continue
                verb = "up"   # the profile is there but logged out: log it in again in place
            key = user_key(self._owner_id(r)) if self.can_reach(r) else None
            self._log_in(r, verb, key)
        self._host(switch(self.region))

    def _run_verify(self):
        status = self._status()
        problems = []
        state = status.get("BackendState")
        me = status.get("Self") or {}
        ips = me.get("TailscaleIPs") or []
        tags = sorted(me.get("Tags") or [])
        prefix = ipaddress.ip_network(self.region.ipv4_prefix)
        v4 = [ip for ip in ips if ":" not in ip]
        self.out(f"    state {state}; addresses {', '.join(ips) or 'none'}; tags {', '.join(tags) or 'none'}")
        if state != "Running":
            problems.append(f"tailscaled is {state}, not Running")
        if not v4 or ipaddress.ip_address(v4[0]) not in prefix:
            problems.append(f"no address inside {prefix}")
        if tags != sorted(self.tags):
            problems.append(f"tags are {tags}, expected {sorted(self.tags)}")
        if self.personal:
            have = self._profiles()
            missing = [r.name for r in self.regions if r.name not in have]
            self.out(f"    profiles {', '.join(sorted(n for n in have if n)) or 'none'}")
            if missing:
                problems.append(f"no profile for {', '.join(missing)}")
        net = _json(self._host(NETCHECK_JSON, echo=False).output, "tailscale netcheck")
        derp = net.get("PreferredDERP")
        self.out(f"    preferred DERP region {derp}; UDP {'ok' if net.get('UDP') else 'blocked'}")
        if derp != self.region.derp_region_id:
            problems.append(f"preferred DERP region is {derp}, expected {self.region.derp_region_id}")
        for r in self.regions:
            if not self.can_reach(r):
                self.out(f"    {r.control_host}: not checked (this machine cannot log in to it)")
                continue
            mine = self._mine(self._nodes(r))
            self.out(f"    {r.control_host} lists {len(mine)} node(s) named {self.label}")
            if len(mine) != 1:
                problems.append(f"{r.control_host} should list exactly one node named {self.label}")
        if self.accept_routes and state == "Running" and v4:
            problems += self._check_across(v4[0])
        if problems:
            raise StepError("; ".join(problems))
        self.out("    verify passed")

    def _check_across(self, my_ip):
        """From this host, with its tailnet address as the source, ping the far border of each line."""
        problems = []
        routes = None if self.macos else self._host("ip -4 route show table 52 2>/dev/null\n", echo=False).output
        for ln, other in self.lines_here:
            alias = str(other.alias_net)
            far = ln.responder if self.site.host_region(ln.initiator).name == self.region.name else ln.initiator
            no_route = f"no route to {alias} (line {ln.name}); is the line applied and its route approved?"
            if routes is not None and alias not in routes:
                problems.append(no_route)
                self.out(f"    ✗ no route to {other.name} ({alias})")
                continue
            if not self.can_reach(other):
                self.out(f"    {other.name}: the ping across line {ln.name} is not checked "
                         f"(this machine cannot log in to {other.control_host} to find {far})")
                continue
            nodes = _json(self.runner.run(other.control_host, scripts.wrap(
                scripts.control_prelude(self.site, other), NODES_JSON), privileged=True, echo=False).output or "[]",
                "headscale nodes list") or []
            node = next((n for n in nodes if str(n.get("given_name", "")).lower() == dns_label(far)), None)
            ip = next((x for x in (node or {}).get("ip_addresses") or [] if ":" not in x), None)
            if ip is None:
                problems.append(f"{far} is not in region {other.name}'s tailnet")
                continue
            target = other.alias_of(ip)
            if self.macos:
                out = self._host(macos.reach(my_ip, target), echo=False).output
                if "TN-ROUTE ok" not in out:
                    problems.append(no_route)
                    self.out(f"    ✗ no route to {other.name} ({alias})")
                    continue
            else:
                out = self._host(f"ping -c 3 -W 2 -I {my_ip} {target} >/dev/null 2>&1 && echo TN-PING ok || echo TN-PING fail\n",
                                 echo=False).output
            ok = "TN-PING ok" in out
            self.out(f"    {'✓' if ok else '✗'} reaches {far} in {other.name} at {target} through line {ln.name}")
            if not ok:
                problems.append(f"cannot reach {far} at {target} through line {ln.name}")
        return problems

    def _nodes(self, region=None):
        return _json(self._on_control(NODES_JSON, echo=False, region=region).output or "[]", "headscale nodes list") or []

    def _mine(self, nodes):
        return [n for n in nodes if str(n.get("given_name", "")).lower() == self.label]

    def _stale_keys(self, nodes, region=None):
        """Pre-auth keys like this host's (its tags; for a personal device, the owner's and untagged)
        that no node uses and that are used up or expired."""
        keys = _json(self._on_control(PREAUTH_KEYS_JSON, echo=False, region=region).output or "[]",
                     "headscale preauthkeys list") or []
        in_use = {str((n.get("pre_auth_key") or {}).get("id")) for n in nodes}

        def like_ours(k):
            if sorted(k.get("acl_tags") or []) != sorted(self.tags):
                return False
            return not self.personal or (k.get("user") or {}).get("name") == self.site.owner_user

        return [k for k in keys if like_ours(k) and str(k.get("id")) not in in_use and (k.get("used") or _expired(k))]

    def _undo_join(self):
        self._host(LOGOUT, args=[r.name for r in self.regions] if self.personal else ())
        for r in self.regions:
            if not self.can_reach(r):
                self.out(f"    this machine cannot log in to {r.control_host}; delete the node there by hand:\n"
                         f"      sudo {render.BIN} nodes list | grep -w {self.label}\n"
                         f"      sudo {render.BIN} nodes delete -i <ID> --force")
                continue
            nodes = self._nodes(r)
            mine = self._mine(nodes)
            if not mine:
                self.out(f"    {r.control_host} lists no node named {self.label}")
            for n in mine:
                self.out(f"    deleting node {n.get('id')} ({n.get('given_name')}) on {r.control_host}")
                self._on_control(delete_node(n.get("id")), region=r)
            remaining = [n for n in nodes if n not in mine]
            for k in self._stale_keys(remaining, r):
                self.out(f"    deleting pre-auth key {k.get('id')} ({'used' if k.get('used') else 'expired'}) "
                         f"on {r.control_host}")
                self._on_control(delete_preauth_key(k.get("id")), region=r)

    def _leftovers_script(self):
        return macos.leftovers(self._ca()) if self.macos else LEFTOVERS

    def leftovers(self):
        """Read-only: what join left on the host and in Headscale. Empty list = nothing."""
        left = [line[len("TN-LEFT "):] for line in self._host(self._leftovers_script(), echo=False).output.splitlines()
                if line.startswith("TN-LEFT ")]
        for r in self.regions:
            if not self.can_reach(r):
                self.out(f"    Headscale on {r.control_host}: not checked (this machine cannot log in to it)")
                continue
            nodes = self._nodes(r)
            left += [f"node {n.get('id')} ({n.get('given_name')}) in Headscale on {r.control_host}" for n in self._mine(nodes)]
            left += [f"pre-auth key {k.get('id')} in Headscale on {r.control_host}" for k in self._stale_keys(nodes, r)]
        return left

    def after_rollback(self):
        try:
            self.out("\n== names")
            names.Names(self.site, self.runner, self.out).sync()
        except self.errors as e:
            self.out(f"Could not update the cross-region names: {e}")
        try:
            left = self.leftovers()
        except self.errors as e:
            self.out(f"\nCould not check for leftovers: {e}")
            return
        controls = ", ".join(r.control_host for r in self.regions)
        if left:
            self.out(f"\n✗ Still there after rollback ({len(left)}):")
            for item in left:
                self.out(f"  ✗ {item}")
        else:
            self.out(f"\n✓ Nothing left: no Tailscale files, {'launchd job' if self.macos else 'unit'}, "
                     f"{'' if self.macos else 'interface '}or process on {self.alias}, "
                     f"and no node or key for it in Headscale on {controls}.")
            if self.forget:
                self.forget(self.member)

    def before_steps(self):
        if self.ca_from:
            siteca.save(self.site, self._ca())
            self.out(f"Saved the site CA certificate from {self.ca_from} to {siteca.path(self.site)}.")
        if self.remember:
            self.remember(self.member)

    def run_rollback(self, step):
        if step.number == 3:
            self._host(self._rollback_ca(self._ca()))
        else:
            self._host(step.rollback)

    # --- the steps --------------------------------------------------------------------

    def _os_steps(self):
        """Steps 1-4, which depend on the host's OS."""
        a, r = self.alias, self.region
        logins = ", ".join(x.server_url for x in self.regions)
        if self.macos:
            return [
                Step(
                    1, "Preflight",
                    ["Check macOS, arch, root, tools and Homebrew; that udp/"
                     f"{self.port} is free; that no other Tailscale runs (the app, brew services);",
                     f"that {a} reaches {logins} over TLS with the site CA. Changes nothing."],
                    [Action(a, "read-only checks", macos.preflight(CA_PLACEHOLDER), "host", True)],
                    rollback_note="none needed (read-only)", read_only=True, run=self._run_preflight,
                    brief="Check the Mac",
                ),
                Step(
                    2, "Tailscale",
                    ["brew install tailscale, as the user who owns Homebrew, unless it is installed already",
                     f"(then it is used as it is). Needs version {macos.MIN_VERSION} or later."],
                    [Action(a, "install with Homebrew", macos.INSTALL, "host", True)],
                    rollback=macos.ROLLBACK_INSTALL,
                    rollback_note="brew uninstall tailscale, only if tailnet-ops installed it",
                    run=self._run_binaries, brief="Install tailscale with Homebrew",
                    undo_brief="uninstall it if tn installed it",
                ),
                Step(
                    3, "Site CA",
                    ["Add the site CA to the System keychain, trusted for TLS only, so tailscaled accepts",
                     f"{logins}. macOS asks for your password or Touch ID in a window. Skipped when it is trusted."],
                    [Action(a, "trust the CA", macos.install_ca(CA_PLACEHOLDER), "host", True)],
                    rollback=macos.rollback_ca(CA_PLACEHOLDER),
                    rollback_note="remove the CA from the System keychain if tailnet-ops added it",
                    run=self._run_ca, brief="Trust the site CA (macOS asks in a window)",
                    undo_brief="remove it from the keychain",
                ),
                Step(
                    4, "tailscaled",
                    [f"Write {macos.PLIST} (port udp/{self.port}, --no-logs-no-support), mark {macos.TS_STATE},",
                     "start it with launchctl bootstrap (RunAtLoad, KeepAlive: it starts at boot and restarts if it",
                     "stops), wait until it answers."],
                    [Action(a, "write the launchd job and start", macos.SERVICE, "host", True)],
                    rollback=macos.ROLLBACK_SERVICE,
                    rollback_note=f"stop tailscaled, remove the launchd job and {macos.TS_STATE}",
                    run=self._run_service, brief="Start tailscaled, at boot too",
                    undo_brief="stop it, remove the job and state",
                ),
            ]
        ca_note = f"{ca_file(self.site)} plus update-ca-certificates"
        return [
            Step(
                1, "Preflight",
                ["Check arch, OS, root, systemd or OpenRC, /dev/net/tun and tools; that udp/"
                 f"{self.port} is free; that no other Tailscale is installed;",
                 f"that {a} reaches {logins} over TLS with the site CA. Changes nothing."],
                [Action(a, "read-only checks", preflight(CA_PLACEHOLDER), "host", True)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_preflight,
                brief="Check the host",
            ),
            Step(
                2, "Binaries",
                [f"The host downloads the static Tailscale {pins.TAILSCALE_VERSION} for its architecture from pkgs.tailscale.com",
                 "and checks the archive's pinned sha256. If it cannot download it, this machine downloads it into",
                 "cache/ and copies the two binaries over. Each binary's pinned sha256 is checked before",
                 f"{TS_BIN} and {TSD_BIN} are installed. Skipped when the pinned build is already installed."],
                [
                    Action(a, "make a staging directory", STAGE, "host", False),
                    Action(a, "download and check the archive; $1 staging directory, $2 url, $3 sha256, $4 folder",
                           DOWNLOAD, "host", False),
                    Action("local", f"only if the host could not download it: fetch {pins.tailscale_url('<arch>')} "
                           "unless cached, verify it, scp tailscale and tailscaled to <staging directory>/"),
                    Action(a, "verify and install; $1 is the staging directory", INSTALL_BINARIES, "host", True),
                ],
                rollback=ROLLBACK_BINARIES, rollback_note="remove both binaries if they are the pinned build",
                run=self._run_binaries, brief=f"Install Tailscale {pins.TAILSCALE_VERSION}",
                undo_brief="remove both binaries",
            ),
            Step(
                3, "Site CA",
                [f"Trust the site CA system-wide ({ca_note}), so tailscaled",
                 f"accepts {logins}. Then check that plain curl accepts it too."],
                [Action(a, "install the CA certificate", install_ca(CA_PLACEHOLDER), "host", True)],
                rollback=rollback_ca(CA_PLACEHOLDER),
                rollback_note="remove the CA file if it is this site's and rebuild the trust store",
                run=self._run_ca, brief="Trust the site CA", undo_brief="remove the CA file",
            ),
            Step(
                4, "tailscaled",
                ([f"Write {TS_INIT}, an OpenRC service under supervise-daemon (port udp/{self.port},",
                  f"--no-logs-no-support), mark {TS_STATE}; rc-update add tailscaled default and start it",
                  "(it starts at boot and is restarted if it dies), wait until it answers."] if self.openrc else
                 [f"Write {TS_UNIT} (port udp/{self.port}, --no-logs-no-support), mark {TS_STATE},",
                  "systemctl enable --now tailscaled (it starts at boot and restarts on failure), wait until it "
                  "answers."]),
                [Action(a, "write the service and start", self._service(), "host", True)],
                rollback=ROLLBACK_SERVICE,
                rollback_note=f"stop and disable tailscaled, remove its service, {TS_STATE} and {TS_CACHE}",
                run=self._run_service, brief="Start tailscaled, at boot too",
                undo_brief="stop it, remove the service and state",
            ),
        ]

    def _join_step(self):
        a, r = self.alias, self.region
        if not self.personal:
            return Step(
                5, "Join",
                [f"On {self.control}: make a single-use pre-auth key, valid {pins.PREAUTH_KEY_EXPIRY}, tagged "
                 f"{', '.join(self.tags)}.",
                 f"Its stdout goes through ssh straight into `tailscale up` on {a}; this machine never reads,",
                 "prints or stores it. Skipped when the host is already joined."],
                [
                    Action(self.control, "make the key (stdout only)", preauth_key(self.tags), "control", True),
                    Action(a, "join with the key on stdin: " + " ".join(shlex.quote(x) for x in self._argv(r)),
                           None, None, True),
                    Action(a, "if it is already joined, set the same options instead",
                           set_prefs(self.accept_routes, self.accept_dns), "host", True),
                    self._code_action(r),
                ],
                rollback=LOGOUT,
                rollback_note=f"log out, then delete the node named {self.label} on {self.control} "
                              "(`headscale nodes delete -i <id> --force`) and its used or expired pre-auth keys "
                              "(`headscale preauthkeys delete -i <id>`)",
                run=self._run_join, undo=self._undo_join, brief="Join with a one-time tagged key",
                undo_brief=f"log out, delete the node and its key on {self.control}",
            )
        owner = self.site.owner_user
        regions = ", ".join(x.name for x in self.regions)
        controls = ", ".join(x.control_host for x in self.regions)
        actions = [Action(controls, f"in each region, make the key for user {owner} (stdout only)",
                          user_key("<id of user " + owner + ">"), "control", True)]
        for x in self.regions:
            actions.append(Action(a, f"log in to {x.name} as a new profile, the key on stdin: "
                                  + " ".join(shlex.quote(v) for v in self._argv(x, "login")), None, None, True))
        actions += [
            Action(a, "if a region's profile is already joined, switch to it and set the same options instead",
                   set_prefs(self.accept_routes, self.accept_dns), "host", True),
            *[self._code_action(x) for x in self.regions],
            Action(a, f"end on {r.name}", switch(r), "host", True),
        ]
        return Step(
            5, "Join",
            [f"For each region ({regions}): its control host makes a single-use pre-auth key, valid "
             f"{pins.PREAUTH_KEY_EXPIRY}, owned by",
             f"user {owner}, without tags. Its stdout goes through ssh straight into `tailscale login "
             f"--nickname=<region>` on {a}:",
             "one profile per region. This machine never reads, prints or stores a key. A region already joined",
             f"is skipped. Ends on {r.name}."],
            actions,
            rollback=LOGOUT,
            rollback_note=f"log out of every profile, then delete the node named {self.label} in each region's "
                          "Headscale and its used or expired pre-auth keys",
            run=self._run_join, undo=self._undo_join, brief=f"Join {regions} as {owner}, a profile each",
            undo_brief=f"log out, delete the nodes and keys on {controls}",
        )

    def _code_action(self, region):
        return Action("you", f"only if this machine cannot log in to {region.control_host}: make a single-use, "
                      f"{pins.JOIN_CODE_EXPIRY} link code where you can, and paste it when step 5 asks",
                      code_commands(self.site, region, self.tags)[0][1] + "\n")

    def steps(self):
        a, r = self.alias, self.region
        controls = ", ".join(x.control_host for x in self.regions)
        steps = self._os_steps() + [
            self._join_step(),
            Step(
                6, "Names",
                [f"Give every region that reaches {r.name} through a line a DNS name for {a}:",
                 f"{self.label}.{r.base_domain} at its alias address there. Names of the other regions' hosts",
                 "are updated the same way; Headscale reloads them by itself."],
                [Action(self.control, "list nodes on each control host, write its extra records file",
                        names.write([{"name": "<name>.<suffix>", "type": "A", "value": "<alias address>"}]),
                        "control", True)],
                rollback_note="none separate: the names are updated again after a rollback",
                run=self._run_names, brief="Update the cross-region names", undo_brief="updated after rollback",
            ),
            Step(
                7, "Verify",
                [f"On {a}: tailscaled is Running with an address in {r.ipv4_prefix}, "
                 + (f"no tags, a profile for each of {', '.join(x.name for x in self.regions)},"
                    if self.personal else f"tags {', '.join(self.tags)},"),
                 f"and prefers DERP region {r.derp_region_id}. On {controls}: exactly one node named "
                 f"{self.label}. Read-only."],
                [
                    Action(a, "status and netcheck", STATUS_JSON + NETCHECK_JSON, "host", True),
                    Action(controls, "list nodes", NODES_JSON, "control", True),
                ],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_verify,
                brief="Check the join",
            ),
        ]
        for step in steps:
            step.host = a
        return steps

    # --- printing ---------------------------------------------------------------------

    def _starter(self):
        return "launchd" if self.macos else ("OpenRC" if self.openrc else "systemd")

    def _adds(self):
        if self.macos:
            return f"Homebrew's tailscale (unless there), {macos.PLIST}, {macos.TS_STATE}, the site CA in the keychain"
        service = TS_INIT if self.openrc else "tailscaled.service"
        return f"tailscale, tailscaled, {service}, {TS_STATE}, the site CA"

    def _who(self):
        """The first lines of the summary: where the host goes and as whom."""
        r, a = self.region, self.alias
        if not self.personal:
            return [f"{a} → region {r.name} ({self.region_reason()}): tailnet {r.ipv4_prefix}, name {self.fqdn}"]
        owner = self.site.owner_user
        out = [f"{a} → personal device of {owner} in {', '.join(x.name for x in self.regions)}; starts on {r.name}",
               f"  identity      user {owner}, no tags; one profile per region, switch with "
               f"`sudo tailscale switch <region>`"]
        for x in self.regions:
            out.append(f"  {x.name:<12}  tailnet {x.ipv4_prefix}, name {self.label}.{x.name}.{x.base_domain}")
        return out

    def summary_header(self, checks=None):
        r, a = self.region, self.alias
        facts = checks["facts"] if checks else {}
        ok, bad = "✓", "✗"

        def mark(good, yes, no):
            if checks is None or not facts:
                return ""
            return f"  {ok} {yes}" if good else f"  {bad} {no}"

        port = facts.get("port")
        logins = ", ".join(x.server_url for x in self.regions)
        out = self._who() + [
            f"  login server  {logins}"
            + mark(facts.get("login") == "ok", f"{a} reaches {'them' if self.personal else 'it'} over TLS",
                   f"{a} cannot reach {'them' if self.personal else 'it'}"),
        ]
        if not self.personal:
            out.append(f"  tags          {', '.join(self.tags)}")
        out += [
            f"  tailscaled    udp/{self.port}, no log upload; a daemon that starts at boot ({self._starter()})"
            + mark(port in ("free", "ours"), "port free" if port == "free" else "already ours", "port in use"),
            f"  options       {self._options()}",
        ]
        if facts:
            out.append(f"  host          {facts.get('os', '?')}, {facts.get('machine', '?')}"
                       + ("  (already joined by tailnet-ops)" if facts.get("joined") == "ours" else ""))
        for name in (checks or {}).get("codes", []):
            x = self.site.region(name)
            out.append(f"  link code     {bad} this machine cannot log in to {x.control_host}: step 5 shows a command "
                       "to make a link code elsewhere, then asks you to paste it")
        if self.ca_from:
            out.append(f"  site CA       from {self.ca_from}: it authenticates every login server; a copy goes to pki/")
        for n in (checks or {}).get("notes", []):
            out.append(f"  note          {n}")
        if self.macos and facts.get("ca") == "no":
            out.append("  site CA       not trusted yet: macOS asks for your password or Touch ID in step 3")
        out += [f"  adds          {self._adds()}", "  leaves alone  everything else"]
        if checks is None:
            out.append("  checks        not run (--offline)")
        elif checks["fails"]:
            out += ["", f"Not ready to join ({len(checks['fails'])}):"] + [f"  {bad} {f}" for f in checks["fails"]]
        else:
            out += ["", f"{ok} Ready: every read-only check on {a} passed."]
        return "\n".join(out)

    def _options(self):
        nf = "" if self.macos else f", netfilter {self.netfilter_mode or 'on (tailscaled adds its own rules)'}"
        return f"{self._dns_text()}, {self._routes_text()}{nf}"

    def header(self):
        r, a = self.region, self.alias
        version = f"Homebrew's tailscale, {macos.MIN_VERSION} or later" if self.macos else f"Tailscale {pins.TAILSCALE_VERSION}"
        if self.personal:
            first = (f"{a} joins {', '.join(x.name for x in self.regions)} as a personal device of "
                     f"{self.site.owner_user}, starting on {r.name} ({version})")
            login = ", ".join(f"{x.server_url} ({x.name}, Headscale on {x.control_host})" for x in self.regions)
            tags = f"none: user {self.site.owner_user}; one profile per region, nickname = region"
        else:
            first = f"{a} joins region {r.name} as {self.fqdn} ({version})"
            login = f"{r.server_url} (Headscale on {self.control})"
            tags = ", ".join(self.tags)
        return "\n".join([
            first,
            f"  login server  {login}",
            f"  tags          {tags}",
            f"  tailscaled    udp/{self.port}, no log upload; a daemon that starts at boot ({self._starter()})",
            f"  options       {self._options()}",
            f"  adds          {self._adds()}",
            "  leaves alone  everything else",
        ])

    def preludes(self):
        out = [(f"{self.alias}", self.prelude), (f"{self.control}, control host", self.control_prelude)]
        for r in self.regions[1:]:
            out.append((f"{r.control_host}, control host of {r.name}", scripts.control_prelude(self.site, r)))
        return out

    def plan_intro(self):
        where = "here with sudo (this machine joins)" if self.local else "as `bash -s` over SSH"
        return (f"Every script on {self.alias} runs {where}: the prelude of its host, then the step body inside\n"
                "`tn_step() { ... }` with stdin from /dev/null. Control hosts' scripts run over SSH the same way.\n"
                "The one exception is `tailscale up` or `login` in step 5, whose stdin is the pre-auth key.")

    def rollback_footer(self):
        return "It keeps the download cache on this machine."

    @property
    def fqdn(self):
        """The name tn shows: with the region; the short <name>.<suffix> works too."""
        return f"{self.label}.{self.region.name}.{self.region.base_domain}"

    def done_message(self):
        label = self.label
        if self.personal:
            others = " ".join(f"`sudo tailscale switch {x.name}`" for x in self.regions)
            return (f"{self.alias} joined {', '.join(x.name for x in self.regions)} as a personal device of "
                    f"{self.site.owner_user} and is on {self.region.name} now ({self.fqdn}).\n"
                    f"Switch region with {others}.")
        return (f"{self.alias} joined region {self.region.name} as {self.fqdn} "
                f"(also {label}.{self.region.base_domain} and {label}).")

    def rolled_back_message(self):
        return (f"Rolled back the join of {self.alias}. Kept on purpose: the download cache and run logs on this "
                "machine" + ("." if self.macos else ", and the host's system journal."))

    def preflight(self):
        return self.run_once(self._run_preflight)

    def apply(self, yes=False, ask=input, checks=None):
        """Read the host first, as `tn join plan` does, so the plan id shown here matches."""
        try:
            checks = self.check()
        except self.errors as e:
            self.out(f"FAILED reading {self.alias}: {e}")
            return 1
        if checks["fails"]:
            self.out(self.summary_text(checks))
            self.out("Not applied; nothing changed.")
            return 1
        return super().apply(yes=yes, ask=ask, checks=checks)

    def verify(self):
        return self.run_once(self._run_verify)
