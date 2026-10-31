"""`tn agent`: an MCP endpoint for Agents and an approval page for the owner, on a region's control host,
reached through a Cloudflare tunnel at agent_domain. No port opens on the host.

On the control host, three services:

- tn-cloudflared.service: cloudflared (pinned), a dynamic user, the tunnel's token root-only. It brings
  requests for agent_domain from Cloudflare's edge to loopback.
- tn-agent.service, user tn-agent-web: the web half, on 127.0.0.1:agent_port only, and allowed to talk
  to loopback only. No state, no rights; it relays every call over a Unix socket.
- tn-agent-helper.service, user tn-agent in group headscale, no network: the private half. It keeps
  the passkeys and requests, checks the token and every passkey signature, and runs the headscale
  commands.

tn makes the tunnel, its route and the agent_domain CNAME through the Cloudflare API with the same
token as the login server's certificate; what it makes carries a mark, and rollback removes only that.

An Agent reads the tailnet and asks for join commands; the machine hands its login to the service
itself, and each join waits until the owner approves it with a passkey that `tn agent enroll` let
them register. The Agent never gets a key. Machines it joins carry the region's agent tag and start
no connection (render.policy).
"""

import hashlib
import io
import json
import re
import secrets
import shutil
import subprocess
import zipfile
from pathlib import Path

from . import VERSION, join, pins, render, scripts
from .agentd import VERSION as SERVICE_VERSION
from .cloudflare import TUNNEL_SUFFIX, Cloudflare, CloudflareError, in_the_way
from .procedure import Action, Procedure, Step, StepError, fetch_pinned
from .site import ensure_private_dir, write_private

DIR = "/opt/tn-agent"
ETC = "/etc/tn-agent"
STATE = "/var/lib/tn-agent"
WEB_UNIT = "/etc/systemd/system/tn-agent.service"
HELPER_UNIT = "/etc/systemd/system/tn-agent-helper.service"
TUNNEL_UNIT = "/etc/systemd/system/tn-cloudflared.service"
TUNNEL_ENV = f"{ETC}/tunnel.env"     # TUNNEL_TOKEN=…, root only
CLOUDFLARED = f"{DIR}/cloudflared"
USER = "tn-agent"            # the private half
WEB_USER = "tn-agent-web"    # the web half
SOCKET = "/run/tn-agent/helper.sock"
MIN_SYSTEMD = 235            # DynamicUser, IPAddressDeny
NAME_SLOT, TAGS_SLOT, SCRIPT_SLOT = "__TN_NAME__", "__TN_TAGS__", "__TN_SCRIPT__"
ENROL_SECONDS = 600
TOKEN_RE = re.compile(r"^tna_[A-Za-z0-9_-]{40,}$")
PACKAGE = Path(__file__).resolve().parent / "agentd"
SKILL = Path(__file__).resolve().parent.parent / "skills" / "tailnet-ops" / "SKILL.md"

# Both halves: no capabilities, a read-only system; memory throttled at MemoryHigh and capped at
# MemoryMax, and under memory pressure the kernel kills them before Headscale. TasksMax is far above
# what memory allows, so only memory binds; it is there so no bug can use up the host's process ids,
# which Headscale needs too.
HARDENING = """NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
OOMScoreAdjust=500
TasksMax=4096
MemoryHigh=200M
MemoryMax=256M"""


def origin(region):
    return f"https://{region.agent_domain}"


def tunnel_name(region):
    return f"tailnet-ops-{region.name}"


def cname_mark(region):
    return f"tailnet-ops agent region={region.name}"


# --- what goes to the host ------------------------------------------------------------


def guide():
    """The Skill without its front matter: what tailnet_guide returns."""
    text = SKILL.read_text()
    if text.startswith("---\n"):
        text = text.split("\n---\n", 1)[1].lstrip("\n")
    return text


def bundle():
    """The service as one zip, byte for byte the same for the same code: sorted names, fixed times."""
    files = {"__main__.py": "from agentd.server import main\n\nmain()\n", "agentd/guide.md": guide()}
    for path in sorted(PACKAGE.glob("*.py")):
        if path.name != "__main__.py":
            files[f"agentd/{path.name}"] = path.read_text()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            z.writestr(info, files[name])
    return buf.getvalue()


def config(site, region):
    return {
        "region": region.name, "listen": "127.0.0.1", "port": region.agent_port, "proxy": "cloudflare",
        "origin": origin(region), "rp_id": region.agent_domain, "login_server": region.server_url,
        "owner": site.owner_user, "tags": [region.agent_tag], "socket": SOCKET,
        "headscale": render.BIN, "headscale_config": f"{render.ETC}/config.yaml",
        "etc": ETC, "state": STATE, "join_template": f"{DIR}/join.sh", "leave_template": f"{DIR}/leave.sh",
        "resume_template": f"{DIR}/resume.sh",
    }


def config_text(site, region):
    return json.dumps(config(site, region), indent=1, sort_keys=True) + "\n"


JOIN_BINARIES = r"""if [ "$(sha256sum "$TS_BIN" 2>/dev/null | cut -d' ' -f1)" = "$(want_sum tailscale)" ] &&
   [ "$(sha256sum "$TSD_BIN" 2>/dev/null | cut -d' ' -f1)" = "$(want_sum tailscaled)" ]; then
  echo "the pinned Tailscale build is installed already"
  return 0
fi
case "$arch" in
  amd64) url=$ARCHIVE_URL_AMD64; want=$ARCHIVE_SUM_AMD64 ;;
  arm64) url=$ARCHIVE_URL_ARM64; want=$ARCHIVE_SUM_ARM64 ;;
  *) die "no pinned Tailscale build for $(uname -m)" ;;
esac
stage=$(mktemp -d /tmp/tn-tailscale.XXXXXXXX)
echo "downloading $url"
if ! curl -fsSL --max-time 600 --retry 2 -o "$stage/tailscale.tgz" "$url"; then
  rm -rf "$stage"
  die "cannot download $url"
fi
got=$(sha256sum "$stage/tailscale.tgz" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  rm -rf "$stage"
  die "the download does not match its pinned sha256: $got"
fi
folder="tailscale_${TS_VERSION}_$arch"
tar -xzf "$stage/tailscale.tgz" -C "$stage" "$folder/tailscale" "$folder/tailscaled"
mv "$stage/$folder/tailscale" "$stage/$folder/tailscaled" "$stage/"
rmdir "$stage/$folder"
rm -f "$stage/tailscale.tgz"
echo "archive sha256 ok"
if [ "$mode" = user ]; then tn_user_install "$stage"; else tn_install_binaries "$stage"; fi
"""

# Shared by the join, leave and resume scripts, after the prelude: system or user mode, and how to reach
# tailscaled in each. User mode is for a machine without root or without systemd/OpenRC (a container, a
# sandbox): the same pinned build runs as the user, in userspace networking, from the user's own directory,
# and other programs reach the tailnet through its SOCKS5/HTTP proxy on localhost.
MACHINE_MODE = r"""UDIR=${TN_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/tailnet-ops/tailscale-$REGION}
SOCKS=${TN_SOCKS:-1055}
mode=${TN_MODE:-}
if [ -z "$mode" ]; then
  if [ "$(id -u)" = 0 ] && { [ -d /run/systemd/system ] || command -v openrc-run >/dev/null 2>&1; }; then
    mode=system
  else
    mode=user
  fi
fi
case "$mode" in system|user) ;; *) die "TN_MODE is system or user" ;; esac
ts_args=()
if [ "$mode" = user ]; then
  TS_BIN="$UDIR/tailscale"
  TSD_BIN="$UDIR/tailscaled"
  ts_args=(--socket="$UDIR/tailscaled.sock")
fi
ts() { "$TS_BIN" ${ts_args[@]+"${ts_args[@]}"} "$@"; }
field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -n 1; }
ours_udir() { [ -f "$UDIR/.tailnet-ops" ] && [ "$(cat "$UDIR/.tailnet-ops")" = "$MARK" ]; }
user_running() { [ -f "$UDIR/tailscaled.pid" ] && kill -0 "$(cat "$UDIR/tailscaled.pid")" 2>/dev/null; }
user_start() {
  if user_running; then
    echo "tailscaled runs already (pid $(cat "$UDIR/tailscaled.pid"))"
  else
    detach=()
    if command -v setsid >/dev/null; then detach=(setsid); fi
    nohup ${detach[@]+"${detach[@]}"} "$TSD_BIN" --tun=userspace-networking --statedir="$UDIR" \
      --state="$UDIR/tailscaled.state" --socket="$UDIR/tailscaled.sock" --port=0 --no-logs-no-support \
      --socks5-server="localhost:$SOCKS" --outbound-http-proxy-listen="localhost:$SOCKS" \
      >>"$UDIR/tailscaled.log" 2>&1 </dev/null &
    echo $! > "$UDIR/tailscaled.pid"
  fi
  for _ in $(seq 1 20); do
    if ts status --json >/dev/null 2>&1; then
      echo "tailscaled is up as $(id -un), userspace networking; SOCKS5 and HTTP proxy on localhost:$SOCKS"
      return 0
    fi
    sleep 1
  done
  tail -n 30 "$UDIR/tailscaled.log" >&2 || true
  die "tailscaled did not answer within 20 s"
}
"""

USER_PREFLIGHT = r"""fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }
os=$( (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null || echo unknown)
if [ "$(uname -s)" = Linux ]; then pass "OS: $os"; else flag "OS: not Linux ($(uname -s))"; fi
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) arch="" ;;
esac
if [ -n "$arch" ]; then pass "arch: $(uname -m)"; else flag "arch: $(uname -m) has no pinned Tailscale build"; fi
missing=""
for c in curl sha256sum tar install; do command -v "$c" >/dev/null || missing="$missing $c"; done
if [ -z "$missing" ]; then pass "tools: curl sha256sum tar install"; else flag "missing tools:$missing"; fi
pass "user mode: Tailscale runs as $(id -un), in userspace networking, from $UDIR"
if [ -e "$UDIR" ] && ! ours_udir; then flag "$UDIR exists and is not tailnet-ops's (set TN_DIR elsewhere)"; fi
parent=$(dirname "$UDIR")
while [ ! -d "$parent" ]; do parent=$(dirname "$parent"); done
if [ -w "$parent" ]; then pass "can write under $parent"; else flag "cannot write under $parent: set TN_DIR"; fi
if command -v ss >/dev/null && [ -n "$(ss -H -ltn "sport = :$SOCKS" 2>/dev/null)" ] && ! user_running; then
  flag "tcp/$SOCKS on localhost is in use: set TN_SOCKS to a free port"
fi
for url in $LOGINS; do
  if out=$(curl -fsS --max-time 10 "$url/health" 2>&1); then pass "reaches $url over TLS"
  else flag "cannot reach $url over TLS: $out"; fi
done
if [ "$fail" != 0 ]; then die "preflight failed; nothing was changed"; fi
echo "preflight passed; nothing was changed"
"""

USER_INSTALL = r"""stage=${1:?staging directory}
for name in tailscale tailscaled; do
  got=$(sha256sum "$stage/$name" | cut -d' ' -f1)
  if [ "$got" != "$(want_sum "$name")" ]; then rm -rf "$stage"; die "checksum mismatch for $name: $got"; fi
done
mkdir -p "$UDIR"
chmod 0700 "$UDIR"
printf '%s\n' "$MARK" > "$UDIR/.tailnet-ops"
install -m 0755 "$stage/tailscale" "$TS_BIN.tn-new"
install -m 0755 "$stage/tailscaled" "$TSD_BIN.tn-new"
mv -f "$TS_BIN.tn-new" "$TS_BIN"
mv -f "$TSD_BIN.tn-new" "$TSD_BIN"
rm -rf "$stage"
"$TS_BIN" version 2>/dev/null | head -n 1 || true
"""

# The login goes from this machine to tn-agent, never through the Agent: tn-agent sees where it
# came from and shows that address to the owner beside what the machine reports about itself.
JOIN_LOGIN = r"""clean() { printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._:/()+-' | cut -c1-80; }
state=$(ts status --json 2>/dev/null | field BackendState || true)
if [ "$state" = Running ]; then
  current=$(ts debug prefs 2>/dev/null | field ControlURL || true)
  if [ "$current" = "$LOGIN" ]; then
    echo "TN-JOINED $(ts ip -4 2>/dev/null | head -n 1)"
    echo "this machine is in tailnet $REGION already; nothing to approve"
    return 0
  fi
  die "this machine is in another tailnet ($current); tailnet-ops leaves it alone"
fi
dns=false
if [ "$mode" = system ] && systemctl is-active --quiet systemd-resolved 2>/dev/null &&
   [ "$(readlink -f /etc/resolv.conf)" = /run/systemd/resolve/stub-resolv.conf ]; then dns=true; fi
out=$(ts up --reset --login-server="$LOGIN" --hostname="$HOST" --advertise-tags="$TAGS" \
  --accept-dns="$dns" --accept-routes="$ACCEPT_ROUTES" --json --timeout=20s 2>&1 || true)
url=$(printf '%s\n' "$out" | field AuthURL || true)
if [ -z "$url" ]; then url=$(ts status --json 2>/dev/null | field AuthURL || true); fi
case "$url" in
  "$LOGIN"/register/hskey-authreq-*) ;;
  *) printf '%s\n' "$out" >&2; die "tailscale up gave no login link for $LOGIN" ;;
esac
body=$(printf '{"auth_url": "%s", "hostname": "%s", "os": "%s", "arch": "%s"}' "$url" \
  "$(clean "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || true)")" "$(clean "${os:-}")" "$(clean "$(uname -m)")")
if ! reply=$(curl -fsS --max-time 60 -H 'Content-Type: application/json' --data "$body" "$AGENT_URL/join/$SCRIPT/login"); then
  die "could not hand the login to $AGENT_URL; ask for a new join command"
fi
request=$(printf '%s\n' "$reply" | field request_id)
approval=$(printf '%s\n' "$reply" | field approval_url)
[ -n "$approval" ] || die "tn-agent did not take the login: $reply"
echo "TN-REQUEST $request"
echo "TN-APPROVAL-URL $approval"
echo "tailscaled now waits (about 15 minutes) for the owner to approve this machine; nothing more to run here"
"""


def _machine_script(site, region, about, parts, main, slots=True):
    """A script an Agent runs on a machine: the join's prelude (its mark, paths and pinned sums), the
    region's facts, the mode (system or user), then the step functions and the main lines."""
    port = pins.DEFAULT_TAILSCALE_PORT
    mark = join.marker(region, NAME_SLOT)
    prelude = join.host_prelude(site, NAME_SLOT, port, [region.server_url], mark, ca_logins=[])
    extra = scripts._vars([
        ("REGION", region.name),
        ("AGENT_URL", origin(region)),
        ("TS_VERSION", pins.TAILSCALE_VERSION),
        ("ARCHIVE_URL_AMD64", pins.tailscale_url("amd64")),
        ("ARCHIVE_SUM_AMD64", pins.TAILSCALE_SHA256["amd64"]),
        ("ARCHIVE_URL_ARM64", pins.tailscale_url("arm64")),
        ("ARCHIVE_SUM_ARM64", pins.TAILSCALE_SHA256["arm64"]),
        ("ACCEPT_ROUTES", "true" if render.line_peers(site, region) else "false"),
    ])
    functions = "\n".join(f"{name}() {{\n{body.rstrip()}\n}}" for name, body in parts)
    slot_lines = f"TAGS={TAGS_SLOT}\nSCRIPT={SCRIPT_SLOT}\n" if slots else ""
    header = "\n".join(f"# {line}" for line in about)
    return f"""#!/bin/bash
{header}
{prelude}
{extra}
{slot_lines}{MACHINE_MODE.rstrip()}
{functions}
{main.rstrip()}
"""


def join_template(site, region):
    """The join script an Agent runs on a machine, with __TN_NAME__, __TN_TAGS__ and __TN_SCRIPT__ for
    the service to fill in. As root with systemd or OpenRC: tn join's own Linux steps (preflight, pinned
    binaries, tailscaled as a service). Otherwise, user mode: the same pinned build in the user's own
    directory, tailscaled in userspace networking with a SOCKS5/HTTP proxy. Either way the login goes
    from the machine to tn-agent and waits for the owner's approval; no key."""
    port = pins.DEFAULT_TAILSCALE_PORT
    mark = join.marker(region, NAME_SLOT)
    parts = [
        ("tn_preflight", join.preflight(None)),
        ("tn_user_preflight", USER_PREFLIGHT),
        ("tn_install_binaries", join.INSTALL_BINARIES),
        ("tn_user_install", USER_INSTALL),
        ("tn_binaries", JOIN_BINARIES),
        ("tn_trust", join.TRUST_CHECK),
        ("tn_systemd", join.service(join.unit(mark, region.name, port))),
        ("tn_openrc", join.openrc_service(join.openrc_script(mark, region.name, port))),
        ("tn_login", JOIN_LOGIN),
    ]
    main = f"""if [ "$mode" = user ]; then
  echo "== 1/5 preflight (user mode: no root, or no systemd/OpenRC)"; tn_user_preflight
  echo "== 2/5 Tailscale {pins.TAILSCALE_VERSION}"; tn_binaries
  echo "== 3/5 TLS to the login server"; tn_trust
  echo "== 4/5 tailscaled (userspace networking)"; user_start
  echo "== 5/5 login"; tn_login
  echo "TN-PROXY socks5h://localhost:$SOCKS"
  echo "programs here reach the tailnet through that proxy (for example ALL_PROXY=socks5h://localhost:$SOCKS);"
  echo "nothing starts tailscaled after a restart: resume_script does"
else
  echo "== 1/5 preflight"; tn_preflight
  echo "== 2/5 Tailscale {pins.TAILSCALE_VERSION}"; tn_binaries
  echo "== 3/5 TLS to the login server"; tn_trust
  echo "== 4/5 tailscaled"
  if [ "$init" = openrc ]; then tn_openrc; else tn_systemd; fi
  echo "== 5/5 login"; tn_login
fi"""
    return _machine_script(site, region, [
        f"tailnet-ops {VERSION}: join this machine to tailnet {region.name} ({region.server_url}) as {NAME_SLOT}.",
        f"Run once. As root with systemd or OpenRC it installs Tailscale {pins.TAILSCALE_VERSION} (sha256 pinned) as a",
        "service; otherwise (or with TN_MODE=user) it runs the same build as the user, in userspace networking,",
        "from TN_DIR (default ~/.local/state/tailnet-ops/tailscale-<region>). Then it hands the login to tn-agent",
        "and prints TN-APPROVAL-URL: the page where the owner approves it with a passkey.",
    ], parts, main)


LEAVE_LOGOUT = r"""if [ -x "$TS_BIN" ] && ts status --json >/dev/null 2>&1; then
  ts logout >/dev/null 2>&1 || true
  echo "logged Tailscale out"
else
  echo "tailscaled is not running; nothing to log out"
fi
"""

LEAVE_USER = r"""if ! ours_udir; then echo "no userspace Tailscale of tailnet-ops in $UDIR"; return 0; fi
if user_running; then
  ts logout >/dev/null 2>&1 || true
  kill "$(cat "$UDIR/tailscaled.pid")" 2>/dev/null || true
  for _ in 1 2 3 4 5; do user_running || break; sleep 1; done
  echo "logged out and stopped the userspace tailscaled"
fi
rm -rf "$UDIR"
echo "removed $UDIR (the node key with it)"
"""

RESUME = r"""if [ "$mode" = user ]; then
  ours_udir || die "no userspace Tailscale of tailnet-ops in $UDIR: join this machine again"
  user_start
elif ours_unit; then
  systemctl start tailscaled
elif ours_init; then
  rc-service tailscaled start
else
  die "tailnet-ops's tailscaled is not installed here: join this machine again"
fi
state=""
for _ in $(seq 1 "${TN_WAIT:-30}"); do
  state=$(ts status --json 2>/dev/null | field BackendState || true)
  [ "$state" = Running ] && break
  sleep 1
done
current=$(ts debug prefs 2>/dev/null | field ControlURL || true)
if [ "$state" = Running ] && [ "$current" = "$LOGIN" ]; then
  echo "TN-JOINED $(ts ip -4 2>/dev/null | head -n 1)"
  if [ "$mode" = user ]; then echo "TN-PROXY socks5h://localhost:$SOCKS"; fi
  return 0
fi
die "tailscaled runs but is not in tailnet $REGION (state ${state:-unknown}): its key is gone; join this machine again"
"""


def leave_template(site, region):
    """The command an Agent runs on a machine that left (or leaves): in user mode it stops the userspace
    tailscaled and removes its directory; as root it runs tn join's own rollback pieces. Each removes only
    what carries the join's mark."""
    parts = [("tn_leave_user", LEAVE_USER), ("tn_logout", LEAVE_LOGOUT), ("tn_service", join.ROLLBACK_SERVICE),
             ("tn_binaries", join.ROLLBACK_BINARIES)]
    main = f"""if [ "$mode" = user ]; then
  echo "== user mode"; tn_leave_user
else
  echo "== 1/3 log out"; tn_logout
  echo "== 2/3 tailscaled"; tn_service
  echo "== 3/3 binaries"; tn_binaries
fi
echo "TN-LEFT {NAME_SLOT}\""""
    return _machine_script(site, region, [
        f"tailnet-ops {VERSION}: take Tailscale off this machine ({NAME_SLOT}, tailnet {region.name}). It removes only",
        "what tn's join command installed (each carries its mark); anything else stays. Use the same user and",
        "TN_MODE/TN_DIR as the join.",
    ], parts, main, slots=False)


def resume_template(site, region):
    """The command an Agent runs after a restart: it starts tailscaled again from the machine's own key (the
    service, or the userspace tailscaled where nothing starts it), with no approval."""
    return _machine_script(site, region, [
        f"tailnet-ops {VERSION}: start Tailscale again on this machine ({NAME_SLOT}, tailnet {region.name}) after",
        "a restart, from its own key; no approval needed. Use the same user and TN_MODE/TN_DIR as the join.",
    ], [("tn_resume", RESUME)], "tn_resume", slots=False)


def marker(region):
    return f"tailnet-ops agent region={region.name}"


def helper_unit(region):
    return f"""# {marker(region)}
[Unit]
Description=tailnet-ops approvals for tailnet {region.name}: passkeys and headscale (local only)
After=headscale.service

[Service]
User={USER}
Group={USER}
SupplementaryGroups=headscale
ExecStart=/usr/bin/env python3 -I {DIR}/agentd.pyz helper --config {ETC}/config.json
Restart=on-failure
RestartSec=5
RuntimeDirectory=tn-agent
RuntimeDirectoryMode=0750
{HARDENING}
CapabilityBoundingSet=
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths={STATE} -/var/run/headscale

[Install]
WantedBy=multi-user.target
"""


def web_unit(region):
    low = region.agent_port < 1024
    caps = "CAP_NET_BIND_SERVICE" if low else ""
    return f"""# {marker(region)}
[Unit]
Description=tailnet-ops MCP and approval pages for tailnet {region.name} (loopback; Cloudflare tunnel)
After=network.target tn-agent-helper.service
Requires=tn-agent-helper.service

[Service]
User={WEB_USER}
Group={WEB_USER}
SupplementaryGroups={USER}
ExecStart=/usr/bin/env python3 -I {DIR}/agentd.pyz web --config {ETC}/config.json
Restart=always
RestartSec=5
{HARDENING}
CapabilityBoundingSet={caps}
{f"AmbientCapabilities={caps}" if low else ""}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=localhost
ReadWritePaths=-/run/tn-agent

[Install]
WantedBy=multi-user.target
"""


def tunnel_unit(region):
    return f"""# {marker(region)}
[Unit]
Description=Cloudflare tunnel to tn-agent for tailnet {region.name} (tailnet-ops)
After=network-online.target tn-agent.service
Wants=network-online.target

[Service]
DynamicUser=yes
EnvironmentFile={TUNNEL_ENV}
ExecStart={CLOUDFLARED} tunnel --no-autoupdate --metrics 127.0.0.1:0 run
Restart=always
RestartSec=5
{HARDENING}
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
"""


def prelude(site, region):
    return f"""set -euo pipefail
umask 022
{scripts._vars([
    ("REGION", region.name),
    ("PORT", region.agent_port),
    ("AGENT_TAG", region.agent_tag),
    ("DIR", DIR),
    ("ETC", ETC),
    ("STATE", STATE),
    ("WEB_UNIT", WEB_UNIT),
    ("HELPER_UNIT", HELPER_UNIT),
    ("TUNNEL_UNIT", TUNNEL_UNIT),
    ("TUNNEL_ENV", TUNNEL_ENV),
    ("CLOUDFLARED", CLOUDFLARED),
    ("USER", USER),
    ("WEB_USER", WEB_USER),
    ("MIN_SYSTEMD", MIN_SYSTEMD),
    ("HS_ETC", render.ETC),
    ("SUM_CF_AMD64", pins.CLOUDFLARED_SHA256["amd64"]),
    ("SUM_CF_ARM64", pins.CLOUDFLARED_SHA256["arm64"]),
    ("MARK", marker(region)),
])}
die() {{ echo "tn: $*" >&2; exit 1; }}
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
ours_dir() {{ [ -f "$1/.tailnet-ops" ] && [ "$(cat "$1/.tailnet-ops")" = "$MARK" ]; }}
ours_unit() {{ [ -f "$1" ] && [ "$(head -n 1 "$1")" = "# $MARK" ]; }}
ours_user() {{ [ "$(getent passwd "$1" | cut -d: -f5)" = "$1 (tailnet-ops)" ]; }}
want_cf() {{
  case "$(uname -m)" in
    x86_64) echo "$SUM_CF_AMD64" ;;
    aarch64|arm64) echo "$SUM_CF_ARM64" ;;
    *) echo none ;;
  esac
}}"""


PREFLIGHT = r"""fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }

if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
  v=$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')
  if [ "${v:-0}" -ge "$MIN_SYSTEMD" ]; then pass "systemd $v"; else flag "systemd ${v:-?} is older than $MIN_SYSTEMD"; fi
else
  flag "systemd is not running"
fi
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) arch="" ;;
esac
if [ -n "$arch" ]; then pass "arch: $(uname -m)"; else flag "arch: $(uname -m) has no pinned cloudflared"; fi
echo "TN-FACT arch=${arch:-none}"
missing=""
for c in python3 curl ss sha256sum install useradd usermod getent timeout; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [ -z "$missing" ]; then pass "tools: python3 curl ss sha256sum install useradd usermod getent timeout"; else flag "missing tools:$missing"; fi
if python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
  pass "$(python3 -V 2>&1)"
else
  flag "needs Python 3.8 or later (python3 -V: $(python3 -V 2>&1 || echo none))"
fi
if [ -f "$HS_ETC/.tailnet-ops" ] && [ "$(cat "$HS_ETC/.tailnet-ops")" = "tailnet-ops region=$REGION" ]; then
  pass "Headscale for tailnet $REGION is tailnet-ops's"
else
  flag "no tailnet-ops Headscale for tailnet $REGION here: run tn control apply $REGION first"
fi
if systemctl is-active --quiet headscale; then pass "headscale.service is running"; else flag "headscale.service is not running"; fi
if getent group headscale >/dev/null; then pass "group headscale"; else flag "group headscale is missing"; fi
if grep -qF "\"$AGENT_TAG\"" "$HS_ETC/policy.hujson" 2>/dev/null; then
  pass "the policy owns $AGENT_TAG and lets it start no connection"
else
  flag "the policy has no $AGENT_TAG: run tn control apply $REGION first (with agent_domain in site.toml)"
fi
if timeout 8 bash -c '</dev/tcp/region1.v2.argotunnel.com/7844' 2>/dev/null; then
  pass "reaches Cloudflare's tunnel edge (region1.v2.argotunnel.com:7844)"
else
  flag "cannot reach region1.v2.argotunnel.com:7844 (TCP): cloudflared needs it, or UDP 7844"
fi

lines=$(ss -H -ltnp "sport = :$PORT" 2>/dev/null || true)
if [ -z "$lines" ]; then pass "tcp/$PORT free on loopback"; echo "TN-FACT port=free"
elif ours_unit "$WEB_UNIT" && systemctl is-active --quiet tn-agent; then pass "tcp/$PORT is tn-agent's"; echo "TN-FACT port=ours"
else flag "tcp/$PORT is in use: $(printf '%s' "$lines" | tr -s ' ' | tr '\n' ' ' | cut -c1-160); set agent_port"; echo "TN-FACT port=busy"; fi

for u in "$USER" "$WEB_USER"; do
  if getent passwd "$u" >/dev/null; then
    if ours_user "$u"; then pass "user $u exists and is ours"; else flag "user $u exists and is not ours"; fi
  elif getent group "$u" >/dev/null; then flag "group $u exists without our user"
  else pass "user $u absent"; fi
done
for d in "$DIR" "$ETC" "$STATE"; do
  if [ ! -e "$d" ]; then pass "$d absent"
  elif ours_dir "$d"; then pass "$d exists and is ours"
  else flag "$d exists and is not ours"; fi
done
for f in "$HELPER_UNIT" "$WEB_UNIT" "$TUNNEL_UNIT"; do
  if [ ! -e "$f" ]; then pass "$f absent"
  elif ours_unit "$f"; then pass "$f exists and is ours"
  else flag "$f exists and is not ours"; fi
done
echo "TN-FACT bundle=$( [ -f "$DIR/agentd.pyz" ] && sha256sum "$DIR/agentd.pyz" | cut -d' ' -f1 || echo none)"
echo "TN-FACT cloudflared=$( [ -f "$CLOUDFLARED" ] && sha256sum "$CLOUDFLARED" | cut -d' ' -f1 || echo none)"
echo "TN-FACT tunnel_token=$( [ -s "$TUNNEL_ENV" ] && echo yes || echo no)"

if [ "$fail" != 0 ]; then die "preflight failed; nothing was changed"; fi
echo "preflight passed; nothing was changed"
"""

USER_AND_DIRS = r"""for d in "$DIR" "$ETC" "$STATE"; do
  if [ -e "$d" ] && ! ours_dir "$d"; then die "$d exists and is not ours"; fi
done
for u in "$USER" "$WEB_USER"; do
  if getent passwd "$u" >/dev/null; then
    ours_user "$u" || die "user $u exists and is not ours"
    echo "user $u: exists"
  else
    if getent group "$u" >/dev/null; then die "group $u exists without our user"; fi
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
      --comment "$u (tailnet-ops)" "$u"
    echo "user $u: created"
  fi
done
usermod -a -G headscale "$USER"
usermod -a -G "$USER" "$WEB_USER"
install -d -o root -g root -m 0755 "$DIR"
install -d -o root -g "$USER" -m 0750 "$ETC"
install -d -o "$USER" -g "$USER" -m 0700 "$STATE"
for d in "$DIR" "$ETC" "$STATE"; do
  printf '%s\n' "$MARK" > "$d/.tailnet-ops"
  chown root:root "$d/.tailnet-ops"
  chmod 0644 "$d/.tailnet-ops"
done
id "$USER"
id "$WEB_USER"
ls -ld "$DIR" "$ETC" "$STATE"
"""

ROLLBACK_USER_AND_DIRS = r"""for d in "$DIR" "$ETC" "$STATE"; do
  if [ ! -e "$d" ]; then echo "$d: absent"
  elif ours_dir "$d"; then rm -rf "$d"; echo "removed $d"
  else echo "skip: $d is not ours"; fi
done
for u in "$WEB_USER" "$USER"; do
  if getent passwd "$u" >/dev/null; then
    if ours_user "$u"; then
      userdel "$u"
      if getent group "$u" >/dev/null; then groupdel "$u"; fi
      echo "removed user $u"
    else echo "skip: user $u is not ours"; fi
  else echo "user $u: absent"; fi
done
"""

STAGE = r"""d=$(mktemp -d /tmp/tn-agent.XXXXXXXX)
echo "TN-FACT stage=$d"
"""


def install_program(config_json, template, leave, resume):
    """$1 the staging directory with agentd.pyz, $2 its sha256."""
    return f"""stage=${{1:?staging directory}}
want=${{2:?sha256 of the bundle}}
case "$stage" in /tmp/tn-agent.*) ;; *) die "unexpected staging path $stage" ;; esac
ours_dir "$DIR" && ours_dir "$ETC" || die "run step 2 first"
got=$(sha256sum "$stage/agentd.pyz" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then rm -rf "$stage"; die "agentd.pyz does not match: $got"; fi
install -o root -g root -m 0644 "$stage/agentd.pyz" "$DIR/agentd.pyz.tn-new"
mv -f "$DIR/agentd.pyz.tn-new" "$DIR/agentd.pyz"
rm -rf "$stage"
cat > "$DIR/join.sh.tn-new" <<'TN_JOIN_EOF'
{template.rstrip()}
TN_JOIN_EOF
chmod 0644 "$DIR/join.sh.tn-new"
mv -f "$DIR/join.sh.tn-new" "$DIR/join.sh"
cat > "$DIR/leave.sh.tn-new" <<'TN_LEAVE_EOF'
{leave.rstrip()}
TN_LEAVE_EOF
chmod 0644 "$DIR/leave.sh.tn-new"
mv -f "$DIR/leave.sh.tn-new" "$DIR/leave.sh"
cat > "$DIR/resume.sh.tn-new" <<'TN_RESUME_EOF'
{resume.rstrip()}
TN_RESUME_EOF
chmod 0644 "$DIR/resume.sh.tn-new"
mv -f "$DIR/resume.sh.tn-new" "$DIR/resume.sh"
cat > "$ETC/config.json.tn-new" <<'TN_EOF'
{config_json.rstrip()}
TN_EOF
chown root:"$USER" "$ETC/config.json.tn-new"
chmod 0640 "$ETC/config.json.tn-new"
mv -f "$ETC/config.json.tn-new" "$ETC/config.json"
touch "$ETC/tokens"
chown root:"$USER" "$ETC/tokens"
chmod 0640 "$ETC/tokens"
python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).testzip()' "$DIR/agentd.pyz"
echo "installed $DIR/agentd.pyz ($want), $DIR/join.sh, leave.sh, resume.sh and $ETC/config.json"
"""


ROLLBACK_PROGRAM = r"""for f in "$DIR/agentd.pyz" "$DIR/join.sh" "$DIR/leave.sh" "$DIR/resume.sh" "$ETC/config.json" "$ETC/tokens" "$ETC/enroll.json"; do
  if [ -e "$f" ]; then
    if ours_dir "$(dirname "$f")"; then rm -f "$f"; echo "removed $f"; else echo "skip: $f is not in our directory"; fi
  fi
done
"""

# $1: the staging directory with the pinned cloudflared for this host's architecture.
INSTALL_CLOUDFLARED = r"""stage=${1:?staging directory}
case "$stage" in /tmp/tn-agent.*) ;; *) die "unexpected staging path $stage" ;; esac
ours_dir "$DIR" || die "run step 2 first"
got=$(sha256sum "$stage/cloudflared" | cut -d' ' -f1)
if [ "$got" != "$(want_cf)" ]; then rm -rf "$stage"; die "cloudflared does not match its pinned sha256: $got"; fi
install -o root -g root -m 0755 "$stage/cloudflared" "$CLOUDFLARED.tn-new"
mv -f "$CLOUDFLARED.tn-new" "$CLOUDFLARED"
rm -rf "$stage"
"$CLOUDFLARED" --version
"""

ROLLBACK_CLOUDFLARED = r"""if [ -e "$CLOUDFLARED" ] && ours_dir "$DIR"; then rm -f "$CLOUDFLARED"; echo "removed $CLOUDFLARED"
else echo "$CLOUDFLARED: absent"; fi
"""

# stdin: the tunnel's token (a secret). Written root-only; systemd hands it to cloudflared.
SAVE_TUNNEL_TOKEN = r"""ours_dir "$ETC" || die "run tn agent apply first"
read -r token
case "$token" in *[!A-Za-z0-9+/=_-]*|"") die "that is not a tunnel token" ;; esac
umask 077
printf 'TUNNEL_TOKEN=%s\n' "$token" > "$TUNNEL_ENV.tn-new"
chown root:root "$TUNNEL_ENV.tn-new"
chmod 0600 "$TUNNEL_ENV.tn-new"
mv -f "$TUNNEL_ENV.tn-new" "$TUNNEL_ENV"
echo "the tunnel token is in $TUNNEL_ENV (root only)"
"""

ROLLBACK_TUNNEL_TOKEN = r"""if [ -e "$TUNNEL_ENV" ]; then rm -f "$TUNNEL_ENV"; echo "removed $TUNNEL_ENV"; else echo "$TUNNEL_ENV: absent"; fi
"""


def start(units):
    """units: [(path variable, systemd name, text)], in the order they start."""
    paths = " ".join(f'"${var}"' for var, _name, _text in units)
    names = " ".join(name for _var, name, _text in units)
    writes = "\n".join(f"cat > \"${var}.tn-new\" <<'TN_EOF'\n{text.rstrip()}\nTN_EOF\nput_unit \"${var}\""
                       for var, _name, text in units)
    return f"""for f in {paths}; do
  if [ -e "$f" ] && ! ours_unit "$f"; then die "$f exists and is not ours"; fi
done
put_unit() {{
  if cmp -s "$1.tn-new" "$1"; then rm -f "$1.tn-new"; echo "unchanged $1"
  else chmod 0644 "$1.tn-new"; mv -f "$1.tn-new" "$1"; echo "wrote $1"; fi
}}
{writes}
systemctl daemon-reload
systemctl enable {names} >/dev/null 2>&1
for s in {names}; do systemctl restart "$s"; done
for _ in $(seq 1 15); do
  if out=$(curl -fsS --max-time 3 "http://127.0.0.1:$PORT/healthz" 2>/dev/null); then
    echo "tn-agent answers on 127.0.0.1:$PORT: $out"
    exit 0
  fi
  sleep 1
done
journalctl -u tn-agent-helper -u tn-agent -n 40 --no-pager || true
die "tn-agent did not answer on 127.0.0.1:$PORT within 15 s"
"""


ROLLBACK_START = r"""for pair in "tn-cloudflared:$TUNNEL_UNIT" "tn-agent:$WEB_UNIT" "tn-agent-helper:$HELPER_UNIT"; do
  name=${pair%%:*}
  f=${pair#*:}
  if [ ! -e "$f" ]; then echo "$f: absent"; continue; fi
  if ours_unit "$f"; then
    systemctl disable --now "$name" >/dev/null 2>&1 || true
    rm -f "$f"
    echo "stopped $name and removed $f"
  else
    echo "skip: $f is not ours"
  fi
done
systemctl daemon-reload
"""

# stdin: the sha256 of the new token. It replaces every token before it.
SAVE_TOKEN = r"""ours_dir "$ETC" || die "tn-agent is not installed: run tn agent apply first"
read -r digest
case "$digest" in *[!0-9a-f]*|"") die "not a sha256" ;; esac
[ "${#digest}" = 64 ] || die "not a sha256"
printf '%s token %s\n' "$digest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ETC/tokens.tn-new"
chown root:"$USER" "$ETC/tokens.tn-new"
chmod 0640 "$ETC/tokens.tn-new"
mv -f "$ETC/tokens.tn-new" "$ETC/tokens"
echo "the new token is the only one tn-agent accepts now"
"""

# stdin: the sha256 of a one-time enrolment code, valid for $1 seconds from now on the host's clock.
SAVE_ENROLMENT = r"""ours_dir "$ETC" || die "tn-agent is not installed: run tn agent apply first"
read -r digest
case "$digest" in *[!0-9a-f]*|"") die "not a sha256" ;; esac
[ "${#digest}" = 64 ] || die "not a sha256"
expires=$(( $(date +%s) + ${1:?seconds} ))
printf '{"code_sha256": "%s", "expires": %s}\n' "$digest" "$expires" > "$ETC/enroll.json.tn-new"
chown root:"$USER" "$ETC/enroll.json.tn-new"
chmod 0640 "$ETC/enroll.json.tn-new"
mv -f "$ETC/enroll.json.tn-new" "$ETC/enroll.json"
echo "the enrolment link works once, for $1 seconds"
"""

STATUS = r"""printf 'helper    %s\n' "$(systemctl is-active tn-agent-helper 2>/dev/null || true)"
printf 'web       %s\n' "$(systemctl is-active tn-agent 2>/dev/null || true)"
printf 'tunnel    %s\n' "$(systemctl is-active tn-cloudflared 2>/dev/null || true)"
echo "TN-BEGIN passkeys"; cat "$STATE/passkeys.json" 2>/dev/null || echo "[]"; echo "TN-END passkeys"
echo "TN-BEGIN requests"; cat "$STATE/requests.json" 2>/dev/null || echo "{}"; echo "TN-END requests"
echo "TN-BEGIN audit"; tail -n 15 "$STATE/audit.jsonl" 2>/dev/null || true; echo "TN-END audit"
printf 'tokens    %s\n' "$(grep -c . "$ETC/tokens" 2>/dev/null || echo 0)"
"""


# --- this machine ------------------------------------------------------------------------


def copy_to_clipboard(text):
    """True if pbcopy (macOS) took it."""
    tool = shutil.which("pbcopy")
    if not tool:
        return False
    return subprocess.run([tool], input=text, text=True).returncode == 0


def https_check(url, run=subprocess.run):
    """curl on this machine, with its own trust store: the way an Agent's platform reaches the service."""
    p = run(["curl", "-fsS", "--max-time", "10", url], capture_output=True, text=True)
    if p.returncode != 0:
        raise StepError(f"this machine cannot reach {url}: {(p.stderr or '').strip()}")
    return p.stdout.strip()


class LocalOps:
    def __init__(self, site, out=print):
        self.site = site
        self.out = out

    def bundle_file(self):
        """(path, sha256) of the service zip, written to cache/ for scp, mode 0600 like everything in the site
        directory. Zips of other versions are dropped."""
        data = bundle()
        digest = hashlib.sha256(data).hexdigest()
        cache = ensure_private_dir(self.site.cache_dir)
        path = cache / f"tn-agent-{digest[:12]}.pyz"
        for old in cache.glob("tn-agent-*.pyz"):
            if old != path:
                old.unlink()
        write_private(path, data)
        return path, digest

    def cloudflared(self, arch):
        cache = ensure_private_dir(self.site.cache_dir)
        return fetch_pinned(pins.cloudflared_url(arch), cache / f"cloudflared-{pins.CLOUDFLARED_VERSION}-linux-{arch}",
                            pins.CLOUDFLARED_SHA256[arch], self.out)


class AgentDeploy(Procedure):
    command = "agent"
    errors = Procedure.errors + (CloudflareError,)

    def __init__(self, site, region_name, runner=None, ops=None, out=print, check=https_check):
        self.site = site
        self.region = site.region(region_name)
        r = self.region
        if not r.domain or not r.agent_domain:
            raise StepError(f"region {r.name} needs domain and agent_domain in site.toml for tn agent "
                            "(machines log in by the domain; the Agent and you reach tn-agent at agent_domain)")
        self.subject = r.name
        self.target = r.control_host
        self.runner = runner
        self.out = out
        self.ops = ops or LocalOps(site, out)
        self.check = check
        self.prelude = prelude(site, r)
        self.facts = {}
        self.digest = hashlib.sha256(bundle()).hexdigest()
        self.ask_token = None      # set by the CLI: (quiet) -> the Cloudflare API token, or None
        self._token = None
        self.cloudflare = Cloudflare

    @property
    def url(self):
        return origin(self.region)

    def _host(self, body, args=(), privileged=True):
        return self.runner.run(self.region.control_host, scripts.wrap(self.prelude, body), args=args,
                               privileged=privileged)

    def token(self, ask=True):
        if self._token is None and self.ask_token:
            self._token = self.ask_token(quiet=not ask) or None
        return self._token

    def _cloudflare(self, ask=True):
        token = self.token(ask)
        if not token:
            raise StepError("needs a Cloudflare API token with Account · Cloudflare Tunnel · Edit and Zone · DNS · "
                            "Edit: run this in a terminal to paste it, or set CF_Token")
        cf = self.cloudflare(token)
        zone = cf.zone_for(self.region.agent_domain)
        if not zone.get("account"):
            raise CloudflareError(f"Cloudflare did not say which account holds {zone['name']}")
        return cf, zone

    # --- running ----------------------------------------------------------------------

    def _check_cloudflare(self):
        """Read-only: the zone, and that no record tn did not make holds agent_domain."""
        r = self.region
        cf, zone = self._cloudflare()
        found = cf.records(zone, r.agent_domain)
        foreign = [x for x in found if (x.get("comment") or "") != cname_mark(r)]
        if foreign:
            raise StepError("Cloudflare: " + in_the_way(foreign[0], r.agent_domain, "CNAME", f"<tunnel>.{TUNNEL_SUFFIX}",
                                                         True))
        tunnel = cf.tunnel(zone["account"], tunnel_name(r))
        self.out(f"  ok    Cloudflare: zone {zone['name']}; {r.agent_domain} "
                 f"{'is ours' if found else 'is free'}; tunnel {tunnel_name(r)} "
                 f"{'exists' if tunnel else 'to be made'}")

    def _run_preflight(self):
        self._check_cloudflare()
        self.facts.update(self._host(PREFLIGHT).facts())

    def _run_user(self):
        self._host(USER_AND_DIRS)

    def _install_body(self):
        return install_program(config_text(self.site, self.region), join_template(self.site, self.region),
                               leave_template(self.site, self.region), resume_template(self.site, self.region))

    def _units(self):
        r = self.region
        return [("HELPER_UNIT", "tn-agent-helper", helper_unit(r)), ("WEB_UNIT", "tn-agent", web_unit(r)),
                ("TUNNEL_UNIT", "tn-cloudflared", tunnel_unit(r))]

    def _start_body(self):
        return start(self._units())

    def _stage(self):
        stage = self._host(STAGE, privileged=False).facts().get("stage", "")
        if not stage.startswith("/tmp/tn-agent."):
            raise StepError(f"unexpected staging directory {stage!r}")
        return stage

    def _run_program(self):
        path, digest = self.ops.bundle_file()
        if self.facts.get("bundle") == digest:
            self.out(f"    {DIR}/agentd.pyz is this version already ({digest[:12]}…); config and join script refreshed")
        stage = self._stage()
        self.out(f"    uploading {path.name} to {stage}/agentd.pyz")
        self.runner.upload(self.region.control_host, path, f"{stage}/agentd.pyz")
        self._host(self._install_body(), args=[stage, digest])

    def _run_cloudflared(self):
        arch = self.facts.get("arch")
        if arch not in pins.CLOUDFLARED_SHA256:
            raise StepError("preflight did not report a supported architecture")
        if self.facts.get("cloudflared") == pins.CLOUDFLARED_SHA256[arch]:
            self.out(f"    {CLOUDFLARED} is the pinned build already")
            return
        path = self.ops.cloudflared(arch)
        stage = self._stage()
        self.out(f"    uploading {path.name} to {stage}/cloudflared")
        self.runner.upload(self.region.control_host, path, f"{stage}/cloudflared")
        self._host(INSTALL_CLOUDFLARED, args=[stage])

    def _run_tunnel(self):
        r = self.region
        cf, zone = self._cloudflare()
        account = zone["account"]
        tunnel_id, made = cf.ensure_tunnel(account, tunnel_name(r))
        self.out(f"    Cloudflare: tunnel {tunnel_name(r)} {'made' if made else 'exists'} ({tunnel_id})")
        service = f"http://127.0.0.1:{r.agent_port}"
        cf.route(account, tunnel_id, r.agent_domain, service)
        self.out(f"    Cloudflare: {r.agent_domain} -> {service} on {r.control_host}, nothing else")
        done = cf.ensure_record(zone, r.agent_domain, "CNAME", f"{tunnel_id}.{TUNNEL_SUFFIX}", True, cname_mark(r))
        self.out(f"    Cloudflare: {r.agent_domain} CNAME {tunnel_id}.{TUNNEL_SUFFIX}, proxied: {done}")
        self.out(f"    the tunnel's token goes to {TUNNEL_ENV} on {r.control_host} over SSH stdin; it is not logged "
                 "or kept here")
        self.runner.feed(r.control_host, ["bash", "-c", f"{self.prelude}\n{SAVE_TUNNEL_TOKEN}"],
                         cf.tunnel_token(account, tunnel_id), what="the tunnel's token")

    def _undo_tunnel(self):
        r = self.region
        self._host(ROLLBACK_TUNNEL_TOKEN)
        if not self.token():
            self.out(f"    no Cloudflare token: delete the tunnel {tunnel_name(r)} and the record {r.agent_domain} there")
            return
        cf, zone = self._cloudflare()
        gone = cf.delete_record(zone, r.agent_domain, cname_mark(r))
        self.out(f"    Cloudflare: deleted {gone} record(s) {r.agent_domain} made by tailnet-ops")
        if cf.delete_tunnel(zone["account"], tunnel_name(r)):
            self.out(f"    Cloudflare: deleted the tunnel {tunnel_name(r)}")

    def _run_start(self):
        self._host(self._start_body())

    def _run_verify(self):
        last = None
        for attempt in range(6):            # the tunnel needs a few seconds to connect after a (re)start
            try:
                answer = self.check(f"{self.url}/healthz")
            except StepError as e:
                last = e
            else:
                if answer.startswith("ok tn-agent"):
                    self.out(f"    this machine reaches {self.url} through Cloudflare: {answer}")
                    return
                last = StepError(f"{self.url}/healthz answered {answer!r}")
            if attempt < 5:
                self.sleep(5)
        raise last

    @staticmethod
    def sleep(seconds):
        import time
        time.sleep(seconds)

    # --- the steps --------------------------------------------------------------------

    def steps(self):
        r, host = self.region, self.region.control_host
        return [
            Step(
                1, "Preflight",
                [f"Here, through the Cloudflare API (read-only): the zone of {r.agent_domain}, and that no record tn",
                 f"did not make holds that name. On {host}: root, systemd {MIN_SYSTEMD}+, tools, Python 3.8+;",
                 f"tailnet-ops's Headscale with a policy that owns {r.agent_tag}; tcp/{r.agent_port} free on loopback;",
                 "Cloudflare's tunnel edge reachable; nothing named tn-agent unless tailnet-ops made it. Changes nothing."],
                [Action("local", f"Cloudflare API: zone of {r.agent_domain}, its records, the tunnel {tunnel_name(r)}"),
                 Action(host, "read-only checks", PREFLIGHT, "agent", True)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_preflight,
                host=host, brief="Check Cloudflare and the host",
            ),
            Step(
                2, "Users and directories",
                [f"Create two system users (no login, no home): {USER} for the private half, in group headscale",
                 f"so it can use the headscale CLI; {WEB_USER} for the web half, in group {USER} only so it",
                 f"reaches the private half's socket. Create {DIR} (root), {ETC} (root, readable by group",
                 f"{USER}) and {STATE} ({USER} only), each marked as made by tailnet-ops."],
                [Action(host, "create", USER_AND_DIRS, "agent", True)],
                rollback=ROLLBACK_USER_AND_DIRS,
                rollback_note=f"remove {DIR}, {ETC}, {STATE} (passkeys, requests, audit log) and both users, if ours",
                run=self._run_user, host=host, brief=f"Create users {USER} and {WEB_USER}, and the directories",
                undo_brief="remove them, the passkeys and the users",
            ),
            Step(
                3, "Program",
                [f"Build the service zip here from tailnet_ops/agentd and the Skill (sha256 {self.digest[:12]}…),",
                 f"copy it to {host}, check it again and install it as {DIR}/agentd.pyz (root-owned: neither",
                 f"half can change its code). Write {ETC}/config.json and, in {DIR}, join.sh, leave.sh and",
                 "resume.sh: the scripts Agents run on machines (shown below)."],
                [
                    Action("local", f"build agentd.pyz into cache/ (sha256 {self.digest})"),
                    Action(host, "make a staging directory", STAGE, "agent", False),
                    Action("local", "scp agentd.pyz to <staging directory>/"),
                    Action(host, "check and install; $1 staging directory, $2 sha256", self._install_body(),
                           "agent", True),
                ],
                rollback=ROLLBACK_PROGRAM, rollback_note="remove the program, its config, tokens and enrolment code",
                run=self._run_program, host=host, brief="Install the service, its config and the join script",
                undo_brief="remove them",
            ),
            Step(
                4, "cloudflared",
                [f"Download cloudflared {pins.CLOUDFLARED_VERSION} for the host's architecture into cache/, check its",
                 f"pinned sha256 (amd64 {pins.CLOUDFLARED_SHA256['amd64'][:12]}…, arm64 "
                 f"{pins.CLOUDFLARED_SHA256['arm64'][:12]}…), copy it over, check again,",
                 f"install it as {CLOUDFLARED}. Skipped when the pinned build is there."],
                [
                    Action("local", f"fetch {pins.cloudflared_url('<arch>')} unless cached; verify sha256"),
                    Action(host, "make a staging directory", STAGE, "agent", False),
                    Action("local", "scp cloudflared to <staging directory>/"),
                    Action(host, "verify and install; $1 is the staging directory", INSTALL_CLOUDFLARED, "agent", True),
                ],
                rollback=ROLLBACK_CLOUDFLARED, rollback_note=f"remove {CLOUDFLARED}",
                run=self._run_cloudflared, host=host, brief=f"Install cloudflared {pins.CLOUDFLARED_VERSION}",
                undo_brief="remove it",
            ),
            Step(
                5, "Tunnel",
                [f"Through the Cloudflare API: the tunnel {tunnel_name(r)} (managed at Cloudflare), its one route",
                 f"{r.agent_domain} -> http://127.0.0.1:{r.agent_port} on {host}, and the record {r.agent_domain}",
                 f"CNAME <tunnel>.{TUNNEL_SUFFIX}, proxied, marked \"{cname_mark(r)}\". The tunnel's token goes",
                 f"over SSH stdin into {TUNNEL_ENV} (root only); it is never logged."],
                [
                    Action("local", f"Cloudflare API: make or keep the tunnel, set its route, make or fix the CNAME, "
                           "read the tunnel's token"),
                    Action(host, "bash -c '<prelude + this>', with the token on stdin", SAVE_TUNNEL_TOKEN, None, True),
                ],
                rollback=ROLLBACK_TUNNEL_TOKEN, undo=self._undo_tunnel,
                rollback_note=f"remove {TUNNEL_ENV}; delete the record and the tunnel at Cloudflare if tn made them",
                run=self._run_tunnel, host=host, brief=f"Tunnel {r.agent_domain} -> 127.0.0.1:{r.agent_port}",
                undo_brief="delete them and the token",
            ),
            Step(
                6, "Services",
                [f"Write {HELPER_UNIT} (no network, writes only {STATE}), {WEB_UNIT} (127.0.0.1:{r.agent_port},",
                 f"may talk to loopback only, writes nothing) and {TUNNEL_UNIT} (cloudflared, a dynamic user, the",
                 "token from its file). All: no capabilities, memory throttled at 200 MB and capped at 256 MB, killed",
                 f"before Headscale when the host runs out. Enable and (re)start them; wait for 127.0.0.1:{r.agent_port}."],
                [Action(host, "write the units and start", self._start_body(), "agent", True)],
                rollback=ROLLBACK_START, rollback_note="stop and disable the three services, remove their units",
                run=self._run_start, host=host, brief="Start tn-agent and the tunnel",
                undo_brief="stop them, remove the units",
            ),
            Step(
                7, "Verify",
                [f"From this machine: GET {self.url}/healthz, through Cloudflare, the way the Agent's",
                 "platform will reach the MCP endpoint. Changes nothing."],
                [Action("local", f"curl -fsS {self.url}/healthz (a few tries while the tunnel connects)")],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_verify,
                host="this machine", brief="Reach it through Cloudflare",
            ),
        ]

    def header(self):
        r = self.region
        return "\n".join([
            f"Region {r.name} of site {self.site.name!r} · tailnet-ops {VERSION} · tn-agent {SERVICE_VERSION} · "
            f"cloudflared {pins.CLOUDFLARED_VERSION}",
            f"  control host  {r.control_host}  (scripts run as root over SSH)",
            f"  serves        {self.url}/mcp (Agents, with a bearer token from `tn agent token`)",
            f"                {self.url}/a/<request> (you approve, with a passkey from `tn agent enroll`)",
            f"  through       a Cloudflare tunnel to 127.0.0.1:{r.agent_port}: no port opens on {r.control_host};",
            "                Cloudflare's edge terminates TLS, so it sees the requests",
            f"  login server  {r.server_url} (machines that join log in there)",
            "  Agents may    list nodes; get a one-time join command for a machine; the machine hands its",
            "                login to tn-agent, and you see its address before you approve",
            f"  joined as     {r.agent_tag}: starts no connection to other machines (tn control's policy)",
            "  Agents never  hold a key, approve, delete or retag nodes, or change the policy",
            f"  adds          users {USER} (group headscale) and {WEB_USER}, {DIR}/, {ETC}/, {STATE}/,",
            "                tn-agent-helper, tn-agent and tn-cloudflared services; at Cloudflare: the tunnel",
            f"                {tunnel_name(r)} and the record {r.agent_domain}",
            "  leaves alone  headscale and its files, every other user, service, port, firewall rule and record",
        ])

    def preludes(self):
        return [("control host", self.prelude)]

    def plan_intro(self):
        return (f"Every script on {self.region.control_host} runs as `bash -s` over SSH: this prelude, then the step\n"
                "body inside `tn_step() { ... }` with stdin from /dev/null.")

    def rollback_footer(self):
        return "Headscale and the nodes that joined through tn-agent stay as they are."

    def done_message(self):
        return (f"tn-agent is up on {self.url}. Next: `tn agent enroll {self.region.name}` (your passkey), then "
                f"`tn agent token {self.region.name}` (the Agent's MCP token).")

    def rolled_back_message(self):
        return f"Rolled back tn-agent for region {self.region.name}."

    def run_rollback(self, step):
        self._host(step.rollback)

    def preflight(self):
        return self.run_once(self._run_preflight)

    def verify(self):
        return self.run_once(self._run_verify)

    # --- token, enrolment, status -------------------------------------------------------

    def new_token(self):
        """Make an MCP token here, send only its sha256 to the host; the token itself is returned."""
        token = "tna_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        self.runner.feed(self.region.control_host, ["bash", "-c", f"{self.prelude}\n{SAVE_TOKEN}"], digest,
                         what="the token's sha256")
        return token

    def new_enrolment(self):
        """A one-time enrolment link; the host keeps only the code's sha256."""
        code = secrets.token_urlsafe(24)
        digest = hashlib.sha256(code.encode()).hexdigest()
        self.runner.feed(self.region.control_host,
                         ["bash", "-c", f"{self.prelude}\n{SAVE_ENROLMENT}", "tn-agent", str(ENROL_SECONDS)],
                         digest, what="the enrolment code's sha256")
        return f"{self.url}/enroll#{code}"

    def passkey_count(self):
        result = self.runner.run(self.region.control_host, scripts.wrap(self.prelude, STATUS), privileged=True,
                                 echo=False)
        try:
            return len(json.loads(result.block("passkeys") or "[]"))
        except ValueError:
            raise StepError("the host's tn-agent state is not JSON")

    def status(self):
        result = self._host(STATUS)
        try:
            keys = json.loads(result.block("passkeys") or "[]")
            reqs = json.loads(result.block("requests") or "{}")
        except ValueError:
            raise StepError("the host's tn-agent state is not JSON")
        self.out(f"  passkeys  {len(keys)}" + "".join(f"\n    {k.get('label', 'passkey')} · id {k['id'][:10]}…"
                                                       for k in keys))
        pending = [x for x in reqs.values() if x.get("status") == "pending"]
        self.out(f"  requests  {len(reqs)} kept, {len(pending)} pending")
        for x in sorted(reqs.values(), key=lambda x: -x.get("created", 0))[:10]:
            machine = x.get("machine") or {}
            self.out(f"    {x.get('status', '?'):8} {x.get('name')}  from {machine.get('ip', '?')}  {x.get('who', '')}")
        audit = (result.block("audit") or "").strip()
        if audit:
            self.out("  audit (latest)")
            for line in audit.splitlines():
                self.out(f"    {line}")
        return 0
