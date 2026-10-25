"""`tn join`: add a host to its region's tailnet with a pinned static Tailscale build."""

import ipaddress
import json
import re
import shlex
import tarfile

from . import VERSION, pins, render, scripts
from .procedure import Action, Procedure, Step, StepError, fetch_pinned, sha256_file
from .site import ensure_private_dir, write_private

TS_BIN = "/usr/local/bin/tailscale"
TSD_BIN = "/usr/local/sbin/tailscaled"
TS_UNIT = "/etc/systemd/system/tailscaled.service"
TS_STATE = "/var/lib/tailscale"
TS_CACHE = "/var/cache/tailscale"
CA_DIR = "/usr/local/share/ca-certificates"

CA_PLACEHOLDER = "<site CA certificate from pki/ca.crt>"


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "site"


def ca_file(site):
    return f"{CA_DIR}/tailnet-ops-{slug(site.name)}.crt"


def marker(region, alias):
    return f"tailnet-ops join region={region.name} host={alias}"


def host_prelude(site, region, alias, port):
    sums = pins.TAILSCALE_BIN_SHA256
    return f"""set -euo pipefail
umask 022
{scripts._vars([
    ("REGION", region.name),
    ("HOST", alias),
    ("LOGIN", region.server_url),
    ("TS_PORT", port),
    ("TS_BIN", TS_BIN),
    ("TSD_BIN", TSD_BIN),
    ("TS_UNIT", TS_UNIT),
    ("TS_STATE", TS_STATE),
    ("TS_CACHE", TS_CACHE),
    ("CA_FILE", ca_file(site)),
    ("SUM_TS_AMD64", sums["amd64"]["tailscale"]),
    ("SUM_TS_ARM64", sums["arm64"]["tailscale"]),
    ("SUM_TSD_AMD64", sums["amd64"]["tailscaled"]),
    ("SUM_TSD_ARM64", sums["arm64"]["tailscaled"]),
])}
MARK="tailnet-ops join region=$REGION host=$HOST"
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
ours_state() {{ [ -f "$TS_STATE/.tailnet-ops" ] && [ "$(cat "$TS_STATE/.tailnet-ops")" = "$MARK" ]; }}"""


def _ca_function(ca_pem):
    return f"""ca() {{
cat <<'TN_PEM'
{ca_pem.strip()}
TN_PEM
}}"""


# --- step 1: preflight (read-only) ------------------------------------------------


def preflight(ca_pem):
    return _ca_function(ca_pem) + r"""
fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }

os=$( (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null || echo unknown)
if [ "$(uname -s)" = Linux ]; then pass "OS: $os"; else flag "OS: not Linux ($os)"; fi
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) arch="" ;;
esac
if [ -n "$arch" ]; then pass "arch: $(uname -m)"; else flag "arch: $(uname -m) has no pinned Tailscale build"; fi
echo "TN-FACT arch=${arch:-none}"
if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then pass "systemd"; else flag "systemd is not running"; fi
if [ -c /dev/net/tun ]; then pass "/dev/net/tun"; else flag "/dev/net/tun is missing"; fi
missing=""
for c in curl sha256sum install update-ca-certificates ip ss; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [ -z "$missing" ]; then pass "tools: curl sha256sum install update-ca-certificates ip ss"; else flag "missing tools:$missing"; fi

lines=$(ss -H -lunp "sport = :$TS_PORT" 2>/dev/null || true)
if [ -z "$lines" ]; then pass "udp/$TS_PORT free (Tailscale)"
elif ! printf '%s\n' "$lines" | grep -qv '"tailscaled"' && ours_unit; then pass "udp/$TS_PORT already used by our tailscaled"
else flag "udp/$TS_PORT is in use: $(printf '%s' "$lines" | tr -s ' ' | tr '\n' ' ' | cut -c1-160)"; fi

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
if [ ! -e "$TS_STATE" ]; then pass "$TS_STATE absent"
elif ours_state; then pass "$TS_STATE exists and is ours"
else flag "$TS_STATE exists and is not ours"; fi
if ip link show tailscale0 >/dev/null 2>&1 && ! ours_unit; then flag "a tailscale0 interface exists outside our unit"; fi
if pgrep -x tailscaled >/dev/null && ! ours_unit; then flag "a tailscaled process runs outside our unit"; fi

if out=$(curl -fsS --max-time 10 --cacert <(ca) "$LOGIN/health" 2>&1); then
  pass "reaches $LOGIN over TLS with the site CA"
else
  flag "cannot reach $LOGIN with the site CA: $out"
fi

if [ "$fail" != 0 ]; then die "preflight failed; nothing was changed"; fi
echo "preflight passed; nothing was changed"
"""


# --- step 2: binaries ---------------------------------------------------------------

STAGE = r"""d=$(mktemp -d /tmp/tn-tailscale.XXXXXXXX)
echo "TN-FACT stage=$d"
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
"""


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
curl -fsS --max-time 10 "$LOGIN/health" >/dev/null || die "the system trust store does not accept $LOGIN yet"
echo "the system trust store accepts $LOGIN"
"""


def rollback_ca(ca_pem):
    return _ca_function(ca_pem) + """
if [ ! -e "$CA_FILE" ]; then echo "$CA_FILE: absent"
elif cmp -s "$CA_FILE" <(ca); then
  rm -f "$CA_FILE"
  update-ca-certificates --fresh >/dev/null
  echo "removed $CA_FILE and rebuilt the trust store"
else echo "skip: $CA_FILE is not this site's CA"; fi
"""


# --- step 4: tailscaled service --------------------------------------------------------


def unit(region, alias, port):
    return f"""# {marker(region, alias)}
[Unit]
Description=Tailscale node agent for tailnet {region.name} (tailnet-ops)
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


ROLLBACK_SERVICE = r"""if [ ! -e "$TS_UNIT" ]; then echo "$TS_UNIT: absent"
elif ours_unit; then
  systemctl disable --now tailscaled
  rm -f "$TS_UNIT"
  systemctl daemon-reload
  echo "stopped tailscaled (it cleans up its routes and rules on stop) and removed $TS_UNIT"
else echo "skip: $TS_UNIT is not ours"; fi
if [ ! -e "$TS_STATE" ]; then echo "$TS_STATE: absent"
elif ours_state; then rm -rf "$TS_STATE" "$TS_CACHE"; echo "removed $TS_STATE (the node key) and $TS_CACHE"
else echo "skip: $TS_STATE is not ours"; fi
"""


# --- step 5: join ------------------------------------------------------------------------


def preauth_key(tags):
    return f"""# Prints only the key, on stdout, which goes straight into `tailscale up` on the host.
"$BIN" preauthkeys create --expiration {pins.PREAUTH_KEY_EXPIRY} --tags {shlex.quote(",".join(tags))}
"""


def dns_label(alias):
    return re.sub(r"[^a-z0-9-]+", "-", alias.lower()).strip("-")


def up_argv(region, alias, netfilter_mode):
    argv = [TS_BIN, "up", f"--login-server={region.server_url}", "--auth-key=file:/dev/stdin",
            f"--hostname={dns_label(alias)}", "--accept-dns=false", "--accept-routes=false", "--timeout=60s"]
    if netfilter_mode:
        argv.append(f"--netfilter-mode={netfilter_mode}")
    return argv


STATUS_JSON = '"$TS_BIN" status --json\n'
NETCHECK_JSON = '"$TS_BIN" netcheck --format=json\n'
NODES_JSON = '"$BIN" nodes list -o json\n'

LOGOUT = r"""if [ -x "$TS_BIN" ] && systemctl is-active --quiet tailscaled; then
  "$TS_BIN" logout || true
  echo "logged out"
else
  echo "tailscaled is not running; nothing to log out"
fi
"""


def delete_node(node_id):
    return f'"$BIN" nodes delete -i {int(node_id)} --force\n'


def _json(text, what):
    try:
        return json.loads(text)
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

    def __init__(self, site, alias, runner=None, ops=None, out=print):
        self.site = site
        self.alias = alias
        self.subject = alias
        self.target = alias
        self.region = site.host_region(alias)
        self.tags = site.host_tags(alias)
        settings = site.host_settings.get(alias)
        self.port = (settings.tailscale_port if settings and settings.tailscale_port
                     else pins.DEFAULT_TAILSCALE_PORT)
        self.netfilter_mode = settings.netfilter_mode if settings else None
        self.control = self.region.control_host
        self.runner = runner
        self.out = out
        self.ops = ops or LocalOps(site, out)
        self.prelude = host_prelude(site, self.region, alias, self.port)
        self.control_prelude = scripts.control_prelude(site, self.region)
        self.facts = {}
        if not self.tags:
            raise StepError(f"{alias}: no tags; its region {self.region.name} needs a tag ending in -server")

    # --- running --------------------------------------------------------------------

    def _host(self, body, args=(), privileged=True, echo=True):
        return self.runner.run(self.alias, scripts.wrap(self.prelude, body), args=args,
                               privileged=privileged, echo=echo)

    def _on_control(self, body, echo=True):
        return self.runner.run(self.control, scripts.wrap(self.control_prelude, body), privileged=True, echo=echo)

    def _ca(self):
        ca = self.ops.ca_pem()
        if ca is None:
            raise StepError(f"no site CA in {self.site.pki_dir}; run `tn control apply {self.region.name}` first")
        return ca

    def _run_preflight(self):
        self.facts.update(self._host(preflight(self._ca())).facts())

    def _run_binaries(self):
        arch = self.facts.get("arch")
        if arch not in pins.TAILSCALE_BIN_SHA256:
            raise StepError("preflight did not report a supported architecture")
        want = pins.TAILSCALE_BIN_SHA256[arch]
        if all(self.facts.get(name) == want[name] for name in want):
            self.out("    the pinned Tailscale build is already installed; nothing to upload")
            return
        paths = self.ops.binaries(arch)
        stage = self._host(STAGE, privileged=False).facts().get("stage", "")
        if not stage.startswith("/tmp/tn-tailscale."):
            raise StepError(f"unexpected staging directory {stage!r}")
        for name, path in paths.items():
            self.out(f"    uploading {name} to {stage}/")
            self.runner.upload(self.alias, path, f"{stage}/{name}")
        self._host(INSTALL_BINARIES, args=[stage])

    def _run_ca(self):
        self._host(install_ca(self._ca()))

    def _run_service(self):
        self._host(service(unit(self.region, self.alias, self.port)))

    def _status(self):
        return _json(self._host(STATUS_JSON, echo=False).output, "tailscale status")

    def _run_join(self):
        status = self._status()
        if status.get("BackendState") == "Running":
            self.out("    already joined; no new key made")
            return
        self.out(f"    a single-use, {pins.PREAUTH_KEY_EXPIRY} key for {', '.join(self.tags)} goes from "
                 f"{self.control} straight into `tailscale up` on {self.alias}; it is never shown or stored here")
        self.runner.pipe(self.control, scripts.wrap(self.control_prelude, preauth_key(self.tags)),
                         self.alias, up_argv(self.region, self.alias, self.netfilter_mode))

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
        net = _json(self._host(NETCHECK_JSON, echo=False).output, "tailscale netcheck")
        derp = net.get("PreferredDERP")
        self.out(f"    preferred DERP region {derp}; UDP {'ok' if net.get('UDP') else 'blocked'}")
        if derp != self.region.derp_region_id:
            problems.append(f"preferred DERP region is {derp}, expected {self.region.derp_region_id}")
        nodes = _json(self._on_control(NODES_JSON, echo=False).output or "[]", "headscale nodes list") or []
        mine = [n for n in nodes if str(n.get("given_name", "")).lower() == dns_label(self.alias)]
        self.out(f"    {self.control} lists {len(mine)} node(s) named {dns_label(self.alias)}")
        if len(mine) != 1:
            problems.append(f"{self.control} should list exactly one node named {dns_label(self.alias)}")
        if problems:
            raise StepError("; ".join(problems))
        self.out("    verify passed")

    def _undo_join(self):
        self._host(LOGOUT)
        nodes = _json(self._on_control(NODES_JSON, echo=False).output or "[]", "headscale nodes list") or []
        mine = [n for n in nodes if str(n.get("given_name", "")).lower() == dns_label(self.alias)]
        if not mine:
            self.out(f"    {self.control} lists no node named {dns_label(self.alias)}")
        for n in mine:
            self.out(f"    deleting node {n.get('id')} ({n.get('given_name')}) on {self.control}")
            self._on_control(delete_node(n.get("id")))

    def run_rollback(self, step):
        if step.number == 3:
            self._host(rollback_ca(self._ca()))
        else:
            self._host(step.rollback)

    # --- the steps --------------------------------------------------------------------

    def steps(self):
        a, r = self.alias, self.region
        ca_note = f"{ca_file(self.site)} plus update-ca-certificates"
        steps = [
            Step(
                1, "Preflight",
                ["Check arch, OS, root, systemd, /dev/net/tun and tools; that udp/"
                 f"{self.port} is free; that no other Tailscale is installed;",
                 f"that {a} reaches {r.server_url} over TLS with the site CA. Changes nothing."],
                [Action(a, "read-only checks", preflight(CA_PLACEHOLDER), "host", True)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_preflight,
            ),
            Step(
                2, "Binaries",
                [f"Download the static Tailscale {pins.TAILSCALE_VERSION} for the architecture preflight reports into cache/,",
                 "check the archive's pinned sha256 and each binary's; copy them to the host, check again,",
                 f"install {TS_BIN} and {TSD_BIN}. Skipped when the pinned build is already installed."],
                [
                    Action("local", f"fetch {pins.tailscale_url('<arch>')} unless cached; verify the .tgz and both binaries"),
                    Action(a, "make a staging directory", STAGE, "host", False),
                    Action("local", "scp tailscale and tailscaled to <staging directory>/"),
                    Action(a, "verify and install; $1 is the staging directory", INSTALL_BINARIES, "host", True),
                ],
                rollback=ROLLBACK_BINARIES, rollback_note="remove both binaries if they are the pinned build",
                run=self._run_binaries,
            ),
            Step(
                3, "Site CA",
                [f"Trust the site CA system-wide ({ca_note}), so tailscaled",
                 f"accepts {r.server_url}. Then check that plain curl accepts it too."],
                [Action(a, "install the CA certificate", install_ca(CA_PLACEHOLDER), "host", True)],
                rollback=rollback_ca(CA_PLACEHOLDER),
                rollback_note="remove the CA file if it is this site's and rebuild the trust store",
                run=self._run_ca,
            ),
            Step(
                4, "tailscaled",
                [f"Write {TS_UNIT} (port udp/{self.port}, --no-logs-no-support), mark {TS_STATE},",
                 "systemctl enable --now tailscaled, wait until it answers."],
                [Action(a, "write the unit and start", service(unit(r, a, self.port)), "host", True)],
                rollback=ROLLBACK_SERVICE,
                rollback_note=f"stop and disable tailscaled, remove the unit, {TS_STATE} and {TS_CACHE}",
                run=self._run_service,
            ),
            Step(
                5, "Join",
                [f"On {self.control}: make a single-use pre-auth key, valid {pins.PREAUTH_KEY_EXPIRY}, tagged "
                 f"{', '.join(self.tags)}.",
                 f"Its stdout goes through ssh straight into `tailscale up` on {a}; this machine never reads,",
                 "prints or stores it. Skipped when the host is already joined."],
                [
                    Action(self.control, "make the key (stdout only)", preauth_key(self.tags), "control", True),
                    Action(a, "join with the key on stdin: "
                           + " ".join(shlex.quote(x) for x in up_argv(r, a, self.netfilter_mode)), None, None, True),
                ],
                rollback=LOGOUT,
                rollback_note=f"log out, then delete the node named {dns_label(a)} on {self.control} "
                              "(`headscale nodes list -o json`, then `headscale nodes delete -i <id> --force`)",
                run=self._run_join, undo=self._undo_join,
            ),
            Step(
                6, "Verify",
                [f"On {a}: tailscaled is Running with an address in {r.ipv4_prefix}, tags {', '.join(self.tags)},",
                 f"and prefers DERP region {r.derp_region_id}. On {self.control}: exactly one node named "
                 f"{dns_label(a)}. Read-only."],
                [
                    Action(a, "status and netcheck", STATUS_JSON + NETCHECK_JSON, "host", True),
                    Action(self.control, "list nodes", NODES_JSON, "control", True),
                ],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_verify,
            ),
        ]
        for step in steps:
            step.host = a
        return steps

    # --- printing ---------------------------------------------------------------------

    def header(self):
        r, a = self.region, self.alias
        nf = self.netfilter_mode or "on (Tailscale default: tailscaled adds and removes its own ts-* rules)"
        return "\n".join([
            f"Join {a} to region {r.name} of site {self.site.name!r} · tailnet-ops {VERSION} · Tailscale {pins.TAILSCALE_VERSION}",
            f"  host          {a}  (scripts run as root over SSH)",
            f"  login server  {r.server_url}  (Headscale on {self.control})",
            f"  name          {dns_label(a)}.{r.base_domain}",
            f"  tags          {', '.join(self.tags)}  (from a single-use {pins.PREAUTH_KEY_EXPIRY} key; no key expiry for tagged nodes)",
            f"  tailscaled    udp/{self.port}, --no-logs-no-support",
            f"  tailscale up  --accept-dns=false --accept-routes=false, netfilter {nf}",
            f"  adds          {TS_BIN}, {TSD_BIN}, {TS_UNIT}, {TS_STATE}/, {ca_file(self.site)}",
            "  leaves alone  every other file, service, port and firewall rule",
        ])

    def preludes(self):
        return [(f"{self.alias}", self.prelude), (f"{self.control}, control host", self.control_prelude)]

    def plan_intro(self):
        return (f"Every script runs as `bash -s` over SSH: the prelude of its host, then the step body inside\n"
                "`tn_step() { ... }` with stdin from /dev/null. The one exception is `tailscale up` in step 5,\n"
                "whose stdin is the pre-auth key.")

    def rollback_footer(self):
        return "It keeps the download cache on this machine."

    def done_message(self):
        return f"{self.alias} joined region {self.region.name} as {dns_label(self.alias)}.{self.region.base_domain}."

    def rolled_back_message(self):
        return f"Rolled back the join of {self.alias}."

    def preflight(self):
        return self.run_once(self._run_preflight)

    def verify(self):
        return self.run_once(self._run_verify)
