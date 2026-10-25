"""`tn line`: connect two regions' tailnets through a dedicated line.

The initiator starts a plain WireGuard tunnel to the responder's entry address and keeps
it alive. Each region's tailnet range appears in the other region as an alias range
(100.64.10.x shows up as 10.255.10.x), so every host that joins is reachable across
without any per-host setting. On each end:

- going into the tunnel, sources from the local tailnet become the local tunnel address;
- coming out of it, an alias becomes the local tailnet address it stands for, and the
  source becomes this border, so hosts need no route back;
- each border advertises the other region's alias range into its own tailnet, and the
  policy lets the owner reach it;
- firewall chains that would drop the forwarded traffic get two tagged accept rules,
  kept in place by a timer.

Everything on a host hangs off the tunnel's wg-quick unit, so stopping it removes the
NAT table and the accept rules too.
"""

import ipaddress
import json
import re

from . import firewall, render, scripts
from .join import NODES_JSON, TS_BIN, dns_label
from .procedure import Action, Procedure, Step, StepError

WG_DIR = "/etc/wireguard"
OTHER = {"initiator": "responder", "responder": "initiator"}


def _json(text, default):
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    if not starts:
        return default
    try:
        return json.JSONDecoder().raw_decode(text[min(starts):])[0]
    except ValueError:
        return default


def table_name(line):
    return "tn_" + re.sub(r"[^a-z0-9_]", "_", line.name.lower())


def prelude(line, side):
    i = line.interface
    return f"""set -euo pipefail
umask 077
{scripts._vars([
    ("LINE", line.name),
    ("SIDE", side),
    ("IFACE", i),
    ("CONF", f"{WG_DIR}/{i}.conf"),
    ("KEY", f"{WG_DIR}/{i}.key"),
    ("KEYMARK", f"{WG_DIR}/{i}.tailnet-ops"),
    ("NFT_FILE", f"{WG_DIR}/{i}.nft"),
    ("ALLOW", f"{WG_DIR}/{i}-allow.sh"),
    ("KEEP", f"tn-{i}-allow"),
    ("KEEP_DIR", "/etc/systemd/system"),
    ("SYSCTL", f"/etc/sysctl.d/90-tailnet-ops-{i}.conf"),
    ("TABLE", table_name(line)),
    ("TS_BIN", TS_BIN),
    ("PORT", line.port),
    ("TUNNEL", line.tunnel_ipv4),
])}
MARK="tailnet-ops line=$LINE side=$SIDE"
die() {{ echo "tn: $*" >&2; exit 1; }}
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
ours_file() {{ [ -f "$1" ] && head -n 2 "$1" | grep -qxF "# $MARK"; }}
ours_conf() {{ ours_file "$CONF"; }}
ours_key() {{ [ -f "$KEYMARK" ] && [ "$(cat "$KEYMARK")" = "$MARK" ]; }}"""


# --- step 1: checks ----------------------------------------------------------------------


def check(side, line, aliases):
    tunnel_ip = line.tunnel_addresses[0 if side == "initiator" else 1]
    body = r"""fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }
if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
for c in wg wg-quick ip ping nft sysctl; do
  command -v "$c" >/dev/null || flag "missing $c"
done
if [ ! -e "$CONF" ]; then pass "$CONF absent"
elif ours_conf; then pass "$CONF exists and is ours"
else flag "$CONF exists and is not ours"; fi
if [ -e "$KEY" ] && ! ours_key; then flag "$KEY exists and is not ours"; fi
if ip link show "$IFACE" >/dev/null 2>&1 && ! ours_conf; then flag "interface $IFACE exists and is not ours"; fi
if "$TS_BIN" status --json 2>/dev/null | grep -q '"BackendState": *"Running"'; then
  pass "tailscale is running"
  echo "TN-FACT tsip=$("$TS_BIN" ip -4 2>/dev/null | head -n 1)"
else
  flag "tailscale is not running; run tn join apply on this host first"
fi
echo "TN-FACT forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
"""
    body += f"""if ip -4 route show "$TUNNEL" | grep -v "dev $IFACE" | grep -q .; then
  flag "$TUNNEL is already routed through another interface"
elif ip -4 -o addr show | grep -v " $IFACE " | grep -qw {tunnel_ip}; then
  flag "{tunnel_ip} is already on another interface"
else
  pass "$TUNNEL is unused here"
fi
"""
    for alias in aliases:
        body += f"""if ip -4 route show root {alias} | grep -v "dev $IFACE" | grep -q .; then
  flag "{alias} (an alias range) is already routed here"
else
  pass "{alias} (an alias range) is unused here"
fi
"""
    if side == "responder":
        entry = line.responder_entry_ipv4
        body += f"""if ip -4 -o addr show | awk '{{print $4}}' | cut -d/ -f1 | grep -qxF {entry}; then
  pass "entry address {entry} is on this host"
else
  flag "entry address {entry} is not on this host"
fi
lines=$(ss -H -lun "sport = :$PORT" 2>/dev/null || true)
if [ -z "$lines" ]; then pass "udp/$PORT free"
elif ours_conf && [ "$(wg show "$IFACE" listen-port 2>/dev/null)" = "$PORT" ]; then pass "udp/$PORT already used by $IFACE"
else flag "udp/$PORT is in use"; fi
"""
    body += r"""echo "TN-BEGIN nft"
nft -j list ruleset 2>/dev/null || true
echo
echo "TN-END nft"
echo "TN-BEGIN legacy"
if command -v iptables-legacy >/dev/null; then iptables-legacy -S FORWARD 2>/dev/null || true; fi
echo "TN-END legacy"
if [ "$fail" != 0 ]; then die "checks failed; nothing was changed"; fi
echo "checks passed; nothing was changed"
"""
    return body


# --- step 2: keys ----------------------------------------------------------------------------

KEYS = r"""install -d -m 0700 /etc/wireguard
if ours_key && [ -s "$KEY" ]; then
  echo "private key: kept"
else
  [ -e "$KEY" ] && die "$KEY exists and is not ours"
  wg genkey > "$KEY.tn-new"
  chmod 0600 "$KEY.tn-new"
  mv -f "$KEY.tn-new" "$KEY"
  printf '%s\n' "$MARK" > "$KEYMARK"
  echo "private key: made on this host"
fi
echo "TN-FACT pub=$(wg pubkey < "$KEY")"
"""

ROLLBACK_KEYS = r"""if ours_key; then rm -f "$KEY" "$KEYMARK"; echo "removed $KEY"
elif [ -e "$KEY" ]; then echo "skip: $KEY is not ours"
else echo "$KEY: absent"; fi
"""


# --- steps 3 and 4: one end -------------------------------------------------------------------


def conf(line, side, peer_public_key, remote_alias):
    initiator_ip, responder_ip = line.tunnel_addresses
    me, peer = (initiator_ip, responder_ip) if side == "initiator" else (responder_ip, initiator_ip)
    i = line.interface
    out = [f"# tailnet-ops line={line.name} side={side}", "[Interface]", f"Address = {me}/30"]
    if side == "responder":
        out.append(f"ListenPort = {line.port}")
    out += [
        f"PostUp = wg set %i private-key {WG_DIR}/{i}.key",
        f"PostUp = nft -f {WG_DIR}/{i}.nft",
        f"PostUp = {WG_DIR}/{i}-allow.sh add",
        f"PostDown = {WG_DIR}/{i}-allow.sh del",
        f"PostDown = nft delete table inet {table_name(line)} 2>/dev/null || true",
        "",
        "[Peer]",
        f"# {line.responder if side == 'initiator' else line.initiator}",
        f"PublicKey = {peer_public_key}",
        f"AllowedIPs = {peer}/32, {remote_alias}",
    ]
    if side == "initiator":
        out += [f"Endpoint = {line.responder_entry_ipv4}:{line.port}",
                f"PersistentKeepalive = {line.keepalive_seconds}"]
    return "\n".join(out) + "\n"


def nft_rules(line, side, local_prefix, local_alias, local_tsip):
    """tailnet-ops's own table: NAT both ways for this end."""
    me = line.tunnel_addresses[0 if side == "initiator" else 1]
    t, i = table_name(line), line.interface
    return f"""# tailnet-ops line={line.name} side={side}
table inet {t} {{}}
delete table inet {t}
table inet {t} {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    # an alias from the other region becomes the local tailnet address it stands for
    iifname "{i}" ip daddr {local_alias} dnat ip prefix to ip daddr map {{ {local_alias} : {local_prefix} }}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    # into the tunnel: local tailnet sources become this end's tunnel address
    oifname "{i}" ip saddr {local_prefix} snat ip to {me}
    # out of the tunnel into the tailnet: the source becomes this border
    iifname "{i}" oifname "tailscale0" snat ip to {local_tsip}
  }}
}}
"""


def keeper_units(line, side):
    i = line.interface
    mark = f"# tailnet-ops line={line.name} side={side}"
    service = f"""{mark}
[Unit]
Description=Keep the accept rules of tailnet-ops line {line.name} in place
After=wg-quick@{i}.service

[Service]
Type=oneshot
ExecStart={WG_DIR}/{i}-allow.sh add
"""
    timer = f"""{mark}
[Unit]
Description=Re-add the accept rules of tailnet-ops line {line.name} every 30 s if another tool removed them

[Timer]
OnBootSec=60
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
"""
    return service, timer


def _put(var, text, mode="0600"):
    return f"""cat > "${var}.tn-new" <<'TN_EOF'
{text.rstrip()}
TN_EOF
chmod {mode} "${var}.tn-new"
if cmp -s "${var}.tn-new" "${var}"; then rm -f "${var}.tn-new"; else mv -f "${var}.tn-new" "${var}"; changed=yes; echo "wrote ${var}"; fi
"""


def start(conf_text, nft_text, allow_text, keep, forward):
    service, timer = keep
    body = """for f in "$CONF" "$NFT_FILE" "$ALLOW" "$KEEP_DIR/$KEEP.service" "$KEEP_DIR/$KEEP.timer" "$SYSCTL"; do
  if [ -e "$f" ] && ! ours_file "$f"; then die "$f exists and is not ours"; fi
done
install -d -m 0700 /etc/wireguard
changed=no
"""
    body += _put("NFT_FILE", nft_text)
    body += 'nft -c -f "$NFT_FILE" || die "the NAT rules do not load"\n'
    body += _put("ALLOW", allow_text, "0700")
    body += '"$ALLOW" dry || die "the accept rules do not load (checked with nft -c; nothing applied)"\n'
    body += _put("CONF", conf_text)
    body += 'KEEP_SERVICE="$KEEP_DIR/$KEEP.service"\nKEEP_TIMER="$KEEP_DIR/$KEEP.timer"\n'
    body += _put("KEEP_SERVICE", service, "0644") + _put("KEEP_TIMER", timer, "0644")
    if forward != "1":
        body += f"""printf '%s\\n' "# $MARK" "# ip_forward was {forward or 0} before" "net.ipv4.ip_forward = 1" > "$SYSCTL"
chmod 0644 "$SYSCTL"
sysctl -q -w net.ipv4.ip_forward=1
echo "turned on IPv4 forwarding ($SYSCTL)"
"""
    body += """systemctl daemon-reload
systemctl enable "wg-quick@$IFACE" >/dev/null 2>&1
if systemctl is-active --quiet "wg-quick@$IFACE"; then
  if [ "$changed" = yes ]; then systemctl restart "wg-quick@$IFACE"; echo "restarted wg-quick@$IFACE"; fi
else
  systemctl start "wg-quick@$IFACE"
  echo "started wg-quick@$IFACE"
fi
# Only once the tunnel is up: the timer keeps its accept rules in place from now on.
systemctl enable --now "$KEEP.timer" >/dev/null 2>&1
"$ALLOW" add
"$ALLOW" check && echo "accept rules in place"
nft list table inet "$TABLE" >/dev/null && echo "NAT table $TABLE loaded"
wg show "$IFACE" | sed -n '1,4p'
"""
    return body


ROLLBACK_END = r"""systemctl disable --now "$KEEP.timer" 2>/dev/null || true
if ours_conf; then systemctl disable --now "wg-quick@$IFACE" 2>/dev/null || true; fi
if ours_file "$ALLOW"; then "$ALLOW" del || true; fi
nft delete table inet "$TABLE" 2>/dev/null || true
for f in "$CONF" "$NFT_FILE" "$ALLOW" "$KEEP_DIR/$KEEP.service" "$KEEP_DIR/$KEEP.timer"; do
  if ours_file "$f"; then rm -f "$f"; echo "removed $f"; elif [ -e "$f" ]; then echo "skip: $f is not ours"; fi
done
if ours_file "$SYSCTL"; then
  if grep -q '^# ip_forward was 0 before' "$SYSCTL"; then sysctl -q -w net.ipv4.ip_forward=0; echo "turned IPv4 forwarding back off"; fi
  rm -f "$SYSCTL"
  echo "removed $SYSCTL"
fi
systemctl daemon-reload
"""


# --- step 6: verify -----------------------------------------------------------------------------


def ping(address, source=None, tries=10):
    src = f" -I {source}" if source else ""
    return f"""for _ in $(seq 1 {tries}); do
  if ping -c 1 -W 2{src} {address} >/dev/null 2>&1; then
    echo "TN-PING {address} ok"
    return 0
  fi
  sleep 1
done
echo "TN-PING {address} fail"
"""


def ping_many(targets, source):
    """targets: [(label, address)]. One TN-PING line per target; never fails the script."""
    body = ""
    for _label, address in targets:
        body += f"""if ping -c 2 -W 2 -I {source} {address} >/dev/null 2>&1; then echo "TN-PING {address} ok"; else echo "TN-PING {address} fail"; fi
"""
    return body or 'echo "nothing to ping"\n'


LEFTOVERS = r"""for f in "$CONF" "$KEY" "$KEYMARK" "$NFT_FILE" "$ALLOW" "$KEEP_DIR/$KEEP.service" "$KEEP_DIR/$KEEP.timer" "$SYSCTL" \
         "/etc/systemd/system/multi-user.target.wants/wg-quick@$IFACE.service" "/etc/systemd/system/timers.target.wants/$KEEP.timer"; do
  if [ -e "$f" ]; then echo "TN-LEFT $f"; fi
done
if ip link show "$IFACE" >/dev/null 2>&1; then echo "TN-LEFT interface $IFACE"; fi
if nft list table inet "$TABLE" >/dev/null 2>&1; then echo "TN-LEFT nft table inet $TABLE"; fi
if nft list ruleset 2>/dev/null | grep -qF "tailnet-ops line=$LINE"; then echo "TN-LEFT nft rules tagged tailnet-ops line=$LINE"; fi
if command -v iptables-legacy >/dev/null && iptables-legacy -S 2>/dev/null | grep -qF "tailnet-ops line=$LINE"; then
  echo "TN-LEFT iptables-legacy rules tagged tailnet-ops line=$LINE"
fi
"""

PREFS = '"$TS_BIN" debug prefs 2>/dev/null\n'


def advertise(routes):
    return f'"$TS_BIN" set --advertise-routes={",".join(routes)}\necho "advertising: {", ".join(routes) or "nothing"}"\n'


def approve(node_id, routes):
    return f'"$BIN" nodes approve-routes -i {int(node_id)} -r "{",".join(routes)}"\n'


class Line(Procedure):
    command = "line"

    def __init__(self, site, name, runner=None, out=print):
        matches = [ln for ln in site.lines if ln.name == name]
        if not matches:
            known = ", ".join(ln.name for ln in site.lines) or "none"
            raise StepError(f"unknown line {name!r} (site has: {known})")
        self.line = ln = matches[0]
        if ln.port is None or ln.tunnel_ipv4 is None:
            raise StepError(f"line {name}: set port and tunnel_ipv4 in site.toml first")
        self.site = site
        self.subject = name
        self.target = f"{ln.initiator} and {ln.responder}"
        self.runner = runner
        self.out = out
        self.ends = {"initiator": ln.initiator, "responder": ln.responder}
        self.regions = {side: site.host_region(host) for side, host in self.ends.items()}
        if self.regions["initiator"].name == self.regions["responder"].name:
            raise StepError(f"line {name}: both ends are in region {self.regions['initiator'].name}")
        for side, r in self.regions.items():
            if r.alias_net is None:
                raise StepError(f"region {r.name}: set alias_ipv4 in site.toml (only /24 tailnets get one by default)")
        self.preludes_by_side = {side: prelude(ln, side) for side in self.ends}
        self.control_preludes = {side: scripts.control_prelude(site, r) for side, r in self.regions.items()}
        self.keys = {}
        self.facts = {"initiator": {}, "responder": {}}
        self.targets = {"initiator": None, "responder": None}

    # --- helpers ----------------------------------------------------------------------------

    def local_alias(self, side):
        return str(self.regions[side].alias_net)

    def remote_alias(self, side):
        return self.local_alias(OTHER[side])

    def _on(self, side, body, echo=True, check=True):
        return self.runner.run(self.ends[side], scripts.wrap(self.preludes_by_side[side], body),
                               privileged=True, echo=echo, check=check)

    def _on_control(self, side, body, echo=False):
        r = self.regions[side]
        return self.runner.run(r.control_host, scripts.wrap(self.control_preludes[side], body),
                               privileged=True, echo=echo)

    def _check_body(self, side):
        return check(side, self.line, [self.local_alias(side), self.remote_alias(side)])

    def _absorb_check(self, side, result):
        self.facts[side].update(result.facts())
        own = (table_name(self.line),)
        self.targets[side] = firewall.blocking_targets(result.block("nft") or "", result.block("legacy") or "", own)

    def _allow_text(self, side, targets):
        return firewall.allow_script(self.line.name, self.line.interface, targets,
                                     mark=f"tailnet-ops line={self.line.name} side={side}")

    def _nodes(self, side):
        return _json(self._on_control(side, NODES_JSON).output, []) or []

    def _node_ipv4(self, node):
        return next((ip for ip in node.get("ip_addresses") or [] if ":" not in ip), None)

    # --- the steps' work ---------------------------------------------------------------------

    def _run_checks(self):
        for side in ("initiator", "responder"):
            self.out(f"    {self.ends[side]} ({side}):")
            self._absorb_check(side, self._on(side, self._check_body(side)))
            for t in self.targets[side]:
                self.out(f"    firewall: {t.label()} drops forwarded traffic ({t.reason}); will add accept rules")

    def _run_keys(self):
        for side in ("initiator", "responder"):
            pub = self._on(side, KEYS).facts().get("pub", "")
            if len(pub) != 44:
                raise StepError(f"{self.ends[side]} did not return a WireGuard public key")
            self.keys[side] = pub
            self.out(f"    {self.ends[side]} public key {pub}")

    def _need_facts(self, side):
        if self.targets[side] is None:
            self._absorb_check(side, self._on(side, self._check_body(side), echo=False))
        if "tsip" not in self.facts[side] or not self.facts[side]["tsip"]:
            raise StepError(f"{self.ends[side]} has no tailnet address; is it joined?")
        if OTHER[side] not in self.keys:
            self._run_keys()

    def _end_body(self, side, peer_key=None, tsip=None, targets=None):
        r = self.regions[side]
        return start(
            conf(self.line, side, peer_key or "<the other end's public key, from step 2>", self.remote_alias(side)),
            nft_rules(self.line, side, r.ipv4_prefix, self.local_alias(side), tsip or "<this end's tailnet address>"),
            self._allow_text(side, targets if targets is not None else []),
            keeper_units(self.line, side),
            self.facts[side].get("forward", "1"),
        )

    def _run_end(self, side):
        self._need_facts(side)
        self._on(side, self._end_body(side, self.keys[OTHER[side]], self.facts[side]["tsip"], self.targets[side]))

    def _border_node(self, side, nodes):
        label = dns_label(self.ends[side])
        mine = [n for n in nodes if str(n.get("given_name", "")).lower() == label]
        if len(mine) != 1:
            raise StepError(f"{self.regions[side].control_host} should list exactly one node named {label}")
        return mine[0]

    def _routes(self, add=True):
        for side in ("initiator", "responder"):
            route = self.remote_alias(side)
            prefs = _json(self._on(side, PREFS, echo=False).output, {}) or {}
            have = list(prefs.get("AdvertiseRoutes") or [])
            want = sorted(set(have) | {route}) if add else [x for x in have if x != route]
            if sorted(want) != sorted(have):
                self._on(side, advertise(want))
            else:
                self.out(f"    {self.ends[side]} already advertises {route}" if add else
                         f"    {self.ends[side]} does not advertise {route}")
            node = self._border_node(side, self._nodes(side))
            approved = list(node.get("approved_routes") or [])
            new = sorted(set(approved) | {route}) if add else [x for x in approved if x != route]
            if sorted(new) != sorted(approved):
                self.out(f"    {self.regions[side].control_host}: approve {', '.join(new) or 'no routes'} for {self.ends[side]}")
                self._on_control(side, approve(node.get("id"), new))
        for side in ("initiator", "responder"):
            r = self.regions[side]
            skip = () if add else (self.line.name,)
            self.out(f"    {r.control_host}: policy for region {r.name}")
            self._on_control(side, scripts.real_policy(render.policy(self.site, r, skip_lines=skip)), echo=True)

    def _run_routes(self):
        self._routes(add=True)

    def _undo_routes(self):
        self._routes(add=False)

    def _run_verify(self):
        i_ip, r_ip = self.line.tunnel_addresses
        problems = []
        for side, peer_ip in (("initiator", r_ip), ("responder", i_ip)):
            out = self._on(side, ping(peer_ip), echo=False).output
            ok = f"TN-PING {peer_ip} ok" in out
            self.out(f"    {'✓' if ok else '✗'} {self.ends[side]} → {peer_ip} through the tunnel")
            if not ok:
                problems.append(f"{self.ends[side]} cannot reach {peer_ip} through the tunnel")
        for side in ("initiator", "responder"):
            other = OTHER[side]
            tsip = self._ts_ip(side)
            if not tsip:
                problems.append(f"{self.ends[side]} has no tailnet address")
                continue
            remote = self.regions[other]
            targets = []
            for n in self._nodes(other):
                ip = self._node_ipv4(n)
                if ip and ipaddress.ip_address(ip) in ipaddress.ip_network(remote.ipv4_prefix):
                    targets.append((str(n.get("given_name")), remote.alias_of(ip)))
            out = self._on(side, ping_many(targets, tsip), echo=False).output
            for label, alias in targets:
                ok = f"TN-PING {alias} ok" in out
                self.out(f"    {'✓' if ok else '✗'} {self.regions[side].name} → {remote.name}: {label} at {alias}")
                if not ok:
                    problems.append(f"{self.ends[side]} cannot reach {label} at {alias}")
        if problems:
            raise StepError("; ".join(problems))
        self.out("    verify passed")

    def _ts_ip(self, side):
        if not self.facts[side].get("tsip"):
            self.facts[side]["tsip"] = self._on(side, '"$TS_BIN" ip -4 2>/dev/null | head -n 1\n', echo=False).output.strip()
        return self.facts[side]["tsip"]

    def check(self):
        """Read-only checks on both ends for the short plan: {"fails", "targets"}."""
        fails = []
        for side in ("initiator", "responder"):
            result = self._on(side, self._check_body(side), echo=False, check=False)
            found = [f"{self.ends[side]}: {line.split('FAIL', 1)[1].strip()}" for line in result.output.splitlines()
                     if line.lstrip().startswith("FAIL ")]
            if result.rc != 0 and not found:
                last = result.output.strip().splitlines()[-1:] or ["no answer"]
                found = [f"{self.ends[side]}: cannot log in over SSH as root: {last[0]}"]
            else:
                self._absorb_check(side, result)
            fails += found
        return {"fails": fails, "targets": dict(self.targets)}

    def run_rollback(self, step):
        if step.number == 2:
            for side in ("responder", "initiator"):
                self._on(side, ROLLBACK_KEYS)
        elif step.number == 3:
            self._on("responder", ROLLBACK_END)
        elif step.number == 4:
            self._on("initiator", ROLLBACK_END)

    def leftovers(self):
        left = []
        for side in ("initiator", "responder"):
            out = self._on(side, LEFTOVERS, echo=False).output
            left += [f"{self.ends[side]}: {line[len('TN-LEFT '):]}" for line in out.splitlines()
                     if line.startswith("TN-LEFT ")]
            route = self.remote_alias(side)
            prefs = _json(self._on(side, PREFS, echo=False).output, {}) or {}
            if route in (prefs.get("AdvertiseRoutes") or []):
                left.append(f"{self.ends[side]}: still advertises {route}")
            try:
                node = self._border_node(side, self._nodes(side))
                if route in (node.get("approved_routes") or []):
                    left.append(f"{self.regions[side].control_host}: {route} still approved for {self.ends[side]}")
            except StepError:
                pass
        return left

    def after_rollback(self):
        try:
            left = self.leftovers()
        except self.errors as e:
            self.out(f"\nCould not check for leftovers: {e}")
            return
        if left:
            self.out(f"\n✗ Still there after rollback ({len(left)}):")
            for item in left:
                self.out(f"  ✗ {item}")
        else:
            self.out(f"\n✓ Nothing left on {self.line.initiator} or {self.line.responder}, "
                     "and no route of this line in either Headscale.")

    # --- the steps ------------------------------------------------------------------------------

    def steps(self):
        ln = self.line
        ini, res = ln.initiator, ln.responder
        i_ip, r_ip = ln.tunnel_addresses
        both = f"{ini} and {res}"
        ri, rr = self.regions["initiator"], self.regions["responder"]
        steps = [
            Step(1, "Check both ends",
                 ["Root, tools, tailscale running, nothing named like ours that is not ours, the tunnel and",
                  "alias ranges unused, the entry address and port on the responder; read the firewall. Changes nothing."],
                 [Action(ini, "checks", self._check_body("initiator"), "initiator", True),
                  Action(res, "checks", self._check_body("responder"), "responder", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_checks,
                 host=both, brief="Check both ends and their firewalls"),
            Step(2, "Keys",
                 ["Make a WireGuard private key on each end (it never leaves the host); read the public keys."],
                 [Action(ini, "make the key", KEYS, "initiator", True), Action(res, "make the key", KEYS, "responder", True)],
                 rollback=ROLLBACK_KEYS, rollback_note="remove the key files on both ends, if ours",
                 run=self._run_keys, host=both, rollback_host=both,
                 brief="Make a private key on each end", undo_brief="remove both keys"),
            Step(3, "Responder",
                 [f"On {res}: {ln.interface} {r_ip}/30 on udp/{ln.port}, no endpoint; NAT in table {table_name(ln)};",
                  "accept rules in each chain that would drop the traffic, kept by a timer."],
                 [Action(res, "write and start", self._end_body("responder", targets=self.targets["responder"] or []),
                         "responder", True)],
                 rollback=ROLLBACK_END, rollback_note=f"stop {ln.interface}; remove its NAT table, accept rules, timer and files",
                 run=lambda: self._run_end("responder"), host=res,
                 brief=f"Tunnel, NAT and accept rules on {res}", undo_brief="stop it and remove all of it"),
            Step(4, "Initiator",
                 [f"On {ini}: {ln.interface} {i_ip}/30 to {ln.responder_entry_ipv4}:{ln.port}, keepalive "
                  f"{ln.keepalive_seconds} s; NAT, accept rules and timer as on {res}."],
                 [Action(ini, "write and start", self._end_body("initiator", targets=self.targets["initiator"] or []),
                         "initiator", True)],
                 rollback=ROLLBACK_END, rollback_note=f"stop {ln.interface}; remove its NAT table, accept rules, timer and files",
                 run=lambda: self._run_end("initiator"), host=ini,
                 brief=f"Tunnel, NAT and accept rules on {ini}, connect", undo_brief="stop it and remove all of it"),
            Step(5, "Routes and policy",
                 [f"{ini} advertises {rr.alias_net} into {ri.name}; {res} advertises {ri.alias_net} into {rr.name};",
                  f"approve both in Headscale; the policies let {self.site.owner_user}@ reach the other region's alias range."],
                 [Action(ini, "advertise", advertise([self.remote_alias("initiator")]), "initiator", True),
                  Action(res, "advertise", advertise([self.remote_alias("responder")]), "responder", True)],
                 rollback=("# On each end: tailscale set --advertise-routes=<what it advertised, minus the alias range>\n"
                           "# On each control host: headscale nodes approve-routes -i <border> -r <approved, minus it>,\n"
                           "# then the region's policy without this line (as in step 7 of tn control)\n"),
                 rollback_note="stop advertising, unapprove, policies without this line",
                 run=self._run_routes, undo=self._undo_routes, host=both, rollback_host=both,
                 brief="Advertise, approve, update both policies", undo_brief="withdraw them"),
            Step(6, "Check across",
                 [f"Ping through the tunnel both ways; then from each end, with its tailnet address as the source,",
                  "ping the alias of every host in the other region. Read-only."],
                 [Action(ini, "ping", ping(r_ip), "initiator", True), Action(res, "ping", ping(i_ip), "responder", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_verify, host=both,
                 brief="Ping every host across, both ways"),
        ]
        return steps

    # --- printing ---------------------------------------------------------------------------------

    def summary_header(self, checks=None):
        ln = self.line
        i_ip, r_ip = ln.tunnel_addresses
        ri, rr = self.regions["initiator"], self.regions["responder"]
        out = [
            f"line {ln.name}: {ln.initiator} ({ri.name}) → {ln.responder} ({rr.name})"
            + (", one-way: only the initiator connects" if ln.one_way else ""),
            f"  tunnel        {ln.interface}: {i_ip} ⇄ {r_ip}; {ln.initiator} connects to "
            f"{ln.responder_entry_ipv4}:{ln.port}, keepalive {ln.keepalive_seconds} s",
            f"  addresses     {ri.name} hosts appear in {rr.name} as {ri.alias_net}; "
            f"{rr.name} hosts appear in {ri.name} as {rr.alias_net}",
            f"  routes        {ln.initiator} advertises {rr.alias_net} into {ri.name}; "
            f"{ln.responder} advertises {ri.alias_net} into {rr.name}",
            f"  NAT           in tailnet-ops's own nft table {table_name(ln)} on both ends",
        ]
        targets = (checks or {}).get("targets") or {}
        found = []
        for side in ("initiator", "responder"):
            if targets.get(side) is None:
                continue
            host = self.ends[side]
            found += [f"{host}: {t.label()} drops forwarded traffic ({t.reason}) → 2 tagged accept rules, kept by a timer"
                      for t in targets[side]] or [f"{host}: nothing drops forwarded traffic"]
        for k, text in enumerate(found):
            out.append(("  firewall      " if k == 0 else " " * 16) + text)
        out += [
            f"  policy        {self.site.owner_user}@ may reach the other region's alias range",
            "  keys          made on each end; only public keys travel",
            "  leaves alone  every existing rule, table, route, interface and service",
        ]
        if checks is None:
            out.append("  checks        not run (--offline); the firewall is read in step 1")
        elif checks["fails"]:
            out += ["", f"Not ready ({len(checks['fails'])}):"] + [f"  ✗ {f}" for f in checks["fails"]]
        else:
            out += ["", f"✓ Ready: every read-only check on {ln.initiator} and {ln.responder} passed."]
        return "\n".join(out)

    def header(self):
        return "\n".join(line for line in self.summary_header(checks=None).splitlines()
                         if not line.startswith("  checks"))

    def preludes(self):
        return [(f"{self.line.initiator}, initiator", self.preludes_by_side["initiator"]),
                (f"{self.line.responder}, responder", self.preludes_by_side["responder"])]

    def plan_intro(self):
        return ("Every script runs as `bash -s` over SSH as root: the prelude of its end, then the step body\n"
                "inside `tn_step() { ... }` with stdin from /dev/null. Step 5 also runs headscale on each control host.")

    def rollback_footer(self):
        return "Nothing on this machine needs undoing."

    def done_message(self):
        ri, rr = self.regions["initiator"], self.regions["responder"]
        return (f"Line {self.line.name} connects {ri.name} and {rr.name}: from {ri.name}, reach {rr.name} hosts at "
                f"{rr.alias_net}; from {rr.name}, reach {ri.name} hosts at {ri.alias_net}.")

    def rolled_back_message(self):
        return f"Rolled back line {self.line.name}."

    def verify(self):
        return self.run_once(self._run_verify)
