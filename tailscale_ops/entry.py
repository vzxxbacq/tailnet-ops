"""The phone entry on a control host: a WireGuard interface for phones' proxy apps.

A phone cannot run Tailscale next to its proxy app (one VPN at a time), so the proxy
app gets WireGuard nodes instead, one per region. A control host with `entry_port`
runs tn-entry on that UDP port. Every phone has one address in the site's entry range,
the same on every entry, and on the way in:

- this region's tailnet addresses are reached as they are;
- the tailnet addresses of a region reached through a line become its alias range
  here, so a phone uses the same address for a host whichever entry it is on;
- anything else is dropped: the entry is no way out to the internet;
- phones are masqueraded, so tailnet hosts see the control host and need no route back;
- firewall chains that would drop this traffic get tagged accept rules, kept by a timer;
- the entry's own address answers DNS (entry_dns.py): the tailnet's names from MagicDNS,
  which gives addresses this entry reaches, and other names from the host's resolvers.

Everything hangs off the wg-quick unit, as for a line, and lives in tailscale-ops's own
nft table. Peers are the phones in the site's phones.json (`tn phone add`).
"""

from pathlib import Path

from . import firewall, render, scripts

IFACE = "tn-entry"
TABLE = "tn_entry"
WG_DIR = "/etc/wireguard"
KEEP = f"{IFACE}-allow"
DNS_UNIT = f"{IFACE}-dns"
DNS_BIN = f"/usr/local/sbin/{DNS_UNIT}"
# What phones use: tailscale0's MTU, so nothing needs fragmenting on the way into the tailnet.
PHONE_MTU = 1280


def mark(region):
    return f"tailnet-ops entry region={region.name}"


def reached(site, region):
    """[(other region)] reached through a line, once each, with an alias range."""
    out = []
    for _ln, other in render.line_peers(site, region):
        if other.alias_net is not None and other.name not in [o.name for o in out]:
            out.append(other)
    return out


def phone_routes(site, region):
    """What a phone sends through this entry: the tailnets at their own addresses, the alias ranges
    MagicDNS answers with for regions across a line, and the entry itself (its DNS)."""
    others = reached(site, region)
    return ([region.ipv4_prefix] + [o.ipv4_prefix for o in others] + [str(o.alias_net) for o in others]
            + [f"{site.entry_address}/32"])


def suffixes(site):
    return sorted({r.base_domain for r in site.regions.values()})


def tunnels(site, region):
    """The line interfaces on this control host: forwarded phone traffic may leave through them."""
    return [ln.interface for ln in site.lines if region.control_host in (ln.initiator, ln.responder)]


def entry_vars(site, region):
    return f"""{scripts._vars([
    ("EIFACE", IFACE),
    ("EWG_DIR", WG_DIR),
    ("ECONF", f"{WG_DIR}/{IFACE}.conf"),
    ("EKEY", f"{WG_DIR}/{IFACE}.key"),
    ("EKEYMARK", f"{WG_DIR}/{IFACE}.tailnet-ops"),
    ("ENFT", f"{WG_DIR}/{IFACE}.nft"),
    ("EALLOW", f"{WG_DIR}/{IFACE}-allow.sh"),
    ("EKEEP", KEEP),
    ("EKEEP_DIR", "/etc/systemd/system"),
    ("ESYSCTL", f"/etc/sysctl.d/90-tailnet-ops-{IFACE}.conf"),
    ("EDNS", DNS_UNIT),
    ("EDNS_BIN", DNS_BIN),
    ("EDNS_UNIT", f"/etc/systemd/system/{DNS_UNIT}.service"),
    ("EADDR", site.entry_address),
    ("ETABLE", TABLE),
    ("EPORT", region.entry_port or ""),
    ("ENET", site.entry_ipv4),
])}
EMARK="tailnet-ops entry region=$REGION"
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
entry_ours() {{ [ -f "$1" ] && head -n 2 "$1" | grep -qxF "# $EMARK"; }}
entry_ours_key() {{ [ -f "$EKEYMARK" ] && [ "$(cat "$EKEYMARK")" = "$EMARK" ]; }}
"""


# --- read-only checks ----------------------------------------------------------------------


def check(site, region):
    return entry_vars(site, region) + f"""fail=0
pass() {{ printf '  ok    %s\\n' "$*"; }}
flag() {{ printf '  FAIL  %s\\n' "$*"; fail=1; }}
note() {{ printf '  note  %s\\n' "$*"; }}
for c in wg wg-quick ip nft sysctl ss; do
  command -v "$c" >/dev/null || flag "missing $c (Debian and Ubuntu: apt install wireguard-tools nftables)"
done
if [ ! -e "$ECONF" ]; then pass "$ECONF absent"
elif entry_ours "$ECONF"; then pass "$ECONF exists and is ours"
else flag "$ECONF exists and is not ours"; fi
if [ -e "$EKEY" ] && ! entry_ours_key; then flag "$EKEY exists and is not ours"; fi
if ip link show "$EIFACE" >/dev/null 2>&1 && ! entry_ours "$ECONF"; then flag "interface $EIFACE exists and is not ours"; fi
lines=$(ss -H -lun "sport = :$EPORT" 2>/dev/null || true)
if [ -z "$lines" ]; then pass "udp/$EPORT free"
elif entry_ours "$ECONF" && [ "$(wg show "$EIFACE" listen-port 2>/dev/null)" = "$EPORT" ]; then pass "udp/$EPORT already used by $EIFACE"
else flag "udp/$EPORT is in use"; fi
if ip -4 route show root "$ENET" | grep -v "dev $EIFACE" | grep -q .; then
  flag "$ENET (the phones' range) is already routed through another interface"
elif ip -4 -o addr show | grep -v " $EIFACE " | grep -qw {site.entry_address}; then
  flag "{site.entry_address} is already on another interface"
else
  pass "$ENET (the phones' range) is unused here"
fi
if [ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 6))'; then
  pass "python3 for the entry's DNS"
else
  flag "the entry's DNS needs /usr/bin/python3 3.6 or newer"
fi
busy=$({{ ss -H -lun "sport = :53"; ss -H -ltn "sport = :53"; }} 2>/dev/null | awk '{{print $4}}' \
  | grep -E "^(0\\.0\\.0\\.0|\\*|\\[::\\]|$EADDR):53$" | sort -u | tr '\\n' ' ' || true)
if [ -z "$busy" ] || systemctl is-active --quiet "$EDNS"; then pass "port 53 on $EADDR is free for the entry's DNS"
else flag "port 53 is taken where the entry's DNS would listen: $busy"; fi
if ip link show tailscale0 >/dev/null 2>&1; then pass "tailscale0 is up"
else note "no tailscale0 yet: phones reach the tailnet once this host joins it (tn join)"; fi
if command -v nft >/dev/null; then
  if out=$(nft -c -f - 2>&1 <<'TN_EOF'
{nft_rules(site, region).rstrip()}
TN_EOF
  ); then pass "the entry's nft table loads (checked with nft -c; nothing applied)"
  else flag "the entry's nft table does not load: $(printf '%s' "$out" | head -n 3 | tr '\\n' ' ')"; fi
fi
echo "TN-FACT forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
echo "TN-BEGIN nft"
nft -j list ruleset 2>/dev/null || true
echo
echo "TN-END nft"
for hook in FORWARD INPUT; do
  echo "TN-BEGIN legacy-$hook"
  if command -v iptables-legacy >/dev/null; then iptables-legacy -S "$hook" 2>/dev/null || true; fi
  echo "TN-END legacy-$hook"
done
if [ "$fail" != 0 ]; then die "entry checks failed; nothing was changed"; fi
echo "entry checks passed; nothing was changed"
"""


def targets(result):
    """{"forward": [Target], "input": [Target]}: the chains that would drop phone traffic."""
    nft = result.block("nft") or ""
    return {hook: firewall.blocking_targets(nft, result.block(f"legacy-{hook.upper()}") or "", (TABLE,), hook)
            for hook in ("forward", "input")}


# --- files -------------------------------------------------------------------------------------


def peers(site):
    """[(name, address, public key)] of the site's phones, in a stable order."""
    return [(name, p["address"], p["public_key"]) for name, p in sorted(site.phones.items())]


def conf(site, region):
    out = [f"# {mark(region)}", "[Interface]", f"Address = {site.entry_address}/{site.entry_net.prefixlen}",
           f"ListenPort = {region.entry_port}",
           f"PostUp = wg set %i private-key {WG_DIR}/{IFACE}.key",
           f"PostUp = nft -f {WG_DIR}/{IFACE}.nft",
           f"PostUp = {WG_DIR}/{IFACE}-allow.sh add",
           f"PostDown = {WG_DIR}/{IFACE}-allow.sh del",
           f"PostDown = nft delete table inet {TABLE} 2>/dev/null || true"]
    for name, address, public_key in peers(site):
        out += ["", "[Peer]", f"# {name}", f"PublicKey = {public_key}", f"AllowedIPs = {address}/32"]
    return "\n".join(out) + "\n"


def nft_rules(site, region):
    """tailscale-ops's own table: where phones may go, the mapping across lines, and NAT."""
    others = reached(site, region)
    allowed = ", ".join([region.ipv4_prefix] + [str(o.alias_net) for o in others])
    maps = [f'    iifname "{IFACE}" ip daddr {o.ipv4_prefix} dnat ip prefix to ip daddr map '
            f'{{ {o.ipv4_prefix} : {o.alias_net} }}' for o in others]
    prerouting = ""
    if maps:
        prerouting = ("  chain prerouting {\n"
                      "    type nat hook prerouting priority dstnat; policy accept;\n"
                      "    # a region reached through a line: its tailnet addresses become its alias range here\n"
                      + "\n".join(maps) + "\n  }\n")
    return f"""# {mark(region)}
table inet {TABLE} {{}}
delete table inet {TABLE}
table inet {TABLE} {{
{prerouting}  chain forward {{
    type filter hook forward priority filter; policy accept;
    # phones reach the tailnets only, never the internet
    iifname "{IFACE}" ip daddr != {{ {allowed} }} drop
    # TCP from phones fits tailscale0 without fragments
    iifname "{IFACE}" tcp flags syn tcp option maxseg size set rt mtu
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    # phones are masqueraded: hosts see this one and need no route back
    iifname "{IFACE}" oifname != "{IFACE}" masquerade
  }}
}}
"""


def allow_script(site, region, found):
    """Accept rules for the chains in found ({"forward", "input"}): phones' traffic into the tailnet
    and the lines and back, the WireGuard port, and phones reaching this host itself."""
    comment = mark(region)
    forward = []
    for out in ["tailscale0", *tunnels(site, region)]:
        forward += [(f'iifname "{IFACE}" oifname "{out}"', f"-i {IFACE} -o {out}"),
                    (f'iifname "{out}" oifname "{IFACE}"', f"-i {out} -o {IFACE}")]
    to = f"ip daddr {region.listen_ipv4} " if region.specific_listen else ""
    to_spec = f"-d {region.listen_ipv4} " if region.specific_listen else ""
    inbound = [(f"{to}udp dport {region.entry_port}", f"{to_spec}-p udp --dport {region.entry_port}"),
               (f'iifname "{IFACE}"', f"-i {IFACE}")]
    chains = [(t, forward) for t in found.get("forward", [])] + [(t, inbound) for t in found.get("input", [])]
    about = [f"# {comment}: accept phones' traffic through {IFACE} in the chains below, which would",
             "# otherwise drop it. Run by wg-quick (PostUp add, PostDown del) and by a timer that puts",
             "# the rules back if another tool reloads its firewall."]
    return firewall.accept_script(comment, chains, about, mark=comment)


def dns_program(region):
    """entry_dns.py as installed: its mark on the second line."""
    lines = Path(__file__).with_name("entry_dns.py").read_text().splitlines(keepends=True)
    return lines[0] + f"# {mark(region)}\n" + "".join(lines[1:])


def dns_unit(site, region):
    names = ", ".join(suffixes(site))
    args = " ".join(f"--suffix {s}" for s in suffixes(site))
    return f"""# {mark(region)}
[Unit]
Description=DNS for phones on the tailnet-ops entry: {names} from MagicDNS, other names from this host's resolvers
After=wg-quick@{IFACE}.service
BindsTo=wg-quick@{IFACE}.service

[Service]
ExecStart={DNS_BIN} --listen {site.entry_address} {args}
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=always
RestartSec=2

[Install]
WantedBy=wg-quick@{IFACE}.service
"""


def keeper_units(region):
    head = f"# {mark(region)}"
    service = f"""{head}
[Unit]
Description=Keep the accept rules of the tailnet-ops phone entry in place
After=wg-quick@{IFACE}.service

[Service]
Type=oneshot
ExecStart={WG_DIR}/{IFACE}-allow.sh add
"""
    timer = f"""{head}
[Unit]
Description=Re-add the accept rules of the tailnet-ops phone entry every 30 s if another tool removed them

[Timer]
OnBootSec=60
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
"""
    return service, timer


def _put(var, text, mode="0600", flag="changed"):
    return f"""cat > "${var}.tn-new" <<'TN_EOF'
{text.rstrip()}
TN_EOF
chmod {mode} "${var}.tn-new"
if cmp -s "${var}.tn-new" "${var}"; then rm -f "${var}.tn-new"; else mv -f "${var}.tn-new" "${var}"; {flag}=yes; echo "wrote ${var}"; fi
"""


# The conf without its peers (and blank lines): what a restart is needed for.
INTERFACE_PART = "sed -e '/^\\[Peer\\]/,$d' -e '/^$/d'"


def _put_conf(text):
    """The conf; only a change outside its [Peer] sections restarts the interface."""
    return f"""cat > "$ECONF.tn-new" <<'TN_EOF'
{text.rstrip()}
TN_EOF
chmod 0600 "$ECONF.tn-new"
if ! cmp -s "$ECONF.tn-new" "$ECONF"; then
  if ! cmp -s <({INTERFACE_PART} "$ECONF.tn-new") <({INTERFACE_PART} "$ECONF" 2>/dev/null); then changed=yes; fi
  mv -f "$ECONF.tn-new" "$ECONF"
  echo "wrote $ECONF"
else
  rm -f "$ECONF.tn-new"
fi
"""


def sync_peers(site):
    """Make the running interface's peers the site's phones, without restarting it."""
    want = "".join(f"{public_key} {address}/32\n" for _name, address, public_key in peers(site))
    return f"""want=$(cat <<'TN_EOF'
{want}TN_EOF
)
for pub in $(wg show "$EIFACE" peers); do
  if ! printf '%s\\n' "$want" | grep -qF "$pub "; then wg set "$EIFACE" peer "$pub" remove; echo "removed a phone that is no longer listed"; fi
done
printf '%s\\n' "$want" | while read -r pub ip; do
  [ -n "$pub" ] || continue
  wg set "$EIFACE" peer "$pub" allowed-ips "$ip"
done
echo "phones on $EIFACE: $(wg show "$EIFACE" peers | grep -c . || true)"
echo "TN-FACT pub=$(wg pubkey < "$EKEY")"
"""


def start(site, region, found, forward):
    """Key, files and the running interface. found: the chains from check(); forward: ip_forward now."""
    service, timer = keeper_units(region)
    body = entry_vars(site, region) + """for f in "$ECONF" "$ENFT" "$EALLOW" "$EKEEP_DIR/$EKEEP.service" "$EKEEP_DIR/$EKEEP.timer" "$ESYSCTL" \\
         "$EDNS_BIN" "$EDNS_UNIT"; do
  if [ -e "$f" ] && ! entry_ours "$f"; then die "$f exists and is not ours"; fi
done
install -d -m 0700 "$EWG_DIR"
if entry_ours_key && [ -s "$EKEY" ]; then
  echo "private key: kept"
else
  [ -e "$EKEY" ] && die "$EKEY exists and is not ours"
  (umask 077; wg genkey > "$EKEY.tn-new")
  mv -f "$EKEY.tn-new" "$EKEY"
  printf '%s\\n' "$EMARK" > "$EKEYMARK"
  echo "private key: made on this host"
fi
changed=no
dns_changed=no
"""
    body += _put("ENFT", nft_rules(site, region))
    body += 'nft -c -f "$ENFT" || die "the entry\'s nft table does not load"\n'
    body += _put("EALLOW", allow_script(site, region, found), "0700")
    body += '"$EALLOW" dry || die "the accept rules do not load (checked with nft -c; nothing applied)"\n'
    body += _put_conf(conf(site, region))
    body += 'EKEEP_SERVICE="$EKEEP_DIR/$EKEEP.service"\nEKEEP_TIMER="$EKEEP_DIR/$EKEEP.timer"\n'
    body += _put("EKEEP_SERVICE", service, "0644") + _put("EKEEP_TIMER", timer, "0644")
    body += _put("EDNS_BIN", dns_program(region), "0755", "dns_changed")
    body += _put("EDNS_UNIT", dns_unit(site, region), "0644", "dns_changed")
    if forward != "1":
        body += f"""printf '%s\\n' "# $EMARK" "# ip_forward was {forward or 0} before" "net.ipv4.ip_forward = 1" > "$ESYSCTL"
chmod 0644 "$ESYSCTL"
sysctl -q -w net.ipv4.ip_forward=1
echo "turned on IPv4 forwarding ($ESYSCTL)"
"""
    body += """systemctl daemon-reload
systemctl enable "wg-quick@$EIFACE" >/dev/null 2>&1
if systemctl is-active --quiet "wg-quick@$EIFACE"; then
  if [ "$changed" = yes ]; then systemctl restart "wg-quick@$EIFACE"; echo "restarted wg-quick@$EIFACE"; fi
else
  systemctl start "wg-quick@$EIFACE"
  echo "started wg-quick@$EIFACE"
fi
# Only once the interface is up: the timer keeps its accept rules in place from now on.
systemctl enable --now "$EKEEP.timer" >/dev/null 2>&1
"$EALLOW" add
"$EALLOW" check && echo "accept rules in place"
nft list table inet "$ETABLE" >/dev/null && echo "nft table $ETABLE loaded"
systemctl enable "$EDNS" >/dev/null 2>&1
if [ "$dns_changed" = yes ] || ! systemctl is-active --quiet "$EDNS"; then systemctl restart "$EDNS"; fi
sleep 1
systemctl is-active --quiet "$EDNS" || die "$EDNS did not start; see journalctl -u $EDNS"
echo "DNS for phones on $EADDR:53 ($EDNS)"
"""
    return body + sync_peers(site)


def update_peers(site, region):
    """For tn phone: write the conf with the site's phones and apply them to the running interface.
    Says TN-FACT entry=absent, changing nothing, where the entry is not installed."""
    return entry_vars(site, region) + f"""if ! entry_ours "$ECONF" || ! wg show "$EIFACE" >/dev/null 2>&1; then
  echo "TN-FACT entry=absent"
  exit 0
fi
cat > "$ECONF.tn-new" <<'TN_EOF'
{conf(site, region).rstrip()}
TN_EOF
chmod 0600 "$ECONF.tn-new"
if ! cmp -s <({INTERFACE_PART} "$ECONF.tn-new") <({INTERFACE_PART} "$ECONF"); then
  rm -f "$ECONF.tn-new"
  die "$ECONF differs outside its peers; run tn control apply $REGION first"
fi
if cmp -s "$ECONF.tn-new" "$ECONF"; then rm -f "$ECONF.tn-new"; else mv -f "$ECONF.tn-new" "$ECONF"; echo "wrote $ECONF"; fi
""" + sync_peers(site)


def rollback(site, region):
    return entry_vars(site, region) + """systemctl disable --now "$EKEEP.timer" 2>/dev/null || true
if entry_ours "$EDNS_UNIT"; then systemctl disable --now "$EDNS" 2>/dev/null || true; fi
if entry_ours "$ECONF"; then systemctl disable --now "wg-quick@$EIFACE" 2>/dev/null || true; fi
if entry_ours "$EALLOW"; then "$EALLOW" del || true; fi
nft delete table inet "$ETABLE" 2>/dev/null || true
for f in "$ECONF" "$ENFT" "$EALLOW" "$EKEEP_DIR/$EKEEP.service" "$EKEEP_DIR/$EKEEP.timer" "$EDNS_BIN" "$EDNS_UNIT"; do
  if entry_ours "$f"; then rm -f "$f"; echo "removed $f"; elif [ -e "$f" ]; then echo "skip: $f is not ours"; fi
done
if entry_ours_key; then rm -f "$EKEY" "$EKEYMARK"; echo "removed $EKEY"
elif [ -e "$EKEY" ]; then echo "skip: $EKEY is not ours"; fi
if entry_ours "$ESYSCTL"; then
  # Turn forwarding back off only if it was off and no other WireGuard interface or tailnet-ops file needs it.
  others=$(wg show interfaces 2>/dev/null | tr ' ' '\\n' | grep -vx "$EIFACE" | grep -c . || true)
  for f in /etc/sysctl.d/90-tailnet-ops-*.conf; do
    if [ -e "$f" ] && [ "$f" != "$ESYSCTL" ]; then others=$((others + 1)); fi
  done
  if grep -q '^# ip_forward was 0 before' "$ESYSCTL" && [ "$others" = 0 ]; then
    sysctl -q -w net.ipv4.ip_forward=0
    echo "turned IPv4 forwarding back off"
  fi
  rm -f "$ESYSCTL"
  echo "removed $ESYSCTL"
fi
systemctl daemon-reload
"""


LEFTOVERS = """for f in "$ECONF" "$EKEY" "$EKEYMARK" "$ENFT" "$EALLOW" "$EKEEP_DIR/$EKEEP.service" "$EKEEP_DIR/$EKEEP.timer" "$ESYSCTL" \\
         "$EDNS_BIN" "$EDNS_UNIT" "/etc/systemd/system/wg-quick@$EIFACE.service.wants/$EDNS.service" \\
         "/etc/systemd/system/multi-user.target.wants/wg-quick@$EIFACE.service" "/etc/systemd/system/timers.target.wants/$EKEEP.timer"; do
  if [ -e "$f" ]; then echo "TN-LEFT $f"; fi
done
if ip link show "$EIFACE" >/dev/null 2>&1; then echo "TN-LEFT interface $EIFACE"; fi
if systemctl is-active --quiet "$EDNS"; then echo "TN-LEFT service $EDNS is running"; fi
if nft list table inet "$ETABLE" >/dev/null 2>&1; then echo "TN-LEFT nft table inet $ETABLE"; fi
if nft list ruleset 2>/dev/null | grep -qF "$EMARK"; then echo "TN-LEFT nft rules tagged $EMARK"; fi
if command -v iptables-legacy >/dev/null && iptables-legacy -S 2>/dev/null | grep -qF "$EMARK"; then
  echo "TN-LEFT iptables-legacy rules tagged $EMARK"
fi
"""


DNS_CHECK = r"""import os, socket, sys
query = os.urandom(2) + b"\x01\x00\x00\x01" + b"\x00" * 6 + b"".join(
    bytes([len(x)]) + x.encode() for x in sys.argv[2].split(".")) + b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(query, (sys.argv[1], 53))
    answer = s.recv(4096)
except OSError as e:
    print("no answer:", e)
    sys.exit(1)
ok = answer[:2] == query[:2] and answer[3] & 15 == 0 and answer[6:8] != b"\x00\x00"
print("answered" if ok else "rcode %d" % (answer[3] & 15))
sys.exit(0 if ok else 1)
"""


def status(site, region, name):
    """Read-only: the services, the accept rules, a DNS lookup of name on the entry, and the peers
    (`wg show dump`: public key, endpoint, seconds since the last handshake or -1, bytes in and out)."""
    return entry_vars(site, region) + f"""if ! entry_ours "$ECONF"; then echo "TN-FACT entry=absent"; exit 0; fi
echo "TN-FACT wg=$(systemctl is-active "wg-quick@$EIFACE" 2>/dev/null || true)"
echo "TN-FACT dns=$(systemctl is-active "$EDNS" 2>/dev/null || true)"
echo "TN-FACT keeper=$(systemctl is-active "$EKEEP.timer" 2>/dev/null || true)"
if [ -x "$EALLOW" ] && "$EALLOW" check >/dev/null 2>&1; then echo "TN-FACT rules=ok"; else echo "TN-FACT rules=missing"; fi
if out=$(/usr/bin/python3 - "$EADDR" {name} 2>&1 <<'TN_EOF'
{DNS_CHECK.rstrip()}
TN_EOF
); then echo "TN-FACT lookup=ok"; else echo "TN-FACT lookup=$out"; fi
now=$(date +%s)
echo "TN-BEGIN peers"
wg show "$EIFACE" dump 2>/dev/null | tail -n +2 | awk -v now="$now" '{{print $1, $3, ($5 > 0 ? now - $5 : -1), $6, $7}}'
echo "TN-END peers"
"""


def leftovers(site, region):
    return entry_vars(site, region) + LEFTOVERS
