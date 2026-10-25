"""`tn line`: the WireGuard tunnel of a dedicated line, started by its initiator.

This is the tunnel alone: the two ends reach each other's tunnel address. Routing other
hosts' traffic through it (subnet routes, forwarding, NAT) is a separate step.
"""

from . import scripts
from .procedure import Action, Procedure, Step, StepError

WG_DIR = "/etc/wireguard"


def prelude(line, side):
    return f"""set -euo pipefail
umask 077
{scripts._vars([
    ("LINE", line.name),
    ("SIDE", side),
    ("IFACE", line.interface),
    ("CONF", f"{WG_DIR}/{line.interface}.conf"),
    ("KEY", f"{WG_DIR}/{line.interface}.key"),
    ("KEYMARK", f"{WG_DIR}/{line.interface}.tailnet-ops"),
    ("PORT", line.port),
    ("TUNNEL", line.tunnel_ipv4),
])}
MARK="tailnet-ops line=$LINE side=$SIDE"
die() {{ echo "tn: $*" >&2; exit 1; }}
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
ours_conf() {{ [ -f "$CONF" ] && [ "$(head -n 1 "$CONF")" = "# $MARK" ]; }}
ours_key() {{ [ -f "$KEYMARK" ] && [ "$(cat "$KEYMARK")" = "$MARK" ]; }}"""


def check(side, tunnel_address, entry=None):
    """Read-only checks on one end."""
    body = r"""fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }
if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
for c in wg wg-quick ip ping; do
  command -v "$c" >/dev/null || flag "missing $c"
done
if [ ! -e "$CONF" ]; then pass "$CONF absent"
elif ours_conf; then pass "$CONF exists and is ours"
else flag "$CONF exists and is not ours"; fi
if [ -e "$KEY" ] && ! ours_key; then flag "$KEY exists and is not ours"; fi
if ip link show "$IFACE" >/dev/null 2>&1 && ! ours_conf; then flag "interface $IFACE exists and is not ours"; fi
"""
    body += f"""if ip -4 route show "$TUNNEL" | grep -v "dev $IFACE" | grep -q .; then
  flag "$TUNNEL is already routed through another interface"
elif ip -4 -o addr show | grep -v " $IFACE " | grep -qw {tunnel_address}; then
  flag "{tunnel_address} is already on another interface"
else
  pass "$TUNNEL is unused here"
fi
"""
    if side == "responder":
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
    body += r"""if [ "$fail" != 0 ]; then die "checks failed; nothing was changed"; fi
echo "checks passed; nothing was changed"
"""
    return body


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


def conf(line, side, peer_public_key):
    initiator_ip, responder_ip = line.tunnel_addresses
    me, peer = (initiator_ip, responder_ip) if side == "initiator" else (responder_ip, initiator_ip)
    lines = [
        f"# tailnet-ops line={line.name} side={side}",
        "[Interface]",
        f"Address = {me}/30",
    ]
    if side == "responder":
        lines.append(f"ListenPort = {line.port}")
    lines += [
        f"PostUp = wg set %i private-key {WG_DIR}/{line.interface}.key",
        "",
        "[Peer]",
        f"# {line.responder if side == 'initiator' else line.initiator}",
        f"PublicKey = {peer_public_key}",
        f"AllowedIPs = {peer}/32",
    ]
    if side == "initiator":
        lines += [f"Endpoint = {line.responder_entry_ipv4}:{line.port}",
                  f"PersistentKeepalive = {line.keepalive_seconds}"]
    return "\n".join(lines) + "\n"


def start(conf_text):
    return f"""if [ -e "$CONF" ] && ! ours_conf; then die "$CONF exists and is not ours"; fi
cat > "$CONF.tn-new" <<'TN_EOF'
{conf_text.rstrip()}
TN_EOF
chmod 0600 "$CONF.tn-new"
changed=no
if cmp -s "$CONF.tn-new" "$CONF"; then rm -f "$CONF.tn-new"; echo "unchanged $CONF"
else mv -f "$CONF.tn-new" "$CONF"; echo "wrote $CONF"; changed=yes; fi
systemctl enable "wg-quick@$IFACE" >/dev/null 2>&1
if systemctl is-active --quiet "wg-quick@$IFACE"; then
  if [ "$changed" = yes ]; then systemctl restart "wg-quick@$IFACE"; echo "restarted wg-quick@$IFACE"; fi
else
  systemctl start "wg-quick@$IFACE"
  echo "started wg-quick@$IFACE"
fi
wg show "$IFACE" | sed -n '1,4p'
"""


ROLLBACK_START = r"""if ours_conf; then
  systemctl disable --now "wg-quick@$IFACE" 2>/dev/null || true
  rm -f "$CONF"
  echo "stopped wg-quick@$IFACE and removed $CONF"
elif [ -e "$CONF" ]; then echo "skip: $CONF is not ours"
else echo "$CONF: absent"; fi
"""


def ping(address):
    return f"""for i in 1 2 3 4 5 6 7 8 9 10; do
  if ping -c 1 -W 2 {address} >/dev/null 2>&1; then
    echo "TN-FACT ping=ok"
    ping -c 3 -W 2 {address} | tail -n 2
    wg show "$IFACE" latest-handshakes
    return 0
  fi
  sleep 1
done
echo "TN-FACT ping=fail"
die "no answer from {address} through $IFACE"
"""


LEFTOVERS = r"""for p in "$CONF" "$KEY" "$KEYMARK" "/etc/systemd/system/multi-user.target.wants/wg-quick@$IFACE.service"; do
  if [ -e "$p" ]; then echo "TN-LEFT $p"; fi
done
if ip link show "$IFACE" >/dev/null 2>&1; then echo "TN-LEFT interface $IFACE"; fi
"""


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
        self.preludes_by_side = {side: prelude(ln, side) for side in self.ends}
        self.keys = {}

    # --- running -----------------------------------------------------------------------

    def _on(self, side, body, echo=True, check=True):
        return self.runner.run(self.ends[side], scripts.wrap(self.preludes_by_side[side], body),
                               privileged=True, echo=echo, check=check)

    def _check_body(self, side):
        i, r = self.line.tunnel_addresses
        return check(side, i if side == "initiator" else r,
                     self.line.responder_entry_ipv4 if side == "responder" else None)

    def _run_checks(self):
        for side in ("initiator", "responder"):
            self.out(f"    {self.ends[side]} ({side}):")
            self._on(side, self._check_body(side))

    def _run_keys(self):
        for side in ("initiator", "responder"):
            pub = self._on(side, KEYS).facts().get("pub", "")
            if len(pub) != 44:
                raise StepError(f"{self.ends[side]} did not return a WireGuard public key")
            self.keys[side] = pub
            self.out(f"    {self.ends[side]} public key {pub}")

    def _peer_key(self, side):
        other = "responder" if side == "initiator" else "initiator"
        if other not in self.keys:
            self._run_keys()
        return self.keys[other]

    def _run_responder(self):
        self._on("responder", start(conf(self.line, "responder", self._peer_key("responder"))))

    def _run_initiator(self):
        self._on("initiator", start(conf(self.line, "initiator", self._peer_key("initiator"))))

    def _run_ping(self):
        i, r = self.line.tunnel_addresses
        self.out(f"    {self.line.initiator} → {r}")
        self._on("initiator", ping(r))
        self.out(f"    {self.line.responder} → {i}")
        self._on("responder", ping(i))

    def check(self):
        """Read-only checks on both ends for the short plan: {"fails": [...]}."""
        fails = []
        for side in ("initiator", "responder"):
            result = self._on(side, self._check_body(side), echo=False, check=False)
            found = [f"{self.ends[side]}: {line.split('FAIL', 1)[1].strip()}" for line in result.output.splitlines()
                     if line.lstrip().startswith("FAIL ")]
            if result.rc != 0 and not found:
                last = result.output.strip().splitlines()[-1:] or ["no answer"]
                found = [f"{self.ends[side]}: cannot log in over SSH as root: {last[0]}"]
            fails += found
        return {"fails": fails}

    def run_rollback(self, step):
        if step.number == 2:
            for side in ("responder", "initiator"):
                self._on(side, ROLLBACK_KEYS)
        elif step.number == 3:
            self._on("responder", ROLLBACK_START)
        elif step.number == 4:
            self._on("initiator", ROLLBACK_START)

    def leftovers(self):
        left = []
        for side in ("initiator", "responder"):
            out = self._on(side, LEFTOVERS, echo=False).output
            left += [f"{self.ends[side]}: {line[len('TN-LEFT '):]}" for line in out.splitlines()
                     if line.startswith("TN-LEFT ")]
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
            self.out(f"\n✓ Nothing left on {self.line.initiator} or {self.line.responder}.")

    # --- the steps ------------------------------------------------------------------------

    def steps(self):
        ln = self.line
        ini, res = ln.initiator, ln.responder
        i_ip, r_ip = ln.tunnel_addresses
        both = f"{ini} and {res}"
        placeholder = "<the other end's public key, from step 2>"
        steps = [
            Step(1, "Check both ends",
                 [f"Root, wg and wg-quick, nothing named {ln.interface} that is not ours; on {res}: the entry",
                  f"address is there and udp/{ln.port} is free. Changes nothing."],
                 [Action(ini, "checks", self._check_body("initiator"), "initiator", True),
                  Action(res, "checks", self._check_body("responder"), "responder", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_checks,
                 host=both, brief="Check both ends"),
            Step(2, "Keys",
                 ["Make a WireGuard private key on each end (it never leaves the host); read the public keys."],
                 [Action(ini, "make the key", KEYS, "initiator", True), Action(res, "make the key", KEYS, "responder", True)],
                 rollback=ROLLBACK_KEYS, rollback_note="remove the key files on both ends, if ours",
                 run=self._run_keys, host=both, rollback_host=both,
                 brief="Make a private key on each end", undo_brief="remove both keys"),
            Step(3, "Responder",
                 [f"On {res}: {ln.interface} {r_ip}/30 listening on udp/{ln.port}; no endpoint, it only answers {ini}."],
                 [Action(res, "write the config and start", start(conf(ln, "responder", placeholder)), "responder", True)],
                 rollback=ROLLBACK_START, rollback_note=f"stop wg-quick@{ln.interface} and remove its config",
                 run=self._run_responder, host=res,
                 brief=f"Start {ln.interface} on {res} (waits for {ini})", undo_brief="stop it, remove the config"),
            Step(4, "Initiator",
                 [f"On {ini}: {ln.interface} {i_ip}/30, endpoint {ln.responder_entry_ipv4}:{ln.port}, "
                  f"keepalive {ln.keepalive_seconds} s."],
                 [Action(ini, "write the config and start", start(conf(ln, "initiator", placeholder)), "initiator", True)],
                 rollback=ROLLBACK_START, rollback_note=f"stop wg-quick@{ln.interface} and remove its config",
                 run=self._run_initiator, host=ini,
                 brief=f"Start {ln.interface} on {ini}, connect to {res}", undo_brief="stop it, remove the config"),
            Step(5, "Check the tunnel",
                 [f"{ini} pings {r_ip} and {res} pings {i_ip} through the tunnel. Read-only."],
                 [Action(ini, "ping", ping(r_ip), "initiator", True), Action(res, "ping", ping(i_ip), "responder", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_ping, host=both,
                 brief="Ping across the tunnel both ways"),
        ]
        return steps

    # --- printing --------------------------------------------------------------------------

    def summary_header(self, checks=None):
        ln = self.line
        i_ip, r_ip = ln.tunnel_addresses
        out = [
            f"line {ln.name}: {ln.initiator} → {ln.responder}"
            + (", one-way (only the initiator connects)" if ln.one_way else ""),
            f"  tunnel        {ln.interface}: {i_ip} ({ln.initiator}) ⇄ {r_ip} ({ln.responder})",
            f"  endpoint      {ln.initiator} connects to {ln.responder_entry_ipv4}:{ln.port}, keepalive {ln.keepalive_seconds} s",
            "  keys          made on each end; only public keys travel",
            f"  adds          {WG_DIR}/{ln.interface}.conf and .key, wg-quick@{ln.interface}, on both ends",
            "  leaves alone  existing tunnels, nft tables, routes, forwarding",
        ]
        if checks is None:
            out.append("  checks        not run (--offline)")
        elif checks["fails"]:
            out += ["", f"Not ready ({len(checks['fails'])}):"] + [f"  ✗ {f}" for f in checks["fails"]]
        else:
            out += ["", f"✓ Ready: every read-only check on {ln.initiator} and {ln.responder} passed."]
        return "\n".join(out)

    def header(self):
        return self.summary_header(checks=None).replace("  checks        not run (--offline)\n", "").rstrip()

    def preludes(self):
        return [(f"{self.line.initiator}, initiator", self.preludes_by_side["initiator"]),
                (f"{self.line.responder}, responder", self.preludes_by_side["responder"])]

    def plan_intro(self):
        return ("Every script runs as `bash -s` over SSH as root: the prelude of its end, then the step body\n"
                "inside `tn_step() { ... }` with stdin from /dev/null.")

    def rollback_footer(self):
        return "Nothing on this machine needs undoing."

    def done_message(self):
        i_ip, r_ip = self.line.tunnel_addresses
        return f"Line {self.line.name} is up: {self.line.initiator} {i_ip} ⇄ {r_ip} {self.line.responder}."

    def rolled_back_message(self):
        return f"Rolled back line {self.line.name}."

    def verify(self):
        return self.run_once(self._run_ping)
