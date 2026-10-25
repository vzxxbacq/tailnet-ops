"""`tn init`: ask only what SSH cannot tell, derive the rest, write site.toml."""

import ipaddress
import json
import re
from dataclasses import dataclass, field

from . import pins
from .privacy import CGNAT
from .site import HOST_RE, REGION_NAME_RE, TAILSCALE_RESERVED, USER_RE

# Read-only. Runs as the SSH login user.
FACTS_SCRIPT = r"""set -u
echo "uid=$(id -u)"
if [ "$(id -u)" = 0 ]; then echo root=yes; elif sudo -n true 2>/dev/null; then echo root=sudo; else echo root=no; fi
echo "os=$( (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null || echo unknown)"
echo "arch=$(uname -m)"
if [ -d /run/systemd/system ]; then echo systemd=yes; else echo systemd=no; fi
for c in bash curl openssl python3 ss ip; do
  if command -v "$c" >/dev/null; then echo "tool=$c"; fi
done
ss -H -ltnp 2>/dev/null | awk '{print "listen=tcp " $4 " " $6}'
ss -H -lunp 2>/dev/null | awk '{print "listen=udp " $4 " " $6}'
ip -4 -o addr show 2>/dev/null | awk '{print "addr=" $2 " " $4}'
ip -4 route get 192.0.2.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print "src=" $(i + 1)}'
for f in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
  if [ -r "$f" ]; then awk '$1 == "nameserver" {print "resolver=" $2}' "$f"; fi
done
"""


@dataclass
class HostFacts:
    uid: int = -1
    root: str = "no"
    os: str = "unknown"
    arch: str = "unknown"
    systemd: bool = False
    tools: set = field(default_factory=set)
    listens: list = field(default_factory=list)   # (proto, ip, port, owner)
    addrs: list = field(default_factory=list)     # (iface, ip, prefixlen)
    src: str = None
    resolvers: list = field(default_factory=list)

    def port_busy(self, proto, port, ours=()):
        """True when something other than `ours` (process names) listens on the port."""
        return any(p == proto and pt == port and o not in ours for p, _ip, pt, o in self.listens)

    def owners(self, proto, port):
        return sorted({o for p, _ip, pt, o in self.listens if p == proto and pt == port and o})

    def has_ipv4(self, ip):
        return any(a == ip for _i, a, _p in self.addrs)

    def cgnat_resolvers(self):
        out = []
        for r in self.resolvers:
            try:
                a = ipaddress.IPv4Address(r)
            except ValueError:
                continue
            if a in CGNAT and r not in out:
                out.append(r)
        return out


def parse_facts(text):
    f = HostFacts()
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key == "uid":
            f.uid = int(value) if value.isdigit() else -1
        elif key == "root":
            f.root = value
        elif key == "os":
            f.os = value
        elif key == "arch":
            f.arch = value
        elif key == "systemd":
            f.systemd = value == "yes"
        elif key == "tool":
            f.tools.add(value)
        elif key == "listen":
            parts = value.split()
            if len(parts) < 2:
                continue
            proto, local = parts[0], parts[1]
            host, _, port = local.rpartition(":")
            host = host.split("%")[0].strip("[]")
            m = re.search(r'users:\(\("([^"]+)"', parts[2]) if len(parts) > 2 else None
            if port.isdigit():
                f.listens.append((proto, host, int(port), m.group(1) if m else ""))
        elif key == "addr":
            parts = value.split()
            if len(parts) == 2 and "/" in parts[1]:
                ip, _, plen = parts[1].partition("/")
                f.addrs.append((parts[0], ip, int(plen)))
        elif key == "src":
            f.src = value
        elif key == "resolver":
            if value not in f.resolvers:
                f.resolvers.append(value)
    return f


# --- questions ---------------------------------------------------------------------


class Asker:
    def __init__(self, input_fn=None, out=print):
        self.input = input_fn or (lambda prompt: input(prompt))
        self.out = out

    def ask(self, prompt, default=None, check=None, allow_empty=False):
        suffix = f" [{default}]" if default not in (None, "") else ""
        for _ in range(3):
            try:
                answer = self.input(f"{prompt}{suffix}: ").strip()
            except EOFError:
                answer = ""
            if not answer and default is not None:
                answer = default
            if not answer and allow_empty:
                return ""
            problem = check(answer) if check else (None if answer else "an answer is needed")
            if problem is None:
                return answer
            self.out(f"  {problem}")
        raise ValueError(f"no valid answer for: {prompt}")

    def yes_no(self, prompt, default):
        answer = self.ask(prompt, "y" if default else "n", _check_yes_no)
        return answer.lower().startswith("y")


def _check_yes_no(a):
    return None if a.lower() in ("y", "yes", "n", "no") else "answer y or n"


def _check_alias(a):
    return None if HOST_RE.match(a) else "use an SSH alias from ~/.ssh/config"


def _check_region(a):
    return None if REGION_NAME_RE.match(a) else "use a-z, 0-9 and '-', starting with a letter (e.g. cn, eu)"


def _check_user(a):
    return None if USER_RE.match(a) else "use lower-case letters, digits, '.', '_' or '-'"


def _check_ipv4(a):
    try:
        ipaddress.IPv4Address(a)
    except ValueError:
        return "enter an IPv4 address"
    return None


def ask_answers(asker):
    """The few things SSH cannot tell."""
    a = {"regions": [], "lines": []}
    a["site"] = asker.ask("Site name", "home", lambda v: None if re.match(r"^[A-Za-z0-9 ._-]{1,40}$", v) else "letters, digits, ' ', '.', '_' or '-'")
    a["owner_user"] = asker.ask("Headscale user that owns the tags", "owner", _check_user)
    while True:
        n = len(a["regions"]) + 1
        name = asker.ask(f"Region {n} name (empty to finish)" if n > 1 else "Region 1 name (e.g. cn)",
                         None, lambda v: _check_region(v), allow_empty=n > 1)
        if not name:
            break
        a["regions"].append({
            "name": name,
            "control_host": asker.ask(f"  {name}: control host (SSH alias)", None, _check_alias),
            "check_from": asker.ask(f"  {name}: checker host in the same region (SSH alias)", None, _check_alias),
            "official_derp": asker.yes_no(f"  {name}: also use Tailscale's official DERP relays as a fallback?", False),
            "ipv4_prefix": asker.ask(
                f"  {name}: tailnet IPv4 prefix inside 100.64.0.0/10 (empty to pick a free /24)",
                None, _check_prefix, allow_empty=True),
            "ports": parse_ports(asker.ask(
                f"  {name}: ports the provider lets in to the control host, used in order for HTTPS, STUN and "
                "Tailscale (e.g. 20000-20002; empty if any port can be opened)",
                None, _check_ports, allow_empty=True)),
        })
    while True:
        n = len(a["lines"]) + 1
        name = asker.ask(f"Line {n} name (empty for {'no more' if n > 1 else 'no'} lines)", None,
                         lambda v: None if HOST_RE.match(v) else "letters, digits, '.', '_' or '-'", allow_empty=True)
        if not name:
            break
        a["lines"].append({
            "name": name,
            "initiator": asker.ask(f"  {name}: initiator, the side that starts connections (SSH alias)", None, _check_alias),
            "responder": asker.ask(f"  {name}: responder (SSH alias)", None, _check_alias),
            "responder_entry_ipv4": asker.ask(f"  {name}: responder's entry address for this line", None, _check_ipv4),
            "one_way": asker.yes_no(f"  {name}: one-way (only the initiator may start connections)?", True),
            "port": int(asker.ask(f"  {name}: UDP port the line passes to the entry, for the tunnel", None,
                                  lambda v: None if v.isdigit() and 1 <= int(v) <= 65535 else "enter a port number")),
        })
    return a


def parse_ports(text):
    """'20000-20002' or '9443, 3478' -> a list of ports, in the given order."""
    out = []
    for item in filter(None, (part.strip() for part in text.split(","))):
        low, _, high = item.partition("-")
        for port in range(int(low), int(high or low) + 1):
            if port not in out:
                out.append(port)
    return out


def _check_prefix(text):
    try:
        net = ipaddress.IPv4Network(text)
    except ValueError:
        return "enter a prefix like 100.64.10.0/24 (the network address, then /length)"
    if not net.subnet_of(CGNAT):
        return "Tailscale clients only work with addresses inside 100.64.0.0/10"
    return None


def _check_ports(text):
    try:
        ports = parse_ports(text)
    except ValueError:
        ports = None
    if ports is None or not all(1 <= p <= 65535 for p in ports) or (text.strip() and len(ports) < 2):
        return "list at least two ports, e.g. 20000-20002 or 9443,3478"
    return None


def _pick_ports(facts, allowed):
    """Take allowed ports in order for HTTPS (tcp), STUN (udp) and Tailscale (udp), skipping busy ones."""
    pool, picks = list(allowed), []
    for proto, ours in (("tcp", ("headscale",)), ("udp", ("headscale",)), ("udp", ("tailscaled",))):
        while pool and facts.port_busy(proto, pool[0], ours):
            pool.pop(0)
        picks.append(pool.pop(0) if pool else None)
    return picks


def hosts_in(answers):
    seen = []
    for r in answers["regions"]:
        for h in (r["control_host"], r["check_from"]):
            if h not in seen:
                seen.append(h)
    for ln in answers["lines"]:
        for h in (ln["initiator"], ln["responder"]):
            if h not in seen:
                seen.append(h)
    return seen


# --- derivation ---------------------------------------------------------------------


def _free_port(facts, proto, preferred, taken=(), ours=("headscale",)):
    port = preferred
    while facts.port_busy(proto, port, ours) or port in taken:
        port += 1
    return port


def _allocate_prefix(avoid, used):
    # 100.64.0.0/24 is skipped: its default alias (10.255.0.0/24) would hold the default tunnels.
    blocked = [ipaddress.IPv4Network(p) for p in avoid] + list(used) + list(TAILSCALE_RESERVED) + [
        ipaddress.IPv4Network("100.64.0.0/24")]
    for net in CGNAT.subnets(new_prefix=24):
        if not any(net.overlaps(b) for b in blocked):
            return net
    raise ValueError("no free /16 left inside 100.64.0.0/10")


def derive(answers, facts, hostnames):
    """Build site.toml data from answers plus SSH facts.

    facts: alias -> HostFacts; hostnames: alias -> IPv4 from `ssh -G`, or None.
    Returns (data, notes, comments) where comments maps (table, key) -> text.
    """
    notes, comments = [], {}
    data = {"site": {"name": answers["site"], "owner_user": answers["owner_user"]}, "regions": {}}
    used = []
    host_ports = {}
    initiators = {ln["initiator"] for ln in answers["lines"]}
    responders = {ln["responder"] for ln in answers["lines"]}
    for i, ra in enumerate(answers["regions"]):
        name, host = ra["name"], ra["control_host"]
        table = f"regions.{name}"
        f = facts[host]
        public = ra.get("public_ipv4") or hostnames.get(host)
        if public is None:
            raise ValueError(f"{host}: HostName is not an IPv4 address; answer its public address")
        comments[(table, "public_ipv4")] = f"from ssh -G {host}"
        if f.has_ipv4(public):
            listen = public
            others = [a for _i, a, _p in f.addrs if a != public and not a.startswith("127.")]
            comments[(table, "listen_ipv4")] = "the public address is on an interface; bind only it" + (
                f" (the host has {len(others)} other IPv4 address{'es' if len(others) > 1 else ''})" if others else "")
        else:
            listen = "0.0.0.0"
            comments[(table, "listen_ipv4")] = "the public address is not on an interface (1:1 NAT)"
        allowed = ra.get("ports") or []
        tailscale_port = None
        if allowed:
            port, stun, tailscale_port = _pick_ports(f, allowed)
            if port is None or stun is None:
                raise ValueError(f"{host}: the allowed ports leave none free for HTTPS and STUN")
            comments[(table, "port")] = f"the provider lets in only {_describe_ports(allowed)}"
            if tailscale_port is None:
                notes.append(f"{host}: no third allowed port is free for Tailscale, so direct connections to it "
                             "are less likely once it joins")
        else:
            port = _free_port(f, "tcp", pins.DEFAULT_PORT)
            stun = _free_port(f, "udp", pins.DEFAULT_STUN_PORT)
            for label, want, got in (("port", pins.DEFAULT_PORT, port), ("stun_port", pins.DEFAULT_STUN_PORT, stun)):
                if want != got:
                    comments[(table, label)] = f"{want} is in use on {host}"
        metrics = _free_port(f, "tcp", pins.DEFAULT_METRICS_PORT, taken=(port,))
        grpc = _free_port(f, "tcp", pins.DEFAULT_GRPC_PORT, taken=(port, metrics))
        if tailscale_port is not None:
            host_ports[host] = tailscale_port
        cgnat = f.cgnat_resolvers()
        avoid = sorted({str(ipaddress.IPv4Network(f"{r}/16", strict=False)) for r in cgnat})
        if cgnat:
            comments[(table, "avoid_prefixes")] = f"resolvers inside 100.64.0.0/10: {', '.join(cgnat)}"
            notes.append(f"{host}: its resolvers ({', '.join(cgnat)}) sit inside 100.64.0.0/10. The prefix avoids "
                         f"{', '.join(avoid)}, and [hosts.{host}] gets netfilter_mode = \"off\" for when it joins.")
        if ra.get("ipv4_prefix"):
            prefix = ipaddress.IPv4Network(ra["ipv4_prefix"])
            comments[(table, "ipv4_prefix")] = "chosen; one /24 per tailnet"
        else:
            prefix = _allocate_prefix(avoid, used)
        used.append(prefix)
        tags = [f"tag:{name}-server"]
        if host in initiators:
            tags.append(f"tag:{name}-gateway")
        if host in responders:
            tags.append(f"tag:{name}-border")
        region = {
            "control_host": host,
            "check_from": ra["check_from"],
            "public_ipv4": public,
            "listen_ipv4": listen,
            "port": port,
            "stun_port": stun,
            "ipv4_prefix": str(prefix),
            "avoid_prefixes": avoid,
            "base_domain": f"{name}.tailnet.internal",
            "derp_region_id": 901 + i,
            "derp_region_code": name,
            "derp_region_name": f"{name.upper()} {host}",
            "official_derp": bool(ra["official_derp"]),
            "tags": tags,
        }
        if metrics != pins.DEFAULT_METRICS_PORT:
            region["metrics_port"] = metrics
        if grpc != pins.DEFAULT_GRPC_PORT:
            region["grpc_port"] = grpc
        data["regions"][name] = region
        for problem in control_host_problems(host, f):
            notes.append(problem)
        for problem in checker_problems(ra["check_from"], facts[ra["check_from"]]):
            notes.append(problem)

    lines = []
    for i, la in enumerate(answers["lines"], 1):
        initiator_ip = la.get("initiator_public_ipv4") or hostnames.get(la["initiator"])
        if initiator_ip is None:
            raise ValueError(f"{la['initiator']}: HostName is not an IPv4 address; answer its public address")
        table = f"lines.{la['name']}"
        comments[(table, "initiator_public_ipv4")] = f"from ssh -G {la['initiator']}"
        responder = facts.get(la["responder"])
        if responder is not None:
            if responder.has_ipv4(la["responder_entry_ipv4"]):
                comments[(table, "responder_entry_ipv4")] = f"on an interface of {la['responder']}"
            else:
                notes.append(f"line {la['name']}: {la['responder_entry_ipv4']} is not on any interface of {la['responder']}")
            if responder.src == la["responder_entry_ipv4"]:
                notes.append(f"line {la['name']}: the entry address is {la['responder']}'s default source address; "
                             "milestone 2 moves it into its own namespace, so plan a maintenance window")
        lines.append({
            "name": la["name"],
            "initiator": la["initiator"],
            "responder": la["responder"],
            "responder_entry_ipv4": la["responder_entry_ipv4"],
            "initiator_public_ipv4": initiator_ip,
            "one_way": bool(la["one_way"]),
            "keepalive_seconds": 25,
            "priority": 10 * i,
            "port": la["port"],
            "tunnel_ipv4": f"10.255.{i - 1}.0/30",
        })
    hosts = {}
    for alias in hosts_in(answers):
        f = facts.get(alias)
        if f is not None and f.cgnat_resolvers():
            hosts.setdefault(alias, {})["netfilter_mode"] = "off"
            comments[(f"hosts.{alias}", "netfilter_mode")] = "its resolvers sit inside 100.64.0.0/10"
    for alias, port in host_ports.items():
        hosts.setdefault(alias, {})["tailscale_port"] = port
        comments[(f"hosts.{alias}", "tailscale_port")] = "UDP for tailscaled --port, the next allowed port"
    if hosts:
        data["hosts"] = hosts
    if lines:
        data["lines"] = lines
    return data, notes, comments


def _describe_ports(ports):
    if ports == list(range(ports[0], ports[-1] + 1)) and len(ports) > 2:
        return f"{ports[0]}-{ports[-1]}"
    return ", ".join(str(p) for p in ports)


def control_host_problems(host, f):
    out = []
    if f.root == "no":
        out.append(f"{host}: needs root or passwordless sudo")
    if not f.systemd:
        out.append(f"{host}: systemd is not running")
    if f.arch not in ("x86_64", "aarch64", "arm64"):
        out.append(f"{host}: arch {f.arch} has no pinned Headscale build")
    for tool in ("curl", "openssl", "ss", "ip"):
        if tool not in f.tools:
            out.append(f"{host}: {tool} is missing")
    return out


def checker_problems(host, f):
    return [f"{host}: {tool} is missing (the checks need it)" for tool in ("bash", "curl", "python3") if tool not in f.tools]


def describe(alias, f, hostname):
    root = {"yes": "root", "sudo": "sudo"}.get(f.root, "no root")
    head = f"{alias}: {f.os} · {f.arch} · {root} · {'systemd' if f.systemd else 'no systemd'}"
    addrs = ", ".join(f"{a}/{p} ({i})" for i, a, p in f.addrs if not a.startswith("127."))
    out = [head, f"    ssh HostName {hostname or 'is a name'} · IPv4 {addrs or 'none'}" + (f" · default source {f.src}" if f.src else "")]
    if f.resolvers:
        out.append(f"    resolvers {', '.join(f.resolvers)}")
    return out


# --- writing and comparing ---------------------------------------------------------


def _toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps(v)


def to_toml(data, comments=None, today=None):
    comments = comments or {}
    out = [
        "# tailnet-ops site configuration. Private: keep it out of every repository.",
        "# Schema: examples/site.example.toml in the tailnet-ops repository."
        + (f" Written by `tn init` on {today}." if today else ""),
        "",
    ]

    def table(name, values, key_table=None):
        out.append(f"[{name}]" if not name.startswith("[[") else name)
        key_table = key_table or name.strip("[]")
        if name.startswith("[["):
            key_table = f"lines.{values['name']}"
        width = max(len(k) for k in values)
        for k, v in values.items():
            line = f"{k.ljust(width)} = {_toml_value(v)}"
            note = comments.get((key_table, k))
            out.append(f"{line}  # {note}" if note else line)
        out.append("")

    table("site", data["site"])
    for name, r in data["regions"].items():
        table(f"regions.{name}", r)
    for alias, h in data.get("hosts", {}).items():
        key = alias if re.match(r"^[A-Za-z0-9_-]+$", alias) else json.dumps(alias)
        table(f"hosts.{key}", h, key_table=f"hosts.{alias}")
    for ln in data.get("lines", []):
        table("[[lines]]", ln)
    return "\n".join(out)


def _brief(v):
    if isinstance(v, dict):
        return "table"
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return f"{len(v)} table{'s' if len(v) > 1 else ''}"
    return _toml_value(v)


def differences(existing, derived, path=""):
    """Human-readable differences between two site.toml dicts."""
    out = []
    if isinstance(existing, dict) and isinstance(derived, dict):
        for k in list(existing) + [k for k in derived if k not in existing]:
            p = f"{path}.{k}" if path else k
            if k not in derived:
                out.append(f"{p}: only in site.toml ({_brief(existing[k])})")
            elif k not in existing:
                out.append(f"{p}: only in the rebuilt file ({_brief(derived[k])})")
            else:
                out += differences(existing[k], derived[k], p)
    elif isinstance(existing, list) and isinstance(derived, list) and existing and isinstance(existing[0], dict):
        for i in range(max(len(existing), len(derived))):
            p = f"{path}[{i + 1}]"
            if i >= len(derived):
                out.append(f"{p}: only in site.toml")
            elif i >= len(existing):
                out.append(f"{p}: only in the rebuilt file")
            else:
                out += differences(existing[i], derived[i], p)
    elif existing != derived:
        out.append(f"{path}: site.toml has {_toml_value(existing)}, rebuilt {_toml_value(derived)}")
    return out
