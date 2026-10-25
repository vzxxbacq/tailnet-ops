"""The private site directory and its site.toml."""

import ipaddress
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import pins
from .privacy import CGNAT

DEFAULT_SITE_DIR = "~/.config/tailnet-ops"
SITE_FILE = "site.toml"
NOTES_FILE = "notes.md"

# Tailscale keeps these inside 100.64.0.0/10 for itself (MagicDNS 100.100.100.100, ChromeOS).
TAILSCALE_RESERVED = (
    ipaddress.IPv4Network("100.100.100.0/24"),
    ipaddress.IPv4Network("100.115.92.0/23"),
)

REGION_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,15}$")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
TAG_RE = re.compile(r"^tag:[a-z0-9][a-z0-9-]*$")
DNS_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class SiteError(Exception):
    """The site directory or site.toml is unusable. args[0] is a list of problems."""

    def __init__(self, problems):
        if isinstance(problems, str):
            problems = [problems]
        super().__init__(problems)
        self.problems = problems

    def __str__(self):
        return "\n".join(self.problems)


@dataclass
class Region:
    name: str
    control_host: str
    check_from: str
    public_ipv4: str
    listen_ipv4: str
    port: int
    stun_port: int
    ipv4_prefix: str
    avoid_prefixes: list
    base_domain: str
    derp_region_id: int
    derp_region_code: str
    derp_region_name: str
    official_derp: bool
    tags: list
    metrics_port: int = pins.DEFAULT_METRICS_PORT
    grpc_port: int = pins.DEFAULT_GRPC_PORT

    @property
    def specific_listen(self):
        return self.listen_ipv4 != "0.0.0.0"

    @property
    def local_ipv4(self):
        """Where the control host reaches its own Headscale."""
        return self.listen_ipv4 if self.specific_listen else "127.0.0.1"

    @property
    def server_url(self):
        return f"https://{self.public_ipv4}:{self.port}"

    @property
    def cert_ips(self):
        ips = [self.public_ipv4]
        if self.specific_listen and self.listen_ipv4 != self.public_ipv4:
            ips.append(self.listen_ipv4)
        return ips


@dataclass
class Line:
    name: str
    initiator: str
    responder: str
    responder_entry_ipv4: str
    initiator_public_ipv4: str
    one_way: bool
    keepalive_seconds: int
    priority: int
    port: int = None             # UDP port of the tunnel on the responder's entry address
    tunnel_ipv4: str = None      # a /30: .1 is the initiator's tunnel address, .2 the responder's

    @property
    def interface(self):
        return f"wg-{self.name}"[:15]

    @property
    def tunnel_addresses(self):
        """(initiator, responder) tunnel addresses."""
        hosts = list(ipaddress.IPv4Network(self.tunnel_ipv4).hosts())
        return str(hosts[0]), str(hosts[1])


@dataclass
class HostSettings:
    """Optional per-host settings, used when the host joins its tailnet."""

    name: str
    tailscale_port: int = None   # fixed UDP port for tailscaled (--port)
    netfilter_mode: str = None   # tailscale up --netfilter-mode
    region: str = None           # needed only for hosts that are no region's control or checker host
    tags: list = None            # default: see Site.host_tags


@dataclass
class Site:
    name: str
    owner_user: str
    regions: dict
    lines: list = field(default_factory=list)
    host_settings: dict = field(default_factory=dict)
    directory: Path = None

    def region(self, name):
        if name not in self.regions:
            known = ", ".join(self.regions) or "none"
            raise SiteError(f"unknown region {name!r} (site has: {known})")
        return self.regions[name]

    def hosts(self):
        """Every SSH alias the site names, in a stable order."""
        seen = []
        for r in self.regions.values():
            for h in (r.control_host, r.check_from):
                if h not in seen:
                    seen.append(h)
        for line in self.lines:
            for h in (line.initiator, line.responder):
                if h not in seen:
                    seen.append(h)
        for h in self.host_settings:
            if h not in seen:
                seen.append(h)
        return seen

    def host_region(self, alias):
        """The region a host joins: [hosts.<alias>] region, else the region it controls or checks."""
        h = self.host_settings.get(alias)
        if h and h.region:
            return self.regions[h.region]
        found = [r for r in self.regions.values() if alias in (r.control_host, r.check_from)]
        if len(found) == 1:
            return found[0]
        if not found:
            raise SiteError(f"{alias}: not in any region; add [hosts.{alias}] region = \"<region>\" to site.toml")
        raise SiteError(f"{alias}: in regions {', '.join(r.name for r in found)}; "
                        f"choose one with [hosts.{alias}] region")

    def host_tags(self, alias):
        """[hosts.<alias>] tags, else the region's -server tag plus -gateway for a line
        initiator and -border for a line responder."""
        h = self.host_settings.get(alias)
        if h and h.tags:
            return list(h.tags)
        region = self.host_region(alias)
        suffixes = {"-server"}
        suffixes |= {"-gateway" for ln in self.lines if ln.initiator == alias}
        suffixes |= {"-border" for ln in self.lines if ln.responder == alias}
        return [t for t in region.tags if any(t.endswith(s) for s in suffixes)]

    @property
    def pki_dir(self):
        return self.directory / "pki"

    @property
    def cache_dir(self):
        return self.directory / "cache"

    @property
    def runs_dir(self):
        return self.directory / "runs"


# --- the directory -------------------------------------------------------------


def resolve_dir(arg=None, environ=None):
    environ = os.environ if environ is None else environ
    raw = arg or environ.get("TN_SITE") or DEFAULT_SITE_DIR
    return Path(raw).expanduser().absolute()


def git_work_tree(path):
    """Return the work tree that contains path, or None."""
    p = Path(path).absolute()
    for candidate in (p, *p.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def check_dir(path):
    """Problems with the site directory: location and permissions."""
    path = Path(path)
    if not path.is_dir():
        return [f"site directory {path} does not exist (run `tn init`, or pass --site DIR)"]
    problems = []
    tree = git_work_tree(path)
    if tree is not None:
        problems.append(f"site directory {path} sits inside the Git work tree {tree}; move it out")
    loose = []
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            p = Path(root) / name
            mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                continue
            if mode & 0o077:
                loose.append(p)
    if path.stat().st_mode & 0o077:
        loose.insert(0, path)
    for p in loose:
        want = "0700" if p.is_dir() else "0600"
        problems.append(f"{p} is readable by others; run: chmod {want} {p}")
    return problems


def ensure_private_dir(path):
    """Create a directory inside the site directory with mode 0700."""
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_private(path, data, mode=0o600):
    """Write a file that only the operator can read."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    os.chmod(path, mode)
    return path


# --- site.toml -------------------------------------------------------------------

SITE_KEYS = {"name": str, "owner_user": str}
REGION_KEYS = {
    "control_host": str,
    "check_from": str,
    "public_ipv4": str,
    "listen_ipv4": str,
    "port": int,
    "stun_port": int,
    "ipv4_prefix": str,
    "avoid_prefixes": list,
    "base_domain": str,
    "derp_region_id": int,
    "derp_region_code": str,
    "derp_region_name": str,
    "official_derp": bool,
    "tags": list,
}
REGION_OPTIONAL = {"metrics_port": int, "grpc_port": int}
HOST_KEYS = {"tailscale_port": int, "netfilter_mode": str, "region": str, "tags": list}
NETFILTER_MODES = ("on", "nodivert", "off")
LINE_OPTIONAL = {"port": int, "tunnel_ipv4": str}
LINE_KEYS = {
    "name": str,
    "initiator": str,
    "responder": str,
    "responder_entry_ipv4": str,
    "initiator_public_ipv4": str,
    "one_way": bool,
    "keepalive_seconds": int,
    "priority": int,
}


def _typed(where, table, required, optional, problems):
    out = {}
    for key, typ in {**required, **optional}.items():
        if key not in table:
            if key in required:
                problems.append(f"{where}: missing {key}")
            continue
        value = table[key]
        # bool is an int in Python; keep them apart.
        if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
            problems.append(f"{where}.{key}: expected {typ.__name__}, got {type(value).__name__}")
            continue
        out[key] = value
    for key in table:
        if key not in required and key not in optional:
            problems.append(f"{where}: unknown key {key}")
    return out


def _ipv4(where, value, problems):
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        problems.append(f"{where}: {value!r} is not an IPv4 address")
        return None


def _net(where, value, problems):
    try:
        return ipaddress.IPv4Network(value)
    except ValueError:
        problems.append(f"{where}: {value!r} is not an IPv4 prefix (use the network address, e.g. 100.64.0.0/16)")
        return None


def _port(where, value, problems):
    if not 1 <= value <= 65535:
        problems.append(f"{where}: {value} is not a port")


def parse(data, known_host=None, directory=None):
    """Build a Site from parsed TOML. Raises SiteError listing every problem.

    known_host(alias) tells whether an alias outside the regions exists (SSH config);
    lines may only name hosts that exist.
    """
    problems = []
    for key in data:
        if key not in ("site", "regions", "hosts", "lines"):
            problems.append(f"unknown table [{key}]")

    site_table = data.get("site")
    if not isinstance(site_table, dict):
        problems.append("missing [site]")
        site_table = {}
    s = _typed("site", site_table, SITE_KEYS, {}, problems)
    if "owner_user" in s and not USER_RE.match(s["owner_user"]):
        problems.append(f"site.owner_user: {s['owner_user']!r} is not a valid Headscale user name")

    regions = {}
    raw_regions = data.get("regions")
    if not isinstance(raw_regions, dict) or not raw_regions:
        problems.append("no [regions.<name>] tables")
        raw_regions = {}
    for name, table in raw_regions.items():
        where = f"regions.{name}"
        if not REGION_NAME_RE.match(name):
            problems.append(f"{where}: region names use a-z, 0-9 and '-', start with a letter, at most 16 characters")
        if not isinstance(table, dict):
            problems.append(f"{where}: not a table")
            continue
        r = _typed(where, table, REGION_KEYS, REGION_OPTIONAL, problems)
        if len(r) < len(REGION_KEYS):
            continue
        for key in ("control_host", "check_from"):
            if not HOST_RE.match(r[key]):
                problems.append(f"{where}.{key}: {r[key]!r} is not an SSH alias")
        pub = _ipv4(f"{where}.public_ipv4", r["public_ipv4"], problems)
        if pub is not None and (pub.is_unspecified or pub.is_loopback):
            problems.append(f"{where}.public_ipv4: clients cannot reach {pub}")
        _ipv4(f"{where}.listen_ipv4", r["listen_ipv4"], problems)
        for key in ("port", "stun_port", "metrics_port", "grpc_port"):
            if key in r:
                _port(f"{where}.{key}", r[key], problems)
        tcp_ports = [r["port"], r.get("metrics_port", pins.DEFAULT_METRICS_PORT), r.get("grpc_port", pins.DEFAULT_GRPC_PORT)]
        if len(set(tcp_ports)) != len(tcp_ports):
            problems.append(f"{where}: port, metrics_port and grpc_port must differ")
        if not DNS_RE.match(r["base_domain"]):
            problems.append(f"{where}.base_domain: {r['base_domain']!r} is not a DNS name")
        if not 900 <= r["derp_region_id"] <= 999:
            problems.append(f"{where}.derp_region_id: use 900-999 for self-hosted DERP regions")
        if not r["derp_region_code"] or not r["derp_region_name"]:
            problems.append(f"{where}: derp_region_code and derp_region_name must not be empty")
        if not r["tags"]:
            problems.append(f"{where}.tags: needs at least one tag")
        for tag in r["tags"]:
            if not isinstance(tag, str) or not TAG_RE.match(tag):
                problems.append(f"{where}.tags: {tag!r} is not a tag like tag:{name}-server")
        if not all(isinstance(p, str) for p in r["avoid_prefixes"]):
            problems.append(f"{where}.avoid_prefixes: must be a list of prefixes")
        regions[name] = Region(name=name, **r)

    # Prefixes, region ids and names across regions.
    nets = {}
    for name, r in regions.items():
        where = f"regions.{name}"
        net = _net(f"{where}.ipv4_prefix", r.ipv4_prefix, problems)
        if net is None:
            continue
        if not net.subnet_of(CGNAT):
            problems.append(f"{where}.ipv4_prefix: {net} is not inside {CGNAT}")
        for reserved in TAILSCALE_RESERVED:
            if net.overlaps(reserved):
                problems.append(f"{where}.ipv4_prefix: {net} overlaps {reserved}, which Tailscale reserves")
        for avoid in r.avoid_prefixes:
            if not isinstance(avoid, str):
                continue
            a = _net(f"{where}.avoid_prefixes", avoid, problems)
            if a is not None and net.overlaps(a):
                problems.append(f"{where}.ipv4_prefix: {net} overlaps avoid_prefixes entry {a}")
        for other, other_net in nets.items():
            if net.overlaps(other_net):
                problems.append(f"{where}.ipv4_prefix: {net} overlaps region {other} ({other_net})")
        nets[name] = net

    def distinct(attr, label):
        seen = {}
        for name, r in regions.items():
            value = getattr(r, attr)
            if value in seen:
                problems.append(f"regions.{name}.{attr}: {label} {value!r} is also used by region {seen[value]}")
            else:
                seen[value] = name

    distinct("derp_region_id", "region id")
    distinct("derp_region_code", "region code")
    distinct("base_domain", "base domain")
    distinct("control_host", "control host")
    for name, r in regions.items():
        for other, o in regions.items():
            if other != name and r.base_domain.endswith("." + o.base_domain):
                problems.append(f"regions.{name}.base_domain: {r.base_domain} sits inside region {other}'s domain")

    site_hosts = {h for r in regions.values() for h in (r.control_host, r.check_from)}
    lines = []
    raw_lines = data.get("lines", [])
    if not isinstance(raw_lines, list):
        problems.append("lines: use [[lines]] tables")
        raw_lines = []
    names = set()
    for i, table in enumerate(raw_lines, 1):
        where = f"lines[{i}]"
        if not isinstance(table, dict):
            problems.append(f"{where}: not a table")
            continue
        ln = _typed(where, table, LINE_KEYS, LINE_OPTIONAL, problems)
        if len(ln) < len(LINE_KEYS):
            continue
        where = f"lines.{ln['name']}"
        if ln["name"] in names:
            problems.append(f"{where}: duplicate line name")
        names.add(ln["name"])
        for key in ("initiator", "responder"):
            host = ln[key]
            if host in site_hosts:
                continue
            if not HOST_RE.match(host) or known_host is None or not known_host(host):
                problems.append(f"{where}.{key}: {host!r} is neither a region host nor an SSH alias")
        if ln["initiator"] == ln["responder"]:
            problems.append(f"{where}: initiator and responder must differ")
        _ipv4(f"{where}.responder_entry_ipv4", ln["responder_entry_ipv4"], problems)
        _ipv4(f"{where}.initiator_public_ipv4", ln["initiator_public_ipv4"], problems)
        if "port" in ln:
            _port(f"{where}.port", ln["port"], problems)
        if "tunnel_ipv4" in ln:
            net = _net(f"{where}.tunnel_ipv4", ln["tunnel_ipv4"], problems)
            if net is not None:
                if net.prefixlen != 30:
                    problems.append(f"{where}.tunnel_ipv4: use a /30: the initiator takes .1, the responder .2")
                if not net.is_private or net.overlaps(CGNAT):
                    problems.append(f"{where}.tunnel_ipv4: use a private range outside 100.64.0.0/10")
                for other in lines:
                    if other.tunnel_ipv4 and net.overlaps(ipaddress.IPv4Network(other.tunnel_ipv4)):
                        problems.append(f"{where}.tunnel_ipv4: overlaps line {other.name}")
        if not 1 <= ln["keepalive_seconds"] <= 3600:
            problems.append(f"{where}.keepalive_seconds: use 1-3600")
        lines.append(Line(**ln))

    named = site_hosts | {h for ln in lines for h in (ln.initiator, ln.responder)}
    host_settings = {}
    raw_hosts = data.get("hosts", {})
    if not isinstance(raw_hosts, dict):
        problems.append("hosts: use [hosts.<alias>] tables")
        raw_hosts = {}
    for alias, table in raw_hosts.items():
        where = f"hosts.{alias}"
        if not isinstance(table, dict):
            problems.append(f"{where}: not a table")
            continue
        h = _typed(where, table, {}, HOST_KEYS, problems)
        if alias not in named and (not HOST_RE.match(alias) or known_host is None or not known_host(alias)):
            problems.append(f"{where}: {alias!r} is neither a site host nor an SSH alias")
        port = h.get("tailscale_port")
        if port is not None:
            _port(f"{where}.tailscale_port", port, problems)
            for r in regions.values():
                if r.control_host == alias and r.stun_port == port:
                    problems.append(f"{where}.tailscale_port: {port} is region {r.name}'s STUN port on this host (both UDP)")
        mode = h.get("netfilter_mode")
        if mode is not None and mode not in NETFILTER_MODES:
            problems.append(f"{where}.netfilter_mode: use one of {', '.join(NETFILTER_MODES)}")
        region_name = h.get("region")
        if region_name is not None and region_name not in regions:
            problems.append(f"{where}.region: no region {region_name!r}")
        tags = h.get("tags")
        if tags is not None:
            home = regions.get(region_name) or next(
                (r for r in regions.values() if alias in (r.control_host, r.check_from)), None)
            allowed = home.tags if home else []
            for tag in tags:
                if not isinstance(tag, str) or tag not in allowed:
                    problems.append(f"{where}.tags: {tag!r} is not a tag of the host's region")
        host_settings[alias] = HostSettings(name=alias, **h)

    if problems:
        raise SiteError(problems)
    return Site(name=s["name"], owner_user=s["owner_user"], regions=regions, lines=lines,
                host_settings=host_settings, directory=directory)


def read_toml(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise SiteError(f"{path} does not exist (run `tn init`)") from None
    except tomllib.TOMLDecodeError as e:
        raise SiteError(f"{path}: {e}") from None


def load(directory, known_host=None, check_permissions=True):
    """Load and validate <directory>/site.toml."""
    directory = Path(directory)
    if check_permissions:
        problems = check_dir(directory)
        if problems:
            raise SiteError(problems)
    data = read_toml(directory / SITE_FILE)
    return parse(data, known_host=known_host, directory=directory)
