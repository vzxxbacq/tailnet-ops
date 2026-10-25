"""Which machine joins, and how.

site.toml names only the hosts that others use: control hosts, checkers and the ends of lines.
Any other machine, server or personal device, joins from command-line options or the questions
of `tn join`, and tn records how in <site>/joined.json so verify and rollback need nothing again.
"""

import platform
from dataclasses import asdict, dataclass

from . import pins
from .site import NETFILTER_MODES, SiteError, dns_label, write_joined

ROLES = ("server", "personal")
OSES = ("linux", "macos")


@dataclass
class Target:
    name: str                    # its name in the tailnet: <name>.<region>.<suffix>
    ssh: str = None              # SSH alias; None = the machine that runs tn
    role: str = "server"         # "server": one region, tagged; "personal": the owner's, in every region
    region: str = None           # a server's region; the region a personal device starts on
    os: str = "linux"            # "linux" or "macos"
    port: int = None             # tailscaled's UDP port; None = the default
    netfilter_mode: str = None   # Linux only: tailscale up --netfilter-mode
    accept_dns: bool = None      # None: on where only the suffix goes to MagicDNS

    @property
    def local(self):
        return self.ssh is None

    @property
    def alias(self):
        """How the runner knows the machine: its SSH alias, or its name when it is this machine."""
        return self.ssh or self.name

    @property
    def personal(self):
        return self.role == "personal"

    def record(self):
        return {k: v for k, v in asdict(self).items() if k != "name"}


def this_os():
    return "macos" if platform.system() == "Darwin" else "linux"


def this_machine_name():
    return dns_label(platform.node().split(".")[0]) or "this-machine"


def from_site(site, alias):
    """A host that site.toml names: a server of its region, with its [hosts] settings."""
    h = site.host_settings.get(alias)
    return Target(name=alias, ssh=alias, region=site.host_region(alias).name,
                  port=h.tailscale_port if h else None, netfilter_mode=h.netfilter_mode if h else None,
                  accept_dns=h.accept_dns if h else None)


def find_record(site, host):
    """(name, record) of a joined machine by name or SSH alias; host None = this machine."""
    for name, rec in site.joined.items():
        this = rec.get("ssh") is None and not rec.get("app")       # a Mac with the app is not this machine
        if (host is None and this) or (host is not None and host in (name, rec.get("ssh"))):
            return name, rec
    return None, None


def resolve(site, host=None, name=None, role=None, region=None, os_name=None, port=None, netfilter_mode=None,
            accept_dns=None, detect_os=None):
    """The Target for `tn join [host] [options]`. Options win over the record of an earlier join,
    which wins over site.toml. host None = the machine that runs tn."""
    rec_name, rec = find_record(site, host)
    rec = rec or {}
    if rec_name is not None:
        host = rec.get("ssh")
    site_host = host is not None and site.is_site_host(host)
    settings = site.host_settings.get(host) if host else None
    base = from_site(site, host) if site_host or (settings and settings.region) else None
    role = role or rec.get("role") or "server"
    if role not in ROLES:
        raise SiteError(f"use --server or --personal, not {role!r}")
    if role == "personal" and site_host:
        raise SiteError(f"{host} is a control host, a checker or a line's end, which others use: it joins as a server")
    if base and region and region != base.region:
        raise SiteError(f"{host} is in region {base.region} in site.toml; leave out --region")
    region = region or rec.get("region") or (base.region if base else None)
    if region is None and role == "personal":
        region = next(iter(site.regions))
    if region is None:
        raise SiteError(f"{host or 'this machine'}: choose its region with --region ({', '.join(site.regions)})")
    site.region(region)
    if os_name is None:
        os_name = rec.get("os") or (this_os() if host is None else (detect_os(host) if detect_os else None)) or "linux"
    if os_name not in OSES:
        raise SiteError(f"--os: use one of {', '.join(OSES)}")
    netfilter_mode = netfilter_mode or rec.get("netfilter_mode") or (base.netfilter_mode if base else None)
    if netfilter_mode is not None and netfilter_mode not in NETFILTER_MODES:
        raise SiteError(f"--netfilter: use one of {', '.join(NETFILTER_MODES)}")
    if netfilter_mode and os_name == "macos":
        raise SiteError("--netfilter is for Linux only")
    port = port or rec.get("port") or (base.port if base else None)
    if port is not None and not 1 <= int(port) <= 65535:
        raise SiteError(f"--port: {port} is not a port")
    if accept_dns is None:
        accept_dns = rec.get("accept_dns") if "accept_dns" in rec else (base.accept_dns if base else None)
    name = name or rec_name or host or this_machine_name()
    if dns_label(name) != name.lower():
        raise SiteError(f"--name: {name!r} is not a usable name; use letters, digits and '-'")
    return Target(name=name, ssh=host, role=role, region=region, os=os_name, port=port,
                  netfilter_mode=netfilter_mode, accept_dns=accept_dns)


def remember(site, target):
    """Record how a machine that site.toml does not name joined; site hosts need no record."""
    if target.ssh is not None and site.is_site_host(target.ssh):
        return
    site.joined[target.name] = target.record()
    write_joined(site.directory, site.joined)


def forget(site, target):
    if site.joined.pop(target.name, None) is not None:
        write_joined(site.directory, site.joined)


def command_line(target, action="apply"):
    """The `tn join` command that does the same without questions."""
    words = ["./tn", "join", action] + ([target.ssh] if target.ssh else [])
    if target.personal:
        words.append("--personal")
    words += ["--region", target.region]
    if target.name != (target.ssh or this_machine_name()):
        words += ["--name", target.name]
    if target.port and target.port != pins.DEFAULT_TAILSCALE_PORT:
        words += ["--port", str(target.port)]
    return " ".join(words)


# --- the questions of `tn join` -----------------------------------------------------------


def _site_role(site, alias):
    for r in site.regions.values():
        if alias == r.control_host:
            return f"control host of {r.name}"
        if alias == r.check_from:
            return f"checker of {r.name}"
    for ln in site.lines:
        if alias in (ln.initiator, ln.responder):
            return f"end of line {ln.name}"
    return ""


def _joined_hint(rec):
    return f"joined: {rec.get('role', 'server')} in {rec.get('region')}" if rec else ""


def ask_app(site, ui, given=None):
    """A Mac with the Tailscale app: its name, and the region it starts on."""
    given = given or {}
    out = {"host": None, "app": True}
    if given.get("name") is None:
        out["name"] = ui.text("Its name in the tailnet", "air",
                              check=lambda v: None if dns_label(v) == v.lower() else "letters, digits and '-'")
    if given.get("region") is None:
        regions = [(r.name, r.name, f"Headscale on {r.control_host}") for r in site.regions.values()]
        out["region"] = ui.select("Which region does it start in?", regions)
    return out


def ask(site, ui, ssh_aliases=(), host=None, given=None, pick=True):
    """Ask which machine joins (unless pick is False: then it is host), how, where and under which
    name, skipping what the command line already gave. Returns resolve()'s keyword arguments."""
    given = given or {}
    here = this_machine_name()
    here_name, here_rec = find_record(site, None)
    if pick:
        machines = [(None, "This machine", ", ".join(x for x in (here_name or here, this_os(),
                                                                 _joined_hint(here_rec)) if x))]
        for alias in ssh_aliases:
            _n, rec = find_record(site, alias)
            machines.append((alias, alias, _site_role(site, alias) or _joined_hint(rec) or "over SSH"))
        machines.append(("app", "A Mac with the Tailscale app…", "a laptop: a profile to install and one paste; no SSH"))
        machines.append(("?", "Another machine…", "type its SSH alias"))
        host = ui.select("Which machine joins?", machines)
        if host == "app":
            return ask_app(site, ui, given)
        if host == "?":
            host = ui.text("SSH alias", check=lambda v: None if v and dns_label(v) else "an SSH alias from ~/.ssh/config")
    rec_name, rec = find_record(site, host)
    rec = rec or {}
    if rec_name is not None:
        host = rec.get("ssh")
    if host is not None and site.is_site_host(host):
        ui.note(f"{host} is the {_site_role(site, host)}: it joins {site.host_region(host).name} as a server.")
        return {"host": host}
    out = {"host": host}
    role = given.get("role")
    if role is None:
        roles = [("personal", "Personal device", "you, in every region; switch with tailscale switch"),
                 ("server", "Server", "one region, tagged, always on")]
        if host is not None:
            roles.reverse()                  # over SSH, a server is the likelier case
        values = [v for v, _l, _h in roles]
        role = ui.select("How does it join?", roles, default=values.index(rec.get("role", values[0])))
        out["role"] = role
    if given.get("region") is None:
        regions = [(r.name, r.name, f"Headscale on {r.control_host}, {r.ipv4_prefix}") for r in site.regions.values()]
        names = [v for v, _l, _h in regions]
        out["region"] = ui.select("Which region does it start in?" if role == "personal" else "Which region?",
                                  regions, default=names.index(rec["region"]) if rec.get("region") in names else 0)
    if given.get("name") is None:
        default = rec_name or (here if host is None else host)
        out["name"] = ui.text("Its name in the tailnet", default,
                              check=lambda v: None if dns_label(v) == v.lower() else "letters, digits and '-'")
    return out
