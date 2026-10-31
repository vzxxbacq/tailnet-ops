"""`tn phone`: a phone reaches the tailnets from its proxy app, through the regions' entries.

A phone runs one VPN at a time, and that is its proxy app, so it does not run Tailscale.
Its proxy app gets one WireGuard node per region's entry instead (entry.py). tn makes
the phone's key on this machine, gives the phone the next address in the site's entry
range, adds it as a peer on every entry and writes into the site directory:

  phones/<name>/<region>.conf   for the WireGuard app, or an app that imports its files
  phones/<name>/clash.yaml      nodes, a group, rules and names for Stash or Clash Meta (mihomo)

Both hold the phone's private key: move them to the phone (AirDrop) and keep them private.
"""

import json
import re
import shutil

from . import entry, names, scripts, wgkey
from .procedure import StepError
from .remote import RemoteError
from .site import dns_label, ensure_private_dir, write_phones, write_private

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
KEY_FILE = "wg.key"
GROUP = "tailnet"


def node_name(region):
    return f"tn-{region.name}"


def next_address(site):
    used = {p.get("address") for p in site.phones.values()} | {site.entry_address}
    for ip in site.entry_net.hosts():
        if str(ip) not in used:
            return str(ip)
    raise StepError(f"no free address left in {site.entry_ipv4}; set a larger entry_ipv4 under [site]")


def routes(site):
    """Every tailnet range a phone reaches through some entry, as the phone sees them."""
    out = []
    for r in site.entry_regions():
        out += [p for p in entry.phone_routes(site, r) if p not in out]
    return out


def wg_conf(site, region, name, private, address, entry_public):
    return "\n".join([
        f"# tailnet-ops phone={name} region={region.name}: for the WireGuard app, or an app that imports it",
        "[Interface]",
        f"PrivateKey = {private}",
        f"Address = {address}/32",
        f"DNS = {site.entry_address}",
        f"MTU = {entry.PHONE_MTU}",
        "",
        "[Peer]",
        f"PublicKey = {entry_public}",
        f"Endpoint = {region.public_ipv4}:{region.entry_port}",
        f"AllowedIPs = {', '.join(entry.phone_routes(site, region))}",
    ]) + "\n"


def phone_hosts(site, nodes_by_region):
    """[(name, address)]: <host>.<region>.<suffix> for every host, and <host>.<suffix> where only one
    region has that host. Addresses are tailnet addresses, which every entry reaches."""
    out, short = [], {}
    for name, r in site.regions.items():
        for host, ip in names._hosts(nodes_by_region.get(name, []), r):
            out.append((f"{host}.{r.name}.{r.base_domain}", ip))
            short.setdefault(f"{host}.{r.base_domain}", []).append(ip)
    out += [(host, ips[0]) for host, ips in short.items() if len(ips) == 1]
    return sorted(out)


def clash_yaml(site, name, private, address, entries, hosts):
    """entries: [(region, the entry's public key)]; hosts: [(name, address)]."""
    q = json.dumps  # a JSON string is a YAML string
    out = [f"# tailnet-ops phone={name}: WireGuard nodes for the regions' phone entries, for Stash or",
           "# Clash Meta (mihomo). Merge them into the phone's configuration: the nodes, the group, the",
           "# rules (before your other rules), the hosts and dns.nameserver-policy (names not in hosts are",
           "# asked of the entry through the tunnel). A proxy that sits in the tailnet reaches it with",
           f"# dialer-proxy: {GROUP}. Private: this file holds the phone's key.",
           "proxies:"]
    for region, public in entries:
        out += [f"  - name: {q(node_name(region))}",
                "    type: wireguard",
                f"    server: {q(region.public_ipv4)}",
                f"    port: {region.entry_port}",
                f"    ip: {q(address)}",
                f"    private-key: {q(private)}",
                f"    public-key: {q(public)}",
                "    udp: true",
                f"    mtu: {entry.PHONE_MTU}"]
    out += ["proxy-groups:", f"  - name: {GROUP}", "    type: select", "    proxies:"]
    out += [f"      - {q(node_name(region))}" for region, _public in entries]
    suffixes = sorted({r.base_domain for r in site.regions.values()})
    out += ["rules:"] + [f"  - DOMAIN-SUFFIX,{s},{GROUP}" for s in suffixes]
    out += [f"  - IP-CIDR,{prefix},{GROUP},no-resolve" for prefix in routes(site)]
    out += ["hosts:" if hosts else "hosts: {}"] + [f"  {q(host)}: {q(ip)}" for host, ip in hosts]
    out += ["dns:", "  nameserver-policy:"]
    out += [f"    {q('+.' + s)}: {q(site.entry_address + '#' + GROUP)}" for s in suffixes]
    return "\n".join(out) + "\n"


def _ago(seconds):
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return f"{seconds // size} {unit} ago"
    return f"{seconds} s ago"


def _size(n):
    n = int(n)
    for unit, size in (("MB", 1 << 20), ("kB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


class Phones:
    def __init__(self, site, runner, out=print):
        self.site = site
        self.runner = runner
        self.out = out

    def _on(self, region, body):
        return self.runner.run(region.control_host, scripts.wrap(scripts.control_prelude(self.site, region), body),
                               privileged=True)

    def _regions(self):
        regions = self.site.entry_regions()
        if not regions:
            raise StepError("no region has a phone entry: set entry_port under [regions.<name>] in site.toml, "
                            "then run tn control apply <region>")
        return regions

    def _push(self):
        """Give every entry the site's phones. {region name: the entry's public key; "" where there is
        no entry yet; None where the control host failed}."""
        keys = {}
        for r in self._regions():
            self.out(f"\n== {r.control_host} ({r.name})")
            try:
                facts = self._on(r, entry.update_peers(self.site, r)).facts()
            except RemoteError as e:
                self.out(f"    ✗ {e}")
                keys[r.name] = None
                continue
            if facts.get("entry") == "absent":
                self.out(f"    no phone entry here yet; tn control apply {r.name} installs it with these phones")
                keys[r.name] = ""
            else:
                keys[r.name] = facts.get("pub") or None
        return keys

    def _hosts(self):
        seen, _unknown = names.Names(self.site, self.runner, out=lambda s: None).peek(tolerant=True)
        return phone_hosts(self.site, {name: p.nodes for name, p in seen.items()})

    def _ask(self, prompt, yes, ask):
        if yes or ask(prompt).strip() == "yes":
            return True
        self.out("Nothing changed.")
        return False

    def add(self, name, yes=False, ask=input):
        """Add a phone, or bring an added one up to date (its peers, names and files)."""
        site = self.site
        if not NAME_RE.match(name):
            raise StepError(f"{name!r}: use a-z, 0-9 and '-', starting with a letter (e.g. iphone)")
        regions = self._regions()
        known = site.phones.get(name)
        address = known["address"] if known else next_address(site)
        folder = site.phones_dir / name
        self.out(f"tn phone add {name}" + (" (already added: refresh its peers, names and files)" if known else ""))
        self.out(f"  address   {address} on every entry (the entries themselves are {site.entry_address})")
        self.out("  key       " + ("kept" if known else "made on this machine") + "; only its public key goes to the entries")
        for r in regions:
            self.out(f"  {r.name.ljust(9)} {r.control_host}: a peer on {entry.IFACE}, "
                     f"udp {r.public_ipv4}:{r.entry_port}")
        self.out("  names     read from each Headscale, for the phone's list of hosts (read-only)")
        self.out(f"  files     {folder}/: {', '.join(f'{r.name}.conf' for r in regions)}, clash.yaml")
        self.out(f"  undo      tn phone remove {name}")
        hosts = " and ".join(r.control_host for r in regions)
        if not self._ask(f"Type yes to add {name} to {hosts}: ", yes, ask):
            return 1
        key_path = folder / KEY_FILE
        if known:
            if not key_path.exists():
                raise StepError(f"{key_path} is missing; run tn phone remove {name}, then add it again")
            private = key_path.read_text().strip()
            if wgkey.public_key(private) != known["public_key"]:
                raise StepError(f"{key_path} does not match the public key in phones.json")
        else:
            private = wgkey.private_key()
            ensure_private_dir(site.phones_dir)
            ensure_private_dir(folder)
            write_private(key_path, private + "\n")
            site.phones[name] = {"address": address, "public_key": wgkey.public_key(private)}
            write_phones(site.directory, site.phones)
        keys = self._push()
        hosts_list = self._hosts()
        entries = [(r, keys[r.name]) for r in regions if keys[r.name]]
        written = []
        for r, public in entries:
            written.append(write_private(folder / f"{r.name}.conf", wg_conf(site, r, name, private, address, public)))
        if entries:
            written.append(write_private(folder / "clash.yaml", clash_yaml(site, name, private, address, entries, hosts_list)))
        missing = [r for r in regions if not keys[r.name]]
        # The phone stays in phones.json either way: tn control apply adds it where this did not.
        self.out("")
        if entries:
            self.out(f"✓ {name} is {address} on " + ", ".join(f"{r.control_host} ({r.name})" for r, _ in entries)
                     + f"; {len(hosts_list)} host name(s) in clash.yaml")
            self.out("Files (private: they hold the phone's key; send them to the phone with AirDrop):")
            for path in written:
                self.out(f"  {path}")
            self.out(f"Test with the WireGuard app: import {entries[0][0].name}.conf, connect, then ping a host, "
                     "e.g. one from tn dns list.")
        for r in missing:
            self.out(f"✗ not on {r.control_host} ({r.name}) yet. Run tn control apply {r.name}, "
                     f"then tn phone add {name} again for its files.")
        return 1 if missing else 0

    def remove(self, name, yes=False, ask=input):
        site = self.site
        if name not in site.phones:
            raise StepError(f"no phone named {name} (tn phone list)")
        regions = self._regions()
        self.out(f"tn phone remove {name}")
        self.out(f"  peers     {site.phones[name]['address']} leaves " + ", ".join(r.control_host for r in regions))
        self.out(f"  files     {site.phones_dir / name}/ is deleted, with the phone's key")
        if not self._ask(f"Type yes to remove {name}: ", yes, ask):
            return 1
        record = site.phones.pop(name)
        keys = self._push()
        failed = [r for r in regions if keys[r.name] is None]
        if failed:
            site.phones[name] = record
            self.out(f"\n✗ could not reach {', '.join(r.control_host for r in failed)}; {name} is still listed. "
                     "Run tn phone remove again.")
            return 1
        write_phones(site.directory, site.phones)
        shutil.rmtree(site.phones_dir / name, ignore_errors=True)
        self.out(f"\n✓ removed {name}. Delete its tunnels on the phone too.")
        return 0

    def stop(self, region_name, yes=False, ask=input):
        """Take the entry off one control host (Headscale and everything else stay)."""
        r = self.site.region(region_name)
        self.out(f"tn phone stop {r.name}")
        self.out(f"  {r.control_host}: stop {entry.IFACE}; remove its key, nft table {entry.TABLE}, accept rules, "
                 "timer and files; then check that nothing is left")
        self.out(f"  phones lose region {r.name}; their files for it stop working")
        if not self._ask(f"Type yes to remove the phone entry from {r.control_host}: ", yes, ask):
            return 1
        self._on(r, entry.rollback(self.site, r))
        left = [line[len("TN-LEFT "):] for line in self._on(r, entry.leftovers(self.site, r)).output.splitlines()
                if line.startswith("TN-LEFT ")]
        if left:
            self.out(f"\n✗ Still there on {r.control_host}:")
            for item in left:
                self.out(f"  ✗ {item}")
            return 1
        self.out(f"\n✓ Nothing of the phone entry is left on {r.control_host}. To put it back: tn control apply {r.name}"
                 + ("; to keep it off, remove entry_port from site.toml" if r.entry_port else ""))
        return 0

    def status(self):
        """Read-only: each entry and every phone on it. Returns 1 when something is wrong."""
        site, bad = self.site, 0
        names = {p["public_key"]: name for name, p in site.phones.items()}
        rows = [("Region", "Entry", "Checks", "Phone", "Last handshake", "In / out")]
        for r in self._regions():
            probe = f"{dns_label(r.control_host)}.{r.name}.{r.base_domain}"
            result = self.runner.run(r.control_host, scripts.wrap(scripts.control_prelude(site, r),
                                                                  entry.status(site, r, probe)),
                                     privileged=True, echo=False, check=False)
            facts = result.facts()
            where = f"{r.control_host} udp {r.entry_port}"
            if result.rc != 0 or facts.get("entry") == "absent":
                rows.append((r.name, where, "✗ " + ("no entry; tn control apply " + r.name
                                                    if facts.get("entry") == "absent" else "no answer over SSH"),
                             "", "", ""))
                bad += 1
                continue
            checks = [("tunnel", facts.get("wg") == "active"), ("DNS", facts.get("dns") == "active"),
                      (f"lookup {probe}", facts.get("lookup") == "ok"),
                      ("accept rules", facts.get("rules") == "ok" and facts.get("keeper") == "active")]
            bad += sum(1 for _, ok in checks if not ok)
            summary = " ".join(("✓ " if ok else "✗ ") + label for label, ok in checks)
            peers = [line.split() for line in (result.block("peers") or "").splitlines() if line.strip()]
            if not peers:
                rows.append((r.name, where, summary, "no phones", "", ""))
            for i, (public, _endpoint, ago, rx, tx) in enumerate(peers):
                seconds = int(ago)
                rows.append((r.name if i == 0 else "", where if i == 0 else "", summary if i == 0 else "",
                             names.get(public, f"unknown {public[:8]}…"),
                             "never" if seconds < 0 else _ago(seconds), f"{_size(rx)} / {_size(tx)}"))
        widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
        for row in rows:
            self.out("  " + "  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
        self.out("\nA phone talks to one entry at a time: the other shows its last use.")
        return 1 if bad else 0

    def rows(self):
        out = [("Phone", "Address", "Files")]
        for name, p in sorted(self.site.phones.items()):
            folder = self.site.phones_dir / name
            files = sorted(f.name for f in folder.glob("*") if f.name != KEY_FILE) if folder.is_dir() else []
            out.append((name, p.get("address", "?"), ", ".join(files) or "none yet"))
        return out
