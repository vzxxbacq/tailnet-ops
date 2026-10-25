"""Names across regions.

Every host is `<name>.<suffix>` and `<name>.<region>.<suffix>`, the same names in every region.
A region's own hosts are answered by MagicDNS from its Headscale (the short name) and by extra
records (the name with the region); the hosts of the regions it reaches through a line are
extra records that point at their alias addresses. tailnet-ops keeps those records in each
Headscale's extra records file, which Headscale reloads when it changes.
"""

import ipaddress
import json

from . import render, scripts

NODES_JSON = '"$BIN" nodes list -o json 2>/dev/null\n'


def _json(text):
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    try:
        return json.JSONDecoder().raw_decode(text[min(starts):])[0] if starts else []
    except ValueError:
        return []


def node_ipv4(node, region):
    net = ipaddress.ip_network(region.ipv4_prefix)
    for ip in node.get("ip_addresses") or []:
        if ":" not in ip and ipaddress.ip_address(ip) in net:
            return ip
    return None


def records(site, region, nodes_by_region, skip_lines=()):
    """(records, skipped): A records for this region's hosts with the region in the name, and
    for the hosts of every region this one reaches, with and without their region."""
    local = {str(n.get("given_name", "")).lower() for n in nodes_by_region.get(region.name, [])}
    out, skipped, seen = [], [], set()
    for n in nodes_by_region.get(region.name, []):
        name, ip = str(n.get("given_name", "")).lower(), node_ipv4(n, region)
        if name and ip:
            out.append({"name": f"{name}.{region.name}.{region.base_domain}", "type": "A", "value": ip})
    for _ln, other in render.line_peers(site, region, skip_lines):
        if other.name in seen or other.alias_net is None:
            continue
        seen.add(other.name)
        for n in nodes_by_region.get(other.name, []):
            name, ip = str(n.get("given_name", "")).lower(), node_ipv4(n, other)
            if not name or ip is None:
                continue
            alias = other.alias_of(ip)
            out.append({"name": f"{name}.{other.name}.{region.base_domain}", "type": "A", "value": alias})
            if name in local:
                skipped.append(f"{name}.{region.base_domain} (also a host in {region.name}; "
                               f"use {name}.{other.name}.{region.base_domain})")
                continue
            out.append({"name": f"{name}.{region.base_domain}", "type": "A", "value": alias})
    return sorted(out, key=lambda r: r["name"]), skipped


def write(records_list):
    text = json.dumps(records_list, indent=2)
    return f"""ours_etc || die "$ETC is missing or not ours"
cat > "$ETC/extra-records.json.tn-new" <<'TN_EOF'
{text}
TN_EOF
chown root:headscale "$ETC/extra-records.json.tn-new"
chmod 0640 "$ETC/extra-records.json.tn-new"
if cmp -s "$ETC/extra-records.json.tn-new" "$ETC/extra-records.json"; then
  rm -f "$ETC/extra-records.json.tn-new"
  echo "names of other regions' hosts: unchanged ({len(records_list)})"
else
  mv -f "$ETC/extra-records.json.tn-new" "$ETC/extra-records.json"
  echo "names of other regions' hosts: now {len(records_list)} (Headscale reloads them by itself)"
fi
"""


class Names:
    def __init__(self, site, runner, out=print):
        self.site = site
        self.runner = runner
        self.out = out

    def _on_control(self, region, body, echo=False):
        return self.runner.run(region.control_host, scripts.wrap(scripts.control_prelude(self.site, region), body),
                               privileged=True, echo=echo)

    def nodes(self):
        return {name: _json(self._on_control(r, NODES_JSON).output) or [] for name, r in self.site.regions.items()}

    def plan(self, skip_lines=()):
        nodes = self.nodes()
        return nodes, {name: records(self.site, r, nodes, skip_lines) for name, r in self.site.regions.items()}

    def sync(self, skip_lines=()):
        _nodes, planned = self.plan(skip_lines)
        for name, (recs, skipped) in planned.items():
            r = self.site.regions[name]
            self.out(f"    {r.control_host} ({name}): {len(recs)} name(s) from other regions")
            for s in skipped:
                self.out(f"      skipped {s}")
            self._on_control(r, write(recs), echo=True)

    def table(self):
        """Every host, as each region resolves it: the name with its region, and the short name."""
        _nodes, planned = self.plan()
        rows = []
        for name, r in self.site.regions.items():
            net = ipaddress.ip_network(r.ipv4_prefix)
            by_value = {}
            for rec in planned[name][0]:
                by_value.setdefault(rec["value"], []).append(rec["name"])
            for value, recs in sorted(by_value.items(), key=lambda kv: sorted(kv[1])[0]):
                long = [x for x in recs if x.count(".") >= 2 + r.base_domain.count(".")]
                here = ipaddress.ip_address(value) in net
                for full in sorted(long):
                    host = full.split(".", 1)[0]
                    # A local host's short name comes from MagicDNS itself; a remote one's from a record,
                    # which is left out when it clashes with a local host.
                    short = here or f"{host}.{r.base_domain}" in recs
                    rows.append((name, full, f"{host}, {host}.{r.base_domain}" if short else "—", value,
                                 "this region" if here else "through a line"))
        return rows
