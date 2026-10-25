"""Names across regions.

Every host is `<name>.<suffix>`, the same name in every region. A region's own hosts are
answered by MagicDNS from its Headscale; the hosts of the regions it reaches through a line
are extra records that point at their alias addresses. tailnet-ops keeps those records in
each Headscale's extra records file, which Headscale reloads when it changes.
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
    """(records, skipped): A records for the hosts of every region this one reaches."""
    local = {str(n.get("given_name", "")).lower() for n in nodes_by_region.get(region.name, [])}
    out, skipped, seen = [], [], set()
    for _ln, other in render.line_peers(site, region, skip_lines):
        if other.name in seen or other.alias_net is None:
            continue
        seen.add(other.name)
        for n in nodes_by_region.get(other.name, []):
            name, ip = str(n.get("given_name", "")).lower(), node_ipv4(n, other)
            if not name or ip is None:
                continue
            if name in local:
                skipped.append(f"{name} (also a host in {region.name})")
                continue
            out.append({"name": f"{name}.{region.base_domain}", "type": "A", "value": other.alias_of(ip)})
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
        """Every name, as each region resolves it."""
        nodes, planned = self.plan()
        rows = []
        for name, r in self.site.regions.items():
            for n in nodes.get(name, []):
                ip = node_ipv4(n, r)
                if ip:
                    rows.append((name, f"{str(n.get('given_name', '')).lower()}.{r.base_domain}", ip, "this region"))
            for rec in planned[name][0]:
                rows.append((name, rec["name"], rec["value"], "through a line"))
        return rows
