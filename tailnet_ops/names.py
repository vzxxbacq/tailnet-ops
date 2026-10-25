"""Names across regions.

Every host is `<name>.<suffix>` and `<name>.<region>.<suffix>`, the same names in every region.
A region's own hosts are answered by MagicDNS from its Headscale (the short name) and by extra
records (the name with the region); the hosts of the regions it reaches through a line are
extra records that point at their alias addresses. tailnet-ops keeps those records in each
Headscale's extra records file, which Headscale reloads when it changes.

A control host set up by `tn control apply` runs a keeper every minute. It writes the records
from its own nodes and from a list of each peer region's hosts. The control host on a line's
initiator side calls the other one over SSH, with a key that can do nothing but swap the two
lists. `Names.sync` hands every keeper its peers, those keys and fresh lists; a control host
without a keeper gets the records written directly, as before.
"""

import ipaddress
import json
import re
import shlex
from collections import namedtuple

from . import render, scripts

NODES_JSON = '"$BIN" nodes list -o json 2>/dev/null\n'
KEEPER_DIR = f"{render.ETC}/names"
KEEPER = f"{KEEPER_DIR}/keeper"
KEEPER_STATE = f"{render.LIB}/names"
KEEPER_UNIT = "tailnet-ops-names"
KEEPER_MINUTES = 1


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


# What the keeper on a control host needs, then its running modes. The awk parts understand
# `headscale nodes list -o json` and the "<name> <IPv4>" lists the keepers swap.
KEEPER_SCRIPT = r"""#!/bin/bash
# @MARK@
# Keeps Headscale's extra records: this region's hosts as <name>.<region>.<suffix>, and each
# peer region's hosts at their alias addresses. Written by tailnet-ops; runs every minute.
#   keeper run              read the nodes, swap lists with the peers this side calls, write
#   keeper local            the same without calling anyone
#   keeper exchange <peer>  the forced SSH command: take the peer's list on stdin, print ours
set -euo pipefail
umask 022
REGION=@REGION@
SUFFIX=@SUFFIX@
PREFIX=@PREFIX@
BIN=@BIN@
DIR=@DIR@
STATE=@STATE@
RECORDS=@RECORDS@
OWNER=@OWNER@

die() { echo "names: $*" >&2; exit 1; }
conf_get() { sed -n "s/^$2=//p" "$1" | head -n 1; }

IP_AWK='
function ip2n(s,   p) {
  if (s !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return -1
  split(s, p, ".")
  if (p[1] > 255 || p[2] > 255 || p[3] > 255 || p[4] > 255) return -1
  return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4]
}
function n2ip(n) { return int(n / 16777216) "." (int(n / 65536) % 256) "." (int(n / 256) % 256) "." (n % 256) }
function lo(net,   a) { split(net, a, "/"); return ip2n(a[1]) }
function hi(net,   a) { split(net, a, "/"); return ip2n(a[1]) + 2 ^ (32 - a[2]) - 1 }
function label(s) { return length(s) <= 63 && s ~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/ }
'

# stdin: headscale nodes list -o json. Prints "<given name> <its IPv4 in PREFIX>" per node.
node_list() {
  awk -v net="$PREFIX" "$IP_AWK"'
    function value(s,   n) {
      if (depth == 2 && key == "given_name") name = tolower(s)
      else if (depth == 3 && key == "ip_addresses" && ip == "") { n = ip2n(s); if (n >= l && n <= h) ip = s }
    }
    BEGIN { l = lo(net); h = hi(net) }
    {
      line = $0
      while (match(line, /"([^"\\]|\\.)*"|[][{}:,]/)) {
        tok = substr(line, RSTART, RLENGTH); line = substr(line, RSTART + RLENGTH)
        if (tok == ":") { if (depth == 2) key = str; pending = 0; continue }
        if (pending) { value(str); pending = 0 }
        if (substr(tok, 1, 1) == "\"") { str = substr(tok, 2, length(tok) - 2); pending = 1 }
        else if (tok == "{" || tok == "[") { if (++depth == 2) { name = ""; ip = ""; key = "" } }
        else if (tok == "}" || tok == "]") {
          if (depth == 2 && tok == "}" && ip != "" && label(name)) print name, ip
          depth--
        }
      }
    }'
}

# stdin: a peer's "<name> <IPv4>" list. Prints it if every line is a host name with an address
# in $1 (at most 4096 lines); fails otherwise, so a bad list never replaces a good one.
valid_list() {
  awk -v net="$1" "$IP_AWK"'
    BEGIN { l = lo(net); h = hi(net) }
    NF == 0 { next }
    NF != 2 || !label($1) { bad = 1; exit }
    { n = ip2n($2); if (n < l || n > h || ++count > 4096) { bad = 1; exit }; print }
    END { exit bad }'
}

own_list() {
  local json tmp
  json=$("$BIN" nodes list -o json 2>/dev/null) || die "headscale nodes list failed"
  case "${json#"${json%%[![:space:]]*}"}" in "["*) ;; *) die "headscale nodes list printed no list" ;; esac
  tmp=$(mktemp "$STATE/.own.XXXXXX")
  printf '%s\n' "$json" | node_list > "$tmp"
  mv -f "$tmp" "$STATE/$REGION.tsv"
}

to_json() {
  awk '{ r[++n] = $0 }
    END {
      if (n == 0) { print "[]"; exit }
      print "["
      for (i = 1; i <= n; i++) {
        split(r[i], f, " ")
        printf "  {\n    \"name\": \"%s\",\n    \"type\": \"A\",\n    \"value\": \"%s\"\n  }%s\n", f[1], f[2], (i < n ? "," : "")
      }
      print "]"
    }'
}

# stdin: "L <name> <IPv4>" for this region's hosts, then "P <peer> <prefix> <alias range> <name>
# <IPv4>" for each peer's. Prints "<record name> <address>", sorted by name.
record_lines() {
  awk -v region="$REGION" -v suffix="$SUFFIX" "$IP_AWK"'
    $1 == "L" { here[$2] = 1; print $2 "." region "." suffix, $3; next }
    $1 == "P" {
      a = n2ip(lo($4) + ip2n($6) - lo($3))
      print $5 "." $2 "." suffix, a
      if (!($5 in here)) print $5 "." suffix, a
    }' | LC_ALL=C sort -s -k1,1
}

write_records() {
  local tmp conf p count
  tmp=$(mktemp "$(dirname "$RECORDS")/.extra-records.XXXXXX")
  {
    awk '{ print "L", $1, $2 }' "$STATE/$REGION.tsv"
    for conf in "$DIR"/peers/*.conf; do
      [ -f "$conf" ] || continue
      p=$(basename "$conf" .conf)
      [ -f "$STATE/$p.tsv" ] || continue
      awk -v p="$p" -v net="$(conf_get "$conf" prefix)" -v alias="$(conf_get "$conf" alias)" \
        '{ print "P", p, net, alias, $1, $2 }' "$STATE/$p.tsv"
    done
  } | record_lines | to_json > "$tmp"
  chown "$OWNER" "$tmp"
  chmod 0640 "$tmp"
  if cmp -s "$tmp" "$RECORDS"; then
    rm -f "$tmp"
  else
    mv -f "$tmp" "$RECORDS"
    count=$(grep -c '"name"' "$RECORDS" || true)
    echo "names: wrote $count records" >&2
  fi
}

# Swap lists with the peer of $1 over SSH; the peer's key runs `keeper exchange <this region>`.
call() {
  local conf=$1 p target raw err tmp rc=0
  p=$(basename "$conf" .conf)
  target=$(conf_get "$conf" target)
  raw=$(mktemp "$STATE/.raw.XXXXXX"); err=$(mktemp "$STATE/.err.XXXXXX"); tmp=$(mktemp "$STATE/.in.XXXXXX")
  $TIMEOUT ssh -i "$DIR/id_ed25519" -p "$(conf_get "$conf" port)" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$DIR/known_hosts" -o GlobalKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=2 -o LogLevel=ERROR \
    "$target" exchange < "$STATE/$REGION.tsv" > "$raw" 2> "$err" || rc=$?
  if [ "$rc" != 0 ]; then
    echo "names: could not swap names with $p ($target): $(tail -n 1 "$err")" >&2
  elif ! valid_list "$(conf_get "$conf" prefix)" < "$raw" > "$tmp"; then
    echo "names: $p ($target) answered with something other than its list: $(head -c 80 "$raw")" >&2
    rc=1
  else
    mv -f "$tmp" "$STATE/$p.tsv"
  fi
  rm -f "$raw" "$err" "$tmp"
  return "$rc"
}

run() {
  local conf failed=0
  own_list
  if [ "${1:-}" != local ]; then
    for conf in "$DIR"/peers/*.conf; do
      [ -f "$conf" ] && [ -n "$(conf_get "$conf" target)" ] || continue
      call "$conf" || failed=1
    done
  fi
  write_records
  return "$failed"
}

exchange() {
  local peer=${1:-} conf tmp
  case "$peer" in ""|*[!a-z0-9-]*) die "exchange needs a region name" ;; esac
  conf="$DIR/peers/$peer.conf"
  [ -f "$conf" ] || die "$peer is not a peer of $REGION"
  tmp=$(mktemp "$STATE/.in.XXXXXX")
  if ! head -n 4097 | valid_list "$(conf_get "$conf" prefix)" > "$tmp"; then
    rm -f "$tmp"
    die "refused the list from $peer"
  fi
  mv -f "$tmp" "$STATE/$peer.tsv"
  own_list
  write_records
  cat "$STATE/$REGION.tsv"
}

TIMEOUT=""
if command -v timeout >/dev/null; then TIMEOUT="timeout 60"; fi
[ -d "$STATE" ] || die "$STATE is missing"
case "${1:-}" in
  run) run ;;
  local) run local ;;
  exchange) exchange "${2:-}" ;;
  *) die "usage: keeper run | local | exchange <region>" ;;
esac
"""


def keeper_script(site, region, bin_path=render.BIN, keeper_dir=KEEPER_DIR, state=KEEPER_STATE,
                  records_file=render.EXTRA_RECORDS, owner="root:headscale"):
    """The keeper for one control host. The paths are parameters so tests can run it."""
    values = {"MARK": render.marker(region), "REGION": region.name, "SUFFIX": region.base_domain,
              "PREFIX": region.ipv4_prefix, "BIN": bin_path, "DIR": keeper_dir, "STATE": state,
              "RECORDS": records_file, "OWNER": owner}
    text = KEEPER_SCRIPT
    for key, value in values.items():
        text = text.replace(f"@{key}@", value if key == "MARK" else shlex.quote(str(value)))
    return text


def _units(region):
    mark = f"# {render.marker(region)}"
    service = f"""{mark}
[Unit]
Description=tailnet-ops: names of every region's hosts for Headscale
After=headscale.service

[Service]
Type=oneshot
ExecStart={KEEPER} run
"""
    timer = f"""{mark}
[Unit]
Description=tailnet-ops: names of every region's hosts, every {KEEPER_MINUTES} minute(s)

[Timer]
OnBootSec={KEEPER_MINUTES}min
OnUnitActiveSec={KEEPER_MINUTES}min
AccuracySec=5s

[Install]
WantedBy=timers.target
"""
    return service, timer


KEEPER_VARS = f"""NAMES_DIR={KEEPER_DIR}
NAMES_STATE={KEEPER_STATE}
NAMES_UNIT=/etc/systemd/system/{KEEPER_UNIT}
ours_names_unit() {{ [ -f "$1" ] && [ "$(head -n 1 "$1")" = "# $MARK" ]; }}
"""

# Lines that let a peer's keeper call this host. Each carries the site's tag; only those are touched.
AUTHORIZE = r"""names_authorize() {
  local u=$1 home f tmp lines
  home=$(getent passwd "$u" | cut -d: -f6)
  [ -n "$home" ] || die "no user $u for the names keys"
  f="$home/.ssh/authorized_keys"
  [ ! -L "$f" ] || die "$f is a symlink; not touched"
  lines=$(cat)
  if [ ! -f "$f" ] && [ -z "$lines" ]; then return 0; fi
  if [ ! -d "$home/.ssh" ]; then install -d -m 0700 "$home/.ssh"; chown "$u:$(id -gn "$u")" "$home/.ssh"; fi
  # Next to the file, so the swap is one rename; every line without the tag is kept as it is.
  tmp=$(mktemp "$home/.ssh/.authorized_keys.XXXXXX")
  if [ -f "$f" ]; then
    awk -v tag="$NAMES_TAG" 'index($0, tag) == 0' "$f" > "$tmp" || { rm -f "$tmp"; die "cannot read $f"; }
  fi
  if [ -n "$lines" ]; then printf '%s\n' "$lines" >> "$tmp"; fi
  if [ -f "$f" ] && cmp -s "$tmp" "$f"; then rm -f "$tmp"; return 0; fi
  if [ -f "$f" ]; then
    chmod --reference="$f" "$tmp"; chown --reference="$f" "$tmp"
  else
    chmod 0600 "$tmp"; chown "$u:$(id -gn "$u")" "$tmp"
  fi
  mv -f "$tmp" "$f"
  echo "names: updated the keys in $f that let other regions swap names"
}
"""


def install(site, region):
    """Step body: the keeper, its key and its timer on the control host. The timer starts once
    Names.sync has given the keeper its peers and their lists."""
    service, timer = _units(region)
    return f"""ours_etc || die "$ETC is missing or not ours"
ours_lib || die "$LIB is missing or not ours"
{KEEPER_VARS}for f in "$NAMES_UNIT.service" "$NAMES_UNIT.timer"; do
  if [ -e "$f" ] && ! ours_names_unit "$f"; then die "$f exists and is not ours"; fi
done
for t in ssh ssh-keygen awk sort cmp mktemp; do command -v "$t" >/dev/null || die "the names keeper needs $t"; done
install -d -o root -g root -m 0755 "$NAMES_DIR" "$NAMES_DIR/peers"
install -d -o root -g root -m 0700 "$NAMES_STATE"
cat > "$NAMES_DIR/keeper.tn-new" <<'TN_EOF'
{keeper_script(site, region).rstrip()}
TN_EOF
chmod 0755 "$NAMES_DIR/keeper.tn-new"
mv -f "$NAMES_DIR/keeper.tn-new" "$NAMES_DIR/keeper"
if [ ! -f "$NAMES_DIR/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C "tailnet-ops names $REGION" -f "$NAMES_DIR/id_ed25519"
  echo "made the key this host uses to swap names: $NAMES_DIR/id_ed25519"
fi
cat > "$NAMES_UNIT.service" <<'TN_EOF'
{service.rstrip()}
TN_EOF
cat > "$NAMES_UNIT.timer" <<'TN_EOF'
{timer.rstrip()}
TN_EOF
systemctl daemon-reload
systemctl enable {KEEPER_UNIT}.timer >/dev/null 2>&1
echo "names keeper: {KEEPER} (every {KEEPER_MINUTES} minute(s), {KEEPER_UNIT}.timer)"
"""


def uninstall(site, user):
    """Rollback body: stop and remove the keeper, and the keys that let peers call this host."""
    return f"""{KEEPER_VARS}NAMES_TAG={shlex.quote(names_tag(site))}
{AUTHORIZE}systemctl disable --now {KEEPER_UNIT}.timer >/dev/null 2>&1 || true
for f in "$NAMES_UNIT.service" "$NAMES_UNIT.timer"; do
  if [ ! -e "$f" ]; then echo "$f: absent"
  elif ours_names_unit "$f"; then rm -f "$f"; echo "removed $f"
  else echo "skip: $f is not ours"; fi
done
systemctl daemon-reload
names_authorize {shlex.quote(user)} </dev/null
if ours_etc; then rm -rf "$NAMES_DIR"; echo "removed $NAMES_DIR"; fi
if ours_lib; then rm -rf "$NAMES_STATE"; echo "removed $NAMES_STATE"; fi
"""


def names_tag(site):
    from .join import slug
    return f"tailnet-ops-names site={slug(site.name)}"


# What Names.sync reads from each control host besides its nodes.
PEEK = 'if [ ! -x "$BIN" ]; then echo "TN-FACT headscale=absent"; exit 0; fi\n' + NODES_JSON + f"""if [ -f {KEEPER} ] && [ "$(sed -n 2p {KEEPER})" = "# $MARK" ]; then
  echo "TN-FACT names_keeper=yes"
  if [ -f {KEEPER_DIR}/id_ed25519.pub ]; then echo "TN-FACT names_key=$(cat {KEEPER_DIR}/id_ed25519.pub)"; fi
fi
akf=$( (sshd -T || /usr/sbin/sshd -T) 2>/dev/null | awk '$1 == "authorizedkeysfile" {{ $1 = ""; print }}' || true)
case " $akf " in
  "  "|*" .ssh/authorized_keys "*|*" %h/.ssh/authorized_keys "*) echo "TN-FACT names_akf=yes" ;;
  *) echo "TN-FACT names_akf=no" ;;
esac
echo "TN-BEGIN hostkeys"
for k in /etc/ssh/ssh_host_*_key.pub; do
  if [ -f "$k" ]; then cut -d' ' -f1,2 "$k"; fi
done
echo "TN-END hostkeys"
"""

Peek = namedtuple("Peek", "nodes keeper key akf hostkeys")


def caller(site, a, b, skip_lines=()):
    """The region whose control host calls the other's to swap names: the initiator's side of the
    first line between a and b. None if no line joins them."""
    from .site import SiteError
    for ln in site.lines:
        if ln.name in skip_lines:
            continue
        try:
            ini, res = site.host_region(ln.initiator).name, site.host_region(ln.responder).name
        except SiteError:
            continue
        if {ini, res} == {a, b} and a != b:
            return ini
    return None


def direct(view):
    """(user@host, port) from `ssh -G` for a control host, or None when it goes through a jump host."""
    if view.get("proxyjump", "none") != "none" or view.get("proxycommand", "none") != "none":
        return None
    if not view.get("hostname"):
        return None
    return f"{view.get('user', 'root')}@{view['hostname']}", view.get("port", "22")


def _heredoc(path, mode, text):
    return f"names_put {path} {mode} <<'TN_EOF'\n{text}TN_EOF\n"


class Names:
    def __init__(self, site, runner, out=print, ssh_view=None):
        from . import remote
        self.site = site
        self.runner = runner
        self.out = out
        self._ssh_view = ssh_view or remote.ssh_config
        self._views = {}

    def ssh_view(self, host):
        """`ssh -G` for a control host, read once."""
        if host not in self._views:
            self._views[host] = self._ssh_view(host)
        return self._views[host]

    def _on_control(self, region, body, echo=False, check=True):
        return self.runner.run(region.control_host, scripts.wrap(scripts.control_prelude(self.site, region), body),
                               privileged=True, echo=echo, check=check)

    def peek(self, tolerant=False, gone=()):
        """({region: Peek}, unknown regions). A region without Headscale yet is left out, as are the
        regions in gone. tolerant: a control host that does not answer is reported as unknown
        instead of stopping."""
        from .remote import RemoteError
        found, unknown = {}, []
        for name, r in self.site.regions.items():
            if name in gone:
                continue
            try:
                result = self._on_control(r, PEEK, check=not tolerant)
            except RemoteError:
                if not tolerant:
                    raise
                result = None
            if result is None or result.rc != 0:
                self.out(f"    {r.control_host} ({name}): no answer; left as it is")
                unknown.append(name)
                continue
            facts = result.facts()
            if facts.get("headscale") == "absent":
                self.out(f"    {r.control_host} ({name}): no Headscale yet")
                continue
            head = re.split(r"^TN-", result.output, maxsplit=1, flags=re.M)[0]
            found[name] = Peek(_json(head) or [], facts.get("names_keeper") == "yes", facts.get("names_key"),
                               facts.get("names_akf", "yes") == "yes",
                               [h for h in (result.block("hostkeys") or "").splitlines() if h.strip()])
        return found, unknown

    def nodes(self):
        return {name: p.nodes for name, p in self.peek()[0].items()}

    def plan(self, skip_lines=()):
        nodes = self.nodes()
        return nodes, {name: records(self.site, r, nodes, skip_lines) for name, r in self.site.regions.items()}

    def peers(self, region, seen, skip_lines=()):
        """[(peer region, (target, port) or None)]: the regions this one reaches through a line, and
        how its keeper calls each one, when it is the side that calls and both have a keeper."""
        out, done = [], set()
        for _ln, other in render.line_peers(self.site, region, skip_lines):
            if other.name in done or other.name not in seen or other.alias_net is None:
                continue
            done.add(other.name)
            how = None
            if (caller(self.site, region.name, other.name, skip_lines) == region.name and seen[region.name].keeper
                    and seen[other.name].keeper and seen[other.name].akf):
                how = direct(self.ssh_view(other.control_host))
            out.append((other, how))
        return out

    def keeper_body(self, region, seen, skip_lines=()):
        """The keeper's peers, their lists, the host keys it trusts and the keys that may call it;
        then it writes the records and its timer runs."""
        peers = self.peers(region, seen, skip_lines)
        body = [KEEPER_VARS, f"NAMES_TAG={shlex.quote(names_tag(self.site))}\n", AUTHORIZE,
                'names_put() { local tmp; tmp=$(mktemp "$1.XXXXXX"); cat > "$tmp"; chmod "$2" "$tmp"; '
                'if cmp -s "$tmp" "$1"; then rm -f "$tmp"; else mv -f "$tmp" "$1"; fi; }\n',
                f'[ -x "$NAMES_DIR/keeper" ] || die "no names keeper; run tn control apply {region.name}"\n',
                f"PEERS={shlex.quote(' '.join(p.name for p, _ in peers))}\n",
                'for f in "$NAMES_DIR"/peers/*.conf; do\n'
                '  [ -f "$f" ] || continue\n'
                '  p=$(basename "$f" .conf)\n'
                '  case " $PEERS " in *" $p "*) ;; *) rm -f "$f" "$NAMES_STATE/$p.tsv"; '
                'echo "names: $p is no longer a peer" ;; esac\n'
                'done\n']
        known = []
        for other, how in peers:
            conf = f"prefix={other.ipv4_prefix}\nalias={other.alias_net}\n"
            if how:
                target, port = how
                conf += f"target={target}\nport={port}\n"
                host = target.split("@", 1)[1]
                where = host if str(port) == "22" else f"[{host}]:{port}"
                known += [f"{where} {k}" for k in seen[other.name].hostkeys]
            body.append(_heredoc(f"$NAMES_DIR/peers/{other.name}.conf", "0644", conf))
            hosts = "".join(f"{n} {ip}\n" for n, ip in _hosts(seen[other.name].nodes, other))
            body.append(_heredoc(f"$NAMES_STATE/{other.name}.tsv", "0644", hosts))
        body.append(_heredoc("$NAMES_DIR/known_hosts", "0644", "".join(f"{k}\n" for k in known)))
        user = self.ssh_view(region.control_host).get("user", "root")
        allowed = []
        for other, _how in peers:
            calls_here = {p.name: how for p, how in self.peers(other, seen, skip_lines)}.get(region.name)
            key = (seen[other.name].key or "").split()
            if calls_here and len(key) >= 2:
                run = f"{KEEPER} exchange {other.name}" if user == "root" else f"sudo -n {KEEPER} exchange {other.name}"
                allowed.append(f'restrict,command="{run}" {key[0]} {key[1]} {names_tag(self.site)} peer={other.name}')
        body.append(f"names_authorize {shlex.quote(user)} <<'TN_EOF'\n" + "".join(f"{a}\n" for a in allowed) + "TN_EOF\n")
        body.append(f'"$NAMES_DIR/keeper" local\nsystemctl start {KEEPER_UNIT}.timer\n')
        return "".join(body)

    def sync(self, skip_lines=(), tolerant=False, gone=()):
        """Every region's names, from every region's nodes. A control host with a keeper gets its
        peers and their lists, and keeps them fresh from then on; one without gets the records."""
        seen, unknown = self.peek(tolerant, gone)
        nodes = {name: p.nodes for name, p in seen.items()}
        for name in list(seen):
            r = self.site.regions[name]
            waiting = [o.control_host for _ln, o in render.line_peers(self.site, r, skip_lines) if o.name in unknown]
            if waiting:
                # Its peer's names are not known now; what it has stays until `tn dns sync` runs.
                self.out(f"    {r.control_host} ({name}): left as it is until {', '.join(waiting)} answers; "
                         "then run `tn dns sync`")
                del seen[name]
        for name, p in seen.items():
            r = self.site.regions[name]
            recs, skipped = records(self.site, r, nodes, skip_lines)
            self.out(f"    {r.control_host} ({name}): {len(recs)} name(s) from other regions"
                     + (", kept by its keeper" if p.keeper else ""))
            for s in skipped:
                self.out(f"      skipped {s}")
            self._on_control(r, self.keeper_body(r, seen, skip_lines) if p.keeper else write(recs), echo=True)
        for name in seen:
            r = self.site.regions[name]
            called = [other.control_host for other, how in self.peers(r, seen, skip_lines) if how]
            if not called:
                continue
            result = self._on_control(r, f'"{KEEPER}" run 2>&1\n', check=False)
            if result.rc == 0:
                self.out(f"    ✓ {r.control_host} swaps names with {', '.join(called)} every {KEEPER_MINUTES} minute(s)")
            else:
                for line in result.output.strip().splitlines() or ["no answer"]:
                    self.out(f"    ✗ {r.control_host}: {line}")
        for name, p in seen.items():
            r = self.site.regions[name]
            if p.keeper and not seen[name].akf:
                self.out(f"    note: sshd on {r.control_host} does not read ~/.ssh/authorized_keys; "
                         "other regions cannot call it to swap names")

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


def _hosts(nodes, region):
    """[(name, IPv4)] of a region's nodes, as the keeper lists them."""
    out = []
    for n in nodes:
        name, ip = str(n.get("given_name", "")).lower(), node_ipv4(n, region)
        if name and ip:
            out.append((name, ip))
    return out
