"""Find the firewall chains that would drop a line's forwarded traffic, and the
narrow accept rules that let it through.

Any host can carry its own firewall: an nftables table with `policy drop` on the
forward hook, Docker's or ufw's `FORWARD DROP` (iptables-nft), or legacy iptables.
A packet is forwarded only if every forward base chain accepts it, so tailnet-ops
inserts, at the top of each chain that could drop, two rules that accept traffic
between the tunnel and tailscale0, tagged with a comment. Nothing else in those
chains changes, and rollback deletes exactly the tagged rules.
"""

import json
import re
import shlex
from dataclasses import dataclass

TAILSCALE = "tailscale0"


@dataclass(frozen=True)
class Target:
    kind: str     # "nft", "iptables" (iptables-nft tables) or "iptables-legacy"
    family: str
    table: str
    chain: str
    reason: str

    def label(self):
        if self.kind == "nft":
            return f"nft {self.family} {self.table} {self.chain}"
        return f"{self.kind} {self.chain}"


def _drops(rule):
    for expr in rule.get("expr") or []:
        if isinstance(expr, dict) and ("drop" in expr or "reject" in expr):
            return True
    return False


# iptables-nft keeps its tables as `ip filter` / `ip6 filter` with upper-case chain names;
# rules there are best managed with iptables itself so ufw and Docker keep reading them.
def _iptables_nft(family, table, chain):
    return family in ("ip", "ip6") and table == "filter" and chain.isupper()


def blocking_targets(nft_json, legacy_forward="", own_tables=()):
    """Chains on the IPv4 forward path that drop by policy or by rule."""
    try:
        items = json.loads(nft_json).get("nftables", []) if nft_json.strip() else []
    except ValueError:
        items = []
    chains, rules = {}, {}
    for item in items:
        if "chain" in item:
            c = item["chain"]
            if c.get("hook") == "forward" and c.get("family") in ("ip", "inet"):
                chains[(c["family"], c["table"], c["name"])] = c
        elif "rule" in item:
            r = item["rule"]
            rules.setdefault((r.get("family"), r.get("table"), r.get("chain")), []).append(r)
    out = []
    for key, c in sorted(chains.items()):
        family, table, name = key
        if table in own_tables:
            continue
        reasons = []
        if c.get("policy") == "drop":
            reasons.append("policy drop")
        if any(_drops(r) for r in rules.get(key, [])):
            reasons.append("drop rules")
        if reasons:
            kind = "iptables" if _iptables_nft(family, table, name) else "nft"
            out.append(Target(kind, family, table, name, " and ".join(reasons)))
    lines = legacy_forward.splitlines()
    if lines and (lines[0].strip() == "-P FORWARD DROP" or any(re.search(r"-j (DROP|REJECT)\b", ln) for ln in lines)):
        out.append(Target("iptables-legacy", "ip", "filter", "FORWARD",
                          "policy DROP" if lines[0].strip() == "-P FORWARD DROP" else "DROP rules"))
    return out


def allow_script(line_name, iface, targets, mark=None):
    """A self-contained script: `add` (idempotent), `del`, `check`. Run by wg-quick and a timer.
    `mark` becomes the second line, which tells rollback the file is ours."""
    comment = f"tailnet-ops line={line_name}"
    pairs = [(iface, TAILSCALE), (TAILSCALE, iface)]
    add, delete, check = [], [], []
    for t in targets:
        if t.kind == "nft":
            where = f"{t.family} {shlex.quote(t.table)} {shlex.quote(t.chain)}"
            check.append(f"nft list chain {where} 2>/dev/null | grep -qF {shlex.quote(comment)}")
            add.append(f"if nft list chain {where} >/dev/null 2>&1 && ! nft list chain {where} | grep -qF "
                       f"{shlex.quote(comment)}; then")
            for i, o in pairs:
                add.append(f'  nft insert rule {where} iifname "{i}" oifname "{o}" counter accept comment "{comment}"')
            add.append("fi")
            delete.append(f"for h in $(nft -a list chain {where} 2>/dev/null | grep -F {shlex.quote(comment)} "
                          "| sed -n 's/.*# handle \\([0-9]*\\).*/\\1/p'); do")
            delete.append(f"  nft delete rule {where} handle \"$h\"")
            delete.append("done")
        else:
            cmd = "iptables-legacy" if t.kind == "iptables-legacy" else "iptables"
            for i, o in pairs:
                spec = f'-i {i} -o {o} -m comment --comment {shlex.quote(comment)} -j ACCEPT'
                check.append(f"{cmd} -C {t.chain} {spec} 2>/dev/null")
                add.append(f"{cmd} -C {t.chain} {spec} 2>/dev/null || {cmd} -I {t.chain} 1 {spec}")
                delete.append(f"while {cmd} -D {t.chain} {spec} 2>/dev/null; do :; done")
    body = [
        "#!/bin/sh",
        *([f"# {mark}"] if mark else []),
        f"# {comment}: accept forwarded traffic between {iface} and {TAILSCALE} in the chains below,",
        "# which would otherwise drop it. Run by wg-quick (PostUp add, PostDown del) and by a timer",
        "# that puts the rules back if another tool reloads its firewall.",
        *[f"#   {t.label()}: {t.reason}" for t in targets],
        "case \"$1\" in",
        "add)",
        *[f"  {x}" for x in (add or [":"])],
        "  ;;",
        "del)",
        *[f"  {x}" for x in (delete or [":"])],
        "  ;;",
        "check)",
        *[f"  {x} || exit 1" for x in check],
        "  ;;",
        "*) echo \"usage: $0 add|del|check\" >&2; exit 2 ;;",
        "esac",
    ]
    return "\n".join(body) + "\n"
