"""tn: quick, private, self-hosted Headscale networks. Every command plans first."""

import argparse
import datetime
import sys
from pathlib import Path

from . import VERSION, init, remote, site as sitemod
from .control import Deployment
from .join import Join
from .line import Line
from .procedure import StepError
from .redact import Redactor, identity

EPILOG = """Site directory: --site DIR, else $TN_SITE, else ~/.config/tailnet-ops.
Nothing on a server changes unless you run apply or rollback and type yes."""


class Console:
    """Prints (redacted when asked) and keeps a full log in <site>/runs/."""

    def __init__(self, redact=identity, log_path=None):
        self.redact = redact
        self.log_file = None
        if log_path is not None:
            sitemod.ensure_private_dir(log_path.parent)
            sitemod.write_private(log_path, "")
            self.log_file = open(log_path, "a")
        self.log_path = log_path

    def out(self, text=""):
        print(self.redact(str(text)), flush=True)
        self.log(text)

    def show(self, text):
        """Print without logging; for text whose full form is already in the log."""
        print(self.redact(str(text)), flush=True)

    def log(self, text):
        if self.log_file:
            self.log_file.write(f"{text}\n")
            self.log_file.flush()

    def close(self):
        if self.log_file:
            self.log_file.close()


def run_log(site, kind, region=None):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-{kind}" + (f"-{region}" if region else "") + ".log"
    return site.runs_dir / name


def load_site(args):
    directory = sitemod.resolve_dir(args.site)
    return sitemod.load(directory, known_host=remote.known_alias)


def cmd_site_check(args):
    directory = sitemod.resolve_dir(args.site)
    problems = sitemod.check_dir(directory)
    try:
        site = sitemod.load(directory, known_host=remote.known_alias, check_permissions=False)
    except sitemod.SiteError as e:
        problems += e.problems
        site = None
    redact = Redactor(site) if args.redact and site else (Redactor() if args.redact else identity)
    if problems:
        print(f"{directory / sitemod.SITE_FILE}: {len(problems)} problem(s)", file=sys.stderr)
        for p in problems:
            print(f"  {redact(p)}", file=sys.stderr)
        return 1
    print(redact(f"{directory / sitemod.SITE_FILE}: ok"))
    for r in site.regions.values():
        print(redact(f"  region {r.name}: {r.control_host} -> {r.server_url}, prefix {r.ipv4_prefix}, "
                     f"DERP {r.derp_region_id}, checked from {r.check_from}"))
    for ln in site.lines:
        print(redact(f"  line {ln.name}: {ln.initiator} -> {ln.responder} ({ln.responder_entry_ipv4})"
                     f"{', one-way' if ln.one_way else ''}"))
    for h in site.host_settings.values():
        parts = [f"tailscale_port {h.tailscale_port}/udp" if h.tailscale_port else "",
                 f"netfilter_mode {h.netfilter_mode}" if h.netfilter_mode else ""]
        print(redact(f"  host {h.name}: {', '.join(p for p in parts if p) or 'no settings'}"))
    return 0


def _deployment(args, kind):
    site = load_site(args)
    console = Console(Redactor(site) if args.redact else identity, run_log(site, kind, args.region))
    runner = remote.SSHRunner(out=console.out, log=console.log)
    return Deployment(site, args.region, runner=runner, out=console.out), console


def show_plan(procedure, console, full, checks=None):
    """Print the short plan (or the full one with --full); the log always gets the full plan."""
    text, _digest = procedure.plan_text()
    console.log(text)
    console.show(text if full else procedure.summary_text(checks))
    saved = "in the site's runs/ directory" if console.redact is not identity else f"to {console.log_path}"
    console.out(f"Full plan saved {saved}. Nothing was changed.")
    return 0


def cmd_control(args):
    dep, console = _deployment(args, args.action)
    try:
        if args.action == "plan":
            return show_plan(dep, console, args.full)
        if args.action == "apply":
            return dep.apply(yes=args.yes)
        if args.action == "rollback":
            return dep.rollback(yes=args.yes)
        if args.action == "verify":
            return dep.verify()
        if args.action == "preflight":
            return dep.preflight()
    finally:
        console.close()
    return 2


def cmd_join(args):
    return run_checked(args, "join", args.host, lambda site, runner, out: Join(site, args.host, runner=runner, out=out))


def cmd_line(args):
    return run_checked(args, "line", args.line, lambda site, runner, out: Line(site, args.line, runner=runner, out=out))


def cmd_line_list(args):
    site = load_site(args)
    redact = Redactor(site) if args.redact else identity
    if not site.lines:
        print("No lines in site.toml. Add [[lines]] (see examples/site.example.toml) or run tn init.")
        return 0
    rows = [("Line", "Ends", "Entry", "Tunnel", "Keepalive", "Priority")]
    for ln in sorted(site.lines, key=lambda ln: ln.priority):
        ends = f"{ln.initiator} → {ln.responder}" + (" (one-way)" if ln.one_way else "")
        entry = f"{ln.responder_entry_ipv4}:{ln.port}" if ln.port else f"{ln.responder_entry_ipv4} (no port)"
        if ln.tunnel_ipv4:
            i_ip, r_ip = ln.tunnel_addresses
            tunnel = f"{ln.interface} {i_ip} ⇄ {r_ip}"
        else:
            tunnel = "not set"
        rows.append((ln.name, ends, entry, tunnel, f"{ln.keepalive_seconds} s", str(ln.priority)))
    rows = [tuple(redact(cell) for cell in r) for r in rows]
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  " + "  ".join(cell.ljust(w) for cell, w in zip(r, widths)).rstrip())
    print(redact(f"\nPlan one with: tn line plan <line>"))
    return 0


def run_checked(args, kind, name, make):
    """plan (with read-only checks unless --offline), apply, verify and rollback for join and line."""
    site = load_site(args)
    console = Console(Redactor(site) if args.redact else identity, run_log(site, f"{kind}-{args.action}", name))
    runner = remote.SSHRunner(out=console.out, log=console.log)
    try:
        job = make(site, runner, console.out)
        if args.action == "plan":
            checks = None if args.offline else job.check()
            if checks is not None:
                console.log(f"checks: {checks}")
            show_plan(job, console, args.full, checks)
            return 1 if checks and checks["fails"] else 0
        if args.action == "apply":
            return job.apply(yes=args.yes)
        if args.action == "rollback":
            return job.rollback(yes=args.yes)
        if args.action == "verify":
            return job.verify()
        if args.action == "preflight" and hasattr(job, "preflight"):
            return job.preflight()
    finally:
        console.close()
    return 2


def cmd_status(args):
    dep, console = _deployment(args, "status")
    try:
        return dep.status()
    finally:
        console.close()


def cmd_init(args):
    directory = sitemod.resolve_dir(args.site)
    target = Path(args.out).expanduser().absolute() if args.out else directory / sitemod.SITE_FILE
    tree = sitemod.git_work_tree(target.parent)
    if tree is not None:
        print(f"refusing: {target.parent} sits inside the Git work tree {tree}", file=sys.stderr)
        return 1
    print("tn init asks only what SSH cannot tell. Everything else comes from read-only SSH checks.")
    asker = init.Asker()
    answers = init.ask_answers(asker)
    hosts = init.hosts_in(answers)
    hostnames = {h: remote.ssh_hostname_ipv4(h) for h in hosts}
    for r in answers["regions"]:
        if hostnames.get(r["control_host"]) is None:
            r["public_ipv4"] = asker.ask(f"  {r['control_host']}: public IPv4 (its SSH HostName is not an address)",
                                         None, init._check_ipv4)
    for ln in answers["lines"]:
        if hostnames.get(ln["initiator"]) is None:
            ln["initiator_public_ipv4"] = asker.ask(f"  {ln['initiator']}: public IPv4", None, init._check_ipv4)
    runner = remote.SSHRunner()
    facts = {}
    print("\nReading facts over SSH (read-only):")
    for h in hosts:
        try:
            result = runner.run(h, init.FACTS_SCRIPT, echo=False)
        except remote.RemoteError as e:
            print(f"  {h}: {e}", file=sys.stderr)
            return 1
        facts[h] = init.parse_facts(result.output)
    data, notes, comments = init.derive(answers, facts, hostnames)

    redact = identity
    if args.redact:
        redact = Redactor(sitemod.parse(data, known_host=lambda h: True))
    for h in hosts:
        for line in init.describe(h, facts[h], hostnames.get(h)):
            print(redact(f"  {line}"))
    if notes:
        print("\nNotes:")
        for n in notes:
            print(redact(f"  - {n}"))
    text = init.to_toml(data, comments, today=datetime.date.today().isoformat())
    print(f"\nRebuilt {sitemod.SITE_FILE}:\n")
    print(redact(text))

    try:
        sitemod.parse(data, known_host=remote.known_alias)
    except sitemod.SiteError as e:
        print("The result does not pass `tn site check`:", file=sys.stderr)
        for p in e.problems:
            print(f"  {redact(p)}", file=sys.stderr)
        return 1

    if target.exists():
        existing = sitemod.read_toml(target)
        diffs = init.differences(existing, data)
        if not diffs:
            print(f"Same settings as the existing {target}. Nothing written.")
            return 0
        print(f"Differs from the existing {target} (not overwritten; use --out PATH to write elsewhere):")
        for d in diffs:
            print(redact(f"  {d}"))
        return 1
    if not args.yes:
        if input(f"Type yes to write {target}: ").strip() != "yes":
            print("Nothing written.")
            return 1
    sitemod.ensure_private_dir(target.parent)
    sitemod.write_private(target, text)
    print(f"Wrote {target} (mode 0600).")
    return 0


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--site", metavar="DIR", default=argparse.SUPPRESS, help="site directory")
    common.add_argument("--redact", action="store_true", default=argparse.SUPPRESS,
                        help="replace addresses, host names and keys with stable placeholders")

    ap = argparse.ArgumentParser(prog="tn", description=__doc__, epilog=EPILOG, parents=[common],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"tailnet-ops {VERSION}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", parents=[common], help="write site.toml from a few answers plus SSH facts")
    p.add_argument("--out", metavar="PATH", help="write here instead of <site>/site.toml")
    p.add_argument("--yes", action="store_true", help="write without asking")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("site", help="site.toml commands")
    s = p.add_subparsers(dest="site_command", required=True)
    c = s.add_parser("check", parents=[common], help="validate the site directory and site.toml")
    c.set_defaults(func=cmd_site_check)

    p = sub.add_parser("control", help="deploy Headscale for a region")
    s = p.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("plan", "print every step with its exact remote script and rollback; changes nothing"),
        ("preflight", "run step 1 only (read-only)"),
        ("apply", "run the steps; asks for yes"),
        ("verify", "check /health, DERP and STUN from the checker host (read-only)"),
        ("rollback", "undo the steps in reverse; asks for yes"),
    ):
        c = s.add_parser(action, parents=[common], help=help_text)
        c.add_argument("region")
        if action == "plan":
            c.add_argument("--full", action="store_true", help="print every remote script and rollback")
        if action in ("apply", "rollback"):
            c.add_argument("--yes", action="store_true", help="do not ask")
        c.set_defaults(func=cmd_control)

    p = sub.add_parser("join", help="add a host to its region's tailnet")
    s = p.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("plan", "print every step with its exact remote script and rollback; changes nothing"),
        ("preflight", "run step 1 only (read-only)"),
        ("apply", "install Tailscale and join; asks for yes"),
        ("verify", "check the host is in its tailnet with the right tags (read-only)"),
        ("rollback", "leave the tailnet and remove what join added; asks for yes"),
    ):
        c = s.add_parser(action, parents=[common], help=help_text)
        c.add_argument("host", help="SSH alias")
        if action == "plan":
            c.add_argument("--full", action="store_true", help="print every remote script and rollback")
            c.add_argument("--offline", action="store_true", help="skip the read-only checks over SSH")
        if action in ("apply", "rollback"):
            c.add_argument("--yes", action="store_true", help="do not ask")
        c.set_defaults(func=cmd_join)

    p = sub.add_parser("line", help="the WireGuard tunnel of a dedicated line")
    s = p.add_subparsers(dest="action", required=True)
    c = s.add_parser("list", parents=[common], help="list the site's lines (reads site.toml only)")
    c.set_defaults(func=cmd_line_list)
    for action, help_text in (
        ("plan", "check both ends (read-only), then print the steps and how each is undone"),
        ("apply", "make keys, start the tunnel on both ends; asks for yes"),
        ("verify", "ping across the tunnel both ways (read-only)"),
        ("rollback", "stop the tunnel and remove its files on both ends; asks for yes"),
    ):
        c = s.add_parser(action, parents=[common], help=help_text)
        c.add_argument("line", help="line name from site.toml")
        if action == "plan":
            c.add_argument("--full", action="store_true", help="print every remote script and rollback")
            c.add_argument("--offline", action="store_true", help="skip the read-only checks over SSH")
        if action in ("apply", "rollback"):
            c.add_argument("--yes", action="store_true", help="do not ask")
        c.set_defaults(func=cmd_line)

    p = sub.add_parser("status", parents=[common], help="list the nodes of a region (read-only)")
    p.add_argument("region")
    p.set_defaults(func=cmd_status)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.site = getattr(args, "site", None)
    args.redact = getattr(args, "redact", False)
    try:
        return args.func(args)
    except sitemod.SiteError as e:
        print("site problem:", file=sys.stderr)
        for p in e.problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    except StepError as e:
        print(f"tn: {e}", file=sys.stderr)
        return 1
    except (ValueError, KeyboardInterrupt) as e:
        print(f"tn: {e or 'interrupted'}", file=sys.stderr)
        return 1
