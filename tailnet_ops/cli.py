"""tn: quick, private, self-hosted Headscale networks. Every command plans first."""

import argparse
import datetime
import sys
from pathlib import Path

from . import VERSION, init, pins, remote, site as sitemod, targets, tui
from .control import Deployment
from .join import Join
from .line import Line
from .procedure import StepError
from .redact import Redactor, identity
from .site import dns_label

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
    redact = redactor(site) if args.redact and site else (Redactor() if args.redact else identity)
    if problems:
        print(f"{directory / sitemod.SITE_FILE}: {len(problems)} problem(s)", file=sys.stderr)
        for p in problems:
            print(f"  {redact(p)}", file=sys.stderr)
        return 1
    print(redact(f"{directory / sitemod.SITE_FILE}: ok"))
    for r in site.regions.values():
        print(redact(f"  region {r.name}: {r.control_host} -> {r.server_url}, prefix {r.ipv4_prefix}, "
                     f"DERP {r.derp_region_id}, checked from {r.check_from}"
                     + (f", phone entry udp {r.entry_port}" if r.entry_port else "")))
    for ln in site.lines:
        print(redact(f"  line {ln.name}: {ln.initiator} -> {ln.responder} ({ln.responder_entry_ipv4})"
                     f"{', one-way' if ln.one_way else ''}"))
    for h in site.host_settings.values():
        parts = [f"region {h.region}" if h.region else "",
                 f"tailscale_port {h.tailscale_port}/udp" if h.tailscale_port else "",
                 f"netfilter_mode {h.netfilter_mode}" if h.netfilter_mode else ""]
        print(redact(f"  host {h.name}: {', '.join(p for p in parts if p) or 'no settings'}"))
    if site.joined:
        print(redact(f"  joined by tn join: {', '.join(sorted(site.joined))} (tn join list)"))
    return 0


def _deployment(args, kind):
    site = load_site(args)
    console = Console(redactor(site) if args.redact else identity, run_log(site, kind, args.region))
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


JOIN_ACTIONS = ("plan", "preflight", "apply", "verify", "rollback", "list")


def detect_os(host):
    """`uname -s` over SSH (read-only): "macos", "linux", or None when the host does not answer."""
    result = remote.SSHRunner(out=lambda s: None).run(host, "uname -s\n", check=False, echo=False)
    words = result.output.split()
    return {"Darwin": "macos", "Linux": "linux"}.get(words[-1] if words else "")


def join_options(args):
    """The resolve() keyword arguments that the command line gives."""
    role = "personal" if args.personal else ("server" if args.server else None)
    return {"name": args.name, "role": role, "region": args.region, "os_name": args.os, "port": args.port,
            "netfilter_mode": args.netfilter, "accept_dns": None if args.dns is None else args.dns == "on"}


def cmd_join(args):
    site = load_site(args)
    action, host = args.action, args.host
    if action is not None and action not in JOIN_ACTIONS:
        action, host = None, action          # `tn join <host>`: ask for the rest
    if action == "list":
        return join_list(site, args)
    options = join_options(args)
    ui = tui.UI()
    here = None
    if action is None:
        if not ui.tty:
            raise ValueError("without a terminal, give an action: tn join plan|apply|verify|rollback [host] [options]")
        print(ui.bold("tn join") + ui.dim(" · add a machine to the tailnet. Nothing changes until you type yes.\n"))
        answers = targets.ask(site, ui, remote.ssh_aliases(), host=host, given={**options, "app": args.app},
                              pick=args.host is None, detect_os=None if args.offline else detect_os)
        host = answers.pop("host")
        args.app = answers.pop("app", False) or args.app
        here = answers.pop("here", None)
        options.update({k: v for k, v in answers.items() if v is not None})
    if not args.app:
        rec_name, rec = targets.find_record(site, host)
        if (rec or {}).get("app"):           # joined with the app: verify and rollback know it from the record
            args.app, here, host = True, bool(rec.get("here")), None if rec.get("here") else rec_name
    if args.app:
        if here is None:
            here = host is None
        name = options.get("name") or (None if here else host)
        if name is None:
            rec_name, rec = targets.find_record(site, None)
            name = rec_name if (rec or {}).get("app") else targets.this_machine_name()
        _n, rec = targets.find_record(site, name)
        return join_app(site, args, action, name, options.get("region") or (rec or {}).get("region"), ui, here)
    target = targets.resolve(site, host, **options, detect_os=None if args.offline else detect_os)
    console = Console(redactor(site) if args.redact else identity,
                      run_log(site, f"join-{action or 'ask'}", target.name))
    runner = remote.SSHRunner(out=console.out, log=console.log, local_hosts=[target.alias] if target.local else ())
    job = Join(site, runner=runner, out=console.out, member=target)
    job.remember = lambda m: targets.remember(site, m)
    job.forget = lambda m: targets.forget(site, m)
    if ui.tty:
        job.ask_code = code_asker(ui)
        job.ask_ca = ca_asker(ui)
    try:
        if action is None:
            return join_asked(job, console, ui, target, offline=args.offline)
        return run_job(job, console, args, action)
    finally:
        console.close()


def code_asker(ui):
    """When this machine cannot log in to a control host: show how to make a link code elsewhere,
    then read the pasted code without echo. The code is never printed or logged."""
    from .join import code_problem

    def ask(region, commands):
        ui.say()
        ui.warn(f"This machine cannot log in to {region.control_host}, the Headscale of {region.name}.")
        ui.say(f"Make a single-use link code, valid {pins.JOIN_CODE_EXPIRY}, with one of these, then paste it here.")
        for where, command in commands:
            ui.say(f"  {where}:")
            ui.command(command)
        return ui.secret(f"Link code for {region.name}", check=code_problem)
    return ask


def ca_asker(ui):
    """When there is no site CA here and no control host gives it: show how to print ca.crt
    elsewhere, then read the pasted certificate or the path of a copy. None if none was usable."""
    from . import siteca

    def ask(region, why, accept):
        ui.say()
        ui.warn(f"No site CA here, and tn cannot read it from the control hosts ({why}).")
        ui.say("Print ca.crt with one of these (it is public; never copy ca.key), then paste it here, "
               "or give the path of a copy.")
        for where, command in siteca.commands(region):
            ui.say(f"  {where}:")
            ui.command(command)
        for _ in range(3):
            text = ui.pasted("Site CA certificate (paste it, or a file path)", "-----BEGIN", "-----END")
            if text and "-----BEGIN" not in text:
                try:
                    text = Path(text).expanduser().read_text()
                except (OSError, UnicodeDecodeError) as e:
                    ui.say(f"  cannot read {text}: {getattr(e, 'strerror', None) or e}")
                    continue
            pem, problem = accept(text)
            if pem:
                ui.chosen("Site CA certificate", "checked against the login servers")
                return pem
            ui.say(f"  {problem}")
        return None
    return ask


def join_app(site, args, action, name, region, ui, here=False):
    """A Mac with the Tailscale app. here: this machine, which tn sets up itself; else tn hands the
    Mac a profile and one block to paste."""
    from .appjoin import AppJoin
    if not name:
        raise ValueError("name the Mac: tn join plan <name> --app")
    if dns_label(name) != name.lower():
        raise ValueError(f"{name!r} is not a usable name; use letters, digits and '-'")
    region = region or next(iter(site.regions))
    console = Console(redactor(site) if args.redact else identity, run_log(site, f"join-{action or 'ask'}", name))
    runner = remote.SSHRunner(out=console.out, log=console.log)
    job = AppJoin(site, name, region, runner=runner, out=console.out, show=console.show, here=here)

    def remember(j):
        site.joined[j.name] = j.record()
        sitemod.write_joined(site.directory, site.joined)

    job.remember = remember
    job.forget = lambda j: targets.forget(site, j)
    if ui.tty:
        job.ask_code = code_asker(ui)
        job.ask_ca = ca_asker(ui)
    if ui.tty and not args.yes:
        job.pause = input
    later = (f"./tn join apply --app --region {job.region.name}" + ("" if name == targets.this_machine_name()
                                                                      else f" --name {name}") if here
             else f"./tn join apply {name} --app --region {job.region.name}")
    try:
        if action is None:
            return join_asked(job, console, ui, later=later, offline=args.offline)
        return run_job(job, console, args, action)
    finally:
        console.close()


def join_asked(job, console, ui, target=None, offline=False, later=None):
    """After the questions: check, show the short plan, and apply only if asked."""
    checks = None
    if not offline:
        print(ui.dim("\nChecking (read-only)…"))
        checks = job.check()
    show_plan(job, console, False, checks)
    later = later or targets.command_line(target)
    if checks and checks["fails"]:
        print(f"\nFix the problems above, then run: {later}")
        return 1
    choices = [("apply", "Apply", "install and join; you type yes to start"),
               ("full", "Show the exact scripts", "every remote script and rollback"),
               ("quit", "Quit", "nothing changes")]
    while True:
        choice = ui.select("What now?", choices)
        if choice != "full":
            break
        show_plan(job, console, True, checks)
        choices = [c for c in choices if c[0] != "full"]
    if choice == "quit":
        print(f"Nothing changed. To apply later: {later}")
        return 0
    rc = job.apply()
    print(f"\nThe same without questions: {later}")
    return rc


def join_list(site, args):
    redact = redactor(site) if args.redact else identity
    rows = [("Name", "Machine", "How", "Region", "OS")]
    for name, rec in sorted(site.joined.items()):
        machine = "Tailscale app" if rec.get("app") else (f"ssh {rec['ssh']}" if rec.get("ssh") else "this machine")
        rows.append((name, machine, rec.get("role", "server"),
                     rec.get("region", "?"), rec.get("os", "linux")))
    if len(rows) == 1:
        print("No machines joined by tn join yet, apart from the hosts in site.toml.")
    else:
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        for r in rows:
            print(redact("  " + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()))
    hosts = [h for h in site.hosts() if site.is_site_host(h)]
    print(redact(f"Hosts in site.toml join as servers of their region: {', '.join(hosts)}"))
    return 0


def redactor(site):
    """--redact for a site, covering the machines tn joined too."""
    extra = {}
    for i, (name, rec) in enumerate(sorted(site.joined.items()), 1):
        extra[name] = f"<joined{i}>"
        if rec.get("ssh"):
            extra.setdefault(rec["ssh"], f"<joined{i}>")
    return Redactor(site, extra_hosts=extra)


def cmd_line(args):
    return run_checked(args, "line", args.line, lambda site, runner, out: Line(site, args.line, runner=runner, out=out))


def cmd_line_list(args):
    site = load_site(args)
    redact = redactor(site) if args.redact else identity
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


def cmd_dns(args):
    from . import names as namesmod
    from .names import Names
    site = load_site(args)
    redact = redactor(site) if args.redact else identity
    names = Names(site, remote.SSHRunner(out=lambda s: print(redact(s))),
                  out=lambda s: print(redact(s)))
    if args.action == "stop":
        r = site.region(args.region)
        print(redact(f"  {r.control_host}: stop and remove the names keeper, its key and the keys that let other "
                     "regions call it; then every region's names are written as before the keeper"))
        if not args.yes and input(f"Type yes to remove the names keeper from {redact(r.control_host)}: ").strip() != "yes":
            print("Nothing changed.")
            return 1
        names._on_control(r, namesmod.uninstall(site, names.ssh_view(r.control_host).get("user", "root")), echo=True)
        names.sync()
        print(f"Removed. To put it back: tn control apply {r.name}")
        return 0
    if args.action == "list":
        rows = [("Region", "Name", "Short forms", "Address", "How")] + names.table()
        rows = [tuple(redact(c) for c in r) for r in rows]
        widths = [max(len(r[i]) for r in rows) for i in range(5)]
        for r in rows:
            print("  " + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
        print("\nOn devices that use MagicDNS every form works: ping <host>.<region>, <host>.<suffix>, <host>")
        return 0
    _nodes, planned = names.plan()
    for region, (recs, skipped) in planned.items():
        print(redact(f"  {region}: {len(recs)} name(s) of other regions' hosts" +
                     (f"; skipped {', '.join(skipped)}" if skipped else "")))
    if not args.yes and input("Type yes to write them to each Headscale: ").strip() != "yes":
        print("Nothing written.")
        return 1
    names.sync()
    return 0


def run_checked(args, kind, name, make):
    """plan (with read-only checks unless --offline), apply, verify and rollback for a line."""
    site = load_site(args)
    console = Console(redactor(site) if args.redact else identity, run_log(site, f"{kind}-{args.action}", name))
    runner = remote.SSHRunner(out=console.out, log=console.log)
    try:
        return run_job(make(site, runner, console.out), console, args, args.action)
    finally:
        console.close()


def run_job(job, console, args, action):
    if action == "plan":
        checks = None if args.offline else job.check()
        if checks is not None:
            console.log(f"checks: {checks}")
        show_plan(job, console, args.full, checks)
        return 1 if checks and checks["fails"] else 0
    if action == "apply":
        return job.apply(yes=args.yes)
    if action == "rollback":
        return job.rollback(yes=args.yes)
    if action == "verify":
        return job.verify()
    if action == "preflight" and hasattr(job, "preflight"):
        return job.preflight()
    return 2


def cmd_phone(args):
    from .phone import Phones
    site = load_site(args)
    redact = redactor(site) if args.redact else identity
    if args.action == "list":
        phones = Phones(site, None)
        if not site.phones:
            print("No phones yet. Add one with: tn phone add <name>")
            return 0
        rows = [tuple(redact(c) for c in r) for r in phones.rows()]
        widths = [max(len(r[i]) for r in rows) for i in range(3)]
        for r in rows:
            print("  " + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
        print(redact(f"\nFiles are in {site.phones_dir}/<phone>/."))
        return 0
    console = Console(redact, run_log(site, f"phone-{args.action}", getattr(args, "name", None)))
    phones = Phones(site, remote.SSHRunner(out=console.out, log=console.log), out=console.out)
    try:
        if args.action == "add":
            return phones.add(args.name, yes=args.yes)
        if args.action == "stop":
            return phones.stop(args.name, yes=args.yes)
        if args.action == "status":
            return phones.status()
        return phones.remove(args.name, yes=args.yes)
    except (StepError, sitemod.SiteError, remote.RemoteError, OSError, ValueError) as e:
        console.out(f"FAILED: {e}")
        return 1
    finally:
        console.close()


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
        ("preflight", "run step 1, and the phone entry's checks, only (read-only)"),
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

    p = sub.add_parser(
        "join", parents=[common], help="add a machine to the tailnet; without an action it asks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Add a machine to the tailnet: this machine, or one you reach over SSH.\n\n"
                    "  tn join                          ask which machine, how and where, then show the plan\n"
                    "  tn join plan|apply [host] ...    the same from options; no host = this machine\n"
                    "  tn join verify|rollback [host]   uses what apply recorded\n"
                    "  tn join list                     machines joined so far\n"
                    "  tn join plan|apply <name> --app  a Mac with the Tailscale app (a laptop): no SSH to it\n\n"
                    "A server joins one region with a tagged key. A personal device joins every region\n"
                    "as the owner, one Tailscale profile each (sudo tailscale switch <region>).\n"
                    "Only hosts that others use (control hosts, checkers, line ends) are in site.toml.")
    p.add_argument("action", nargs="?", metavar="action",
                   help="plan, preflight, apply, verify, rollback or list; leave out to be asked")
    p.add_argument("host", nargs="?", help="SSH alias or a joined machine's name; leave out for this machine")
    how = p.add_mutually_exclusive_group()
    how.add_argument("--personal", action="store_true", help="the owner's device, in every region")
    how.add_argument("--server", action="store_true", help="one region, tagged (the default)")
    how.add_argument("--app", action="store_true",
                     help="a Mac with the Tailscale app: a profile to install and one block to paste there")
    p.add_argument("--region", help="a server's region; where a personal device starts")
    p.add_argument("--name", help="its name in the tailnet (default: the SSH alias or this machine's name)")
    p.add_argument("--port", type=int, help=f"tailscaled's UDP port (default {pins.DEFAULT_TAILSCALE_PORT})")
    p.add_argument("--netfilter", choices=sitemod.NETFILTER_MODES, help="Linux: tailscale up --netfilter-mode")
    p.add_argument("--dns", choices=("on", "off"), help="accept MagicDNS (default: on where only the suffix goes to it)")
    p.add_argument("--os", choices=targets.OSES, help="for --offline plans of a host over SSH (found by itself otherwise)")
    p.add_argument("--full", action="store_true", help="plan: print every remote script and rollback")
    p.add_argument("--offline", action="store_true", help="plan: skip the read-only checks")
    p.add_argument("--yes", action="store_true", help="apply, rollback: do not ask")
    p.set_defaults(func=cmd_join)

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

    p = sub.add_parser("dns", help="names across regions")
    s = p.add_subparsers(dest="action", required=True)
    c = s.add_parser("list", parents=[common], help="every name as each region resolves it (read-only)")
    c.set_defaults(func=cmd_dns)
    c = s.add_parser("sync", parents=[common], help="write each region's names of other regions' hosts; asks for yes")
    c.add_argument("--yes", action="store_true", help="do not ask")
    c.set_defaults(func=cmd_dns)
    c = s.add_parser("stop", parents=[common],
                     help="remove the names keeper from a region's control host (tn control apply puts it back); asks for yes")
    c.add_argument("region")
    c.add_argument("--yes", action="store_true", help="do not ask")
    c.set_defaults(func=cmd_dns)

    p = sub.add_parser(
        "phone", help="phones: WireGuard nodes for the phone's proxy app, through each region's entry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="A phone runs one VPN at a time (its proxy app), so it reaches the tailnets through the\n"
                    "regions' phone entries (entry_port in site.toml, installed by tn control apply).\n\n"
                    "  tn phone add <name>      make its key here, add it to every entry, write its files\n"
                    "                           (again: refresh its peers, names and files)\n"
                    "  tn phone remove <name>   take it off every entry and delete its files\n"
                    "  tn phone list            the phones added so far\n"
                    "  tn phone status          each entry, its DNS and every phone's last handshake (read-only)\n"
                    "  tn phone stop <region>   remove only that region's entry (tn control apply puts it back)")
    s = p.add_subparsers(dest="action", required=True)
    c = s.add_parser("list", parents=[common], help="the phones added so far (reads the site directory only)")
    c.set_defaults(func=cmd_phone)
    c = s.add_parser("status", parents=[common],
                     help="each entry, its DNS and every phone's last handshake (read-only over SSH)")
    c.set_defaults(func=cmd_phone)
    for action, help_text in (("add", "add a phone to every entry and write its files; asks for yes"),
                              ("remove", "take a phone off every entry and delete its files; asks for yes")):
        c = s.add_parser(action, parents=[common], help=help_text)
        c.add_argument("name", help="the phone's name, e.g. iphone")
        c.add_argument("--yes", action="store_true", help="do not ask")
        c.set_defaults(func=cmd_phone)
    c = s.add_parser("stop", parents=[common],
                     help="remove the phone entry from one region's control host; asks for yes")
    c.add_argument("name", metavar="region")
    c.add_argument("--yes", action="store_true", help="do not ask")
    c.set_defaults(func=cmd_phone)

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
