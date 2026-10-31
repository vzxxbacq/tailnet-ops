"""`tn --tui`: set up or update one region's Headscale in one guided run.

0. What: Headscale and tn-agent together (every question first, then the work), or either alone.
1. Which region, and which certificate: the site CA by IP, or Let's Encrypt for a domain on
   Cloudflare. For Let's Encrypt only a Cloudflare API token is needed: the wizard looks the zone up
   and apply makes the A record itself. A change is written to site.toml, a copy kept.
2. The read-only checks (tn control preflight).
3. When Headscale runs there already: a record of its nodes (runs/), and a backup on the control host.
4. The plan; apply once you type yes; verify.
5. When the login address changed: every node tn knows moves to it, one after another, and their
   addresses are compared with the record. Until a node moves it cannot reach those that did, so
   this runs straight after the switch.

Every step that changes something asks first. Quitting leaves what is done; the end says how to undo.
"""

import datetime
import json

from . import scripts, site as sitemod
from .cloudflare import Cloudflare, CloudflareError
from .site import DNS_RE, SiteError, dns_label


def movers(site, region, nodes):
    """How each node of region moves to a new login address: [{node, target, how}], in the order to run
    them. target is what `tn join apply` takes, or None for a node tn cannot move itself."""
    known = {}
    for alias in site.hosts():
        if not site.is_site_host(alias):
            continue
        try:
            if site.host_region(alias).name == region.name:
                known[dns_label(alias)] = (alias, "server over SSH")
        except SiteError:
            continue
    for name, rec in site.joined.items():
        if rec.get("region") != region.name and rec.get("role") != "personal":
            continue
        if rec.get("app") and not rec.get("here"):
            known[name] = (None, f"the Tailscale app on another Mac: tn join apply {name} --app, then paste there")
        elif rec.get("app"):
            known[name] = (name, "the Tailscale app on this Mac")
        else:
            known[name] = (name, "personal device over SSH" if rec.get("role") == "personal" else "server over SSH")

    def rank(item):
        node, (target, how) = item
        if node == dns_label(region.control_host):
            return (0, node)
        if node == dns_label(region.check_from):
            return (1, node)
        return (2 if target and "server" in how else 3 if target else 4, node)

    plan = [(n["name"], known.get(n["name"], (None, "not set up by tn: log it in to the new address by hand")))
            for n in nodes]
    return [{"node": node, "target": target, "how": how} for node, (target, how) in sorted(plan, key=rank)]


def nodes_from(output):
    """[{id, name, ipv4, online}] from `headscale nodes list -o json`."""
    out = []
    for n in json.loads(output or "[]") or []:
        ips = n.get("ip_addresses") or []
        out.append({"id": n.get("id"), "name": n.get("given_name") or n.get("name"),
                    "ipv4": next((ip for ip in ips if "." in ip), None), "online": bool(n.get("online"))})
    return sorted(out, key=lambda n: n["name"] or "")


def compare(before, after):
    """[(name, before ipv4, after ipv4, problem or None)] by node id."""
    now = {n["id"]: n for n in after}
    rows = []
    for b in before:
        a = now.get(b["id"])
        if a is None:
            rows.append((b["name"], b["ipv4"], "—", "gone from Headscale"))
        elif a["ipv4"] != b["ipv4"]:
            rows.append((b["name"], b["ipv4"], a["ipv4"], "its address changed"))
        elif not a["online"]:
            rows.append((b["name"], b["ipv4"], a["ipv4"], "offline"))
        else:
            rows.append((b["name"], b["ipv4"], a["ipv4"], None))
    return rows


def _cert(region):
    return "site CA" if region.site_ca else "Let's Encrypt"


def _table(rows):
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return ["  " + "  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]


def policy_owns(tag):
    """Read-only, on the control host: whether Headscale's policy file names tag."""
    return (f"if grep -qF '\"{tag}\"' \"$ETC/policy.hujson\" 2>/dev/null; then echo 'TN-FACT agent_tag=yes'; "
            "else echo 'TN-FACT agent_tag=no'; fi\n")


class Wizard:
    """open_deployment(site, region, token) -> (Deployment, Console); open_agent(site, region, token) ->
    (AgentDeploy, Console); tn(argv) -> rc runs a tn command (for tn join apply); load() -> Site reads the
    site directory again; clipboard(text) -> True if the text is on the clipboard."""

    def __init__(self, ui, load, open_deployment, tn, ask_token=None, cloudflare=Cloudflare, open_agent=None,
                 clipboard=lambda text: False, now=datetime.datetime.now):
        self.ui = ui
        self.load = load
        self.open_deployment = open_deployment
        self.open_agent = open_agent
        self.tn = tn
        self.ask_token = ask_token      # (quiet=False) -> the Cloudflare API token, or None
        self.cloudflare = cloudflare
        self.clipboard = clipboard
        self.now = now
        self.edited = False      # site.toml was changed in this run
        self.applied = False     # tn control apply ran to the end in this run
        self.verified = False    # and tn control verify passed after it
        self.token = None

    def run(self):
        ui = self.ui
        ui.say(ui.bold("tn --tui") + ui.dim(" · set up a region's Headscale, or tn-agent beside it. Each change asks "
                                            "first.\n"))
        site = self.load()
        tasks = [
            ("control", "Headscale only", "a region's control plane: certificate, checks, apply, moving its nodes"),
            ("agent", "tn-agent only", "MCP for Agents beside a Headscale that has a domain already"),
        ]
        if self.open_agent:
            tasks.insert(0, ("all", "Headscale and tn-agent", "both, in one run: every question first, then the work"))
        task = ui.select("Set up", tasks)
        if task == "agent":
            return self._agent(site)
        name = ui.select("Region", [(r.name, r.name, f"{r.control_host} · {r.server_url} · {_cert(r)}")
                                    for r in site.regions.values()])
        if task == "all":
            return self._all(site, name)
        old_url = site.region(name).server_url
        site = self._certificate(site, name)
        if site is None:
            return 0
        dep, console = self.open_deployment(site, name, self.token)
        try:
            return self._deploy(site, site.region(name), dep, console, old_url)
        finally:
            console.close()

    def _all(self, site, name):
        """Headscale and tn-agent for one region: the questions first, one site.toml change, then the work.
        tn-agent's name is in site.toml before tn control apply, so its policy owns the agent tag at once."""
        ui, r = self.ui, site.region(name)
        old_url = r.server_url
        domain = r.domain
        if not domain:
            ui.say(f"tn-agent needs the login server on a domain, so {name} switches to Let's Encrypt.")
            domain = ui.text("Domain for the login server", check=self._domain_check(site, r))
        zone = self._cloudflare_ready(domain, r)
        if zone is None:
            return 0
        values, notes = {}, []
        if domain != r.domain:
            values["domain"] = domain
            notes += [f"The login address becomes https://{domain}:{r.port}. Nodes already in {name} move to it",
                      "after apply; until a node moves, it cannot reach the nodes that did, so they move one after another."]
        agent_domain = r.agent_domain
        if not agent_domain:
            agent_domain = self._agent_name(site, r, zone, also=domain)
            if agent_domain is None:
                return 0
            values["agent_domain"] = agent_domain
            notes.append(f"tn-agent will answer at https://{agent_domain} through a Cloudflare tunnel; nothing opens "
                         f"on {r.control_host}.")
        if values:
            site = self._write_values(site, name, values, notes)
            if site is None:
                return 0
        r = site.region(name)
        ui.say(ui.bold(f"\n1/2 · Headscale for {name}"))
        dep, console = self.open_deployment(site, name, self.token)
        try:
            rc = self._deploy(site, r, dep, console, old_url)
        finally:
            console.close()
        if not self.verified:
            return rc
        ui.say(ui.bold(f"\n2/2 · tn-agent for {name}"))
        return self._agent_install(site, r) or rc

    # --- 1. the certificate -----------------------------------------------------------

    def _certificate(self, site, name):
        ui, r = self.ui, site.region(name)
        if r.site_ca:
            options = [("keep", "Keep the site CA", f"login by IP: {r.server_url}; devices trust the site CA"),
                       ("le", "Switch to Let's Encrypt", "login by a domain on Cloudflare; devices need no site CA")]
        else:
            options = [("keep", f"Keep Let's Encrypt for {r.domain}", r.server_url),
                       ("ca", "Switch back to the site CA", f"login by IP: https://{r.public_ipv4}:{r.port}")]
        choice = ui.select("Certificate", options)
        if choice == "keep":
            return site
        if choice == "le":
            domain = ui.text("Domain for the login server", check=self._domain_check(site, r))
            if not self._cloudflare_ready(domain, r):
                return None
            value = domain
        else:
            value = None
        url = f"https://{value or r.public_ipv4}:{r.port}"
        return self._write_values(site, name, {"domain": value}, [
            f"The login address becomes {url}. Nodes already in {name} move to it at the end of this run;",
            "until a node moves, it cannot reach the nodes that did, so the run moves them one after another."])

    def _domain_check(self, site, r):
        others = {x for o in site.regions.values() for x in (o.domain, o.agent_domain) if x and o.name != r.name}

        def check(value):
            if not DNS_RE.match(value):
                return "a DNS name such as hs-" + r.name + ".example.com"
            if value == r.base_domain or value.endswith("." + r.base_domain):
                return f"it sits inside the MagicDNS suffix {r.base_domain}; use a public name"
            if value in others:
                return "another region uses it"
            return None
        return check

    def _write_values(self, site, name, values, notes=()):
        """Set keys in [regions.<name>] of site.toml (None removes one), once asked, keeping a copy; the site
        read again, or None."""
        ui = self.ui
        path = site.directory / sitemod.SITE_FILE
        text = path.read_text()
        new = text
        ui.say()
        for key, value in values.items():
            new = sitemod.set_region_value(new, name, key, value)
            ui.say(f"site.toml, [regions.{name}]: " + (f'{key} = "{value}"' if value else f"remove the {key} line"))
        for line in notes:
            ui.say(line)
        if not ui.confirm("Write it to site.toml? A copy goes to site.toml.bak", default=True):
            ui.say("Nothing changed.")
            return None
        sitemod.write_private(path.with_name(sitemod.SITE_FILE + ".bak"), text)
        sitemod.write_private(path, new)
        self.edited = True
        try:
            return self.load()
        except SiteError:
            sitemod.write_private(path, text)
            raise

    def _cloudflare_ready(self, domain, r):
        """Ask for the token once and look at Cloudflare (read-only): the zone, and the A record apply makes.
        The zone, or None (and why) when it cannot go on."""
        ui = self.ui
        self.token = self.token or (self.ask_token() if self.ask_token else None)
        if not self.token:
            ui.say("Nothing changed: Let's Encrypt here needs a Cloudflare API token ($CF_Token, or paste it).")
            return None
        mark = f"tailnet-ops region={r.name}"
        try:
            cf = self.cloudflare(self.token)
            zone = cf.zone_for(domain)
            state, rec, _found = cf.record_state(zone, domain, "A", r.public_ipv4, False, mark)
        except CloudflareError as e:
            ui.warn(f"Cloudflare: {e}")
            ui.say("Nothing changed.")
            return None
        if state == "foreign":
            ui.warn(f"Cloudflare has a {rec['type']} record {domain} -> {rec['content']} that tn did not make.")
            ui.say("Delete it in Cloudflare (or point it here, DNS only), then run tn --tui again. Nothing changed.")
            return None
        ui.say()
        ui.say(f"Cloudflare: {domain} is in your zone {zone['name']}. During apply tn will, with this token:")
        ui.say(f"  · {'keep' if state == 'ok' else 'make' if state == 'absent' else 'fix'} the A record {domain} -> "
               f"{r.public_ipv4}, DNS only (marked {mark!r}; rollback deletes only that)")
        ui.say("  · give the token to the control host (root only), where acme.sh answers Let's Encrypt's DNS-01")
        ui.say("    check and renews the certificate")
        return zone

    # --- 2-5 ------------------------------------------------------------------------------

    def _nodes(self, dep):
        r = dep.region
        result = dep.runner.run(r.control_host, scripts.wrap(dep.prelude, scripts.STATUS), privileged=True,
                                check=False, echo=False)
        if result.rc != 0:
            return None
        try:
            return nodes_from(result.output)
        except ValueError:
            return None

    def _record(self, site, region, nodes, label):
        path = sitemod.ensure_private_dir(site.runs_dir) / f"{self.now():%Y%m%d-%H%M%S}-nodes-{region.name}-{label}.json"
        sitemod.write_private(path, json.dumps(nodes, indent=1) + "\n")
        return path

    def _deploy(self, site, r, dep, console, old_url):
        ui = self.ui
        ui.say(ui.dim("\nChecking (read-only)…"))
        if dep.preflight():
            ui.warn(f"The checks failed. Fix the problems above, then run tn --tui again. {self._unchanged(r)}")
            return 1
        before = None
        if dep.facts.get("installed", "none") != "none":
            before = self._nodes(dep)
            if before:
                path = self._record(site, r, before, "before")
                ui.say(f"\nNodes in {r.name} now (kept in {path.name}):")
                for line in _table([("Name", "Address", "Online")] +
                                   [(n["name"], n["ipv4"] or "—", "yes" if n["online"] else "no") for n in before]):
                    ui.say(line)
            if ui.confirm(f"Back up Headscale on {r.control_host} first (database, /etc/headscale and its keys, "
                          "to /root/tailnet-ops-backup/)?", default=True):
                if dep.run_once(lambda: self._backup(dep)) and not ui.confirm("The backup failed. Go on anyway?"):
                    return 1
        outcome = self._plan_and_apply(dep, console)
        if outcome == "quit":
            ui.say(f"Stopped before apply. {self._unchanged(r)} The same later: tn --tui, or ./tn control apply {r.name}")
            return 0
        if outcome == "failed":
            ui.warn(f"Apply stopped at a step; see above. {self._again(r)}")
            return 1
        self.applied = True
        if dep.verify():
            ui.warn(f"Verify failed; see above. {self._again(r, old_url)}")
            return 1
        self.verified = True
        if before and r.server_url != old_url:
            return self._move(site, r, dep, before, old_url)
        ui.say(ui.bold(f"\nDone: {r.name} runs on {r.server_url}, verified."))
        return 0

    def _plan_and_apply(self, dep, console):
        """Show the short plan (the full one on request), then apply once asked: "applied", "quit" or "failed"."""
        text, _digest = dep.plan_text()
        console.log(text)
        console.show(dep.summary_text())
        choices = [("apply", "Apply", "you type yes to start"), ("full", "Show the exact scripts", ""),
                   ("quit", "Quit", "nothing more changes")]
        while True:
            choice = self.ui.select("What now?", choices)
            if choice != "full":
                break
            console.show(text)
            choices = [c for c in choices if c[0] != "full"]
        if choice == "quit":
            return "quit"
        confirmed = []

        def ask(prompt):
            """The apply prompt wants the word yes; anything but yes or no is asked again."""
            try:
                answer = self.ui.text(prompt.strip().rstrip(":"), check=lambda v: None if v.strip().lower() in (
                    "yes", "no") else "type the word yes to start, or no to stop")
            except ValueError:
                return "no"
            if answer.strip().lower() != "yes":
                return "no"
            confirmed.append(True)
            return "yes"
        rc = dep.apply(ask=ask)
        if not confirmed:
            return "quit"
        return "failed" if rc else "applied"

    # --- tn-agent ---------------------------------------------------------------------------

    def _agent(self, site, name=None):
        ui = self.ui
        ready = [r for r in site.regions.values() if r.domain]
        if not ready:
            ui.warn("tn-agent needs a region whose login server has a domain: choose Headscale first and switch a "
                    "region to Let's Encrypt.")
            return 1
        if name is None:
            name = ui.select("Region", [(r.name, r.name, f"tn-agent at {r.agent_domain}" if r.agent_domain
                                         else "no tn-agent yet") for r in ready])
        r = site.region(name)
        self.token = self.token or (self.ask_token() if self.ask_token else None)
        if not self.token:
            ui.say("Nothing changed: tn-agent needs a Cloudflare API token, with Account · Cloudflare Tunnel · Edit.")
            return 1
        if not r.agent_domain:
            try:
                zone = self.cloudflare(self.token).zone_for(r.domain)
            except CloudflareError as e:
                ui.warn(f"Cloudflare: {e}")
                return 1
            agent_domain = self._agent_name(site, r, zone)
            if agent_domain is None:
                return 0
            site = self._write_values(site, name, {"agent_domain": agent_domain}, [
                f"tn agent apply makes the tunnel and the record {agent_domain} with your token; nothing opens on "
                f"{r.control_host}."])
            if site is None:
                return 0
            r = site.region(name)
        return self._agent_install(site, r)

    def _agent_install(self, site, r):
        """The policy if it needs the agent tag, then tn agent plan and apply, your passkey and the Agent's token."""
        ui, name = self.ui, r.name
        dep, console = self.open_deployment(site, name, self.token)
        try:
            rc = self._agent_policy(dep, console, r)
        finally:
            console.close()
        if rc is not None:
            return rc
        agent, console = self.open_agent(site, name, self.token)
        try:
            ui.say(ui.dim("\nChecking Cloudflare and the host (read-only)…"))
            if agent.preflight():
                ui.warn(f"The checks failed. Fix the problems above, then run tn --tui again. {self._unchanged(r)}")
                return 1
            outcome = self._plan_and_apply(agent, console)
            if outcome == "quit":
                ui.say(f"Stopped before apply. The same later: tn --tui, or ./tn agent apply {name}")
                return 0
            if outcome == "failed":
                ui.warn(f"Apply stopped at a step; see above. Fix the cause and run tn --tui again, or remove what "
                        f"tn-agent made so far: ./tn agent rollback {name}")
                return 1
            return self._agent_access(agent, r)
        finally:
            console.close()

    def _agent_name(self, site, r, zone, also=None):
        """tn-agent's name, a proxied record in the owner's zone: asked, with agent-<region>.<zone> offered, and
        checked at Cloudflare (read-only). None if a record tn did not make holds it."""
        ui, mark = self.ui, f"tailnet-ops agent region={r.name}"
        cf = self.cloudflare(self.token)
        used = {x for o in site.regions.values() for x in (o.domain, o.agent_domain) if x} | ({also} if also else set())

        def check(value):
            if not DNS_RE.match(value):
                return f"a DNS name such as agent-{r.name}.{zone['name']}"
            if value in used:
                return "a login server or another tn-agent has that name"
            if value == r.base_domain or value.endswith("." + r.base_domain):
                return f"it sits inside the MagicDNS suffix {r.base_domain}"
            return None
        name = ui.text("Name for tn-agent (a proxied record in your Cloudflare zone)",
                       default=f"agent-{r.name}.{zone['name']}", check=check)
        try:
            found = cf.records(cf.zone_for(name), name)
        except CloudflareError as e:
            ui.warn(f"Cloudflare: {e}")
            return None
        foreign = [x for x in found if (x.get("comment") or "") != mark]
        if foreign:
            ui.warn(f"Cloudflare has a {foreign[0]['type']} record {name} -> {foreign[0]['content']} that tn did not "
                    "make. Pick another name, or delete that record first. Nothing changed.")
            return None
        return name

    def _agent_policy(self, dep, console, r):
        """None when Headscale's policy owns the agent tag (after bringing it in line, if needed); else an rc."""
        ui = self.ui
        result = dep.runner.run(r.control_host, scripts.wrap(dep.prelude, policy_owns(r.agent_tag)), privileged=True,
                                check=False, echo=False)
        if result.facts().get("agent_tag") == "yes":
            return None
        ui.say(f"\nHeadscale's policy for {r.name} does not own {r.agent_tag} yet. Machines tn-agent joins carry that "
               "tag; tn control apply brings the policy in line. Headscale reloads it and "
               "keeps running; nothing else changes unless the plan says so.")
        ui.say(ui.dim("Checking (read-only)…"))
        if dep.preflight():
            ui.warn(f"The checks failed. Fix the problems above, then run tn --tui again. {self._unchanged(r)}")
            return 1
        outcome = self._plan_and_apply(dep, console)
        if outcome == "quit":
            ui.say(f"Stopped before apply. {self._unchanged(r)}")
            return 0
        if outcome == "failed" or dep.verify():
            ui.warn(f"tn control apply {r.name} did not finish; see above. {self._again(r)}")
            return 1
        return None

    def _agent_access(self, agent, r):
        """After tn agent apply: your passkey (unless you have one), then the token page for the Agent's token.
        Nothing here replaces what is there: another passkey is added beside the first, and the token page
        makes tokens beside the ones made before."""
        ui = self.ui
        count = []
        agent.run_once(lambda: count.append(agent.passkey_count()))
        have = bool(count and count[0])
        question = (f"{count[0]} passkey(s) are registered already. Register another one?" if have
                    else "Register your passkey now (a one-time link, 10 minutes)?")
        if ui.confirm(question, default=not have):
            links = []
            if agent.run_once(lambda: links.append(agent.new_enrolment())) == 0:
                copied = self.clipboard(links[0])
                ui.say(f"\n    {links[0]}\n")
                ui.say("Open it in Safari on this Mac (the passkey syncs to your iPhone through iCloud Keychain) or on "
                       "the iPhone, and register." + (" It is on the clipboard too." if copied else ""))
                ui.text("Press Enter once the page says it is registered", default="done", check=lambda v: None)
                count = []
                agent.run_once(lambda: count.append(agent.passkey_count()))
                if count and count[0]:
                    ui.say(f"✓ {count[0]} passkey(s) registered on {r.control_host}")
                else:
                    ui.warn(f"No passkey is registered yet; make a new link later with ./tn agent enroll {r.name}")
        page = f"{agent.url}/tokens"
        copied = self.clipboard(page)
        ui.say("\nThe Agent's MCP token: open the token page on the device where you set up the Agent, name the")
        ui.say("token and confirm with your passkey; it shows the token, the MCP address and the header to paste.")
        ui.say(f"\n    {page}\n")
        if copied:
            ui.say("The link is on the clipboard.")
        ui.note("Tokens made before stay valid; revoke one there when you no longer need it.")
        ui.say(ui.bold(f"\nDone: tn-agent runs at {agent.url}."))
        return 0

    def _backup(self, dep):
        result = dep.runner.run(dep.region.control_host, scripts.wrap(dep.prelude, scripts.BACKUP), privileged=True)
        self.ui.say(f"  backup: {dep.region.control_host}:{result.facts().get('backup', '?')}")

    def _unchanged(self, r):
        note = f"Nothing changed on {r.control_host}."
        if self.edited:
            note += " site.toml has the new setting; the one before is in site.toml.bak."
        return note

    def _again(self, r, old_url=None):
        """What to do after a step failed: run again; never a rollback, which removes Headscale and its nodes."""
        note = "Fix the cause and run tn --tui again: what is done is kept, and every step runs again safely."
        if self.edited:
            note += (" To go back to the setting before, put site.toml.bak back as site.toml and run "
                     f"./tn control apply {r.name}")
            if old_url and r.server_url != old_url:
                note += "; nodes that moved then need tn join apply again"
            note += "."
        return note

    def _move(self, site, r, dep, before, old_url):
        ui = self.ui
        plan = movers(site, r, before)
        auto = [p for p in plan if p["target"]]
        ui.say(f"\nThe login address changed: {old_url} → {r.server_url}. These nodes move to it:")
        for line in _table([("Node", "How")] + [(p["node"], p["how"]) for p in plan]):
            ui.say(line)
        ui.warn("Until a node moves, it cannot reach the nodes that did. Move them all now, in one go.")
        if not auto or not ui.confirm(f"Move the {len(auto)} node(s) tn can move now, one after another?",
                                      default=True):
            ui.say("Move them later with: " + "; ".join(f"./tn join apply {p['target']}" for p in auto))
            return 0
        failed = []
        for p in auto:
            ui.say(ui.bold(f"\n== moving {p['node']}"))
            if self.tn(["join", "apply", p["target"], "--yes"]):
                failed.append(p["node"])
        manual = [p for p in plan if not p["target"]]
        after = self._nodes(dep) or []
        if after:
            self._record(site, r, after, "after")
        rows = compare(before, after)
        ui.say(f"\nNodes in {r.name}, before and after:")
        for line in _table([("Name", "Before", "After", "")] +
                           [(n, b or "—", a or "—", "✓" if p is None else f"✗ {p}") for n, b, a, p in rows]):
            ui.say(line)
        if failed:
            ui.warn(f"These did not move: {', '.join(failed)}. Run ./tn join apply <node> for each. "
                    + self._again(r, old_url))
        for p in manual:
            ui.warn(f"{p['node']}: {p['how']}")
        if not failed and not manual and all(p is None for *_x, p in rows):
            ui.say(ui.bold(f"\nDone: {r.name} runs on {r.server_url}; every node moved and kept its address."))
            return 0
        return 1
