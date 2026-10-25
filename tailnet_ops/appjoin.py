"""`tn join --app`: a Mac that runs the Tailscale app joins every region as the owner.

tn runs on a machine that can log in to the control hosts. For another Mac, which needs no SSH,
keys or tn, it writes a configuration profile for the app and hands over one block to paste into
that Mac's Terminal. For this machine (here) it opens the profile and runs the block itself.
Then it waits until every region lists the Mac, updates names and writes a Clash Verge script.
"""

import shutil
import subprocess
import time
from pathlib import Path

from . import apple, join, macos, names, pins, scripts, siteca
from .procedure import Action, Procedure, Step, StepError
from .site import dns_label, ensure_private_dir, write_private

WAIT_SECONDS = 15 * 60


class AppJoin(Procedure):
    command = "join"
    errors = Procedure.errors + (KeyboardInterrupt,)

    def __init__(self, site, name, region, runner=None, out=print, show=None, ca_pem=None, clipboard=None,
                 here=False, local=None):
        self.site = site
        self.name = name
        self.label = dns_label(name)
        self.subject = name
        self.target = name
        self.region = site.region(region)
        self.regions = [self.region] + [r for r in site.regions.values() if r.name != self.region.name]
        self.runner = runner
        self.out = out
        self.show = show or out                  # prints without logging: the block holds keys
        self.ca_pem = ca_pem
        self.ca_from = None                      # the control host the CA came from, when pki/ has none
        self.clipboard = clipboard if clipboard is not None else copy_to_clipboard
        self.here = here                         # this machine: tn opens the profile and runs the block
        self.local = local or Local()
        self.remember = self.forget = None
        self.pause = None            # set in a terminal: wait until the profile is on the Mac
        self.sleep = time.sleep
        self.users = {}
        out_dir = site.directory / "out"
        self.profile_path = out_dir / f"{name}.mobileconfig"
        self.clash_path = out_dir / f"{name}-clash-verge.js"

    # --- the host side ---------------------------------------------------------------

    def _on_control(self, region, body, echo=False, check=True, secret=False):
        return self.runner.run(region.control_host, scripts.wrap(scripts.control_prelude(self.site, region), body),
                               privileged=True, echo=echo, check=check, secret=secret)

    def _ca(self):
        """pki/ca.crt, else the copy on the control hosts (checked against their TLS)."""
        if self.ca_pem is None:
            self.ca_pem = siteca.local(self.site)
        if self.ca_pem is None:
            pem, source = siteca.fetch(self.site, self.runner, self.regions)
            if pem is None:
                raise StepError(f"{siteca.missing(self.site, self.region)}; from the control hosts: {source}")
            self.ca_pem, self.ca_from = pem, source
        return self.ca_pem

    def _nodes(self, region):
        return join._json(self._on_control(region, join.NODES_JSON).output or "[]", "headscale nodes list") or []

    def _mine(self, nodes):
        return [n for n in nodes if str(n.get("given_name", "")).lower() == self.label]

    def check(self):
        """Read-only: every control host answers as root and has the owner's Headscale user."""
        fails = []
        for r in self.regions:
            result = self._on_control(r, join.USERS_JSON, check=False)
            if result.rc != 0:
                fails.append(f"cannot log in to {r.control_host} as root; tn join --app runs where you can")
                continue
            users = join._json(result.output or "[]", "headscale users list") or []
            found = [u.get("id") for u in users if u.get("name") == self.site.owner_user]
            if not found:
                fails.append(f"{r.control_host} has no Headscale user {self.site.owner_user}")
            else:
                self.users[r.name] = int(found[0])
        try:
            self._ca()
        except StepError as e:
            fails.append(str(e))
        if self.here:
            fails += self.local.problems()
        return {"facts": {}, "fails": fails}

    # --- steps ------------------------------------------------------------------------

    def _run_check(self):
        checks = self.check()
        for f in checks["fails"]:
            self.out(f"    ✗ {f}")
        if checks["fails"]:
            raise StepError("not ready")
        self.out(f"    every control host answers; user {self.site.owner_user} is in every region")

    def _run_app(self):
        if self.local.run(apple.app_block(), self.out) != 0:
            raise StepError("the Tailscale app is not ready; see above")

    def _run_profile(self):
        if self.ca_from:
            siteca.save(self.site, self._ca())
            self.out(f"    saved the site CA certificate from {self.ca_from} to {siteca.path(self.site)}")
        ensure_private_dir(self.profile_path.parent)
        write_private(self.profile_path, apple.profile(self.site, self.name, self.label, self._ca()))
        self.out(f"    wrote {self.profile_path} (the site CA and the app's settings; no secret)")
        if self.here:
            self.local.open(self.profile_path)
            self.out("    opened it: install it in System Settings → General → Device Management (it asks for your")
            self.out("    password). It must be installed before the accounts are added.")
            return
        self.out("    On the Mac: AirDrop it there, open it, then install it in System Settings → General →")
        self.out("    Device Management (it asks for your password). It must be installed before you paste the block.")

    def _run_accounts(self):
        if self.pause:
            self.pause("    Press Enter once the profile is installed on the Mac (the keys are made then) ")
        keys = {}
        for r in self.regions:
            if r.name not in self.users:
                raise StepError("run the check first")
            output = self._on_control(r, join.user_key(self.users[r.name], pins.JOIN_CODE_EXPIRY), secret=True).output
            key = next((w for w in output.split() if join.code_problem(w) is None), None)
            if key is None:
                raise StepError(f"{r.control_host} did not print a pre-auth key")
            keys[r.name] = key
        block = apple.login_block(self.site, self.regions, keys, self.region)
        self.out(f"    made a single-use, {pins.JOIN_CODE_EXPIRY} key in each region for user {self.site.owner_user}")
        if self.here:
            self.out("    adding an account for each region to the Tailscale app here; the keys are not shown or stored")
            if self.local.run(block, self.out) != 0:
                raise StepError("the Tailscale app did not take the accounts; see above")
            return
        copied = self.clipboard(block)
        self.out("    On the Mac, with the Tailscale app installed and the profile in place, paste this into Terminal"
                 + (" (it is on the clipboard):" if copied else ":"))
        self.show("\n" + block)
        self.out("    It adds an account for each region, named after it, and ends on "
                 f"{self.region.name}. The keys are used once and never stored.")

    def _run_wait(self):
        waiting = {r.name for r in self.regions}
        deadline = time.monotonic() + WAIT_SECONDS
        self.out(f"    waiting for the Mac to appear in {', '.join(sorted(waiting))} (Ctrl-C to stop; "
                 f"`tn join verify {self.name}` checks later)")
        while waiting:
            for r in self.regions:
                if r.name in waiting and self._mine(self._nodes(r)):
                    waiting.discard(r.name)
                    self.out(f"    ✓ {r.name}: {self.label} joined")
            if not waiting:
                break
            if time.monotonic() > deadline:
                raise StepError(f"the Mac did not appear in {', '.join(sorted(waiting))} within "
                                f"{WAIT_SECONDS // 60} minutes; paste the block again with new keys: "
                                f"tn join apply {self.name} --app")
            self.sleep(5)

    def _run_names(self):
        names.Names(self.site, self.runner, self.out).sync()

    def _run_verify(self):
        problems = []
        for r in self.regions:
            mine = self._mine(self._nodes(r))
            tags = sorted({t for n in mine for t in (n.get("tags") or n.get("forced_tags") or [])})
            online = any(n.get("online") for n in mine)
            self.out(f"    {r.control_host} lists {len(mine)} node(s) named {self.label}"
                     + (", online" if online else "") + (f", tags {', '.join(tags)}" if tags else ""))
            if len(mine) != 1:
                problems.append(f"{r.control_host} should list exactly one node named {self.label}")
            if tags:
                problems.append(f"{self.label} in {r.name} has tags; a personal device has none")
        if problems:
            raise StepError("; ".join(problems))
        self.out(f"    verify passed; on the Mac, switch region in the Tailscale menu: "
                 f"{', '.join(r.name for r in self.regions)}")

    def _run_clash(self):
        ensure_private_dir(self.clash_path.parent)
        write_private(self.clash_path, apple.clash_script(self.site))
        self.out(f"    wrote {self.clash_path}")
        self.out("    Clash Verge with TUN on: Profiles → Global Extend Script, paste that file, save. With the system")
        self.out(f"    proxy on too, add this to its proxy bypass list: {apple.clash_bypass(self.site)}")

    def _undo_accounts(self):
        for r in self.regions:
            nodes = self._nodes(r)
            mine = self._mine(nodes)
            if not mine:
                self.out(f"    {r.control_host} lists no node named {self.label}")
            for n in mine:
                self.out(f"    deleting node {n.get('id')} ({n.get('given_name')}) on {r.control_host}")
                self._on_control(r, join.delete_node(n.get("id")), echo=True)
            in_use = {str((n.get("pre_auth_key") or {}).get("id")) for n in nodes if n not in mine}
            keys = join._json(self._on_control(r, join.PREAUTH_KEYS_JSON).output or "[]",
                              "headscale preauthkeys list") or []
            for k in keys:
                if (not k.get("acl_tags") and (k.get("user") or {}).get("name") == self.site.owner_user
                        and str(k.get("id")) not in in_use and (k.get("used") or join._expired(k))):
                    self.out(f"    deleting pre-auth key {k.get('id')} on {r.control_host}")
                    self._on_control(r, join.delete_preauth_key(k.get("id")), echo=True)

    def _remove(self, path):
        if path.exists():
            path.unlink()
            self.out(f"    removed {path}")
        else:
            self.out(f"    {path}: absent")

    def steps(self):
        regions = ", ".join(r.name for r in self.regions)
        controls = ", ".join(r.control_host for r in self.regions)
        steps = [
            Step(1, "Check", [f"On {controls}: Headscale answers as root and has user {self.site.owner_user}. Read-only."],
                 [Action(controls, "list users", join.USERS_JSON, "control", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_check,
                 brief="Check the control hosts"),
            Step(2, "Profile",
                 [f"Write {self.profile_path}: the site CA as a trusted root, and the app's settings:",
                  f"name {self.label}, subnet routes and DNS always on. You AirDrop it to the Mac and install it."],
                 [Action("local", f"write the configuration profile ({apple.APP_DOMAIN} policies and the CA)")],
                 rollback="(this machine) delete the profile file", rollback_note="delete the file here; on the Mac, "
                 "remove the profile in System Settings", run=self._run_profile, undo=lambda: self._remove(self.profile_path),
                 brief="Write the app's profile", undo_brief="delete the file"),
            Step(3, "Accounts",
                 [f"In each region ({regions}) make a single-use, {pins.JOIN_CODE_EXPIRY} key for user "
                  f"{self.site.owner_user}, without tags,",
                  "and put a block on the clipboard that you paste into the Mac's Terminal: the app's CLI logs in",
                  f"to each region as an account named after it, and ends on {self.region.name}. Keys are not logged."],
                 [Action(controls, "make a key in each region (read here, never logged)",
                         join.user_key("<user id>", pins.JOIN_CODE_EXPIRY), "control", True),
                  Action("you", "paste on the Mac", apple.login_block(self.site, self.regions,
                                                                     {r.name: "<key>" for r in self.regions},
                                                                     self.region))],
                 rollback="(each control host) delete the Mac's nodes and its used or expired keys",
                 rollback_note=f"delete the node named {self.label} in every region and its used or expired keys",
                 run=self._run_accounts, undo=self._undo_accounts, brief=f"Make the accounts for {regions}",
                 undo_brief=f"delete the nodes on {controls}"),
            Step(4, "Wait", [f"Wait up to {WAIT_SECONDS // 60} minutes until every region lists {self.label}. Read-only."],
                 [Action(controls, "list nodes every 5 s", join.NODES_JSON, "control", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_wait,
                 brief="Wait for the Mac to join"),
            Step(5, "Names", ["Update every region's names of the other regions' hosts, the Mac included."],
                 [Action(controls, "write the extra records file",
                         names.write([{"name": "<name>.<suffix>", "type": "A", "value": "<address>"}]), "control", True)],
                 rollback_note="none separate: updated again after a rollback", run=self._run_names,
                 brief="Update the cross-region names", undo_brief="updated after rollback"),
            Step(6, "Verify", [f"On {controls}: exactly one node named {self.label}, without tags. Read-only."],
                 [Action(controls, "list nodes", join.NODES_JSON, "control", True)],
                 rollback_note="none needed (read-only)", read_only=True, run=self._run_verify, brief="Check the join"),
            Step(7, "Clash Verge",
                 [f"Write {self.clash_path}: a Clash Verge extension script that sends the tailnet's ranges,",
                  f".{self.site.dns_suffix} names and Tailscale's own traffic DIRECT and keeps them out of TUN."],
                 [Action("local", "write the extension script", apple.clash_script(self.site))],
                 rollback="(this machine) delete the script file", rollback_note="delete the file here; remove the "
                 "script in Clash Verge", run=self._run_clash, undo=lambda: self._remove(self.clash_path),
                 brief="Write the Clash Verge script", undo_brief="delete the file"),
        ]
        if self.here:
            steps.insert(1, Step(0, "Tailscale app",
                                 [f"Unless the app is in {apple.APP}: download Tailscale {pins.TAILSCALE_APP_VERSION}, the "
                                  "official package, check its pinned sha256",
                                  "and that Tailscale Inc. signed it, install it with sudo. Open the app and wait until "
                                  "it answers: macOS asks you",
                                  "to allow its system extension and VPN configuration."],
                                 [Action("local", "install if missing, open, wait", apple.app_block())],
                                 rollback_note="none: the app stays (remove it like any app)", run=self._run_app,
                                 brief=f"Install and open the Tailscale app ({pins.TAILSCALE_APP_VERSION})",
                                 undo_brief="the app stays"))
        local = {"Tailscale app", "Profile", "Clash Verge"}
        for number, s in enumerate(steps, 1):
            s.number = number
            s.host = "this machine" if s.title in local else controls
            if s.title in local:
                s.rollback_host = "this machine, without root"
        return steps

    def run_rollback(self, step):
        (step.undo or (lambda: None))()

    def before_steps(self):
        if self.remember:
            self.remember(self)

    def after_rollback(self):
        try:
            self.out("\n== names")
            self._run_names()
        except self.errors as e:
            self.out(f"Could not update the cross-region names: {e}")
        block = apple.logout_block(self.site)
        if self.here:
            self.out("\n== leaving every account in the Tailscale app here")
            self.local.run(block, self.out)
            self.out("Remove the profile in System Settings → General → Device Management to drop the CA and settings.")
            if self.forget:
                self.forget(self)
            return
        copied = self.clipboard(block)
        self.out("\nOn the Mac: remove the profile in System Settings → General → Device Management, and paste this"
                 + (" (on the clipboard)" if copied else "") + " to leave every account:")
        self.show("\n" + block)
        if self.forget:
            self.forget(self)

    # --- printing ---------------------------------------------------------------------

    def summary_header(self, checks=None):
        out = [f"{self.name} → {'this Mac' if self.here else 'a Mac'} with the Tailscale app, personal device of {self.site.owner_user} in "
               f"{', '.join(r.name for r in self.regions)}; starts on {self.region.name}"]
        for r in self.regions:
            out.append(f"  {r.name:<12}  {r.server_url}, name {self.label}.{r.name}.{r.base_domain}")
        if self.here:
            app = ("installed" if Path(apple.APP).exists()
                   else f"not installed: tn installs Tailscale {pins.TAILSCALE_APP_VERSION} (official, signed)")
            out.append(f"  this Mac      the app is {app}; you install the profile when it opens; tn adds the accounts")
        else:
            out.append("  on the Mac    install the profile (AirDrop), paste one block in Terminal: it installs the app "
                       "if missing; no SSH, no tn")
        out.append(f"  this machine  writes {self.profile_path.parent}/{self.name}.*, makes single-use keys")
        if self.ca_from:
            out.append(f"  site CA       from {self.ca_from}: it authenticates every login server; a copy goes to pki/")
        if checks is None:
            out.append("  checks        not run (--offline)")
        elif checks["fails"]:
            out += ["", f"Not ready ({len(checks['fails'])}):"] + [f"  ✗ {f}" for f in checks["fails"]]
        else:
            out += ["", "✓ Ready: every control host answers."]
        return "\n".join(out)

    def header(self):
        return self.summary_header(None).replace("  checks        not run (--offline)", "").rstrip()

    def plan_intro(self):
        return ("Scripts on the control hosts run as `bash -s` over SSH: the control prelude, then the step body.\n"
                "Nothing runs on the Mac except the block you paste.")

    def preludes(self):
        return [(f"{r.control_host}, control host of {r.name}", scripts.control_prelude(self.site, r))
                for r in self.regions]

    def rollback_footer(self):
        return "The Mac keeps the app; remove the profile there to drop the CA and the settings."

    def done_message(self):
        return (f"{self.name} joined {', '.join(r.name for r in self.regions)} through the Tailscale app as "
                f"{self.label}.{self.region.name}.{self.region.base_domain}. Switch region in the app's account menu.")

    def rolled_back_message(self):
        return f"Rolled back {self.name}: its nodes are gone from every region."

    def verify(self):
        return self.run_once(self._run_verify)

    def apply(self, yes=False, ask=input, checks=None):
        checks = self.check()
        if checks["fails"]:
            self.out(self.summary_text(checks))
            self.out("Not applied; nothing changed.")
            return 1
        return super().apply(yes=yes, ask=ask, checks=checks)

    # --- the record ---------------------------------------------------------------------

    def record(self):
        return {"ssh": None, "app": True, "here": self.here, "role": "personal", "region": self.region.name,
                "os": "macos"}


class Local:
    """This machine, when it is the Mac with the app."""

    def problems(self):
        out = []
        if Path(macos.PLIST).exists():
            out.append("this Mac runs tailscaled from tn join (command line); roll that back first, or keep it")
        elif subprocess.run(["pgrep", "-x", "tailscaled"], capture_output=True).returncode == 0:
            out.append("a tailscaled daemon runs here (Homebrew?); the app and it would fight over routes and DNS")
        return out

    def open(self, path):
        subprocess.run(["open", str(path)], check=False)

    def run(self, block, out):
        """Run a block here with bash; its output (never a key) is shown."""
        p = subprocess.Popen(["/bin/bash", "-s"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        p.stdin.write(block)
        p.stdin.close()
        for line in p.stdout:
            out(f"    {line.rstrip()}")
        return p.wait()


def copy_to_clipboard(text):
    """pbcopy on macOS; False where there is none."""
    if shutil.which("pbcopy") is None:
        return False
    return subprocess.run(["pbcopy"], input=text, text=True).returncode == 0

