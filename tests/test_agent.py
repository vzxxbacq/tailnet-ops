"""`tn agent`: the site settings, the plan, apply over a fake runner, the bundle, tokens and enrolment
links, and the join script's login step against a stub tailscale. Offline."""

import hashlib
import io
import json
import os
import signal
import shutil
import subprocess
import sys
import time
import unittest
import zipfile
from pathlib import Path

from tailscale_ops import agent, join, pins, privacy, render, scripts
from tailscale_ops.procedure import StepError
from tailscale_ops import site as sitemod
from tailscale_ops.site import SiteError
from tests.helpers import FakeRunner, TempDirTest, example_text, run_bash

OVS = ('public_ipv4 = "203.0.113.20"',
       'public_ipv4 = "203.0.113.20"\ndomain = "hs-ovs.example.com"\nagent_domain = "agent-ovs.example.com"')
LOGIN = "https://hs-ovs.example.com:9443"
AUTH_URL = LOGIN + "/register/hskey-authreq-" + "A" * 24
STAGE = "/tmp/tn-agent.Ab12Cd34"
TUNNEL_TOKEN = "eyJhIjoidHVubmVsLXRva2VuLWZvci10ZXN0cyJ9"


class Ops:
    def __init__(self, tmp):
        self.path = Path(tmp) / "agentd.pyz"
        self.path.write_bytes(agent.bundle())
        self.fetched = []

    def bundle_file(self):
        return self.path, hashlib.sha256(self.path.read_bytes()).hexdigest()

    def cloudflared(self, arch):
        self.fetched.append(arch)
        return Path(f"/cache/cloudflared-{arch}")


class FakeCF:
    """What tn asks of Cloudflare; no request leaves this process."""

    def __init__(self, token, records=(), tunnel=None, calls=None):
        self.token, self.records_, self.tunnel_ = token, list(records), tunnel
        self.calls = calls if calls is not None else []

    def zone_for(self, name):
        return {"id": "z1", "name": "example.com", "account": "a1"}

    def records(self, zone, name):
        return self.records_

    def tunnel(self, account, name):
        return self.tunnel_

    def ensure_tunnel(self, account, name):
        self.calls.append(("tunnel", account, name))
        return "t1", True

    def route(self, account, tunnel_id, hostname, service):
        self.calls.append(("route", tunnel_id, hostname, service))

    def ensure_record(self, zone, name, kind, content, proxied, mark):
        self.calls.append(("record", name, kind, content, proxied, mark))
        return "created"

    def tunnel_token(self, account, tunnel_id):
        return TUNNEL_TOKEN

    def delete_record(self, zone, name, mark):
        self.calls.append(("delete record", name, mark))
        return 1

    def delete_tunnel(self, account, name):
        self.calls.append(("delete tunnel", name))
        return True


class SiteTest(TempDirTest):
    def test_agent_domain(self):
        site = self.load_site(example_text(OVS))
        ovs = site.regions["ovs"]
        self.assertEqual((ovs.agent_domain, ovs.agent_port, ovs.agent_tag),
                         ("agent-ovs.example.com", pins.DEFAULT_AGENT_PORT, "tag:ovs-agent"))
        self.assertIsNone(site.regions["cn"].agent_tag)

    def test_agent_domain_problems(self):
        cases = (
            ('public_ipv4 = "203.0.113.20"\nagent_domain = "agent-ovs.example.com"', "needs the region's domain"),
            ('public_ipv4 = "203.0.113.20"\ndomain = "hs-ovs.example.com"\nagent_domain = "hs-ovs.example.com"',
             "another name than the login server"),
            ('public_ipv4 = "203.0.113.20"\ndomain = "hs-ovs.example.com"\nagent_domain = "x.example.com"\n'
             'agent_port = 9443', "must differ"),
            ('public_ipv4 = "203.0.113.20"\nagent_port = 18000', "set agent_domain too"),
        )
        for i, (new, problem) in enumerate(cases):
            with self.subTest(problem):
                with self.assertRaises(SiteError) as cm:
                    self.load_site(example_text((OVS[0], new)), name=f"s{i}")
                self.assertIn(problem, str(cm.exception))

    def test_the_agent_tag_is_reserved(self):
        text = example_text(OVS, ('tags = ["tag:ovs-server", "tag:ovs-border"]',
                                  'tags = ["tag:ovs-server", "tag:ovs-agent"]'))
        with self.assertRaises(SiteError) as cm:
            self.load_site(text, name="reserved")
        self.assertIn("tag:ovs-agent is for the machines tn-agent joins", str(cm.exception))


class PolicyTest(TempDirTest):
    def test_agent_machines_start_no_connection(self):
        site = self.load_site(example_text(OVS))
        doc = json.loads("\n".join(l for l in render.policy(site, site.regions["ovs"]).splitlines()
                                   if not l.startswith("//")))
        self.assertEqual(doc["tagOwners"]["tag:ovs-agent"], ["owner@"])
        for grant in doc["grants"]:
            self.assertEqual(grant["src"], ["autogroup:member", "tag:ovs-server", "tag:ovs-border"])
        self.assertEqual(doc["grants"][0]["dst"], ["*"])     # the others still reach them

    def test_regions_without_tn_agent_keep_their_policy(self):
        site = self.load_site(example_text(OVS))
        doc = json.loads("\n".join(l for l in render.policy(site, site.regions["cn"]).splitlines()
                                   if not l.startswith("//")))
        self.assertEqual(doc["grants"][0]["src"], ["*"])
        self.assertNotIn("tag:cn-agent", doc["tagOwners"])


class PlanTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(OVS))
        self.runner = FakeRunner({"preflight passed": "TN-FACT port=free\nTN-FACT bundle=none\nTN-FACT arch=amd64\n"
                                                      "TN-FACT cloudflared=none\n",
                                  "mktemp -d /tmp/tn-agent.": f"TN-FACT stage={STAGE}\n"})
        self.checked, self.cf_calls = [], []
        self.dep = self.deploy()

    def deploy(self, **cf):
        dep = agent.AgentDeploy(self.site, "ovs", runner=self.runner, ops=Ops(self.tmp), out=lambda s: None,
                                check=lambda url: self.checked.append(url) or "ok tn-agent 1 ovs")
        dep.ask_token = lambda quiet=False: "cf-token-for-tests-0123456789"
        dep.cloudflare = lambda token: FakeCF(token, calls=self.cf_calls, **cf)
        dep.sleep = lambda s: None
        return dep

    def test_needs_both_names(self):
        with self.assertRaises(StepError):
            agent.AgentDeploy(self.site, "cn")

    def test_plan(self):
        text, _ = self.dep.plan_text()
        summary = self.dep.summary_text()
        self.assertIn(self.dep.digest, text)
        self.assertIn(pins.CLOUDFLARED_SHA256["amd64"][:12], text)
        self.assertIn("https://agent-ovs.example.com/mcp", summary)
        self.assertIn("no port opens on ovs-control", summary)
        self.assertIn("Agents never  hold a key", summary)
        self.assertEqual(len(self.dep.steps()), 7)

    def test_config(self):
        config = agent.config(self.site, self.site.regions["ovs"])
        self.assertEqual((config["listen"], config["port"], config["proxy"]), ("127.0.0.1", pins.DEFAULT_AGENT_PORT,
                                                                             "cloudflare"))
        self.assertEqual((config["rp_id"], config["origin"], config["login_server"]),
                         ("agent-ovs.example.com", "https://agent-ovs.example.com", LOGIN))
        self.assertNotIn("cert", config)
        self.assertEqual(config["tags"], ["tag:ovs-agent"])
        self.assertEqual(config["leave_template"], f"{agent.DIR}/leave.sh")
        self.assertEqual(config["resume_template"], f"{agent.DIR}/resume.sh")

    def test_leave_script_removes_only_what_the_join_made(self):
        text = agent.leave_template(self.site, self.site.regions["ovs"])
        self.assertIn("MARK='tailnet-ops join region=ovs host=__TN_NAME__'", text)   # the join's own mark
        for check in ("ours_unit", "ours_state", "ours_bin", "logout"):
            self.assertIn(check, text)
        self.assertNotIn("headscale", text)
        install = self.dep._install_body()
        self.assertIn("TN_LEAVE_EOF", install)
        self.assertIn("TN_RESUME_EOF", install)
        self.assertIn('"$DIR/leave.sh"', agent.ROLLBACK_PROGRAM)
        self.assertIn('"$DIR/resume.sh"', agent.ROLLBACK_PROGRAM)

    def test_units(self):
        r = self.site.regions["ovs"]
        helper, web, tunnel = agent.helper_unit(r), agent.web_unit(r), agent.tunnel_unit(r)
        for unit in (helper, web, tunnel):
            for line in ("MemoryHigh=200M\n", "MemoryMax=256M\n", "OOMScoreAdjust=500\n", "TasksMax=4096\n",
                         "CapabilityBoundingSet=\n"):
                self.assertIn(line, unit)
        for line in ("User=tn-agent\n", "SupplementaryGroups=headscale\n", "PrivateNetwork=yes\n",
                     "RestrictAddressFamilies=AF_UNIX\n"):
            self.assertIn(line, helper)
        for line in ("User=tn-agent-web\n", "SupplementaryGroups=tn-agent\n", "IPAddressDeny=any\n",
                     "IPAddressAllow=localhost\n"):
            self.assertIn(line, web)
        self.assertNotIn("headscale", web.split("[Service]")[1])
        for line in ("DynamicUser=yes\n", f"EnvironmentFile={agent.TUNNEL_ENV}\n", "--no-autoupdate"):
            self.assertIn(line, tunnel)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        items = []
        for step in self.dep.steps():
            items += [(f"step{step.number}", scripts.wrap(self.dep.prelude, a.body)) for a in step.actions if a.body]
            if step.rollback:
                items.append((f"rollback{step.number}", scripts.wrap(self.dep.prelude, step.rollback)))
        items += [(name, f"{self.dep.prelude}\n{body}") for name, body in
                  (("token", agent.SAVE_TOKEN), ("enrol", agent.SAVE_ENROLMENT), ("status", agent.STATUS),
                   ("tunnel token", agent.SAVE_TUNNEL_TOKEN))]
        items.append(("join", agent.join_template(self.site, self.site.regions["ovs"])
                      .replace(agent.NAME_SLOT, "web1").replace(agent.TAGS_SLOT, "tag:ovs-agent")
                      .replace(agent.SCRIPT_SLOT, "Scr123456789")))
        items.append(("leave", agent.leave_template(self.site, self.site.regions["ovs"]).replace(agent.NAME_SLOT, "web1")))
        items.append(("resume", agent.resume_template(self.site, self.site.regions["ovs"]).replace(agent.NAME_SLOT, "web1")))
        for name, script in items:
            with self.subTest(script=name):
                p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"], input=script,
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)

    def test_apply(self):
        self.assertEqual(self.dep.apply(yes=True), 0)
        calls = self.runner.calls
        uploads = [c[2:] for c in calls if c[0] == "upload"]
        self.assertEqual(uploads, [(str(self.dep.ops.path), f"{STAGE}/agentd.pyz"),
                                   ("/cache/cloudflared-amd64", f"{STAGE}/cloudflared")])
        install = next(c for c in calls if c[0] == "run" and "agentd.pyz.tn-new" in c[2])
        self.assertEqual(install[3], (STAGE, self.dep.digest))
        self.assertIn("TN_JOIN_EOF", install[2])
        self.assertIn(("route", "t1", "agent-ovs.example.com", f"http://127.0.0.1:{pins.DEFAULT_AGENT_PORT}"),
                      self.cf_calls)
        self.assertIn(("record", "agent-ovs.example.com", "CNAME", "t1.cfargotunnel.com", True,
                       "tailnet-ops agent region=ovs"), self.cf_calls)
        feed = next(c for c in calls if c[0] == "feed")
        self.assertEqual(feed[3], TUNNEL_TOKEN)
        self.assertNotIn(TUNNEL_TOKEN, json.dumps([c for c in calls if c[0] != "feed"]))
        self.assertTrue(any(c[0] == "run" and "for s in tn-agent-helper tn-agent tn-cloudflared;" in c[2] for c in calls))
        self.assertEqual(self.checked, ["https://agent-ovs.example.com/healthz"])

    def test_a_new_apply_keeps_what_the_install_made(self):
        """An update runs apply again: it keeps the MCP token, the passkeys, requests and audit log, and the
        tunnel's token is written again from the same tunnel."""
        scripts_run = "\n".join(a.body for s in self.dep.steps() for a in s.actions if a.body)
        self.assertIn('touch "$ETC/tokens"', scripts_run)
        self.assertNotIn('> "$ETC/tokens"', scripts_run)
        for kept in ("passkeys.json", "requests.json", "tokens.json", "audit.jsonl", 'rm -rf "$STATE"',
                     'rm -rf "$ETC"', 'rm -f "$TUNNEL_ENV"'):
            self.assertNotIn(kept, scripts_run)
        self.assertIn("install -d -o \"$USER\" -g \"$USER\" -m 0700 \"$STATE\"", scripts_run)   # keeps its files

    def test_a_record_tn_did_not_make_stops_preflight(self):
        dep = self.deploy(records=[{"type": "A", "content": "192.0.2.9", "proxied": False, "comment": "mine"}])
        self.assertEqual(dep.apply(yes=True), 1)
        self.assertFalse(any(c[0] == "upload" for c in self.runner.calls))

    def test_verify_waits_for_the_tunnel(self):
        answers = iter([StepError("not yet"), StepError("not yet"), "ok tn-agent 1 ovs"])

        def check(url):
            a = next(answers)
            if isinstance(a, Exception):
                raise a
            return a
        self.dep.check = check
        self.assertEqual(self.dep.verify(), 0)

    def test_rollback_removes_only_what_tn_made_at_cloudflare(self):
        self.assertEqual(self.dep.rollback(yes=True), 0)
        self.assertIn(("delete record", "agent-ovs.example.com", "tailnet-ops agent region=ovs"), self.cf_calls)
        self.assertIn(("delete tunnel", "tailnet-ops-ovs"), self.cf_calls)

    def test_token_goes_as_a_hash(self):
        token = self.dep.new_token()
        self.assertRegex(token, agent.TOKEN_RE)
        feed = next(c for c in self.runner.calls if c[0] == "feed")
        self.assertEqual(feed[3], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, json.dumps(self.runner.calls))
        self.assertTrue(any(label == "tn-agent MCP token" and p.search(token) for label, p in privacy.SECRET_PATTERNS))

    def test_enrolment_link(self):
        link = self.dep.new_enrolment()
        self.assertTrue(link.startswith("https://agent-ovs.example.com/enroll#"))
        code = link.split("#", 1)[1]
        feed = next(c for c in self.runner.calls if c[0] == "feed")
        self.assertEqual(feed[3], hashlib.sha256(code.encode()).hexdigest())
        self.assertEqual(feed[2][-1], str(agent.ENROL_SECONDS))

    def test_saved_files(self):
        """The stdin scripts write what the service and cloudflared read."""
        etc = self.tmp / "etc"
        etc.mkdir()
        (etc / ".tailnet-ops").write_text(agent.marker(self.site.regions["ovs"]) + "\n")
        prelude = (self.dep.prelude.replace(f"ETC={agent.ETC}", f"ETC={etc}")
                   .replace(f"TUNNEL_ENV={agent.TUNNEL_ENV}", f"TUNNEL_ENV={etc}/tunnel.env")
                   .replace("\nUSER=tn-agent\n", "\nUSER=$(id -gn)\n"))
        for body, args, stdin in ((agent.SAVE_TOKEN, (), "ab" * 32), (agent.SAVE_ENROLMENT, ("600",), "ab" * 32),
                                  (agent.SAVE_TUNNEL_TOKEN, (), TUNNEL_TOKEN)):
            script = f"chown() {{ :; }}\n{prelude}\n{body}"
            p = subprocess.run(["bash", "-c", script, "tn", *args], input=stdin + "\n", capture_output=True,
                               text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((etc / "tokens").read_text().split()[0], "ab" * 32)
        self.assertEqual(json.loads((etc / "enroll.json").read_text())["code_sha256"], "ab" * 32)
        self.assertEqual((etc / "tunnel.env").read_text(), f"TUNNEL_TOKEN={TUNNEL_TOKEN}\n")
        self.assertEqual((etc / "tunnel.env").stat().st_mode & 0o777, 0o600)


class BundleFileTest(TempDirTest):
    def test_private_and_only_this_version(self):
        site = self.load_site(example_text(OVS))
        cache = site.cache_dir
        cache.mkdir(mode=0o700, exist_ok=True)
        (cache / "tn-agent-000000000000.pyz").write_bytes(b"old")
        sitemod.write_private(cache / "headscale_keep", b"other")
        path, digest = agent.LocalOps(site).bundle_file()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(sorted(p.name for p in cache.iterdir()), sorted(["headscale_keep", path.name]))
        self.assertEqual(sitemod.check_dir(site.directory), [])


class BundleTest(TempDirTest):
    def test_same_bytes_every_time(self):
        self.assertEqual(agent.bundle(), agent.bundle())

    def test_contents_and_start(self):
        data = agent.bundle()
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertIn("__main__.py", names)
        self.assertIn("agentd/server.py", names)
        self.assertIn("agentd/guide.md", names)
        self.assertNotIn("agentd/__main__.py", names)
        path = self.tmp / "agentd.pyz"
        path.write_bytes(data)
        p = subprocess.run([sys.executable, "-I", str(path), "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("--config", p.stdout)
        p = subprocess.run([sys.executable, "-I", "-c", "import sys, pkgutil; sys.path.insert(0, sys.argv[1]); "
                            "print(pkgutil.get_data('agentd', 'guide.md').decode().splitlines()[0])", str(path)],
                           capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "# tailscale-ops")

    def test_guide_is_the_skill(self):
        self.assertTrue(agent.SKILL.read_text().startswith("---\nname: tailscale-ops\n"))
        self.assertTrue(agent.guide().startswith("# tailscale-ops"))
        self.assertIn("passkey", agent.guide())


STUB = r"""#!/bin/bash
case "$1" in
  status) echo "{\"BackendState\": \"$TN_STATE\", \"AuthURL\": \"\"}" ;;
  debug) echo "{\"ControlURL\": \"$TN_CONTROL\"}" ;;
  ip) echo 100.64.2.7 ;;
  up) printf '%s\n' "$*" > "$TN_ARGS"
      printf '{\n\t"AuthURL": "%s",\n\t"BackendState": "NeedsLogin"\n}\n' "$TN_AUTH"
      echo "timeout waiting for Tailscale service to enter a Running state" >&2
      exit 1 ;;
esac
"""

# curl, as tn-agent answers the machine's login
CURL = r"""#!/bin/bash
printf '%s\n' "$@" > "$TN_CURL"
[ "$TN_AGENT" = down ] && exit 7
echo '{"request_id": "Req123456789", "approval_url": "https://agent-ovs.example.com/a/Req123456789", "status": "pending"}'
"""


class JoinLoginTest(TempDirTest):
    """Step 5 of the join script: the machine hands its login to tn-agent; no key, no Agent in between."""

    def setUp(self):
        super().setUp()
        site = self.load_site(example_text(OVS))
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        for name, text in (("tailscale", STUB), ("curl", CURL)):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.bin = bin_dir
        pre = join.host_prelude(site, "web1", 41641, [LOGIN], "mark", ca_logins=[])
        self.script = (f"{pre}\nREGION=ovs\nACCEPT_ROUTES=false\nTAGS=tag:ovs-agent\nTS_BIN={bin_dir}/tailscale\n"
                       f"AGENT_URL=https://agent-ovs.example.com\nSCRIPT=Scr123456789\nos='Debian 12'\n"
                       f"{agent.MACHINE_MODE}\ntn_login() {{\n{agent.JOIN_LOGIN}\n}}\ntn_login\n")

    def run_login(self, state="NeedsLogin", control="", auth=AUTH_URL, agent_up=True):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "TN_STATE": state, "TN_CONTROL": control, "TN_AUTH": auth,
               "TN_ARGS": str(self.tmp / "args"), "TN_CURL": str(self.tmp / "curl"),
               "TN_AGENT": "up" if agent_up else "down", "TN_MODE": "system"}
        return run_bash(self.script, env=env)

    def test_hands_the_login_to_tn_agent(self):
        p = self.run_login()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("TN-APPROVAL-URL https://agent-ovs.example.com/a/Req123456789\n", p.stdout)
        self.assertNotIn("register/hskey-authreq", p.stdout)       # the Agent never sees the login
        args = (self.tmp / "args").read_text()
        for flag in (f"--login-server={LOGIN}", "--hostname=web1", "--advertise-tags=tag:ovs-agent", "--json"):
            self.assertIn(flag, args)
        self.assertNotIn("auth-key", args)
        curl = (self.tmp / "curl").read_text().splitlines()
        self.assertEqual(curl[-1], "https://agent-ovs.example.com/join/Scr123456789/login")
        body = json.loads(curl[curl.index("--data") + 1])
        self.assertEqual((body["auth_url"], body["os"], body["arch"]), (AUTH_URL, "Debian 12", os_machine()))

    def test_tn_agent_unreachable(self):
        p = self.run_login(agent_up=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("could not hand the login", p.stderr)

    def test_already_joined(self):
        p = self.run_login(state="Running", control=LOGIN)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("TN-JOINED 100.64.2.7", p.stdout)
        self.assertFalse((self.tmp / "args").exists())

    def test_leaves_another_tailnet_alone(self):
        p = self.run_login(state="Running", control="https://controlplane.tailscale.com")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("another tailnet", p.stderr)
        self.assertFalse((self.tmp / "args").exists())

    def test_refuses_a_link_for_another_server(self):
        p = self.run_login(auth="https://login.tailscale.com/a/abcdef")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("no login link", p.stderr)
        self.assertFalse((self.tmp / "curl").exists())


USER_TS = r"""#!/bin/bash
if [ "${1#--socket=}" != "$1" ]; then printf 'cli %s\n' "$1" >> "$TN_LOG"; shift; fi
case "$1" in
  status) if [ -f "$TN_JOINED" ]; then echo '{"BackendState": "Running", "AuthURL": ""}'
          else echo '{"BackendState": "NeedsLogin", "AuthURL": ""}'; fi ;;
  debug) echo "{\"ControlURL\": \"$TN_CONTROL\"}" ;;
  ip) echo 100.64.2.9 ;;
  up) printf 'up %s\n' "$*" >> "$TN_LOG"; printf '{\n\t"AuthURL": "%s"\n}\n' "$TN_AUTH"; exit 1 ;;
  logout) echo logout >> "$TN_LOG"; rm -f "$TN_JOINED" ;;
  version) echo 1.104.2 ;;
esac
"""

USER_TSD = r"""#!/bin/bash
printf 'tailscaled %s\n' "$*" >> "$TN_LOG"
exec sleep 30
"""


class UserModeTest(TempDirTest):
    """A machine without root or systemd: join in user mode, start again after a restart, leave. Offline:
    tailscale, tailscaled and curl are stubs; only the pinned download is skipped."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(OVS))
        r = self.site.regions["ovs"]
        self.udir = self.tmp / "home" / "ts"
        self.udir.mkdir(parents=True)
        (self.udir / ".tailnet-ops").write_text(join.marker(r, "web1") + "\n")
        for name, text in (("tailscale", USER_TS), ("tailscaled", USER_TSD)):
            (self.udir / name).write_text(text)
            (self.udir / name).chmod(0o755)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        uname = '#!/bin/bash\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) /usr/bin/uname "$@" ;; esac\n'
        for name, text in (("curl", CURL), ("sha256sum", "#!/bin/bash\necho 0  \"$1\"\n"), ("uname", uname)):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        fill = lambda s: (s.replace(agent.NAME_SLOT, "web1").replace(agent.TAGS_SLOT, "tag:ovs-agent")
                          .replace(agent.SCRIPT_SLOT, "Scr123456789"))
        # the pinned download needs the network; the stubs above stand in for its two binaries
        self.join = fill(agent.join_template(self.site, r)).replace("; tn_binaries\n", "; :\n", 1)
        self.resume = fill(agent.resume_template(self.site, r))
        self.leave = fill(agent.leave_template(self.site, r))
        self.log = self.tmp / "log"
        self.addCleanup(self.stop)

    def env(self):
        return {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.tmp / "home"), "TN_DIR": str(self.udir),
                "TN_LOG": str(self.log), "TN_AUTH": AUTH_URL, "TN_CONTROL": LOGIN, "TN_CURL": str(self.tmp / "curl"),
                "TN_JOINED": str(self.tmp / "joined"), "TN_MODE": "user", "TN_WAIT": "2"}

    def pid(self):
        return int((self.udir / "tailscaled.pid").read_text())

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def stop(self):
        try:
            os.kill(self.pid(), signal.SIGTERM)
        except (OSError, ValueError):
            pass

    def run_script(self, script):
        return run_bash(script, env=self.env())

    def test_join_resume_leave(self):
        p = self.run_script(self.join)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("TN-APPROVAL-URL https://agent-ovs.example.com/a/Req123456789", p.stdout)
        self.assertIn("TN-PROXY socks5h://localhost:1055", p.stdout)
        log = self.log.read_text()
        for flag in ("--tun=userspace-networking", "--socks5-server=localhost:1055", "--no-logs-no-support",
                     f"--socket={self.udir}/tailscaled.sock", f"--statedir={self.udir}"):
            self.assertIn(flag, log)
        up = next(line for line in log.splitlines() if line.startswith("up "))
        self.assertIn("--accept-dns=false", up)
        self.assertNotIn("auth-key", up)
        self.assertTrue(self.alive(self.pid()))

        (self.tmp / "joined").write_text("")                  # the owner approved
        os.kill(self.pid(), signal.SIGTERM)                   # the container restarts
        time.sleep(0.3)
        p = self.run_script(self.resume)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("TN-JOINED 100.64.2.9", p.stdout)
        self.assertIn("TN-PROXY socks5h://localhost:1055", p.stdout)
        self.assertTrue(self.alive(self.pid()))

        pid = self.pid()
        p = self.run_script(self.leave)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("TN-LEFT web1", p.stdout)
        self.assertIn("logout", self.log.read_text())
        self.assertFalse(self.udir.exists())
        time.sleep(0.3)
        self.assertFalse(self.alive(pid))

    def test_resume_without_the_key_says_join_again(self):
        p = self.run_script(self.resume)                     # tailscaled starts, but was never approved
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("join this machine again", p.stderr)

    def test_a_directory_that_is_not_ours_is_left_alone(self):
        (self.udir / ".tailnet-ops").write_text("someone else\n")
        p = self.run_script(self.join)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("is not tailnet-ops's", p.stdout + p.stderr)
        p = self.run_script(self.leave)
        self.assertTrue(self.udir.exists())


def os_machine():
    return subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip()


if __name__ == "__main__":
    unittest.main()
