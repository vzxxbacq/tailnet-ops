import json
import os
import plistlib
import shutil
import subprocess
import unittest

from tailscale_ops import join, macos, scripts, targets
from tailscale_ops.procedure import StepError
from tests.helpers import FakeRunner, TempDirTest, bash, run_bash
from tests.test_join import CA, FakeOps, status

# This machine, a Mac: as a personal device and as a server of cn.
PERSONAL = targets.Target(name="mac", role="personal", region="cn", os="macos")
MAC = targets.Target(name="mac", role="server", region="cn", os="macos")
USERS = json.dumps([{"id": 4, "name": "other"}, {"id": 1, "name": "owner"}])
INTEL = "/usr/local/opt/tailscale/bin/tailscale"


class MacPlanTest(TempDirTest):
    def test_server_plan(self):
        site = self.load_site()
        job = join.Join(site, ops=FakeOps(), member=MAC)
        text = job.plan_text()[0]
        for n, title in enumerate(["Preflight", "Tailscale", "Site CA", "tailscaled", "Join", "Names", "Verify"], 1):
            self.assertIn(f"Step {n}/7  {title}", text)
        self.assertIn("brew install tailscale", text)
        self.assertIn("security add-trusted-cert -d -r trustRoot -p ssl", text)
        self.assertIn("launchctl bootstrap system", text)
        self.assertIn(f"{macos.DEFAULT_TS_BIN} up --login-server=https://198.51.100.10:9443", text)
        self.assertNotIn("--netfilter-mode", text)
        self.assertNotIn("systemctl", text)
        self.assertIn("runs here with sudo", text)
        job.facts["ts_bin"] = INTEL                      # Homebrew on an Intel Mac
        self.assertEqual(job._argv(site.regions["cn"])[0], INTEL)
        self.assertTrue(job.accept_dns)                  # only the suffix goes to MagicDNS

    def test_summary_says_macos_will_ask(self):
        site = self.load_site()
        facts = "TN-FACT os=macOS 15.1\nTN-FACT machine=arm64\nTN-FACT port=free\nTN-FACT login=ok\nTN-FACT ca=no\n"
        job = join.Join(site, runner=FakeRunner({"TN-FACT os=": facts}), ops=FakeOps(), member=MAC)
        text = job.summary_text(job.check())
        self.assertIn("host          macOS 15.1, arm64", text)
        self.assertIn("macOS asks for your password or Touch ID in step 3", text)
        self.assertIn("Ready: every read-only check on mac passed", text)


class PersonalTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def job(self, runner):
        job = join.Join(self.site, runner=runner, ops=FakeOps(), out=self.out.append, member=PERSONAL)
        job.facts["ts_bin"] = INTEL
        return job

    def test_plan(self):
        job = self.job(FakeRunner())
        self.assertEqual([r.name for r in job.regions], ["cn", "ovs"])
        self.assertEqual(job.tags, [])
        text = job.plan_text()[0]
        self.assertIn('"$BIN" preauthkeys create --expiration 10m --user <id of user owner>', text)
        self.assertIn("--login-server=https://203.0.113.20:9443", text)
        self.assertIn("--nickname=ovs", text)
        self.assertIn("Prelude (ovs-control, control host of ovs)", text)
        summary = job.summary_text(None)
        self.assertIn("mac → personal device of owner in cn, ovs; starts on cn", summary)
        self.assertIn("name mac.ovs.tailnet.internal", summary)
        self.assertIn("accept-routes on (in cn to ovs at 10.255.2.0/24; in ovs to cn at 10.255.1.0/24)", summary)

    def test_joins_every_region_with_its_own_profile(self):
        runner = FakeRunner({join.PROFILES_JSON: "[]", join.USERS_JSON: USERS})
        self.job(runner)._run_join()
        pipes = [c for c in runner.calls if c[0] == "pipe"]
        self.assertEqual([(c[1], c[3]) for c in pipes], [("cn-control", "mac"), ("ovs-control", "mac")])
        for call, region in zip(pipes, ("cn", "ovs")):
            self.assertIn('"$BIN" preauthkeys create --expiration 10m --user 1\n', call[2])
            self.assertEqual(call[4][:2], (INTEL, "login"))
            self.assertIn(f"--nickname={region}", call[4])
            self.assertIn("--accept-routes=true", call[4])
        self.assertIn('"$TS_BIN" switch cn >/dev/null', runner.scripts_for("mac")[-1])   # ends where it starts

    def test_skips_a_joined_region_and_logs_in_a_logged_out_one(self):
        profiles = json.dumps([{"id": "a1", "nickname": "cn"}, {"id": "b2", "nickname": "ovs"}])
        states = iter([status(tags=()), status(state="NeedsLogin")])
        runner = FakeRunner({join.PROFILES_JSON: profiles, join.USERS_JSON: USERS})

        def fake_run(host, script, **kw):
            if join.STATUS_JSON in script:
                runner.responses[join.STATUS_JSON] = next(states)
            return FakeRunner.run(runner, host, script, **kw)

        runner.run = fake_run
        self.job(runner)._run_join()
        pipes = [c for c in runner.calls if c[0] == "pipe"]
        self.assertEqual([c[1] for c in pipes], ["ovs-control"])
        self.assertEqual(pipes[0][4][1], "up")                       # in place, not a second ovs profile
        self.assertTrue(any("set --accept-routes=true --accept-dns=true" in s for s in runner.scripts_for("mac")))

    def test_needs_the_owner_in_headscale(self):
        runner = FakeRunner({join.PROFILES_JSON: "[]", join.USERS_JSON: "[]"})
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_join()
        self.assertIn("cn-control has no Headscale user owner", str(cm.exception))

    def test_verify(self):
        nodes = [{"id": 2, "given_name": "mac", "ip_addresses": ["100.64.1.7"]},
                 {"id": 3, "given_name": "ovs-line", "ip_addresses": ["100.64.2.4"]}]
        runner = FakeRunner({join.STATUS_JSON: status(ip="100.64.1.7", tags=()),
                             join.NETCHECK_JSON: json.dumps({"UDP": True, "PreferredDERP": 901}),
                             join.NODES_JSON: json.dumps(nodes),
                             join.PROFILES_JSON: json.dumps([{"nickname": "cn"}]),
                             "TN-ROUTE": "TN-ROUTE ok\nTN-PING ok\n"})
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_verify()
        self.assertEqual(str(cm.exception), "no profile for ovs")
        self.assertIn("    ✓ reaches ovs-line in ovs at 10.255.2.4 through line line1", self.out)
        self.assertIn("    ovs-control lists 1 node(s) named mac", self.out)
        runner.responses["TN-ROUTE"] = "TN-ROUTE none\nTN-PING fail\n"
        runner.responses[join.PROFILES_JSON] = json.dumps([{"nickname": "cn"}, {"nickname": "ovs"}])
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_verify()
        self.assertIn("no route to 10.255.2.0/24 (line line1)", str(cm.exception))

    def test_rollback_leaves_every_region(self):
        nodes = [{"id": 2, "given_name": "mac", "pre_auth_key": {"id": 1}}]
        keys = [{"id": 1, "used": True, "acl_tags": [], "user": {"name": "owner"}},
                {"id": 5, "used": True, "acl_tags": [], "user": {"name": "other"}},          # not the owner's
                {"id": 6, "used": True, "acl_tags": ["tag:cn-server"], "user": {"name": "owner"}}]  # tagged
        runner = FakeRunner({join.NODES_JSON: json.dumps(nodes), join.PREAUTH_KEYS_JSON: json.dumps(keys)})
        job = self.job(runner)
        job._undo_join()
        first = runner.calls[0]
        self.assertEqual((first[1], first[3]), ("mac", ("cn", "ovs")))
        self.assertIn(join.LOGOUT.strip(), first[2])
        deletes = [(c[1], s) for c in runner.calls for s in [c[2]] if "delete -i" in s]
        self.assertEqual([h for h, _ in deletes], ["cn-control", "cn-control", "ovs-control", "ovs-control"])
        self.assertTrue(all("-i 2 " in s or "-i 1\n" in s for _h, s in deletes), deletes)


class MacScriptsTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.job = join.Join(self.site, ops=FakeOps(), member=PERSONAL)

    def bodies(self):
        return [("preflight", macos.preflight(CA)), ("install", macos.INSTALL),
                ("rollback-install", macos.ROLLBACK_INSTALL), ("ca", macos.install_ca(CA)),
                ("rollback-ca", macos.rollback_ca(CA)), ("service", macos.SERVICE),
                ("rollback-service", macos.ROLLBACK_SERVICE), ("logout", join.LOGOUT),
                ("reach", macos.reach("100.64.1.7", "10.255.2.4")), ("leftovers", macos.leftovers(CA)),
                ("switch", join.switch(self.site.regions["cn"]))]

    def test_every_script_parses(self):
        # /bin/bash on macOS is bash 3.2; the scripts must run there.
        shells = [bash()] + (["/bin/bash"] if os.path.exists("/bin/bash") else [])
        for shell in shells:
            for name, body in self.bodies():
                with self.subTest(shell=shell, script=name):
                    p = subprocess.run([shell, "-n"], input=scripts.wrap(self.job.prelude, body),
                                       capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        for name, body in self.bodies():
            with self.subTest(script=name):
                p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"],
                                   input=scripts.wrap(self.job.prelude, body), capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)

    def sandbox(self, body, stubs=None):
        """Run a macOS script with its paths under a temp root and stub commands."""
        root = self.tmp / "root"
        root.mkdir(exist_ok=True)
        bin_dir = self.tmp / "stubs"
        bin_dir.mkdir(exist_ok=True)
        log = self.tmp / "stub.log"
        defaults = {
            "launchctl": 'echo "launchctl $*" >> "$STUB_LOG"\n'
                         'case "$1" in print) [ -f "$STUB_ROOT/loaded" ] ;; bootstrap) touch "$STUB_ROOT/loaded" ;;'
                         ' bootout) rm -f "$STUB_ROOT/loaded" ;; esac',
            "chown": "exit 0",
            "sudo": 'echo "sudo $*" >> "$STUB_LOG"',
            "security": 'echo "security $*" >> "$STUB_LOG"\n'
                        'case "$1" in find-certificate) echo "SHA-1 hash: ABCD" ;;'
                        ' verify-cert) [ -f "$STUB_ROOT/trusted" ] ;;'
                        ' add-trusted-cert) touch "$STUB_ROOT/trusted" ;; esac',
            "openssl": 'cat >/dev/null; echo "SHA1 Fingerprint=AB:CD"',
            "pgrep": "exit 1",
            "tailscale": '[ "$1" = version ] && echo 1.104.2; exit 0',
        }
        for name, text in {**defaults, **(stubs or {})}.items():
            (bin_dir / name).write_text(f"#!/bin/sh\n{text}\n")
            (bin_dir / name).chmod(0o755)
        overrides = "\n".join([
            f"BREW={bin_dir}/brew", f"TS_BIN={bin_dir}/tailscale", f"TSD_BIN={bin_dir}/tailscaled",
            f"PLIST={root}/job.plist", f"TN_DIR={root}/tn", f"TS_STATE={root}/tn/tailscale",
            f"CA_FILE={root}/tn/ca.crt", f"KEYCHAIN={root}/System.keychain", f"SOCKET={root}/socket",
        ])
        (bin_dir / "brew").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "brew").chmod(0o755)
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "STUB_LOG": str(log), "STUB_ROOT": str(root)}
        p = run_bash(scripts.wrap(self.job.prelude + "\n" + overrides, body), env=env)
        return p, root, (log.read_text() if log.exists() else ""), bin_dir

    def test_version_check(self):
        p, *_ = self.sandbox('for v in 1.104.2 1.80.0-t1 2.0 1.78.1 "" x.y; do\n'
                             '  if version_ok "$v"; then echo "ok $v"; else echo "old $v"; fi\ndone\n')
        self.assertEqual(p.stdout.split("\n")[:6],
                         ["ok 1.104.2", "ok 1.80.0-t1", "ok 2.0", "old 1.78.1", "old ", "old x.y"])

    def test_service_writes_a_valid_launchd_job_once(self):
        p, root, log, bin_dir = self.sandbox(macos.SERVICE)
        self.assertEqual(p.returncode, 0, p.stderr)
        job = plistlib.loads((root / "job.plist").read_bytes())
        self.assertEqual(job["Label"], macos.LABEL)
        self.assertEqual(job["ProgramArguments"], [
            f"{bin_dir}/tailscaled", f"--state={root}/tn/tailscale/tailscaled.state", f"--socket={root}/socket",
            "--port=41641", "--no-logs-no-support"])
        self.assertTrue(job["KeepAlive"] and job["RunAtLoad"])
        self.assertIn(f"launchctl bootstrap system {root}/job.plist", log)
        self.assertIn("tailscaled is up", p.stdout)
        p, root, log, _ = self.sandbox(macos.SERVICE)
        self.assertIn("unchanged", p.stdout)
        self.assertEqual(log.count("bootstrap"), 1)

    def test_service_refuses_a_foreign_job(self):
        p, root, log, _ = self.sandbox(f'printf x > "$PLIST"\n{macos.SERVICE}')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("job.plist exists and is not ours", p.stderr)
        self.assertNotIn("bootstrap", log)

    def test_ca_is_trusted_once_and_removed_only_if_ours(self):
        p, root, log, _ = self.sandbox(macos.install_ca(CA))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("security add-trusted-cert -d -r trustRoot -p ssl", log)
        self.assertEqual((root / "tn" / "ca-added").read_text().strip(), "ABCD")
        p, root, log, _ = self.sandbox(macos.install_ca(CA))
        self.assertIn("macOS already trusts the site CA", p.stdout)
        self.assertEqual(log.count("add-trusted-cert"), 1)
        p, root, log, _ = self.sandbox(macos.rollback_ca(CA))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("security delete-certificate -Z ABCD", log)
        self.assertFalse((root / "tn" / "ca-added").exists())
        self.assertFalse((root / "tn" / "ca.crt").exists())
        p, root, log, _ = self.sandbox(macos.rollback_ca(CA))
        self.assertIn("not added by tailnet-ops", p.stdout)
        self.assertEqual(log.count("delete-certificate"), 1)

    def test_install_uses_homebrew_only_when_tailscale_is_missing(self):
        p, root, log, _ = self.sandbox(macos.INSTALL)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("already installed with Homebrew; using it as it is", p.stdout)
        self.assertNotIn("sudo", log)
        self.assertFalse((root / "tn" / "brew-installed").exists())
        brew = {"sudo": 'echo "sudo $*" >> "$STUB_LOG"\n'
                        'case "$*" in *" install tailscale") cp "$(dirname "$0")/tailscale" "$STUB_ROOT/ts" ;; esac'}
        p, root, log, _ = self.sandbox(f'TS_BIN={self.tmp}/root/ts\n{macos.INSTALL}', brew)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("install tailscale", log)
        self.assertIn("tailscale 1.104.2", p.stdout)
        self.assertTrue((root / "tn" / "brew-installed").exists())
        p, root, log, _ = self.sandbox(f'rm -f "$TN_DIR/brew-installed"\n{macos.ROLLBACK_INSTALL}')
        self.assertIn("not installed by tailnet-ops", p.stdout)
        self.assertNotIn("uninstall", log)

    def test_rollback_install_uninstalls_what_tn_installed(self):
        p, root, log, _ = self.sandbox("make_dir\nprintf '%s\\n' \"$MARK\" > \"$TN_DIR/brew-installed\"\n"
                                       + macos.ROLLBACK_INSTALL)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("uninstall tailscale", log)
        self.assertIn("HOMEBREW_NO_AUTO_UPDATE=1", log)
        self.assertFalse((root / "tn").exists())                 # nothing else in it, so it goes too
