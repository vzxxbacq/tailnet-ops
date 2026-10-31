"""A Mac with the Tailscale app: the profile, the block to paste, the Clash script, tn join --app."""

import hashlib
import json
import os
import plistlib
import shutil
import ssl
import subprocess
import unittest
from unittest import mock

from tailnet_ops import apple, join, pins, targets
from tailnet_ops.appjoin import AppJoin
from tailnet_ops.procedure import StepError
from tailnet_ops.remote import Result
from tests.helpers import FakeRunner, TempDirTest, bash, run_bash

# A throwaway certificate whose key was never kept.
CA = """-----BEGIN CERTIFICATE-----
MIIBdzCCARygAwIBAgIUbytNtAjZE4GGHGP4GhVstTfXISYwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWdGFpbG5ldC1vcHMgZXhhbXBsZSBDQTAeFw0yNjEwMjUwODQ2
NDBaFw0zNjEwMjIwODQ2NDBaMCExHzAdBgNVBAMMFnRhaWxuZXQtb3BzIGV4YW1w
bGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnNTmmOHEJBOzvzykBA3yR
Ois4avxubqqcjcIdaMrhIA8nRvyiDg6FmPq54r05WxI3qepFRbYFL7qexZUx7+Od
ozIwMDAdBgNVHQ4EFgQUibyxatFBHAI2vRHppniF09GqIWgwDwYDVR0TAQH/BAUw
AwEB/zAKBggqhkjOPQQDAgNJADBGAiEAtNoKOHw0IH7/Bw/ozmanXbpVZsK3OmiE
oOK49qsn3awCIQDfTD2/7gvBe/yFGGwR9fSQgj1+GAvrANkIyJiW64WIsA==
-----END CERTIFICATE-----
"""
KEY_CN = "hskey-auth-" + "cnCN1234" * 2
KEY_OVS = "hskey-auth-" + "ovsOVS56" * 2


class FilesTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()

    def test_profile(self):
        data = apple.profile(self.site, "air", "air", CA)
        top = plistlib.loads(data)
        self.assertEqual(top["PayloadType"], "Configuration")
        self.assertEqual(top["PayloadScope"], "System")
        ca, app = top["PayloadContent"]
        self.assertEqual(ca["PayloadType"], "com.apple.security.root")
        self.assertEqual(ca["PayloadContent"], ssl.PEM_cert_to_DER_cert(CA))
        self.assertEqual(app["PayloadType"], "io.tailscale.ipn.macsys")
        self.assertEqual((app["Hostname"], app["UseTailscaleSubnets"], app["UseTailscaleDNSSettings"]),
                         ("air", "always", "always"))
        # A login server policy would force every account onto one server; a key would be a secret.
        for key in ("LoginURL", "ControlURL", "AuthKey"):
            self.assertNotIn(key, app)
        self.assertIn("cn https://198.51.100.10:9443; ovs https://203.0.113.20:9443", app["ManagedByCaption"])
        self.assertEqual(data, apple.profile(self.site, "air", "air", CA))      # same device, same UUIDs

    def test_login_block(self):
        regions = list(self.site.regions.values())
        block = apple.login_block(self.site, regions, {"cn": KEY_CN, "ovs": KEY_OVS}, regions[1])
        p = subprocess.run([bash(), "-n"], input=block, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"account cn https://198.51.100.10:9443 {KEY_CN}", block)
        self.assertIn(f"account ovs https://203.0.113.20:9443 {KEY_OVS}", block)
        self.assertTrue(block.rstrip().endswith('"$T" switch ovs >/dev/null 2>&1 || true\n[ "$ok" = yes ]\nTN_EOF'))
        self.assertNotIn("add-trusted-cert", block)                    # without the CA: no trust lines
        with_ca = apple.login_block(self.site, regions, {"cn": KEY_CN, "ovs": KEY_OVS}, regions[1], CA)
        self.assertLess(with_ca.index("add-trusted-cert"), with_ca.index("account cn"))
        p = subprocess.run([bash(), "-n"], input=with_ca, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def run_login_block(self, prefs_url):
        """The block with a stub app CLI that already has a cn account, logged in to prefs_url."""
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        log = self.tmp / "calls"
        (stubs / "open").write_text("#!/bin/sh\nexit 0\n")
        (stubs / "security").write_text("#!/bin/sh\nexit 0\n")         # the CA is trusted
        (stubs / "Tailscale").write_text(
            '#!/bin/sh\necho "$*" >> "$CALLS"\n'
            'case "$1" in\n'
            '  switch) [ "$2" = --list ] && echo \'[{"nickname": "cn"}]\' ;;\n'
            '  debug) printf \'{\\n\\t"ControlURL": "%s"\\n}\\n\' "$PREFS_URL" ;;\n'
            'esac\nexit 0\n')
        for f in stubs.iterdir():
            f.chmod(0o755)
        regions = list(self.site.regions.values())
        block = apple.login_block(self.site, regions, {"cn": KEY_CN, "ovs": KEY_OVS}, regions[0])
        block = block.replace(f"T={apple.APP_CLI}", f"T={stubs}/Tailscale")
        p = run_bash(block.split("\n", 1)[1].rsplit("TN_EOF", 1)[0],
                     env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "CALLS": str(log),
                          "PREFS_URL": prefs_url})
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout, log.read_text()

    def test_login_block_runs_and_skips_existing_accounts(self):
        out, calls = self.run_login_block(self.site.regions["cn"].server_url)
        self.assertIn("cn: already there; name and settings set", out)
        self.assertIn("ovs: joined", out)
        self.assertNotIn(KEY_CN, calls)                                # cn was there: its key is not used
        self.assertIn("switch cn\ndebug prefs\nset --hostname=air --accept-routes=true --accept-dns=true", calls)
        self.assertIn("login --login-server=https://203.0.113.20:9443 --nickname=ovs --hostname=air "
                      f"--accept-routes=true --accept-dns=true --auth-key={KEY_OVS}", calls)
        self.assertTrue(calls.rstrip().endswith("switch cn"))

    def test_login_block_moves_an_account_to_a_new_login_server(self):
        out, calls = self.run_login_block("https://192.0.2.99:9443")
        self.assertIn("cn: moving to https://198.51.100.10:9443", out)
        self.assertIn("cn: moved", out)
        self.assertIn("up --login-server=https://198.51.100.10:9443 --force-reauth --hostname=air "
                      f"--accept-routes=true --accept-dns=true --auth-key={KEY_CN}", calls)
        self.assertNotIn("set --hostname", calls)

    def test_clash_script(self):
        js = apple.clash_script(self.site)
        for want in ('"100.64.0.0/10"', '"10.255.1.0/24"', '"10.255.2.0/24"', "IP-CIDR,198.51.100.10/32,DIRECT",
                     "DOMAIN-SUFFIX,tailnet.internal,DIRECT", "PROCESS-NAME,io.tailscale.ipn.macsys.network-extension",
                     'config.tun["route-exclude-address"]', '"+.tailnet.internal": "100.100.100.100"'):
            self.assertIn(want, js)
        self.assertEqual(apple.clash_bypass(self.site), "*.tailnet.internal,100.64.0.0/10,10.255.1.0/24,10.255.2.0/24")

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_clash_script_merges(self):
        js = apple.clash_script(self.site) + """
const before = {rules: ["MATCH,PROXY"], tun: {enable: true, "route-exclude-address": ["192.0.2.0/24"]}};
const after = main(main(before));
console.log(JSON.stringify(after));"""
        p = subprocess.run(["node", "-e", js], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        after = json.loads(p.stdout)
        self.assertEqual(after["rules"][-1], "MATCH,PROXY")
        self.assertEqual(after["rules"].count("DOMAIN-SUFFIX,tailnet.internal,DIRECT"), 1)   # twice is the same
        self.assertEqual(after["tun"]["route-exclude-address"][0], "192.0.2.0/24")
        self.assertTrue(after["tun"]["enable"])


class AppInstallTest(TempDirTest):
    """The lines that install, open and wait for the app, with stub commands."""

    def run_app(self, app_there=False, sha_ok=True, signed=True):
        stubs = self.tmp / "stubs"
        stubs.mkdir(exist_ok=True)
        log = self.tmp / "calls"
        cli = stubs / "Tailscale"
        stub = '#!/bin/sh\necho "$(basename "$0") $*" >> "$CALLS"\n'
        files = {
            "curl": stub + 'for a; do case "$prev" in -o) printf pkg > "$a" ;; esac; prev=$a; done\n',
            "pkgutil": stub + (f'echo "   1. {pins.TAILSCALE_APP_SIGNER}"\n' if signed else 'echo "   1. Someone Else"\n'),
            "sudo": stub + f'cp "{stubs}/Tailscale.ready" "{cli}"; chmod +x "{cli}"\n',
            "open": stub,
            "seq": '#!/bin/sh\necho 1\n',
            "sleep": "#!/bin/sh\nexit 0\n",
            "Tailscale.ready": stub + "exit 0\n",
        }
        for name, text in files.items():
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)
        if app_there:
            shutil.copy(stubs / "Tailscale.ready", cli)
        elif cli.exists():
            cli.unlink()
        sha = hashlib.sha256(b"pkg").hexdigest() if sha_ok else "0" * 64
        with mock.patch.object(pins, "TAILSCALE_APP_SHA256", sha):
            block = apple.app_block().replace(f"T={apple.APP_CLI}", f"T={cli}")
        p = run_bash(block.split("\n", 1)[1].rsplit("TN_EOF", 1)[0],
                     env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "CALLS": str(log)})
        return p, (log.read_text() if log.exists() else "")

    def test_installs_the_checked_package(self):
        p, calls = self.run_app()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f"curl -fsSL --max-time 600 -o", calls)
        self.assertRegex(calls, r"sudo installer -pkg /tmp/tn-tailscale-app\.\w+/Tailscale\.pkg -target /")
        self.assertIn("open -a Tailscale", calls)
        self.assertIn("the Tailscale app is ready", p.stdout)

    def test_refuses_a_wrong_package(self):
        for kw, why in (({"sha_ok": False}, "does not match its pinned sha256"),
                        ({"signed": False}, "is not signed by Tailscale Inc.")):
            with self.subTest(**kw):
                p, calls = self.run_app(**kw)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(why, p.stdout)
                self.assertNotIn("installer", calls)

    def test_leaves_an_installed_app_alone(self):
        p, calls = self.run_app(app_there=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn("curl", calls)
        self.assertIn("open -a Tailscale", calls)


class TrustTest(TempDirTest):
    """The lines that make macOS trust the site CA, with stub commands."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site()

    def run_trust(self, trusted=False, takes=True):
        site = self.site
        stubs = self.tmp / "stubs"
        stubs.mkdir(exist_ok=True)
        log = self.tmp / "calls"
        log.unlink(missing_ok=True)
        state = self.tmp / "trusted"
        if trusted:
            state.write_text("")
        files = {
            "security": '#!/bin/sh\necho "security $*" >> "$CALLS"\n'
                        f'case "$1" in verify-cert) [ -f "{state}" ] ;; add-trusted-cert) '
                        + (f'touch "{state}"' if takes else "exit 1") + " ;; esac\n",
            "sudo": '#!/bin/sh\necho "sudo $*" >> "$CALLS"\nexec "$@"\n',
        }
        for name, text in files.items():
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)
        block = apple.trust_block(site, CA)
        p = run_bash(block.split("\n", 1)[1].rsplit("TN_EOF", 1)[0],
                     env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "CALLS": str(log)})
        return p, (log.read_text() if log.exists() else "")

    def test_trusts_once(self):
        p, calls = self.run_trust()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain", calls)
        self.assertIn("macOS trusts the site CA", p.stdout)
        p, calls = self.run_trust(trusted=True)
        self.assertNotIn("add-trusted-cert", calls)

    def test_says_when_macos_refuses(self):
        p, _calls = self.run_trust(takes=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("macOS did not trust the site CA", p.stdout)

    def test_untrust_command(self):
        sha1 = hashlib.sha1(ssl.PEM_cert_to_DER_cert(CA)).hexdigest().upper()
        self.assertEqual(apple.untrust_command(CA),
                         f"sudo security delete-certificate -Z {sha1} /Library/Keychains/System.keychain")


class Runner(FakeRunner):
    def __init__(self, responses=None):
        super().__init__(responses)
        self.secrets = []

    def run(self, host, script, args=(), privileged=False, check=True, echo=True, secret=False):
        if secret:
            self.secrets.append(host)
            key = KEY_CN if host == "cn-control" else KEY_OVS
            self.calls.append(("run", host, script, tuple(args), privileged))
            return Result(0, key + "\n")
        return super().run(host, script, args=args, privileged=privileged, check=check, echo=echo)


class AppJoinTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out, self.shown, self.clip = [], [], []

    def job(self, runner, region="cn"):
        job = AppJoin(self.site, "air", region, runner=runner, out=self.out.append, show=self.shown.append, ca_pem=CA,
                      clipboard=lambda text: self.clip.append(text) or True)
        job.sleep = lambda s: None
        return job

    @staticmethod
    def responses(nodes=None):
        return {join.USERS_JSON: json.dumps([{"id": 3, "name": "owner"}]),
                join.NODES_JSON: json.dumps(nodes if nodes is not None else [{"id": 9, "given_name": "air"}]),
                join.PREAUTH_KEYS_JSON: "[]"}

    def test_check(self):
        job = self.job(Runner(AppJoinTest.responses()))
        self.assertEqual(job.check()["fails"], [])
        self.assertEqual(job.users, {"cn": 3, "ovs": 3})
        bad = self.job(Runner({join.USERS_JSON: "[]"}))
        self.assertIn("cn-control has no Headscale user owner", bad.check()["fails"])

    def test_apply(self):
        runner, recorded = Runner(AppJoinTest.responses()), []
        job = self.job(runner, region="ovs")
        job.remember = recorded.append
        self.assertEqual(job.apply(yes=True), 0, "\n".join(self.out))
        self.assertEqual(recorded, [job])
        profile = self.site.directory / "out" / "air.mobileconfig"
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
        self.assertEqual(plistlib.loads(profile.read_bytes())["PayloadContent"][1]["Hostname"], "air")
        self.assertEqual(runner.secrets, ["ovs-control", "cn-control"])        # the home region first
        self.assertEqual(len(self.clip), 1)
        self.assertIn(KEY_CN, self.clip[0])
        self.assertTrue(any(KEY_OVS in s for s in self.shown))
        self.assertFalse(any(KEY_CN in line or KEY_OVS in line for line in self.out))   # out is logged
        self.assertTrue((self.site.directory / "out" / "air-clash-verge.js").exists())
        self.assertIn("    verify passed; on the Mac, switch region in the Tailscale menu: ovs, cn", self.out)
        self.assertEqual(job.record()["region"], "ovs")

    def test_wait_names_a_node_that_came_up_under_its_host_name(self):
        nodes = [{"id": 9, "given_name": "owners-macbook-air", "name": "air"}]
        runner = Runner(AppJoinTest.responses(nodes))
        self.job(runner)._run_wait()
        renames = [(c[1], line.strip()) for c in runner.calls for line in c[2].splitlines() if "nodes rename" in line]
        self.assertEqual(renames, [("cn-control", '"$BIN" nodes rename -i 9 air'),
                                   ("ovs-control", '"$BIN" nodes rename -i 9 air')])
        self.assertIn("    cn: renaming owners-macbook-air to air", self.out)

    def test_wait_gives_up(self):
        job = self.job(Runner(AppJoinTest.responses(nodes=[])))
        clock = iter(range(0, 10 ** 6, 600))
        from tailnet_ops import appjoin
        real = appjoin.time.monotonic
        appjoin.time.monotonic = lambda: next(clock)
        try:
            with self.assertRaises(StepError) as cm:
                job._run_wait()
        finally:
            appjoin.time.monotonic = real
        self.assertIn("did not appear in cn, ovs", str(cm.exception))

    def test_rollback(self):
        nodes = [{"id": 9, "given_name": "air", "pre_auth_key": {"id": 4}}]
        keys = [{"id": 4, "used": True, "acl_tags": [], "user": {"name": "owner"}},
                {"id": 5, "used": True, "acl_tags": ["tag:cn-server"], "user": {"name": "owner"}}]
        runner = Runner({**AppJoinTest.responses(nodes), join.PREAUTH_KEYS_JSON: json.dumps(keys)})
        job, forgotten = self.job(runner), []
        job.forget = forgotten.append
        job._run_profile()
        self.assertEqual(job.rollback(yes=True), 0, "\n".join(self.out))
        deletes = [f"{c[1]}: {line.strip()}" for c in runner.calls for line in c[2].splitlines() if "delete -i" in line]
        self.assertEqual(deletes, [f"{host}: {cmd}" for host in ("cn-control", "ovs-control") for cmd in
                                   ('"$BIN" nodes delete -i 9 --force', '"$BIN" preauthkeys delete -i 4')])
        self.assertFalse((self.site.directory / "out" / "air.mobileconfig").exists())
        self.assertIn("logout", self.clip[-1])
        self.assertEqual(forgotten, [job])


class FakeLocal:
    def __init__(self, problems=()):
        self._problems = list(problems)
        self.opened, self.blocks = [], []

    def problems(self):
        return self._problems

    def open(self, path):
        self.opened.append(path)

    def run(self, block, out):
        self.blocks.append(block)
        out("cn: joined")
        return 0


class HereTest(TempDirTest):
    """The Mac with the app is this machine: tn opens the profile and adds the accounts itself."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out, self.shown, self.clip = [], [], []

    def job(self, local):
        job = AppJoin(self.site, "here-mac", "cn", runner=Runner(AppJoinTest.responses([{"id": 9, "given_name": "here-mac"}])),
                      out=self.out.append,
                      show=self.shown.append, ca_pem=CA, clipboard=lambda t: self.clip.append(t) or True,
                      here=True, local=local)
        job.sleep = lambda s: None
        return job

    def test_apply_here(self):
        local = FakeLocal()
        job = self.job(local)
        self.assertEqual(job.apply(yes=True), 0, "\n".join(self.out))
        self.assertEqual(local.opened, [self.site.directory / "out" / "here-mac.mobileconfig"])
        self.assertEqual(len(local.blocks), 3)                       # trust the CA, the app, the accounts
        self.assertIn("add-trusted-cert", local.blocks[0])
        self.assertIn("installer -pkg", local.blocks[1])
        self.assertNotIn(KEY_CN, local.blocks[1])
        self.assertIn(KEY_CN, local.blocks[2])
        self.assertEqual((self.clip, self.shown), ([], []))           # nothing to paste, nothing shown
        self.assertFalse(any(KEY_CN in line or KEY_OVS in line for line in self.out))
        self.assertTrue(job.record()["here"])
        job.rollback(yes=True)
        self.assertIn("logout", local.blocks[-1])

    def test_problems_here_stop_it(self):
        job = self.job(FakeLocal(["the Tailscale app is not in /Applications/Tailscale.app"]))
        self.assertEqual(job.apply(yes=True), 1)
        self.assertTrue(any("the Tailscale app is not in" in line for line in self.out))


class RecordTest(TempDirTest):
    def test_an_app_mac_is_not_this_machine(self):
        site = self.load_site()
        site.joined["air"] = {"ssh": None, "app": True, "role": "personal", "region": "cn", "os": "macos"}
        self.assertEqual(targets.find_record(site, None), (None, None))
        self.assertEqual(targets.find_record(site, "air")[0], "air")
        site.joined["air"]["here"] = True                             # set up on this machine
        self.assertEqual(targets.find_record(site, None)[0], "air")
