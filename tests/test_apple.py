"""A Mac with the Tailscale app: the profile, the block to paste, the Clash script, tn join --app."""

import json
import os
import plistlib
import shutil
import ssl
import subprocess
import unittest

from tailnet_ops import apple, join, targets
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
        self.assertTrue(block.rstrip().endswith('"$T" switch ovs\nTN_EOF'))

    def test_login_block_runs_and_skips_existing_accounts(self):
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        log = self.tmp / "calls"
        (stubs / "open").write_text("#!/bin/sh\nexit 0\n")
        (stubs / "Tailscale").write_text(
            '#!/bin/sh\necho "$*" >> "$CALLS"\n'
            'case "$1" in switch) [ "$2" = --list ] && echo \'[{"nickname": "cn"}]\' ;; esac\nexit 0\n')
        for f in stubs.iterdir():
            f.chmod(0o755)
        regions = list(self.site.regions.values())
        block = apple.login_block(self.site, regions, {"cn": KEY_CN, "ovs": KEY_OVS}, regions[0])
        block = block.replace(f"T={apple.APP_CLI}", f"T={stubs}/Tailscale")
        p = run_bash(block.split("\n", 1)[1].rsplit("TN_EOF", 1)[0],
                     env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "CALLS": str(log)})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("cn: already there", p.stdout)
        self.assertIn("ovs: joined", p.stdout)
        calls = log.read_text()
        self.assertNotIn(KEY_CN, calls)                                # cn was there: its key is not used
        self.assertIn(f"login --login-server=https://203.0.113.20:9443 --nickname=ovs --auth-key={KEY_OVS}", calls)
        self.assertTrue(calls.rstrip().endswith("switch cn"))

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

    def responses(self, nodes=None):
        return {join.USERS_JSON: json.dumps([{"id": 3, "name": "owner"}]),
                join.NODES_JSON: json.dumps(nodes if nodes is not None else [{"id": 9, "given_name": "air"}]),
                join.PREAUTH_KEYS_JSON: "[]"}

    def test_check(self):
        job = self.job(Runner(self.responses()))
        self.assertEqual(job.check()["fails"], [])
        self.assertEqual(job.users, {"cn": 3, "ovs": 3})
        bad = self.job(Runner({join.USERS_JSON: "[]"}))
        self.assertIn("cn-control has no Headscale user owner", bad.check()["fails"])

    def test_apply(self):
        runner, recorded = Runner(self.responses()), []
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

    def test_wait_gives_up(self):
        job = self.job(Runner(self.responses(nodes=[])))
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
        runner = Runner({**self.responses(nodes), join.PREAUTH_KEYS_JSON: json.dumps(keys)})
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


class RecordTest(TempDirTest):
    def test_an_app_mac_is_not_this_machine(self):
        site = self.load_site()
        site.joined["air"] = {"ssh": None, "app": True, "role": "personal", "region": "cn", "os": "macos"}
        self.assertEqual(targets.find_record(site, None), (None, None))
        self.assertEqual(targets.find_record(site, "air")[0], "air")
