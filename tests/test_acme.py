"""A region with a domain: a Let's Encrypt certificate through acme.sh and Cloudflare DNS-01, and joins
that need no site CA. Offline: acme.sh, Cloudflare and Let's Encrypt are stubs."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from tailnet_ops import acme, apple, join, pins, scripts
from tailnet_ops.control import Deployment
from tailnet_ops.procedure import StepError
from tailnet_ops.site import SiteError
from tests.helpers import FakeRunner, TempDirTest, bash, example_text, run_bash
from tests.test_join import FakeOps as JoinOps, responses as join_responses, status
from tests.test_scripts import Sandbox, all_scripts

TOKEN = "cf-" + "x" * 37
OVS_DOMAIN = ('public_ipv4 = "203.0.113.20"', 'public_ipv4 = "203.0.113.20"\ndomain = "hs-ovs.example.com"')
CN_DOMAIN = ('public_ipv4 = "198.51.100.10"', 'public_ipv4 = "198.51.100.10"\ndomain = "hs-cn.example.com"')


class AcmeOps:
    def __init__(self):
        self.calls = []

    def acme_files(self):
        self.calls.append("acme_files")
        return {"acme.sh": Path("/cache/acme.sh"), "dns_cf.sh": Path("/cache/dns_cf.sh")}

    def ca_pem(self):
        raise AssertionError("a Let's Encrypt region needs no site CA")


def state(installed=False, token=False):
    sums = pins.ACME_SH_SHA256
    return (f"TN-FACT acme_sh={sums['acme.sh'] if installed else 'none'}\n"
            f"TN-FACT dns_cf={sums['dnsapi/dns_cf.sh'] if installed else 'none'}\n"
            f"TN-FACT token={'yes' if token else 'no'}\n")


class SiteTest(TempDirTest):
    def test_domain_makes_the_login_server_a_name(self):
        site = self.load_site(example_text(OVS_DOMAIN))
        ovs, cn = site.regions["ovs"], site.regions["cn"]
        self.assertFalse(ovs.site_ca)
        self.assertEqual(ovs.server_url, "https://hs-ovs.example.com:9443")
        self.assertTrue(cn.site_ca)
        self.assertEqual(cn.server_url, "https://198.51.100.10:9443")

    def test_bad_domains(self):
        for value, problem in (("not a name", "is not a DNS name"), ("hs.tailnet.internal", "MagicDNS suffix")):
            with self.subTest(value=value):
                with self.assertRaises(SiteError) as cm:
                    self.load_site(example_text((OVS_DOMAIN[0], f'{OVS_DOMAIN[0]}\ndomain = "{value}"')),
                                   name=value.replace(" ", "-"))
                self.assertIn(problem, str(cm.exception))

    def test_one_domain_per_region(self):
        with self.assertRaises(SiteError) as cm:
            self.load_site(example_text(OVS_DOMAIN, (CN_DOMAIN[0], CN_DOMAIN[0] + '\ndomain = "hs-ovs.example.com"')))
        self.assertIn("is also region", str(cm.exception))


class ControlPlanTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(OVS_DOMAIN))
        self.dep = Deployment(self.site, "ovs")

    def test_plan_names_the_certificate_and_its_renewal(self):
        text, _ = self.dep.plan_text()
        self.assertIn("server_url    https://hs-ovs.example.com:9443", text)
        self.assertIn("certificate   Let's Encrypt for hs-ovs.example.com (DNS-01 via Cloudflare)", text)
        self.assertIn(f"--dns dns_cf -d \"$DOMAIN\" --keylength ec-256 --dnssleep {pins.ACME_DNS_SLEEP}", text)
        self.assertIn(f"--server {pins.ACME_SERVER}", text)
        self.assertIn("ExecStart=/etc/headscale/acme/acme.sh --cron", text)
        self.assertIn('DOMAIN=hs-ovs.example.com', text)
        self.assertNotIn("<server certificate signed on this machine", text)
        summary = self.dep.summary_text()
        line = next(x for x in summary.splitlines() if "Let's Encrypt certificate for hs-ovs.example.com" in x)
        self.assertTrue(line.endswith("remove them, acme.sh and the token"), line)

    def test_verify_trusts_the_system_and_uses_the_name(self):
        body = scripts.verify()
        self.assertNotIn("--cacert", body)
        self.assertIn('base="https://$NAME:$PORT"', body)
        self.assertIn("NAME=hs-ovs.example.com", self.dep.checker_prelude)

    def test_every_script_parses(self):
        for name, script in all_scripts(self.dep):
            with self.subTest(script=name):
                p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
        for name, text in (("hook", acme.hook(self.site.regions["ovs"])), ("save token", acme.SAVE_TOKEN)):
            with self.subTest(script=name):
                p = subprocess.run(["sh", "-n"], input=text, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        items = all_scripts(self.dep) + [("hook", acme.hook(self.site.regions["ovs"])), ("save", acme.SAVE_TOKEN)]
        for name, script in items:
            with self.subTest(script=name):
                shell = "sh" if name in ("hook", "save") else "bash"
                p = subprocess.run(["shellcheck", "-s", shell, "-S", "warning", "-e", "SC2034", "-"], input=script,
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)

    def test_site_ca_regions_drop_a_renewal_from_before(self):
        self.assertIn("drop_acme", scripts.install_cert("x", "y"))
        self.assertIn("drop_acme", scripts.ROLLBACK_CERT)


class FakeCloudflare:
    """The records tn would see and what it asked for; no request leaves this process."""

    def __init__(self, token, state="absent", calls=None):
        self.token, self.state = token, state
        self.calls = calls if calls is not None else []

    def zone_for(self, name):
        self.calls.append(("zone", name))
        return {"id": "z1", "name": "example.com", "account": "a1"}

    def record_state(self, zone, name, kind, content, proxied, mark):
        self.calls.append(("state", name, kind, content, proxied, mark))
        rec = {"type": "A", "content": "192.0.2.9", "proxied": True}
        return self.state, rec if self.state == "foreign" else None, []

    def ensure_record(self, zone, name, kind, content, proxied, mark):
        self.calls.append(("ensure", name, kind, content, proxied, mark))
        return "created"

    def delete_record(self, zone, name, mark):
        self.calls.append(("delete", name, mark))
        return 1


class ControlApplyTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(OVS_DOMAIN))
        self.out = []
        self.cf_calls = []

    def apply(self, facts, ask=None, dns="no", cf_state="absent"):
        runner = FakeRunner({
            "TN-FACT arch=": f"TN-FACT arch=amd64\nTN-FACT installed={pins.HEADSCALE_SHA256['amd64']}\n"
                             f"TN-FACT dns={dns}\n",
            "TN-FACT acme_sh=": facts,
            "mktemp -d /tmp/tn-acme.": "TN-FACT stage=/tmp/tn-acme.abc123\n",
        })
        ops = AcmeOps()
        dep = Deployment(self.site, "ovs", runner=runner, ops=ops, out=self.out.append)
        dep.ask_token = ask
        dep.cloudflare = lambda token: FakeCloudflare(token, cf_state, self.cf_calls)
        return dep.apply(yes=True), runner, ops

    def test_installs_acme_saves_the_token_and_issues(self):
        asked = []
        rc, runner, ops = self.apply(state(), ask=lambda quiet=False: None if quiet else asked.append(1) or TOKEN)
        self.assertEqual(rc, 0, "\n".join(self.out))
        self.assertEqual((asked, ops.calls), ([1], ["acme_files"]))
        self.assertIn(("ensure", "hs-ovs.example.com", "A", "203.0.113.20", False, "tailnet-ops region=ovs"),
                      self.cf_calls)
        uploads = [(c[2], c[3]) for c in runner.calls if c[0] == "upload"]
        self.assertEqual(uploads, [("/cache/acme.sh", "/tmp/tn-acme.abc123/acme.sh"),
                                   ("/cache/dns_cf.sh", "/tmp/tn-acme.abc123/dns_cf.sh")])
        feeds = [c for c in runner.calls if c[0] == "feed"]
        self.assertEqual(feeds, [("feed", "ovs-control", tuple(acme.save_token_argv()), TOKEN)])
        sent = "\n".join(c[2] for c in runner.calls if c[0] == "run")
        self.assertNotIn(TOKEN, sent)                       # the token goes on stdin only
        self.assertNotIn(TOKEN, "\n".join(self.out))
        self.assertIn("acme --install-cert", sent)
        self.assertNotIn('echo "TN-BEGIN csr"', sent)       # no site CA certificate here
        verify = runner.scripts_for("ovs-probe")[-1]
        self.assertNotIn("--cacert", verify)

    def test_keeps_what_is_there(self):
        rc, runner, ops = self.apply(state(installed=True, token=True), dns="ok",
                                     ask=lambda quiet=False: None if quiet else self.fail("asked for a token"))
        self.assertEqual(rc, 0, "\n".join(self.out))
        self.assertEqual(ops.calls, [])
        self.assertFalse(any(c[0] in ("upload", "feed") for c in runner.calls))
        self.assertIn("    ovs-control has the Cloudflare API token already", self.out)

    def test_without_a_token_it_stops_at_the_certificate(self):
        rc, runner, _ops = self.apply(state(installed=True), ask=lambda quiet=False: None)
        self.assertEqual(rc, 1)
        joined = "\n".join(self.out)
        self.assertIn("FAILED at step 4 (Certificate): needs a Cloudflare API token", joined)
        self.assertFalse(any("acme --install-cert" in c[2] for c in runner.calls if c[0] == "run"))

    def test_preflight_asks_cloudflare_first(self):
        """With a token, Cloudflare says whether the record is right; the host looks the name up only then."""
        for cf_state, mode in (("ok", "check"), ("absent", "skip"), ("ours", "skip")):
            with self.subTest(cf_state):
                self.cf_calls.clear()
                _rc, runner, _ops = self.apply(state(installed=True, token=True), cf_state=cf_state,
                                               ask=lambda quiet=False: TOKEN)
                preflight = next(c for c in runner.calls if c[0] == "run" and "preflight passed" in c[2])
                self.assertEqual(preflight[3], (mode,))

    def test_a_record_tn_did_not_make_stops_preflight(self):
        rc, runner, _ops = self.apply(state(installed=True, token=True), cf_state="foreign",
                                      ask=lambda quiet=False: TOKEN)
        self.assertEqual(rc, 1)
        self.assertIn("that tn did not make", "\n".join(self.out))
        self.assertFalse(any("acme --install-cert" in c[2] for c in runner.calls if c[0] == "run"))

    def test_without_a_token_preflight_looks_softly(self):
        _rc, runner, _ops = self.apply(state(installed=True), ask=lambda quiet=False: None)
        preflight = next(c for c in runner.calls if c[0] == "run" and "preflight passed" in c[2])
        self.assertEqual(preflight[3], ("soft",))

    def test_token_check(self):
        self.assertIsNone(acme.token_problem(TOKEN))
        for bad in ("", "short", "has space " + "x" * 30, "quote'" + "x" * 30):
            self.assertIsNotNone(acme.token_problem(bad), bad)


class IssueSandboxTest(TempDirTest):
    """Runs the exact issue body with a stub acme.sh, systemctl and openssl."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(OVS_DOMAIN))
        self.region = self.site.regions["ovs"]
        self.box = Sandbox(self.tmp, self.site)
        self.acme = self.box.root / "acme"
        self.units = self.box.root / "units"
        self.units.mkdir()
        (self.box.etc / "tls").mkdir(parents=True)
        (self.box.etc / ".tailnet-ops").write_text("tailnet-ops region=ovs\n")
        (self.box.etc / "tls" / "ca.crt").write_text("old site CA\n")
        (self.acme / "dnsapi").mkdir(parents=True)
        (self.acme / "data" / "old.example.com_ecc").mkdir(parents=True)
        (self.acme / "cloudflare.env").write_text(f"export CF_Token='{TOKEN}'\n")
        stub = self.acme / "acme.sh"
        stub.write_text('#!/bin/sh\necho "acme.sh $* token=${CF_Token:-none}" >> "$STUB_LOG"\n'
                        'case " $* " in *" --issue "*) exit "${STUB_ISSUE:-0}" ;; esac\nexit 0\n')
        stub.chmod(0o755)
        openssl = self.tmp / "stubs" / "openssl"
        openssl.write_text('#!/bin/sh\necho "subject=CN = hs-ovs.example.com"\n')
        openssl.chmod(0o755)

    def run_issue(self, **env):
        script = self.box.script(acme.issue(self.region), self.region)
        for var, real, fake in (("ACME", acme.DIR, self.acme), ("CERT_SERVICE", acme.SERVICE, self.units / "c.service"),
                                ("CERT_TIMER", acme.TIMER, self.units / "c.timer")):
            self.assertIn(f"{var}={real}\n", script)
            script = script.replace(f"{var}={real}\n", f"{var}={fake}\n")
        return run_bash(script, env={**self.box.env, **env})

    def test_issues_installs_and_enables_the_renewal(self):
        p = self.run_issue()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        log = self.box.stub_log()
        self.assertIn(f"--issue --server letsencrypt --dns dns_cf -d hs-ovs.example.com --keylength ec-256 "
                      f"--dnssleep {pins.ACME_DNS_SLEEP} token={TOKEN}", log)
        install = next(line for line in log.splitlines() if "--install-cert" in line)
        self.assertTrue(install.endswith("token=none"), install)     # the token stays in the issue's subshell
        self.assertIn(f"--reloadcmd {self.acme}/installed.sh", install)
        self.assertIn("systemctl enable --now c.timer", log)
        self.assertIn("issued a certificate for hs-ovs.example.com", p.stdout)
        self.assertIn("dropped the certificate for old.example.com", p.stdout)
        self.assertFalse((self.box.etc / "tls" / "ca.crt").exists())
        self.assertTrue((self.acme / "installed.sh").exists())
        self.assertEqual((self.units / "c.timer").read_text().splitlines()[0], "# tailnet-ops region=ovs")
        again = self.run_issue(STUB_ISSUE="2")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("the certificate for hs-ovs.example.com is current; kept it", again.stdout)
        self.assertNotIn("wrote", again.stdout)

    def test_a_failed_issue_stops(self):
        p = self.run_issue(STUB_ISSUE="1")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("acme.sh could not get a certificate for hs-ovs.example.com (exit 1)", p.stderr)
        self.assertNotIn("--install-cert", self.box.stub_log())

    def test_refuses_foreign_units(self):
        (self.units / "c.timer").write_text("[Timer]\n")
        p = self.run_issue()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("exists and is not ours", p.stderr)

    def test_save_token_checks_what_it_writes(self):
        target = self.tmp / "acme-dir"
        target.mkdir()
        argv = acme.save_token_argv()[:-1] + [str(target)]
        ok = subprocess.run(argv, input=TOKEN + "\n", capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual((target / "cloudflare.env").read_text(), f"export CF_Token='{TOKEN}'\n")
        self.assertEqual((target / "cloudflare.env").stat().st_mode & 0o777, 0o600)
        bad = subprocess.run(argv, input="x'; rm -rf /\n", capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual((target / "cloudflare.env").read_text(), f"export CF_Token='{TOKEN}'\n")


class JoinTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site(example_text(OVS_DOMAIN, CN_DOMAIN))
        self.out = []

    def job(self, runner, alias="cn-probe"):
        return join.Join(self.site, alias, runner=runner, ops=JoinOps(ca=None), out=self.out.append)

    def test_needs_no_site_ca(self):
        job = self.job(FakeRunner())
        self.assertEqual(job.site_ca(), (None, None))
        self.assertIn("CA_LOGINS=''", job.prelude)
        self.assertIn("PUBLIC_LOGINS=https://hs-cn.example.com:9443", job.prelude)
        text, _ = job.plan_text()
        self.assertIn("Step 3/7  Trust  [read-only]", text)
        self.assertIn("over TLS with the system's CAs", text)
        self.assertNotIn("<site CA certificate", text)
        self.assertNotIn("update-ca-certificates\n", text.split("Step 3/7", 1)[1].split("Step 4/7", 1)[0])

    def test_preflight_without_a_ca_parses(self):
        for script in (join.preflight(None), join.TRUST_CHECK):
            p = subprocess.run([bash(), "-n"], input=scripts.wrap(self.job(FakeRunner()).prelude, script),
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("ca()", join.preflight(None))

    def test_a_joined_host_moves_to_the_new_login_server(self):
        prefs = json.dumps({"ControlURL": "https://198.51.100.10:9443", "AdvertiseRoutes": ["10.255.2.0/24"]})
        runner = FakeRunner({**join_responses(status=status()), join.PREFS_JSON: prefs})
        self.job(runner)._run_join()
        pipes = [c for c in runner.calls if c[0] == "pipe"]
        self.assertEqual(len(pipes), 1)
        argv = pipes[0][4]
        self.assertIn("--login-server=https://hs-cn.example.com:9443", argv)
        self.assertIn("--force-reauth", argv)
        self.assertIn("--advertise-routes=10.255.2.0/24", argv)
        self.assertIn("    cn: logged in to https://198.51.100.10:9443; moving it to https://hs-cn.example.com:9443 "
                      "with a new key", self.out)

    def test_a_host_on_the_right_server_stays(self):
        prefs = json.dumps({"ControlURL": "https://hs-cn.example.com:9443"})
        runner = FakeRunner({**join_responses(status=status()), join.PREFS_JSON: prefs})
        self.job(runner)._run_join()
        self.assertFalse(any(c[0] == "pipe" for c in runner.calls))

    def test_clash_leaves_the_login_server_names_alone(self):
        js = apple.clash_script(self.site)
        self.assertIn('"DOMAIN,hs-cn.example.com,DIRECT"', js)
        self.assertIn('["+.tailnet.internal", "hs-cn.example.com", "hs-ovs.example.com"]', js)

    def test_mixed_regions_check_each_login_server_its_way(self):
        site = self.load_site(example_text(OVS_DOMAIN), name="mixed")
        job = join.Join(site, "cn-probe", ops=JoinOps(), out=self.out.append)
        self.assertEqual([r.name for r in job.ca_regions], ["cn"])
        self.assertIn("CA_LOGINS=https://198.51.100.10:9443", job.prelude)
        self.assertIn("PUBLIC_LOGINS=''", job.prelude)
        with self.assertRaises(StepError):
            join.Join(site, "cn-probe", ops=JoinOps(ca=None), out=self.out.append)._ca()
