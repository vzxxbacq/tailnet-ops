import contextlib
import io
import os
from unittest import mock

from tailnet_ops import cli, init, remote
from tailnet_ops import site as sitemod
from tailnet_ops.remote import Result
from tests import test_init
from tests.helpers import TempDirTest


def run_cli(*argv, stdin_answers=None):
    out, err = io.StringIO(), io.StringIO()
    patches = [mock.patch.object(remote, "known_alias", lambda alias: True)]
    if stdin_answers is not None:
        it = iter(stdin_answers)
        patches.append(mock.patch("builtins.input", lambda prompt="": next(it)))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class CliTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.make_site_dir()

    def test_site_check(self):
        rc, out, err = run_cli("site", "check", "--site", str(self.site))
        self.assertEqual(rc, 0, err)
        self.assertIn("region cn: cn-control -> https://198.51.100.10:9443", out)
        self.assertIn("host ovs-control: tailscale_port 41641/udp", out)
        rc, out, _ = run_cli("--redact", "site", "check", "--site", str(self.site))
        self.assertIn("region cn: <cn-control> -> https://<cn-public-ip>:9443", out)

    def test_site_check_reports_permissions(self):
        os.chmod(self.site / "site.toml", 0o644)
        rc, _out, err = run_cli("site", "check", "--site", str(self.site))
        self.assertEqual(rc, 1)
        self.assertIn("chmod 0600", err)

    def test_plan_logs_privately_and_changes_nothing(self):
        rc, out, err = run_cli("control", "plan", "ovs", "--site", str(self.site))
        self.assertEqual(rc, 0, err)
        self.assertIn("  8  Check TLS, DERP and STUN from ovs-probe (read-only)", out)
        self.assertIn("  2  Install Headscale 0.29.6", out)
        self.assertIn("remove the binary", out)
        self.assertNotIn("Step 8/8", out)
        self.assertNotIn("set -euo pipefail", out)
        runs = self.site / "runs"
        self.assertEqual(runs.stat().st_mode & 0o777, 0o700)
        logs = list(runs.iterdir())
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].stat().st_mode & 0o777, 0o600)
        self.assertIn("Step 8/8  Verify", logs[0].read_text())
        self.assertIn("set -euo pipefail", logs[0].read_text())
        self.assertFalse((self.site / "pki").exists())
        rc, out, _err = run_cli("control", "plan", "ovs", "--full", "--site", str(self.site))
        self.assertIn("Step 8/8  Verify", out)

    def test_line_list(self):
        rc, out, err = run_cli("line", "list", "--site", str(self.site))
        self.assertEqual(rc, 0, err)
        self.assertIn("Line", out)
        self.assertIn("line1  cn-gateway → ovs-line (one-way)  203.0.113.30:11011  wg-line1 192.0.2.1 ⇄ 192.0.2.2", out)
        rc, out, _err = run_cli("--redact", "line", "list", "--site", str(self.site))
        self.assertNotIn("cn-gateway", out)
        self.assertNotIn("203.0.113.30", out)
        header, row = out.splitlines()[:2]
        self.assertEqual(header.index("Entry"), row.index("<line1-entry-ip>"))

    def test_redacted_output_has_no_site_names(self):
        hosts = ("cn-control", "cn-probe", "ovs-control", "ovs-probe", "cn-gateway", "ovs-line", "line1")
        for argv in (("control", "plan", "cn"), ("join", "plan", "cn-probe", "--offline"),
                     ("line", "plan", "line1", "--offline"), ("line", "list"), ("site", "check")):
            with self.subTest(argv=argv):
                rc, out, err = run_cli("--redact", *argv, "--site", str(self.site))
                self.assertEqual(rc, 0, err)
                for host in hosts:
                    self.assertNotRegex(out, rf"(?<![\w<:-]){host}(?![\w>])", f"{host} in {argv}")
                self.assertNotIn("wg-line1", out)

    def test_join_plan(self):
        rc, out, err = run_cli("join", "plan", "cn-probe", "--offline", "--site", str(self.site))
        self.assertEqual(rc, 0, err)
        self.assertIn("cn-probe → region cn (its checker host): tailnet 100.64.0.0/16", out)
        self.assertIn("checks        not run (--offline)", out)
        self.assertIn("  5  Join with a one-time tagged key  log out, delete the node and its key on cn-control", out)
        ready = "TN-FACT os=Ubuntu 24.04 LTS\nTN-FACT machine=x86_64\nTN-FACT arch=amd64\nTN-FACT port=free\nTN-FACT login=ok\n"
        with mock.patch.object(remote.SSHRunner, "run", lambda *a, **k: Result(0, ready)):
            (self.site / "pki").mkdir(mode=0o700)
            sitemod.write_private(self.site / "pki" / "ca.crt", "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n")
            rc, out, err = run_cli("join", "plan", "cn-probe", "--site", str(self.site))
        self.assertEqual(rc, 0, err)
        self.assertIn("✓ cn-probe reaches it over TLS", out)
        self.assertIn("✓ Ready: every read-only check on cn-probe passed.", out)
        rc, _out, err = run_cli("join", "plan", "nowhere", "--offline", "--site", str(self.site))
        self.assertEqual(rc, 1)
        self.assertIn("not in any region", err)

    def test_plan_redacted(self):
        rc, out, _ = run_cli("control", "plan", "cn", "--redact", "--site", str(self.site))
        self.assertEqual(rc, 0)
        self.assertNotIn("198.51.100.10", out)
        self.assertNotIn(" cn-control ", out)
        self.assertIn("<cn-public-ip>", out)

    def test_env_site(self):
        with mock.patch.dict(os.environ, {"TN_SITE": str(self.site)}):
            rc, _out, err = run_cli("site", "check")
        self.assertEqual(rc, 0, err)

    def test_missing_site(self):
        rc, _out, err = run_cli("control", "plan", "cn", "--site", str(self.tmp / "none"))
        self.assertEqual(rc, 1)
        self.assertIn("does not exist", err)


def fake_run(runner, host, script, args=(), privileged=False, check=True, echo=True):
    assert script == init.FACTS_SCRIPT and not privileged
    return Result(0, {"cn-edge": test_init.CN_EDGE, "ovs-edge": test_init.OVS_EDGE}.get(host, test_init.PROBE))


class InitCliTest(TempDirTest):
    def run_init(self, *extra, answers=None):
        with mock.patch.object(remote.SSHRunner, "run", fake_run), \
                mock.patch.object(remote, "ssh_hostname_ipv4", lambda h: test_init.HOSTNAMES[h]):
            return run_cli("init", *extra, stdin_answers=answers or test_init.ANSWERS)

    def test_writes_a_new_site(self):
        d = self.tmp / "newsite"
        rc, out, err = self.run_init("--site", str(d), answers=test_init.ANSWERS + ["yes"])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        self.assertEqual((d / "site.toml").stat().st_mode & 0o777, 0o600)
        rc, out, err = run_cli("site", "check", "--site", str(d))
        self.assertEqual(rc, 0, err)

    def test_compares_with_an_existing_site(self):
        d = self.tmp / "newsite"
        self.run_init("--site", str(d), answers=test_init.ANSWERS + ["yes"])
        before = (d / "site.toml").read_text()
        rc, out, _err = self.run_init("--site", str(d))
        self.assertEqual(rc, 0)
        self.assertIn("Same settings as the existing", out)
        self.assertEqual((d / "site.toml").read_text(), before)

    def test_refuses_git_tree(self):
        (self.tmp / ".git").mkdir()
        rc, _out, err = self.run_init("--site", str(self.tmp / "s"))
        self.assertEqual(rc, 1)
        self.assertIn("inside the Git work tree", err)
