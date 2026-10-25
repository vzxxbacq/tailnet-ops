from pathlib import Path

from tailnet_ops import pins, render, scripts
from tailnet_ops.control import Deployment, StepError
from tests.helpers import FakeRunner, TempDirTest, example_text

ARCH_FACTS = "TN-FACT arch=amd64\nTN-FACT installed=none\n"
CSR = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
CERT = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
CA = "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n"


class FakeOps:
    def __init__(self, reuse=False):
        self.reuse = reuse
        self.calls = []

    def cached_binary(self, arch):
        self.calls.append(("binary", arch))
        return Path("/cache") / pins.headscale_asset(arch)

    def ensure_ca(self):
        return CA

    def ca_pem(self):
        return CA

    def server_cert(self, region, csr, existing, host_ca):
        self.calls.append(("sign", csr, tuple(region.cert_ips)))
        return CERT, self.reuse


def responses(installed="none"):
    return {
        "TN-FACT arch=": f"TN-FACT arch=amd64\nTN-FACT installed={installed}\n",
        "mktemp -d /tmp/tn-headscale.": "TN-FACT stage=/tmp/tn-headscale.abc123\n",
        'echo "TN-BEGIN csr"': f"TN-BEGIN csr\n{CSR}TN-END csr\n",
    }


class PlanTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()

    def test_plan_prints_every_step_with_rollback(self):
        text, digest = Deployment(self.site, "cn").plan_text()
        for n, title in enumerate(["Preflight", "Binary", "User and directories", "Certificate", "Configuration",
                                   "Start", "Real policy", "Verify"], 1):
            self.assertIn(f"Step {n}/8  {title}", text)
        self.assertEqual(text.count("  Rollback"), 8)
        self.assertIn("runs the rollbacks of steps 6, 5, 4, 3, 2 in that order", text)
        self.assertIn(f"Plan id {digest}", text)
        # The exact files and scripts appear verbatim.
        region = self.site.regions["cn"]
        for chunk in (render.headscale_config(self.site, region), render.systemd_unit(region),
                      render.policy(self.site, region), scripts.ROLLBACK_USER_AND_DIRS):
            for line in chunk.strip().splitlines():
                if line:
                    self.assertIn(line, text)

    def test_plan_shows_the_reserved_port(self):
        text, _ = Deployment(self.site, "ovs").plan_text()
        self.assertIn("reserves      udp 41641 for Tailscale on ovs-control", text)
        self.assertIn("TAILSCALE_PORT=41641", text)
        self.assertIn("TAILSCALE_PORT=''", Deployment(self.site, "cn").plan_text()[0])

    def test_plan_touches_nothing(self):
        dep = Deployment(self.site, "ovs", runner=None)
        dep.plan_text()
        self.assertFalse(self.site.runs_dir.exists())
        self.assertFalse(self.site.pki_dir.exists())

    def test_plan_id_is_stable_and_tracks_the_site(self):
        a = Deployment(self.site, "cn").plan_id()
        self.assertEqual(a, Deployment(self.site, "cn").plan_id())
        moved = self.load_site(example_text(("port = 9443", "port = 9444")), name="moved")
        self.assertNotEqual(a, Deployment(moved, "cn").plan_id())

    def test_unknown_region(self):
        with self.assertRaises(Exception) as cm:
            Deployment(self.site, "eu")
        self.assertIn("unknown region 'eu'", str(cm.exception))


class ApplyTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def dep(self, runner, ops=None, region="cn"):
        return Deployment(self.site, region, runner=runner, ops=ops or FakeOps(), out=self.out.append)

    def test_needs_yes(self):
        runner = FakeRunner()
        rc = self.dep(runner).apply(ask=lambda prompt: "y")
        self.assertEqual(rc, 1)
        self.assertEqual(runner.calls, [])
        self.assertIn("Not applied; nothing changed.", self.out)

    def test_runs_every_step_in_order(self):
        runner = FakeRunner(responses())
        ops = FakeOps()
        rc = self.dep(runner, ops).apply(ask=lambda prompt: "yes")
        self.assertEqual(rc, 0, "\n".join(self.out))
        kinds = []
        for call in runner.calls:
            if call[0] == "upload":
                kinds.append(("upload", call[1], call[3]))
                continue
            _run, host, script, args, privileged = call
            for marker, name in (("check_port tcp", "preflight"), ("mktemp -d", "stage"),
                                 ("install -o root -g root -m 0755", "install"), ("useradd --system", "user"),
                                 ('echo "TN-BEGIN csr"', "csr"), ("server.crt.tn-new", "cert"),
                                 ("configtest --config", "config"), ("systemctl enable --now", "start"),
                                 ("policy check -f", "policy"), ("3/3 STUN", "verify")):
                if marker in script:
                    kinds.append((name, host, privileged, args))
                    break
        self.assertEqual(kinds, [
            ("preflight", "cn-control", True, ()),
            ("stage", "cn-control", False, ()),
            ("upload", "cn-control", "/tmp/tn-headscale.abc123/headscale"),
            ("install", "cn-control", True, ("/tmp/tn-headscale.abc123",)),
            ("user", "cn-control", True, ()),
            ("csr", "cn-control", True, ()),
            ("cert", "cn-control", True, ()),
            ("config", "cn-control", True, ()),
            ("start", "cn-control", True, ()),
            ("policy", "cn-control", True, ()),
            ("verify", "cn-probe", False, ()),
        ])
        self.assertEqual(ops.calls[0], ("binary", "amd64"))
        self.assertEqual(ops.calls[1], ("sign", CSR, ("198.51.100.10",)))
        cert_script = next(c[2] for c in runner.calls if c[0] == "run" and "server.crt.tn-new" in c[2])
        self.assertIn(CERT.strip(), cert_script)
        self.assertIn(CA.strip(), cert_script)
        verify_script = runner.scripts_for("cn-probe")[0]
        self.assertIn(CA.strip(), verify_script)
        self.assertNotIn("<site CA", verify_script)

    def test_skips_upload_when_installed(self):
        runner = FakeRunner(responses(installed=pins.HEADSCALE_SHA256["amd64"]))
        ops = FakeOps(reuse=True)
        self.assertEqual(self.dep(runner, ops).apply(yes=True), 0)
        self.assertFalse(any(c[0] == "upload" for c in runner.calls))
        self.assertNotIn(("binary", "amd64"), ops.calls)
        self.assertFalse(any("server.crt.tn-new" in c[2] for c in runner.calls if c[0] == "run"))

    def test_stops_at_the_failing_step(self):
        runner = FakeRunner(responses(), fail_on="useradd --system")
        rc = self.dep(runner).apply(yes=True)
        self.assertEqual(rc, 1)
        self.assertFalse(any("configtest" in c[2] for c in runner.calls if c[0] == "run"))
        joined = "\n".join(self.out)
        self.assertIn("FAILED at step 3 (User and directories)", joined)
        self.assertIn("tn control rollback cn", joined)

    def test_preflight_failure_changes_nothing(self):
        runner = FakeRunner(responses(), fail_on="check_port tcp")
        self.assertEqual(self.dep(runner).apply(yes=True), 1)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("Nothing was changed.", self.out)


class RollbackVerifyStatusTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def test_rollback_order_and_yes(self):
        runner = FakeRunner()
        dep = Deployment(self.site, "cn", runner=runner, ops=FakeOps(), out=self.out.append)
        self.assertEqual(dep.rollback(ask=lambda p: "no"), 1)
        self.assertEqual(runner.calls, [])
        self.assertEqual(dep.rollback(ask=lambda p: "yes"), 0)
        sent = [c[2] for c in runner.calls]
        expected = [scripts.ROLLBACK_START, scripts.ROLLBACK_CONFIGURATION, scripts.ROLLBACK_CERT,
                    scripts.ROLLBACK_USER_AND_DIRS, scripts.ROLLBACK_BINARY]
        self.assertEqual(len(sent), len(expected))
        for script, body in zip(sent, expected):
            self.assertIn(body.strip(), script)
        self.assertTrue(all(c[4] for c in runner.calls))

    def test_verify_runs_on_checker(self):
        runner = FakeRunner()
        dep = Deployment(self.site, "ovs", runner=runner, ops=FakeOps(), out=self.out.append)
        self.assertEqual(dep.verify(), 0)
        self.assertEqual([(c[1], c[4]) for c in runner.calls], [("ovs-probe", False)])

    def test_verify_needs_the_ca(self):
        class NoCA(FakeOps):
            def ca_pem(self):
                return None

        dep = Deployment(self.site, "cn", runner=FakeRunner(), ops=NoCA(), out=self.out.append)
        with self.assertRaises(StepError):
            dep._run_verify()

    def test_status(self):
        runner = FakeRunner()
        dep = Deployment(self.site, "cn", runner=runner, ops=FakeOps(), out=self.out.append)
        self.assertEqual(dep.status(), 0)
        self.assertIn('"$BIN" nodes list -o json', runner.calls[0][2])
