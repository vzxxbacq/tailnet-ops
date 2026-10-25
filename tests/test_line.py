import shutil
import subprocess
import unittest

from tailnet_ops import line as linemod
from tailnet_ops import scripts
from tailnet_ops import site as sitemod
from tailnet_ops.procedure import StepError
from tailnet_ops.remote import Result
from tests.helpers import FakeRunner, TempDirTest, bash, example_text

PUB_I = "I" * 43 + "="
PUB_R = "R" * 43 + "="


class LineSiteTest(TempDirTest):
    def test_tunnel_fields(self):
        ln = self.load_site().lines[0]
        self.assertEqual(ln.port, 11011)
        self.assertEqual(ln.interface, "wg-line1")
        self.assertEqual(ln.tunnel_addresses, ("192.0.2.1", "192.0.2.2"))

    def test_tunnel_validation(self):
        for value, message in (('"192.0.2.0/29"', "use a /30"),
                               ('"100.64.200.0/30"', "private range outside 100.64.0.0/10"),
                               ('"nope"', "is not an IPv4 prefix")):
            text = example_text(('tunnel_ipv4 = "192.0.2.0/30"', f"tunnel_ipv4 = {value}"))
            with self.subTest(value=value), self.assertRaises(sitemod.SiteError) as cm:
                sitemod.load(self.make_site_dir(text, name=f"t{len(message)}"), known_host=lambda a: True)
            self.assertIn(message, str(cm.exception))

    def test_needs_port_and_tunnel(self):
        text = example_text(("port = 11011                       # UDP port", "# port"),
                            ('tunnel_ipv4 = "192.0.2.0/30"', "# tunnel"))
        site = self.load_site(text, name="bare")
        with self.assertRaises(StepError) as cm:
            linemod.Line(site, "line1")
        self.assertIn("set port and tunnel_ipv4", str(cm.exception))
        with self.assertRaises(StepError):
            linemod.Line(site, "nope")


class LinePlanTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.ln = self.site.lines[0]

    def test_configs(self):
        responder = linemod.conf(self.ln, "responder", PUB_I)
        self.assertIn("Address = 192.0.2.2/30", responder)
        self.assertIn("ListenPort = 11011", responder)
        self.assertIn(f"PublicKey = {PUB_I}", responder)
        self.assertIn("AllowedIPs = 192.0.2.1/32", responder)
        self.assertNotIn("Endpoint", responder)
        initiator = linemod.conf(self.ln, "initiator", PUB_R)
        self.assertIn("Address = 192.0.2.1/30", initiator)
        self.assertIn("Endpoint = 203.0.113.30:11011", initiator)
        self.assertIn("PersistentKeepalive = 25", initiator)
        self.assertNotIn("ListenPort", initiator)
        for text in (responder, initiator):
            self.assertIn("PostUp = wg set %i private-key /etc/wireguard/wg-line1.key", text)
            self.assertNotIn("PrivateKey", text)

    def test_plan(self):
        job = linemod.Line(self.site, "line1")
        text, digest = job.plan_text()
        self.assertEqual(text.count("  Rollback"), 5)
        self.assertIn("runs the rollbacks of steps 4, 3, 2 in that order", text)
        self.assertEqual(digest, linemod.Line(self.site, "line1").plan_id())
        summary = job.summary_text()
        self.assertIn("tunnel        wg-line1: 192.0.2.1 (cn-gateway) ⇄ 192.0.2.2 (ovs-line)", summary)
        self.assertIn("leaves alone  existing tunnels, nft tables, routes, forwarding", summary)


class LineApplyTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def runner(self):
        class Ends(FakeRunner):
            def run(inner, host, script, **kw):
                FakeRunner.run(inner, host, script, **kw)
                if "wg genkey" in script:
                    return Result(0, f"TN-FACT pub={PUB_I if host == 'cn-gateway' else PUB_R}\n")
                if "TN-LEFT" in script:
                    return Result(0, "")
                return Result(0, "TN-FACT ping=ok\n" if "ping -c" in script else "")
        return Ends()

    def test_apply_order_and_keys(self):
        runner = self.runner()
        job = linemod.Line(self.site, "line1", runner=runner, out=self.out.append)
        self.assertEqual(job.apply(ask=lambda p: "no"), 1)
        self.assertEqual(runner.calls, [])
        self.assertEqual(job.apply(yes=True), 0, "\n".join(self.out))
        order = []
        for _r, host, script, _a, privileged in runner.calls:
            self.assertTrue(privileged)
            for marker, name in (("checks passed", "check"), ("wg genkey", "keys"), ("wg-quick@", "start"),
                                 ("ping -c", "ping")):
                if marker in script:
                    order.append((name, host))
                    break
        self.assertEqual(order, [("check", "cn-gateway"), ("check", "ovs-line"), ("keys", "cn-gateway"),
                                 ("keys", "ovs-line"), ("start", "ovs-line"), ("start", "cn-gateway"),
                                 ("ping", "cn-gateway"), ("ping", "ovs-line")])
        starts = {host: script for _r, host, script, _a, _p in runner.calls if "wg-quick@" in script and "cat >" in script}
        self.assertIn(f"PublicKey = {PUB_I}", starts["ovs-line"])
        self.assertIn(f"PublicKey = {PUB_R}", starts["cn-gateway"])
        self.assertIn("Line line1 is up: cn-gateway 192.0.2.1 ⇄ 192.0.2.2 ovs-line.", self.out[-1])

    def test_rollback(self):
        runner = self.runner()
        job = linemod.Line(self.site, "line1", runner=runner, out=self.out.append)
        self.assertEqual(job.rollback(yes=True), 0, "\n".join(self.out))
        sent = [(c[1], c[2]) for c in runner.calls]
        self.assertEqual(sent[0][0], "cn-gateway")
        self.assertIn(linemod.ROLLBACK_START.strip(), sent[0][1])
        self.assertEqual(sent[1][0], "ovs-line")
        self.assertIn(linemod.ROLLBACK_START.strip(), sent[1][1])
        self.assertIn(linemod.ROLLBACK_KEYS.strip(), sent[2][1])
        self.assertIn(linemod.ROLLBACK_KEYS.strip(), sent[3][1])
        self.assertIn(linemod.LEFTOVERS.strip(), sent[4][1])
        self.assertTrue(any("✓ Nothing left on cn-gateway or ovs-line." in line for line in self.out))

    def test_check_collects_failures(self):
        class Failing(FakeRunner):
            def run(inner, host, script, **kw):
                if host == "ovs-line":
                    return Result(1, "  FAIL  udp/11011 is in use\n")
                return Result(0, "checks passed\n")
        checks = linemod.Line(self.site, "line1", runner=Failing()).check()
        self.assertEqual(checks["fails"], ["ovs-line: udp/11011 is in use"])


class LineScriptsTest(TempDirTest):
    def test_scripts_parse_and_pass_shellcheck(self):
        job = linemod.Line(self.load_site(), "line1")
        bodies = []
        for step in job.steps():
            for action in step.actions:
                if action.body:
                    bodies.append(scripts.wrap(job.preludes_by_side[action.prelude], action.body))
            if step.rollback:
                bodies.append(scripts.wrap(job.preludes_by_side["initiator"], step.rollback))
        bodies.append(scripts.wrap(job.preludes_by_side["responder"], linemod.LEFTOVERS))
        for script in bodies:
            p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            if shutil.which("shellcheck"):
                p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"],
                                   input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)


if __name__ == "__main__":
    unittest.main()
