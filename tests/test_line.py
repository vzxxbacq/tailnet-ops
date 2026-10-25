import json
import os
import shutil
import subprocess

from tailnet_ops import firewall, render, scripts
from tailnet_ops import line as linemod
from tailnet_ops import site as sitemod
from tailnet_ops.procedure import StepError
from tailnet_ops.remote import Result
from tests.helpers import FakeRunner, TempDirTest, bash, example_text

PUB_I = "I" * 43 + "="
PUB_R = "R" * 43 + "="

NFT_POLICY_DROP = json.dumps({"nftables": [
    {"chain": {"family": "inet", "table": "phones", "name": "forward", "hook": "forward", "policy": "drop"}},
    {"rule": {"family": "inet", "table": "phones", "chain": "forward", "expr": [{"accept": None}]}},
]})


def check_output(tsip, nft=NFT_POLICY_DROP, legacy="-P FORWARD ACCEPT"):
    return (f"TN-FACT tsip={tsip}\nTN-FACT forward=1\nTN-BEGIN nft\n{nft}\nTN-END nft\n"
            f"TN-BEGIN legacy\n{legacy}\nTN-END legacy\nchecks passed; nothing was changed\n")


def nodes(name, ip, approved=()):
    return json.dumps([{"id": 1, "given_name": name, "ip_addresses": [ip, "fd7a:115c:a1e0::1"],
                        "approved_routes": list(approved)},
                       {"id": 2, "given_name": f"{name}-member", "ip_addresses": [ip[:-1] + "7"]}])


class LineSiteTest(TempDirTest):
    def test_tunnel_and_alias_fields(self):
        site = self.load_site()
        ln = site.lines[0]
        self.assertEqual((ln.port, ln.interface), (11011, "wg-line1"))
        self.assertEqual(ln.tunnel_addresses, ("192.0.2.1", "192.0.2.2"))
        cn, ovs = site.regions["cn"], site.regions["ovs"]
        self.assertEqual(str(cn.alias_net), "10.255.1.0/24")
        self.assertEqual(ovs.alias_of("100.64.2.7"), "10.255.2.7")

    def test_validation(self):
        for old, new, message in (
            ('tunnel_ipv4 = "192.0.2.0/30"', 'tunnel_ipv4 = "192.0.2.0/29"', "use a /30"),
            ('tunnel_ipv4 = "192.0.2.0/30"', 'tunnel_ipv4 = "100.64.200.0/30"', "private range outside 100.64.0.0/10"),
            ('ipv4_prefix = "100.64.2.0/24"', 'ipv4_prefix = "100.65.0.0/16"', "only /24 tailnets get one by default"),
            ('ipv4_prefix = "100.64.2.0/24"', 'ipv4_prefix = "100.64.2.0/24"\nalias_ipv4 = "192.0.2.0/24"',
             "overlaps lines.line1.tunnel_ipv4"),
        ):
            with self.subTest(new=new), self.assertRaises(sitemod.SiteError) as cm:
                sitemod.load(self.make_site_dir(example_text((old, new)), name=f"v{abs(hash(new))}"),
                             known_host=lambda a: True)
            self.assertIn(message, str(cm.exception))

    def test_policy_grants_the_other_alias(self):
        site = self.load_site()
        doc = json.loads("\n".join(l for l in render.policy(site, site.regions["cn"]).splitlines()
                                   if not l.startswith("//")))
        self.assertIn({"src": ["owner@"], "dst": ["10.255.2.0/24"], "ip": ["*"]}, doc["grants"])
        doc = json.loads("\n".join(l for l in render.policy(site, site.regions["cn"], skip_lines=("line1",)).splitlines()
                                   if not l.startswith("//")))
        self.assertEqual(len(doc["grants"]), 2)

    def test_needs_port_and_tunnel(self):
        text = example_text(("port = 11011                       # UDP port", "# port"),
                            ('tunnel_ipv4 = "192.0.2.0/30"', "# tunnel"))
        site = self.load_site(text, name="bare")
        with self.assertRaises(StepError) as cm:
            linemod.Line(site, "line1")
        self.assertIn("set port and tunnel_ipv4", str(cm.exception))
        with self.assertRaises(StepError):
            linemod.Line(site, "nope")


class FirewallTest(TempDirTest):
    def test_finds_what_drops(self):
        ruleset = json.dumps({"nftables": [
            {"chain": {"family": "inet", "table": "phones", "name": "forward", "hook": "forward", "policy": "drop"}},
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}},
            {"chain": {"family": "inet", "table": "quiet", "name": "fwd", "hook": "forward", "policy": "accept"}},
            {"chain": {"family": "inet", "table": "strict", "name": "fwd", "hook": "forward", "policy": "accept"}},
            {"rule": {"family": "inet", "table": "strict", "chain": "fwd", "expr": [{"drop": None}]}},
            {"chain": {"family": "ip6", "table": "v6", "name": "fwd", "hook": "forward", "policy": "drop"}},
            {"chain": {"family": "inet", "table": "tn_line1", "name": "fwd", "hook": "forward", "policy": "drop"}},
            {"chain": {"family": "inet", "table": "phones", "name": "input", "hook": "input", "policy": "drop"}},
        ]})
        targets = firewall.blocking_targets(ruleset, "-P FORWARD DROP\n", own_tables=("tn_line1",))
        self.assertEqual([(t.kind, t.label(), t.reason) for t in targets], [
            ("nft", "nft inet phones forward", "policy drop"),
            ("nft", "nft inet strict fwd", "drop rules"),
            ("iptables", "iptables FORWARD", "policy drop"),          # Docker or ufw through iptables-nft
            ("iptables-legacy", "iptables-legacy FORWARD", "policy DROP"),
        ])
        self.assertEqual(firewall.blocking_targets("", "-P FORWARD ACCEPT\n"), [])

    def test_allow_script(self):
        targets = firewall.blocking_targets(NFT_POLICY_DROP, "-P FORWARD DROP\n")
        text = firewall.allow_script("line1", "wg-line1", targets, mark="tailnet-ops line=line1 side=initiator")
        self.assertEqual(text.splitlines()[1], "# tailnet-ops line=line1 side=initiator")
        self.assertIn('nft \'insert rule inet phones forward iifname "wg-line1" oifname "tailscale0" counter accept '
                      'comment "tailnet-ops line=line1"\'', text)
        self.assertIn('iifname "tailscale0" oifname "wg-line1"', text)
        self.assertIn("iptables-legacy -I FORWARD 1 -i wg-line1 -o tailscale0", text)
        p = subprocess.run(["sh", "-n"], input=text, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_rules_reach_nft_as_one_argument(self):
        """The shell must not split the rule: nft needs the quoted comment intact."""
        targets = firewall.blocking_targets(NFT_POLICY_DROP, "")
        script = self.tmp / "allow.sh"
        script.write_text(firewall.allow_script("line1", "wg-line1", targets))
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        log = self.tmp / "nft.log"
        (stubs / "nft").write_text(
            '#!/bin/sh\n[ "$1" = list ] && exit 0\nprintf \'%s|\' "$#" "$@" >> "$NFT_LOG"\necho >> "$NFT_LOG"\n')
        (stubs / "nft").chmod(0o755)
        env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "NFT_LOG": str(log)}
        for mode in ("add", "dry"):
            p = subprocess.run(["sh", str(script), mode], capture_output=True, text=True, env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
        calls = log.read_text().splitlines()
        self.assertEqual(len(calls), 4)
        want = ('insert rule inet phones forward iifname "wg-line1" oifname "tailscale0" counter accept '
                'comment "tailnet-ops line=line1"')
        self.assertEqual(calls[0], f"1|{want}|")
        self.assertEqual(calls[2], f"2|-c|{want}|")


class LinePlanTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.ln = self.site.lines[0]

    def test_configs(self):
        responder = linemod.conf(self.ln, "responder", PUB_I, "10.255.1.0/24")
        self.assertIn("ListenPort = 11011", responder)
        self.assertIn("AllowedIPs = 192.0.2.1/32, 10.255.1.0/24", responder)
        self.assertNotIn("Endpoint", responder)
        initiator = linemod.conf(self.ln, "initiator", PUB_R, "10.255.2.0/24")
        self.assertIn("Endpoint = 203.0.113.30:11011", initiator)
        self.assertIn("PersistentKeepalive = 25", initiator)
        for text in (responder, initiator):
            self.assertIn("PostUp = nft -f /etc/wireguard/wg-line1.nft", text)
            self.assertIn("PostUp = /etc/wireguard/wg-line1-allow.sh add", text)
            self.assertIn("PostDown = nft delete table inet tn_line1 2>/dev/null || true", text)
            self.assertNotIn("PrivateKey", text)

    def test_nat(self):
        text = linemod.nft_rules(self.ln, "responder", "100.64.2.0/24", "10.255.2.0/24", "100.64.2.1")
        self.assertIn('iifname "wg-line1" ip daddr 10.255.2.0/24 dnat ip prefix to ip daddr map '
                      '{ 10.255.2.0/24 : 100.64.2.0/24 }', text)
        self.assertIn('oifname "wg-line1" ip saddr 100.64.2.0/24 snat ip to 192.0.2.2', text)
        self.assertIn('iifname "wg-line1" oifname "tailscale0" snat ip to 100.64.2.1', text)

    def test_plan(self):
        job = linemod.Line(self.site, "line1")
        text, digest = job.plan_text()
        self.assertEqual(text.count("  Rollback"), 6)
        self.assertIn("runs the rollbacks of steps 5, 4, 3, 2 in that order", text)
        self.assertEqual(digest, linemod.Line(self.site, "line1").plan_id())
        summary = job.summary_text()
        self.assertIn("addresses     cn hosts appear in ovs as 10.255.1.0/24; ovs hosts appear in cn as 10.255.2.0/24",
                      summary)
        self.assertIn("routes        cn-gateway advertises 10.255.2.0/24 into cn", summary)


class Ends(FakeRunner):
    """Both ends and both control hosts of the example line, answering like real hosts."""

    def __init__(self, ping_ok=True):
        super().__init__()
        self.ping_ok = ping_ok
        self.prefs = {"cn-gateway": [], "ovs-line": []}

    def run(self, host, script, **kw):
        FakeRunner.run(self, host, script, **kw)
        ts = {"cn-gateway": "100.64.1.3", "ovs-line": "100.64.2.4"}
        if "checks passed" in script:
            return Result(0, check_output(ts[host]))
        if "wg genkey" in script:
            return Result(0, f"TN-FACT pub={PUB_I if host == 'cn-gateway' else PUB_R}\n")
        if "debug prefs" in script:
            return Result(0, json.dumps({"AdvertiseRoutes": self.prefs[host]}))
        if "--advertise-routes=" in script:
            routes = script.split("--advertise-routes=", 1)[1].split("\n", 1)[0]
            self.prefs[host] = [r for r in routes.split(",") if r]
            return Result(0, "")
        if "nodes list -o json" in script:
            return Result(0, nodes("cn-gateway", "100.64.1.3") if host == "cn-control" else nodes("ovs-line", "100.64.2.4"))
        if "TN-PING" in script:
            addrs = [w for w in script.split() if w.count(".") == 3 and w[0].isdigit()]
            dsts = [a for a in addrs if not a.startswith(("100.64.", "1.", "2."))]
            return Result(0, "".join(f"TN-PING {a} {'ok' if self.ping_ok else 'fail'}\n" for a in dsts))
        if '"$TS_BIN" ip -4' in script:
            return Result(0, ts[host] + "\n")
        if "TN-LEFT" in script:
            return Result(0, "")
        return Result(0, "")


class LineApplyTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def job(self, runner):
        return linemod.Line(self.site, "line1", runner=runner, out=self.out.append)

    def test_apply(self):
        runner = Ends()
        job = self.job(runner)
        self.assertEqual(job.apply(ask=lambda p: "no"), 1)
        self.assertTrue(runner.calls and all("checks passed; nothing was changed" in c[2] for c in runner.calls))
        runner.calls.clear()
        self.assertEqual(job.apply(yes=True), 0, "\n".join(self.out))
        ends = {h: s for _r, h, s, _a, _p in runner.calls if "cat > \"$CONF.tn-new\"" in s}
        self.assertIn(f"PublicKey = {PUB_I}", ends["ovs-line"])
        self.assertIn(f"PublicKey = {PUB_R}", ends["cn-gateway"])
        self.assertIn("snat ip to 100.64.2.4", ends["ovs-line"])
        self.assertIn("nft 'insert rule inet phones forward", ends["cn-gateway"])
        self.assertIn('"$ALLOW" dry || die', ends["cn-gateway"])
        self.assertEqual(runner.prefs, {"cn-gateway": ["10.255.2.0/24"], "ovs-line": ["10.255.1.0/24"]})
        approvals = [s for _r, h, s, _a, _p in runner.calls if "approve-routes" in s]
        self.assertEqual(len(approvals), 2)
        self.assertIn('-r "10.255.2.0/24"', approvals[0])
        policies = [(h, s) for _r, h, s, _a, _p in runner.calls if "policy check -f" in s]
        self.assertEqual([h for h, _s in policies], ["cn-control", "ovs-control"])
        self.assertIn("10.255.2.0/24", policies[0][1])
        self.assertTrue(any("✓ cn → ovs: ovs-line-member at 10.255.2.7" in line for line in self.out), self.out)
        self.assertIn("Line line1 connects cn and ovs", self.out[-1])

    def test_apply_shows_the_same_plan_id_as_plan(self):
        runner = Ends()
        planned = self.job(runner)
        planned.check()
        planned_id = planned.plan_id()
        self.job(Ends()).apply(ask=lambda p: "no")
        self.assertTrue(any(f"plan id {planned_id}" in line for line in self.out), self.out[:3])

    def test_verify_reports_each_host(self):
        runner = Ends(ping_ok=False)
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_verify()
        self.assertIn("cannot reach ovs-line-member at 10.255.2.7", str(cm.exception))

    def test_rollback(self):
        runner = Ends()
        runner.prefs = {"cn-gateway": ["10.255.2.0/24", "192.0.2.128/25"], "ovs-line": ["10.255.1.0/24"]}
        job = self.job(runner)
        self.assertEqual(job.rollback(yes=True), 0, "\n".join(self.out))
        self.assertEqual(runner.prefs, {"cn-gateway": ["192.0.2.128/25"], "ovs-line": []})
        policies = [s for _r, h, s, _a, _p in runner.calls if "policy check -f" in s]
        self.assertTrue(policies and all("10.255." not in s for s in policies))
        ends = [h for _r, h, s, _a, _p in runner.calls if linemod.ROLLBACK_END.strip() in s]
        self.assertEqual(ends, ["cn-gateway", "ovs-line"])  # step 4 (initiator) is undone before step 3

    def test_check_collects_failures(self):
        class Failing(FakeRunner):
            def run(inner, host, script, **kw):
                if host == "ovs-line":
                    return Result(1, "  FAIL  udp/11011 is in use\n")
                return Result(0, check_output("100.64.1.3"))
        checks = linemod.Line(self.site, "line1", runner=Failing()).check()
        self.assertEqual(checks["fails"], ["ovs-line: udp/11011 is in use"])
        self.assertEqual([t.label() for t in checks["targets"]["initiator"]], ["nft inet phones forward"])


class LineScriptsTest(TempDirTest):
    def test_scripts_parse_and_pass_shellcheck(self):
        job = linemod.Line(self.load_site(), "line1")
        job.targets = {"initiator": firewall.blocking_targets(NFT_POLICY_DROP, "-P FORWARD DROP"), "responder": []}
        bodies = []
        for step in job.steps():
            for action in step.actions:
                if action.body:
                    bodies.append(scripts.wrap(job.preludes_by_side[action.prelude], action.body))
            if step.rollback and step.undo is None:  # a custom undo runs from this machine, not as this script
                bodies.append(scripts.wrap(job.preludes_by_side["initiator"], step.rollback))
        bodies.append(scripts.wrap(job.preludes_by_side["responder"], linemod.LEFTOVERS))
        bodies.append(scripts.wrap(job.preludes_by_side["initiator"],
                                   linemod.ping_many([("a", "10.255.2.7")], "100.64.1.3")))
        for script in bodies:
            p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            if shutil.which("shellcheck"):
                p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"],
                                   input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)
