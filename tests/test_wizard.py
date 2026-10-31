"""tn --tui: the site.toml edit, which nodes move and how, and whole runs with scripted answers.
Offline: the deployment and the tn commands it runs are fakes."""

import io
import json

from tailscale_ops import scripts, site as sitemod
from tailscale_ops.remote import Result
from tailscale_ops.site import SiteError
from tailscale_ops.tui import UI
from tailscale_ops.cloudflare import CloudflareError
from tailscale_ops.wizard import Wizard, compare, movers, nodes_from
from tests.helpers import FakeRunner, TempDirTest, any_host, example_text

NODES = [
    {"id": 1, "given_name": "ovs-control", "ip_addresses": ["100.64.2.1"], "online": True},
    {"id": 2, "given_name": "ovs-probe", "ip_addresses": ["100.64.2.2"], "online": True},
    {"id": 3, "given_name": "web", "ip_addresses": ["100.64.2.3"], "online": True},
    {"id": 4, "given_name": "mymac", "ip_addresses": ["100.64.2.4"], "online": True},
    {"id": 5, "given_name": "stray", "ip_addresses": ["100.64.2.5"], "online": False},
]
JOINED = {
    "web": {"ssh": "web-host", "role": "server", "region": "ovs", "os": "linux"},
    "mymac": {"app": True, "here": True, "role": "personal", "region": "cn", "os": "macos"},
    "cn-box": {"ssh": "cn-box", "role": "server", "region": "cn", "os": "linux"},
}


class SetValueTest(TempDirTest):
    TEXT = ('[site]\nname = "x"\n\n[regions.cn]\nport = 1   # a comment\nstun_port = 2\n\n'
            '# about ovs\n[regions.ovs]\nport = 3\n\n[[lines]]\nname = "l"\n')

    def test_insert_replace_remove(self):
        added = sitemod.set_region_value(self.TEXT, "ovs", "domain", "hs-ovs.example.com")
        self.assertIn('[regions.ovs]\nport = 3\ndomain = "hs-ovs.example.com"\n', added)
        self.assertIn("port = 1   # a comment\n", added)
        changed = sitemod.set_region_value(added, "ovs", "domain", "hs2.example.com")
        self.assertIn('domain = "hs2.example.com"\n', changed)
        self.assertNotIn("hs-ovs", changed)
        self.assertEqual(sitemod.set_region_value(changed, "ovs", "domain", None), self.TEXT)
        self.assertEqual(sitemod.set_region_value(self.TEXT, "ovs", "domain", None), self.TEXT)

    def test_unknown_region(self):
        with self.assertRaises(SiteError):
            sitemod.set_region_value(self.TEXT, "eu", "domain", "x.example.com")

    def test_the_example_still_loads(self):
        text = sitemod.set_region_value(example_text(), "ovs", "domain", "hs-ovs.example.com")
        self.assertEqual(self.load_site(text).regions["ovs"].domain, "hs-ovs.example.com")


class MoversTest(TempDirTest):
    def test_order_and_how(self):
        site = self.load_site()
        site.joined = JOINED
        plan = movers(site, site.regions["ovs"], nodes_from(json.dumps(NODES)))
        self.assertEqual([(p["node"], p["target"]) for p in plan],
                         [("ovs-control", "ovs-control"), ("ovs-probe", "ovs-probe"), ("web", "web"),
                          ("mymac", "mymac"), ("stray", None)])
        self.assertIn("by hand", plan[-1]["how"])

    def test_compare(self):
        before = nodes_from(json.dumps(NODES[:3]))
        after = nodes_from(json.dumps([NODES[0], dict(NODES[1], ip_addresses=["100.64.2.9"])]))
        self.assertEqual([r[3] for r in compare(before, after)], [None, "its address changed", "gone from Headscale"])


class FakeConsole:
    def __init__(self):
        self.shown, self.logged, self.closed = [], [], False

    def out(self, text=""):
        self.shown.append(str(text))

    def show(self, text):
        self.shown.append(str(text))

    def log(self, text):
        self.logged.append(str(text))

    def close(self):
        self.closed = True


class FakeDeployment:
    def __init__(self, site, region, installed=True, nodes=NODES, after=None, fail=None, has_tag=False):
        self.region = site.region(region)
        self.prelude = "PRELUDE"
        self.facts = {}
        self.installed, self.fail = installed, fail
        self.calls = []
        self.runner = FakeRunner({"TN-FACT backup": ""})
        listings = [nodes, after if after is not None else nodes]

        def run(host, script, args=(), privileged=False, check=True, echo=True, secret=False):
            self.calls.append(("run", script))
            if scripts.STATUS.strip() in script:
                return Result(0, json.dumps(listings.pop(0) if len(listings) > 1 else listings[0]))
            if "agent_tag=" in script:
                return Result(0, f"TN-FACT agent_tag={'yes' if has_tag else 'no'}\n")
            return Result(0, "TN-FACT backup=/root/tailnet-ops-backup/ovs-x\n")
        self.runner.run = run

    def preflight(self):
        self.calls.append("preflight")
        self.facts["installed"] = "abc" if self.installed else "none"
        return 1 if self.fail == "preflight" else 0

    def run_once(self, fn):
        fn()
        return 0

    def plan_text(self):
        return "FULL PLAN", "id"

    def summary_text(self):
        return "SHORT PLAN"

    def apply(self, ask=None):
        if ask and ask("Type yes to apply these steps to ovs-control: ") != "yes":
            return 1
        self.calls.append("apply")
        return 0

    def verify(self):
        self.calls.append("verify")
        return 0


class FakeCF:
    def __init__(self, token, state="absent"):
        self.token, self.state = token, state

    def zone_for(self, name):
        if self.state == "no zone":
            raise CloudflareError("no zone this token can read holds " + name)
        return {"id": "z1", "name": "example.com", "account": "a1"}

    def record_state(self, zone, name, kind, content, proxied, mark):
        return self.state, {"type": "A", "content": "192.0.2.9"} if self.state == "foreign" else None, []

    def records(self, zone, name):
        return [{"type": "A", "content": "192.0.2.9", "comment": ""}] if self.state == "foreign" else []


class FakeAgent:
    def __init__(self, site, region, fail=None, passkeys=0):
        self.region = site.region(region)
        self.url = f"https://{self.region.agent_domain}"
        self.calls, self.fail, self.passkeys = [], fail, passkeys

    def preflight(self):
        self.calls.append("preflight")
        return 1 if self.fail == "preflight" else 0

    def run_once(self, fn):
        fn()
        return 0

    def plan_text(self):
        return "FULL AGENT PLAN", "id"

    def summary_text(self):
        return "SHORT AGENT PLAN"

    def apply(self, ask=None):
        if ask and ask("Type yes to apply these steps to ovs-control: ") != "yes":
            return 1
        self.calls.append("apply")
        return 0


    def passkey_count(self):
        return self.passkeys

    def new_enrolment(self):
        self.calls.append("enrol")
        self.passkeys += 1
        return self.url + "/enroll#one-time-code"

    def new_token(self):
        self.calls.append("token")
        return "tna_" + "x" * 43


class WizardCase(TempDirTest):
    def setUp(self):
        super().setUp()
        self.dir = self.make_site_dir()
        sitemod.write_joined(self.dir, JOINED)
        self.deps, self.ran, self.tokens, self.agents, self.clipped = [], [], [], [], []

    def wizard(self, answers, token="cf-token-for-tests-0123456789", cf_state="absent", agent=None, **dep):
        self.out = io.StringIO()
        ui = UI(inp=io.StringIO("".join(a + "\n" for a in answers)), out=self.out, tty=False)

        def open_deployment(site, region, token=None):
            self.tokens.append(token)
            d = FakeDeployment(site, region, **dep)
            self.deps.append(d)
            return d, FakeConsole()

        def tn(argv):
            self.ran.append(argv)
            return 0
        def open_agent(site, region, token=None):
            a = FakeAgent(site, region, **(agent or {}))
            self.agents.append(a)
            return a, FakeConsole()
        return Wizard(ui, lambda: sitemod.load(self.dir, known_host=any_host), open_deployment, tn,
                      ask_token=lambda quiet=False: token, cloudflare=lambda tok: FakeCF(tok, cf_state),
                      open_agent=open_agent if agent is not None else None,
                      clipboard=lambda text: self.clipped.append(text) or True)


class WizardTest(WizardCase):
    def test_switch_to_lets_encrypt_and_move_the_nodes(self):
        rc = self.wizard(["1", "2", "2", "hs-ovs.example.com", "y", "y", "1", "yes", "y"]).run()
        self.assertEqual(rc, 1, self.out.getvalue())                      # stray must be moved by hand
        text = (self.dir / "site.toml").read_text()
        self.assertIn('domain = "hs-ovs.example.com"', text)
        self.assertNotIn("hs-ovs.example.com", (self.dir / "site.toml.bak").read_text())
        dep = self.deps[0]
        self.assertEqual(dep.region.server_url, "https://hs-ovs.example.com:9443")
        self.assertTrue(any(c[0] == "run" and "tailnet-ops-backup" in c[1] for c in dep.calls if isinstance(c, tuple)))
        self.assertEqual([c for c in dep.calls if isinstance(c, str)], ["preflight", "apply", "verify"])
        self.assertEqual(self.ran, [["join", "apply", t, "--yes"] for t in ("ovs-control", "ovs-probe", "web", "mymac")])
        out = self.out.getvalue()
        self.assertIn("make the A record hs-ovs.example.com -> 203.0.113.20, DNS only", out)
        self.assertEqual(self.tokens, ["cf-token-for-tests-0123456789"])   # handed to the deployment
        self.assertIn("stray: not set up by tn", out)
        records = sorted(p.name for p in (self.dir / "runs").iterdir())
        self.assertTrue(any(n.endswith("-nodes-ovs-before.json") for n in records))
        self.assertTrue(any(n.endswith("-nodes-ovs-after.json") for n in records))

    def test_a_changed_address_is_flagged(self):
        after = [dict(n, ip_addresses=["100.64.2.99"]) if n["id"] == 3 else n for n in NODES]
        self.wizard(["1", "2", "2", "hs-ovs.example.com", "y", "y", "1", "yes", "y"], after=after).run()
        self.assertIn("✗ its address changed", self.out.getvalue())

    def test_keep_the_certificate(self):
        before = (self.dir / "site.toml").read_text()
        rc = self.wizard(["1", "1", "1", "1", "yes"], installed=False).run()
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertEqual((self.dir / "site.toml").read_text(), before)
        self.assertFalse((self.dir / "site.toml.bak").exists())
        self.assertEqual(self.ran, [])
        self.assertEqual([c for c in self.deps[0].calls if isinstance(c, str)], ["preflight", "apply", "verify"])

    def test_a_new_region_has_nothing_to_back_up_or_move(self):
        self.wizard(["1", "2", "2", "hs-ovs.example.com", "y", "1", "yes"], installed=False).run()
        self.assertFalse(any(isinstance(c, tuple) for c in self.deps[0].calls))
        self.assertEqual(self.ran, [])

    def test_the_apply_prompt_wants_the_word_yes(self):
        """Typing what the menu said (apply) is asked again; no stops without a word about rollback."""
        rc = self.wizard(["1", "2", "1", "y", "1", "apply", "no"]).run()
        out = self.out.getvalue()
        self.assertEqual(rc, 0, out)
        self.assertIn("type the word yes to start, or no to stop", out)
        self.assertNotIn("apply", self.deps[0].calls)
        self.assertNotIn("rollback", out)
        self.assertIn("Stopped before apply", out)
        rc = self.wizard(["1", "2", "1", "y", "1", "apply", "yes"]).run()
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn("apply", self.deps[1].calls)

    def test_quit_before_apply(self):
        rc = self.wizard(["1", "2", "1", "y", "3"]).run()
        self.assertEqual(rc, 0)
        self.assertNotIn("apply", self.deps[0].calls)

    def test_cloudflare_problems_change_nothing(self):
        before = (self.dir / "site.toml").read_text()
        for kw, said in (({"token": None}, "needs a Cloudflare API token"),
                         ({"cf_state": "foreign"}, "that tn did not make"),
                         ({"cf_state": "no zone"}, "no zone this token can read")):
            with self.subTest(said):
                self.assertEqual(self.wizard(["1", "2", "2", "hs-ovs.example.com"], **kw).run(), 0)
                self.assertIn(said, self.out.getvalue())
                self.assertEqual((self.dir / "site.toml").read_text(), before)
                self.assertEqual(self.deps, [])

    def test_failed_checks_stop_before_anything(self):
        self.assertEqual(self.wizard(["1", "2", "1"], fail="preflight").run(), 1)
        self.assertEqual(self.deps[0].calls, ["preflight"])
        self.assertIn("Nothing changed on ovs-control.", self.out.getvalue())
        self.assertNotIn("site.toml.bak", self.out.getvalue())

    def test_the_site_toml_change_is_told(self):
        self.wizard(["1", "2", "2", "hs-ovs.example.com", "y"], fail="preflight").run()
        self.assertIn("site.toml has the new setting; the one before is in site.toml.bak.", self.out.getvalue())

    def test_bad_domains_are_asked_again(self):
        self.wizard(["1", "2", "2", "not a name", "hs.tailnet.internal", "hs-ovs.example.com"], token=None).run()
        out = self.out.getvalue()
        self.assertIn("a DNS name", out)
        self.assertIn("MagicDNS suffix", out)


OVS_DOMAIN = ('public_ipv4 = "203.0.113.20"', 'public_ipv4 = "203.0.113.20"\ndomain = "hs-ovs.example.com"')


class AgentWizardTest(WizardCase):
    """With tn-agent on offer, the menu is: 1 Headscale and tn-agent, 2 Headscale only, 3 tn-agent only."""

    def setUp(self):
        super().setUp()
        self.dir = self.make_site_dir(example_text(OVS_DOMAIN), name="with-domain")
        sitemod.write_joined(self.dir, JOINED)

    def test_tn_agent_only(self):
        rc = self.wizard(["3", "1", "", "y", "1", "yes", "1", "yes", "y", ""], agent={}).run()
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn('agent_domain = "agent-ovs.example.com"', (self.dir / "site.toml").read_text())
        self.assertIn("apply", self.deps[0].calls)                      # the policy, by tn control apply
        self.assertEqual(self.agents[0].calls, ["preflight", "apply", "enrol"])     # no token made here
        self.assertEqual(self.clipped, ["https://agent-ovs.example.com/enroll#one-time-code",
                                        "https://agent-ovs.example.com/tokens"])
        out = self.out.getvalue()
        self.assertIn("1 passkey(s) registered", out)
        self.assertIn("Tokens made before stay valid", out)

    def test_a_second_run_keeps_the_passkey_and_the_tokens(self):
        """Run again to update: no new passkey unless asked, and no token replaced."""
        rc = self.wizard(["3", "1", "", "y", "1", "yes", "1", "yes", ""], agent={"passkeys": 1}).run()
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn("1 passkey(s) are registered already. Register another one? [y/N]", self.out.getvalue())
        self.assertEqual(self.agents[0].calls, ["preflight", "apply"])

    def test_a_policy_that_owns_the_tag_needs_no_apply(self):
        rc = self.wizard(["3", "1", "", "y", "1", "yes", "n"], agent={}, has_tag=True).run()
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertNotIn("apply", self.deps[0].calls)
        self.assertEqual(self.agents[0].calls, ["preflight", "apply"])

    def test_both_on_a_region_with_a_domain_already(self):
        rc = self.wizard(["1", "2", "", "y", "y", "1", "yes", "1", "yes", "n"], agent={}, has_tag=True).run()
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn('agent_domain = "agent-ovs.example.com"', (self.dir / "site.toml").read_text())
        self.assertEqual([c for c in self.deps[0].calls if isinstance(c, str)], ["preflight", "apply", "verify"])
        self.assertEqual(self.agents[0].calls, ["preflight", "apply"])
        self.assertEqual(self.ran, [])                                   # the login address did not change

    def test_a_record_in_the_way_stops_it(self):
        before = (self.dir / "site.toml").read_text()
        self.assertEqual(self.wizard(["3", "1", ""], agent={}, cf_state="foreign").run(), 0)
        self.assertIn("that tn did not make", self.out.getvalue())
        self.assertEqual((self.dir / "site.toml").read_text(), before)
        self.assertEqual(self.agents, [])


class OneRunTest(WizardCase):
    def test_everything_in_one_run(self):
        """A region on the site CA: every question first, one site.toml change, then Headscale (its policy owns the
        agent tag at once), the nodes' move, tn-agent, the passkey and the token."""
        answers = ["1", "2", "hs-ovs.example.com", "", "y",      # what, region, domain, tn-agent's name, write
                   "y", "1", "yes", "y",                         # backup, apply Headscale, yes, move the nodes
                   "1", "yes", "y", ""]                          # apply tn-agent, yes, passkey, Enter
        rc = self.wizard(answers, agent={}, has_tag=True).run()
        out = self.out.getvalue()
        self.assertEqual(rc, 1, out)                                    # stray must be moved by hand
        text = (self.dir / "site.toml").read_text()
        self.assertIn('domain = "hs-ovs.example.com"', text)
        self.assertIn('agent_domain = "agent-ovs.example.com"', text)
        self.assertNotIn('agent_domain = "agent-ovs.example.com"', (self.dir / "site.toml.bak").read_text())
        self.assertEqual(out.count("Write it to site.toml?"), 1)
        self.assertEqual([c for c in self.deps[0].calls if isinstance(c, str)], ["preflight", "apply", "verify"])
        self.assertNotIn("apply", self.deps[1].calls)                   # the policy check found the tag
        self.assertEqual(self.ran, [["join", "apply", t, "--yes"] for t in ("ovs-control", "ovs-probe", "web", "mymac")])
        self.assertEqual(self.agents[0].calls, ["preflight", "apply", "enrol"])
        self.assertLess(out.index("1/2 · Headscale for ovs"), out.index("2/2 · tn-agent for ovs"))

    def test_tn_agent_waits_for_a_verified_headscale(self):
        self.wizard(["1", "2", "hs-ovs.example.com", "", "y", "y", "3"], agent={}).run()
        self.assertEqual(self.agents, [])


class NoDomainAgentTest(WizardCase):
    def test_needs_a_region_with_a_domain(self):
        self.assertEqual(self.wizard(["3"], agent={}).run(), 1)
        self.assertIn("needs a region whose login server has a domain", self.out.getvalue())
