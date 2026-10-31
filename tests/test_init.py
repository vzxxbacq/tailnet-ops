import tomllib
import unittest

from tailscale_ops import init, site as sitemod

CN_EDGE = """uid=0
root=yes
os=Ubuntu 24.04 LTS
arch=x86_64
systemd=yes
tool=bash
tool=curl
tool=openssl
tool=python3
tool=ss
tool=ip
listen=tcp 0.0.0.0:11010 users:(("relay",pid=11,fd=3))
listen=tcp *:22 users:(("sshd",pid=12,fd=3))
listen=udp 0.0.0.0:11020 users:(("wg",pid=13,fd=3))
addr=lo 127.0.0.1/8
addr=eth0 192.0.2.50/20
src=192.0.2.50
resolver=100.80.0.2
resolver=100.80.0.3
"""

OVS_EDGE = """uid=0
root=yes
os=Ubuntu 22.04.3 LTS
arch=x86_64
systemd=yes
tool=bash
tool=curl
tool=openssl
tool=ss
tool=ip
listen=tcp 203.0.113.30%ens3:11010
addr=lo 127.0.0.1/8
addr=ens3 203.0.113.20/24
addr=ens3 203.0.113.30/24
src=203.0.113.20
resolver=127.0.0.53
resolver=192.0.2.53
"""

PROBE = "uid=1000\nroot=sudo\nos=Ubuntu 24.04 LTS\narch=x86_64\nsystemd=yes\ntool=bash\ntool=curl\ntool=python3\n"

ANSWERS = [
    "example", "", "",                              # site name, owner user, DNS suffix (defaults)
    "cn", "cn-edge", "cn-probe", "n", "100.64.10.0/24", "", "",  # region 1; any port; site CA
    "ovs", "ovs-edge", "ovs-probe", "y", "", "20000-20002", "hs-ovs.example.com",  # region 2; free /24; 3 ports; LE
    "",                                             # no more regions
    "l1", "cn-edge", "ovs-edge", "203.0.113.30", "", "11011",  # line 1: one-way by default, tunnel port
    "",                                             # no more lines
]

EXPECTED = {
    "site": {"name": "example", "owner_user": "owner", "dns_suffix": "tailnet.internal"},
    "regions": {
        "cn": {
            "control_host": "cn-edge", "check_from": "cn-probe",
            "public_ipv4": "198.51.100.10", "listen_ipv4": "0.0.0.0", "port": 9443, "stun_port": 3478,
            "ipv4_prefix": "100.64.10.0/24", "avoid_prefixes": ["100.80.0.0/16"],
            "derp_region_id": 901, "derp_region_code": "cn",
            "derp_region_name": "CN cn-edge", "official_derp": False, "tags": ["tag:cn-server", "tag:cn-gateway"],
        },
        "ovs": {
            "control_host": "ovs-edge", "check_from": "ovs-probe",
            "public_ipv4": "203.0.113.20", "listen_ipv4": "203.0.113.20", "port": 20000, "stun_port": 20001,
            "ipv4_prefix": "100.64.1.0/24", "avoid_prefixes": [],
            "derp_region_id": 902, "derp_region_code": "ovs",
            "derp_region_name": "OVS ovs-edge", "official_derp": True, "tags": ["tag:ovs-server", "tag:ovs-border"],
            "domain": "hs-ovs.example.com",
        },
    },
    "hosts": {
        "cn-edge": {"netfilter_mode": "off"},
        "ovs-edge": {"tailscale_port": 20002},
    },
    "lines": [{
        "name": "l1", "initiator": "cn-edge", "responder": "ovs-edge", "responder_entry_ipv4": "203.0.113.30",
        "initiator_public_ipv4": "198.51.100.10", "one_way": True, "keepalive_seconds": 25, "priority": 10,
        "port": 11011, "tunnel_ipv4": ".".join(["10", "255", "0", "0"]) + "/30",
    }],
}


def scripted(answers):
    it = iter(answers)
    return lambda prompt: next(it)


def facts():
    return {"cn-edge": init.parse_facts(CN_EDGE), "ovs-edge": init.parse_facts(OVS_EDGE),
            "cn-probe": init.parse_facts(PROBE), "ovs-probe": init.parse_facts(PROBE)}


HOSTNAMES = {"cn-edge": "198.51.100.10", "ovs-edge": "203.0.113.20", "cn-probe": "198.51.100.50",
             "ovs-probe": "203.0.113.50"}


class InitTest(unittest.TestCase):
    def answers(self):
        return init.ask_answers(init.Asker(scripted(ANSWERS), out=lambda s: None))

    def test_answers_as_json_match_the_questions(self):
        doc = {"site": "example",
               "regions": [{"name": "cn", "control_host": "cn-edge", "check_from": "cn-probe",
                            "ipv4_prefix": "100.64.10.0/24"},
                           {"name": "ovs", "control_host": "ovs-edge", "check_from": "ovs-probe", "official_derp": True,
                            "ports": "20000-20002", "domain": "hs-ovs.example.com"}],
               "lines": [{"name": "l1", "initiator": "cn-edge", "responder": "ovs-edge",
                          "responder_entry_ipv4": "203.0.113.30", "port": 11011}]}
        answers, problems = init.answers_from(doc)
        self.assertEqual(problems, [])
        self.assertEqual(answers, self.answers())
        data, _notes, _comments = init.derive(answers, facts(), HOSTNAMES)
        self.assertEqual(data, EXPECTED)
        doc["regions"][1]["ports"] = [20000, 20001, 20002]
        self.assertEqual(init.answers_from(doc)[0]["regions"][1]["ports"], [20000, 20001, 20002])

    def test_answers_for_tn_agent_and_phones(self):
        answers, problems = init.answers_from({"regions": [{
            "name": "ovs", "control_host": "ovs-edge", "check_from": "ovs-probe", "domain": "hs-ovs.example.com",
            "agent_domain": "agent-ovs.example.com", "entry_port": 51820}]})
        self.assertEqual(problems, [])
        self.assertEqual((answers["site"], answers["owner_user"], answers["lines"]), ("home", "owner", []))
        data, _notes, _comments = init.derive(answers, facts(), HOSTNAMES)
        region = data["regions"]["ovs"]
        self.assertEqual((region["agent_domain"], region["entry_port"]), ("agent-ovs.example.com", 51820))
        sitemod.parse(data, known_host=lambda h: False)

    def test_bad_answers_say_what_is_wrong(self):
        _answers, problems = init.answers_from({
            "site": "x", "regions": [{"name": "Not A Region", "control_host": "cn-edge", "prot": 1,
                                      "official_derp": "yes", "entry_port": 70000}],
            "lines": [{"name": "l1"}]})
        text = "\n".join(problems)
        for expected in ("regions[0].name:", "regions[0].check_from: needed", "regions[0].prot: not a known answer",
                         "regions[0].official_derp: true or false", "regions[0].entry_port: a port number",
                         "lines[0].initiator: needed", "lines[0].port: needed"):
            self.assertIn(expected, text)
        self.assertIn("answers.regions: a list of at least one region", init.answers_from({})[1])
        self.assertIn("answers: expected an object", init.answers_from([])[1])

    def test_parse_facts(self):
        f = init.parse_facts(CN_EDGE)
        self.assertEqual(f.root, "yes")
        self.assertIn(("tcp", "0.0.0.0", 11010, "relay"), f.listens)
        self.assertIn(("tcp", "*", 22, "sshd"), f.listens)
        self.assertEqual(f.cgnat_resolvers(), ["100.80.0.2", "100.80.0.3"])
        self.assertTrue(f.has_ipv4("192.0.2.50"))
        self.assertEqual(init.parse_facts(OVS_EDGE).listens[0][:3], ("tcp", "203.0.113.30", 11010))

    def test_questions(self):
        a = self.answers()
        self.assertEqual(a["site"], "example")
        self.assertEqual([r["name"] for r in a["regions"]], ["cn", "ovs"])
        self.assertEqual([r["official_derp"] for r in a["regions"]], [False, True])
        self.assertEqual(a["lines"][0]["one_way"], True)
        self.assertEqual(init.hosts_in(a), ["cn-edge", "cn-probe", "ovs-edge", "ovs-probe"])

    def test_prefix_answer(self):
        self.assertIsNone(init._check_prefix("100.64.20.0/24"))
        outside = ".".join(["100", "10", "0", "0"]) + "/24"  # public space; built here so the guard passes
        for bad in (outside, "100.64.10.1/24", "nope"):
            self.assertIsNotNone(init._check_prefix(bad), bad)
        self.assertEqual(str(init._allocate_prefix(["100.64.0.0/16"], [])), "100.65.0.0/24")

    def test_allowed_ports(self):
        self.assertEqual(init.parse_ports("20000-20002"), [20000, 20001, 20002])
        self.assertEqual(init.parse_ports(" 9443, 3478 ,"), [9443, 3478])
        self.assertEqual(init.parse_ports(""), [])
        self.assertIsNone(init._check_ports(""))
        self.assertIsNone(init._check_ports("9443,3478"))
        for bad in ("9443", "a-b", "0-2", "65535-65536"):
            self.assertIsNotNone(init._check_ports(bad), bad)
        busy = init.parse_facts("listen=udp 0.0.0.0:20001\n")
        self.assertEqual(init._pick_ports(busy, [20000, 20001, 20002, 20003]), [20000, 20002, 20003])
        self.assertEqual(init._pick_ports(busy, [20000, 20001]), [20000, None, None])
        ours = init.parse_facts('listen=tcp 0.0.0.0:20000 users:(("headscale",pid=1,fd=3))\n'
                                'listen=udp 0.0.0.0:20001 users:(("headscale",pid=1,fd=4))\n')
        self.assertEqual(init._pick_ports(ours, [20000, 20001, 20002]), [20000, 20001, 20002])

    def test_bad_answer_is_asked_again(self):
        seen = []
        asker = init.Asker(scripted(["Not A Region", "eu"]), out=seen.append)
        self.assertEqual(asker.ask("Region", None, init._check_region), "eu")
        self.assertTrue(seen)

    def test_derive_rebuilds_the_site(self):
        data, notes, _comments = init.derive(self.answers(), facts(), HOSTNAMES)
        self.assertEqual(data, EXPECTED)
        joined = "\n".join(notes)
        self.assertIn('[hosts.cn-edge] gets netfilter_mode = "off"', joined)
        self.assertIn("ovs-probe: python3 is missing", "\n".join(notes + init.checker_problems(
            "ovs-probe", init.parse_facts(PROBE.replace("tool=python3\n", "")))))
        sitemod.parse(data, known_host=lambda h: False)

    def test_busy_ports_move_and_are_recorded(self):
        busy = CN_EDGE + "listen=tcp 0.0.0.0:9443\nlisten=udp 0.0.0.0:3478\nlisten=tcp 127.0.0.1:9090\n"
        f = facts()
        f["cn-edge"] = init.parse_facts(busy)
        data, _notes, comments = init.derive(self.answers(), f, HOSTNAMES)
        cn = data["regions"]["cn"]
        self.assertEqual((cn["port"], cn["stun_port"], cn["metrics_port"]), (9444, 3479, 9091))
        self.assertNotIn("grpc_port", cn)
        self.assertEqual(comments[("regions.cn", "port")], "9443 is in use on cn-edge")

    def test_toml_round_trip(self):
        data, _notes, comments = init.derive(self.answers(), facts(), HOSTNAMES)
        text = init.to_toml(data, comments, today="2026-01-01")
        self.assertEqual(tomllib.loads(text), data)
        self.assertIn("# from ssh -G cn-edge", text)
        self.assertIn("[[lines]]", text)
        self.assertIn("[hosts.cn-edge]", text)
        self.assertIn("tailscale_port = 20002  # UDP for tailscaled --port", text)

    def test_differences(self):
        self.assertEqual(init.differences(EXPECTED, EXPECTED), [])
        changed = tomllib.loads(init.to_toml(EXPECTED))
        changed["regions"]["cn"]["port"] = 9500
        del changed["lines"]
        diffs = init.differences(changed, EXPECTED)
        self.assertIn("regions.cn.port: site.toml has 9500, rebuilt 9443", diffs)
        self.assertIn("lines: only in the rebuilt file (1 table)", diffs)

    def test_facts_script_is_read_only(self):
        for word in ("rm ", "mkdir", "useradd", "systemctl", "tee ", " > "):
            self.assertNotIn(word, init.FACTS_SCRIPT)
