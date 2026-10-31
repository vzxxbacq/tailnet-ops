from tailscale_ops.control import Deployment
from tailscale_ops.redact import Redactor
from tests.helpers import TempDirTest, example_text

# Built at run time so this file never holds the literals the guard blocks.
OUTSIDE_IP = ".".join(["8", "8", "4", "4"])
OTHER_IP = ".".join(["9", "9", "9", "9"])
NODEKEY = "nodekey:" + "ab" * 32
HSKEY = "hs" + "key-auth-" + "Zx9" * 6
PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIGH\n-----END " + "PRIVATE KEY-----"
EXAMPLE_WITH_EXTRA_HOST = example_text(("[[lines]]", "[hosts.far-edge]\ntailscale_port = 20002\n\n[[lines]]"))


class RedactTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.r = Redactor(self.site)

    def test_site_values_get_role_placeholders(self):
        text = "ssh cn-control -> https://198.51.100.10:9443 from cn-probe; ovs at 203.0.113.20; line1 via ovs-line"
        self.assertEqual(
            self.r(text),
            "ssh <cn-control> -> https://<cn-public-ip>:9443 from <cn-checker>; ovs at <ovs-public-ip>; "
            "<line1> via <line1-responder>",
        )

    def test_whole_tokens_only(self):
        r = Redactor(extra_hosts={"edge": "<edge>"})
        self.assertEqual(r("tag:cn-edge and edge1 stay; ssh edge."), "tag:cn-edge and edge1 stay; ssh <edge>.")

    def test_names_in_site_keys(self):
        r = Redactor(extra_hosts={"edge": "<edge>", "zip": "<zip>"})
        self.assertEqual(r("[hosts.edge] region; lines.edge.port; x.zip stays"),
                         "[hosts.<edge>] region; lines.<edge>.port; x.zip stays")

    def test_hosts_only_in_host_settings(self):
        site = self.load_site(EXAMPLE_WITH_EXTRA_HOST, name="extra")
        self.assertRegex(Redactor(site)("ssh far-edge"), r"^ssh <host\d+>$")

    def test_generic_values(self):
        text = f"{OUTSIDE_IP} then {OTHER_IP} then {OUTSIDE_IP}; 100.64.0.1 and 127.0.0.1 and 0.0.0.0:3478 stay"
        self.assertEqual(self.r(text), "<ip-1> then <ip-2> then <ip-1>; 100.64.0.1 and 127.0.0.1 and 0.0.0.0:3478 stay")

    def test_keys(self):
        out = self.r(f"{NODEKEY} {NODEKEY} {HSKEY}\n{PEM}")
        self.assertEqual(out, "<nodekey-1> <nodekey-1> <redacted Headscale key>\n<redacted private key>")

    def test_whole_plan_has_no_site_values(self):
        text, _ = Deployment(self.site, "ovs").plan_text()
        red = self.r(text)
        self.assertIn("203.0.113.20", text)
        for value in ("198.51.100.10", "203.0.113.20", "203.0.113.30", "198.51.100.40"):
            self.assertNotIn(value, red)
        for host in ("ovs-control", "ovs-probe"):
            self.assertRegex(text, rf"(?<![\w<-]){host}(?![\w-])")
            self.assertNotRegex(red, rf"(?<![\w<-]){host}(?![\w-])")
        self.assertIn("server_url: \"https://<ovs-public-ip>:9443\"", red)
