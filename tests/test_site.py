import os
from pathlib import Path

from tailnet_ops import site as sitemod
from tests.helpers import TempDirTest, any_host, example_text


class SiteFileTest(TempDirTest):
    def problems(self, text, known_host=any_host, name="site"):
        with self.assertRaises(sitemod.SiteError) as cm:
            sitemod.load(self.make_site_dir(text, name), known_host=known_host)
        return "\n".join(cm.exception.problems)

    def test_example_is_valid(self):
        site = self.load_site()
        self.assertEqual(list(site.regions), ["cn", "ovs"])
        cn, ovs = site.regions["cn"], site.regions["ovs"]
        self.assertFalse(cn.specific_listen)
        self.assertEqual(cn.local_ipv4, "127.0.0.1")
        self.assertEqual(cn.cert_ips, ["198.51.100.10"])
        self.assertEqual(ovs.local_ipv4, "203.0.113.20")
        self.assertEqual(ovs.cert_ips, ["203.0.113.20"])
        self.assertEqual(cn.metrics_port, 9090)
        self.assertEqual(cn.grpc_port, 50443)
        self.assertEqual(site.lines[0].initiator, "cn-gateway")
        self.assertEqual(site.host_settings["cn-control"].netfilter_mode, "off")
        self.assertEqual(site.host_settings["ovs-control"].tailscale_port, 41641)

    def test_prefix_must_sit_inside_cgnat(self):
        text = example_text(('ipv4_prefix = "100.64.0.0/16"', 'ipv4_prefix = "192.0.2.0/24"'))
        self.assertIn("is not inside 100.64.0.0/10", self.problems(text))

    def test_prefix_must_avoid_avoid_prefixes(self):
        text = example_text(("avoid_prefixes = []", 'avoid_prefixes = ["100.64.128.0/17"]'))
        self.assertIn("overlaps avoid_prefixes entry 100.64.128.0/17", self.problems(text))

    def test_prefixes_must_not_overlap(self):
        text = example_text(('ipv4_prefix = "100.65.0.0/16"', 'ipv4_prefix = "100.64.0.0/15"'))
        self.assertIn("overlaps region cn", self.problems(text))

    def test_prefix_must_avoid_tailscale_reserved(self):
        text = example_text(('ipv4_prefix = "100.65.0.0/16"', 'ipv4_prefix = "100.100.0.0/16"'))
        self.assertIn("which Tailscale reserves", self.problems(text))

    def test_region_ids_distinct(self):
        text = example_text(("derp_region_id = 902", "derp_region_id = 901"))
        self.assertIn("region id 901 is also used by region cn", self.problems(text))

    def test_lines_name_existing_hosts(self):
        msg = self.problems(None, known_host=lambda alias: False)
        self.assertIn("lines.line1.initiator: 'cn-gateway' is neither a region host nor an SSH alias", msg)
        # A line between region hosts needs no SSH lookup.
        text = example_text(('initiator = "cn-gateway"', 'initiator = "cn-control"'),
                            ('responder = "ovs-line"', 'responder = "ovs-control"'),
                            ("[hosts.cn-gateway]", "[hosts.cn-probe]"))
        site = sitemod.load(self.make_site_dir(text, name="b"), known_host=lambda alias: False)
        self.assertEqual(site.lines[0].responder, "ovs-control")

    def test_types_and_unknown_keys(self):
        text = example_text(("port = 9443", 'port = "9443"'), ("official_derp = false", "official_derp = 0"),
                            ("stun_port = 3478", "stun_port = 3478\nstun_prot = 1"))
        msg = self.problems(text)
        self.assertIn("regions.cn.port: expected int, got str", msg)
        self.assertIn("regions.cn.official_derp: expected bool, got int", msg)
        self.assertIn("regions.cn: unknown key stun_prot", msg)

    def test_bool_is_not_an_int(self):
        self.assertIn("expected int, got bool", self.problems(example_text(("port = 9443", "port = true"))))

    def test_bad_toml(self):
        self.assertIn("site.toml", self.problems("[site\n"))

    def test_host_settings(self):
        text = example_text(('netfilter_mode = "off"', 'netfilter_mode = "nope"\nport = 1'),
                            ("tailscale_port = 41641", "tailscale_port = 3478"))
        msg = self.problems(text)
        self.assertIn("hosts.cn-control.netfilter_mode: use one of on, nodivert, off", msg)
        self.assertIn("hosts.cn-control: unknown key port", msg)
        self.assertIn("hosts.ovs-control.tailscale_port: 3478 is region ovs's STUN port on this host", msg)
        text = example_text(("[hosts.ovs-control]", "[hosts.elsewhere]"))
        self.assertIn("'elsewhere' is neither a site host nor an SSH alias",
                      self.problems(text, known_host=lambda alias: alias != "elsewhere", name="b"))

    def test_optional_ports(self):
        text = example_text(("stun_port = 3478", "stun_port = 3478\nmetrics_port = 9443"))
        self.assertIn("port, metrics_port and grpc_port must differ", self.problems(text))


class SiteDirTest(TempDirTest):
    def test_resolve_order(self):
        self.assertEqual(sitemod.resolve_dir("/x/a", {"TN_SITE": "/x/b"}), Path("/x/a"))
        self.assertEqual(sitemod.resolve_dir(None, {"TN_SITE": "/x/b"}), Path("/x/b"))
        self.assertEqual(sitemod.resolve_dir(None, {}), Path(os.path.expanduser("~/.config/tailnet-ops")))

    def test_good_dir(self):
        self.assertEqual(sitemod.check_dir(self.make_site_dir()), [])

    def test_loose_permissions(self):
        d = self.make_site_dir()
        os.chmod(d / "site.toml", 0o644)
        (d / "pki").mkdir(mode=0o755)
        os.chmod(d / "pki", 0o755)
        problems = "\n".join(sitemod.check_dir(d))
        self.assertIn("chmod 0600", problems)
        self.assertIn("chmod 0700", problems)

    def test_refuses_git_work_tree(self):
        d = self.make_site_dir()
        (self.tmp / ".git").mkdir()
        self.assertIn("inside the Git work tree", "\n".join(sitemod.check_dir(d)))

    def test_missing_dir(self):
        self.assertIn("does not exist", sitemod.check_dir(self.tmp / "nope")[0])

    def test_load_checks_permissions(self):
        d = self.make_site_dir()
        os.chmod(d, 0o755)
        with self.assertRaises(sitemod.SiteError):
            sitemod.load(d, known_host=any_host)

    def test_write_private(self):
        p = sitemod.write_private(self.tmp / "f", "x")
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
