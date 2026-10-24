import json

from tailnet_ops import pins, render
from tests.helpers import TempDirTest


def strip_comments(hujson):
    return "\n".join(line for line in hujson.splitlines() if not line.lstrip().startswith("//"))


class RenderTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.cn = self.site.regions["cn"]
        self.ovs = self.site.regions["ovs"]

    def test_yaml_writer(self):
        text = render.to_yaml({"a": "x", "b": {"c": True, "d": [], "e": {}, "f": [1, "y"]}, "g": 3})
        self.assertEqual(text, 'a: "x"\nb:\n  c: true\n  d: []\n  e: {}\n  f:\n    - 1\n    - "y"\ng: 3')

    def test_config_follows_the_plan_mapping(self):
        cfg = render.headscale_config(self.site, self.cn)
        for line in (
            'server_url: "https://198.51.100.10:9443"',
            'listen_addr: "0.0.0.0:9443"',
            'metrics_listen_addr: "127.0.0.1:9090"',
            'grpc_listen_addr: "127.0.0.1:50443"',
            '  v4: "100.64.0.0/16"',
            f'  v6: "{pins.IPV6_PREFIX}"',
            "    enabled: true",
            "    region_id: 901",
            '    region_code: "cn"',
            '    region_name: "CN control"',
            "    verify_clients: true",
            '    stun_listen_addr: "0.0.0.0:3478"',
            '    ipv4: "198.51.100.10"',
            "  urls: []",
            "  magic_dns: true",
            '  base_domain: "cn.tailnet.internal"',
            "  override_local_dns: false",
            "    global: []",
            'tls_cert_path: "/etc/headscale/tls/server.crt"',
            'tls_key_path: "/etc/headscale/tls/server.key"',
            '  mode: "file"',
            '  path: "/etc/headscale/policy.hujson"',
            "logtail:\n  enabled: false",
        ):
            self.assertIn(line, cfg)
        self.assertTrue(cfg.startswith("# tailnet-ops region=cn\n"))

    def test_official_derp_and_specific_listen(self):
        cfg = render.headscale_config(self.site, self.ovs)
        self.assertIn(f"  urls:\n    - \"{pins.OFFICIAL_DERP_MAP}\"", cfg)
        self.assertIn("  auto_update_enabled: true", cfg)
        self.assertIn('listen_addr: "203.0.113.20:9443"', cfg)
        self.assertIn('stun_listen_addr: "203.0.113.20:3478"', cfg)
        self.assertNotIn("ipv6:", cfg)

    def test_policy(self):
        doc = json.loads(strip_comments(render.policy(self.site, self.cn)))
        tags = ["tag:cn-server", "tag:cn-gateway"]
        self.assertEqual(doc["tagOwners"], {t: ["owner@"] for t in tags})
        self.assertEqual(doc["grants"], [
            {"src": tags, "dst": tags, "ip": ["*"]},
            {"src": ["owner@"], "dst": tags, "ip": ["*"]},
        ])
        self.assertNotIn("acls", doc)
        self.assertNotIn("ssh", doc)

    def test_unit(self):
        unit = render.systemd_unit(self.cn)
        self.assertTrue(unit.startswith("# tailnet-ops region=cn\n"))
        for line in ("RuntimeDirectory=headscale", "ExecReload=/bin/kill -HUP $MAINPID", "User=headscale",
                     "ExecStart=/usr/local/bin/headscale serve --config /etc/headscale/config.yaml",
                     "ReadWritePaths=/var/lib/headscale", "WantedBy=multi-user.target"):
            self.assertIn(line, unit)
