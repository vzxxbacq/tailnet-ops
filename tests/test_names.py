import json
import subprocess

from tailscale_ops import names, scripts
from tests.helpers import FakeRunner, TempDirTest, bash, example_text


def node(name, ip):
    return {"given_name": name, "ip_addresses": [ip, "fd7a:115c:a1e0::9"]}


class NamesTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.nodes = {
            "cn": [node("cn-control", "100.64.1.1"), node("cn-gateway", "100.64.1.2"), node("shared", "100.64.1.9")],
            "ovs": [node("ovs-control", "100.64.2.1"), node("ovs-line", "100.64.2.4"), node("shared", "100.64.2.9"),
                    node("stray", "100.64.1.77")],   # an address outside ovs's range is ignored
        }

    def test_each_region_gets_the_others_hosts_at_their_aliases(self):
        recs, skipped = names.records(self.site, self.site.regions["cn"], self.nodes)
        by_name = {r["name"]: r["value"] for r in recs}
        self.assertEqual(by_name["ovs-control.tailnet.internal"], "10.255.2.1")
        self.assertEqual(by_name["ovs-line.ovs.tailnet.internal"], "10.255.2.4")      # with the region
        self.assertEqual(by_name["cn-gateway.cn.tailnet.internal"], "100.64.1.2")     # own host, with the region
        self.assertEqual(by_name["shared.ovs.tailnet.internal"], "10.255.2.9")        # a clash still has this form
        self.assertNotIn("shared.tailnet.internal", by_name)
        self.assertEqual(skipped, ["shared.tailnet.internal (also a host in cn; use shared.ovs.tailnet.internal)"])
        recs, _ = names.records(self.site, self.site.regions["ovs"], self.nodes)
        self.assertIn({"name": "cn-gateway.tailnet.internal", "type": "A", "value": "10.255.1.2"}, recs)

    def test_no_line_no_names(self):
        recs, _ = names.records(self.site, self.site.regions["cn"], self.nodes, skip_lines=("line1",))
        self.assertTrue(recs and all(r["value"].startswith("100.64.1.") for r in recs))  # only its own hosts

    def test_write_script(self):
        body = names.write([{"name": "a.tailnet.internal", "type": "A", "value": "10.255.2.1"}])
        self.assertIn('"value": "10.255.2.1"', body)
        script = scripts.wrap(scripts.control_prelude(self.site, self.site.regions["cn"]), body)
        p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_sync_writes_every_region(self):
        runner = FakeRunner({names.NODES_JSON: json.dumps(self.nodes["ovs"] + self.nodes["cn"])})
        names.Names(self.site, runner, out=lambda s: None).sync()
        writes = [(c[1], c[2]) for c in runner.calls if "extra-records.json.tn-new" in c[2]]
        self.assertEqual([h for h, _ in writes], ["cn-control", "ovs-control"])

    def test_table(self):
        runner = FakeRunner()
        n = names.Names(self.site, runner, out=lambda s: None)
        n.nodes = lambda: self.nodes
        rows = {(r[0], r[1]): r for r in n.table()}
        self.assertEqual(rows[("cn", "ovs-line.ovs.tailnet.internal")][2:],
                         ("ovs-line, ovs-line.tailnet.internal", "10.255.2.4", "through a line"))
        self.assertEqual(rows[("cn", "cn-gateway.cn.tailnet.internal")][3:], ("100.64.1.2", "this region"))
        self.assertEqual(rows[("cn", "shared.ovs.tailnet.internal")][2], "—")   # its short name is cn's own host

    def test_suffixes(self):
        from tailscale_ops.site import suffix_problem
        for ok in ("vlan", "vlan.internal", "tailnet.internal"):
            self.assertIsNone(suffix_problem(ok), ok)
        for bad in ("local", "office.local", "localhost", "Bad_Name", "-x"):
            self.assertIsNotNone(suffix_problem(bad), bad)

    def test_shared_suffix_needs_unique_names(self):
        text = example_text(('check_from = "ovs-probe"', 'check_from = "CN-probe"'))
        with self.assertRaises(Exception) as cm:
            self.load_site(text, name="dup")
        self.assertIn("would all be named cn-probe in DNS", str(cm.exception))
