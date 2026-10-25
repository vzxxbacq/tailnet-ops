import json

from tailnet_ops import remote, render
from tailnet_ops import site as sitemod
from tests.helpers import TempDirTest, example_text

ADMIN = (("tags = [\"tag:cn-server\", \"tag:cn-gateway\"]", "tags = [\"tag:cn-server\", \"tag:cn-gateway\", \"tag:cn-admin\"]"),
         ("[[lines]]", "[hosts.vault]\nregion = \"cn\"\nrole = \"admin\"\nlocal = true\n\n[[lines]]"))


def grants(site, region):
    text = render.policy(site, site.regions[region])
    return json.loads("\n".join(l for l in text.splitlines() if not l.startswith("//")))["grants"]


class RolesTest(TempDirTest):
    def test_admin_reaches_all_and_nobody_reaches_it(self):
        site = self.load_site(example_text(*ADMIN), name="admin")
        self.assertEqual(site.host_tags("vault"), ["tag:cn-admin"])
        self.assertEqual(grants(site, "cn")[:2], [
            {"src": ["*"], "dst": ["tag:cn-server", "tag:cn-gateway", "owner@"], "ip": ["*"]},
            {"src": ["tag:cn-admin"], "dst": ["*"], "ip": ["*"]},
        ])
        self.assertEqual(grants(site, "ovs")[0], {"src": ["*"], "dst": ["*"], "ip": ["*"]})  # no admin there

    def test_admin_needs_its_tag_and_no_line(self):
        text = example_text(ADMIN[1])
        with self.assertRaises(sitemod.SiteError) as cm:
            self.load_site(text, name="notag")
        self.assertIn("add a tag like tag:cn-admin", str(cm.exception))
        text = example_text(ADMIN[0], ("[hosts.cn-gateway]\nregion = \"cn\"", "[hosts.cn-gateway]\nregion = \"cn\"\nrole = \"admin\""))
        with self.assertRaises(sitemod.SiteError) as cm:
            self.load_site(text, name="border")
        self.assertIn("cannot be a line's border", str(cm.exception))

    def test_local_host_needs_no_ssh_alias_and_is_unique(self):
        site = sitemod.load(self.make_site_dir(example_text(*ADMIN), "l"), known_host=lambda a: a != "vault")
        self.assertTrue(site.host_settings["vault"].local)
        two = example_text(*ADMIN, ("[[lines]]", "[hosts.other]\nregion = \"cn\"\nlocal = true\n\n[[lines]]"))
        with self.assertRaises(sitemod.SiteError) as cm:
            self.load_site(two, name="two")
        self.assertIn("only one host can be local", str(cm.exception))


class LocalRunnerTest(TempDirTest):
    def test_commands(self):
        runner = remote.SSHRunner(local_hosts=["vault"])
        self.assertEqual(runner.command("vault", "true"), ["bash", "-c", "true"])
        self.assertEqual(runner.command("edge", "true")[0], "ssh")
        self.assertIn("exec sudo bash -s", remote.remote_command((), True, interactive=True))
        self.assertIn("exec sudo -n bash -s", remote.remote_command((), True))
        self.assertIn("exec sudo /usr/local/bin/tailscale up", remote.privileged_command(["/usr/local/bin/tailscale", "up"], True))

    def test_local_run_and_copy(self):
        runner = remote.SSHRunner(out=lambda s: None, local_hosts=["here"])
        result = runner.run("here", "echo TN-FACT x=1\n")
        self.assertEqual(result.facts(), {"x": "1"})
        src, dst = self.tmp / "a", self.tmp / "b"
        src.write_text("data")
        runner.upload("here", src, str(dst))
        self.assertEqual(dst.read_text(), "data")
