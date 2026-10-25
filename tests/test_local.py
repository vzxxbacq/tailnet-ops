from tailnet_ops import remote
from tailnet_ops import site as sitemod
from tests.helpers import TempDirTest, example_text

LOCAL = ("[[lines]]", "[hosts.vault]\nregion = \"cn\"\nlocal = true\n\n[[lines]]")


class LocalHostTest(TempDirTest):
    def test_local_host_needs_no_ssh_alias_and_is_unique(self):
        site = sitemod.load(self.make_site_dir(example_text(LOCAL), "l"), known_host=lambda a: a != "vault")
        self.assertTrue(site.host_settings["vault"].local)
        two = example_text(LOCAL, ("[[lines]]", "[hosts.other]\nregion = \"cn\"\nlocal = true\n\n[[lines]]"))
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
