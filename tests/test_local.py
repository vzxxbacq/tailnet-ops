from tailnet_ops import remote
from tests.helpers import TempDirTest


class LocalRunnerTest(TempDirTest):
    def test_commands(self):
        runner = remote.SSHRunner(local_hosts=["vault"])
        self.assertEqual(runner.command("vault", "true"), ["bash", "-c", "true"])
        self.assertEqual(runner.command("edge", "true")[0], "ssh")
        self.assertIn("exec sudo -p '[sudo] password of %u on this machine", remote.remote_command((), True, interactive=True))
        self.assertIn("exec sudo -n bash -s", remote.remote_command((), True))
        self.assertIn("as root): ' /usr/local/bin/tailscale up", remote.privileged_command(["/usr/local/bin/tailscale", "up"], True))

    def test_local_run_and_copy(self):
        runner = remote.SSHRunner(out=lambda s: None, local_hosts=["here"])
        result = runner.run("here", "echo TN-FACT x=1\n")
        self.assertEqual(result.facts(), {"x": "1"})
        src, dst = self.tmp / "a", self.tmp / "b"
        src.write_text("data")
        runner.upload("here", src, str(dst))
        self.assertEqual(dst.read_text(), "data")
