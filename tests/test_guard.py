import contextlib
import io
import os
import subprocess
from unittest import mock

from tailnet_ops import guard
from tests.helpers import TempDirTest

# Built at run time so this file never holds the literals the guard blocks.
OUTSIDE_IP = ".".join(["8", "8", "4", "4"])
PRIVATE_IP = ".".join(["10", "1", "2", "3"])
HSKEY = "hs" + "key-auth-" + "Zx9" * 6
TSKEY = "ts" + "key-auth-" + "k1" * 10
PEM = "-----BEGIN " + "EC PRIVATE KEY-----"
LINK = "https://claude" + ".ai/artifact/abc123"
GH = "gh" + "p_" + "a" * 36


def rules(text, names=()):
    return [rule for _no, rule in guard.scan_text(text, names)]


class ScanTextTest(TempDirTest):
    def test_shareable_addresses_pass(self):
        text = ("192.0.2.1 198.51.100.10/24 203.0.113.20:9443 100.64.0.0/16 100.100.100.100 "
                "127.0.0.1 0.0.0.0:3478 10.255.1.0/24 version 1.104.2 and 0.29.6")
        self.assertEqual(rules(text), [])

    def test_other_addresses_fail(self):
        self.assertEqual(rules(f"dns {OUTSIDE_IP}"), ["IPv4 address outside the shareable ranges"])
        self.assertEqual(rules(f"lan {PRIVATE_IP}/8"), ["IPv4 address outside the shareable ranges"])

    def test_secrets_and_links(self):
        self.assertEqual(rules(HSKEY), ["Headscale key"])
        self.assertEqual(rules(TSKEY), ["Tailscale key"])
        self.assertEqual(rules(PEM), ["private key"])
        self.assertEqual(rules(GH), ["token"])
        self.assertEqual(rules(f"see {LINK}"), ["link to a private document"])
        self.assertEqual(rules("sha256 " + "a" * 64), [])

    def test_site_host_names(self):
        self.assertEqual(rules("ssh edge1 now", ["edge1"]), ["host name from the site directory"])
        self.assertEqual(rules("tag:cn-edge1 and edge12", ["edge1"]), [])

    def test_blocked_paths(self):
        self.assertIsNotNone(guard.scan_path("x/site.toml"))
        self.assertIsNotNone(guard.scan_path("pki/ca.key"))
        self.assertIsNone(guard.scan_path("examples/site.example.toml"))


class RepoTest(TempDirTest):
    def git(self, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_GLOBAL": os.devnull}
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True, env=env)

    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.site = self.make_site_dir()

    def run_guard(self, *extra):
        # Do not read the operator's real ~/.ssh/config.
        with mock.patch.object(guard, "ssh_config", lambda alias: {}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return guard.main(["--repo", str(self.repo), "--site", str(self.site), *extra])

    def test_clean(self):
        (self.repo / "a.md").write_text("ok 192.0.2.1\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "start")
        self.assertEqual(self.run_guard("--history"), 0)

    def test_history_keeps_what_the_tree_dropped(self):
        (self.repo / "a.md").write_text(f"old {OUTSIDE_IP}\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "one")
        (self.repo / "a.md").write_text("fixed\n")
        self.git("commit", "-q", "-am", "two")
        self.assertEqual(self.run_guard(), 0)
        findings, blobs, commits = guard.scan_history(self.repo, [])
        self.assertEqual(commits, 2)
        self.assertEqual(len(findings), 1)
        self.assertIn("history a.md:1", findings[0])
        self.assertNotIn(OUTSIDE_IP, findings[0])
        self.assertEqual(self.run_guard("--history"), 1)

    def test_commit_messages_and_untracked_files(self):
        (self.repo / "a.md").write_text("ok\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", f"key {HSKEY}")
        findings, _b, _c = guard.scan_history(self.repo, [])
        self.assertTrue(any("message line 1: Headscale key" in f for f in findings))
        (self.repo / "new.txt").write_text(f"{PRIVATE_IP}\n")
        self.assertTrue(any(f.startswith("new.txt:1") for f in guard.scan_worktree(self.repo, [])))

    def test_site_names_are_blocked(self):
        (self.repo / "a.md").write_text("then ssh ovs-probe\n")
        names = guard.site_host_names(self.site, lookup=lambda alias: {"hostname": f"{alias}.example.net"})
        self.assertIn("ovs-probe", names)
        self.assertIn("ovs-probe.example.net", names)
        self.assertEqual(self.run_guard(), 1)

    def test_empty_repo(self):
        self.assertEqual(guard.scan_history(self.repo, []), ([], 0, 0))
