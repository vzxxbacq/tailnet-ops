"""Joining when this machine cannot log in to a control host: a link code made elsewhere."""

import io
import os
import shlex
import subprocess
from unittest import mock

from tailnet_ops import join, remote, targets, tui
from tailnet_ops.cli import code_asker
from tailnet_ops.procedure import StepError
from tailnet_ops.remote import RemoteError, Result
from tests.helpers import FakeRunner, TempDirTest, bash
from tests.test_join import FakeOps, responses, status

CODE = "hskey-auth-" + "Ab3_x-9Q" * 3


class NoControl(FakeRunner):
    """A runner that cannot log in to the given control hosts."""

    def __init__(self, responses=None, down=("cn-control", "ovs-control")):
        super().__init__(responses)
        self.down = set(down)

    def run(self, host, script, args=(), privileged=False, check=True, echo=True):
        if host in self.down:
            self.calls.append(("run", host, script, tuple(args), privileged))
            if check:
                raise RemoteError(f"script on {host} exited with 255")
            return Result(255, "ssh: connect to host: Connection refused\n")
        return super().run(host, script, args=args, privileged=privileged, check=check, echo=echo)


class CodeTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def job(self, runner, member=None, alias="cn-probe"):
        return join.Join(self.site, alias, runner=runner, ops=FakeOps(), out=self.out.append, member=member)

    def test_what_a_code_looks_like(self):
        self.assertIsNone(join.code_problem(CODE))
        self.assertIsNone(join.code_problem(" " + CODE + "\n"))
        for bad in ("", "hello", "hskey-auth-", "tskey" + "-auth-abcdefgh12"):   # built here so the guard passes
            self.assertIsNotNone(join.code_problem(bad), bad)

    def test_commands_to_make_a_code(self):
        cn = self.site.regions["cn"]
        (where, make), (_where, over_ssh) = join.code_commands(self.site, cn, ["tag:cn-server"])
        self.assertEqual(where, "on cn-control, the Headscale of cn")
        self.assertEqual(make, "sudo /usr/local/bin/headscale preauthkeys create --expiration 30m --tags tag:cn-server")
        self.assertEqual(over_ssh, f"ssh cn-control '{make}'")
        (_w, make), (_w2, over_ssh) = join.code_commands(self.site, cn, [])
        self.assertIn("users list --name owner -o json | grep -m1 '\"id\"' | tr -dc 0-9", make)
        for command in (make, over_ssh):
            p = subprocess.run([bash(), "-n"], input=command, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(shlex.split(over_ssh)[2], make)              # the SSH form carries it unchanged

    def test_the_plan_says_so(self):
        runner = NoControl({"TN-FACT os=": "TN-FACT os=Ubuntu\nTN-FACT machine=x86_64\nTN-FACT login=ok\n"},
                           down=("cn-control",))
        job = self.job(runner)
        checks = job.check()
        self.assertEqual(checks["codes"], ["cn"])
        self.assertEqual(checks["fails"], [])
        self.assertIn("link code     ✗ this machine cannot log in to cn-control", job.summary_text(checks))
        self.assertIn("only if this machine cannot log in to cn-control", job.plan_text()[0])

    def test_join_with_a_pasted_code(self):
        runner = NoControl(responses(status=status(state="NeedsLogin")), down=("cn-control",))
        asked = []
        job = self.job(runner)
        job.ask_code = lambda region, commands: asked.append((region.name, commands)) or CODE
        job._run_join()
        self.assertEqual(asked[0][0], "cn")
        self.assertIn("preauthkeys create --expiration 30m --tags tag:cn-server", asked[0][1][0][1])
        feeds = [c for c in runner.calls if c[0] == "feed"]
        self.assertEqual(len(feeds), 1)
        self.assertEqual(feeds[0][1], "cn-probe")
        self.assertEqual(feeds[0][2][:2], (join.TS_BIN, "up"))
        self.assertEqual(feeds[0][3], CODE)
        self.assertFalse(any(c[0] == "pipe" for c in runner.calls))
        self.assertFalse(any(CODE in line for line in self.out))

    def test_without_a_terminal_it_says_how(self):
        job = self.job(NoControl(responses(status=status(state="NeedsLogin")), down=("cn-control",)))
        with self.assertRaises(StepError) as cm:
            job._run_join()
        self.assertIn("make a link code where you can with `sudo /usr/local/bin/headscale preauthkeys create", str(cm.exception))

    def test_personal_device_codes_only_where_needed(self):
        member = targets.Target(name="mac", role="personal", region="cn", os="macos")
        runner = NoControl({join.PROFILES_JSON: "[]", join.USERS_JSON: '[{"id": 1, "name": "owner"}]'},
                           down=("ovs-control",))
        job = self.job(runner, member=member)
        job.ask_code = lambda region, commands: CODE
        job._run_join()
        self.assertEqual([c[1] for c in runner.calls if c[0] == "pipe"], ["cn-control"])
        feeds = [c for c in runner.calls if c[0] == "feed"]
        self.assertEqual(len(feeds), 1)
        self.assertIn("--nickname=ovs", feeds[0][2])
        self.assertEqual(feeds[0][2][1], "login")

    def test_names_verify_and_rollback_go_on_without_headscale(self):
        runner = NoControl(responses(status=status()), down=("cn-control",))
        job = self.job(runner)
        job._run_names()
        self.assertIn("Run `tn dns sync` on a machine that can", self.out[-1])
        job._run_verify()
        self.assertIn("    cn-control: not checked (this machine cannot log in to it)", self.out)
        self.assertIn("    verify passed", self.out)
        job._undo_join()
        self.assertTrue(any("nodes delete -i <ID> --force" in line for line in self.out))


class CodePromptTest(TempDirTest):
    def test_shows_commands_and_reads_the_code(self):
        site = self.load_site()
        out = io.StringIO()
        ui = tui.UI(inp=io.StringIO("not a code\n" + CODE + "\n"), out=out, tty=False)
        commands = join.code_commands(site, site.regions["cn"], ["tag:cn-server"])
        self.assertEqual(code_asker(ui)(site.regions["cn"], commands), CODE)
        text = out.getvalue()
        self.assertIn("! This machine cannot log in to cn-control, the Headscale of cn.", text)
        self.assertIn("\n    " + commands[0][1] + "\n", text)        # alone on its line, ready to copy
        self.assertIn("\n    " + commands[1][1] + "\n", text)
        self.assertIn("a link code looks like hskey-auth-", text)
        self.assertIn("✔ Link code for cn received", text)
        self.assertNotIn(CODE, text)


class FeedTest(TempDirTest):
    def test_the_code_reaches_stdin_and_nothing_else(self):
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        (stubs / "ssh").write_text('#!/bin/sh\nfor last; do :; done\nexec /bin/bash -c "$last"\n')
        (stubs / "sudo").write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')
        for f in stubs.iterdir():
            f.chmod(0o755)
        out, log = [], []
        runner = remote.SSHRunner(out=out.append, log=log.append)
        with mock.patch.dict(os.environ, {"PATH": f"{stubs}:{os.environ['PATH']}"}):
            runner.feed("dst", ["wc", "-c"], CODE)
        self.assertEqual([line.strip() for line in out], [str(len(CODE) + 1)])
        self.assertFalse(any(CODE in line for line in out + log))
