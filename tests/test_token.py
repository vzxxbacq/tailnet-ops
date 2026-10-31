"""The Cloudflare API token on the operator's machine: $CF_Token, the run's own copy, the macOS keychain,
or pasted once. Offline: `security` is a fake; no keychain is touched."""

import os
import subprocess
import unittest
from unittest import mock

from tailscale_ops import cli

TOKEN = "cf" + "Ab9" * 12


class FakeUI:
    tty = True

    def __init__(self, keep=True):
        self.keep, self.said, self.asked = keep, [], 0

    def say(self, text=""):
        self.said.append(text)

    warn = say

    def secret(self, title, check=None):
        self.asked += 1
        return TOKEN

    def confirm(self, title, default=False):
        self.said.append(title)
        return self.keep


class Security:
    """Records the `security` calls; holds at most one item."""

    def __init__(self, item=None, silent=False):
        self.item, self.calls, self.silent = item, [], silent

    def __call__(self, argv, input=None, **kw):
        self.calls.append((argv, input))
        if argv[1] == "find-generic-password" and "-w" not in argv:
            return subprocess.CompletedProcess(argv, 0 if self.item else 44, stdout="attributes\n", stderr="")
        if argv[1] == "find-generic-password":
            if self.silent:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
            return subprocess.CompletedProcess(argv, 0 if self.item else 44, stdout=(self.item or "") + "\n", stderr="")
        if argv[1] == "-i":
            self.item = input.split('-w "', 1)[1].split('"', 1)[0]
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if argv[1] == "delete-generic-password":
            found, self.item = self.item is not None, None
            return subprocess.CompletedProcess(argv, 0 if found else 44, stdout="", stderr="")
        raise AssertionError(argv)


def asker(ui, security):
    return cli.token_asker(ui, "home", run=security, which=lambda name: "/usr/bin/security")


@mock.patch.dict(os.environ, {"CF_Token": ""})
class TokenTest(unittest.TestCase):
    def test_the_environment_wins(self):
        security = Security(item=TOKEN)
        with mock.patch.dict(os.environ, {"CF_Token": "from-the-environment-0123456789"}):
            self.assertEqual(asker(FakeUI(), security)(), "from-the-environment-0123456789")
        self.assertEqual(security.calls, [])

    def test_the_keychain_answers_without_asking(self):
        ui, security = FakeUI(), Security(item=TOKEN)
        ask = asker(ui, security)
        self.assertEqual((ask(), ask()), (TOKEN, TOKEN))
        self.assertEqual(ui.asked, 0)
        reads = [c for c in security.calls if "-w" in c[0]]
        self.assertEqual(len(reads), 1)                          # read once per run
        self.assertTrue(any("macOS shows a dialog" in s for s in ui.said))   # said before it waits

    def test_quiet_reads_no_keychain(self):
        security = Security(item=TOKEN)
        self.assertIsNone(asker(FakeUI(), security)(quiet=True))
        self.assertEqual(security.calls, [])

    def test_pasted_once_then_kept_off_the_command_line(self):
        ui, security = FakeUI(), Security()
        ask = asker(ui, security)
        self.assertEqual(ask(), TOKEN)
        self.assertEqual(ask(), TOKEN)
        self.assertEqual(ui.asked, 1)
        add = next(c for c in security.calls if c[0][1] == "-i")
        self.assertNotIn(TOKEN, " ".join(add[0]))                # not in argv, where ps would show it
        self.assertIn(TOKEN, add[1])
        self.assertIn('-T ""', add[1])                           # no app trusted: macOS asks before each read
        self.assertEqual(asker(FakeUI(), security)(), TOKEN)     # the next run asks nobody

    def test_an_unanswered_dialog_falls_back_to_pasting(self):
        ui, security = FakeUI(keep=False), Security(item=TOKEN, silent=True)
        self.assertEqual(asker(ui, security)(), TOKEN)
        self.assertEqual(ui.asked, 1)
        self.assertTrue(any("did not give it" in s for s in ui.said))

    def test_no_item_no_dialog(self):
        ui, security = FakeUI(keep=False), Security()
        asker(ui, security)()
        self.assertFalse(any("-w" in c[0] and c[0][1] == "find-generic-password" for c in security.calls))
        self.assertFalse(any("macOS shows a dialog" in s for s in ui.said))

    def test_not_kept_when_declined(self):
        security = Security()
        asker(FakeUI(keep=False), security)()
        self.assertIsNone(security.item)

    def test_forget(self):
        security = Security(item=TOKEN)
        self.assertTrue(cli.keychain_forget("home", run=security))
        self.assertFalse(cli.keychain_forget("home", run=security))


if __name__ == "__main__":
    unittest.main()
