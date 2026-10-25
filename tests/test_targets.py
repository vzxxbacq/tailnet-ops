import io
import json
import os
import threading
import unittest
from unittest import mock

from tailnet_ops import guard, join, targets, tui
from tailnet_ops import site as sitemod
from tailnet_ops.site import SiteError
from tests.helpers import TempDirTest
from tests.test_join import FakeOps


class ResolveTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()

    def test_site_hosts_come_from_site_toml(self):
        t = targets.resolve(self.site, "ovs-control", detect_os=lambda h: "linux")
        self.assertEqual((t.name, t.ssh, t.role, t.region, t.port), ("ovs-control", "ovs-control", "server", "ovs", 41641))
        self.assertEqual(targets.resolve(self.site, "cn-control").netfilter_mode, "off")
        with self.assertRaises(SiteError) as cm:
            targets.resolve(self.site, "cn-control", region="ovs")
        self.assertIn("cn-control is in region cn in site.toml", str(cm.exception))
        with self.assertRaises(SiteError) as cm:
            targets.resolve(self.site, "ovs-line", role="personal")
        self.assertIn("it joins as a server", str(cm.exception))

    def test_other_machines_come_from_options(self):
        t = targets.resolve(self.site, "box", region="ovs", port=20002, detect_os=lambda h: "macos")
        self.assertEqual((t.name, t.ssh, t.region, t.os, t.port), ("box", "box", "ovs", "macos", 20002))
        job = join.Join(self.site, ops=FakeOps(), member=t)
        self.assertEqual(job.tags, ["tag:ovs-server"])
        with self.assertRaises(SiteError) as cm:
            targets.resolve(self.site, "box")
        self.assertIn("box: choose its region with --region (cn, ovs)", str(cm.exception))
        for bad, msg in (({"region": "eu"}, "unknown region 'eu'"), ({"region": "cn", "netfilter_mode": "x"}, "--netfilter"),
                         ({"region": "cn", "os_name": "macos", "netfilter_mode": "off"}, "Linux only"),
                         ({"region": "cn", "name": "Not a name"}, "--name")):
            with self.subTest(bad=bad), self.assertRaises(SiteError) as cm:
                targets.resolve(self.site, "box", **bad)
            self.assertIn(msg, str(cm.exception))

    def test_this_machine(self):
        with mock.patch.object(targets.platform, "node", return_value="Owners-Mac.local"), \
                mock.patch.object(targets.platform, "system", return_value="Darwin"):
            t = targets.resolve(self.site, role="personal")
        self.assertEqual((t.name, t.ssh, t.local, t.region, t.os), ("owners-mac", None, True, "cn", "macos"))
        self.assertEqual(t.alias, "owners-mac")

    def test_the_record_remembers_options(self):
        t = targets.resolve(self.site, name="laptop", role="personal", region="ovs", os_name="macos")
        targets.remember(self.site, t)
        path = self.site.directory / sitemod.JOINED_FILE
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        again = sitemod.load(self.site.directory, known_host=lambda a: True)
        self.assertEqual(again.joined["laptop"]["role"], "personal")
        for host in (None, "laptop"):                       # this machine, or by its name
            self.assertEqual(targets.resolve(again, host), t)
        self.assertEqual(targets.resolve(again, "laptop", role="server").role, "server")   # options win
        targets.forget(again, t)
        self.assertEqual(json.loads(path.read_text()), {})
        targets.remember(self.site, targets.resolve(self.site, "cn-probe"))   # site hosts need no record
        self.assertNotIn("cn-probe", self.site.joined)

    def test_command_line(self):
        t = targets.Target(name="laptop", role="personal", region="ovs", os="macos")
        with mock.patch.object(targets, "this_machine_name", return_value="laptop"):
            self.assertEqual(targets.command_line(t), "./tn join apply --personal --region ovs")
        t = targets.Target(name="hm", ssh="box", region="cn", port=20002)
        self.assertEqual(targets.command_line(t, "plan"), "./tn join plan box --region cn --name hm --port 20002")

    def test_guard_and_redact_know_joined_names(self):
        targets.remember(self.site, targets.Target(name="laptop7", ssh="box7", region="cn"))
        names = guard.site_host_names(self.site.directory, lookup=lambda a: {})
        self.assertIn("laptop7", names)
        self.assertIn("box7", names)
        from tailnet_ops.cli import redactor
        self.assertEqual(redactor(self.site)("ssh box7 for laptop7"), "ssh <joined1> for <joined1>")


class FakeUI:
    """Answers select() and text() from a script, by title."""

    def __init__(self, answers):
        self.answers = answers
        self.asked = []
        self.notes = []
        self.said = []

    def select(self, title, options, default=0):
        self.asked.append(title)
        want = self.answers.get(title, options[default][0])
        assert want in [v for v, _l, _h in options], (title, want, options)
        return want

    def text(self, title, default=None, check=None):
        self.asked.append(title)
        answer = self.answers.get(title, default)
        assert check is None or check(answer) is None, (title, answer)
        return answer

    def note(self, text):
        self.notes.append(text)

    def chosen(self, title, answer):
        self.said.append(title)


class AskTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()

    def ask(self, answers, this_os="linux", aliases=("cn-control", "box"), **kw):
        ui = FakeUI(answers)
        with mock.patch.object(targets, "this_machine_name", return_value="owners-mac"), \
                mock.patch.object(targets, "this_os", return_value=this_os):
            got = targets.ask(self.site, ui, list(aliases), **kw)
        return got, ui

    def test_this_machine_on_the_command_line(self):
        got, ui = self.ask({"Which machine?": None, "How does it join?": "personal",
                            "Which region first?": "ovs"})
        self.assertEqual(got, {"host": None, "os_name": "linux", "role": "personal", "region": "ovs",
                               "name": "owners-mac"})
        self.assertEqual(ui.asked, ["Which Tailscale?", "Which OS?", "Which machine?", "How does it join?",
                                    "Which region first?", "Its name in the tailnet"])

    def test_the_os_decides_whether_this_machine_is_offered(self):
        got, ui = self.ask({"Which OS?": "macos", "Which machine?": "box"}, this_os="linux")
        self.assertEqual((got["host"], got["os_name"], got["role"]), ("box", "macos", "server"))
        with self.assertRaises(AssertionError):                       # "This machine" is not a choice
            self.ask({"Which OS?": "macos", "Which machine?": None}, this_os="linux")

    def test_the_app_on_this_mac_or_another(self):
        got, ui = self.ask({"Which Tailscale?": "app", "Which Mac?": "here"}, this_os="macos")
        self.assertEqual(got, {"host": None, "here": True, "app": True, "region": "cn", "name": "owners-mac"})
        self.assertNotIn("Which OS?", ui.asked)                       # the app: macOS only, said not asked
        self.assertIn("Which OS?", ui.said)
        got, ui = self.ask({"Which Tailscale?": "app", "Which Mac?": "other", "Its name in the tailnet": "air"},
                           this_os="macos")
        self.assertEqual(got, {"host": None, "here": False, "app": True, "region": "cn", "name": "air"})
        got, ui = self.ask({"Which Tailscale?": "app"}, this_os="linux")   # from Linux: another Mac only
        self.assertFalse(got["here"])
        self.assertIn("Which Mac?", ui.said)

    def test_a_site_host_needs_no_more_questions(self):
        got, ui = self.ask({"Which machine?": "cn-control"})
        self.assertEqual(got, {"host": "cn-control", "os_name": "linux"})
        self.assertEqual(ui.notes, ["cn-control is the control host of cn: it joins cn as a server."])

    def test_options_skip_their_questions(self):
        got, ui = self.ask({}, host="box", given={"role": "server", "region": "cn"}, pick=False)
        self.assertEqual(got, {"host": "box", "name": "box"})
        self.assertEqual(ui.asked, ["Its name in the tailnet"])
        got, ui = self.ask({"Which Mac?": "other"}, this_os="macos", given={"app": True})
        self.assertNotIn("Which Tailscale?", ui.asked)                # --app answers it

    def test_another_machine_by_alias(self):
        got, _ui = self.ask({"Which machine?": "?", "SSH alias": "far-box", "Which region?": "ovs"})
        self.assertEqual(got, {"host": "far-box", "os_name": "linux", "role": "server", "region": "ovs",
                               "name": "far-box"})


class TuiTest(unittest.TestCase):
    def test_menu_keys(self):
        self.assertEqual(tui.menu_key(0, "up", 3), (2, False))
        self.assertEqual(tui.menu_key(2, "down", 3), (0, False))
        self.assertEqual(tui.menu_key(1, "j", 3), (2, False))
        self.assertEqual(tui.menu_key(1, "enter", 3), (1, True))
        self.assertEqual(tui.menu_key(0, "3", 3), (2, True))
        self.assertEqual(tui.menu_key(0, "9", 3), (0, False))
        with self.assertRaises(KeyboardInterrupt):
            tui.menu_key(0, "esc", 3)

    def test_without_a_terminal(self):
        out = io.StringIO()
        ui = tui.UI(inp=io.StringIO("2\n\nx\nmine\n"), out=out, tty=False)
        self.assertEqual(ui.select("Pick", [("a", "A", "first"), ("b", "B", "")]), "b")
        self.assertEqual(ui.text("Name", "dflt"), "dflt")
        self.assertEqual(ui.text("Other", check=lambda v: None if v == "mine" else "say mine"), "mine")
        text = out.getvalue()
        self.assertIn("  1. A  first\n  2. B\n", text)
        self.assertIn("✔ Pick B", text)
        self.assertIn("say mine", text)
        self.assertNotIn("\x1b[", text)
        with self.assertRaises(KeyboardInterrupt):    # end of input
            tui.UI(inp=io.StringIO(""), out=io.StringIO(), tty=False).text("Name")

    @unittest.skipUnless(hasattr(os, "openpty"), "needs a pty")
    def test_arrow_keys_in_a_terminal(self):
        master, slave = os.openpty()
        # The menu flushes input typed before it starts, so type once it is up; Enter in the end
        # makes sure a stuck test ends.
        typing = threading.Timer(0.3, os.write, (master, b"\x1b[B\x1b[B\x1b[A\r"))
        typing.start()
        try:
            with os.fdopen(slave, "r", closefd=False) as inp:
                out = io.StringIO()
                with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
                    ui = tui.UI(inp=inp, out=out, tty=True)
                    got = ui.select("Pick", [("a", "A", ""), ("b", "B", ""), ("c", "C", "")])
        finally:
            typing.join()
            os.close(master)
            os.close(slave)
        self.assertEqual(got, "b")
        self.assertTrue(out.getvalue().endswith("✔ Pick B\n"))
        self.assertIn("\x1b[?25h", out.getvalue())           # the cursor is shown again
