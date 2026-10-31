"""The site CA on a machine that did not make it: read from the control hosts, checked against TLS."""

import io
import ssl
import urllib.error

from tailscale_ops import join, siteca, tui
from tailscale_ops.cli import ca_asker
from tailscale_ops.appjoin import AppJoin
from tests.helpers import FakeRunner, TempDirTest
from tests.test_apple import CA, AppJoinTest, Runner
from tests.test_join import FakeOps, responses

OTHER = CA.replace("MIIBdzCC", "MIIBdzCD")     # a different certificate as far as comparing goes


class HostsKeepCA(FakeRunner):
    def __init__(self, cas, base=None):
        super().__init__(base or {})
        self.cas = cas

    def run(self, host, script, args=(), privileged=False, check=True, echo=True, secret=False):
        if siteca.CA_CERT in script:
            self.calls.append(("run", host, script, tuple(args), privileged))
            return _Result(self.cas.get(host, ""))
        return super().run(host, script, args=args, privileged=privileged, check=check, echo=echo)


class _Result:
    def __init__(self, output):
        self.rc, self.output = 0, output


class CAAndKeys(HostsKeepCA, Runner):
    """Control hosts that keep the CA and hand out keys."""


def accepts(url, context, timeout):
    return _Closing()


class _Closing:
    def close(self):
        pass


def rejects(url, context, timeout):
    raise urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed: unable to get local issuer"))


def offline(url, context, timeout):
    raise urllib.error.URLError(OSError("Network is unreachable"))


def not_found(url, context, timeout):
    raise urllib.error.HTTPError(url, 404, "Not Found", None, None)


class FetchTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.regions = list(self.site.regions.values())

    def fetch(self, cas, opener=accepts):
        return siteca.fetch(self.site, HostsKeepCA(cas), self.regions, opener=opener)

    def test_the_same_ca_everywhere(self):
        pem, source = self.fetch({"cn-control": CA, "ovs-control": CA})
        self.assertEqual((pem, source), (CA, "cn-control"))
        self.assertEqual(self.fetch({"ovs-control": CA})[0], CA)            # one host is enough
        self.assertEqual(self.fetch({"cn-control": CA}, opener=offline)[0], CA)   # cannot check: not the CA's fault

    def test_refuses_what_does_not_fit(self):
        self.assertEqual(self.fetch({}), (None, "no control host answered with it"))
        pem, why = self.fetch({"cn-control": CA, "ovs-control": OTHER})
        self.assertIsNone(pem)
        self.assertIn("keep different CAs", why)
        pem, why = self.fetch({"cn-control": CA}, opener=rejects)
        self.assertIsNone(pem)
        self.assertIn("does not authenticate https://198.51.100.10:9443", why)

    def test_save(self):
        siteca.save(self.site, CA)
        self.assertEqual(siteca.local(self.site), CA)
        self.assertEqual(siteca.path(self.site).stat().st_mode & 0o777, 0o600)


class UseTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []
        self.real = siteca.authenticates
        siteca.authenticates = lambda pem, url, opener=None: None

    def tearDown(self):
        siteca.authenticates = self.real
        super().tearDown()

    def test_the_app_path_uses_and_keeps_it(self):
        runner = CAAndKeys({"cn-control": CA}, AppJoinTest.responses())
        job = AppJoin(self.site, "air", "cn", runner=runner, out=self.out.append, show=lambda s: None,
                      clipboard=lambda s: True)
        checks = job.check()
        self.assertEqual(checks["fails"], [])
        self.assertIn("site CA       from cn-control", job.summary_text(checks))
        self.assertIsNone(siteca.local(self.site))                      # the check writes nothing
        job._run_profile()
        self.assertEqual(siteca.local(self.site), CA)

    def test_the_command_line_path_uses_and_keeps_it(self):
        runner = HostsKeepCA({"cn-control": CA}, responses())
        job = join.Join(self.site, "cn-probe", runner=runner, ops=FakeOps(ca=None), out=self.out.append)
        ca, problem = job.site_ca()
        self.assertEqual((ca, problem, job.ca_from), (CA, None, "cn-control"))
        job.before_steps()
        self.assertEqual(siteca.local(self.site), CA)


class PasteTest(TempDirTest):
    """No site CA here and no control host gives it: the user prints ca.crt elsewhere and pastes it."""

    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.regions = list(self.site.regions.values())

    def test_a_pasted_certificate_must_fit(self):
        self.assertEqual(siteca.pasted("\r\n" + CA.replace("\n", "\r\n"), self.regions, accepts), (CA, None))
        self.assertEqual(siteca.pasted(CA, self.regions, not_found), (CA, None))      # TLS held
        self.assertIn("exactly one certificate", siteca.pasted("hello", self.regions, accepts)[1])
        self.assertIn("exactly one certificate", siteca.pasted(CA + CA, self.regions, accepts)[1])
        self.assertIn("not a certificate", siteca.pasted(OTHER, self.regions, accepts)[1])
        self.assertIn("does not authenticate https://198.51.100.10:9443", siteca.pasted(CA, self.regions, rejects)[1])
        self.assertIn("cannot reach", siteca.pasted(CA, self.regions, offline)[1])   # trusted only once checked

    def test_commands(self):
        where = [c for _w, c in siteca.commands(self.site.regions["cn"])]
        self.assertEqual(where, ["sudo cat /etc/headscale/tls/ca.crt",
                                 "ssh cn-control 'sudo cat /etc/headscale/tls/ca.crt'",
                                 "cat ~/.config/tailnet-ops/pki/ca.crt"])

    def test_the_prompt_takes_a_paste_or_a_path(self):
        copy = self.tmp / "ca.crt"
        copy.write_text(CA)
        accept = lambda text: siteca.pasted(text, self.regions, accepts)       # noqa: E731
        for answer in (CA, f"{self.tmp}/missing.crt\n{copy}\n"):
            out = io.StringIO()
            ui = tui.UI(inp=io.StringIO(answer), out=out, tty=False)
            self.assertEqual(ca_asker(ui)(self.site.regions["cn"], "no control host answered with it", accept), CA)
            text = out.getvalue()
            self.assertIn("! No site CA here, and tn cannot read it from the control hosts", text)
            self.assertIn("\n    sudo cat /etc/headscale/tls/ca.crt\n", text)
            self.assertIn("✔ Site CA certificate checked against the login servers", text)
        self.assertIn("cannot read", text)
        ui = tui.UI(inp=io.StringIO("x\ny\nz\n"), out=io.StringIO(), tty=False)
        self.assertIsNone(ca_asker(ui)(self.site.regions["cn"], "why", accept))

    def test_both_join_paths_ask_and_keep_it(self):
        accepted = []

        def ask(region, why, accept):
            accepted.append(why)
            return CA

        app = AppJoin(self.site, "air", "cn", runner=HostsKeepCA({}, AppJoinTest.responses()), out=lambda s: None,
                      show=lambda s: None, clipboard=lambda s: True)
        app.ask_ca = ask
        self.assertEqual((app._ca(), app.ca_from), (CA, "your paste"))
        self.assertIsNone(siteca.local(self.site))                      # kept only when the profile is written
        app._run_profile()
        self.assertEqual(siteca.local(self.site), CA)
        cmd = join.Join(self.site, "cn-probe", runner=HostsKeepCA({}, responses()), ops=FakeOps(ca=None),
                        out=lambda s: None)
        cmd.ask_ca = ask
        self.assertEqual(cmd.site_ca(), (CA, None))
        self.assertEqual(cmd.ca_from, "your paste")
        self.assertEqual(accepted, ["no control host answered with it"] * 2)
