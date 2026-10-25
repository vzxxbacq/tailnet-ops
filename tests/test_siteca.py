"""The site CA on a machine that did not make it: read from the control hosts, checked against TLS."""

import ssl
import urllib.error

from tailnet_ops import join, siteca
from tailnet_ops.appjoin import AppJoin
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
