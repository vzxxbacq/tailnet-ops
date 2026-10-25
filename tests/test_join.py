import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import unittest
from pathlib import Path
from unittest import mock

from tailnet_ops import join, pins, remote, scripts
from tailnet_ops import site as sitemod
from tailnet_ops.procedure import StepError
from tests.helpers import FakeRunner, TempDirTest, bash, example_text, run_bash

CA = "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n"
SUMS = pins.TAILSCALE_BIN_SHA256["amd64"]


class FakeOps:
    def __init__(self, ca=CA):
        self.ca = ca
        self.calls = []

    def ca_pem(self):
        return self.ca

    def binaries(self, arch):
        self.calls.append(("binaries", arch))
        return {"tailscale": Path("/cache/tailscale"), "tailscaled": Path("/cache/tailscaled")}


def status(state="Running", ip="100.64.1.1", tags=("tag:cn-server",)):
    return json.dumps({"BackendState": state, "Self": {"TailscaleIPs": [ip, "fd7a:115c:a1e0::1"], "Tags": list(tags)}})


def responses(**kw):
    preflight = kw.get("preflight", "TN-FACT arch=amd64\nTN-FACT tailscale=none\nTN-FACT tailscaled=none\n")
    return {
        "TN-FACT arch=": preflight,
        "mktemp -d /tmp/tn-tailscale.": "TN-FACT stage=/tmp/tn-tailscale.abc123\n",
        join.STATUS_JSON: kw.get("status", status(state="NeedsLogin")),
        join.NETCHECK_JSON: json.dumps({"UDP": True, "PreferredDERP": kw.get("derp", 901)}),
        join.NODES_JSON: json.dumps(kw.get("nodes", [
            {"id": 7, "given_name": "cn-probe", "tags": ["tag:cn-server"]},
            {"id": 3, "given_name": "ovs-line", "ip_addresses": ["100.64.2.4", "fd7a:115c:a1e0::4"]}])),
        "ip -4 route show table 52": kw.get("routes", "10.255.2.0/24 dev tailscale0 table 52\n"),
        "echo TN-PING ok": "TN-PING ok\n" if kw.get("across", True) else "TN-PING fail\n",
    }


class SiteHostsTest(TempDirTest):
    def test_region_and_tags(self):
        site = self.load_site()
        self.assertEqual(site.host_region("cn-control").name, "cn")
        self.assertEqual(site.host_region("ovs-probe").name, "ovs")
        self.assertEqual(site.host_tags("cn-probe"), ["tag:cn-server"])
        self.assertEqual(site.host_region("cn-gateway").name, "cn")  # [hosts.cn-gateway] region in the example
        self.assertEqual(site.host_tags("cn-gateway"), ["tag:cn-server", "tag:cn-gateway"])  # line initiator
        with self.assertRaises(sitemod.SiteError) as cm:
            site.host_region("elsewhere")
        self.assertIn('add [hosts.elsewhere] region = "<region>"', str(cm.exception))

    def test_line_roles_add_tags(self):
        text = example_text(('initiator = "cn-gateway"', 'initiator = "cn-control"'),
                            ('responder = "ovs-line"', 'responder = "ovs-control"'))
        site = self.load_site(text, name="roles")
        self.assertEqual(site.host_tags("cn-control"), ["tag:cn-server", "tag:cn-gateway"])
        self.assertEqual(site.host_tags("ovs-control"), ["tag:ovs-server", "tag:ovs-border"])

    def test_explicit_region_and_tags(self):
        text = example_text(('region = "cn"', 'region = "cn"\ntags = ["tag:cn-gateway"]'))
        site = self.load_site(text, name="explicit")
        self.assertEqual(site.host_tags("cn-gateway"), ["tag:cn-gateway"])
        bad = example_text(('region = "cn"', 'region = "eu"'),
                           ("[[lines]]", '[hosts.cn-probe]\ntags = ["tag:ovs-server"]\n\n[[lines]]'))
        with self.assertRaises(sitemod.SiteError) as cm:
            sitemod.load(self.make_site_dir(bad, "bad"), known_host=lambda a: True)
        msg = str(cm.exception)
        self.assertIn("hosts.cn-gateway.region: no region 'eu'", msg)
        self.assertIn("hosts.cn-probe.tags: 'tag:ovs-server' is not a tag of the host's region", msg)


class JoinPlanTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()

    def test_plan(self):
        text, digest = join.Join(self.site, "ovs-control", ops=FakeOps()).plan_text()
        for n, title in enumerate(["Preflight", "Binaries", "Site CA", "tailscaled", "Join", "Verify"], 1):
            self.assertIn(f"Step {n}/6  {title}", text)
        self.assertEqual(text.count("  Rollback"), 6)
        self.assertIn("runs the rollbacks of steps 5, 4, 3, 2 in that order", text)
        self.assertIn("--port=41641 --no-logs-no-support", text)
        self.assertIn("--login-server=https://203.0.113.20:9443 --auth-key=file:/dev/stdin --hostname=ovs-control", text)
        self.assertIn("preauthkeys create --expiration 10m --tags tag:ovs-server", text)
        self.assertNotIn("--advertise-tags", text)
        self.assertEqual(digest, join.Join(self.site, "ovs-control", ops=FakeOps()).plan_id())

    def test_check_reports_what_matters(self):
        ok = "TN-FACT os=Ubuntu 24.04 LTS\nTN-FACT machine=x86_64\nTN-FACT port=free\nTN-FACT login=ok\n"
        job = join.Join(self.site, "cn-probe", runner=FakeRunner({"TN-FACT os=": ok}), ops=FakeOps())
        checks = job.check()
        self.assertEqual(checks["fails"], [])
        text = job.summary_text(checks)
        self.assertIn("✓ cn-probe reaches it over TLS", text)
        self.assertIn("✓ port free", text)
        self.assertIn("host          Ubuntu 24.04 LTS, x86_64", text)

    def test_check_lists_failures(self):
        out = ("TN-FACT os=Ubuntu\nTN-FACT arch=amd64\nTN-FACT port=busy\nTN-FACT login=fail\n"
               "  FAIL  udp/41641 is in use: x\n  FAIL  cannot reach https://198.51.100.10:9443 with the site CA: y\n")

        class Failing(FakeRunner):
            def run(self, host, script, **kw):
                self.calls.append(("run", host, script, (), kw.get("privileged")))
                return remote.Result(1, out)

        job = join.Join(self.site, "cn-probe", runner=Failing(), ops=FakeOps())
        checks = job.check()
        self.assertEqual(len(checks["fails"]), 2)
        text = job.summary_text(checks)
        self.assertIn("✗ cn-probe cannot reach it", text)
        self.assertIn("✗ port in use", text)
        self.assertIn("Not ready to join (2):", text)

    def test_check_without_ssh_or_ca(self):
        from tailnet_ops.remote import Result

        class NoSSH(FakeRunner):
            def run(self, host, script, **kw):
                return Result(255, "ssh: Could not resolve hostname cn-probe\n")

        checks = join.Join(self.site, "cn-probe", runner=NoSSH(), ops=FakeOps()).check()
        self.assertEqual(checks["fails"], ["cannot log in over SSH as root: ssh: Could not resolve hostname cn-probe"])
        checks = join.Join(self.site, "cn-probe", runner=NoSSH(), ops=FakeOps(ca=None)).check()
        self.assertIn("no site CA yet", checks["fails"][0])

    def test_host_settings(self):
        site = self.load_site(example_text(("tailscale_port = 41641", "tailscale_port = 20002")), name="b")
        job = join.Join(site, "cn-control", ops=FakeOps())
        self.assertIn("--netfilter-mode=off", job.plan_text()[0])
        self.assertEqual(join.Join(site, "ovs-control", ops=FakeOps()).port, 20002)
        self.assertEqual(join.Join(site, "cn-probe", ops=FakeOps()).port, 41641)


class JoinApplyTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.out = []

    def job(self, runner, alias="cn-probe", ops=None):
        return join.Join(self.site, alias, runner=runner, ops=ops or FakeOps(), out=self.out.append)

    def test_needs_yes(self):
        runner = FakeRunner()
        self.assertEqual(self.job(runner).apply(ask=lambda p: "no"), 1)
        self.assertEqual(runner.calls, [])

    def test_runs_every_step(self):
        state = {"joined": False}
        runner = FakeRunner(responses())

        def fake_run(host, script, **kw):
            if join.STATUS_JSON in script:
                runner.responses[join.STATUS_JSON] = status() if state["joined"] else status(state="NeedsLogin")
            return FakeRunner.run(runner, host, script, **kw)

        def fake_pipe(*a):
            FakeRunner.pipe(runner, *a)
            state["joined"] = True

        runner.run, runner.pipe = fake_run, fake_pipe
        ops = FakeOps()
        rc = self.job(runner, ops=ops).apply(yes=True)
        self.assertEqual(rc, 0, "\n".join(self.out))
        kinds = []
        for call in runner.calls:
            if call[0] == "upload":
                kinds.append(("upload", call[1], call[3]))
            elif call[0] == "pipe":
                kinds.append(("pipe", call[1], call[3]))
                self.assertIn('"$BIN" preauthkeys create --expiration 10m --tags tag:cn-server', call[2])
                self.assertEqual(call[4][:2], (join.TS_BIN, "up"))
                self.assertIn("--auth-key=file:/dev/stdin", call[4])
            else:
                _r, host, script, args, privileged = call
                for marker, name in (("pass \"/dev/net/tun\"", "preflight"),
                                     ("mktemp -d /tmp/tn-tailscale.", "stage"), ("install -o root -g root", "install"),
                                     ("update-ca-certificates", "ca"), ("systemctl enable --now tailscaled", "service"),
                                     (join.NETCHECK_JSON, "netcheck"), (join.STATUS_JSON, "status"),
                                     (join.NODES_JSON, "nodes")):
                    if marker in script:
                        kinds.append((name, host, privileged))
                        break
        self.assertEqual(kinds, [
            ("preflight", "cn-probe", True),
            ("stage", "cn-probe", False),
            ("upload", "cn-probe", "/tmp/tn-tailscale.abc123/tailscale"),
            ("upload", "cn-probe", "/tmp/tn-tailscale.abc123/tailscaled"),
            ("install", "cn-probe", True),
            ("ca", "cn-probe", True),
            ("service", "cn-probe", True),
            ("status", "cn-probe", True),
            ("pipe", "cn-control", "cn-probe"),
            ("status", "cn-probe", True),
            ("netcheck", "cn-probe", True),
            ("nodes", "cn-control", True),
            ("nodes", "ovs-control", True),  # the far border's address, for the ping across line1
        ])
        self.assertIn("    verify passed", self.out)
        self.assertIn("    ✓ reaches ovs-line in ovs at 10.255.2.4 through line line1", self.out)

    def test_cross_region_failures(self):
        runner = FakeRunner(responses(status=status(), routes=""))
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_verify()
        self.assertIn("no route to 10.255.2.0/24 (line line1)", str(cm.exception))
        runner = FakeRunner(responses(status=status(), across=False))
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_verify()
        self.assertIn("cannot reach ovs-line at 10.255.2.4 through line line1", str(cm.exception))

    def test_borders_do_not_take_routes(self):
        site = self.load_site(example_text(('initiator = "cn-gateway"', 'initiator = "cn-probe"')), name="b")
        self.assertFalse(join.Join(site, "cn-probe", ops=FakeOps()).accept_routes)
        self.assertTrue(join.Join(self.site, "cn-probe", ops=FakeOps()).accept_routes)
        self.assertIn("--accept-routes=true", " ".join(join.up_argv(self.site.regions["cn"], "x", None, True)))

    def test_skips_what_is_done(self):
        sums = f"TN-FACT arch=amd64\nTN-FACT tailscale={SUMS['tailscale']}\nTN-FACT tailscaled={SUMS['tailscaled']}\n"
        runner = FakeRunner(responses(preflight=sums, status=status()))
        ops = FakeOps()
        self.assertEqual(self.job(runner, ops=ops).apply(yes=True), 0, "\n".join(self.out))
        self.assertEqual(ops.calls, [])
        self.assertFalse(any(c[0] in ("upload", "pipe") for c in runner.calls))
        self.assertIn("    already joined; no new key made", self.out)

    def test_verify_catches_problems(self):
        runner = FakeRunner(responses(status=status(ip="100.64.2.9", tags=["tag:cn-gateway"]), derp=902, nodes=[]))
        with self.assertRaises(StepError) as cm:
            self.job(runner)._run_verify()
        msg = str(cm.exception)
        self.assertIn("no address inside 100.64.1.0/24", msg)
        self.assertIn("tags are ['tag:cn-gateway'], expected ['tag:cn-server']", msg)
        self.assertIn("preferred DERP region is 902, expected 901", msg)
        self.assertIn("exactly one node named cn-probe", msg)

    def test_json_with_noise_before_it(self):
        noisy = "# Warning: this JSON format is not yet considered a stable interface\n" + json.dumps({"PreferredDERP": 901})
        self.assertEqual(join._json(noisy, "netcheck"), {"PreferredDERP": 901})
        self.assertEqual(join._json("[]\n", "nodes"), [])
        with self.assertRaises(StepError):
            join._json("no json here", "netcheck")

    def test_needs_the_site_ca(self):
        runner = FakeRunner(responses())
        self.assertEqual(self.job(runner, ops=FakeOps(ca=None)).apply(yes=True), 1)
        self.assertEqual(runner.calls, [])
        self.assertTrue(any("tn control apply cn" in line for line in self.out))

    def test_rollback(self):
        nodes = [{"id": 7, "given_name": "cn-probe", "pre_auth_key": {"id": 1}},
                 {"id": 8, "given_name": "cn-other", "pre_auth_key": {"id": 2}}]
        keys = [{"id": 1, "used": True, "acl_tags": ["tag:cn-server"]},            # this node's key
                {"id": 2, "used": True, "acl_tags": ["tag:cn-server"]},            # still used by cn-other
                {"id": 3, "used": False, "acl_tags": ["tag:cn-server"],
                 "expiration": "2000-01-01T00:00:00Z"},                             # expired, unused
                {"id": 4, "used": False, "acl_tags": ["tag:cn-server"],
                 "expiration": "2999-01-01T00:00:00Z"},                             # still valid
                {"id": 5, "used": True, "acl_tags": ["tag:cn-gateway"]}]           # other tags
        runner = FakeRunner({**responses(nodes=nodes), join.PREAUTH_KEYS_JSON: json.dumps(keys)})
        job = self.job(runner)
        self.assertEqual(job.rollback(ask=lambda p: "no"), 1)
        self.assertEqual(runner.calls, [])
        self.assertEqual(job.rollback(yes=True), 0, "\n".join(self.out))
        sent = [(c[1], c[2]) for c in runner.calls]
        self.assertIn(join.LOGOUT.strip(), sent[0][1])
        deletes = [s for h, s in sent if "delete -i" in s]
        self.assertEqual(len(deletes), 3, deletes)
        self.assertIn('"$BIN" nodes delete -i 7 --force', deletes[0])
        self.assertIn('"$BIN" preauthkeys delete -i 1', deletes[1])
        self.assertIn('"$BIN" preauthkeys delete -i 3', deletes[2])
        host_scripts = [s for h, s in sent if h == "cn-probe"]
        self.assertIn(join.ROLLBACK_SERVICE.strip(), host_scripts[1])
        self.assertIn("update-ca-certificates --fresh", host_scripts[2])
        self.assertIn(CA.strip(), host_scripts[2])
        self.assertIn(join.ROLLBACK_BINARIES.strip(), host_scripts[3])
        self.assertIn(join.LEFTOVERS.strip(), host_scripts[4])
        # The fake Headscale still lists the node, so the leftovers check reports it.
        self.assertTrue(any("node 7 (cn-probe) in Headscale" in line for line in self.out), self.out)

    def test_leftovers_clean(self):
        runner = FakeRunner({**responses(nodes=[]), join.PREAUTH_KEYS_JSON: "[]", join.LEFTOVERS: ""})
        job = self.job(runner)
        self.assertEqual(job.leftovers(), [])
        job.after_rollback()
        self.assertTrue(any(line.startswith("\n✓ Nothing left") for line in self.out), self.out)
        runner.responses[join.LEFTOVERS] = "TN-LEFT /var/lib/tailscale\nTN-LEFT interface tailscale0\n"
        self.assertEqual(job.leftovers(), ["/var/lib/tailscale", "interface tailscale0"])


class JoinScriptsTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.job = join.Join(self.site, "ovs-control", ops=FakeOps())

    def all_scripts(self):
        out = []
        for step in self.job.steps():
            for i, action in enumerate(step.actions):
                if action.body:
                    prelude = self.job.prelude if action.prelude == "host" else self.job.control_prelude
                    out.append((f"step{step.number}.{i}", scripts.wrap(prelude, action.body)))
            if step.rollback:
                out.append((f"rollback{step.number}", scripts.wrap(self.job.prelude, step.rollback)))
        out.append(("rollback-ca", scripts.wrap(self.job.prelude, join.rollback_ca(CA))))
        return out

    def test_every_script_parses(self):
        for name, script in self.all_scripts():
            with self.subTest(script=name):
                p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        for name, script in self.all_scripts():
            with self.subTest(script=name):
                p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"],
                                   input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)

    def sandbox(self, body):
        """Run a host script with its paths under a temp root and stub commands."""
        root = self.tmp / "root"
        root.mkdir(exist_ok=True)
        stubs = self.tmp / "stubs"
        stubs.mkdir(exist_ok=True)
        log = self.tmp / "stub.log"
        for name, text in {
            "systemctl": 'echo "systemctl $*" >> "$STUB_LOG"; [ "$1" = is-active ] && exit 3; exit 0',
            "update-ca-certificates": 'echo "update-ca-certificates $*" >> "$STUB_LOG"',
            "sha256sum": 'exec shasum -a 256 "$@"',
        }.items():
            (stubs / name).write_text(f"#!/bin/sh\n{text}\n")
            (stubs / name).chmod(0o755)
        prelude = self.job.prelude
        for var, real in (("TS_BIN", join.TS_BIN), ("TSD_BIN", join.TSD_BIN), ("TS_UNIT", join.TS_UNIT),
                          ("TS_STATE", join.TS_STATE), ("TS_CACHE", join.TS_CACHE),
                          ("CA_FILE", join.ca_file(self.site))):
            line = f"{var}={real}"
            self.assertIn(line, prelude)
            prelude = prelude.replace(line, f"{var}={root}/{var.lower()}")
        env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "STUB_LOG": str(log)}
        p = run_bash(scripts.wrap(prelude, body), env=env)
        return p, root, (log.read_text() if log.exists() else "")

    def test_rollback_ca_only_removes_this_sites_ca(self):
        p, root, log = self.sandbox("printf 'other\\n' > \"$CA_FILE\"\n" + join.rollback_ca(CA))
        self.assertIn("is not this site's CA", p.stdout)
        self.assertTrue((root / "ca_file").exists())
        self.assertNotIn("update-ca-certificates", log)
        p, root, log = self.sandbox(f"cat > \"$CA_FILE\" <<'EOF'\n{CA}EOF\n" + join.rollback_ca(CA))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((root / "ca_file").exists())
        self.assertIn("update-ca-certificates --fresh", log)

    def test_rollback_service_keeps_foreign_state(self):
        p, root, log = self.sandbox('mkdir -p "$TS_STATE"; printf x > "$TS_UNIT"\n' + join.ROLLBACK_SERVICE)
        self.assertIn("is not ours", p.stdout)
        self.assertTrue((root / "ts_state").exists())
        self.assertTrue((root / "ts_unit").exists())
        self.assertNotIn("disable", log)

    def test_install_rejects_wrong_binaries(self):
        stage = Path("/tmp") / f"tn-tailscale.test{os.getpid()}"
        stage.mkdir(exist_ok=True)
        try:
            (stage / "tailscale").write_text("not tailscale")
            (stage / "tailscaled").write_text("not tailscaled")
            p, root, _log = self.sandbox(f"set -- {stage}\n" + join.INSTALL_BINARIES)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("checksum mismatch for tailscale", p.stderr)
            self.assertFalse((root / "ts_bin").exists())
            self.assertFalse(stage.exists())
        finally:
            shutil.rmtree(stage, ignore_errors=True)


class BinariesTest(TempDirTest):
    def test_extracts_and_checks_the_pinned_binaries(self):
        site = self.load_site()
        cache = site.cache_dir
        cache.mkdir(mode=0o700)
        prefix = f"tailscale_{pins.TAILSCALE_VERSION}_amd64"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            for name, data in (("tailscale", b"cli"), ("tailscaled", b"daemon"), ("systemd/x", b"unit")):
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        tgz = cache / pins.tailscale_asset("amd64")
        tgz.write_bytes(buf.getvalue())
        sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
        with mock.patch.dict(pins.TAILSCALE_SHA256, {"amd64": sha(buf.getvalue())}), \
                mock.patch.dict(pins.TAILSCALE_BIN_SHA256, {"amd64": {"tailscale": sha(b"cli"), "tailscaled": sha(b"daemon")}}):
            paths = join.LocalOps(site, out=lambda s: None).binaries("amd64")
            self.assertEqual(paths["tailscale"].read_bytes(), b"cli")
            self.assertEqual(paths["tailscaled"].stat().st_mode & 0o777, 0o600)
            with mock.patch.dict(pins.TAILSCALE_BIN_SHA256, {"amd64": {"tailscale": sha(b"x"), "tailscaled": sha(b"daemon")}}):
                with self.assertRaises(StepError):
                    join.LocalOps(site, out=lambda s: None).binaries("amd64")


class PipeTest(TempDirTest):
    def test_key_goes_from_one_ssh_to_the_other(self):
        """With a fake ssh that runs commands locally, the secret reaches the second command's
        stdin but never this process's output or log."""
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        (stubs / "ssh").write_text('#!/bin/sh\nfor last; do :; done\nexec /bin/bash -c "$last"\n')
        (stubs / "sudo").write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')
        for f in stubs.iterdir():
            f.chmod(0o755)
        secret = "hs" + "key-auth-" + "s3cr3t" * 4
        out, log = [], []
        runner = remote.SSHRunner(out=out.append, log=log.append)
        with mock.patch.dict(os.environ, {"PATH": f"{stubs}:{os.environ['PATH']}"}):
            runner.pipe("src", f"tn_main() {{ echo {secret}; }}\ntn_main\n", "dst", ["wc", "-c"])
        self.assertEqual([line.strip() for line in out], [str(len(secret) + 1)])
        self.assertFalse(any(secret in line for line in out))
        self.assertFalse(any(secret in line for line in log if "tn_main" not in line))
