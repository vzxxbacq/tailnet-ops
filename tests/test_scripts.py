"""The remote scripts: syntax, and their logic in a local sandbox with stub commands."""

import http.server
import os
import shutil
import ssl
import subprocess
import threading
import unittest
from pathlib import Path

from tailnet_ops import pki, render, scripts
from tailnet_ops.control import CA_PLACEHOLDER, CERT_PLACEHOLDER, Deployment
from tailnet_ops.site import Region
from tests.helpers import TempDirTest, bash, run_bash
from tests.test_pki import host_key_and_csr
from tests.test_stun import FakeStunServer

STUBS = {
    # name: shell body; $STUB_LOG collects calls.
    "chown": 'echo "chown $*" >> "$STUB_LOG"',
    "getent": 'echo "getent $*" >> "$STUB_LOG"; exit 2',
    "systemctl": 'echo "systemctl $*" >> "$STUB_LOG"; case "$1" in is-active) exit "${STUB_ACTIVE:-3}";; esac',
    "runuser": 'echo "runuser $*" >> "$STUB_LOG"',
    "userdel": 'echo "userdel $*" >> "$STUB_LOG"',
    "groupdel": 'echo "groupdel $*" >> "$STUB_LOG"',
    "journalctl": 'echo "journalctl $*" >> "$STUB_LOG"',
    "sha256sum": 'exec shasum -a 256 "$@"',
    "ip": 'echo "1: lo    inet 127.0.0.1/8 scope host lo"',
    "ss": 'for a in "$@"; do case "$a" in *":$STUB_BUSY_PORT") '
          'echo "LISTEN 0 4096 0.0.0.0:$STUB_BUSY_PORT 0.0.0.0:* users:((\\"$STUB_BUSY_OWNER\\",pid=7,fd=3))";; esac; done',
}


def all_scripts(dep):
    """(name, full script) for everything tailnet-ops can send to a host."""
    out = []
    for step in dep.steps():
        for i, action in enumerate(step.actions):
            if action.body:
                prelude = dep.prelude if action.prelude == "control" else dep.checker_prelude
                out.append((f"step{step.number}.{i}", scripts.wrap(prelude, action.body)))
        if step.rollback:
            out.append((f"rollback{step.number}", scripts.wrap(dep.prelude, step.rollback)))
    out.append(("status", scripts.wrap(dep.prelude, scripts.STATUS)))
    return out


class Sandbox:
    """Control-host scripts with their paths moved under a temp root and stub commands first on PATH."""

    def __init__(self, tmp, site):
        self.site = site
        self.root = tmp / "root"
        self.etc = self.root / "etc-headscale"
        self.lib = self.root / "var-lib-headscale"
        self.unit = self.root / "headscale.service"
        self.bin = self.root / "headscale"
        self.root.mkdir()
        stubs = tmp / "stubs"
        stubs.mkdir()
        for name, body in STUBS.items():
            p = stubs / name
            p.write_text(f"#!/bin/sh\n{body}\n")
            p.chmod(0o755)
        self.log = tmp / "stub.log"
        self.env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "STUB_LOG": str(self.log),
                    "STUB_BUSY_PORT": "0", "STUB_BUSY_OWNER": "x"}

    def script(self, body, region=None):
        prelude = scripts.control_prelude(self.site, region or self.site.regions["cn"])
        for var, real, fake in (("BIN", render.BIN, self.bin), ("ETC", render.ETC, self.etc),
                                ("LIB", render.LIB, self.lib), ("UNIT", render.UNIT, self.unit)):
            line = f"{var}={real}"
            if line not in prelude:
                raise AssertionError(f"prelude has no {line}")
            prelude = prelude.replace(line, f"{var}={fake}")
        return scripts.wrap(prelude, body)

    def run(self, body, region=None, **env):
        return run_bash(self.script(body, region), env={**self.env, **env})

    def stub_log(self):
        return self.log.read_text() if self.log.exists() else ""


class SandboxTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.site = self.load_site()
        self.dep = Deployment(self.site, "cn")
        self.box = Sandbox(self.tmp, self.site)
        self.etc, self.lib, self.unit, self.bin = self.box.etc, self.box.lib, self.box.unit, self.box.bin

    def run_sandboxed(self, body, **env):
        return self.box.run(body, **env)

    def stub_log(self):
        return self.box.stub_log()

    def mark(self, path, region="cn"):
        path.mkdir(parents=True, exist_ok=True)
        (path / ".tailnet-ops").write_text(f"tailnet-ops region={region}\n")


class SyntaxTest(SandboxTest):
    def test_every_script_parses(self):
        for region in ("cn", "ovs"):
            for name, script in all_scripts(Deployment(self.site, region)):
                with self.subTest(region=region, script=name):
                    p = subprocess.run([bash(), "-n"], input=script, capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        for name, script in all_scripts(self.dep):
            with self.subTest(script=name):
                p = subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", "-e", "SC2034", "-"], input=script,
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)

    def test_placeholders_only_in_plan(self):
        bodies = "\n".join(s for _n, s in all_scripts(self.dep))
        self.assertIn(CA_PLACEHOLDER, bodies)
        self.assertIn(CERT_PLACEHOLDER, bodies)
        real = scripts.install_cert("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----", "x")
        self.assertNotIn(CERT_PLACEHOLDER, real)

    def test_heredoc_terminators_do_not_occur_in_content(self):
        stun = scripts.stun_source()
        self.assertNotIn("\nTN_PY\n", stun)
        for text in (render.headscale_config(self.site, self.site.regions["cn"]), render.systemd_unit(
                self.site.regions["cn"]), render.policy(self.site, self.site.regions["cn"])):
            self.assertNotIn("\nTN_EOF\n", f"\n{text}\n")


class OwnershipTest(SandboxTest):
    CHECK = 'for f in ours_etc ours_lib ours_unit; do if $f; then echo "$f yes"; else echo "$f no"; fi; done\n'

    def test_marks(self):
        out = self.run_sandboxed(self.CHECK).stdout
        self.assertEqual(out.split("\n")[:3], ["ours_etc no", "ours_lib no", "ours_unit no"])
        self.mark(self.etc)
        self.mark(self.lib, region="ovs")
        self.unit.write_text("# tailnet-ops region=cn\n[Unit]\n")
        out = self.run_sandboxed(self.CHECK).stdout
        self.assertEqual(out.split("\n")[:3], ["ours_etc yes", "ours_lib no", "ours_unit yes"])

    def test_binary_must_be_pinned(self):
        self.bin.write_text("not headscale")
        out = self.run_sandboxed('if ours_bin; then echo yes; else echo no; fi\n').stdout
        self.assertEqual(out.strip(), "no")
        out = self.run_sandboxed(scripts.ROLLBACK_BINARY).stdout
        self.assertIn("skip: ", out)
        self.assertTrue(self.bin.exists())


class RollbackTest(SandboxTest):
    def test_removes_only_marked_directories(self):
        self.etc.mkdir()
        (self.etc / "config.yaml").write_text("someone else's\n")
        self.mark(self.lib)
        p = self.run_sandboxed(scripts.ROLLBACK_USER_AND_DIRS)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"skip: {self.etc} is not ours", p.stdout)
        self.assertIn(f"removed {self.lib}", p.stdout)
        self.assertTrue((self.etc / "config.yaml").exists())
        self.assertFalse(self.lib.exists())
        self.assertNotIn("userdel", self.stub_log())

    def test_unit_rollback_refuses_while_running(self):
        self.unit.write_text("# tailnet-ops region=cn\n")
        p = self.run_sandboxed(scripts.ROLLBACK_CONFIGURATION, STUB_ACTIVE="0")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(self.unit.exists())
        p = self.run_sandboxed(scripts.ROLLBACK_CONFIGURATION, STUB_ACTIVE="3")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(self.unit.exists())

    def test_foreign_unit_is_kept(self):
        self.unit.write_text("[Unit]\nDescription=someone else's headscale\n")
        p = self.run_sandboxed(scripts.ROLLBACK_CONFIGURATION)
        self.assertIn("is not ours", p.stdout)
        self.assertTrue(self.unit.exists())
        p = self.run_sandboxed(scripts.ROLLBACK_START)
        self.assertIn("skip:", p.stdout)
        self.assertNotIn("disable", self.stub_log())


class ConfigurationTest(SandboxTest):
    def test_writes_then_is_idempotent(self):
        self.mark(self.etc)
        body = self.dep.configuration_body()
        p = self.run_sandboxed(body)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("wrote "), 3)
        self.assertEqual((self.etc / "config.yaml").read_text(), render.headscale_config(self.site, self.dep.region))
        self.assertEqual((self.etc / "policy.hujson").read_text(), "{}\n")
        self.assertEqual(self.unit.read_text(), render.systemd_unit(self.dep.region))
        self.assertTrue((self.etc / ".restart-needed").exists())
        self.assertIn("runuser -u headscale -- ", self.stub_log())
        self.assertIn("configtest --config", self.stub_log())

        (self.etc / ".restart-needed").unlink()
        (self.etc / "policy.hujson").write_text("real policy\n")
        p = self.run_sandboxed(body)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("unchanged "), 2)
        self.assertEqual((self.etc / "policy.hujson").read_text(), "real policy\n")
        self.assertFalse((self.etc / ".restart-needed").exists())

    def test_refuses_foreign_directory(self):
        self.etc.mkdir()
        p = self.run_sandboxed(self.dep.configuration_body())
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.etc / "config.yaml").exists())


class PreflightPortsTest(SandboxTest):
    def test_busy_port_fails(self):
        p = self.run_sandboxed(scripts.PREFLIGHT, STUB_BUSY_PORT="9443", STUB_BUSY_OWNER="nginx")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("FAIL  tcp/9443 is in use (Headscale HTTPS and DERP)", p.stdout)
        self.assertIn("nginx", p.stdout)
        self.assertIn("ok    udp/3478 free (STUN)", p.stdout)
        self.assertIn("preflight failed; nothing was changed", p.stderr)

    def test_port_used_by_our_headscale(self):
        self.mark(self.etc)
        p = self.run_sandboxed(scripts.PREFLIGHT, STUB_BUSY_PORT="9443", STUB_BUSY_OWNER="headscale")
        self.assertIn("ok    tcp/9443 already used by our Headscale", p.stdout)

    def test_foreign_files_fail(self):
        self.etc.mkdir()
        self.bin.write_text("x")
        p = self.run_sandboxed(scripts.PREFLIGHT)
        self.assertIn(f"FAIL  {self.etc} exists and is not ours", p.stdout)
        self.assertIn(f"FAIL  {self.bin} exists and is not the pinned build", p.stdout)


# --- verify and the local health check against a fake Headscale -----------------


class FakeHeadscale(http.server.BaseHTTPRequestHandler):
    derp = True

    def do_GET(self):
        if self.path == "/health":
            self._send(200, b'{"status":"pass"}')
        elif self.path == "/derp/probe" and self.derp:
            self._send(200, b"")
        elif self.path == "/derp" and self.derp:
            self._send(426, b"DERP requires connection upgrade")
        else:
            self._send(404, b"not found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class VerifyTest(TempDirTest):
    """Runs the exact verify and start scripts against a local fake (offline)."""

    def setUp(self):
        super().setUp()
        self.pki = self.tmp / "pki"
        _created, self.ca_pem = pki.ensure_ca(self.pki, "example")
        key, csr = host_key_and_csr(self.tmp)
        cert = self.tmp / "server.crt"
        cert.write_text(pki.sign(self.pki, csr, ["127.0.0.1", "203.0.113.10"]))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.handler = type("H", (FakeHeadscale,), {"derp": True})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.stun = FakeStunServer()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.stun.close()
        super().tearDown()

    def region(self, public):
        return Region(name="cn", control_host="cn-control", check_from="cn-probe", public_ipv4=public,
                      listen_ipv4="0.0.0.0", port=self.httpd.server_address[1], stun_port=self.stun.port,
                      ipv4_prefix="100.64.0.0/16", avoid_prefixes=[], base_domain="cn.tailnet.internal",
                      derp_region_id=901, derp_region_code="cn", derp_region_name="CN", official_derp=False,
                      tags=["tag:cn-server"])

    def test_verify_passes(self):
        script = scripts.wrap(scripts.checker_prelude(self.region("127.0.0.1")), scripts.verify(self.ca_pem))
        p = run_bash(script)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('{"status":"pass"}', p.stdout)
        self.assertIn("/derp/probe -> 200, /derp without upgrade -> 426", p.stdout)
        self.assertIn("STUN binding ok", p.stdout)
        self.assertIn("verify passed", p.stdout)

    def test_verify_fails_without_derp(self):
        self.handler.derp = False
        script = scripts.wrap(scripts.checker_prelude(self.region("127.0.0.1")), scripts.verify(self.ca_pem))
        p = run_bash(script)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("DERP endpoints did not answer", p.stderr)

    def test_verify_rejects_another_ca(self):
        _created, other_ca = pki.ensure_ca(self.tmp / "other-pki", "other")
        script = scripts.wrap(scripts.checker_prelude(self.region("127.0.0.1")), scripts.verify(other_ca))
        p = run_bash(script)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn("verify passed", p.stdout)

    def test_start_checks_health_through_connect_to(self):
        """START reaches the public address locally: curl --connect-to PUBLIC:PORT:LOCAL:PORT."""
        box = Sandbox(self.tmp, self.load_site())
        region = self.region("203.0.113.10")
        (box.etc / "tls").mkdir(parents=True)
        (box.etc / "tls" / "ca.crt").write_text(self.ca_pem)
        box.unit.write_text("# tailnet-ops region=cn\n")
        p = box.run(scripts.START, region)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('local /health over TLS: {"status":"pass"}', p.stdout)
        self.assertIn("systemctl enable --now headscale", box.stub_log())
