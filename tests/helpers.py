"""Fake sites and runners. Everything here is offline: no test contacts a real host."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tailnet_ops import site as sitemod
from tailnet_ops.remote import RemoteError, Result

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "site.example.toml"


def any_host(_alias):
    return True


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        os.chmod(self.tmp, 0o700)

    def tearDown(self):
        self._tmp.cleanup()

    def make_site_dir(self, text=None, name="site"):
        d = self.tmp / name
        d.mkdir(mode=0o700)
        os.chmod(d, 0o700)
        sitemod.write_private(d / sitemod.SITE_FILE, text if text is not None else EXAMPLE.read_text())
        return d

    def load_site(self, text=None, name="site"):
        return sitemod.load(self.make_site_dir(text, name), known_host=any_host)


def example_text(*pairs):
    """The example site with (old, new) text replacements, each of which must apply."""
    text = EXAMPLE.read_text()
    for old, new in pairs:
        assert old in text, old
        text = text.replace(old, new, 1)
    return text


class FakeRunner:
    """Records calls. `responses` maps a marker substring of a script to output text or an exit code."""

    def __init__(self, responses=None, fail_on=None):
        self.calls = []
        self.responses = responses or {}
        self.fail_on = fail_on

    def run(self, host, script, args=(), privileged=False, check=True, echo=True):
        self.calls.append(("run", host, script, tuple(args), privileged))
        if self.fail_on and self.fail_on in script:
            if check:
                raise RemoteError(f"script on {host} exited with 1")
            return Result(1, "")
        output = ""
        for marker, value in self.responses.items():
            if marker in script:
                output = value
        return Result(0, output)

    def upload(self, host, local, remote):
        self.calls.append(("upload", host, str(local), remote))

    def pipe(self, src_host, src_script, dst_host, dst_argv):
        self.calls.append(("pipe", src_host, src_script, dst_host, tuple(dst_argv)))
        if self.fail_on and self.fail_on in src_script:
            raise RemoteError(f"script on {src_host} exited with 1")

    def scripts_for(self, host):
        return [c[2] for c in self.calls if c[0] == "run" and c[1] == host]


def bash():
    return shutil.which("bash") or "/bin/bash"


def run_bash(script, env=None, cwd=None):
    return subprocess.run([bash(), "-s"], input=script, capture_output=True, text=True, env=env, cwd=cwd)
