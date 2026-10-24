"""Run scripts on hosts over SSH. Hosts are SSH aliases from ~/.ssh/config."""

import ipaddress
import shlex
import subprocess
from dataclasses import dataclass

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15"]


class RemoteError(Exception):
    pass


@dataclass
class Result:
    rc: int
    output: str

    def facts(self):
        """`TN-FACT key=value` lines."""
        out = {}
        for line in self.output.splitlines():
            if line.startswith("TN-FACT "):
                key, _, value = line[len("TN-FACT "):].partition("=")
                out[key] = value
        return out

    def block(self, name):
        """Text between `TN-BEGIN name` and `TN-END name`, or None."""
        lines, inside = [], False
        for line in self.output.splitlines():
            if line == f"TN-BEGIN {name}":
                inside = True
            elif line == f"TN-END {name}":
                return "\n".join(lines) + "\n"
            elif inside:
                lines.append(line)
        return None


def remote_command(args=(), privileged=False):
    argv = " ".join(shlex.quote(a) for a in ("bash", "-s", "--", *args))
    if not privileged:
        return argv
    return f'if [ "$(id -u)" = 0 ]; then exec {argv}; else exec sudo -n {argv}; fi'


class SSHRunner:
    def __init__(self, out=print, log=None):
        self.out = out
        self.log = log

    def _log(self, text):
        if self.log is not None:
            self.log(text)

    def run(self, host, script, args=(), privileged=False, check=True, echo=True):
        cmd = ["ssh", *SSH_OPTS, host, remote_command(args, privileged)]
        self._log(f"$ ssh {host} {'(root)' if privileged else ''}\n{script}")
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        p.stdin.write(script)
        p.stdin.close()
        lines, hidden = [], False
        for line in p.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            self._log(line)
            if line.startswith("TN-BEGIN "):
                hidden = True
            elif line.startswith("TN-END "):
                hidden = False
            elif echo and not hidden and not line.startswith("TN-FACT "):
                self.out(f"    {line}")
        rc = p.wait()
        result = Result(rc, "\n".join(lines) + "\n")
        if check and rc != 0:
            raise RemoteError(f"script on {host} exited with {rc}")
        return result

    def upload(self, host, local, remote):
        self._log(f"$ scp {local} {host}:{remote}")
        p = subprocess.run(["scp", "-q", *SSH_OPTS, str(local), f"{host}:{remote}"], capture_output=True, text=True)
        if p.returncode != 0:
            raise RemoteError(f"scp to {host} failed: {p.stderr.strip()}")


def ssh_config(host):
    """`ssh -G` for an alias: a dict of lower-case keys. Reads local config only."""
    p = subprocess.run(["ssh", "-G", host], capture_output=True, text=True)
    if p.returncode != 0:
        return {}
    out = {}
    for line in p.stdout.splitlines():
        key, _, value = line.partition(" ")
        out.setdefault(key.lower(), value)
    return out


def known_alias(host):
    """True when ~/.ssh/config gives the alias its own HostName."""
    hostname = ssh_config(host).get("hostname", host)
    return hostname.lower() != host.lower()


def ssh_hostname_ipv4(host):
    """The alias's HostName when it is an IPv4 address, else None."""
    hostname = ssh_config(host).get("hostname", "")
    try:
        return str(ipaddress.IPv4Address(hostname))
    except ValueError:
        return None
