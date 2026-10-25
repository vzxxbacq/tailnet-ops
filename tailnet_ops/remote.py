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


def privileged_command(argv):
    """A remote command line that runs argv as root (directly, or through sudo -n)."""
    line = " ".join(shlex.quote(a) for a in argv)
    return f'if [ "$(id -u)" = 0 ]; then exec {line}; else exec sudo -n {line}; fi'


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
            if line.startswith("TN-BEGIN "):
                hidden = True
            elif line.startswith("TN-END "):
                hidden = False
            # Printed lines reach the log through out(); log the rest directly.
            if echo and not hidden and not line.startswith(("TN-FACT ", "TN-BEGIN ", "TN-END ")):
                self.out(f"    {line}")
            else:
                self._log(line)
        rc = p.wait()
        result = Result(rc, "\n".join(lines) + "\n")
        if check and rc != 0:
            raise RemoteError(f"script on {host} exited with {rc}")
        return result

    def pipe(self, src_host, src_script, dst_host, dst_argv):
        """Run src_script (as root) on src_host and feed its stdout into dst_argv (as root) on
        dst_host. The bytes go from one ssh process straight to the other: this process never
        reads, prints or logs them. Used for pre-auth keys."""
        self._log(f"$ ssh {src_host} (root) | ssh {dst_host} (root) {' '.join(dst_argv)}\n{src_script}")
        src = subprocess.Popen(["ssh", *SSH_OPTS, src_host, remote_command((), True)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        dst = subprocess.Popen(["ssh", *SSH_OPTS, dst_host, privileged_command(dst_argv)],
                               stdin=src.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        src.stdout.close()
        src.stdin.write(src_script.encode())
        src.stdin.close()
        for line in dst.stdout:
            line = line.rstrip("\n")
            self._log(line)
            self.out(f"    {line}")
        dst_rc = dst.wait()
        src_err = src.stderr.read().decode(errors="replace").strip()
        src_rc = src.wait()
        if src_err:
            self._log(src_err)
            self.out("    " + src_err.replace("\n", "\n    "))
        if src_rc != 0:
            raise RemoteError(f"script on {src_host} exited with {src_rc}")
        if dst_rc != 0:
            raise RemoteError(f"command on {dst_host} exited with {dst_rc}")

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
