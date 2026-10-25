"""Run scripts on hosts over SSH. Hosts are SSH aliases from ~/.ssh/config."""

import ipaddress
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

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


# What sudo shows on the machine that runs tn, so a bare "Password:" is not a riddle.
SUDO_PROMPT = "[sudo] password of %u on this machine (tn runs its scripts here as root): "
LOCAL_SUDO = f"sudo -p {shlex.quote(SUDO_PROMPT)}"


def remote_command(args=(), privileged=False, interactive=False):
    """`bash -s` with args, as root when privileged. Over SSH sudo must not prompt (-n); on the
    machine that runs tn (interactive) it may ask for the password on the terminal."""
    argv = " ".join(shlex.quote(a) for a in ("bash", "-s", "--", *args))
    if not privileged:
        return argv
    sudo = LOCAL_SUDO if interactive else "sudo -n"
    return f'if [ "$(id -u)" = 0 ]; then exec {argv}; else exec {sudo} {argv}; fi'


def privileged_command(argv, interactive=False):
    """A command line that runs argv as root (directly, or through sudo)."""
    line = " ".join(shlex.quote(a) for a in argv)
    sudo = LOCAL_SUDO if interactive else "sudo -n"
    return f'if [ "$(id -u)" = 0 ]; then exec {line}; else exec {sudo} {line}; fi'


class SSHRunner:
    """Runs scripts on hosts over SSH, except on `local_hosts` (the machine that runs tn),
    where they run here directly."""

    def __init__(self, out=print, log=None, local_hosts=()):
        self.out = out
        self.log = log
        self.local_hosts = set(local_hosts)

    def command(self, host, line):
        """argv that runs a shell command line on host."""
        if host in self.local_hosts:
            return ["bash", "-c", line]
        return ["ssh", *SSH_OPTS, host, line]

    def _interactive(self, host):
        return host in self.local_hosts

    def _log(self, text):
        if self.log is not None:
            self.log(text)

    def run(self, host, script, args=(), privileged=False, check=True, echo=True, secret=False):
        """secret: the output is a secret (a pre-auth key): it is returned, never printed or logged."""
        cmd = self.command(host, remote_command(args, privileged, self._interactive(host)))
        where = "this machine" if host in self.local_hosts else f"ssh {host}"
        self._log(f"$ {where} {'(root)' if privileged else ''}\n{script}")
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
            if secret:
                continue
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
        src = subprocess.Popen(self.command(src_host, remote_command((), True, self._interactive(src_host))),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        dst = subprocess.Popen(self.command(dst_host, privileged_command(dst_argv, self._interactive(dst_host))),
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

    def feed(self, host, argv, secret):
        """Run argv as root on host with secret on its stdin. The secret is never printed or logged.
        Used for a link code that the user pasted."""
        self._log(f"$ {'this machine' if host in self.local_hosts else f'ssh {host}'} (root) {' '.join(argv)} "
                  "<- the link code on stdin")
        p = subprocess.Popen(self.command(host, privileged_command(argv, self._interactive(host))),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        p.stdin.write(secret.strip() + "\n")
        p.stdin.close()
        for line in p.stdout:
            line = line.rstrip("\n")
            self._log(line)
            self.out(f"    {line}")
        rc = p.wait()
        if rc != 0:
            raise RemoteError(f"command on {host} exited with {rc}")

    def upload(self, host, local, remote):
        if host in self.local_hosts:
            self._log(f"$ cp {local} {remote}")
            p = subprocess.run(["cp", str(local), remote], capture_output=True, text=True)
            if p.returncode != 0:
                raise RemoteError(f"copy to {remote} failed: {p.stderr.strip()}")
            return
        self._log(f"$ scp {local} {host}:{remote}")
        p = subprocess.run(["scp", "-q", *SSH_OPTS, str(local), f"{host}:{remote}"], capture_output=True, text=True)
        if p.returncode != 0:
            raise RemoteError(f"scp to {host} failed: {p.stderr.strip()}")


def ssh_aliases(path=None):
    """The Host aliases in ~/.ssh/config, in order, without patterns."""
    path = Path(path) if path else Path.home() / ".ssh" / "config"
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        words = line.split()
        if len(words) >= 2 and words[0].lower() == "host":
            out += [w for w in words[1:] if not any(c in w for c in "*?!") and w not in out]
    return out


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
