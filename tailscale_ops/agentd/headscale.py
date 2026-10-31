"""The headscale commands the service may run, and nothing else: list nodes, register or reject a
pending login, rename a node, set its tags, delete a node (only one the owner approved to leave). They talk to Headscale over its local socket. Every one
asks for JSON, which also keeps the CLI from looking for updates on the network.

The CLI processes run inside the service's own limits (tasks, memory): at most CONCURRENT of them run
at a time, each with GOMAXPROCS=2 so the Go runtime starts few threads. Each takes a fraction of a
second, so the rest wait briefly."""

import json
import os
import subprocess
import threading

CONCURRENT = 2


class HeadscaleError(Exception):
    pass


class Headscale:
    def __init__(self, binary, config, run=subprocess.run, timeout=30):
        self.binary = binary
        self.config = config
        self.run = run
        self.timeout = timeout
        self.slots = threading.BoundedSemaphore(CONCURRENT)

    def _cli(self, args):
        argv = [self.binary, "-c", self.config, *args, "-o", "json"]
        try:
            with self.slots:
                p = self.run(argv, capture_output=True, text=True, timeout=self.timeout,
                             env=dict(os.environ, GOMAXPROCS="2"))
        except (OSError, subprocess.TimeoutExpired) as e:
            raise HeadscaleError(f"headscale {args[0]} {args[1]}: {e}")
        if p.returncode != 0:
            lines = (p.stderr or p.stdout or "").strip().splitlines()
            raise HeadscaleError(f"headscale {args[0]} {args[1]}: {lines[-1] if lines else f'exit {p.returncode}'}")
        try:
            return json.loads(p.stdout or "null")
        except ValueError:
            raise HeadscaleError(f"headscale {args[0]} {args[1]}: output is not JSON")

    def nodes(self):
        return self._cli(["nodes", "list"]) or []

    def register(self, auth_id, user):
        """The pending login of auth_id joins as user; tags the node asked for and the user owns apply."""
        return self._cli(["auth", "register", "--auth-id", auth_id, "--user", user])

    def reject(self, auth_id):
        self._cli(["auth", "reject", "--auth-id", auth_id])

    def rename(self, node_id, name):
        return self._cli(["nodes", "rename", "-i", str(node_id), name])

    def set_tags(self, node_id, tags):
        args = ["nodes", "tag", "-i", str(node_id)]
        for tag in tags:
            args += ["-t", tag]
        return self._cli(args)

    def delete(self, node_id):
        self._cli(["nodes", "delete", "-i", str(node_id), "--force"])
