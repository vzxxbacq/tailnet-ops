"""The public half of tn-agent (user tn-agent-web): HTTPS on agent_port.

    POST /mcp                 the Agent, with its bearer token
    GET  /a/<id>, /enroll,    the owner's pages: approve a join, enrol a passkey, make or revoke MCP tokens;
         /tokens              POST /a/<id>/begin|finish, /enroll/begin|finish, /tokens/begin|finish from them
    GET  /join/<id>           the join script, for the machine that joins
    POST /join/<id>/login     that machine hands over its pending login
    GET  /healthz

It keeps no state and has no rights: it reads its config and relays every call to the private half
(helper.py) over a Unix socket. It does not count connections: memory is what runs out, so when
memory is short (Memory) new requests get 429, and the units cap its memory and make the kernel
kill it before Headscale. tn agent puts it behind a Cloudflare tunnel: it listens on loopback only,
in plain HTTP, and cloudflared on the same host brings the requests (with TLS at Cloudflare's edge).
Given a certificate in its config, it serves HTTPS itself instead.

    python3 -I agentd.pyz web --config /etc/tn-agent/config.json
    python3 -I agentd.pyz helper --config /etc/tn-agent/config.json
"""

import argparse
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import VERSION, pages
from .helper import HelperClient

MAX_BODY = 64 * 1024
RETRY_AFTER = 5
OWN_SHARE = 0.8             # 429 once this service uses this share of its memory limit
HOST_FREE = 0.10            # 429 once the host has less than this share of its memory available
ID = r"[A-Za-z0-9_-]{8,64}"


class Memory:
    """Whether memory is short: this service close to its own limit (its cgroup's memory.high or
    memory.max), or the whole host with less than HOST_FREE of its memory available. Then new
    requests get 429, so tn-agent backs off before the kernel has to choose what to kill; if it
    must, the units make tn-agent go first and Headscale stay. Read at most once a second."""

    def __init__(self, proc="/proc", cgroups="/sys/fs/cgroup", clock=time.monotonic):
        self.proc, self.cgroups, self.clock = proc, cgroups, clock
        self.checked, self.answer = None, False
        self.lock = threading.Lock()

    def _read(self, path):
        with open(path) as f:
            return f.read()

    def _host_short(self):
        info = {}
        for line in self._read(os.path.join(self.proc, "meminfo")).splitlines():
            key, _, rest = line.partition(":")
            if rest.split():
                info[key] = int(rest.split()[0])
        return info["MemAvailable"] < HOST_FREE * info["MemTotal"]

    def _own_short(self):
        line = next(x for x in self._read(os.path.join(self.proc, "self", "cgroup")).splitlines()
                    if x.startswith("0::"))
        here = os.path.join(self.cgroups, line[3:].lstrip("/"))
        current = int(self._read(os.path.join(here, "memory.current")))
        limits = []
        for name in ("memory.high", "memory.max"):
            try:
                value = self._read(os.path.join(here, name)).strip()
            except OSError:
                continue
            if value.isdigit():
                limits.append(int(value))
        return bool(limits) and current > OWN_SHARE * min(limits)

    def short(self):
        with self.lock:
            now = self.clock()
            if self.checked is not None and now - self.checked < 1:
                return self.answer
            answer = False
            for check in (self._host_short, self._own_short):
                try:
                    answer = answer or check()
                except (OSError, ValueError, KeyError, StopIteration):
                    pass                  # not Linux, or no cgroup v2: never short
            self.checked, self.answer = now, answer
            return answer


class Handler(BaseHTTPRequestHandler):
    server_version = "tn-agent"
    sys_version = ""
    timeout = 20

    def setup(self):
        super().setup()
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    @property
    def config(self):
        return self.server.config

    def client_ip(self):
        """Where the request came from. Behind the Cloudflare tunnel every request arrives from cloudflared on
        loopback, which names the real client in CF-Connecting-IP; nothing else reaches the loopback port."""
        if self.config.get("proxy") == "cloudflare":
            try:
                return str(ipaddress.ip_address((self.headers.get("CF-Connecting-IP") or "").strip()))
            except ValueError:
                return "unknown"
        return self.client_address[0]

    def _ask(self, op, **fields):
        try:
            return self.server.helper(op, **fields)
        except (OSError, ValueError):
            return {"ok": False, "code": 503, "error": "the approval service is not answering"}

    # --- replies ----------------------------------------------------------------------

    def _send(self, code, body, kind, headers=()):
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _html(self, code, text):
        self._send(code, text.encode(), "text/html; charset=utf-8",
                   [("Content-Security-Policy", pages.CSP), ("X-Frame-Options", "DENY")])

    def _json(self, code, value, headers=()):
        self._send(code, pages.json_body(value), "application/json", headers)

    def _relay(self, reply):
        if reply["ok"]:
            return self._json(200, reply["result"])
        return self._json(reply.get("code", 400), {"error": reply.get("error", "refused")})

    def _body(self):
        """The JSON body, or None when it is missing, too large or not JSON."""
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if not 0 < size <= MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(size))
        except ValueError:
            return None

    # --- GET --------------------------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            reply = self._ask("health")
            if not reply["ok"]:
                return self._send(503, b"tn-agent: the approval service is not answering\n", "text/plain")
            return self._send(200, f"ok tn-agent {VERSION} {self.config['region']}\n".encode(), "text/plain")
        if path == "/static/app.js":
            return self._send(200, pages.SCRIPT.encode(), "text/javascript; charset=utf-8")
        if path == "/enroll":
            return self._html(200, pages.enrolment(self.config))
        if path == "/tokens":
            return self._html(200, pages.tokens(self.config))
        m = re.fullmatch(f"/a/({ID})", path)
        if m:
            reply = self._ask("view", id=m.group(1))
            if not reply["ok"]:
                return self._html(reply.get("code", 404), pages.message("找不到这个请求", reply.get("error", "")))
            return self._html(200, pages.approval(reply["result"], self.config))
        m = re.fullmatch(f"/join/({ID})", path)
        if m:
            reply = self._ask("script", id=m.group(1))
            if not reply["ok"]:
                return self._send(404, b"echo 'tn: this join link expired; ask for a new one' >&2; exit 1\n",
                                  "text/plain")
            return self._send(200, reply["result"].encode(), "text/x-shellscript; charset=utf-8")
        if path == "/mcp":
            return self._send(405, b"POST JSON-RPC messages here\n", "text/plain", [("Allow", "POST")])
        return self._send(404, b"not found\n", "text/plain")

    # --- POST -------------------------------------------------------------------------

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/mcp":
            return self._mcp()
        m = re.fullmatch(f"/join/({ID})/login", path)
        if m:
            body = self._body()
            if not isinstance(body, dict):
                return self._json(400, {"error": "expected a JSON object of at most 64 KiB"})
            return self._relay(self._ask("login", id=m.group(1), answer=body, ip=self.client_ip()))
        page = re.fullmatch(f"/a/({ID})/(begin|finish)", path)
        enrol = re.fullmatch("/enroll/(begin|finish)", path)
        tokens = re.fullmatch("/tokens/(begin|finish)", path)
        if not (page or enrol or tokens):
            return self._json(404, {"error": "not found"})
        if self.headers.get("Origin") != self.config["origin"]:
            return self._json(403, {"error": "requests come only from this service's own pages"})
        body = self._body()
        if not isinstance(body, dict):
            return self._json(400, {"error": "expected a JSON object of at most 64 KiB"})
        if page:
            rid, step = page.groups()
            if step == "begin":
                return self._relay(self._ask("begin", id=rid, decision=body.get("decision")))
            return self._relay(self._ask("finish", id=rid, decision=body.get("decision"), answer=body))
        if tokens:
            if tokens.group(1) == "begin":
                return self._relay(self._ask("tokens_begin", action=body.get("action"), subject=body.get("subject")))
            return self._relay(self._ask("tokens_finish", action=body.get("action"), subject=body.get("subject"),
                                         answer=body))
        if enrol.group(1) == "begin":
            return self._relay(self._ask("enroll_begin", code=body.get("code")))
        return self._relay(self._ask("enroll_finish", code=body.get("code"), answer=body))

    def _mcp(self):
        origin = self.headers.get("Origin")
        if origin and origin != self.config["origin"]:
            return self._json(403, {"error": "cross-origin MCP requests are refused"})
        words = (self.headers.get("Authorization") or "").split()
        token = words[1] if len(words) == 2 and words[0].lower() == "bearer" else ""
        message = self._body()
        if message is None:
            return self._json(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": "a JSON body of at most 64 KiB is expected"}})
        reply = self._ask("mcp", token=token, who=f"MCP from {self.client_ip()}", message=message)
        if not reply["ok"]:
            if reply.get("code") == 401:
                time.sleep(0.5)
                return self._json(401, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32001, "message": reply["error"]}},
                                  [("WWW-Authenticate", 'Bearer realm="tn-agent"')])
            return self._json(reply.get("code", 503), {"jsonrpc": "2.0", "id": None,
                                                       "error": {"code": -32603, "message": reply.get("error")}})
        if reply["result"] is None:
            return self._send(202, b"", "application/json")
        return self._json(200, reply["result"])


class BusyHandler(Handler):
    """Memory is short: answer 429 and close, without asking the private half anything."""

    timeout = RETRY_AFTER

    def _busy(self):
        headers = [("Retry-After", str(RETRY_AFTER))]
        if urlsplit(self.path).path == "/mcp":
            return self._json(429, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32000, "message": "tn-agent is busy; try again shortly"}},
                              headers)
        return self._send(429, b"tn-agent is busy; try again shortly\n", "text/plain", headers)

    def do_GET(self):
        self._busy()

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            size = 0
        if 0 < size <= MAX_BODY:
            self.rfile.read(size)          # read it, so the client gets the answer rather than a reset
        self._busy()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, config, helper, cert=None, key=None):
        super().__init__(address, Handler)
        self.config = config
        self.helper = helper
        self.memory = Memory()
        self.tls = None
        if cert:
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self.tls.load_cert_chain(cert, key)

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls:
            sock = self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def finish_request(self, request, client_address):
        (BusyHandler if self.memory.short() else self.RequestHandlerClass)(request, client_address, self)

    def handle_error(self, request, client_address):
        sys.stderr.write(f"{client_address[0]} connection error: {sys.exc_info()[1]}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tn-agent")
    ap.add_argument("role", choices=("web", "helper"), help="web: the public HTTPS half; helper: the private half")
    ap.add_argument("--config", default="/etc/tn-agent/config.json")
    args = ap.parse_args(argv)
    with open(args.config) as f:
        config = json.load(f)
    if args.role == "helper":
        from .helper import serve
        sys.stderr.write(f"tn-agent {VERSION} helper: tailnet {config['region']} on {config['socket']}\n")
        serve(config)
        return
    # Behind the tunnel, cloudflared talks to this half on loopback: plain HTTP, no certificate here.
    server = Server((config["listen"], config["port"]), config, HelperClient(config["socket"]),
                    config.get("cert"), config.get("key"))
    sys.stderr.write(f"tn-agent {VERSION}: tailnet {config['region']} on {config['origin']}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
