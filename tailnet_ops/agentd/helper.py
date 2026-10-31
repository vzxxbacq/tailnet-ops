"""The private half of tn-agent (user tn-agent, group headscale, no network).

It keeps the passkeys and the requests, checks every token and every passkey signature, and runs the
headscale commands. It listens only on a Unix socket that the public half (server.py) can reach. The
public half only relays: nothing it sends changes the tailnet without a signature checked here.

Each connection carries one JSON line, {"op": ..., ...}, and gets one back: {"ok": true, "result": ...}
or {"ok": false, "code": <HTTP status>, "error": ...}.
"""

import json
import os
import pkgutil
import socket
import socketserver
import stat

from . import mcp
from .app import App, Refused
from .headscale import Headscale, HeadscaleError
from .store import Store

MAX_MESSAGE = 256 * 1024


def _ok(result):
    return {"ok": True, "result": result}


def _error(code, message):
    return {"ok": False, "code": code, "error": message}


def dispatch(app, msg):
    if not isinstance(msg, dict):
        return _error(400, "expected a JSON object")
    op = msg.get("op")
    try:
        if op == "health":
            return _ok({"region": app.region})
        if op == "mcp":
            return _mcp(app, msg)
        if op == "view":
            return _ok(app.view(msg.get("id")))
        if op == "begin":
            return _ok(app.begin(msg.get("id"), msg.get("decision")))
        if op == "finish":
            return _ok(app.finish(msg.get("id"), msg.get("decision"), msg.get("answer")))
        if op == "enroll_begin":
            return _ok(app.enroll_begin(msg.get("code")))
        if op == "enroll_finish":
            return _ok(app.enroll_finish(msg.get("code"), msg.get("answer")))
        if op == "script":
            return _ok(app.script(msg.get("id")))
        if op == "login":
            return _ok(app.login(msg.get("id"), msg.get("answer"), msg.get("ip")))
        if op == "tokens_begin":
            return _ok(app.tokens_begin(msg.get("action"), msg.get("subject")))
        if op == "tokens_finish":
            return _ok(app.tokens_finish(msg.get("action"), msg.get("subject"), msg.get("answer")))
    except Refused as e:
        return _error(400, str(e))
    except HeadscaleError as e:
        return _error(502, f"Headscale failed: {e}")
    return _error(404, f"no operation {op!r}")


def _mcp(app, msg):
    if not app.authorised(msg.get("token")):
        return _error(401, "a valid bearer token is needed")
    who = str(msg.get("who") or "an Agent")
    message = msg.get("message")
    replies = []
    for m in message if isinstance(message, list) else [message]:
        reply = mcp.handle(app, m, who)
        if isinstance(m, dict) and m.get("method") == "tools/call" and reply:
            params = m.get("params") if isinstance(m.get("params"), dict) else {}
            app.store.audit("tool", tool=params.get("name"), who=who,
                            error=bool((reply.get("result") or {}).get("isError")))
        if reply is not None:
            replies.append(reply)
    if isinstance(message, list):
        return _ok(replies or None)
    return _ok(replies[0] if replies else None)


class _Handler(socketserver.StreamRequestHandler):
    timeout = 180

    def handle(self):
        line = self.rfile.readline(MAX_MESSAGE + 1)
        if len(line) > MAX_MESSAGE:
            reply = _error(413, "message too large")
        else:
            try:
                reply = dispatch(self.server.app, json.loads(line))
            except ValueError:
                reply = _error(400, "not JSON")
        self.wfile.write(json.dumps(reply, ensure_ascii=False).encode() + b"\n")


class HelperServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, app):
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                os.unlink(path)          # left over from the last run
        except FileNotFoundError:
            pass
        super().__init__(path, _Handler)
        os.chmod(path, 0o660)            # the public half reaches it through group tn-agent
        self.app = app


class HelperClient:
    """What the public half calls: helper("op", field=...) -> the reply dict."""

    def __init__(self, path, timeout=180):
        self.path = path
        self.timeout = timeout

    def __call__(self, op, **fields):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect(self.path)
            s.sendall(json.dumps({"op": op, **fields}).encode() + b"\n")
            with s.makefile("rb") as f:
                line = f.readline(2 * MAX_MESSAGE)
        return json.loads(line)


def _read_optional(path):
    """A script tn agent installed, or "" (one from before that version had none)."""
    if not path:
        return ""
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def app_from(config):
    with open(config["join_template"]) as f:
        template = f.read()
    leave, resume = (_read_optional(config.get(key)) for key in ("leave_template", "resume_template"))
    try:
        guide = (pkgutil.get_data(__package__, "guide.md") or b"").decode()
    except OSError:
        guide = ""
    store = Store(config["state"], config["etc"])
    return App(config, store, Headscale(config["headscale"], config["headscale_config"]), template, guide,
               leave_template=leave, resume_template=resume)


def serve(config):
    server = HelperServer(config["socket"], app_from(config))
    server.serve_forever()
