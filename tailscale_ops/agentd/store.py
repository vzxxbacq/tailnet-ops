"""What the service keeps. Under the state directory, written by the service: passkeys, requests,
used enrolment codes, the MCP tokens made on the token page (their sha256) and an audit log. Under the config directory, written by `tn agent` as root
and only read here: the MCP token hashes and the current enrolment code's hash.

Each JSON file is written whole (temp file, then rename), mode 0600; one lock serialises changes.
"""

import json
import os
import threading
import time

KEEP_SECONDS = 30 * 86400   # finished requests are dropped after this


class Store:
    def __init__(self, state_dir, etc_dir, clock=time.time):
        self.state_dir = state_dir
        self.etc_dir = etc_dir
        self.clock = clock
        self.lock = threading.RLock()

    def _read(self, path, default):
        try:
            with open(path) as f:
                return json.load(f)
        except FileNotFoundError:
            return default

    def _write(self, name, value):
        path = os.path.join(self.state_dir, name)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)

    # --- passkeys -------------------------------------------------------------------

    def credentials(self):
        return self._read(os.path.join(self.state_dir, "passkeys.json"), [])

    def add_credential(self, cred):
        with self.lock:
            creds = [c for c in self.credentials() if c["id"] != cred["id"]]
            self._write("passkeys.json", creds + [cred])

    def set_sign_count(self, cred_id, count):
        with self.lock:
            creds = self.credentials()
            for c in creds:
                if c["id"] == cred_id:
                    c["sign_count"] = count
                    c["last_used"] = int(self.clock())
            self._write("passkeys.json", creds)

    # --- requests -------------------------------------------------------------------

    def requests(self):
        return self._read(os.path.join(self.state_dir, "requests.json"), {})

    def request(self, rid):
        return self.requests().get(rid)

    def save_request(self, req):
        with self.lock:
            reqs = self.requests()
            now = self.clock()
            reqs = {k: v for k, v in reqs.items() if v.get("status") == "pending" or now - v["created"] < KEEP_SECONDS}
            reqs[req["id"]] = req
            self._write("requests.json", reqs)

    # --- enrolment codes and tokens, from tn agent ------------------------------------

    def enrolment(self):
        """{code_sha256, expires} of the code `tn agent enroll` made last, or None."""
        return self._read(os.path.join(self.etc_dir, "enroll.json"), None)

    def used_codes(self):
        return self._read(os.path.join(self.state_dir, "used-codes.json"), [])

    def use_code(self, code_sha256):
        with self.lock:
            self._write("used-codes.json", self.used_codes()[-50:] + [code_sha256])

    def token_hashes(self):
        """The sha256 of each MCP token `tn agent token` made: one hex digest per line."""
        try:
            with open(os.path.join(self.etc_dir, "tokens")) as f:
                return {w for line in f for w in line.split()[:1] if len(w) == 64}
        except FileNotFoundError:
            return set()

    def web_tokens(self):
        """MCP tokens made on the token page, with a passkey: [{id, label, sha256, created, last_used}]."""
        return self._read(os.path.join(self.state_dir, "tokens.json"), [])

    def save_web_tokens(self, tokens):
        with self.lock:
            self._write("tokens.json", tokens)

    # --- audit ----------------------------------------------------------------------

    def audit(self, event, **fields):
        line = json.dumps({"at": int(self.clock()), "event": event, **fields}, sort_keys=True)
        with self.lock:
            fd = os.open(os.path.join(self.state_dir, "audit.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(line + "\n")
