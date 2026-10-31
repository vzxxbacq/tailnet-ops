"""The service's logic without HTTP: what the MCP tools, the approval pages and joining machines ask.

A join goes in three steps, and the Agent never carries the login:
1. The Agent asks for a join command (join_script) for a name; it gets a one-time script id.
2. The machine runs it. The script hands its pending Headscale login to the service itself, from
   the machine (POST /join/<script id>/login); the service notes the address it came from, with the
   host name and OS the machine reports. That makes a request.
3. The owner opens the request's page and signs a challenge with an enrolled passkey. The challenge
   is a hash of the request's digest, the decision and a one-time nonce, so a signature approves
   exactly this request, once. Only then does the service run headscale.
"""

import hashlib
import hmac
import json
import os
import re
import threading
import time

from . import webauthn
from .headscale import HeadscaleError

NAME_RE = re.compile(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
AUTH_ID = r"hskey-authreq-[A-Za-z0-9_-]{24}"
REQUEST_SECONDS = 14 * 60      # Headscale keeps a pending login for 15 minutes
CHALLENGE_SECONDS = 3 * 60
SCRIPT_SECONDS = 30 * 60
WAIT_SECONDS = 50              # the longest request_status waits for the owner: well inside Cloudflare's 100 s
MAX_PENDING = 10               # requests waiting for the owner
MAX_SCRIPTS = 20               # join commands not run yet
MAX_TOKENS = 20                # MCP tokens made on the token page
TOUCH_SECONDS = 600            # how often a token's last use is written down
REASON_CHARS = 300
TOKEN_ID = re.compile(r"^[A-Za-z0-9_-]{4,16}$")


class Refused(Exception):
    """A request the service turns down; the message says why, to the Agent, the machine or the page."""


def sha256_hex(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def _iso(seconds):
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(seconds)))
    except (TypeError, ValueError):
        return None


def _plain(text, limit):
    """One line of printable text, at most limit characters."""
    return "".join(c if c.isprintable() else " " for c in str(text or "")).strip()[:limit]


def _addresses(node):
    ips = node.get("ip_addresses") or []
    return (next((ip for ip in ips if "." in ip), None), next((ip for ip in ips if ":" in ip), None))


class App:
    """config: the dict tn agent writes (region, origin, rp_id, login_server, owner, tags).
    template: the join script, with __TN_NAME__, __TN_TAGS__ and __TN_SCRIPT__ to fill in."""

    def __init__(self, config, store, headscale, template, guide="", clock=time.time, random=os.urandom,
                 leave_template="", resume_template=""):
        self.config = config
        self.store = store
        self.hs = headscale
        self.template = template
        self.leave_template = leave_template
        self.resume_template = resume_template
        self.guide = guide
        self.clock = clock
        self.random = random
        self.lock = threading.Lock()
        self.decided = threading.Condition()   # notified when the owner decides a request
        self.scripts = {}       # script id -> {name, tags, reason, who, text, expires, request}
        self.enrolments = {}    # sha256 of an enrolment code -> (challenge, expires)
        self.token_challenges = {}   # challenge (base64url) -> (action, subject, expires)

    @property
    def region(self):
        return self.config["region"]

    @property
    def origin(self):
        return self.config["origin"]

    @property
    def tags(self):
        return sorted(self.config["tags"])

    def authorised(self, token):
        """True for a bearer token that `tn agent token` or the token page made (the host keeps only sha256s)."""
        if not isinstance(token, str) or not token:
            return False
        digest = sha256_hex(token)
        if any(hmac.compare_digest(digest, h) for h in self.store.token_hashes()):
            return True
        with self.store.lock:
            tokens = self.store.web_tokens()
            for entry in tokens:
                if hmac.compare_digest(digest, entry.get("sha256", "")):
                    now = int(self.clock())
                    if now - (entry.get("last_used") or 0) >= TOUCH_SECONDS:
                        entry["last_used"] = now
                        self.store.save_web_tokens(tokens)
                    return True
        return False

    # --- checks -----------------------------------------------------------------------

    def _name(self, name, nodes=None):
        name = str(name or "").strip().lower()
        if not NAME_RE.match(name):
            raise Refused(f"{name!r} is not a name: a-z, 0-9 and '-', starting with a letter, at most 63 characters")
        for n in self.hs.nodes() if nodes is None else nodes:
            if n.get("given_name") == name:
                raise Refused(f"{name} is already a node of tailnet {self.region} (id {n.get('id')}); pick another name")
        return name

    def _auth_id(self, auth):
        text = str(auth or "").strip()
        m = re.fullmatch(re.escape(self.config["login_server"]) + "/register/(" + AUTH_ID + ")", text)
        if not m:
            raise Refused(f"auth_url must be a login link of {self.config['login_server']}")
        return m.group(1)

    def _live_scripts(self):
        now = self.clock()
        self.scripts = {k: v for k, v in self.scripts.items()
                        if v["expires"] > now or (v["request"] and v["expires"] > now - 86400)}
        return {k: v for k, v in self.scripts.items()
                if v["expires"] > now and not v["request"] and not v.get("downloaded")}

    # --- MCP: read --------------------------------------------------------------------

    def nodes(self):
        out = []
        for n in self.hs.nodes():
            ipv4, ipv6 = _addresses(n)
            tags = sorted(n.get("tags") or [])
            out.append({
                "id": n.get("id"),
                "name": n.get("given_name") or n.get("name"),
                "hostname": n.get("name"),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "tags": tags,
                "owner": None if tags else (n.get("user") or {}).get("name"),
                "online": bool(n.get("online")),
                "last_seen": _iso((n.get("last_seen") or {}).get("seconds")),
            })
        return {"region": self.region, "login_server": self.config["login_server"],
                "nodes": sorted(out, key=lambda x: x["name"] or "")}

    # --- joins ------------------------------------------------------------------------

    def join_script(self, name, reason, who="an Agent"):
        reason = _plain(reason, REASON_CHARS)
        if not reason:
            raise Refused("reason is one line for the owner: what the machine is and why it joins")
        name = self._name(name)
        with self.lock:
            live = self._live_scripts()
            # One join command per name: a new one replaces one that was not run (the Agent may have lost it).
            replaced = [k for k, s in live.items() if s.get("kind", "join") == "join" and s["name"] == name]
            for k in replaced:
                del self.scripts[k]
            if len(live) - len(replaced) >= MAX_SCRIPTS:
                raise Refused(f"{MAX_SCRIPTS} commands are out and not run yet; wait for them to expire")
            sid = webauthn.b64url(self.random(18))
            text = (self.template.replace("__TN_NAME__", name).replace("__TN_TAGS__", ",".join(self.tags))
                    .replace("__TN_SCRIPT__", sid))
            self.scripts[sid] = {"kind": "join", "name": name, "tags": self.tags, "reason": reason,
                                 "who": _plain(who, 80), "text": text, "expires": self.clock() + SCRIPT_SECONDS,
                                 "request": None}
        url = f"{self.origin}/join/{sid}"
        digest = sha256_hex(text)
        command = (f"f=$(mktemp) && curl -fsS --max-time 60 -o \"$f\" '{url}' && "
                   f"echo \"{digest}  $f\" | sha256sum -c - && sudo bash \"$f\"; rm -f \"$f\"")
        self.store.audit("script", script=sid, name=name, who=_plain(who, 80), replaced=replaced)
        user_mode = (f"f=$(mktemp) && curl -fsS --max-time 60 -o \"$f\" '{url}' && "
                     f"echo \"{digest}  $f\" | sha256sum -c - && TN_MODE=user bash \"$f\"; rm -f \"$f\"")
        return {
            "script_id": sid, "region": self.region, "name": name, "tags": self.tags, "command": command,
            "command_without_root": user_mode, "sha256": digest, "expires_in_minutes": SCRIPT_SECONDS // 60,
            "next": (f"The earlier join command for {name} no longer works. " if replaced else "") +
                    "Run `command` once on the machine over SSH (drop `sudo` when you are root). Without root or "
                    "systemd (a container, a sandbox), run `command_without_root` instead: the same pinned "
                    "Tailscale runs as the user, in userspace networking, and other programs reach the tailnet "
                    "through the SOCKS5/HTTP proxy it prints (TN-PROXY). Either way the script hands its login "
                    "to the service itself and prints TN-APPROVAL-URL. Send that link to the owner, then wait "
                    f"for their decision with request_status (this script_id, wait_seconds {WAIT_SECONDS}).",
        }

    def script(self, sid):
        """The script behind a command. A join script can be fetched again until the machine hands over its
        login; a leave or resume script once, since nothing else tells when it ran."""
        with self.lock:
            entry = self._live_scripts().get(str(sid or ""))
            if entry is None:
                raise Refused("this link is not valid (any more); ask the Agent for a new command")
            if entry.get("kind", "join") != "join":
                entry["downloaded"] = int(self.clock())
        return entry["text"]

    def login(self, sid, answer, ip):
        """The machine hands over its pending login: that makes the request the owner decides."""
        if not isinstance(answer, dict):
            raise Refused("expected a JSON object")
        auth_id = self._auth_id(answer.get("auth_url"))
        with self.store.lock:
            with self.lock:
                entry = self._live_scripts().get(str(sid or ""))
                if entry is None or entry.get("kind", "join") != "join":
                    raise Refused("this join command was used or has expired; ask the Agent for a new one")
                pending = [r for r in self.store.requests().values() if self._live(r)]
                if len(pending) >= MAX_PENDING:
                    raise Refused(f"{MAX_PENDING} requests are waiting for the owner; try again later")
                now = int(self.clock())
                req = {
                    "id": webauthn.b64url(self.random(12)), "kind": "join", "region": self.region,
                    "name": entry["name"], "tags": entry["tags"], "auth_id": auth_id, "reason": entry["reason"],
                    "who": entry["who"], "script": sid, "created": now, "expires": now + REQUEST_SECONDS,
                    "machine": {"ip": _plain(ip, 45), "hostname": _plain(answer.get("hostname"), 80),
                                "os": _plain(answer.get("os"), 80), "arch": _plain(answer.get("arch"), 20)},
                    "status": "pending",
                }
                req["digest"] = self._digest(req)
                entry["request"] = req["id"]
            self.store.save_request(req)
        self.store.audit("requested", request=req["id"], script=sid, name=req["name"], machine=req["machine"])
        return {"request_id": req["id"], "approval_url": self.approval_url(req), "status": "pending"}

    def request_leave(self, name, reason, who="an Agent"):
        """Ask the owner to take a machine out. Only machines tn-agent joined (the agent tag) can leave this way;
        the owner's servers and devices cannot even be asked about through MCP."""
        reason = _plain(reason, REASON_CHARS)
        if not reason:
            raise Refused("reason is one line for the owner: why the machine leaves")
        name = str(name or "").strip().lower()
        node = next((n for n in self.hs.nodes() if n.get("given_name") == name), None)
        if node is None:
            raise Refused(f"no node named {name!r} in tailnet {self.region}")
        if not set(self.tags) & set(node.get("tags") or []):
            raise Refused(f"{name} did not join through tn-agent (no {', '.join(self.tags)}); only the owner can "
                          "take it out")
        ipv4, _ipv6 = _addresses(node)
        with self.store.lock:
            pending = [r for r in self.store.requests().values() if self._live(r)]
            for r in pending:
                if r.get("kind") == "leave" and r["name"] == name:
                    return self._public(r)
            if len(pending) >= MAX_PENDING:
                raise Refused(f"{MAX_PENDING} requests are waiting for the owner; try again later")
            now = int(self.clock())
            req = {
                "id": webauthn.b64url(self.random(12)), "kind": "leave", "region": self.region, "name": name,
                "node": {"id": node.get("id"), "ipv4": ipv4, "online": bool(node.get("online")),
                         "last_seen": _iso((node.get("last_seen") or {}).get("seconds"))},
                "tags": sorted(node.get("tags") or []), "reason": reason, "who": _plain(who, 80),
                "created": now, "expires": now + REQUEST_SECONDS, "status": "pending",
            }
            req["digest"] = self._digest(req)
            self.store.save_request(req)
        self.store.audit("leave_requested", request=req["id"], name=name, node=req["node"]["id"], who=req["who"])
        return self._public(req)

    def leave_script(self, name):
        """A one-time command that takes Tailscale off a machine: what tn installed, nothing else. It needs no
        approval: whoever runs it controls that machine already. It does not remove the node: request_leave does."""
        return self._command("leave", name, self.leave_template,
                             "Run `command` on the machine over SSH, as the user the join ran as (as root: drop "
                             "`sudo` when you are root). It logs Tailscale out, stops tailscaled and removes what "
                             "tn installed for it; anything else stays.")

    def resume_script(self, name):
        """A one-time command that starts Tailscale again on a machine that joined through tn-agent, after a
        restart: from the machine's own key, so no approval. Where the key is gone, it says to join again."""
        name = str(name or "").strip().lower()
        node = next((n for n in self.hs.nodes() if n.get("given_name") == name), None)
        if node is None or not set(self.tags) & set(node.get("tags") or []):
            raise Refused(f"{name!r} is not a machine that joined tailnet {self.region} through tn-agent")
        return self._command("resume", name, self.resume_template,
                             "Run `command` on the machine over SSH, as the user the join ran as. It starts "
                             "tailscaled from the machine's own key and prints TN-JOINED <address> (and TN-PROXY "
                             "in user mode). If it says to join again, the key is gone: use join_script.")

    def _command(self, kind, name, template, next_step):
        name = str(name or "").strip().lower()
        if not NAME_RE.match(name):
            raise Refused(f"{name!r} is not a name")
        if not template:
            raise Refused(f"this tn-agent has no {kind} script; the owner updates it with tn agent apply")
        with self.lock:
            live = self._live_scripts()
            if len(live) >= MAX_SCRIPTS:
                raise Refused(f"{MAX_SCRIPTS} commands are out and not run yet; wait for them to expire")
            sid = webauthn.b64url(self.random(18))
            text = template.replace("__TN_NAME__", name)
            self.scripts[sid] = {"kind": kind, "name": name, "tags": self.tags, "reason": "", "who": "",
                                 "text": text, "expires": self.clock() + SCRIPT_SECONDS, "request": None}
        url = f"{self.origin}/join/{sid}"
        digest = sha256_hex(text)
        fetch = f"f=$(mktemp) && curl -fsS --max-time 60 -o \"$f\" '{url}' && echo \"{digest}  $f\" | sha256sum -c - && "
        return {"name": name, "command": fetch + "sudo bash \"$f\"; rm -f \"$f\"",
                "command_without_root": fetch + "TN_MODE=user bash \"$f\"; rm -f \"$f\"",
                "sha256": digest, "expires_in_minutes": SCRIPT_SECONDS // 60,
                "next": next_step + " Use command_without_root where the join ran without root."}

    def status(self, rid, wait=0):
        """A request by its id, or by the script id of the command that made it. With wait (seconds, at most
        WAIT_SECONDS), a request that waits for the owner is answered as soon as they decide."""
        try:
            wait = max(0.0, min(float(wait or 0), WAIT_SECONDS))
        except (TypeError, ValueError):
            raise Refused("wait_seconds is a number of seconds")
        deadline = time.monotonic() + wait
        while True:
            out = self._status(rid)
            left = deadline - time.monotonic()
            if out["status"] not in ("pending", "approved") or left <= 0:
                return out
            with self.decided:
                self.decided.wait(min(left, 5))   # woken by a decision; looks again every 5 s regardless

    def _decided(self):
        with self.decided:
            self.decided.notify_all()

    def _status(self, rid):
        rid = str(rid or "")
        with self.lock:
            entry = self.scripts.get(rid)
        if entry is not None:
            kind = entry.get("kind", "join")
            if entry["request"] is None:
                if entry.get("downloaded"):
                    return {"script_id": rid, "kind": kind, "status": "downloaded", "name": entry["name"],
                            "next": f"The machine fetched the {kind} script; its own output says how it went "
                                    f"(the last line is {'TN-LEFT' if kind == 'leave' else 'TN-JOINED'} when it worked)."}
                if entry["expires"] <= self.clock():
                    raise Refused(f"that {kind} command expired before the machine ran it")
                return {"script_id": rid, "kind": kind, "status": "waiting_for_machine", "name": entry["name"],
                        "next": f"Run the {kind} command on the machine" +
                                ("; it prints TN-APPROVAL-URL." if kind == "join" else ".")}
            rid = entry["request"]
        return self._public(self._request(rid))

    # --- requests ---------------------------------------------------------------------

    DIGEST_KEYS = {
        "join": ("id", "kind", "region", "name", "tags", "auth_id", "reason", "who", "script", "machine",
                 "created", "expires"),
        "leave": ("id", "kind", "region", "name", "node", "tags", "reason", "who", "created", "expires"),
    }

    @classmethod
    def _digest(cls, req):
        return sha256_hex(json.dumps({k: req[k] for k in cls.DIGEST_KEYS[req.get("kind", "join")]}, sort_keys=True))

    def _live(self, req):
        return req.get("status") == "pending" and req["expires"] > self.clock()

    def _request(self, rid):
        with self.store.lock:
            req = self.store.request(str(rid or ""))
            if req is None:
                raise Refused("no such request")
            if req["status"] == "pending" and not self._live(req):
                req["status"] = "expired"
                req.pop("challenge", None)
                self.store.save_request(req)
            return req

    def approval_url(self, req):
        return f"{self.origin}/a/{req['id']}"

    def _public(self, req):
        out = {"request_id": req["id"], "status": req["status"], "region": req["region"], "name": req["name"],
               "tags": req["tags"], "approval_url": self.approval_url(req), "expires_at": _iso(req["expires"])}
        if req.get("result"):
            out["result"] = req["result"]
        if req.get("error"):
            out["error"] = req["error"]
        out["kind"] = req.get("kind", "join")
        leave = out["kind"] == "leave"
        out["next"] = {
            "pending": "Send approval_url to the owner as a plain link and ask them to approve it with their "
                       "passkey. Do not say it is approved. Then, in the same turn, call request_status with "
                       f"wait_seconds {WAIT_SECONDS}, again while it says pending: it answers the moment the owner "
                       "decides, so you can tell them how it went without being asked.",
            "done": ("The machine is out of the tailnet. Tell the owner. To remove Tailscale from it, run the "
                     "leave_script command on it." if leave else
                     "The machine is in the tailnet at the address in result. Tell the owner. In user mode, other "
                     "programs on it reach the tailnet through the proxy the script printed (TN-PROXY)."),
            "denied": "The owner denied it. Do not retry unless the owner asks.",
            "expired": ("Nobody approved it in time. Ask the owner before asking again." if leave else
                        "Nobody approved it in time. Ask the owner before trying again with a new join command."),
            "failed": "It was approved but Headscale refused it; tell the owner the error.",
            "approved": ("Approved; the service is removing it now." if leave else
                         "Approved; the service is joining it now.") + " Check again in a few seconds.",
        }[req["status"]]
        return out

    # --- approval pages ---------------------------------------------------------------

    def view(self, rid):
        req = dict(self._request(rid))
        req.pop("challenge", None)
        return req

    def _challenge(self, req, decision, nonce):
        text = json.dumps({"request": req["id"], "digest": req["digest"], "decision": decision, "nonce": nonce},
                          sort_keys=True)
        return hashlib.sha256(text.encode()).digest()

    def begin(self, rid, decision):
        if decision not in ("approve", "deny"):
            raise Refused("decision is approve or deny")
        creds = self.store.credentials()
        if not creds:
            raise Refused("no passkey is enrolled here: run `tn agent enroll` first")
        with self.store.lock:
            req = self._request(rid)
            if req["status"] != "pending":
                raise Refused(f"this request is {req['status']}")
            nonce = self.random(16).hex()
            req["challenge"] = {"decision": decision, "nonce": nonce, "expires": int(self.clock()) + CHALLENGE_SECONDS}
            self.store.save_request(req)
        return {"challenge": webauthn.b64url(self._challenge(req, decision, nonce)), "rpId": self.config["rp_id"],
                "allowCredentials": [c["id"] for c in creds], "timeout": 120000}

    def finish(self, rid, decision, answer):
        if not isinstance(answer, dict):
            raise Refused("expected a JSON object")
        with self.store.lock:
            req = self._request(rid)
            if req["status"] != "pending":
                raise Refused(f"this request is {req['status']}")
            challenge = req.pop("challenge", None)    # one try per challenge
            self.store.save_request(req)
            if not challenge or challenge["decision"] != decision or challenge["expires"] < self.clock():
                raise Refused("start again: the passkey prompt is for another decision or timed out")
            if self._digest(req) != req["digest"]:
                raise Refused("the request changed after it was made")
            cred = next((c for c in self.store.credentials() if c["id"] == answer.get("id")), None)
            if cred is None:
                raise Refused("that passkey is not enrolled here")
            try:
                count = webauthn.assertion(
                    cred, webauthn.unb64url(answer.get("clientDataJSON")),
                    webauthn.unb64url(answer.get("authenticatorData")), webauthn.unb64url(answer.get("signature")),
                    self._challenge(req, decision, challenge["nonce"]), self.origin, self.config["rp_id"])
            except webauthn.WebAuthnError as e:
                self.store.audit("passkey_refused", request=req["id"], credential=cred["id"], reason=str(e))
                raise Refused(f"the passkey check failed: {e}")
            self.store.set_sign_count(cred["id"], count)
            req.update(decided_by=cred["id"], decided_at=int(self.clock()))
            if decision == "deny":
                try:
                    if req.get("kind", "join") == "join":
                        self.hs.reject(req["auth_id"])
                except HeadscaleError:
                    pass                      # the login may have expired already
                req["status"] = "denied"
                self.store.save_request(req)
                self.store.audit("denied", request=req["id"], credential=cred["id"])
                self._decided()
                return self._public(req)
            req["status"] = "approved"
            self.store.save_request(req)
            self.store.audit("approved", request=req["id"], credential=cred["id"], digest=req["digest"])
            try:
                req["result"] = self._leave(req) if req.get("kind") == "leave" else self._join(req)
                req["status"] = "done"
            except HeadscaleError as e:
                req["status"], req["error"] = "failed", str(e)
            self.store.save_request(req)
            self.store.audit(req["status"], request=req["id"], **({"error": req["error"]} if req.get("error") else
                                                                    {"node": req["result"]}))
            self._decided()
            return self._public(req)

    def _leave(self, req):
        """Delete the node, if it is still the one approved: same id, name and the agent tag."""
        node = next((n for n in self.hs.nodes() if n.get("id") == req["node"]["id"]), None)
        if node is None:
            return {"node_id": req["node"]["id"], "name": req["name"], "removed": "already gone"}
        if node.get("given_name") != req["name"] or not set(self.tags) & set(node.get("tags") or []):
            raise HeadscaleError(f"node {req['node']['id']} is no longer {req['name']} with {', '.join(self.tags)}; "
                                 "nothing was removed")
        self.hs.delete(req["node"]["id"])
        return {"node_id": req["node"]["id"], "name": req["name"], "removed": "yes"}

    def _join(self, req):
        """Register the pending login, then hold the node to the approved name and tags."""
        node = self.hs.register(req["auth_id"], self.config["owner"]) or {}
        node_id = node.get("id")
        if node_id is None:
            raise HeadscaleError("headscale auth register returned no node")
        if node.get("given_name") != req["name"]:
            node = self.hs.rename(node_id, req["name"]) or node
        if sorted(node.get("tags") or []) != req["tags"]:
            node = self.hs.set_tags(node_id, req["tags"]) or node
        ipv4, ipv6 = _addresses(node)
        return {"node_id": node_id, "name": node.get("given_name"), "hostname": node.get("name"),
                "ipv4": ipv4, "ipv6": ipv6, "tags": sorted(node.get("tags") or [])}

    # --- the token page ---------------------------------------------------------------

    def _token_action(self, action, subject):
        if action == "create":
            return "create", _plain(subject, 40) or "agent"
        if action == "revoke":
            if not TOKEN_ID.match(str(subject or "")):
                raise Refused("no such token")
            return "revoke", subject
        if action == "list":
            return "list", ""
        raise Refused("action is create, revoke or list")

    def tokens(self):
        return [{"id": t["id"], "label": t["label"], "created": t["created"], "last_used": t.get("last_used")}
                for t in self.store.web_tokens()]

    def tokens_begin(self, action, subject):
        """A passkey challenge for one action on the tokens: bound to the action and its subject, used once."""
        action, subject = self._token_action(action, subject)
        creds = self.store.credentials()
        if not creds:
            raise Refused("no passkey is enrolled here: run `tn agent enroll` first")
        nonce = self.random(16).hex()
        text = json.dumps({"tokens": action, "subject": subject, "nonce": nonce}, sort_keys=True)
        challenge = webauthn.b64url(hashlib.sha256(text.encode()).digest())
        now = self.clock()
        with self.lock:
            self.token_challenges = {k: v for k, v in self.token_challenges.items() if v[2] > now}
            self.token_challenges[challenge] = (action, subject, now + CHALLENGE_SECONDS)
        return {"challenge": challenge, "rpId": self.config["rp_id"], "allowCredentials": [c["id"] for c in creds],
                "timeout": 120000}

    def tokens_finish(self, action, subject, answer):
        """Check the passkey's answer, then do the action: create gives the token, once."""
        if not isinstance(answer, dict):
            raise Refused("expected a JSON object")
        action, subject = self._token_action(action, subject)
        try:
            raw = webauthn.unb64url(answer.get("clientDataJSON"))
            challenge = json.loads(raw.decode("utf-8")).get("challenge")
        except (webauthn.WebAuthnError, UnicodeDecodeError, ValueError, AttributeError):
            raise Refused("bad clientDataJSON")
        with self.lock:
            entry = self.token_challenges.pop(str(challenge), None)    # one try per challenge
        if entry is None or entry[:2] != (action, subject) or entry[2] < self.clock():
            raise Refused("start again: the passkey prompt is for another action or timed out")
        cred = next((c for c in self.store.credentials() if c["id"] == answer.get("id")), None)
        if cred is None:
            raise Refused("that passkey is not enrolled here")
        try:
            count = webauthn.assertion(cred, raw, webauthn.unb64url(answer.get("authenticatorData")),
                                       webauthn.unb64url(answer.get("signature")), webauthn.unb64url(challenge),
                                       self.origin, self.config["rp_id"])
        except webauthn.WebAuthnError as e:
            self.store.audit("passkey_refused", tokens=action, credential=cred["id"], reason=str(e))
            raise Refused(f"the passkey check failed: {e}")
        self.store.set_sign_count(cred["id"], count)
        out = {"mcp_url": f"{self.origin}/mcp"}
        with self.store.lock:
            tokens = self.store.web_tokens()
            if action == "create":
                if len(tokens) >= MAX_TOKENS:
                    raise Refused(f"{MAX_TOKENS} tokens exist; revoke one first")
                token = "tna_" + webauthn.b64url(self.random(32))
                made = {"id": webauthn.b64url(self.random(6)), "label": subject, "sha256": sha256_hex(token),
                        "created": int(self.clock()), "last_used": None}
                self.store.save_web_tokens(tokens + [made])
                self.store.audit("token_created", token=made["id"], label=subject, credential=cred["id"])
                out["token"] = token
            elif action == "revoke":
                left = [x for x in tokens if x["id"] != subject]
                if len(left) == len(tokens):
                    raise Refused("no such token")
                self.store.save_web_tokens(left)
                self.store.audit("token_revoked", token=subject, credential=cred["id"])
        out["tokens"] = self.tokens()
        return out

    # --- enrolment --------------------------------------------------------------------

    def _code(self, code):
        """The sha256 of a valid enrolment code from `tn agent enroll`."""
        digest = sha256_hex(str(code or ""))
        current = self.store.enrolment()
        if (not current or not hmac.compare_digest(current.get("code_sha256", ""), digest)
                or current.get("expires", 0) < self.clock() or digest in self.store.used_codes()):
            raise Refused("this enrolment link is not valid (any more): run `tn agent enroll` again")
        return digest

    def enroll_begin(self, code):
        digest = self._code(code)
        challenge, user_id = self.random(32), self.random(16)
        with self.lock:
            self.enrolments[digest] = (challenge, self.clock() + CHALLENGE_SECONDS)
        owner = self.config["owner"]
        return {"challenge": webauthn.b64url(challenge),
                "rp": {"id": self.config["rp_id"], "name": f"tailscale-ops {self.region}"},
                "user": {"id": webauthn.b64url(user_id), "name": f"{owner}@{self.region}",
                         "displayName": f"tailscale-ops {self.region}"},
                "excludeCredentials": [c["id"] for c in self.store.credentials()], "timeout": 120000}

    def enroll_finish(self, code, answer):
        if not isinstance(answer, dict):
            raise Refused("expected a JSON object")
        digest = self._code(code)
        with self.lock:
            challenge, expires = self.enrolments.pop(digest, (None, 0))
        if challenge is None or expires < self.clock():
            raise Refused("start again: the passkey prompt timed out")
        try:
            cred = webauthn.registration(webauthn.unb64url(answer.get("clientDataJSON")),
                                         webauthn.unb64url(answer.get("attestationObject")),
                                         challenge, self.origin, self.config["rp_id"])
        except webauthn.WebAuthnError as e:
            raise Refused(f"the passkey was not accepted: {e}")
        cred.update(created=int(self.clock()), label=_plain(answer.get("label"), 60) or "passkey")
        self.store.add_credential(cred)
        self.store.use_code(digest)
        self.store.audit("enrolled", credential=cred["id"], label=cred["label"])
        return {"enrolled": cred["id"], "passkeys": len(self.store.credentials())}
