"""tn-agent, the service on the control host: P-256, CBOR, WebAuthn, the approval flow, MCP and HTTP.
Offline: Headscale and the authenticator are fakes; keys are made at random for each run."""

import ast
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from tailscale_ops.agentd import app as appmod, cbor, helper, mcp, p256, pages, webauthn
from tailscale_ops.agentd.app import App, Refused
from tailscale_ops.agentd.headscale import Headscale, HeadscaleError
from tailscale_ops.agentd import server as web
from tailscale_ops.agentd.server import Handler, Server
from tailscale_ops.agentd.store import Store
from tests.helpers import TempDirTest

RP_ID = "hs-ovs.example.com"
ORIGIN = "https://hs-ovs.example.com:8443"
LOGIN = "https://hs-ovs.example.com:9443"
AUTH_ID = "hskey-authreq-" + "A1b2C3d4E5f6G7h8I9j0K-_x"
AUTH_URL = f"{LOGIN}/register/{AUTH_ID}"
CONFIG = {"region": "ovs", "origin": ORIGIN, "rp_id": RP_ID, "login_server": LOGIN, "owner": "owner",
          "tags": ["tag:ovs-agent"]}
TEMPLATE = "#!/bin/bash\nHOST=__TN_NAME__\nTAGS=__TN_TAGS__\nSCRIPT=__TN_SCRIPT__\n"
MACHINE = {"auth_url": AUTH_URL, "hostname": "web1.example", "os": "Debian GNU/Linux 12", "arch": "x86_64"}
PACKAGE = Path(__file__).resolve().parent.parent / "tailscale_ops" / "agentd"


# --- test-only signing and encoding ------------------------------------------------------


def sign(d, digest):
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(p256.N - 1) + 1
        r = p256.mul(k, p256.G)[0] % p256.N
        s = pow(k, -1, p256.N) * (z + r * d) % p256.N
        if r and s:
            return r, s


def der(r, s):
    def integer(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(b)]) + b
    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def cbor_dumps(v):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor_dumps(x) for x in v)
    return head(5, len(v)) + b"".join(cbor_dumps(k) + cbor_dumps(x) for k, x in v.items())


class Authenticator:
    """A passkey: makes a credential and signs assertions, the way a browser hands them over."""

    def __init__(self, rp_id=RP_ID, origin=ORIGIN):
        self.rp_id, self.origin = rp_id, origin
        self.d = secrets.randbelow(p256.N - 1) + 1
        self.x, self.y = p256.mul(self.d, p256.G)
        self.raw_id = secrets.token_bytes(32)
        self.id = webauthn.b64url(self.raw_id)
        self.count = 0

    def _client(self, kind, challenge, origin=None):
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def _auth(self, flags, rp_id=None):
        return (hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags])
                + self.count.to_bytes(4, "big"))

    def create(self, options, flags=webauthn.FLAG_UP | webauthn.FLAG_UV, origin=None, rp_id=None):
        cose = {1: 2, 3: -7, -1: 1, -2: self.x.to_bytes(32, "big"), -3: self.y.to_bytes(32, "big")}
        attested = b"\0" * 16 + len(self.raw_id).to_bytes(2, "big") + self.raw_id + cbor_dumps(cose)
        auth = self._auth(flags | webauthn.FLAG_AT, rp_id) + attested
        att = cbor_dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"clientDataJSON": webauthn.b64url(self._client("webauthn.create", options["challenge"], origin)),
                "attestationObject": webauthn.b64url(att), "label": "test passkey"}

    def get(self, options, flags=webauthn.FLAG_UP | webauthn.FLAG_UV, origin=None, rp_id=None, key=None):
        cdj = self._client("webauthn.get", options["challenge"], origin)
        ad = self._auth(flags, rp_id)
        r, s = sign(key or self.d, hashlib.sha256(ad + hashlib.sha256(cdj).digest()).digest())
        return {"id": self.id, "clientDataJSON": webauthn.b64url(cdj), "authenticatorData": webauthn.b64url(ad),
                "signature": webauthn.b64url(der(r, s))}


class FakeHeadscale:
    def __init__(self, nodes=None):
        self.list = nodes or [{"id": 1, "given_name": "node-a", "name": "node-a", "online": True,
                               "ip_addresses": ["100.64.2.1", "fd7a:115c:a1e0::1"], "tags": ["tag:ovs-server"],
                               "last_seen": {"seconds": 1767225600}}]
        self.calls = []
        self.fail = None
        self.joined = {"id": 7, "given_name": "web1-x1", "name": "web1", "online": True,
                       "ip_addresses": ["100.64.2.7", "fd7a:115c:a1e0::7"], "tags": ["tag:ovs-agent"]}

    def nodes(self):
        return self.list

    def register(self, auth_id, user):
        self.calls.append(("register", auth_id, user))
        if self.fail:
            raise HeadscaleError(self.fail)
        return dict(self.joined)

    def rename(self, node_id, name):
        self.calls.append(("rename", node_id, name))
        return dict(self.joined, given_name=name)

    def set_tags(self, node_id, tags):
        self.calls.append(("tags", node_id, tuple(tags)))
        return dict(self.joined, given_name="web1", tags=list(tags))

    def reject(self, auth_id):
        self.calls.append(("reject", auth_id))

    def delete(self, node_id):
        self.calls.append(("delete", node_id))
        self.list = [n for n in self.list if n.get("id") != node_id]


class Clock:
    def __init__(self, now=1767225600):
        self.now = now

    def __call__(self):
        return self.now


# --- primitives --------------------------------------------------------------------------


class P256Test(unittest.TestCase):
    def test_round_trip(self):
        d = secrets.randbelow(p256.N - 1) + 1
        public = p256.mul(d, p256.G)
        digest = hashlib.sha256(b"approve").digest()
        r, s = sign(d, digest)
        self.assertTrue(p256.verify(public, digest, r, s))
        self.assertFalse(p256.verify(public, hashlib.sha256(b"deny").digest(), r, s))
        self.assertFalse(p256.verify(public, digest, r, (s + 1) % p256.N))
        self.assertFalse(p256.verify(public, digest, 0, s))
        self.assertFalse(p256.verify((public[0], public[1] + 1), digest, r, s))

    def test_der(self):
        self.assertEqual(p256.der_signature(der(5, 2**255 + 3)), (5, 2**255 + 3))
        for bad in (b"", b"\x31\x00", der(1, 2) + b"\x00", der(1, 2)[:-1], b"\x30\x03\x02\x01"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    p256.der_signature(bad)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_signatures_from_openssl(self):
        with tempfile.TemporaryDirectory() as d:
            key, msg = Path(d) / "k.pem", Path(d) / "m"
            msg.write_bytes(b"tailnet-ops")
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
                           check=True, capture_output=True)
            pub = subprocess.run(["openssl", "ec", "-in", str(key), "-pubout", "-outform", "DER"],
                                 check=True, capture_output=True).stdout
            sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), str(msg)],
                                 check=True, capture_output=True).stdout
        point = (int.from_bytes(pub[-64:-32], "big"), int.from_bytes(pub[-32:], "big"))
        self.assertTrue(p256.verify(point, hashlib.sha256(b"tailnet-ops").digest(), *p256.der_signature(sig)))


class CBORTest(unittest.TestCase):
    def test_values(self):
        value = {1: 2, -2: b"\x01" * 32, "fmt": "none", "list": [0, 23, 24, 255, 256, 65536, 2**32, -1, -25],
                 "flags": [True, False]}
        self.assertEqual(cbor.loads(cbor_dumps(value)), value)

    def test_refuses(self):
        for bad in (b"", b"\x5f", b"\x42\x00", cbor_dumps(1) + b"\x00", bytes([0x81] * 20 + [0])):
            with self.subTest(bad=bad):
                with self.assertRaises(cbor.CBORError):
                    cbor.loads(bad)


class WebAuthnTest(unittest.TestCase):
    def setUp(self):
        self.a = Authenticator()
        self.challenge = secrets.token_bytes(32)
        self.options = {"challenge": webauthn.b64url(self.challenge)}

    def register(self, answer):
        return webauthn.registration(webauthn.unb64url(answer["clientDataJSON"]),
                                     webauthn.unb64url(answer["attestationObject"]), self.challenge, ORIGIN, RP_ID)

    def check(self, cred, answer):
        return webauthn.assertion(cred, webauthn.unb64url(answer["clientDataJSON"]),
                                  webauthn.unb64url(answer["authenticatorData"]),
                                  webauthn.unb64url(answer["signature"]), self.challenge, ORIGIN, RP_ID)

    def test_register_and_sign(self):
        cred = self.register(self.a.create(self.options))
        self.assertEqual(cred["id"], self.a.id)
        self.assertEqual(int(cred["x"], 16), self.a.x)
        self.assertEqual(self.check(cred, self.a.get(self.options)), 0)

    def test_refused_registrations(self):
        cases = {
            "another origin": self.a.create(self.options, origin="https://evil.example"),
            "another RP ID": self.a.create(self.options, rp_id="evil.example"),
            "no user verification": self.a.create(self.options, flags=webauthn.FLAG_UP),
            "another challenge": self.a.create({"challenge": webauthn.b64url(b"x" * 32)}),
        }
        for name, answer in cases.items():
            with self.subTest(name), self.assertRaises(webauthn.WebAuthnError):
                self.register(answer)

    def test_refused_assertions(self):
        cred = self.register(self.a.create(self.options))
        cases = {
            "another origin": self.a.get(self.options, origin="https://evil.example"),
            "another RP ID": self.a.get(self.options, rp_id="evil.example"),
            "presence only": self.a.get(self.options, flags=webauthn.FLAG_UP),
            "another key": self.a.get(self.options, key=12345),
            "another challenge": self.a.get({"challenge": webauthn.b64url(b"y" * 32)}),
        }
        for name, answer in cases.items():
            with self.subTest(name), self.assertRaises(webauthn.WebAuthnError):
                self.check(cred, answer)

    def test_counter_must_move_forward(self):
        cred = self.register(self.a.create(self.options))
        self.a.count = 5
        self.assertEqual(self.check(cred, self.a.get(self.options)), 5)
        cred["sign_count"] = 5
        with self.assertRaises(webauthn.WebAuthnError):
            self.check(cred, self.a.get(self.options))


# --- the approval flow --------------------------------------------------------------------


class AppCase(TempDirTest):
    TOKEN = "t" * 40

    def setUp(self):
        super().setUp()
        self.state, self.etc = self.tmp / "state", self.tmp / "etc"
        self.state.mkdir()
        self.etc.mkdir()
        (self.etc / "tokens").write_text(hashlib.sha256(self.TOKEN.encode()).hexdigest() + " token\n")
        self.clock = Clock()
        self.store = Store(str(self.state), str(self.etc), clock=self.clock)
        self.hs = FakeHeadscale()
        self.app = App(CONFIG, self.store, self.hs, TEMPLATE, guide="# guide", clock=self.clock)
        self.passkey = Authenticator()

    def code(self, expires_in=600):
        code = secrets.token_urlsafe(24)
        (self.etc / "enroll.json").write_text(json.dumps(
            {"code_sha256": hashlib.sha256(code.encode()).hexdigest(), "expires": self.clock.now + expires_in}))
        return code

    def enroll(self, passkey=None):
        code = self.code()
        options = self.app.enroll_begin(code)
        return self.app.enroll_finish(code, (passkey or self.passkey).create(options))

    def script(self, name="web1"):
        return self.app.join_script(name, "the blog's web server", "MCP from 192.0.2.9")

    def request(self, name="web1", ip="198.51.100.7", **machine):
        return self.app.login(self.script(name)["script_id"], dict(MACHINE, **machine), ip)

    def decide(self, rid, decision, passkey=None):
        options = self.app.begin(rid, decision)
        return self.app.finish(rid, decision, (passkey or self.passkey).get(options))


class EnrolTest(AppCase):
    def test_enrol_once(self):
        code = self.code()
        options = self.app.enroll_begin(code)
        self.assertEqual(options["rp"]["id"], RP_ID)
        self.assertEqual(self.app.enroll_finish(code, self.passkey.create(options))["passkeys"], 1)
        with self.assertRaises(Refused):
            self.app.enroll_begin(code)
        self.assertIn("enrolled", (self.state / "audit.jsonl").read_text())

    def test_bad_codes(self):
        with self.assertRaises(Refused):
            self.app.enroll_begin("no code was made")
        self.code()
        with self.assertRaises(Refused):
            self.app.enroll_begin("not the code")
        expired = self.code(expires_in=-1)
        with self.assertRaises(Refused):
            self.app.enroll_begin(expired)

    def test_a_passkey_for_another_site_is_refused(self):
        code = self.code()
        options = self.app.enroll_begin(code)
        with self.assertRaises(Refused):
            self.app.enroll_finish(code, Authenticator(origin="https://evil.example").create(options))


class JoinTest(AppCase):
    def test_join_script(self):
        out = self.script("Web1")
        sid = out["script_id"]
        self.assertEqual((out["name"], out["tags"]), ("web1", ["tag:ovs-agent"]))
        text = self.app.script(sid)
        self.assertEqual(text, f"#!/bin/bash\nHOST=web1\nTAGS=tag:ovs-agent\nSCRIPT={sid}\n")
        self.assertEqual(out["sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertIn(f"{ORIGIN}/join/{sid}", out["command"])
        self.assertIn(out["sha256"], out["command"])
        self.assertIn("sudo bash", out["command"])
        self.assertIn('TN_MODE=user bash "$f"', out["command_without_root"])
        self.assertNotIn("sudo", out["command_without_root"])
        self.assertEqual(self.app.status(sid)["status"], "waiting_for_machine")
        self.clock.now += appmod.SCRIPT_SECONDS + 1
        with self.assertRaises(Refused):
            self.app.script(sid)

    def test_join_script_refuses(self):
        for name, reason, problem in (("node-a", "x", "already a node"), ("1web", "x", "is not a name"),
                                      ("web;rm", "x", "is not a name"), ("web1", " ", "reason")):
            with self.subTest(name=name):
                with self.assertRaises(Refused) as cm:
                    self.app.join_script(name, reason)
                self.assertIn(problem, str(cm.exception))
        self.script()
        with self.assertRaises(Refused):
            self.script()

    def test_the_machine_hands_over_its_login(self):
        sid = self.script()["script_id"]
        out = self.app.login(sid, MACHINE, "198.51.100.7")
        self.assertEqual(out["status"], "pending")
        self.assertEqual(out["approval_url"], f"{ORIGIN}/a/{out['request_id']}")
        req = self.app.view(out["request_id"])
        self.assertEqual(req["machine"], {"ip": "198.51.100.7", "hostname": "web1.example",
                                          "os": "Debian GNU/Linux 12", "arch": "x86_64"})
        self.assertEqual(req["auth_id"], AUTH_ID)
        self.assertEqual(self.app.status(sid)["request_id"], out["request_id"])
        with self.assertRaises(Refused):
            self.app.login(sid, MACHINE, "203.0.113.66")          # one login per join command

    def test_login_needs_this_login_server(self):
        for auth in ("https://other.example:9443/register/" + AUTH_ID, AUTH_ID, "hskey-" + "auth-abcdefgh", ""):
            with self.subTest(auth=auth):
                with self.assertRaises(Refused):
                    self.app.login(self.script(f"web{len(auth)}")["script_id"], dict(MACHINE, auth_url=auth), "x")

    def test_what_the_machine_reports_is_trimmed(self):
        out = self.request(hostname="a\nb" + "x" * 200, os="<b>")
        machine = self.app.view(out["request_id"])["machine"]
        self.assertEqual(len(machine["hostname"]), 80)
        self.assertNotIn("\n", machine["hostname"])

    def test_approve(self):
        self.enroll()
        rid = self.request()["request_id"]
        out = self.decide(rid, "approve")
        self.assertEqual(out["status"], "done")
        self.assertEqual(out["result"]["ipv4"], "100.64.2.7")
        self.assertEqual(out["result"]["name"], "web1")
        self.assertEqual(self.hs.calls[:2], [("register", AUTH_ID, "owner"), ("rename", 7, "web1")])
        self.assertEqual(self.app.status(rid)["status"], "done")
        audit = (self.state / "audit.jsonl").read_text()
        self.assertIn('"approved"', audit)
        self.assertIn('"done"', audit)

    def test_tags_are_held_to_the_agent_tag(self):
        self.enroll()
        self.hs.joined["tags"] = ["tag:ovs-server"]
        out = self.decide(self.request()["request_id"], "approve")
        self.assertIn(("tags", 7, ("tag:ovs-agent",)), self.hs.calls)
        self.assertEqual(out["result"]["tags"], ["tag:ovs-agent"])

    def test_deny(self):
        self.enroll()
        rid = self.request()["request_id"]
        self.assertEqual(self.decide(rid, "deny")["status"], "denied")
        self.assertEqual(self.hs.calls, [("reject", AUTH_ID)])
        with self.assertRaises(Refused):
            self.app.begin(rid, "approve")

    def test_a_challenge_works_once_and_for_its_decision(self):
        self.enroll()
        rid = self.request()["request_id"]
        answer = self.passkey.get(self.app.begin(rid, "deny"))
        with self.assertRaises(Refused):
            self.app.finish(rid, "approve", answer)
        with self.assertRaises(Refused):
            self.app.finish(rid, "deny", answer)          # used up by the try before
        answer = self.passkey.get(self.app.begin(rid, "approve"))
        self.assertEqual(self.app.finish(rid, "approve", answer)["status"], "done")
        with self.assertRaises(Refused):
            self.app.finish(rid, "approve", answer)
        self.assertEqual([c[0] for c in self.hs.calls].count("register"), 1)

    def test_only_enrolled_passkeys(self):
        rid = self.request()["request_id"]
        with self.assertRaises(Refused) as cm:
            self.app.begin(rid, "approve")
        self.assertIn("tn agent enroll", str(cm.exception))
        self.enroll()
        with self.assertRaises(Refused):
            self.decide(rid, "approve", passkey=Authenticator())
        self.assertEqual(self.hs.calls, [])
        self.assertEqual(self.app.status(rid)["status"], "pending")

    def test_a_changed_request_is_not_run(self):
        self.enroll()
        rid = self.request()["request_id"]
        options = self.app.begin(rid, "approve")
        reqs = json.loads((self.state / "requests.json").read_text())
        reqs[rid]["machine"]["ip"] = "192.0.2.1"
        (self.state / "requests.json").write_text(json.dumps(reqs))
        with self.assertRaises(Refused):
            self.app.finish(rid, "approve", self.passkey.get(options))
        self.assertEqual(self.hs.calls, [])

    def test_expiry(self):
        self.enroll()
        rid = self.request()["request_id"]
        self.clock.now += appmod.REQUEST_SECONDS + 1
        self.assertEqual(self.app.status(rid)["status"], "expired")
        with self.assertRaises(Refused):
            self.app.begin(rid, "approve")

    def test_headscale_failure(self):
        self.enroll()
        self.hs.fail = "no pending auth session"
        out = self.decide(self.request()["request_id"], "approve")
        self.assertEqual(out["status"], "failed")
        self.assertIn("no pending auth session", out["error"])

    def test_caps(self):
        for i in range(appmod.MAX_PENDING):
            self.request(f"web{i}")
        with self.assertRaises(Refused):
            self.request("one-more")
        for i in range(appmod.MAX_SCRIPTS - 1):          # one-more's command is still out
            self.script(f"spare{i}")
        with self.assertRaises(Refused):
            self.script("too-many")

    def test_tokens(self):
        self.assertTrue(self.app.authorised(self.TOKEN))
        for bad in ("", None, "x" * 40, self.TOKEN + "x"):
            self.assertFalse(self.app.authorised(bad))

    def test_nodes_leave_out_keys_and_endpoints(self):
        self.hs.list[0].update(machine_key="mkey:secret", node_key="nodekey:secret", endpoints=["192.0.2.1:41641"])
        out = self.app.nodes()
        self.assertEqual(out["nodes"][0]["ipv4"], "100.64.2.1")
        self.assertNotIn("secret", json.dumps(out))
        self.assertNotIn("192.0.2.1", json.dumps(out))


class TokenPageTest(AppCase):
    def do(self, action, subject="", passkey=None):
        options = self.app.tokens_begin(action, subject)
        return self.app.tokens_finish(action, subject, (passkey or self.passkey).get(options))

    def test_make_use_list_revoke(self):
        self.enroll()
        out = self.do("create", "agent")
        token = out["token"]
        self.assertRegex(token, r"^tna_[A-Za-z0-9_-]{43}$")
        self.assertEqual(out["mcp_url"], ORIGIN + "/mcp")
        self.assertTrue(self.app.authorised(token))
        listed = self.do("list")["tokens"]
        self.assertEqual([x["label"] for x in listed], ["agent"])
        self.assertNotIn("sha256", listed[0])
        self.assertIsNotNone(listed[0]["last_used"])
        self.assertNotIn(token, (self.state / "tokens.json").read_text())      # only its sha256 is kept
        self.do("revoke", listed[0]["id"])
        self.assertFalse(self.app.authorised(token))
        audit = (self.state / "audit.jsonl").read_text()
        self.assertIn('"token_created"', audit)
        self.assertIn('"token_revoked"', audit)

    def test_the_token_from_the_install_stays_valid(self):
        """The token tn agent token made (its sha256 in etc/tokens) keeps working beside the page's ones, and the
        page neither lists nor revokes it."""
        self.enroll()
        self.do("create", "second")
        self.assertTrue(self.app.authorised(self.TOKEN))
        self.assertEqual([x["label"] for x in self.do("list")["tokens"]], ["second"])
        with self.assertRaises(Refused):
            self.do("revoke", "etc-token")
        self.assertTrue(self.app.authorised(self.TOKEN))

    def test_every_action_needs_its_own_passkey(self):
        self.enroll()
        answer = self.passkey.get(self.app.tokens_begin("list", ""))
        with self.assertRaises(Refused):
            self.app.tokens_finish("create", "x", answer)             # a challenge for another action
        with self.assertRaises(Refused):
            self.app.tokens_finish("list", "", answer)                # used up by the try before
        with self.assertRaises(Refused):
            self.do("create", "x", passkey=Authenticator())           # not enrolled here
        rid = self.request()["request_id"]
        approval = self.passkey.get(self.app.begin(rid, "approve"))
        with self.assertRaises(Refused):
            self.app.tokens_finish("create", "x", approval)           # an approval's signature makes no token
        self.assertEqual(self.app.tokens(), [])

    def test_needs_an_enrolled_passkey(self):
        with self.assertRaises(Refused):
            self.app.tokens_begin("create", "x")

    def test_last_use_is_written_now_and_then(self):
        self.enroll()
        token = self.do("create", "a")["token"]
        self.app.authorised(token)
        first = self.app.tokens()[0]["last_used"]
        self.clock.now += 5
        self.app.authorised(token)
        self.assertEqual(self.app.tokens()[0]["last_used"], first)
        self.clock.now += appmod.TOUCH_SECONDS
        self.app.authorised(token)
        self.assertGreater(self.app.tokens()[0]["last_used"], first)


AGENT_NODE = {"id": 7, "given_name": "web1", "name": "web1", "online": True, "ip_addresses": ["100.64.2.7"],
              "tags": ["tag:ovs-agent"], "last_seen": {"seconds": 1767225000}}
LEAVE = "#!/bin/bash\nHOST=__TN_NAME__\necho TN-LEFT __TN_NAME__\n"


class LeaveTest(AppCase):
    def setUp(self):
        super().setUp()
        self.hs.list.append(dict(AGENT_NODE))
        self.app.leave_template = LEAVE

    def ask(self, name="web1"):
        return self.app.request_leave(name, "the blog moved", "MCP from 192.0.2.9")

    def test_approve_removes_the_node(self):
        self.enroll()
        req = self.ask()
        self.assertEqual((req["status"], req["kind"]), ("pending", "leave"))
        page = pages.approval(self.app.view(req["request_id"]), CONFIG)
        self.assertIn("让 web1 退出 ovs？", page)
        self.assertIn("100.64.2.7", page)
        out = self.decide(req["request_id"], "approve")
        self.assertEqual(out["status"], "done", out)
        self.assertIn(("delete", 7), self.hs.calls)
        self.assertIn("leave_script", out["next"])
        self.assertIn('"leave_requested"', (self.state / "audit.jsonl").read_text())

    def test_only_machines_tn_agent_joined(self):
        for name, problem in (("node-a", "did not join through tn-agent"), ("ghost", "no node named")):
            with self.subTest(name):
                with self.assertRaises(Refused) as cm:
                    self.ask(name)
                self.assertIn(problem, str(cm.exception))
        with self.assertRaises(Refused):
            self.app.request_leave("web1", " ")                      # a reason is needed

    def test_deny_removes_nothing(self):
        self.enroll()
        rid = self.ask()["request_id"]
        self.assertEqual(self.decide(rid, "deny")["status"], "denied")
        self.assertEqual(self.hs.calls, [])

    def test_a_node_that_changed_is_not_removed(self):
        self.enroll()
        rid = self.ask()["request_id"]
        self.hs.list[-1]["tags"] = ["tag:ovs-server"]                 # retagged by the owner meanwhile
        out = self.decide(rid, "approve")
        self.assertEqual(out["status"], "failed")
        self.assertNotIn(("delete", 7), self.hs.calls)

    def test_already_gone(self):
        self.enroll()
        rid = self.ask()["request_id"]
        self.hs.list.pop()
        out = self.decide(rid, "approve")
        self.assertEqual((out["status"], out["result"]["removed"]), ("done", "already gone"))

    def test_one_request_per_machine(self):
        self.assertEqual(self.ask()["request_id"], self.ask()["request_id"])

    def test_leave_script(self):
        out = self.app.leave_script("web1")
        sid = out["command"].split("/join/", 1)[1].split("'", 1)[0]
        text = self.app.script(sid)
        self.assertEqual(text, "#!/bin/bash\nHOST=web1\necho TN-LEFT web1\n")
        self.assertIn(hashlib.sha256(text.encode()).hexdigest(), out["command"])
        with self.assertRaises(Refused):
            self.app.login(sid, MACHINE, "198.51.100.7")             # a leave command logs nothing in
        self.assertIn('TN_MODE=user bash "$f"', out["command_without_root"])
        self.app.leave_template = ""
        with self.assertRaises(Refused):
            self.app.leave_script("web1")

    def test_resume_script_only_for_machines_tn_agent_joined(self):
        self.app.resume_template = "#!/bin/bash\nHOST=__TN_NAME__\n"
        out = self.app.resume_script("web1")
        sid = out["command"].split("/join/", 1)[1].split("'", 1)[0]
        self.assertEqual(self.app.script(sid), "#!/bin/bash\nHOST=web1\n")
        self.assertIn('TN_MODE=user bash "$f"', out["command_without_root"])
        for name in ("node-a", "ghost"):
            with self.subTest(name), self.assertRaises(Refused):
                self.app.resume_script(name)
        self.app.resume_template = ""
        with self.assertRaises(Refused):
            self.app.resume_script("web1")

    def test_requests_from_before_still_check(self):
        """A join request saved before this version keeps its digest: the join keys did not change."""
        self.enroll()
        self.assertEqual(appmod.App.DIGEST_KEYS["join"], ("id", "kind", "region", "name", "tags", "auth_id",
                                                          "reason", "who", "script", "machine", "created", "expires"))
        rid = self.request("web2")["request_id"]
        req = self.app.view(rid)
        self.assertEqual(appmod.App._digest(req), req["digest"])
        self.assertEqual(self.decide(rid, "approve")["status"], "done")


class HeadscaleTest(unittest.TestCase):
    def test_commands(self):
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            self.assertEqual(kw["env"]["GOMAXPROCS"], "2")
            return subprocess.CompletedProcess(argv, 0, stdout='{"id": 3}', stderr="")
        hs = Headscale("/usr/local/bin/headscale", "/etc/headscale/config.yaml", run=run)
        hs.register(AUTH_ID, "owner")
        hs.set_tags(3, ["tag:a", "tag:b"])
        hs.delete(3)
        base = ["/usr/local/bin/headscale", "-c", "/etc/headscale/config.yaml"]
        self.assertEqual(calls[0], base + ["auth", "register", "--auth-id", AUTH_ID, "--user", "owner", "-o", "json"])
        self.assertEqual(calls[1], base + ["nodes", "tag", "-i", "3", "-t", "tag:a", "-t", "tag:b", "-o", "json"])
        self.assertEqual(calls[2], base + ["nodes", "delete", "-i", "3", "--force", "-o", "json"])

    def test_errors(self):
        def run(argv, **kw):
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Error: no pending auth session\n")
        with self.assertRaises(HeadscaleError) as cm:
            Headscale("hs", "c", run=run).register(AUTH_ID, "owner")
        self.assertIn("no pending auth session", str(cm.exception))


# --- MCP and the private half --------------------------------------------------------------


class MCPTest(AppCase):
    def rpc(self, method, params=None, mid=1):
        return mcp.handle(self.app, {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})

    def test_initialize(self):
        out = self.rpc("initialize", {"protocolVersion": "2025-03-26"})["result"]
        self.assertEqual(out["protocolVersion"], "2025-03-26")
        self.assertIn("passkey", out["instructions"])
        self.assertEqual(self.rpc("initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"],
                         "2025-06-18")
        self.assertIsNone(mcp.handle(self.app, {"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_tools(self):
        names = [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]
        self.assertEqual(names, ["tailnet_guide", "list_nodes", "join_script", "request_status", "request_leave",
                                 "leave_script", "resume_script"])
        out = self.rpc("tools/call", {"name": "list_nodes", "arguments": {}})["result"]
        self.assertFalse(out["isError"])
        self.assertEqual(json.loads(out["content"][0]["text"])["nodes"][0]["name"], "node-a")
        self.assertEqual(self.rpc("tools/call", {"name": "tailnet_guide"})["result"]["content"][0]["text"], "# guide")

    def test_refusals_are_tool_errors(self):
        out = self.rpc("tools/call", {"name": "join_script", "arguments": {"name": "node-a", "reason": "x"}})
        self.assertTrue(out["result"]["isError"])
        self.assertTrue(self.rpc("tools/call", {"name": "approve"})["result"]["isError"])
        self.assertEqual(self.rpc("resources/list")["error"]["code"], -32601)
        self.assertEqual(mcp.handle(self.app, {"id": 1})["error"]["code"], -32600)

    def test_no_tool_changes_the_tailnet(self):
        """The only tool that is not read-only hands out a join command; none reaches a Headscale write."""
        writes = [t["name"] for t in mcp.TOOLS if not t["annotations"]["readOnlyHint"]]
        self.assertEqual(writes, ["join_script", "request_leave"])
        out = self.rpc("tools/call", {"name": "join_script", "arguments": {"name": "web1", "reason": "test"}})
        sid = json.loads(out["result"]["content"][0]["text"])["script_id"]
        self.rpc("tools/call", {"name": "request_status", "arguments": {"request_id": sid}})
        self.assertEqual(self.hs.calls, [])


class HelperTest(AppCase):
    def ask(self, op, **fields):
        return helper.dispatch(self.app, json.loads(json.dumps({"op": op, **fields})))

    def test_dispatch(self):
        self.assertEqual(self.ask("health"), {"ok": True, "result": {"region": "ovs"}})
        hello = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        self.assertEqual(self.ask("mcp", token="wrong", message=hello)["code"], 401)
        self.assertEqual(self.ask("mcp", token=self.TOKEN, message=hello)["result"]["result"]["serverInfo"]["name"],
                         "tailscale-ops")
        self.assertEqual(self.ask("mcp", token=self.TOKEN, message={"jsonrpc": "2.0", "method": "x"})["result"], None)
        self.assertEqual(self.ask("view", id="nope")["code"], 400)
        self.assertEqual(self.ask("delete_node", id=1)["code"], 404)
        self.assertEqual(helper.dispatch(self.app, ["op"])["code"], 400)

    def test_tool_calls_are_audited(self):
        self.ask("mcp", token=self.TOKEN, who="MCP from 192.0.2.9",
                 message={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_nodes"}})
        self.assertIn('"tool": "list_nodes"', (self.state / "audit.jsonl").read_text())

    def test_over_a_unix_socket(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            path = os.path.join(d, "helper.sock")
            server = helper.HelperServer(path, self.app)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o660)
                client = helper.HelperClient(path, timeout=10)
                self.assertEqual(client("health")["result"], {"region": "ovs"})
                sid = client("mcp", token=self.TOKEN, message={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "join_script", "arguments": {"name": "web1", "reason": "test"}}})
                self.assertTrue(sid["ok"])
            finally:
                server.shutdown()
                server.server_close()


# --- the public half ------------------------------------------------------------------------


class MemoryTest(TempDirTest):
    def setup_host(self, available_kb, current, high="209715200", maximum="268435456"):
        proc, cg = self.tmp / "proc", self.tmp / "cg"
        (proc / "self").mkdir(parents=True, exist_ok=True)
        (proc / "meminfo").write_text(f"MemTotal:        2000000 kB\nMemFree:          100000 kB\n"
                                      f"MemAvailable:    {available_kb} kB\n")
        (proc / "self" / "cgroup").write_text("0::/system.slice/tn-agent.service\n")
        unit = cg / "system.slice" / "tn-agent.service"
        unit.mkdir(parents=True, exist_ok=True)
        (unit / "memory.current").write_text(f"{current}\n")
        (unit / "memory.high").write_text(f"{high}\n")
        (unit / "memory.max").write_text(f"{maximum}\n")
        clock = Clock(0)
        return web.Memory(str(proc), str(cg), clock=clock), clock

    def test_plenty(self):
        memory, _ = self.setup_host(1000000, 50 * 2**20)
        self.assertFalse(memory.short())

    def test_close_to_its_own_limit(self):
        memory, _ = self.setup_host(1000000, 170 * 2**20)        # over 80% of memory.high (200 MiB)
        self.assertTrue(memory.short())

    def test_the_host_is_low(self):
        memory, _ = self.setup_host(150000, 50 * 2**20)          # under 10% of 2 GB available
        self.assertTrue(memory.short())

    def test_read_once_a_second(self):
        memory, clock = self.setup_host(1000000, 50 * 2**20)
        self.assertFalse(memory.short())
        self.setup_host(100000, 50 * 2**20)
        self.assertFalse(memory.short())
        clock.now += 1
        self.assertTrue(memory.short())

    def test_unknown_is_never_short(self):
        memory = web.Memory(str(self.tmp / "none"), str(self.tmp / "none"))
        self.assertFalse(memory.short())
        memory, _ = self.setup_host(1000000, 50 * 2**20, high="max", maximum="max")
        self.assertFalse(memory.short())


class ServerTest(AppCase):
    def setUp(self):
        super().setUp()
        quiet = mock.patch.object(Handler, "log_message", lambda *a: None)
        quiet.start()
        self.addCleanup(quiet.stop)
        self.down = False

        def ask(op, **fields):
            if self.down:
                raise ConnectionRefusedError()
            return helper.dispatch(self.app, json.loads(json.dumps({"op": op, **fields})))
        self.server = Server(("127.0.0.1", 0), CONFIG, ask)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def http(self, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json",
                                                                           **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read().decode(), dict(e.headers)

    def mcp(self, message, token=AppCase.TOKEN):
        return self.http("/mcp", message, {"Authorization": f"Bearer {token}"} if token else {})

    def test_health(self):
        self.assertEqual(self.http("/healthz")[:2], (200, "ok tn-agent 1 ovs\n"))
        self.down = True
        self.assertEqual(self.http("/healthz")[0], 503)

    def test_mcp_needs_the_token(self):
        hello = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        code, _body, headers = self.mcp(hello, token=None)
        self.assertEqual(code, 401)
        self.assertIn("Bearer", headers["WWW-Authenticate"])
        self.assertEqual(self.mcp(hello, token="x" * 40)[0], 401)
        code, body, _ = self.mcp(hello)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["result"]["serverInfo"]["name"], "tailscale-ops")
        self.assertEqual(self.mcp({"jsonrpc": "2.0", "method": "notifications/initialized"})[0], 202)
        self.assertEqual(self.http("/mcp", hello, {"Authorization": f"Bearer {self.TOKEN}",
                                                   "Origin": "https://evil.example"})[0], 403)

    def test_join_end_to_end(self):
        _code, body, _ = self.mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": "join_script", "arguments": {"name": "web1", "reason": "blog"}}})
        sid = json.loads(json.loads(body)["result"]["content"][0]["text"])["script_id"]
        code, text, _ = self.http(f"/join/{sid}")
        self.assertEqual((code, text), (200, f"#!/bin/bash\nHOST=web1\nTAGS=tag:ovs-agent\nSCRIPT={sid}\n"))
        code, body, _ = self.http(f"/join/{sid}/login", MACHINE)
        self.assertEqual(code, 200, body)
        rid = json.loads(body)["request_id"]
        code, page, headers = self.http(f"/a/{rid}")
        self.assertEqual(code, 200)
        self.assertIn("127.0.0.1", page)                 # where the login came from
        self.assertIn("web1.example", page)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.enroll()
        self.assertEqual(self.http(f"/a/{rid}/begin", {"decision": "approve"})[0], 403)
        self.assertEqual(self.http(f"/a/{rid}/begin", {"decision": "approve"}, {"Origin": "https://evil.example"})[0], 403)
        code, body, _ = self.http(f"/a/{rid}/begin", {"decision": "approve"}, {"Origin": ORIGIN})
        self.assertEqual(code, 200)
        code, body, _ = self.http(f"/a/{rid}/finish", dict(self.passkey.get(json.loads(body)), decision="approve"),
                                  {"Origin": ORIGIN})
        self.assertEqual((code, json.loads(body)["status"]), (200, "done"))
        self.assertEqual(self.http(f"/join/{sid}/login", MACHINE)[0], 400)
        self.assertEqual(self.http("/join/AAAAAAAAAAAAAAAA")[0], 404)
        self.assertEqual(self.http("/a/AAAAAAAAAAAAAAAA")[0], 400)
        self.assertEqual(self.http("/static/app.js")[0], 200)

    def test_short_of_memory_429(self):
        self.server.memory = mock.Mock(short=lambda: True)
        code, body, headers = self.http("/healthz")
        self.assertEqual((code, headers["Retry-After"]), (429, "5"))
        code, body, _ = self.mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual((code, json.loads(body)["error"]["code"]), (429, -32000))
        self.server.memory = mock.Mock(short=lambda: False)
        self.assertEqual(self.http("/healthz")[0], 200)

    def test_many_connections_at_once(self):
        import socket
        port = self.server.server_address[1]
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(200)]
        try:
            self.assertEqual(self.http("/healthz")[0], 200)       # no connection count turns it away
        finally:
            for s in idle:
                s.close()

    def test_behind_cloudflare_the_address_comes_from_its_header(self):
        self.server.config = dict(CONFIG, proxy="cloudflare")
        for header, shown in (("198.51.100.77", "198.51.100.77"), ("not an address", "unknown")):
            with self.subTest(header):
                sid = self.app.join_script(f"web{len(header)}", "blog")["script_id"]
                code, body, _ = self.http(f"/join/{sid}/login", MACHINE, {"CF-Connecting-IP": header})
                self.assertEqual(code, 200, body)
                self.assertEqual(self.app.view(json.loads(body)["request_id"])["machine"]["ip"], shown)

    def test_token_page(self):
        code, page, headers = self.http("/tokens")
        self.assertEqual(code, 200)
        self.assertIn('data-page="tokens"', page)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.enroll()
        self.assertEqual(self.http("/tokens/begin", {"action": "create", "subject": "x"})[0], 403)
        code, body, _ = self.http("/tokens/begin", {"action": "create", "subject": "agent"}, {"Origin": ORIGIN})
        self.assertEqual(code, 200, body)
        answer = dict(self.passkey.get(json.loads(body)), action="create", subject="agent")
        code, body, _ = self.http("/tokens/finish", answer, {"Origin": ORIGIN})
        self.assertEqual(code, 200, body)
        token = json.loads(body)["token"]
        hello = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        self.assertEqual(self.mcp(hello, token=token)[0], 200)
        self.assertEqual(self.mcp(hello)[0], 200)                    # and the install's token still works

    def test_page_escapes_what_the_agent_and_machine_wrote(self):
        sid = self.app.join_script("web1", "<script>alert(1)</script>")["script_id"]
        rid = self.app.login(sid, dict(MACHINE, hostname="<img src=x>"), "198.51.100.7")["request_id"]
        page = pages.approval(self.app.view(rid), CONFIG)
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;", page)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_tls(self):
        import ssl
        cert, key = self.tmp / "c.pem", self.tmp / "k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        server = Server(("127.0.0.1", 0), CONFIG, self.server.helper, str(cert), str(key))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            ctx = ssl.create_default_context(cafile=str(cert))
            ctx.check_hostname = False
            url = f"https://127.0.0.1:{server.server_address[1]}/healthz"
            with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
                self.assertEqual(r.read(), b"ok tn-agent 1 ovs\n")
        finally:
            server.shutdown()
            server.server_close()


class CodeTest(unittest.TestCase):
    def test_python_38_syntax(self):
        """The control host may have an older Python than this machine."""
        for path in PACKAGE.glob("*.py"):
            with self.subTest(path.name):
                ast.parse(path.read_text(), filename=str(path), feature_version=(3, 8))

    def test_standard_library_only(self):
        allowed = set(sys.stdlib_module_names)
        for path in PACKAGE.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module.split(".")[0]]
                else:
                    continue
                with self.subTest(path.name, names=names):
                    self.assertLessEqual(set(names), allowed)


if __name__ == "__main__":
    unittest.main()
