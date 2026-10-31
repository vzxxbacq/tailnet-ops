"""The Cloudflare API client: zones, the records tn marks, tunnels. Offline: a fake HTTP layer."""

import json
import unittest

from tailscale_ops.cloudflare import Cloudflare, CloudflareError
from tests import helpers  # noqa: F401  (keeps the real API out of reach)

MARK = "tailnet-ops region=ovs"


class FakeAPI:
    def __init__(self, zones=("example.com",), records=None, tunnels=None, deny=(), ignore_filter=False):
        self.zones = list(zones)
        self.records = records if records is not None else []
        self.tunnels = tunnels if tunnels is not None else []
        self.deny = deny
        self.ignore_filter = ignore_filter
        self.calls = []

    def __call__(self, method, url, token, body=None, timeout=30):
        path = url.split("/client/v4", 1)[1]
        self.calls.append((method, path, body))
        if any(path.startswith(d) for d in self.deny):
            return 403, json.dumps({"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}).encode()
        result = None
        if method == "GET" and path.startswith("/zones?name="):
            name = path.split("=", 1)[1]
            result = [{"id": "z1", "name": name, "account": {"id": "a1"}}] if name in self.zones else []
        elif method == "GET" and "/dns_records?" in path:
            name = path.split("name.exact=", 1)[1].split("&", 1)[0]
            result = list(self.records) if self.ignore_filter else [r for r in self.records if r["name"] == name]
        elif method == "POST" and path.endswith("/dns_records"):
            self.records.append(dict(body, id=f"r{len(self.records) + 1}"))
            result = self.records[-1]
        elif method == "PUT" and "/dns_records/" in path:
            rid = path.rsplit("/", 1)[1]
            self.records = [dict(body, id=rid) if r["id"] == rid else r for r in self.records]
        elif method == "DELETE" and "/dns_records/" in path:
            rid = path.rsplit("/", 1)[1]
            self.records = [r for r in self.records if r["id"] != rid]
        elif method == "GET" and "/cfd_tunnel?name=" in path:
            name = path.split("name=", 1)[1].split("&", 1)[0]
            result = [t for t in self.tunnels if t["name"] == name]
        elif method == "POST" and path.endswith("/cfd_tunnel"):
            self.tunnels.append({"id": "t1", "name": body["name"]})
            result = self.tunnels[-1]
        elif method == "GET" and path.endswith("/token"):
            result = "tunnel-token-xyz"
        elif method == "DELETE" and path.endswith("/t1"):
            self.tunnels = []
        return 200, json.dumps({"success": True, "errors": [], "result": result}).encode()


def a_record(content, proxied=False, comment=MARK, rid="r1"):
    return {"id": rid, "type": "A", "name": "hs-ovs.example.com", "content": content, "proxied": proxied, "comment": comment}


class RecordTest(unittest.TestCase):
    def cf(self, **kw):
        self.api = FakeAPI(**kw)
        cf = Cloudflare("token", http=self.api)
        return cf, cf.zone_for("hs-ovs.example.com")

    def test_zone_is_found_by_walking_up(self):
        _cf, zone = self.cf()
        self.assertEqual((zone["name"], zone["account"]), ("example.com", "a1"))
        self.assertEqual([c[1] for c in self.api.calls], ["/zones?name=hs-ovs.example.com", "/zones?name=example.com"])
        with self.assertRaises(CloudflareError):
            Cloudflare("token", http=FakeAPI(zones=())).zone_for("hs-ovs.example.com")

    def test_create_then_unchanged(self):
        cf, zone = self.cf()
        self.assertEqual(cf.ensure_record(zone, "hs-ovs.example.com", "A", "203.0.113.20", False, MARK), "created")
        self.assertEqual(self.api.records[0]["comment"], MARK)
        self.assertFalse(self.api.records[0]["proxied"])
        self.assertEqual(cf.ensure_record(zone, "hs-ovs.example.com", "A", "203.0.113.20", False, MARK), "unchanged")

    def test_fix_only_what_tn_made(self):
        cf, zone = self.cf(records=[a_record("192.0.2.1", proxied=True)])
        self.assertEqual(cf.ensure_record(zone, "hs-ovs.example.com", "A", "203.0.113.20", False, MARK), "updated")
        self.assertEqual((self.api.records[0]["content"], self.api.records[0]["proxied"]), ("203.0.113.20", False))
        cf, zone = self.cf(records=[a_record("192.0.2.1", comment="the owner's own")])
        with self.assertRaises(CloudflareError) as cm:
            cf.ensure_record(zone, "hs-ovs.example.com", "A", "203.0.113.20", False, MARK)
        self.assertIn("tn did not make", str(cm.exception))
        self.assertEqual(self.api.records[0]["content"], "192.0.2.1")

    def test_delete_only_what_tn_made(self):
        cf, zone = self.cf(records=[a_record("203.0.113.20"), dict(a_record("192.0.2.1", comment=""), id="r2")])
        self.assertEqual(cf.delete_record(zone, "hs-ovs.example.com", MARK), 1)
        self.assertEqual([r["id"] for r in self.api.records], ["r2"])

    def test_other_names_in_the_zone_are_not_in_the_way(self):
        """As the API answers a filter it does not apply: every record of the zone, the apex's MX among them."""
        mx = {"id": "r9", "type": "MX", "name": "example.com", "content": "route3.mx.cloudflare.net", "comment": ""}
        cf, zone = self.cf(records=[mx], ignore_filter=True)
        self.assertEqual(cf.records(zone, "hs-ovs.example.com"), [])
        self.assertEqual(cf.ensure_record(zone, "hs-ovs.example.com", "A", "203.0.113.20", False, MARK), "created")
        self.assertEqual(cf.delete_record(zone, "example.com", MARK), 0)          # not tn's: left alone
        self.assertIn("name.exact=hs-ovs.example.com", self.api.calls[2][1])

    def test_a_missing_permission_says_which(self):
        cf, zone = self.cf(deny=("/zones/z1/dns_records",))
        with self.assertRaises(CloudflareError) as cm:
            cf.ensure_record(zone, "hs-ovs.example.com", "A", "203.0.113.20", False, MARK)
        self.assertIn("Zone · DNS · Edit", str(cm.exception))


class TunnelTest(unittest.TestCase):
    def test_make_route_token_delete(self):
        api = FakeAPI()
        cf = Cloudflare("token", http=api)
        self.assertEqual(cf.ensure_tunnel("a1", "tailnet-ops-ovs"), ("t1", True))
        self.assertEqual(cf.ensure_tunnel("a1", "tailnet-ops-ovs"), ("t1", False))
        cf.route("a1", "t1", "agent-ovs.example.com", "http://127.0.0.1:18480")
        put = next(c for c in api.calls if c[0] == "PUT")
        self.assertEqual(put[2]["config"]["ingress"], [{"hostname": "agent-ovs.example.com", "service": "http://127.0.0.1:18480"},
                                                       {"service": "http_status:404"}])
        self.assertEqual(cf.tunnel_token("a1", "t1"), "tunnel-token-xyz")
        self.assertTrue(cf.delete_tunnel("a1", "tailnet-ops-ovs"))
        self.assertFalse(cf.delete_tunnel("a1", "tailnet-ops-ovs"))

    def test_no_test_reaches_the_real_api(self):
        with self.assertRaises(AssertionError):
            Cloudflare("token").zone_for("example.com")
