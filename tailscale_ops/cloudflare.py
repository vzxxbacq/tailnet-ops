"""The Cloudflare API, from the machine that runs tn, with the owner's API token.

One token does it all. It needs these permissions:
- Zone · Zone · Read and Zone · DNS · Edit on the zone: the login server's A record, and the DNS-01
  answers acme.sh gives on the control host (where the token is kept for renewals);
- Account · Cloudflare Tunnel · Edit: only for tn agent, which reaches tn-agent through a tunnel.

What tn makes carries a mark (a record's comment; the tunnel's name), and tn changes or deletes only
what has its mark. The token is never printed, logged or kept on this machine.
"""

import json
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
TUNNEL_SUFFIX = "cfargotunnel.com"

PERMISSIONS = ("Zone · Zone · Read and Zone · DNS · Edit on the zone, and Account · Cloudflare Tunnel · Edit "
               "for tn agent")


class CloudflareError(Exception):
    pass


def _http(method, url, token, body=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "tailscale-ops"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        with e:
            return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise CloudflareError(f"cannot reach the Cloudflare API: {getattr(e, 'reason', e)}")


def _same(a, b):
    """DNS names compare without case and without a trailing dot."""
    return isinstance(a, str) and a.rstrip(".").lower() == b.rstrip(".").lower()


def in_the_way(rec, name, kind, content, proxied):
    return (f"Cloudflare has a {rec['type']} record {name} -> {rec['content']}"
            f"{' (proxied)' if rec.get('proxied') else ''} that tn did not make; delete it, or make it "
            f"{kind} {content}{' (proxied)' if proxied else ', DNS only'}, then run this again")


class Cloudflare:
    def __init__(self, token, http=None):
        self.token = token
        self.http = http or _http

    def call(self, method, path, body=None, need=""):
        """The `result` of an API call. need: the permission it takes, for the error message."""
        status, raw = (self.http or _http)(method, API + path, self.token, body)
        try:
            doc = json.loads(raw or b"{}")
        except ValueError:
            raise CloudflareError(f"{method} {path}: HTTP {status}, not JSON")
        if status in (401, 403) or (doc.get("errors") and any(e.get("code") in (9109, 10000) for e in doc["errors"])):
            raise CloudflareError(f"the token may not {need or 'do this'}: give it {PERMISSIONS}")
        if not doc.get("success", 200 <= status < 300):
            messages = "; ".join(e.get("message", "?") for e in doc.get("errors") or []) or f"HTTP {status}"
            raise CloudflareError(f"{method} {path}: {messages}")
        return doc.get("result")

    # --- zones and records ------------------------------------------------------------

    def zone_for(self, name):
        """{id, name, account} of the zone that holds name: the name itself, else each parent."""
        labels = name.rstrip(".").split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            found = self.call("GET", f"/zones?name={candidate}", need="read zones (Zone · Zone · Read)") or []
            found = [z for z in found if _same(z.get("name"), candidate)]
            if found:
                z = found[0]
                return {"id": z["id"], "name": z["name"], "account": (z.get("account") or {}).get("id")}
        raise CloudflareError(f"no zone this token can read holds {name}: is the domain on this Cloudflare account, "
                              "and the token for its zone?")

    def records(self, zone, name):
        """The records named exactly name. The API filters with name.exact (a plain name= is ignored now, and
        every record of the zone comes back); the list is filtered here again either way."""
        found = self.call("GET", f"/zones/{zone['id']}/dns_records?name.exact={name}&per_page=1000",
                          need="read DNS records (Zone · DNS · Edit)") or []
        return [r for r in found if _same(r.get("name"), name)]

    def record_state(self, zone, name, kind, content, proxied, mark):
        """(state, record, every record of that name): "ok" (as wanted), "absent", "ours" (all marked, but not
        as wanted) or "foreign" (a record tn did not make is in the way)."""
        found = self.records(zone, name)
        same = [r for r in found if r["type"] == kind and r["content"] == content and bool(r.get("proxied")) == proxied]
        if same and len(found) == 1:
            return "ok", same[0], found
        if not found:
            return "absent", None, found
        mine = [r for r in found if (r.get("comment") or "") == mark]
        if len(mine) == len(found):
            return "ours", mine[0], found
        return "foreign", next(r for r in found if (r.get("comment") or "") != mark), found

    def ensure_record(self, zone, name, kind, content, proxied, mark):
        """Make the record so; returns what was done. A record tn did not make is not touched."""
        state, rec, found = self.record_state(zone, name, kind, content, proxied, mark)
        body = {"type": kind, "name": name, "content": content, "proxied": proxied, "ttl": 1, "comment": mark}
        need = "edit DNS records (Zone · DNS · Edit)"
        if state == "ok":
            return "unchanged"
        if state == "absent":
            self.call("POST", f"/zones/{zone['id']}/dns_records", body, need=need)
            return "created"
        if state == "ours":
            for extra in found:
                if extra["id"] != rec["id"]:
                    self.call("DELETE", f"/zones/{zone['id']}/dns_records/{extra['id']}", need=need)
            self.call("PUT", f"/zones/{zone['id']}/dns_records/{rec['id']}", body, need=need)
            return "updated"
        raise CloudflareError(in_the_way(rec, name, kind, content, proxied))

    def delete_record(self, zone, name, mark):
        """Delete the records named name that carry mark; returns how many."""
        gone = 0
        for r in self.records(zone, name):
            if (r.get("comment") or "") == mark:
                self.call("DELETE", f"/zones/{zone['id']}/dns_records/{r['id']}",
                          need="edit DNS records (Zone · DNS · Edit)")
                gone += 1
        return gone

    # --- tunnels ----------------------------------------------------------------------

    def tunnel(self, account, name):
        found = self.call("GET", f"/accounts/{account}/cfd_tunnel?name={name}&is_deleted=false",
                          need="read tunnels (Account · Cloudflare Tunnel · Edit)") or []
        found = [x for x in found if x.get("name") == name and not x.get("deleted_at")]
        return found[0] if found else None

    def ensure_tunnel(self, account, name):
        """(tunnel id, created?) for a remotely managed tunnel of that name."""
        found = self.tunnel(account, name)
        if found:
            return found["id"], False
        made = self.call("POST", f"/accounts/{account}/cfd_tunnel", {"name": name, "config_src": "cloudflare"},
                         need="make tunnels (Account · Cloudflare Tunnel · Edit)")
        return made["id"], True

    def route(self, account, tunnel_id, hostname, service):
        """The tunnel sends hostname to service on the host; nothing else."""
        ingress = [{"hostname": hostname, "service": service}, {"service": "http_status:404"}]
        self.call("PUT", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations",
                  {"config": {"ingress": ingress}}, need="configure tunnels (Account · Cloudflare Tunnel · Edit)")

    def tunnel_token(self, account, tunnel_id):
        token = self.call("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/token",
                          need="read tunnel tokens (Account · Cloudflare Tunnel · Edit)")
        if not isinstance(token, str) or not token:
            raise CloudflareError("Cloudflare returned no tunnel token")
        return token

    def delete_tunnel(self, account, name):
        found = self.tunnel(account, name)
        if not found:
            return False
        need = "delete tunnels (Account · Cloudflare Tunnel · Edit)"
        self.call("DELETE", f"/accounts/{account}/cfd_tunnel/{found['id']}/connections", need=need)
        self.call("DELETE", f"/accounts/{account}/cfd_tunnel/{found['id']}", need=need)
        return True
