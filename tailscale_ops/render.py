"""Files that tailscale-ops writes on a control host."""

import json

from . import pins

BIN = "/usr/local/bin/headscale"
ETC = "/etc/headscale"
LIB = "/var/lib/headscale"
UNIT = "/etc/systemd/system/headscale.service"
SOCKET = "/var/run/headscale/headscale.sock"
# Names of other regions' hosts, kept by tailscale-ops; Headscale reloads it when it changes.
EXTRA_RECORDS = f"{ETC}/extra-records.json"


def marker(region):
    return f"tailnet-ops region={region.name}"


def _scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value)


def to_yaml(obj, indent=0):
    """A small YAML writer for nested dicts, lists of scalars and scalars."""
    pad = "  " * indent
    lines = []
    for key, value in obj.items():
        if isinstance(value, dict):
            if value:
                lines.append(f"{pad}{key}:")
                lines.append(to_yaml(value, indent + 1))
            else:
                lines.append(f"{pad}{key}: {{}}")
        elif isinstance(value, list):
            if value:
                lines.append(f"{pad}{key}:")
                lines.extend(f"{pad}  - {_scalar(v)}" for v in value)
            else:
                lines.append(f"{pad}{key}: []")
        else:
            lines.append(f"{pad}{key}: {_scalar(value)}")
    return "\n".join(lines)


def headscale_config(site, region):
    r = region
    cfg = {
        "server_url": r.server_url,
        "listen_addr": f"{r.listen_ipv4}:{r.port}",
        "metrics_listen_addr": f"127.0.0.1:{r.metrics_port}",
        "grpc_listen_addr": f"127.0.0.1:{r.grpc_port}",
        "grpc_allow_insecure": False,
        "noise": {"private_key_path": f"{LIB}/noise_private.key"},
        "prefixes": {"v4": r.ipv4_prefix, "v6": pins.IPV6_PREFIX, "allocation": "sequential"},
        "derp": {
            "server": {
                "enabled": True,
                "region_id": r.derp_region_id,
                "region_code": r.derp_region_code,
                "region_name": r.derp_region_name,
                "verify_clients": True,
                "stun_listen_addr": f"{r.listen_ipv4}:{r.stun_port}",
                "private_key_path": f"{LIB}/derp_server_private.key",
                "automatically_add_embedded_derp_region": True,
                "ipv4": r.public_ipv4,
            },
            "urls": [pins.OFFICIAL_DERP_MAP] if r.official_derp else [],
            "paths": [],
            "auto_update_enabled": r.official_derp,
            "update_frequency": "3h",
        },
        "database": {
            "type": "sqlite",
            "sqlite": {"path": f"{LIB}/db.sqlite", "write_ahead_log": True},
        },
        "tls_cert_path": f"{ETC}/tls/server.crt",
        "tls_key_path": f"{ETC}/tls/server.key",
        "log": {"level": "info", "format": "text"},
        "policy": {"mode": "file", "path": f"{ETC}/policy.hujson"},
        "dns": {
            "magic_dns": True,
            "base_domain": r.base_domain,
            "override_local_dns": False,
            "nameservers": {"global": [], "split": {}},
            "search_domains": [],
            "extra_records_path": EXTRA_RECORDS,
        },
        "unix_socket": SOCKET,
        "unix_socket_permission": "0770",
        "logtail": {"enabled": False},
    }
    head = (
        f"# {marker(region)}\n"
        f"# Headscale {pins.HEADSCALE_VERSION} for tailnet {r.name}. Written by tailnet-ops from site.toml;\n"
        "# edit site.toml and re-run `tn control apply`, not this file.\n"
    )
    return head + to_yaml(cfg) + "\n"


def line_peers(site, region, skip_lines=()):
    """[(line, other region)] for each line with an end in this region."""
    from .site import SiteError
    out = []
    for ln in site.lines:
        if ln.name in skip_lines:
            continue
        try:
            a, b = site.host_region(ln.initiator), site.host_region(ln.responder)
        except SiteError:
            continue
        if region.name == a.name and b.name != a.name:
            out.append((ln, b))
        elif region.name == b.name and a.name != b.name:
            out.append((ln, a))
    return out


def policy(site, region, skip_lines=()):
    """Every member reaches every member of this tailnet, and through each line the other
    region's alias range. The region's tags are owned by the owner, for tagged join keys.

    With tn-agent (agent_port), the machines it joins carry the region's agent tag and start no
    connection: every grant's source is then the owner's devices and the region's other tags, not
    "*". Traffic from a line or a phone entry still counts, as the border or the control host sends
    it (both tagged)."""
    owner = f"{site.owner_user}@"
    tags = list(region.tags) + ([region.agent_tag] if region.agent_tag else [])
    src = ["autogroup:member", *region.tags] if region.agent_tag else ["*"]
    doc = {
        "tagOwners": {tag: [owner] for tag in tags},
        "grants": [{"src": src, "dst": ["*"], "ip": ["*"]}],
    }
    for _ln, other in line_peers(site, region, skip_lines):
        if other.alias_net is not None:
            doc["grants"].append({"src": src, "dst": [str(other.alias_net)], "ip": ["*"]})
    head = (
        f"// {marker(region)}\n"
        f"// Policy for tailnet {region.name}: every member reaches every member, and the other\n"
        "// region's alias range through each line. Written by tailnet-ops from site.toml.\n"
        + (f"// Machines tagged {region.agent_tag} (joined through tn-agent) start no connection;\n"
           "// the others may still reach them.\n" if region.agent_tag else "")
    )
    return head + json.dumps(doc, indent=2) + "\n"


BOOTSTRAP_POLICY = "{}\n"


def systemd_unit(region):
    return f"""# {marker(region)}
[Unit]
Description=Headscale control plane for tailnet {region.name} (tailnet-ops)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=headscale
Group=headscale
ExecStart={BIN} serve --config {ETC}/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

WorkingDirectory={LIB}
ReadWritePaths={LIB}
RuntimeDirectory=headscale
RuntimeDirectoryMode=0750

CapabilityBoundingSet=
LockPersonality=true
NoNewPrivileges=true
PrivateDevices=true
PrivateMounts=true
PrivateTmp=true
ProcSubset=pid
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
RemoveIPC=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
UMask=0077

[Install]
WantedBy=multi-user.target
"""
