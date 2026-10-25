# Plan

给 owner 的一句话：tailnet-ops 要做成任何人都能复用的快速搭建工具。代码和文档里没有任何人的隐私；每个使用者的站点配置、证书和密钥只在自己电脑的私有目录里。第一阶段仍是部署两套 Headscale，先用你的站点验证，部署前把计划给你确认。

## Product

tailnet-ops sets up a self-hosted Headscale network quickly:

- **Regions.** The network is split into regions, with one tailnet per region. Inside a region, devices connect directly. Regions never see each other, so nothing probes across a border.
- **Lines.** Regions can be joined by dedicated lines. A line may be one-way for connection setup: only its initiator can start a connection, and traffic then flows both ways inside the tunnel it keeps alive.
- **Reuse.** Anyone can use it with their own site. Everything site-specific lives in a private site directory; the repository never contains it.

The first site is the owner's. Its configuration and notes are in the owner's site directory: `site.toml` and `notes.md`, the latter holding host facts and the services to leave untouched. Read them at run time; do not copy them here.

## Privacy, built into the tool

1. **The repository is publishable.** It holds code, templates, docs and examples only. Examples use documentation ranges and placeholder names. `make check` runs a guard over tracked files and all history: it blocks other IPv4 literals outside 100.64.0.0/10 and 10.255.0.0/16 (tailnet-ops's default alias and tunnel range, the same for every site), private keys, Headscale and Tailscale auth keys, and tokens.
2. **The site directory is private.**
   - Location: `~/.config/tailnet-ops/` by default, or `--site DIR` or `TN_SITE`.
   - Permissions: the directory is 0700 and its files 0600.
   - The tool refuses a site directory that sits inside a Git work tree.
   - Contents: `site.toml`, `notes.md`, `pki/`, `cache/` and `runs/` (plan and apply logs).
3. **Secrets are created where they are used.**
   - The CA key exists only in the site directory.
   - Each server key exists only on its server.
   - Pre-auth keys are single-use and expire in 10 minutes. They are piped over SSH and never printed, logged or written on the operator's machine.
4. **No telemetry.**
   - Headscale runs with `logtail.enabled: false`.
   - tailscaled runs with `--no-logs-no-support`.
   - A region can set `official_derp = false` so its devices never use third-party relays.
5. **No public names.** A private CA plus IP-based URLs means no public certificates (and so no CT log entries) and no public DNS records.
6. **Shareable output.** `--redact` on every command that prints plans or status replaces addresses, host names and keys with stable placeholders, so the output can be shared when asking for help.

## Site configuration

`examples/site.example.toml` documents the schema:

- `[site]`;
- one `[regions.<name>]` per tailnet;
- optional `[hosts.<alias>]` with `tailscale_port` (a fixed UDP port for tailscaled), `netfilter_mode`, `region` (for hosts that neither control nor check a region) and `tags` (default: the region's `-server` tag, plus `-gateway` for a line initiator and `-border` for a line responder), used when a host joins;
- optional `[[lines]]`, each with `initiator`, `responder`, `responder_entry_ipv4`, `one_way`, and for the tunnel `port` (UDP on the entry) and `tunnel_ipv4` (a private /30: .1 initiator, .2 responder).

**Ask only what SSH cannot tell.** The tool derives the following over SSH and never asks for it:
- OS, architecture, root or sudo, systemd;
- listening ports and their owners;
- interface addresses, and the source address of the default route;
- whether the resolvers sit inside 100.64.0.0/10. If they do, the tool suggests `avoid_prefixes` and `netfilter_mode = off`.

`public_ipv4` comes from `ssh -G <alias>` when HostName is an IP address.

## Commands

| Command | Milestone | What it does |
| --- | --- | --- |
| `tn init` | 1 | Asks for the site name, regions (name, control host, checker host), lines (initiator, responder, entry address, one-way or not) and, per region, the ports a provider lets in to the control host (taken in order for HTTPS, STUN and Tailscale). Derives the rest over SSH, shows a summary and writes `site.toml`. |
| `tn site check` | 1 | Validates `site.toml`. Each prefix must sit inside 100.64.0.0/10, avoid its `avoid_prefixes` and not overlap another region. Region ids must be distinct, and every line must name existing hosts. |
| `tn control plan/apply/verify/rollback <region>` | 1 | Deploys Headscale for a region (steps below). |
| `tn status <region>` | 1 | Runs `headscale nodes list -o json` on the control host. |
| `tn join plan/apply <host>` | 2 | Adds a host to its region. |
| `tn line plan/apply <line>` | 2 | Builds a line. |
| `tn client mac/phone` | 3 | Sets up Mac clients and phone entries. |
| `tn doctor` | 3 | Checks isolation (no cross-region peers), paths and DERP use. |

Every command plans by default and changes nothing. `apply` asks for `yes` unless given `--yes`. A plan prints, per step, what it does and how it is undone; `--full` and the plan log in `runs/` add the exact remote script and rollback of every step.

## Milestone 1: control planes

For a region, `tn control apply` runs these steps:

1. **Preflight**, read-only. Check:
   - arch, OS, root, systemd, openssl and curl;
   - that the configured ports are free, or already used by our Headscale;
   - that no `/etc/headscale` exists unless it is ours.
2. **Binary.**
   - Download the pinned Headscale binary into `cache/` and verify its sha256.
   - Copy it to the host, verify again, and install it as `/usr/local/bin/headscale`.
3. **User and directories.** Create the `headscale` system user, `/etc/headscale/tls/` and `/var/lib/headscale/`.
4. **Certificate.**
   - Generate the server key and CSR on the host.
   - Sign the CSR with the site CA on the operator's machine. The certificate gets SAN = `public_ipv4`, plus `listen_ipv4` when that is a specific address; EKU `serverAuth`; and 825 days of validity.
   - Install the certificate on the host.
5. **Configuration.**
   - Write `config.yaml`, a bootstrap policy (`{}`) and the systemd unit. The unit uses `RuntimeDirectory=headscale` and `ExecReload` with SIGHUP.
   - Run `headscale configtest`.
6. **Start.** Run `systemctl enable --now headscale` and wait for the local `/health`.
7. **Real policy.**
   - Create `owner_user` and write the real policy. In it, the region's tags are owned by `owner_user`, every member reaches every member, and through each line every member reaches the other region's alias range.
   - Run `systemctl reload headscale` and check the journal for policy errors.
8. **Verify** from `check_from`:
   - `/health` over TLS with `curl --cacert`;
   - the DERP probe;
   - a STUN binding request (a small python3 script).

The rollback runs in reverse:
1. Stop and disable the unit.
2. Remove the unit, `/etc/headscale`, `/var/lib/headscale` and `/usr/local/bin/headscale`.
3. Remove the user.

Touch nothing else.

How `site.toml` maps to the Headscale config:

| Headscale key | From |
| --- | --- |
| `server_url` | `https://<public_ipv4>:<port>` |
| `listen_addr` | `<listen_ipv4>:<port>` |
| `derp.server.stun_listen_addr` | `<listen_ipv4>:<stun_port>` |
| `prefixes.v4` / `prefixes.v6` | `ipv4_prefix` / `fd7a:115c:a1e0::/48` |
| `derp.server.{enabled,region_id,region_code,region_name,ipv4,verify_clients}` | `true`, `derp_region_*`, `public_ipv4`, `true` |
| `derp.urls` | empty, or the official default map when `official_derp = true` |
| `dns` | `magic_dns: true`, `base_domain`, `override_local_dns: false`, no nameservers |
| `logtail.enabled` | `false` |
| `grpc_listen_addr`, `metrics_listen_addr` | `127.0.0.1` only |
| `tls_cert_path`, `tls_key_path` | `/etc/headscale/tls/server.{crt,key}` |
| `policy` | `mode: file`, `path: /etc/headscale/policy.hujson` |

Milestone 1 is done when:

1. `make check` passes.
2. `tn init` can rebuild the owner's `site.toml` from SSH plus a few answers.
3. `tn control plan` for both regions of the owner's site prints every step with its rollback, and the owner approves.
4. After that approval, `apply` and `verify` pass for both regions.
5. You have sent the owner a short report in Chinese and stopped.

## Pinned versions and checked facts

**Versions:**
- Headscale 0.29.6, released 2026-10-24. Checksums: amd64 `7477c374949eea6fb7cf3cbff14dbef49e4d118d9a33557d6764a77ece617e53`, arm64 `7b3c792ebe10e1a81a0c8d9674aee8eb540e7dbb7ccb80a98b71024da4c72a48`. Minimum client version: 1.80.0.
- Tailscale 1.104.2, current stable.

**Headscale CLI** (0.29.6 source):
- `preauthkeys create` takes `--user <numeric id>`, `--reusable`, `--ephemeral`, `--expiration`/`-e` (default 1h) and `--tags` (comma list).
- `nodes tag -i <id> -t tag:a,tag:b`.
- `nodes approve-routes --identifier <id> --routes <cidrs>`.
- `auth register --user <user> --auth-id <id>`.
- `configtest`, `health` and `policy` subcommands exist.
- Tagged nodes are owned by the special user `tagged-devices`.

**Policy:**
- HuJSON, the same format as Tailscale. Prefer `grants` to `acls`.
- `autoApprovers.routes` maps a CIDR to tags, and those tags need `tagOwners`.
- Reload with SIGHUP.

## Milestone 2 notes

- **`tn join`.**
  - Pushes the static Tailscale build from the operator's machine and installs the site CA into the host's trust store.
  - Pipes a tagged, single-use, 10-minute pre-auth key over SSH.
  - Uses `--accept-dns=false`, and `--netfilter-mode=off` where the resolvers sit inside 100.64.0.0/10.
  - A control host joining its own control plane may need a local rule when its public address does not hairpin.
- **`tn line`.**
  - The initiator starts a plain WireGuard tunnel to `responder_entry_ipv4` and keeps it alive. The responder never sets an endpoint.
  - Each side advertises the other region's site addresses and masquerades on both hops.
  - On the responder, the entry address goes into its own network namespace: WireGuard is created there and moved back, so tailscaled never advertises the entry address. Where another service already binds that address, this needs a maintenance window.

## Release (owner decides when)

When milestones 1 and 2 work on the owner's site:
- choose a license;
- add an English section to the README;
- tag a version;
- publish.

The guard over all history must pass before the first push.
