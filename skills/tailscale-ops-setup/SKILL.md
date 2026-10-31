---
name: tailscale-ops-setup
description: Build someone a self-hosted Tailscale network (Headscale) with tailscale-ops, on servers you reach over SSH. Ask what they need, install it step by step with their OK, then hand it over so that they hold the keys and approve every later change with a passkey.
---

# Set up a tailnet with tailscale-ops

Someone asked you to build them a private network ("tailnet") with this repository. Tailscale clients
on their machines talk to a control server, Headscale, that you install on one of their servers. You
work from your own machine with this repository and SSH access to their servers.

The owner is the person who asked. Until the hand-over at the end, you have root on their servers,
so each step needs their OK in chat. After the hand-over they hold the site's keys, you keep no root
access, and every later join or leave waits for their passkey.

## Rules

1. **Ask first.** Install nothing until the owner has answered the questions below and agreed to
   what you will build.
2. **Plan, summarise, then apply.** Every `tn` command that changes a server has a `plan` that
   changes nothing. Run it and give the owner a short summary: what changes, on which host, and how
   it is undone. Run `apply --yes` only after they say yes to that plan. One yes covers one plan.
3. **Leave what runs alone.** tn takes free ports only and never touches what it did not make. If a
   preflight says a port or a name is taken, ask the owner. Never force it, and never stop their services.
4. **Secrets stay out of sight.** Put the Cloudflare token only in your shell's environment
   (`export CF_Token=…`, typed without echoing it back). Never write it to a file, a command you show,
   a log or the chat. Never show private keys. The site directory holds the network's keys: keep it
   out of every Git repository.
5. **On failure, stop.** Report the line starting with `tn:` and what the plan said. Running `apply`
   again is safe. Never run `tn control rollback` on a region that has machines in it: it deletes
   Headscale and its database. Use it only if the owner explicitly asks.
6. **Talk like the owner.** Use their language and keep it short. A table beats paragraphs. Explain
   a term the first time you use it.

## What you need

- On your machine: this repository (`git clone https://github.com/vzxxbacq/tailscale-ops`),
  Python 3.11 or newer, `ssh` and `curl`. Run tn as `./tn` from the repository.
- SSH to each server, as root or as a user with passwordless sudo. The servers run Linux with
  systemd (or OpenRC), on amd64 or arm64.
- One SSH alias per server in `~/.ssh/config`. tn names servers by alias:

  ```
  Host web1
    HostName 203.0.113.20
    User root
    IdentityFile ~/.ssh/id_ed25519
  ```

## 1. Ask what they need

Ask in one or two messages, not one question at a time. Skip what you already know, and explain why
you ask where it is not obvious.

1. **What should the network connect?** Servers only, or also their laptops and phones?
2. **Which servers, and can you reach them over SSH?** Get the address and user of each. Which one
   runs the control server? It needs a public IPv4 address and stays on.
3. **Are the machines in places that reach each other badly**, for example mainland China and
   abroad? Then use one region per place: one control server and one tailnet each, optionally joined
   by a **line** (a dedicated WireGuard tunnel between two servers, which may be one-way). Otherwise
   one region is enough. Name each region (`home`, `cn`, `eu`, …).
4. **Does the provider limit inbound ports** on the control server? If so, which ones? tn needs
   three: HTTPS with the relay (TCP), STUN (UDP), and the server's own Tailscale (UDP). Without limits,
   tn picks free ports itself.
5. **Is there a domain on Cloudflare?** With one, each region gets:
   - a trusted certificate (Let's Encrypt), so devices need no extra setup;
   - **tn-agent**, a small service behind a Cloudflare tunnel. There the owner approves every later
     join and leave with a passkey, and Agents manage machines through it (MCP).

   It takes a Cloudflare API token, which they make at
   https://dash.cloudflare.com/profile/api-tokens → Create Token → Custom token:
   - permissions: Zone · Zone · Read, Zone · DNS · Edit, and Account · Cloudflare Tunnel · Edit;
   - resources: Include · Specific zone · their zone, and Include · their account.

   The token is kept on the control server (root only) to renew the certificate. Without a domain,
   every device must trust a private certificate authority that tn makes, and there is no approval
   page.
6. **A second machine per region to check from.** Any server you can SSH to that reaches the control
   server's public address from outside. With a single server, use the control server itself. Its
   checks then go to its own public address, which some providers do not loop back. If only those
   checks fail, say so; the network itself may still be fine.
7. **Phones.** A phone runs one VPN at a time. If the owner uses a proxy app (Clash, Stash, …), tn
   adds a phone entry on the control server: one more UDP port. Ask which phones and which app.

Then write back, in a small table, what you will build: regions, control servers, domains, lines,
phones and the machines that join. Wait for their OK.

## 2. Write the site

Write the answers as JSON in a file outside the repository, for example `~/tn-answers.json`:

```json
{
  "site": "home",
  "regions": [
    {"name": "home", "control_host": "web1", "check_from": "web2",
     "domain": "hs-home.example.com", "agent_domain": "agent-home.example.com", "entry_port": 51820}
  ]
}
```

| Key | Meaning |
| --- | --- |
| `site`, `owner_user`, `dns_suffix` | Optional: a name for the site (`home`), the Headscale user (`owner`), the suffix of every name (`tailnet.internal`) |
| `regions[].name`, `control_host`, `check_from` | The region, the SSH alias of its control server, and of the host it is checked from |
| `regions[].ports` | Only if the provider limits ports: `"20000-20002"` or `[20000, 20001, 20002]`, in the order HTTPS, STUN, Tailscale |
| `regions[].domain` | The login server's name, on Cloudflare (DNS only, not proxied); tn makes its A record |
| `regions[].agent_domain` | tn-agent's name (needs `domain`): another name in the same zone, outside the tailnet's DNS suffix |
| `regions[].entry_port` | A free UDP port for the phone entry |
| `regions[].public_ipv4` | Only if the SSH HostName is not the public IPv4 address |
| `regions[].official_derp`, `ipv4_prefix` | Rarely needed: also use Tailscale's relays as a fallback; a fixed /24 inside 100.64.0.0/10 |
| `lines[]` | `name`, `initiator`, `responder` (SSH aliases), `responder_entry_ipv4`, `port` (UDP), `one_way` (default true) |

Then:

```
./tn init --answers ~/tn-answers.json         # reads facts over SSH (read-only) and prints site.toml
./tn init --answers ~/tn-answers.json --yes   # writes it to ~/.config/tailnet-ops/site.toml
./tn site check
```

tn reports a wrong answer by its key; fix it and run tn again. The printed `site.toml` shows the
ports tn chose and why. Tell the owner if a port moved because one was taken.

## 3. Control servers

For each region (the token is needed only with a domain):

```
export CF_Token=…                    # typed, not shown
./tn control plan <region>           # summarise for the owner, wait for yes
./tn control apply <region> --yes
./tn control verify <region>
```

## 4. tn-agent and the owner's passkey (regions with a domain)

```
./tn agent plan <region>             # summarise, wait for yes
./tn agent apply <region> --yes
./tn agent verify <region>
./tn agent enroll <region> --yes     # prints a one-time link, valid for 10 minutes
```

Send the link to the owner as it is, and say what it does: it registers their passkey on their
phone or laptop, and that passkey approves every later change. Never open it yourself: whoever opens
it first owns the approvals. Once they have registered, they can make MCP tokens at
`https://<agent_domain>/tokens`.

## 5. Lines and names (several regions)

```
./tn line plan <line>                # summarise, wait for yes
./tn line apply <line> --yes
./tn line verify <line>
./tn dns sync --yes                  # names of every region's hosts, in every region
```

## 6. Machines

- **Servers you reach over SSH:** `./tn join plan <alias> --region <region>`, summarise, then
  `./tn join apply <alias> --region <region> --yes`.
- **Phones (with `entry_port`):** `./tn phone add <name> --yes` writes the phone's WireGuard and
  Clash files into the site directory. They hold the phone's private key, so they go to the owner
  with the site directory (step 7), never through the chat.
- **The owner's laptops:** they join after the hand-over, from the laptop itself with the site
  directory: `./tn join` asks how. A Mac with the Tailscale app uses `./tn join plan <name> --app`.

Check the result with `./tn status <region>`.

## 7. Hand over

1. **Report.** Give a table of each region's login server, its machines and their addresses, and
   what is left to do (laptops, phones).
2. **The site directory goes to the owner.** It holds the network's keys and lets them run tn
   themselves. Put it on their control server, readable by root only:

   ```
   tar czf - -C ~/.config tailnet-ops | ssh <control> 'sudo sh -c "umask 077; cat > /root/tailscale-ops-site.tgz"'
   ```

   Then tell them how to fetch it with their own SSH access, unpack it to `~/.config/tailnet-ops/`
   on their computer, and delete the copy on the server. Also give them the `Host` blocks of your
   `~/.ssh/config` without your key paths, because tn names the servers by those aliases. Once they
   confirm they have it, delete yours: `rm -rf ~/.config/tailnet-ops ~/tn-answers.json`.
3. **Your SSH access goes.** First make sure the owner can log in to every server themselves (ask
   them to try). Then remove your own key from each server: delete only that line of
   `authorized_keys`, after telling them which line it is (its comment or fingerprint). If they prefer
   to do it themselves, tell them which line.
4. **From now on**, you or another Agent manage machines through tn-agent, if the owner wants that.
   They make a token at `https://<agent_domain>/tokens` and add the MCP server
   `https://<agent_domain>/mcp` with the header `Authorization: Bearer <token>`. Then follow
   `skills/tailscale-ops/SKILL.md`: every join and leave waits for their passkey.
