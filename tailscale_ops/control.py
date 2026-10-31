"""`tn control`: deploy Headscale for one region, step by step."""

from . import VERSION, acme, entry, names, pins, pki, render, scripts
from .cloudflare import Cloudflare, CloudflareError, in_the_way
from .procedure import Action, Procedure, Step, StepError, fetch_pinned
from .site import ensure_private_dir, write_private

CA_PLACEHOLDER = "<site CA certificate from pki/ca.crt; created in step 4 if missing>"
CERT_PLACEHOLDER = "<server certificate signed on this machine in step 4>"

__all__ = ["CA_PLACEHOLDER", "CERT_PLACEHOLDER", "Deployment", "LocalOps", "StepError"]

PERMISSIONS = "Zone · Zone · Read and Zone · DNS · Edit on the domain's zone"


class LocalOps:
    """Work on the operator's machine: download cache and the site CA."""

    def __init__(self, site, out=print):
        self.site = site
        self.out = out

    def cached_binary(self, arch):
        cache = ensure_private_dir(self.site.cache_dir)
        return fetch_pinned(pins.headscale_url(arch), cache / pins.headscale_asset(arch),
                            pins.HEADSCALE_SHA256[arch], self.out)

    def acme_files(self):
        """{name in the staging directory: path} for the pinned acme.sh files, downloaded once."""
        folder = ensure_private_dir(self.site.cache_dir / f"acme.sh-{pins.ACME_SH_VERSION}")
        return {acme.staged_name(path): fetch_pinned(pins.acme_url(path), folder / acme.staged_name(path), want,
                                                     self.out)
                for path, want in pins.ACME_SH_SHA256.items()}

    def ensure_ca(self):
        created, pem = pki.ensure_ca(self.site.pki_dir, self.site.name)
        if created:
            self.out(f"    created the site CA in {self.site.pki_dir} (EC P-256, {pins.CA_DAYS} days)")
        return pem

    def ca_pem(self):
        _key, crt = pki.ca_paths(self.site.pki_dir)
        return crt.read_text() if crt.exists() else None

    def server_cert(self, region, csr, existing, host_ca):
        """Return (pem, reused)."""
        ca = self.ensure_ca()
        ips = region.cert_ips
        if existing and host_ca == ca and pki.cert_is_current(self.site.pki_dir, existing, csr, ips):
            return existing, True
        pem = pki.sign(self.site.pki_dir, csr, ips)
        write_private(self.site.pki_dir / f"{region.name}-server.crt", pem)
        self.out(f"    signed a server certificate for {', '.join('IP:' + ip for ip in ips)} ({pins.SERVER_CERT_DAYS} days)")
        return pem, False


class Deployment(Procedure):
    command = "control"
    errors = Procedure.errors + (pki.PKIError, CloudflareError)

    def __init__(self, site, region_name, runner=None, ops=None, out=print, ssh_view=None):
        self.site = site
        self.region = site.region(region_name)
        self.subject = self.region.name
        self.target = self.region.control_host
        self.runner = runner
        self.out = out
        self.ops = ops or LocalOps(site, out)
        self.prelude = scripts.control_prelude(site, self.region)
        self.checker_prelude = scripts.checker_prelude(self.region)
        self.facts = {}
        self.names = names.Names(site, runner, out, ssh_view=ssh_view)
        self.entry_found = None  # the firewall chains that would drop phone traffic, from the entry's checks
        self.ask_token = None    # set by the CLI: (quiet) -> a Cloudflare API token, or None; quiet: do not prompt
        self._token = None
        self.cloudflare = Cloudflare
        self.dns_mark = f"tailnet-ops region={self.region.name}"   # the comment on the A record tn makes

    # --- running ------------------------------------------------------------

    def _control(self, body, args=(), privileged=True):
        script = scripts.wrap(self.prelude, body)
        return self.runner.run(self.region.control_host, script, args=args, privileged=privileged)

    def _checker(self, body):
        script = scripts.wrap(self.checker_prelude, body)
        return self.runner.run(self.region.check_from, script, privileged=False)

    def token(self, ask=True):
        """The Cloudflare API token: from $CF_Token, else asked for once (not when ask is False)."""
        if self._token is None and self.ask_token:
            self._token = self.ask_token(quiet=not ask) or None
        return self._token

    def _cloudflare(self, ask=True):
        token = self.token(ask)
        if not token:
            raise StepError(f"needs a Cloudflare API token ({PERMISSIONS}): run this in a terminal to paste it, "
                            "or set CF_Token")
        cf = self.cloudflare(token)
        return cf, cf.zone_for(self.region.domain)

    def _dns_check(self):
        """How the host's preflight treats the domain: "check" it when Cloudflare has the A record as wanted;
        "skip" it when step 4 makes or fixes the record (a lookup now would leave the old answer cached);
        "soft" (look, but do not fail) when there is no token to ask Cloudflare."""
        r = self.region
        if not self.token(ask=False):
            return "soft"
        cf, zone = self._cloudflare(ask=False)
        state, rec, _found = cf.record_state(zone, r.domain, "A", r.public_ipv4, False, self.dns_mark)
        if state == "foreign":
            raise StepError("Cloudflare: " + in_the_way(rec, r.domain, "A", r.public_ipv4, False))
        if state == "ok":
            self.out(f"  ok    Cloudflare: {r.domain} A {r.public_ipv4}, DNS only")
            return "check"
        self.out(f"  note  Cloudflare: step 4 {'makes' if state == 'absent' else 'fixes'} {r.domain} A "
                 f"{r.public_ipv4}, DNS only, in zone {zone['name']}")
        return "skip"

    def _run_preflight(self):
        args = [] if self.region.site_ca else [self._dns_check()]
        self.facts.update(self._control(scripts.PREFLIGHT, args=args).facts())

    def _run_dns(self):
        r = self.region
        if self.facts.get("dns") == "ok" and not self.token(ask=False):
            self.out(f"    {r.domain} resolves to {r.public_ipv4} already; no Cloudflare token needed for it")
            return
        cf, zone = self._cloudflare()
        done = cf.ensure_record(zone, r.domain, "A", r.public_ipv4, False, self.dns_mark)
        self.out(f"    Cloudflare: {r.domain} A {r.public_ipv4}, DNS only: {done}")

    def _undo_letsencrypt(self):
        self._control(scripts.ROLLBACK_CERT)
        if not self.token(ask=False):
            self.out(f"    no Cloudflare token: the A record {self.region.domain} stays; delete it there if you want")
            return
        cf, zone = self._cloudflare()
        gone = cf.delete_record(zone, self.region.domain, self.dns_mark)
        self.out(f"    Cloudflare: deleted {gone} record(s) {self.region.domain} made by tailscale-ops")

    def _run_binary(self):
        arch = self.facts.get("arch")
        if arch not in pins.HEADSCALE_SHA256:
            raise StepError("preflight did not report a supported architecture")
        want = pins.HEADSCALE_SHA256[arch]
        if self.facts.get("installed") == want:
            self.out(f"    {render.BIN} is already the pinned build; nothing to upload")
            return
        path = self.ops.cached_binary(arch)
        stage = self._control(scripts.STAGE, privileged=False).facts().get("stage", "")
        if not stage.startswith("/tmp/tn-headscale."):
            raise StepError(f"unexpected staging directory {stage!r}")
        self.out(f"    uploading {path.name} to {stage}/")
        self.runner.upload(self.region.control_host, path, f"{stage}/headscale")
        self._control(scripts.INSTALL_BINARY, args=[stage])

    def _run_user_and_dirs(self):
        self._control(scripts.USER_AND_DIRS)

    def _run_cert(self):
        if not self.region.site_ca:
            self._run_letsencrypt()
            return
        result = self._control(scripts.KEY_AND_CSR)
        csr = result.block("csr")
        if not csr:
            raise StepError("the host did not return a CSR")
        pem, reused = self.ops.server_cert(self.region, csr, result.block("crt"), result.block("ca"))
        if reused:
            self.out("    the installed certificate is current; kept it")
            return
        self._control(scripts.install_cert(pem, self.ops.ensure_ca()))

    def _run_letsencrypt(self):
        host = self.region.control_host
        self._run_dns()
        facts = self._control(acme.STATE).facts()
        want = {acme.staged_name(p): s for p, s in pins.ACME_SH_SHA256.items()}
        if (facts.get("acme_sh"), facts.get("dns_cf")) == (want["acme.sh"], want["dns_cf.sh"]):
            self.out(f"    acme.sh {pins.ACME_SH_VERSION} is already installed")
        else:
            files = self.ops.acme_files()
            stage = self._control(acme.STAGE, privileged=False).facts().get("stage", "")
            if not stage.startswith("/tmp/tn-acme."):
                raise StepError(f"unexpected staging directory {stage!r}")
            for name, path in files.items():
                self.out(f"    uploading {name} to {stage}/")
                self.runner.upload(host, path, f"{stage}/{name}")
            self._control(acme.install(), args=[stage])
        if facts.get("token") == "yes":
            self.out(f"    {host} has the Cloudflare API token already")
        else:
            token = self.token()
            if not token:
                raise StepError(f"needs a Cloudflare API token ({PERMISSIONS}): run tn control apply in a terminal "
                                "to paste it, or set CF_Token")
            self.out(f"    the token goes to {acme.TOKEN_FILE} on {host} over SSH stdin; it is not logged or kept here")
            self.runner.feed(host, acme.save_token_argv(), token, what="the Cloudflare API token")
        self._control(acme.issue(self.region))

    def _run_config(self):
        self._control(self.configuration_body())

    def _run_start(self):
        self._control(scripts.START)

    def _run_policy(self):
        self._control(scripts.real_policy(render.policy(self.site, self.region)))

    def _run_names(self):
        self._control(names.install(self.site, self.region))
        self.names.sync(tolerant=True)

    def _undo_names(self):
        self._control(self._names_rollback())
        self.names.sync(tolerant=True, gone=(self.region.name,))

    def _names_rollback(self):
        return names.uninstall(self.site, self.names.ssh_view(self.region.control_host).get("user", "root"))

    def _peer_controls(self):
        return sorted({other.control_host for _ln, other in render.line_peers(self.site, self.region)})

    def _entry_check(self):
        result = self._control(entry.check(self.site, self.region))
        self.entry_found = entry.targets(result)
        for hook, found in self.entry_found.items():
            for t in found:
                self.out(f"    firewall: {t.label()} could drop phone traffic ({hook}, {t.reason}); "
                         "the entry adds tagged accept rules there")
        if not any(self.entry_found.values()):
            self.out("    firewall: nothing would drop phone traffic")
        return result

    def _run_entry(self):
        result = self._entry_check()
        pub = self._control(self.entry_body(self.entry_found, result.facts().get("forward", "1"))).facts().get("pub")
        if pub:
            self.out(f"    entry public key {pub}; add a phone with: tn phone add <name>")

    def entry_body(self, found=None, forward="1"):
        return entry.start(self.site, self.region, found or {}, forward)

    def _run_verify(self):
        if not self.region.site_ca:
            self._checker(scripts.verify())
            return
        ca = self.ops.ca_pem()
        if ca is None:
            raise StepError(f"no site CA in {self.site.pki_dir}; run `tn control apply {self.region.name}` first")
        self._checker(scripts.verify(ca))

    def configuration_body(self):
        return scripts.configuration(render.headscale_config(self.site, self.region), render.systemd_unit(self.region))

    # --- the steps ----------------------------------------------------------

    def steps(self):
        r = self.region
        host, checker = r.control_host, r.check_from
        arch_note = "the architecture preflight reports (amd64 or arm64)"
        steps = [
            Step(
                1, "Preflight",
                ["Check arch, OS, root, systemd and tools; that the configured ports are free or ours;",
                 "that nothing named headscale exists unless tailscale-ops made it. Changes nothing."],
                [Action(host, "read-only checks", scripts.PREFLIGHT, "control", True)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_preflight,
                brief="Check the host",
            ),
            Step(
                2, "Binary",
                [f"Download Headscale {pins.HEADSCALE_VERSION} for {arch_note} into cache/ and check its",
                 f"pinned sha256; copy it to {host}, check again, install as {render.BIN}.",
                 "Skipped when the pinned build is already installed."],
                [
                    Action("local", f"fetch {pins.headscale_url('<arch>')} unless cached; verify sha256 "
                           f"(amd64 {pins.HEADSCALE_SHA256['amd64'][:12]}…, arm64 {pins.HEADSCALE_SHA256['arm64'][:12]}…)"),
                    Action(host, "make a staging directory", scripts.STAGE, "control", False),
                    Action("local", "scp the binary to <staging directory>/headscale"),
                    Action(host, "verify and install; $1 is the staging directory", scripts.INSTALL_BINARY, "control", True),
                ],
                rollback=scripts.ROLLBACK_BINARY, rollback_note=f"remove {render.BIN} if it is the pinned build",
                run=self._run_binary, brief=f"Install Headscale {pins.HEADSCALE_VERSION}", undo_brief="remove the binary",
            ),
            Step(
                3, "User and directories",
                [f"Create the system user and group headscale, {render.ETC}/tls/ and {render.LIB}/,",
                 "and mark both directories as made by tailscale-ops."],
                [Action(host, "create", scripts.USER_AND_DIRS, "control", True)],
                rollback=scripts.ROLLBACK_USER_AND_DIRS,
                rollback_note=f"remove {render.ETC} and {render.LIB} (with the database) and the user, if ours",
                run=self._run_user_and_dirs, brief="Create user headscale and its directories",
                undo_brief="remove them, the database and the user",
            ),
            self._cert_step(),
            Step(
                5, "Configuration",
                [f"Write {render.ETC}/config.yaml, a bootstrap policy {{}} (only if no policy exists yet)",
                 f"and {render.UNIT}; run headscale configtest as the headscale user."],
                [Action(host, "write files and test", self.configuration_body(), "control", True)],
                rollback=scripts.ROLLBACK_CONFIGURATION, rollback_note="remove the unit, config.yaml and the policy",
                run=self._run_config, brief="Write config, policy {} and unit; configtest",
                undo_brief="remove the unit, config and policy",
            ),
            Step(
                6, "Start",
                ["systemctl enable --now headscale; restart if files changed while it ran;",
                 f"wait for /health over TLS on {r.local_ipv4}:{r.port}."],
                [Action(host, "start", scripts.START, "control", True)],
                rollback=scripts.ROLLBACK_START, rollback_note="stop and disable the unit",
                run=self._run_start, brief="Start headscale, wait for /health", undo_brief="stop and disable it",
            ),
            Step(
                7, "Real policy",
                [f"Create the Headscale user {self.site.owner_user}; write the real policy: {', '.join(r.tags)}",
                 f"are owned by {self.site.owner_user}@, the tagged servers reach each other and",
                 f"{self.site.owner_user}@ reaches all of them. Check it, reload with SIGHUP, read the journal."],
                [Action(host, "policy", scripts.real_policy(render.policy(self.site, r)), "control", True)],
                rollback_note=f"nothing separate: the user lives in {render.LIB} and the policy in {render.ETC}; "
                              "step 3's rollback removes both",
                run=self._run_policy, brief=f"Create user {self.site.owner_user}, load the real policy",
                undo_brief="removed with step 3",
            ),
            Step(
                8, "Names",
                [f"Install a keeper with its own SSH key and a timer: every {names.KEEPER_MINUTES} minute(s) it writes the",
                 f"names of this region's hosts to {render.EXTRA_RECORDS}, and those of each region it reaches",
                 "through a line. The control host on a line's initiator side calls the other one over SSH with",
                 "a key that can only swap the two lists. Then every region's names are updated: each keeper",
                 "gets its peers, their host keys and their lists; a control host without one gets the records."],
                [Action(host, "install the keeper, its key and its timer", names.install(self.site, r), "control", True),
                 *[Action(peer, "pair with this region (peers, host keys, the key that may call, the lists)",
                          names.KEEPER_VARS + "# names_put $NAMES_DIR/peers/<region>.conf, $NAMES_STATE/<region>.tsv,\n"
                          "# $NAMES_DIR/known_hosts; names_authorize <SSH user> <restrict,command=... lines>\n",
                          "control", True) for peer in self._peer_controls()]],
                rollback=self._names_rollback(),
                rollback_note="stop and remove the keeper and its keys; the other regions drop this region's names",
                run=self._run_names, undo=self._undo_names,
                brief=f"Names keeper, every {names.KEEPER_MINUTES} minute(s)"
                      + (f"; swaps names with {', '.join(self._peer_controls())}" if self._peer_controls() else ""),
                undo_brief="remove it; the others drop these names",
            ),
            *([self._entry_step()] if r.entry_port else []),
            Step(
                9, "Verify",
                [f"From {checker}: /health over TLS "
                 + ("trusting only the site CA" if r.site_ca else "with its own trust store, by name") + ", the DERP probe",
                 "and a STUN binding request. Read-only."],
                [Action(checker, "checks as the login user", scripts.verify(CA_PLACEHOLDER if r.site_ca else None),
                        "checker", False)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_verify,
                brief=f"Check TLS, DERP and STUN from {checker}",
            ),
        ]
        for number, step in enumerate(steps, 1):
            step.number = number
            step.host = checker if step.title == "Verify" else host
        return steps

    def _cert_step(self):
        r, host = self.region, self.region.control_host
        if r.site_ca:
            sans = ", ".join(f"IP:{ip}" for ip in r.cert_ips)
            return Step(
                4, "Certificate",
                ["Make the server key and CSR on the host (the key never leaves it). Sign the CSR here",
                 f"with the site CA (created now if missing): SAN {sans}, EKU serverAuth,",
                 f"{pins.SERVER_CERT_DAYS} days. Install the certificate and the CA certificate.",
                 "A current certificate for the same key and SANs is kept. A Let's Encrypt renewal from before is removed."],
                [
                    Action(host, "key and CSR; prints the CSR and any current certificate", scripts.KEY_AND_CSR, "control", True),
                    Action("local", f"create pki/ca.key + pki/ca.crt if missing; sign; save pki/{r.name}-server.crt"),
                    Action(host, "install the certificate", scripts.install_cert(CERT_PLACEHOLDER, CA_PLACEHOLDER), "control", True),
                ],
                rollback=scripts.ROLLBACK_CERT,
                rollback_note="remove the server key and certificates on the host; the site CA here stays",
                run=self._run_cert, brief=f"Server key on the host, certificate for {sans}",
                undo_brief="remove the key and certificates",
            )
        files = ", ".join(pins.ACME_SH_SHA256)
        return Step(
            4, "Certificate",
            [f"First, through the Cloudflare API from here: the A record {r.domain} -> {r.public_ipv4}, DNS only,",
             f"marked \"{self.dns_mark}\" (a record tn did not make is never changed). Then",
             f"a Let's Encrypt certificate for {r.domain}. acme.sh {pins.ACME_SH_VERSION} ({files}, each checked",
             f"against its pinned sha256) goes to {acme.DIR}, root only. It proves the name with a DNS-01 TXT",
             "record made through the Cloudflare API, so no port is opened. The API token is asked for once,",
             f"goes over SSH stdin into {acme.TOKEN_FILE} and is never logged. The certificate and its key",
             f"go to {render.ETC}/tls; {acme.TIMER.rsplit('/', 1)[-1]} renews them daily when due and restarts Headscale.",
             "A current certificate is kept."],
            [
                Action("local", f"Cloudflare API: make or fix A {r.domain} -> {r.public_ipv4}, DNS only, "
                       f"comment \"{self.dns_mark}\""),
                Action(host, "what is installed (read-only)", acme.STATE, "control", True),
                Action("local", f"only if acme.sh is missing or another build: fetch {pins.acme_url('<file>')} "
                       "into cache/ unless there, verify sha256"),
                Action(host, "make a staging directory", acme.STAGE, "control", False),
                Action("local", "scp acme.sh and dns_cf.sh to <staging directory>/"),
                Action(host, "verify and install; $1 is the staging directory", acme.install(), "control", True),
                Action(host, f"only if the host has no token: sh -c '<this>' sh {acme.DIR}, with the token "
                       "pasted here on stdin", acme.SAVE_TOKEN, None, True),
                Action(host, "get or keep the certificate, install it, enable the renewal timer", acme.issue(r),
                       "control", True),
            ],
            rollback=scripts.ROLLBACK_CERT, undo=self._undo_letsencrypt,
            rollback_note=f"remove the renewal timer, {acme.DIR} (with the token) and the key and certificate, and "
                          "the A record if tn made it; delete the token in Cloudflare too",
            run=self._run_cert, brief=f"A record and Let's Encrypt certificate for {r.domain}",
            undo_brief="remove them, acme.sh and the token",
        )

    def _entry_step(self):
        site, r = self.site, self.region
        across = ", ".join(f"{o.name} {o.ipv4_prefix} (as {o.alias_net})" for o in entry.reached(site, r))
        return Step(
            0, "Phone entry",
            [f"WireGuard for phones' proxy apps: {entry.IFACE} {site.entry_address}/{site.entry_net.prefixlen} on "
             f"udp/{r.entry_port}, with a key made on the host.",
             f"Phones reach {r.ipv4_prefix}" + (f" and, through the line, {across}" if across else "")
             + " and nothing else;",
             f"they are masqueraded (nft table {entry.TABLE}). Firewall chains that would drop this traffic get",
             "tagged accept rules, kept by a timer: the checks find those chains and the accept-rules script",
             f"lists them (shown here without any). Peers: the phones in phones.json ({len(site.phones)} now; "
             "tn phone add)."],
            [Action(r.control_host, "read-only checks: tools, files, port, range; read the firewall",
                    entry.check(site, r), "control", True),
             Action(r.control_host, "key, nft table, accept rules, conf and timer; start; set the peers",
                    self.entry_body(), "control", True)],
            rollback=entry.rollback(site, r),
            rollback_note=f"stop {entry.IFACE}; remove its key, nft table, accept rules, timer and files",
            run=self._run_entry,
            brief=f"Phone entry: WireGuard udp/{r.entry_port}, nft table {entry.TABLE}",
            undo_brief="stop it and remove all of it",
        )

    def header(self):
        r, site = self.region, self.site
        official = "on (fallback)" if r.official_derp else "off: devices use only this region's relay"
        avoid = f" · avoids {', '.join(r.avoid_prefixes)}" if r.avoid_prefixes else ""
        return "\n".join([
            f"Region {r.name} of site {site.name!r} · tailscale-ops {VERSION} · Headscale {pins.HEADSCALE_VERSION}",
            f"  control host  {r.control_host}  (scripts run as root over SSH)",
            f"  checker host  {r.check_from}  (read-only checks as its login user)",
            f"  server_url    {r.server_url}",
            f"  listens on    tcp {r.listen_ipv4}:{r.port} (HTTPS + DERP) · udp {r.listen_ipv4}:{r.stun_port} (STUN)",
            f"                tcp 127.0.0.1:{r.metrics_port} (metrics) · tcp 127.0.0.1:{r.grpc_port} (gRPC)",
            *([f"  reserves      udp {host.tailscale_port} for Tailscale on {r.control_host} (checked in preflight; used when it joins)"]
              if (host := site.host_settings.get(r.control_host)) and host.tailscale_port else []),
            f"  tailnet       {r.ipv4_prefix} · {pins.IPV6_PREFIX}{avoid} · MagicDNS {r.base_domain}",
            f"  DERP          embedded region {r.derp_region_id} {r.derp_region_code!r} ({r.derp_region_name}); official map {official}",
            (f"  certificate   SAN {', '.join('IP:' + ip for ip in r.cert_ips)}, signed by the site CA in pki/"
             if r.site_ca else
             f"  certificate   Let's Encrypt for {r.domain} (DNS-01 via Cloudflare), renewed by "
             f"{acme.TIMER.rsplit('/', 1)[-1]}; devices need no site CA"),
            f"  adds          {render.BIN}, user headscale, {render.ETC}/, {render.LIB}/, headscale.service,",
            f"                {names.KEEPER_UNIT}.timer (names every {names.KEEPER_MINUTES} minute(s))"
            + ("" if r.site_ca else f", {acme.DIR}/, {acme.TIMER.rsplit('/', 1)[-1]}"),
            *([f"  names         swapped with {', '.join(self._peer_controls())} over SSH, by a key that can only "
               "swap names"] if self._peer_controls() else []),
            *([f"  phone entry   udp {r.listen_ipv4}:{r.entry_port}, WireGuard {entry.IFACE} {site.entry_address}"
               f"/{site.entry_net.prefixlen}, nft table {entry.TABLE}, {len(site.phones)} phone(s);",
               "                tagged accept rules where a firewall chain would drop phone traffic"]
              if r.entry_port else []),
            "  leaves alone  every other file, user, service, port and firewall rule",
        ])

    def preludes(self):
        return [("control host", self.prelude), ("checker", self.checker_prelude)]

    def plan_intro(self):
        return (f"Every script on {self.region.control_host} runs as `bash -s` over SSH: this prelude, then the step body\n"
                "inside `tn_step() { ... }` with stdin from /dev/null. Scripts on the checker use the short prelude.")

    def rollback_footer(self):
        return "It keeps the site CA, the server certificate copy in pki/ and the download cache on this machine."

    def done_message(self):
        return (f"Region {self.region.name}: Headscale is up on {self.region.server_url} "
                f"and verified from {self.region.check_from}.")

    def rolled_back_message(self):
        return f"Rolled back region {self.region.name}. The site CA and cache on this machine are kept."

    def run_rollback(self, step):
        self._control(step.rollback)

    def preflight(self):
        def checks():
            self._run_preflight()
            if self.region.entry_port:
                self.out(f"  phone entry (step {next(s.number for s in self.steps() if s.title == 'Phone entry')}):")
                self._entry_check()
        return self.run_once(checks)

    def verify(self):
        return self.run_once(self._run_verify)

    def status(self):
        return self.run_once(lambda: self._control(scripts.STATUS))
