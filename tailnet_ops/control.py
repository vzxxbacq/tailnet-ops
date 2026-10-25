"""`tn control`: deploy Headscale for one region, step by step."""

from . import VERSION, names, pins, pki, render, scripts
from .procedure import Action, Procedure, Step, StepError, fetch_pinned
from .site import ensure_private_dir, write_private

CA_PLACEHOLDER = "<site CA certificate from pki/ca.crt; created in step 4 if missing>"
CERT_PLACEHOLDER = "<server certificate signed on this machine in step 4>"

__all__ = ["CA_PLACEHOLDER", "CERT_PLACEHOLDER", "Deployment", "LocalOps", "StepError"]


class LocalOps:
    """Work on the operator's machine: download cache and the site CA."""

    def __init__(self, site, out=print):
        self.site = site
        self.out = out

    def cached_binary(self, arch):
        cache = ensure_private_dir(self.site.cache_dir)
        return fetch_pinned(pins.headscale_url(arch), cache / pins.headscale_asset(arch),
                            pins.HEADSCALE_SHA256[arch], self.out)

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
    errors = Procedure.errors + (pki.PKIError,)

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

    # --- running ------------------------------------------------------------

    def _control(self, body, args=(), privileged=True):
        script = scripts.wrap(self.prelude, body)
        return self.runner.run(self.region.control_host, script, args=args, privileged=privileged)

    def _checker(self, body):
        script = scripts.wrap(self.checker_prelude, body)
        return self.runner.run(self.region.check_from, script, privileged=False)

    def _run_preflight(self):
        self.facts.update(self._control(scripts.PREFLIGHT).facts())

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
        result = self._control(scripts.KEY_AND_CSR)
        csr = result.block("csr")
        if not csr:
            raise StepError("the host did not return a CSR")
        pem, reused = self.ops.server_cert(self.region, csr, result.block("crt"), result.block("ca"))
        if reused:
            self.out("    the installed certificate is current; kept it")
            return
        self._control(scripts.install_cert(pem, self.ops.ensure_ca()))

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

    def _run_verify(self):
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
        sans = ", ".join(f"IP:{ip}" for ip in r.cert_ips)
        arch_note = "the architecture preflight reports (amd64 or arm64)"
        steps = [
            Step(
                1, "Preflight",
                ["Check arch, OS, root, systemd and tools; that the configured ports are free or ours;",
                 "that nothing named headscale exists unless tailnet-ops made it. Changes nothing."],
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
                 "and mark both directories as made by tailnet-ops."],
                [Action(host, "create", scripts.USER_AND_DIRS, "control", True)],
                rollback=scripts.ROLLBACK_USER_AND_DIRS,
                rollback_note=f"remove {render.ETC} and {render.LIB} (with the database) and the user, if ours",
                run=self._run_user_and_dirs, brief="Create user headscale and its directories",
                undo_brief="remove them, the database and the user",
            ),
            Step(
                4, "Certificate",
                ["Make the server key and CSR on the host (the key never leaves it). Sign the CSR here",
                 f"with the site CA (created now if missing): SAN {sans}, EKU serverAuth,",
                 f"{pins.SERVER_CERT_DAYS} days. Install the certificate and the CA certificate.",
                 "A current certificate for the same key and SANs is kept."],
                [
                    Action(host, "key and CSR; prints the CSR and any current certificate", scripts.KEY_AND_CSR, "control", True),
                    Action("local", f"create pki/ca.key + pki/ca.crt if missing; sign; save pki/{r.name}-server.crt"),
                    Action(host, "install the certificate", scripts.install_cert(CERT_PLACEHOLDER, CA_PLACEHOLDER), "control", True),
                ],
                rollback=scripts.ROLLBACK_CERT,
                rollback_note="remove the server key and certificates on the host; the site CA here stays",
                run=self._run_cert, brief=f"Server key on the host, certificate for {sans}",
                undo_brief="remove the key and certificates",
            ),
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
            Step(
                9, "Verify",
                [f"From {checker}: /health over TLS trusting only the site CA, the DERP probe and",
                 "a STUN binding request. Read-only."],
                [Action(checker, "checks as the login user", scripts.verify(CA_PLACEHOLDER), "checker", False)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_verify,
                brief=f"Check TLS, DERP and STUN from {checker}",
            ),
        ]
        for number, step in enumerate(steps, 1):
            step.number = number
            step.host = checker if step.title == "Verify" else host
        return steps

    def header(self):
        r, site = self.region, self.site
        official = "on (fallback)" if r.official_derp else "off: devices use only this region's relay"
        avoid = f" · avoids {', '.join(r.avoid_prefixes)}" if r.avoid_prefixes else ""
        return "\n".join([
            f"Region {r.name} of site {site.name!r} · tailnet-ops {VERSION} · Headscale {pins.HEADSCALE_VERSION}",
            f"  control host  {r.control_host}  (scripts run as root over SSH)",
            f"  checker host  {r.check_from}  (read-only checks as its login user)",
            f"  server_url    {r.server_url}",
            f"  listens on    tcp {r.listen_ipv4}:{r.port} (HTTPS + DERP) · udp {r.listen_ipv4}:{r.stun_port} (STUN)",
            f"                tcp 127.0.0.1:{r.metrics_port} (metrics) · tcp 127.0.0.1:{r.grpc_port} (gRPC)",
            *([f"  reserves      udp {host.tailscale_port} for Tailscale on {r.control_host} (checked in preflight; used when it joins)"]
              if (host := site.host_settings.get(r.control_host)) and host.tailscale_port else []),
            f"  tailnet       {r.ipv4_prefix} · {pins.IPV6_PREFIX}{avoid} · MagicDNS {r.base_domain}",
            f"  DERP          embedded region {r.derp_region_id} {r.derp_region_code!r} ({r.derp_region_name}); official map {official}",
            f"  certificate   SAN {', '.join('IP:' + ip for ip in r.cert_ips)}, signed by the site CA in pki/",
            f"  adds          {render.BIN}, user headscale, {render.ETC}/, {render.LIB}/, headscale.service,",
            f"                {names.KEEPER_UNIT}.timer (names every {names.KEEPER_MINUTES} minute(s))",
            *([f"  names         swapped with {', '.join(self._peer_controls())} over SSH, by a key that can only "
               "swap names"] if self._peer_controls() else []),
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
        return self.run_once(self._run_preflight)

    def verify(self):
        return self.run_once(self._run_verify)

    def status(self):
        return self.run_once(lambda: self._control(scripts.STATUS))
