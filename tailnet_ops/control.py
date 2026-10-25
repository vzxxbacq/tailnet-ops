"""`tn control`: deploy Headscale for one region, step by step."""

import hashlib
import os
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import VERSION, pins, pki, render, scripts
from .remote import RemoteError
from .site import ensure_private_dir, write_private

CA_PLACEHOLDER = "<site CA certificate from pki/ca.crt; created in step 4 if missing>"
CERT_PLACEHOLDER = "<server certificate signed on this machine in step 4>"


class StepError(Exception):
    pass


@dataclass
class Action:
    where: str            # "local" or an SSH alias
    what: str
    body: str = None      # remote script body, printed verbatim
    prelude: str = None   # "control" or "checker"
    privileged: bool = False


@dataclass
class Step:
    number: int
    title: str
    what: list
    actions: list
    rollback: str = None
    rollback_note: str = ""
    read_only: bool = False
    run: object = field(default=None, repr=False)


class LocalOps:
    """Work on the operator's machine: download cache and the site CA."""

    def __init__(self, site, out=print):
        self.site = site
        self.out = out

    def cached_binary(self, arch):
        want = pins.HEADSCALE_SHA256[arch]
        cache = ensure_private_dir(self.site.cache_dir)
        path = cache / pins.headscale_asset(arch)
        if path.exists():
            if _sha256(path) == want:
                self.out(f"    cache: {path.name} (sha256 ok)")
                return path
            raise StepError(f"{path} does not match the pinned sha256; delete it and retry")
        url = pins.headscale_url(arch)
        self.out(f"    downloading {url}")
        part = path.with_name(path.name + ".part")
        digest = hashlib.sha256()
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f, urllib.request.urlopen(url, timeout=60) as resp:
            while chunk := resp.read(1 << 20):
                f.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != want:
            part.unlink()
            raise StepError(f"download does not match the pinned sha256 (got {digest.hexdigest()})")
        part.rename(path)
        self.out(f"    sha256 ok: {want}")
        return path

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


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _indent(text, pad="      "):
    return "\n".join(pad + line if line else "" for line in text.rstrip("\n").splitlines())


class Deployment:
    def __init__(self, site, region_name, runner=None, ops=None, out=print):
        self.site = site
        self.region = site.region(region_name)
        self.runner = runner
        self.out = out
        self.ops = ops or LocalOps(site, out)
        self.prelude = scripts.control_prelude(site, self.region)
        self.checker_prelude = scripts.checker_prelude(self.region)
        self.facts = {}

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
        return [
            Step(
                1, "Preflight",
                ["Check arch, OS, root, systemd and tools; that the configured ports are free or ours;",
                 "that nothing named headscale exists unless tailnet-ops made it. Changes nothing."],
                [Action(host, "read-only checks", scripts.PREFLIGHT, "control", True)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_preflight,
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
                run=self._run_binary,
            ),
            Step(
                3, "User and directories",
                [f"Create the system user and group headscale, {render.ETC}/tls/ and {render.LIB}/,",
                 "and mark both directories as made by tailnet-ops."],
                [Action(host, "create", scripts.USER_AND_DIRS, "control", True)],
                rollback=scripts.ROLLBACK_USER_AND_DIRS,
                rollback_note=f"remove {render.ETC} and {render.LIB} (with the database) and the user, if ours",
                run=self._run_user_and_dirs,
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
                run=self._run_cert,
            ),
            Step(
                5, "Configuration",
                [f"Write {render.ETC}/config.yaml, a bootstrap policy {{}} (only if no policy exists yet)",
                 f"and {render.UNIT}; run headscale configtest as the headscale user."],
                [Action(host, "write files and test", self.configuration_body(), "control", True)],
                rollback=scripts.ROLLBACK_CONFIGURATION, rollback_note="remove the unit, config.yaml and the policy",
                run=self._run_config,
            ),
            Step(
                6, "Start",
                ["systemctl enable --now headscale; restart if files changed while it ran;",
                 f"wait for /health over TLS on {r.local_ipv4}:{r.port}."],
                [Action(host, "start", scripts.START, "control", True)],
                rollback=scripts.ROLLBACK_START, rollback_note="stop and disable the unit",
                run=self._run_start,
            ),
            Step(
                7, "Real policy",
                [f"Create the Headscale user {self.site.owner_user}; write the real policy: {', '.join(r.tags)}",
                 f"are owned by {self.site.owner_user}@, the tagged servers reach each other and",
                 f"{self.site.owner_user}@ reaches all of them. Check it, reload with SIGHUP, read the journal."],
                [Action(host, "policy", scripts.real_policy(render.policy(self.site, r)), "control", True)],
                rollback_note=f"nothing separate: the user lives in {render.LIB} and the policy in {render.ETC}; "
                              "step 3's rollback removes both",
                run=self._run_policy,
            ),
            Step(
                8, "Verify",
                [f"From {checker}: /health over TLS trusting only the site CA, the DERP probe and",
                 "a STUN binding request. Read-only."],
                [Action(checker, "checks as the login user", scripts.verify(CA_PLACEHOLDER), "checker", False)],
                rollback_note="none needed (read-only)", read_only=True, run=self._run_verify,
            ),
        ]

    def rollback_steps(self):
        return [s for s in reversed(self.steps()) if s.rollback]

    # --- printing -------------------------------------------------------------

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
            f"  adds          {render.BIN}, user headscale, {render.ETC}/, {render.LIB}/, headscale.service",
            "  leaves alone  every other file, user, service, port and firewall rule",
        ])

    def plan_text(self):
        body = self._plan_body()
        digest = hashlib.sha256(body.encode()).hexdigest()[:12]
        return f"tn control plan {self.region.name}\nPlan id {digest}\n\n{body}", digest

    def plan_id(self):
        return self.plan_text()[1]

    def _plan_body(self):
        out = [self.header(), ""]
        out.append(
            f"Every script on {self.region.control_host} runs as `bash -s` over SSH: this prelude, then the step body\n"
            "inside `tn_step() { ... }` with stdin from /dev/null. Scripts on the checker use the short prelude."
        )
        out += ["", "  Prelude (control host):", _indent(self.prelude), "",
                "  Prelude (checker):", _indent(self.checker_prelude), ""]
        for step in self.steps():
            tag = "  [read-only]" if step.read_only else ""
            out.append(f"Step {step.number}/8  {step.title}{tag}")
            out += [f"  {line}" for line in step.what]
            for i, action in enumerate(step.actions, 1):
                label = f"{step.number}.{i}" if len(step.actions) > 1 else f"{step.number}"
                who = "this machine" if action.where == "local" else (
                    f"{action.where} as root" if action.privileged else f"{action.where} as the SSH user")
                out.append(f"  {label} on {who}: {action.what}")
                if action.body:
                    out.append(_indent(action.body))
            if step.rollback:
                out.append(f"  Rollback ({step.rollback_note}), as root on {self.region.control_host}:")
                out.append(_indent(step.rollback))
            else:
                out.append(f"  Rollback: {step.rollback_note}")
            out.append("")
        order = ", ".join(str(s.number) for s in self.rollback_steps())
        out.append(
            f"`tn control rollback {self.region.name}` runs the rollbacks of steps {order} in that order.\n"
            "It keeps the site CA, the server certificate copy in pki/ and the download cache on this machine."
        )
        return "\n".join(out) + "\n"

    # --- commands ---------------------------------------------------------------

    def _run_steps(self, steps, label):
        for step in steps:
            self.out(f"\n== {label} step {step.number}/8 {step.title} on "
                     f"{self.region.check_from if step.number == 8 else self.region.control_host}")
            try:
                step.run()
            except (RemoteError, StepError, pki.PKIError, OSError) as e:
                self.out(f"\nFAILED at step {step.number} ({step.title}): {e}")
                return step
        return None

    def apply(self, yes=False, ask=input):
        steps = self.steps()
        self.out(self.header())
        self.out(f"\nPlan id {self.plan_id()} (compare with the plan you approved)")
        for s in steps:
            self.out(f"  {s.number}. {s.title}{' (read-only)' if s.read_only else ''}")
        if not yes:
            answer = ask(f"Type yes to apply these steps to {self.region.control_host}: ")
            if answer.strip() != "yes":
                self.out("Not applied; nothing changed.")
                return 1
        failed = self._run_steps(steps, "apply")
        if failed is not None:
            done = failed.number - 1
            self.out(f"Steps 1-{done} completed; nothing after step {failed.number} ran." if done else
                     "Nothing was changed.")
            if done >= 2:
                self.out(f"Fix the cause and re-run apply (steps are idempotent), or undo with "
                         f"`tn control rollback {self.region.name}`.")
            return 1
        self.out(f"\nRegion {self.region.name}: Headscale is up on {self.region.server_url} and verified from {self.region.check_from}.")
        return 0

    def rollback(self, yes=False, ask=input):
        steps = self.rollback_steps()
        self.out(f"Rollback for region {self.region.name} on {self.region.control_host}:")
        for s in steps:
            self.out(f"  step {s.number} {s.title}: {s.rollback_note}")
        self.out("Only things marked as made by tailnet-ops are removed; anything else is reported and skipped.")
        if not yes:
            answer = ask(f"Type yes to roll back on {self.region.control_host}: ")
            if answer.strip() != "yes":
                self.out("Not rolled back; nothing changed.")
                return 1
        for s in steps:
            self.out(f"\n== rollback step {s.number} {s.title}")
            try:
                self._control(s.rollback)
            except RemoteError as e:
                self.out(f"\nFAILED: {e}. Later rollback steps did not run.")
                return 1
        self.out(f"\nRolled back region {self.region.name}. The site CA and cache on this machine are kept.")
        return 0

    def preflight(self):
        try:
            self._run_preflight()
        except RemoteError as e:
            self.out(f"FAILED: {e}")
            return 1
        return 0

    def verify(self):
        try:
            self._run_verify()
        except (RemoteError, StepError) as e:
            self.out(f"FAILED: {e}")
            return 1
        return 0

    def status(self):
        try:
            self._control(scripts.STATUS)
        except RemoteError as e:
            self.out(f"FAILED: {e}")
            return 1
        return 0
