"""Steps with exact scripts and rollbacks, printed as a plan and run by apply.

`tn control` and `tn join` are both a Procedure: a list of Steps. A plan prints every
step's remote scripts and rollback verbatim; apply runs the steps in order and stops at
the first failure; rollback runs the rollbacks in reverse.
"""

import hashlib
import os
import urllib.request
from dataclasses import dataclass, field

from .remote import RemoteError


class StepError(Exception):
    pass


@dataclass
class Action:
    where: str            # "local" or an SSH alias
    what: str
    body: str = None      # remote script body, printed verbatim
    prelude: str = None   # which prelude the body runs after (a key of Procedure.preludes())
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
    host: str = None            # where the step runs, for progress lines
    rollback_host: str = None   # where its rollback runs; defaults to host
    undo: object = field(default=None, repr=False)  # runs the rollback; None = rollback script on rollback_host
    brief: str = ""             # one line for the short plan
    undo_brief: str = ""        # how it is undone, in a few words


def indent(text, pad="      "):
    return "\n".join(pad + line if line else "" for line in text.rstrip("\n").splitlines())


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_pinned(url, path, want, out):
    """Download url to path (mode 0600) unless a file with the pinned sha256 is there."""
    if path.exists():
        if sha256_file(path) == want:
            out(f"    cache: {path.name} (sha256 ok)")
            return path
        raise StepError(f"{path} does not match the pinned sha256; delete it and retry")
    out(f"    downloading {url}")
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
    out(f"    sha256 ok: {want}")
    return path


class Procedure:
    """Subclasses set command, subject, target and out, and implement steps(), header(),
    preludes(), plan_intro(), rollback_footer(), done_message() and run_rollback(step)."""

    command = ""      # "control" or "join"
    subject = ""      # what the command names: a region or a host
    target = ""       # the host apply and rollback prompts name
    errors = (RemoteError, StepError, OSError)

    def preludes(self):
        """[(label, prelude text)] printed once at the top of the plan."""
        return []

    def rollback_steps(self):
        return [s for s in reversed(self.steps()) if s.rollback]

    # --- printing -----------------------------------------------------------------

    def plan_text(self):
        body = self._plan_body()
        digest = hashlib.sha256(body.encode()).hexdigest()[:12]
        return f"tn {self.command} plan {self.subject}\nPlan id {digest}\n\n{body}", digest

    def plan_id(self):
        return self.plan_text()[1]

    def summary_text(self):
        """The short plan: what changes, step by step, and how each step is undone."""
        steps = self.steps()
        width = max(len(self._brief(s)) for s in steps)
        out = [f"tn {self.command} plan {self.subject} · plan id {self.plan_id()}", "", self.header(), "",
               f"     {'Step'.ljust(width)}  Undo"]
        for s in steps:
            undo = s.undo_brief or ("—" if not s.rollback and s.read_only else s.rollback_note)
            out.append(f"  {s.number}  {self._brief(s).ljust(width)}  {undo}")
        out += ["", f"Undo everything: tn {self.command} rollback {self.subject}",
                f"Exact scripts and rollbacks: tn {self.command} plan {self.subject} --full"]
        return "\n".join(out) + "\n"

    @staticmethod
    def _brief(step):
        brief = step.brief or step.title
        return f"{brief} (read-only)" if step.read_only else brief

    def _plan_body(self):
        steps = self.steps()
        out = [self.header(), "", self.plan_intro(), ""]
        for label, text in self.preludes():
            out += [f"  Prelude ({label}):", indent(text), ""]
        for step in steps:
            tag = "  [read-only]" if step.read_only else ""
            out.append(f"Step {step.number}/{len(steps)}  {step.title}{tag}")
            out += [f"  {line}" for line in step.what]
            for i, action in enumerate(step.actions, 1):
                label = f"{step.number}.{i}" if len(step.actions) > 1 else f"{step.number}"
                who = "this machine" if action.where == "local" else (
                    f"{action.where} as root" if action.privileged else f"{action.where} as the SSH user")
                out.append(f"  {label} on {who}: {action.what}")
                if action.body:
                    out.append(indent(action.body))
            if step.rollback:
                out.append(f"  Rollback ({step.rollback_note}), as root on {step.rollback_host or step.host}:")
                out.append(indent(step.rollback))
            else:
                out.append(f"  Rollback: {step.rollback_note}")
            out.append("")
        order = ", ".join(str(s.number) for s in self.rollback_steps())
        out.append(f"`tn {self.command} rollback {self.subject}` runs the rollbacks of steps {order} in that order.\n"
                   + self.rollback_footer())
        return "\n".join(out) + "\n"

    # --- running ------------------------------------------------------------------

    def _run_steps(self, steps, label):
        for step in steps:
            self.out(f"\n== {label} step {step.number}/{len(steps)} {step.title} on {step.host}")
            try:
                step.run()
            except self.errors as e:
                self.out(f"\nFAILED at step {step.number} ({step.title}): {e}")
                return step
        return None

    def apply(self, yes=False, ask=input):
        steps = self.steps()
        self.out(self.summary_text().rstrip("\n").rsplit("\n\n", 1)[0])
        self.out("\nCompare the plan id with the plan you approved.")
        if not yes:
            answer = ask(f"Type yes to apply these steps to {self.target}: ")
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
                         f"`tn {self.command} rollback {self.subject}`.")
            return 1
        self.out("\n" + self.done_message())
        return 0

    def rollback(self, yes=False, ask=input):
        steps = self.rollback_steps()
        self.out(f"Rollback for {self.command} {self.subject} on {self.target}:")
        for s in steps:
            self.out(f"  step {s.number} {s.title}: {s.rollback_note}")
        self.out("Only things marked as made by tailnet-ops are removed; anything else is reported and skipped.")
        if not yes:
            answer = ask(f"Type yes to roll back on {self.target}: ")
            if answer.strip() != "yes":
                self.out("Not rolled back; nothing changed.")
                return 1
        for s in steps:
            self.out(f"\n== rollback step {s.number} {s.title}")
            try:
                (s.undo or (lambda: self.run_rollback(s)))()
            except self.errors as e:
                self.out(f"\nFAILED: {e}. Later rollback steps did not run.")
                return 1
        self.out("\n" + self.rolled_back_message())
        return 0

    def run_once(self, fn):
        """Run one read-only piece (preflight, verify, status); report failure as rc 1."""
        try:
            fn()
        except self.errors as e:
            self.out(f"FAILED: {e}")
            return 1
        return 0
