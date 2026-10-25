"""Keep site data and secrets out of the repository: working tree and all history.

    python3 -m tailnet_ops.guard [--history] [--repo DIR] [--site DIR]

Generic rules apply everywhere: IPv4 literals outside the documentation ranges,
100.64.0.0/10 and loopback; private keys; Headscale and Tailscale keys; tokens;
links to private documents; site files by name. When a site directory exists, its
host aliases are blocked too. Findings name the place and the rule, never the value.
"""

import argparse
import subprocess
import sys
from pathlib import Path, PurePosixPath

from . import privacy
from .remote import ssh_config
from .site import SiteError, read_joined, read_toml, resolve_dir

BLOCKED_NAMES = {"site.toml", "inventory.toml", "joined.json", "phones.json"}
BLOCKED_SUFFIXES = {".key", ".pem", ".csr", ".crt", ".p12", ".pfx", ".srl", ".sqlite", ".db", ".mobileconfig"}


def site_host_names(site_dir, lookup=None):
    """Host aliases (and non-IP SSH HostNames) of the local site, if there is one, with the
    machines tn joined."""
    lookup = lookup or ssh_config
    path = Path(site_dir) / "site.toml"
    if not path.exists():
        return []
    try:
        data = read_toml(path)
    except SiteError:
        return []
    names = []
    for r in (data.get("regions") or {}).values():
        if isinstance(r, dict):
            names += [r.get("control_host"), r.get("check_from")]
    for ln in data.get("lines") or []:
        if isinstance(ln, dict):
            names += [ln.get("initiator"), ln.get("responder"), ln.get("name")]
    if isinstance(data.get("hosts"), dict):
        names += list(data["hosts"])
    try:
        joined = read_joined(site_dir)
    except SiteError:
        joined = {}
    for name, rec in joined.items():
        names += [name, rec.get("ssh") if isinstance(rec, dict) else None]
    names = [n for n in names if isinstance(n, str) and n]
    for alias in list(names):
        hostname = lookup(alias).get("hostname", "")
        if hostname and hostname.lower() != alias.lower() and privacy.parse_ipv4(hostname) is None:
            names.append(hostname)
    return sorted(set(names), key=str.lower)


def scan_text(text, host_names=()):
    """Yield (line_number, rule) for each finding."""
    for no, line in enumerate(text.splitlines(), 1):
        for _m, _addr in privacy.unshareable_ipv4(line):
            yield no, "IPv4 address outside the shareable ranges"
        for label, pattern in privacy.SECRET_PATTERNS:
            if pattern.search(line):
                yield no, label
        if privacy.PRIVATE_LINK.search(line):
            yield no, "link to a private document"
        for name in host_names:
            if privacy.name_pattern(name).search(line):
                yield no, "host name from the site directory"


def scan_path(path):
    p = PurePosixPath(path)
    if p.name in BLOCKED_NAMES:
        return f"site file {p.name} must not be in the repository"
    if p.suffix.lower() in BLOCKED_SUFFIXES:
        return f"{p.suffix} files must not be in the repository"
    return None


def _git(repo, *args, input=None):
    p = subprocess.run(["git", "-C", str(repo), *args], input=input, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


def _decode(data):
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def worktree_files(repo):
    """Tracked files plus untracked files that are not ignored: what a commit could include."""
    out = _git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({f for f in out.decode().split("\0") if f})


def scan_worktree(repo, host_names):
    findings = []
    for rel in worktree_files(repo):
        problem = scan_path(rel)
        if problem:
            findings.append(f"{rel}: {problem}")
        path = Path(repo) / rel
        if not path.is_file():
            continue
        text = _decode(path.read_bytes())
        if text is None:
            continue
        for no, rule in scan_text(text, host_names):
            findings.append(f"{rel}:{no}: {rule}")
    return findings


def history_blobs(repo):
    """(blob id, path) for every blob reachable from any ref."""
    listing = _git(repo, "rev-list", "--objects", "--all").decode()
    objects = []
    for line in listing.splitlines():
        oid, _, path = line.partition(" ")
        if path:
            objects.append((oid, path))
    if not objects:
        return []
    check = _git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                 input="".join(f"{oid}\n" for oid, _ in objects).encode()).decode()
    kinds = dict(line.split() for line in check.splitlines() if line)
    return [(oid, path) for oid, path in objects if kinds.get(oid) == "blob"]


def _read_blobs(repo, oids):
    if not oids:
        return {}
    raw = _git(repo, "cat-file", "--batch", input="".join(f"{o}\n" for o in oids).encode())
    out, pos = {}, 0
    while pos < len(raw):
        nl = raw.index(b"\n", pos)
        oid, _kind, size = raw[pos:nl].decode().split()
        start = nl + 1
        out[oid] = raw[start:start + int(size)]
        pos = start + int(size) + 1
    return out


def scan_history(repo, host_names):
    findings = []
    try:
        _git(repo, "rev-parse", "--verify", "-q", "HEAD")
    except RuntimeError:
        return findings, 0, 0
    blobs = history_blobs(repo)
    contents = _read_blobs(repo, sorted({oid for oid, _ in blobs}))
    seen = set()
    for oid, path in blobs:
        problem = scan_path(path)
        if problem and (path, problem) not in seen:
            seen.add((path, problem))
            findings.append(f"history {path}: {problem}")
        text = _decode(contents.get(oid, b""))
        if text is None:
            continue
        for no, rule in scan_text(text, host_names):
            key = (oid, no, rule)
            if key not in seen:
                seen.add(key)
                findings.append(f"history {path}:{no} (blob {oid[:10]}): {rule}")
    log = _git(repo, "log", "--all", "--format=%H%x00%B%x00").decode(errors="replace")
    parts = log.split("\0")
    commits = 0
    for i in range(0, len(parts) - 1, 2):
        sha, message = parts[i].strip(), parts[i + 1]
        if not sha:
            continue
        commits += 1
        for no, rule in scan_text(message, host_names):
            findings.append(f"commit {sha[:10]} message line {no}: {rule}")
    return findings, len({oid for oid, _ in blobs}), commits


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guard", description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", default=".", help="repository to scan (default: .)")
    ap.add_argument("--site", default=None, help="site directory whose host names to block (default: TN_SITE or ~/.config/tailnet-ops)")
    ap.add_argument("--history", action="store_true", help="also scan every blob and commit message reachable from any ref")
    args = ap.parse_args(argv)

    site_dir = resolve_dir(args.site)
    names = site_host_names(site_dir)
    findings = scan_worktree(args.repo, names)
    blobs = commits = 0
    if args.history:
        hist, blobs, commits = scan_history(args.repo, names)
        findings += hist
    files = len(worktree_files(args.repo))
    scope = f"{files} files" + (f", {blobs} blobs and {commits} commits in history" if args.history else "")
    site_note = f", plus {len(names)} host names from the site directory" if names else ""
    if findings:
        print(f"guard: {len(findings)} problem(s) in {scope}{site_note}:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print("Remove the data (and rewrite history if it was committed) before committing or pushing.", file=sys.stderr)
        return 1
    print(f"guard: clean ({scope}{site_note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
