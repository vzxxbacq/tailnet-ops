"""`tn join` on macOS: Tailscale from Homebrew, run by launchd, the site CA in the System keychain.

Homebrew's tailscale is the open-source tailscaled, run as root by a launchd job of our own, as
systemd runs it on Linux. For DNS it writes /etc/resolver/<suffix>, so only names under the
site's suffix go to MagicDNS. macOS asks for a password or Touch ID in a window before it trusts
a CA, so a Mac joins best from itself (local = true).
"""

from . import scripts

LABEL = "tailnet-ops.tailscaled"
PLIST = f"/Library/LaunchDaemons/{LABEL}.plist"
TN_DIR = "/Library/tailnet-ops"
TS_STATE = f"{TN_DIR}/tailscale"
KEYCHAIN = "/Library/Keychains/System.keychain"
SOCKET = "/var/run/tailscaled.socket"   # where Homebrew's tailscale CLI looks
DEFAULT_TS_BIN = "/opt/homebrew/opt/tailscale/bin/tailscale"
MIN_VERSION = "1.80"


def prelude(mark, alias, logins, port, ca_name):
    return f"""set -euo pipefail
umask 022
{scripts._vars([
    ("HOST", alias),
    ("LOGIN", logins[0]),
    ("LOGINS", " ".join(logins)),
    ("TS_PORT", port),
    ("LABEL", LABEL),
    ("PLIST", PLIST),
    ("TN_DIR", TN_DIR),
    ("TS_STATE", TS_STATE),
    ("CA_FILE", f"{TN_DIR}/{ca_name}"),
    ("KEYCHAIN", KEYCHAIN),
    ("SOCKET", SOCKET),
    ("TS_MIN", MIN_VERSION),
    ("MARK", mark),
])}
die() {{ echo "tn: $*" >&2; exit 1; }}
# Homebrew lives in /opt/homebrew on Apple silicon and in /usr/local on Intel.
BREW=""
for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [ -x "$b" ]; then BREW=$b; break; fi
done
BREW_PREFIX=${{BREW%/bin/brew}}
TS_BIN=${{BREW_PREFIX:-/opt/homebrew}}/opt/tailscale/bin/tailscale
TSD_BIN=${{BREW_PREFIX:-/opt/homebrew}}/opt/tailscale/bin/tailscaled
# Homebrew refuses to run as root: run it as the user who owns it, as if that user ran it.
brew_user() {{ stat -L -f %Su "$BREW"; }}
as_brew() {{
  sudo -u "$(brew_user)" -H env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND \
    HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ENV_HINTS=1 "$BREW" "$@"
}}
version_ok() {{
  local v=${{1%%-*}} major minor
  major=${{v%%.*}}
  minor=${{v#*.}}
  minor=${{minor%%.*}}
  case "$major.$minor" in *[!0-9.]*|.*|*.) return 1 ;; esac
  [ "$major" -gt "${{TS_MIN%%.*}}" ] || {{ [ "$major" -eq "${{TS_MIN%%.*}}" ] && [ "$minor" -ge "${{TS_MIN#*.}}" ]; }}
}}
# The SHA-1 of the PEM certificate on stdin, as `security find-certificate -Z` prints it.
fingerprint() {{ openssl x509 -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'; }}
in_keychain() {{ security find-certificate -a -Z "$KEYCHAIN" 2>/dev/null | grep -q "SHA-1 hash: $1"; }}
# macOS's own TLS check, the one tailscaled's Go runtime uses.
trusted() {{
  local url
  for url in $LOGINS; do security verify-cert "$url" >/dev/null 2>&1 || return 1; done
}}
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
ours_dir() {{ [ -f "$TN_DIR/.tailnet-ops" ] && [ "$(cat "$TN_DIR/.tailnet-ops")" = "$MARK" ]; }}
ours_plist() {{ [ -f "$PLIST" ] && grep -qxF "<!-- $MARK -->" "$PLIST"; }}
ours_state() {{ [ -f "$TS_STATE/.tailnet-ops" ] && [ "$(cat "$TS_STATE/.tailnet-ops")" = "$MARK" ]; }}
make_dir() {{
  if [ -e "$TN_DIR" ] && ! ours_dir; then die "$TN_DIR exists and is not ours"; fi
  install -d -m 0755 "$TN_DIR"
  printf '%s\\n' "$MARK" > "$TN_DIR/.tailnet-ops"
}}"""


# --- step 1: preflight (read-only) ------------------------------------------------


def preflight(ca_pem):
    return scripts.ca_function(ca_pem) + r"""
fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }

if [ "$(uname -s)" = Darwin ]; then
  os="macOS $(sw_vers -productVersion 2>/dev/null || echo unknown)"
  pass "OS: $os"
else
  os=$(uname -s)
  flag "OS: not macOS ($os); join it with --os linux"
fi
echo "TN-FACT os=$os"
echo "TN-FACT machine=$(uname -m)"
case "$(uname -m)" in
  x86_64|arm64) pass "arch: $(uname -m)" ;;
  *) flag "arch: $(uname -m) is not supported" ;;
esac
if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
missing=""
for c in curl lsof launchctl security openssl; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [ -z "$missing" ]; then pass "tools: curl lsof launchctl security openssl"; else flag "missing tools:$missing"; fi

if [ -n "$BREW" ]; then pass "Homebrew: $BREW, owned by $(brew_user)"; else flag "Homebrew is not installed (https://brew.sh)"; fi
echo "TN-FACT ts_bin=$TS_BIN"
if [ ! -x "$TS_BIN" ]; then
  pass "tailscale: not installed yet; step 2 runs brew install tailscale"
  echo "TN-FACT tailscale=none"
else
  v=$("$TS_BIN" version 2>/dev/null | head -n 1 || true)
  if version_ok "$v"; then pass "tailscale $v from Homebrew"
  else flag "tailscale ${v:-of unknown version} from Homebrew is older than $TS_MIN; run brew upgrade tailscale"; fi
  echo "TN-FACT tailscale=$v"
fi
if [ -e /Applications/Tailscale.app ]; then flag "the Tailscale app is installed; it and tailscaled would fight over routes and DNS"; fi
if [ -e /Library/LaunchDaemons/homebrew.mxcl.tailscale.plist ]; then
  flag "brew services runs tailscaled; stop it first: sudo brew services stop tailscale"
fi
if pgrep -x tailscaled >/dev/null && ! ours_plist; then flag "a tailscaled process runs outside tailnet-ops"; fi
if [ -e "$SOCKET" ] && ! ours_plist; then flag "$SOCKET exists outside tailnet-ops"; fi

lines=$(lsof -nP -iUDP:"$TS_PORT" 2>/dev/null | tail -n +2 || true)
if [ -z "$lines" ]; then pass "udp/$TS_PORT free (Tailscale)"; echo "TN-FACT port=free"
elif ! printf '%s\n' "$lines" | awk '{print $1}' | grep -qv '^tailscale' && ours_plist; then
  pass "udp/$TS_PORT already used by our tailscaled"; echo "TN-FACT port=ours"
else flag "udp/$TS_PORT is in use: $(printf '%s' "$lines" | tr -s ' ' | tr '\n' ' ' | cut -c1-160)"; echo "TN-FACT port=busy"; fi

if [ ! -e "$TN_DIR" ]; then pass "$TN_DIR absent"
elif ours_dir; then pass "$TN_DIR exists and is ours"
else flag "$TN_DIR exists and is not ours"; fi
if [ ! -e "$PLIST" ]; then pass "$PLIST absent"
elif ours_plist; then pass "$PLIST exists and is ours"
else flag "$PLIST exists and is not ours"; fi
if [ ! -e "$TS_STATE" ]; then pass "$TS_STATE absent"
elif ours_state; then pass "$TS_STATE exists and is ours"
else flag "$TS_STATE exists and is not ours"; fi

login=ok
for url in $LOGINS; do
  if out=$(curl -fsS --max-time 10 --cacert <(ca) "$url/health" 2>&1); then
    pass "reaches $url over TLS with the site CA"
  else
    flag "cannot reach $url with the site CA: $out"; login=fail
  fi
done
echo "TN-FACT login=$login"
if trusted; then echo "TN-FACT ca=trusted"; else echo "TN-FACT ca=no"; fi
if ours_plist; then echo "TN-FACT joined=ours"; else echo "TN-FACT joined=no"; fi

if [ "$fail" != 0 ]; then die "preflight failed; nothing was changed"; fi
echo "preflight passed; nothing was changed"
"""


# --- step 2: tailscale from Homebrew ---------------------------------------------------

INSTALL = r"""[ -n "$BREW" ] || die "Homebrew is not installed"
if [ -x "$TS_BIN" ]; then
  echo "tailscale is already installed with Homebrew; using it as it is"
else
  make_dir
  echo "brew install tailscale (as $(brew_user))"
  as_brew install tailscale
  printf '%s\n' "$MARK" > "$TN_DIR/brew-installed"
fi
v=$("$TS_BIN" version | head -n 1)
version_ok "$v" || die "tailscale $v is older than $TS_MIN; run brew upgrade tailscale"
echo "tailscale $v"
"""

ROLLBACK_INSTALL = r"""if ours_dir && [ -f "$TN_DIR/brew-installed" ]; then
  if pgrep -x tailscaled >/dev/null; then
    echo "skip: tailscaled still runs, so Homebrew's tailscale stays"
  else
    if [ -x "$TS_BIN" ]; then as_brew uninstall tailscale; echo "uninstalled tailscale, which tailnet-ops installed with Homebrew"; fi
    rm -f "$TN_DIR/brew-installed"
  fi
else
  echo "Homebrew's tailscale: not installed by tailnet-ops; left as it is"
fi
if ours_dir; then
  rest=no
  for f in "$TN_DIR"/* "$TN_DIR"/.[!.]*; do
    if [ -e "$f" ] && [ "$f" != "$TN_DIR/.tailnet-ops" ]; then rest=yes; fi
  done
  if [ "$rest" = no ]; then rm -rf "$TN_DIR"; echo "removed $TN_DIR"; fi
fi
"""


# --- step 3: site CA in the System keychain ---------------------------------------------


def install_ca(ca_pem):
    return f"""make_dir
cat > "$CA_FILE.tn-new" <<'TN_PEM'
{ca_pem.strip()}
TN_PEM
chmod 0644 "$CA_FILE.tn-new"
if cmp -s "$CA_FILE.tn-new" "$CA_FILE"; then rm -f "$CA_FILE.tn-new"; else mv -f "$CA_FILE.tn-new" "$CA_FILE"; fi
if trusted; then
  echo "macOS already trusts the site CA"
else
  echo "Adding the site CA to the System keychain, trusted for TLS only."
  echo "macOS asks for your password or Touch ID in a window."
  security add-trusted-cert -d -r trustRoot -p ssl -k "$KEYCHAIN" "$CA_FILE" ||
    die "macOS did not trust the CA. Over SSH it cannot ask in a window: join the Mac from itself (local = true)"
  fingerprint < "$CA_FILE" > "$TN_DIR/ca-added"
  trusted || die "macOS still does not accept $LOGINS"
fi
echo "macOS accepts $LOGINS"
"""


def rollback_ca(ca_pem):
    return scripts.ca_function(ca_pem) + """
if ! ours_dir || [ ! -f "$TN_DIR/ca-added" ]; then
  echo "the site CA in the System keychain: not added by tailnet-ops; left as it is"
else
  sha=$(cat "$TN_DIR/ca-added")
  if [ "$sha" != "$(ca | fingerprint)" ]; then echo "skip: the CA tailnet-ops added is not this site's"
  else
    echo "Removing the site CA from the System keychain; macOS asks for your password or Touch ID in a window."
    if [ -f "$CA_FILE" ]; then security remove-trusted-cert -d "$CA_FILE" || true; fi
    if in_keychain "$sha"; then security delete-certificate -Z "$sha" "$KEYCHAIN"; fi
    echo "removed the site CA from the System keychain"
  fi
  rm -f "$TN_DIR/ca-added"
fi
if [ -f "$CA_FILE" ] && cmp -s "$CA_FILE" <(ca); then rm -f "$CA_FILE"; echo "removed $CA_FILE"; fi
"""


# --- step 4: tailscaled under launchd ----------------------------------------------------

# Expanded on the host: $TSD_BIN depends on where Homebrew lives. No log file: tailscaled would
# keep writing to a rotated one; `sudo tailscale debug daemon-logs` shows the log live.
PLIST_TEXT = """<?xml version="1.0" encoding="UTF-8"?>
<!-- $MARK -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$TSD_BIN</string>
    <string>--state=$TS_STATE/tailscaled.state</string>
    <string>--socket=$SOCKET</string>
    <string>--port=$TS_PORT</string>
    <string>--no-logs-no-support</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>"""

SERVICE = r"""make_dir
if [ -e "$PLIST" ] && ! ours_plist; then die "$PLIST exists and is not ours"; fi
if [ -e "$TS_STATE" ] && ! ours_state; then die "$TS_STATE exists and is not ours"; fi
install -d -m 0700 "$TS_STATE"
printf '%s\n' "$MARK" > "$TS_STATE/.tailnet-ops"
cat > "$PLIST.tn-new" <<TN_EOF
""" + PLIST_TEXT + r"""
TN_EOF
chown root:wheel "$PLIST.tn-new"
chmod 0644 "$PLIST.tn-new"
changed=no
if cmp -s "$PLIST.tn-new" "$PLIST"; then rm -f "$PLIST.tn-new"; echo "unchanged $PLIST"
else mv -f "$PLIST.tn-new" "$PLIST"; echo "wrote $PLIST"; changed=yes; fi
gone() {
  local _
  for _ in $(seq 1 20); do launchctl print "system/$LABEL" >/dev/null 2>&1 || return 0; sleep 0.5; done
  return 1
}
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  if [ "$changed" = yes ]; then
    launchctl bootout "system/$LABEL" || true
    gone || die "launchd did not stop $LABEL"
    launchctl bootstrap system "$PLIST"
    echo "restarted tailscaled"
  fi
else
  launchctl enable "system/$LABEL"
  launchctl bootstrap system "$PLIST"
  echo "started tailscaled ($LABEL)"
fi
for _ in $(seq 1 20); do
  if "$TS_BIN" status --json >/dev/null 2>&1; then echo "tailscaled is up"; return 0; fi
  sleep 1
done
launchctl print "system/$LABEL" 2>/dev/null | grep -E '^\s*(state|last exit code)' || true
die "tailscaled did not answer within 20 s; sudo launchctl print system/$LABEL shows why it stopped"
"""

ROLLBACK_SERVICE = r"""if [ ! -e "$PLIST" ]; then echo "$PLIST: absent"
elif ours_plist; then
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  for _ in $(seq 1 20); do launchctl print "system/$LABEL" >/dev/null 2>&1 || break; sleep 0.5; done
  # tailscaled removes its routes and /etc/resolver files when it stops; --cleanup makes sure.
  if [ -x "$TSD_BIN" ]; then "$TSD_BIN" --cleanup >/dev/null 2>&1 || true; fi
  rm -f "$PLIST"
  echo "stopped tailscaled and removed $PLIST"
else echo "skip: $PLIST is not ours"; fi
if [ ! -e "$TS_STATE" ]; then echo "$TS_STATE: absent"
elif ours_state; then rm -rf "$TS_STATE"; echo "removed $TS_STATE (the node keys of every profile)"
else echo "skip: $TS_STATE is not ours"; fi
"""


# --- join, verify, leftovers ---------------------------------------------------------------

LOGOUT_ALL = r"""if [ -x "$TS_BIN" ] && "$TS_BIN" status --json >/dev/null 2>&1; then
  for nick in "$@"; do
    if "$TS_BIN" switch "$nick" >/dev/null 2>&1; then "$TS_BIN" logout || true; echo "logged out of $nick"; fi
  done
else
  echo "tailscaled is not running; nothing to log out"
fi
"""


def reach(my_ip, target):
    """Whether the route to target leaves through the interface that has my_ip, and a ping."""
    return f"""ifc=$(ifconfig | awk -v ip={my_ip} '/^[a-z0-9]+:/ {{i=$1; sub(/:$/, "", i)}} $1 == "inet" && $2 == ip {{print i}}')
via=$(route -n get {target} 2>/dev/null | awk '/interface:/ {{print $2}}')
if [ -n "$ifc" ] && [ "$via" = "$ifc" ]; then echo TN-ROUTE ok; else echo TN-ROUTE none; fi
ping -c 3 -t 6 -S {my_ip} {target} >/dev/null 2>&1 && echo TN-PING ok || echo TN-PING fail
"""


def leftovers(ca_pem):
    return scripts.ca_function(ca_pem) + r"""
for p in "$PLIST" "$TS_STATE" "$TN_DIR" "$SOCKET"; do
  if [ -e "$p" ]; then echo "TN-LEFT $p"; fi
done
if launchctl print "system/$LABEL" >/dev/null 2>&1; then echo "TN-LEFT launchd job $LABEL"; fi
if pgrep -x tailscaled >/dev/null; then echo "TN-LEFT a running tailscaled"; fi
if in_keychain "$(ca | fingerprint)"; then echo "TN-LEFT the site CA in the System keychain"; fi
for f in /etc/resolver/*; do
  if [ -f "$f" ] && [ "$(head -n 1 "$f")" = "# Added by tailscaled" ]; then echo "TN-LEFT $f"; fi
done
"""
