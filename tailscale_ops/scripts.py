"""Bash scripts that run on remote hosts.

A control-host script is the prelude followed by a step body. The runner sends

    <prelude>
    tn_step() {
    <body>
    }
    tn_step "$@" </dev/null

to `bash -s` over SSH, so a command inside a body can never read the rest of the
script from stdin. The plan prints the prelude once and every body verbatim.
"""

import shlex
from pathlib import Path

from . import acme, pins, render


def wrap(prelude, body):
    return f"{prelude}\ntn_step() {{\n{body.rstrip()}\n}}\ntn_step \"$@\" </dev/null\n"


def _vars(pairs):
    return "\n".join(f"{k}={shlex.quote(str(v))}" for k, v in pairs)


def ca_function(ca_pem):
    """`ca`: a shell function that prints the site CA, for `--cacert <(ca)` and comparisons."""
    return f"""ca() {{
cat <<'TN_PEM'
{ca_pem.strip()}
TN_PEM
}}"""


def control_prelude(site, region):
    r = region
    host = site.host_settings.get(r.control_host)
    tailscale_port = host.tailscale_port if host and host.tailscale_port else ""
    entry_port = r.entry_port or ""
    return f"""set -euo pipefail
umask 022
{_vars([
    ("REGION", r.name),
    ("PUBLIC", r.public_ipv4),
    ("NAME", r.server_name),
    ("DOMAIN", r.domain or ""),
    ("LISTEN", r.listen_ipv4),
    ("LOCAL", r.local_ipv4),
    ("PORT", r.port),
    ("STUN_PORT", r.stun_port),
    ("METRICS_PORT", r.metrics_port),
    ("GRPC_PORT", r.grpc_port),
    ("TAILSCALE_PORT", tailscale_port),
    ("ENTRY_PORT", entry_port),
    ("OFFICIAL_DERP", "yes" if r.official_derp else "no"),
    ("OWNER", site.owner_user),
    ("BIN", render.BIN),
    ("ETC", render.ETC),
    ("LIB", render.LIB),
    ("UNIT", render.UNIT),
    ("ACME", acme.DIR),
    ("CERT_SERVICE", acme.SERVICE),
    ("CERT_TIMER", acme.TIMER),
    ("SUM_AMD64", pins.HEADSCALE_SHA256["amd64"]),
    ("SUM_ARM64", pins.HEADSCALE_SHA256["arm64"]),
    ("GECOS", "Headscale (tailnet-ops)"),
])}
MARK="tailnet-ops region=$REGION"
die() {{ echo "tn: $*" >&2; exit 1; }}
want_sum() {{
  case "$(uname -m)" in
    x86_64) echo "$SUM_AMD64" ;;
    aarch64|arm64) echo "$SUM_ARM64" ;;
    *) echo none ;;
  esac
}}
# Each thing tailnet-ops creates carries its own mark; nothing else counts as ours.
ours_etc() {{ [ -f "$ETC/.tailnet-ops" ] && [ "$(cat "$ETC/.tailnet-ops")" = "$MARK" ]; }}
ours_lib() {{ [ -f "$LIB/.tailnet-ops" ] && [ "$(cat "$LIB/.tailnet-ops")" = "$MARK" ]; }}
ours_unit() {{ [ -f "$UNIT" ] && [ "$(head -n 1 "$UNIT")" = "# $MARK" ]; }}
ours_user() {{ [ "$(getent passwd headscale | cut -d: -f5)" = "$GECOS" ]; }}
ours_bin() {{
  [ -f "$BIN" ] || return 1
  local sum
  sum=$(sha256sum "$BIN" | cut -d' ' -f1)
  [ "$sum" = "$SUM_AMD64" ] || [ "$sum" = "$SUM_ARM64" ]
}}"""


def checker_prelude(region):
    r = region
    return f"""set -euo pipefail
{_vars([("PUBLIC", r.public_ipv4), ("NAME", r.server_name), ("PORT", r.port), ("STUN_PORT", r.stun_port)])}
die() {{ echo "tn: $*" >&2; exit 1; }}"""


# --- step 1: preflight (read-only) ------------------------------------------------

PREFLIGHT = r"""fail=0
pass() { printf '  ok    %s\n' "$*"; }
flag() { printf '  FAIL  %s\n' "$*"; fail=1; }
note() { printf '  note  %s\n' "$*"; }

os=$( (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null || echo unknown)
if [ "$(uname -s)" = Linux ]; then pass "OS: $os"; else flag "OS: not Linux ($os)"; fi
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) arch="" ;;
esac
if [ -n "$arch" ]; then pass "arch: $(uname -m)"; else flag "arch: $(uname -m) has no pinned Headscale build"; fi
echo "TN-FACT arch=${arch:-none}"
if [ "$(id -u)" = 0 ]; then pass "running as root"; else flag "not running as root"; fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then pass "systemd"; else flag "systemd is not running"; fi
missing=""
for c in openssl curl ss ip sha256sum install useradd userdel groupdel runuser getent journalctl; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [ -z "$missing" ]; then pass "tools: openssl curl ss ip sha256sum useradd runuser journalctl"; else flag "missing tools:$missing"; fi

if [ "$LISTEN" != 0.0.0.0 ]; then
  if ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -qxF "$LISTEN"; then
    pass "listen address $LISTEN is on this host"
  else
    flag "listen address $LISTEN is not on this host"
  fi
fi

check_port() {
  local proto=$1 port=$2 label=$3 owner=${4:-headscale} who lines
  who="our Headscale"
  if [ "$owner" != headscale ]; then who=$owner; fi
  if [ "$proto" = tcp ]; then
    lines=$(ss -H -ltnp "sport = :$port" 2>/dev/null || true)
  else
    lines=$(ss -H -lunp "sport = :$port" 2>/dev/null || true)
  fi
  if [ -z "$lines" ]; then
    pass "$proto/$port free ($label)"
  elif ! printf '%s\n' "$lines" | grep -qv "\"$owner\"" && { [ "$owner" != headscale ] || ours_etc; }; then
    pass "$proto/$port already used by $who ($label)"
  else
    flag "$proto/$port is in use ($label): $(printf '%s' "$lines" | tr -s ' ' | tr '\n' ' ' | cut -c1-160)"
  fi
}
check_port tcp "$PORT" "Headscale HTTPS and DERP"
check_port udp "$STUN_PORT" "STUN"
check_port tcp "$METRICS_PORT" "metrics on 127.0.0.1"
check_port tcp "$GRPC_PORT" "gRPC on 127.0.0.1"
if [ -n "$TAILSCALE_PORT" ]; then check_port udp "$TAILSCALE_PORT" "reserved for Tailscale" tailscaled; fi
if [ -n "$ENTRY_PORT" ]; then
  lines=$(ss -H -lun "sport = :$ENTRY_PORT" 2>/dev/null || true)
  if [ -z "$lines" ]; then pass "udp/$ENTRY_PORT free (WireGuard entry for phones)"
  elif [ "$(wg show tn-entry listen-port 2>/dev/null)" = "$ENTRY_PORT" ]; then pass "udp/$ENTRY_PORT already used by tn-entry (WireGuard entry for phones)"
  else flag "udp/$ENTRY_PORT is in use (WireGuard entry for phones): $(printf '%s' "$lines" | tr -s ' ' | tr '\n' ' ' | cut -c1-160)"; fi
  missing=""
  for c in wg wg-quick nft; do command -v "$c" >/dev/null || missing="$missing $c"; done
  if [ -n "$missing" ]; then flag "missing for the phone entry:$missing (Debian and Ubuntu: apt install wireguard-tools nftables)"; fi
fi

if [ ! -e "$ETC" ]; then pass "$ETC absent"
elif ours_etc; then pass "$ETC exists and is ours"
else flag "$ETC exists and is not ours"; fi
if [ ! -e "$LIB" ]; then pass "$LIB absent"
elif ours_lib; then pass "$LIB exists and is ours"
else flag "$LIB exists and is not ours"; fi
if [ ! -e "$UNIT" ]; then pass "$UNIT absent"
elif ours_unit; then pass "$UNIT exists and is ours"
else flag "$UNIT exists and is not ours"; fi
if [ ! -e "$BIN" ]; then pass "$BIN absent"; echo "TN-FACT installed=none"
elif ours_bin; then pass "$BIN is the pinned build"; echo "TN-FACT installed=$(sha256sum "$BIN" | cut -d' ' -f1)"
else flag "$BIN exists and is not the pinned build"; fi
if ! getent passwd headscale >/dev/null; then
  if getent group headscale >/dev/null; then flag "group headscale exists without a headscale user"; else pass "user headscale absent"; fi
elif ours_user; then pass "user headscale exists and is ours"
else flag "user headscale exists and is not ours"; fi
if command -v dpkg-query >/dev/null && dpkg-query -W -f='${Status}' headscale 2>/dev/null | grep -q 'ok installed'; then
  flag "a headscale package is installed"
fi
if pgrep -x headscale >/dev/null && ! ours_unit; then flag "a headscale process runs outside our unit"; fi

free_kb=$(df -Pk /var/lib 2>/dev/null | awk 'NR==2 {print $4}' || true)
if [ "${free_kb:-0}" -ge 204800 ]; then pass "disk: $((free_kb / 1024)) MB free in /var/lib"; else flag "disk: less than 200 MB free in /var/lib"; fi
if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)" = yes ]; then
  pass "clock is NTP-synchronised"
else
  note "clock sync unknown; certificates need a correct clock"
fi
if [ -n "$DOMAIN" ]; then
  # Let's Encrypt over DNS-01: the name must point here, unproxied, and both APIs must answer.
  # $1: check (Cloudflare has the record as wanted), skip (step 4 makes it; a lookup now would stay
  # cached) or soft (no token to ask Cloudflare: look, but step 4 sets it).
  dns=${1:-check}
  if [ "$dns" = skip ]; then
    note "$DOMAIN: not looked up here; step 4 makes its A record first"
    echo "TN-FACT dns=skipped"
  else
    got=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
    case " $got" in
      *" $PUBLIC "*) pass "$DOMAIN resolves to $PUBLIC"; echo "TN-FACT dns=ok" ;;
      " ") echo "TN-FACT dns=no"
           if [ "$dns" = soft ]; then note "$DOMAIN does not resolve yet; step 4 makes its A record -> $PUBLIC"
           else flag "$DOMAIN does not resolve, though Cloudflare has it -> $PUBLIC: check this host's DNS"; fi ;;
      *) echo "TN-FACT dns=no"
         if [ "$dns" = soft ]; then note "$DOMAIN resolves to ${got% }; step 4 points its A record -> $PUBLIC"
         else flag "$DOMAIN resolves to ${got% } here, not $PUBLIC, though Cloudflare has it right: check this host's DNS"; fi ;;
    esac
  fi
  if curl -fsS --max-time 10 -o /dev/null https://acme-v02.api.letsencrypt.org/directory; then pass "reaches Let's Encrypt"
  else flag "cannot reach https://acme-v02.api.letsencrypt.org"; fi
  if curl -sS --max-time 10 -o /dev/null https://api.cloudflare.com/client/v4/ips; then pass "reaches the Cloudflare API"
  else flag "cannot reach https://api.cloudflare.com"; fi
  for u in "$CERT_SERVICE" "$CERT_TIMER"; do
    if [ ! -e "$u" ]; then pass "$u absent"
    elif [ "$(head -n 1 "$u")" = "# $MARK" ]; then pass "$u exists and is ours"
    else flag "$u exists and is not ours"; fi
  done
fi
if [ "$OFFICIAL_DERP" = yes ]; then
  if curl -fsS --max-time 10 -o /dev/null https://controlplane.tailscale.com/derpmap/default; then
    pass "official DERP map reachable (Headscale fetches it at start)"
  else
    flag "cannot fetch the official DERP map; Headscale would fail to start"
  fi
fi

if [ "$fail" != 0 ]; then die "preflight failed; nothing was changed"; fi
echo "preflight passed; nothing was changed"
"""


# --- step 2: binary -------------------------------------------------------------

STAGE = r"""d=$(mktemp -d /tmp/tn-headscale.XXXXXXXX)
echo "TN-FACT stage=$d"
"""

INSTALL_BINARY = r"""stage=${1:?staging directory}
case "$stage" in /tmp/tn-headscale.*) ;; *) die "unexpected staging path $stage" ;; esac
want=$(want_sum)
got=$(sha256sum "$stage/headscale" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  rm -rf "$stage"
  die "checksum mismatch on the host: $got"
fi
install -o root -g root -m 0755 "$stage/headscale" "$BIN.tn-new"
mv -f "$BIN.tn-new" "$BIN"
rm -rf "$stage"
if ours_etc; then touch "$ETC/.restart-needed"; fi
echo "installed $BIN ($got)"
"""

ROLLBACK_BINARY = r"""if [ ! -e "$BIN" ]; then echo "$BIN: absent"
elif ours_bin; then rm -f "$BIN"; echo "removed $BIN"
else echo "skip: $BIN is not the pinned build"; fi
for d in /tmp/tn-headscale.*; do
  if [ -d "$d" ]; then rm -rf "$d"; echo "removed the staging directory $d"; fi
done
"""


# --- step 3: user and directories ----------------------------------------------

USER_AND_DIRS = r"""if [ -e "$ETC" ] && ! ours_etc; then die "$ETC exists and is not ours"; fi
if [ -e "$LIB" ] && ! ours_lib; then die "$LIB exists and is not ours"; fi
if getent passwd headscale >/dev/null; then
  ours_user || die "user headscale exists and is not ours"
  echo "user headscale: exists"
else
  if getent group headscale >/dev/null; then die "group headscale exists without our user"; fi
  useradd --system --user-group --home-dir "$LIB" --no-create-home \
    --shell /usr/sbin/nologin --comment "$GECOS" headscale
  echo "user headscale: created"
fi
install -d -o root -g headscale -m 0750 "$ETC" "$ETC/tls"
install -d -o headscale -g headscale -m 0750 "$LIB"
printf '%s\n' "$MARK" > "$ETC/.tailnet-ops"
printf '%s\n' "$MARK" > "$LIB/.tailnet-ops"
chmod 0644 "$ETC/.tailnet-ops" "$LIB/.tailnet-ops"
ls -ld "$ETC" "$ETC/tls" "$LIB"
"""

ROLLBACK_USER_AND_DIRS = r"""for d in "$ETC" "$LIB"; do
  if [ ! -e "$d" ]; then echo "$d: absent"
  elif [ -f "$d/.tailnet-ops" ] && [ "$(cat "$d/.tailnet-ops")" = "$MARK" ]; then rm -rf "$d"; echo "removed $d"
  else echo "skip: $d is not ours"; fi
done
if ! getent passwd headscale >/dev/null; then echo "user headscale: absent"
elif ours_user; then
  userdel headscale
  echo "removed user headscale"
  if getent group headscale >/dev/null; then groupdel headscale; echo "removed group headscale"; fi
else echo "skip: user headscale is not ours"; fi
"""


# --- step 4: certificate --------------------------------------------------------

KEY_AND_CSR = r"""ours_etc || die "$ETC is missing or not ours"
cd "$ETC/tls"
if [ -s server.key ]; then
  echo "server key: kept"
else
  (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key.tn-new)
  mv -f server.key.tn-new server.key
  echo "server key: created on this host"
fi
chown root:headscale server.key
chmod 0640 server.key
echo "TN-BEGIN csr"
openssl req -new -key server.key -subj "/CN=tailnet-ops $REGION control"
echo "TN-END csr"
if [ -s server.crt ]; then
  echo "TN-BEGIN crt"
  cat server.crt
  echo "TN-END crt"
fi
if [ -s ca.crt ]; then
  echo "TN-BEGIN ca"
  cat ca.crt
  echo "TN-END ca"
fi
"""


# The Let's Encrypt renewal, if there is one: its timer, and acme.sh with its account and the API token.
DROP_ACME = r"""drop_acme() {
  local u removed=no
  for u in "$CERT_TIMER" "$CERT_SERVICE"; do
    if [ -e "$u" ] && [ "$(head -n 1 "$u")" = "# $MARK" ]; then
      if [ "$u" = "$CERT_TIMER" ]; then systemctl disable --now "${u##*/}" >/dev/null 2>&1 || true; fi
      rm -f "$u"
      echo "removed $u"
      removed=yes
    fi
  done
  if [ "$removed" = yes ]; then systemctl daemon-reload; fi
  if [ -d "$ACME" ] && ours_etc; then rm -rf "$ACME"; echo "removed $ACME (acme.sh, its account, the API token)"; fi
}
"""


def install_cert(server_pem, ca_pem):
    return DROP_ACME + f"""ours_etc || die "$ETC is missing or not ours"
cd "$ETC/tls"
cat > server.crt.tn-new <<'TN_PEM'
{server_pem.strip()}
TN_PEM
cat > ca.crt.tn-new <<'TN_PEM'
{ca_pem.strip()}
TN_PEM
key_pub=$(openssl pkey -in server.key -pubout | sha256sum)
crt_pub=$(openssl x509 -in server.crt.tn-new -noout -pubkey | sha256sum)
if [ "$key_pub" != "$crt_pub" ]; then
  rm -f server.crt.tn-new ca.crt.tn-new
  die "the certificate does not match the server key"
fi
openssl verify -CAfile ca.crt.tn-new server.crt.tn-new
changed=no
for f in server.crt ca.crt; do
  if cmp -s "$f.tn-new" "$f"; then rm -f "$f.tn-new"; else mv -f "$f.tn-new" "$f"; changed=yes; fi
done
chmod 0644 server.crt ca.crt
if [ "$changed" = yes ]; then touch "$ETC/.restart-needed"; fi
# A Let's Encrypt renewal from before would install its certificate over this one.
drop_acme
openssl x509 -in server.crt -noout -subject -enddate -ext subjectAltName
"""


ROLLBACK_CERT = DROP_ACME + r"""if ours_etc; then
  drop_acme
  rm -f "$ETC/tls/server.key" "$ETC/tls/server.crt" "$ETC/tls/ca.crt"
  echo "removed the server key and certificates in $ETC/tls"
else
  echo "skip: $ETC is absent or not ours"
fi
"""


# --- step 5: configuration ------------------------------------------------------


def configuration(config_yaml, unit):
    return f"""ours_etc || die "$ETC is missing or not ours"
changed=no
put() {{
  local mode=$1 owner=$2 path=$3
  cat > "$path.tn-new"
  chown "$owner" "$path.tn-new"
  chmod "$mode" "$path.tn-new"
  if cmp -s "$path.tn-new" "$path"; then
    rm -f "$path.tn-new"
    echo "unchanged $path"
  else
    mv -f "$path.tn-new" "$path"
    echo "wrote $path"
    changed=yes
  fi
}}
put 0640 root:headscale "$ETC/config.yaml" <<'TN_EOF'
{config_yaml.rstrip()}
TN_EOF
if [ ! -e "$ETC/policy.hujson" ]; then
  put 0640 root:headscale "$ETC/policy.hujson" <<'TN_EOF'
{render.BOOTSTRAP_POLICY.rstrip()}
TN_EOF
fi
if [ ! -e "$ETC/extra-records.json" ]; then
  # Headscale needs the file to exist; tailnet-ops fills it with the names of other regions' hosts.
  put 0640 root:headscale "$ETC/extra-records.json" <<'TN_EOF'
[]
TN_EOF
fi
if [ -e "$UNIT" ] && ! ours_unit; then die "$UNIT exists and is not ours"; fi
put 0644 root:root "$UNIT" <<'TN_EOF'
{unit.rstrip()}
TN_EOF
systemctl daemon-reload
runuser -u headscale -- "$BIN" configtest --config "$ETC/config.yaml"
echo "configtest passed"
if [ "$changed" = yes ]; then touch "$ETC/.restart-needed"; fi
"""


ROLLBACK_CONFIGURATION = r"""if [ ! -e "$UNIT" ]; then echo "$UNIT: absent"
elif ours_unit; then
  if systemctl is-active --quiet headscale; then die "headscale still runs; roll back step 6 first"; fi
  rm -f "$UNIT"
  systemctl daemon-reload
  echo "removed $UNIT"
else echo "skip: $UNIT is not ours"; fi
if ours_etc; then
  rm -f "$ETC/config.yaml" "$ETC/policy.hujson" "$ETC/extra-records.json" "$ETC/.restart-needed"
  echo "removed $ETC/config.yaml, $ETC/policy.hujson and $ETC/extra-records.json"
fi
"""


# --- step 6: start --------------------------------------------------------------

START = r"""ours_unit || die "$UNIT is missing or not ours"
was_active=no
if systemctl is-active --quiet headscale; then was_active=yes; fi
systemctl enable --now headscale
if [ "$was_active" = yes ] && [ -e "$ETC/.restart-needed" ]; then
  systemctl restart headscale
  echo "restarted headscale to load new files"
fi
rm -f "$ETC/.restart-needed"
url="https://$NAME:$PORT/health"
trust=()
if [ -z "$DOMAIN" ]; then trust=(--cacert "$ETC/tls/ca.crt"); fi
for _ in $(seq 1 30); do
  if out=$(curl -fsS --max-time 3 ${trust[@]+"${trust[@]}"} --connect-to "$NAME:$PORT:$LOCAL:$PORT" "$url" 2>&1); then
    echo "local /health over TLS: $out"
    return 0
  fi
  sleep 1
done
systemctl status --no-pager headscale || true
journalctl -u headscale -n 40 --no-pager || true
die "headscale did not become healthy within 30 s"
"""

ROLLBACK_START = r"""if ours_unit; then
  systemctl disable --now headscale
  echo "stopped and disabled headscale"
else
  echo "skip: $UNIT is absent or not ours"
fi
"""


# --- step 7: real policy --------------------------------------------------------


def real_policy(policy_text):
    return f"""ours_etc || die "$ETC is missing or not ours"
systemctl is-active --quiet headscale || die "headscale is not running"
if "$BIN" users list -o json | grep -Eq "\\"name\\": *\\"$OWNER\\""; then
  echo "user $OWNER: exists"
else
  "$BIN" users create "$OWNER"
fi
cat > "$ETC/policy.hujson.tn-new" <<'TN_EOF'
{policy_text.rstrip()}
TN_EOF
chown root:headscale "$ETC/policy.hujson.tn-new"
chmod 0640 "$ETC/policy.hujson.tn-new"
if ! "$BIN" policy check -f "$ETC/policy.hujson.tn-new"; then
  rm -f "$ETC/policy.hujson.tn-new"
  die "the policy does not pass headscale policy check"
fi
mv -f "$ETC/policy.hujson.tn-new" "$ETC/policy.hujson"
since=$(date +%s)
systemctl reload headscale
sleep 3
log=$(journalctl -u headscale --since "@$since" --no-pager -o cat 2>&1 || true)
printf '%s\\n' "$log" | tail -n 10
printf '%s\\n' "$log" | grep -q 'reloading ACL policy' || die "no policy reload in the journal"
if printf '%s\\n' "$log" | grep -Eq 'ERR|FTL|level=error|level=fatal'; then die "policy errors in the journal"; fi
systemctl is-active --quiet headscale || die "headscale stopped after the reload"
echo "policy loaded"
"""


# --- step 8: verify, on the checker --------------------------------------------


def stun_source():
    return (Path(__file__).with_name("stun.py")).read_text()


def verify(ca_pem=None):
    """From the checker. With ca_pem, TLS must hold with only the site CA; without, with the
    checker's own trust store, as any device sees a Let's Encrypt certificate."""
    if ca_pem:
        head, trust, how = ca_function(ca_pem) + "\n", " --cacert <(ca)", "trusting only the site CA"
    else:
        head, trust, how = "", "", "trusting the system's CAs, as every device does"
    return f"""{head}base="https://$NAME:$PORT"
echo "1/3 /health over TLS, {how}"
health=$(curl -fsS --max-time 10{trust} "$base/health")
echo "    $health"
case "$health" in *'"pass"'*) ;; *) die "unexpected /health answer" ;; esac
echo "2/3 DERP"
probe=$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10{trust} "$base/derp/probe")
derp=$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10{trust} "$base/derp")
echo "    /derp/probe -> $probe, /derp without upgrade -> $derp"
if [ "$probe" != 200 ] || [ "$derp" != 426 ]; then die "the DERP endpoints did not answer as expected"; fi
echo "3/3 STUN binding request to udp/$STUN_PORT"
python3 - "$PUBLIC" "$STUN_PORT" <<'TN_PY'
{stun_source().rstrip()}
TN_PY
echo "verify passed"
"""


STATUS = r""""$BIN" nodes list -o json
"""

# A copy of Headscale's state before a change, under /root (root only): the database through
# SQLite's online backup (safe while Headscale runs, WAL and all), and /etc/headscale plus the
# server keys. Restore: stop headscale, put db.sqlite and the files back, start it.
BACKUP = r"""ours_etc || die "$ETC is missing or not ours"
dir=/root/tailnet-ops-backup/$REGION-$(date -u +%Y%m%d-%H%M%S)
install -d -m 0700 "$dir"
if command -v sqlite3 >/dev/null; then
  sqlite3 "$LIB/db.sqlite" ".backup '$dir/db.sqlite'"
elif command -v python3 >/dev/null; then
  python3 -c 'import sqlite3, sys; sqlite3.connect(sys.argv[1]).backup(sqlite3.connect(sys.argv[2]))' \
    "$LIB/db.sqlite" "$dir/db.sqlite"
else
  die "neither sqlite3 nor python3 is here to copy the database safely"
fi
tar -C / --exclude='db.sqlite*' -czf "$dir/files.tgz" "${ETC#/}" "${LIB#/}"
chmod 0600 "$dir"/*
echo "TN-FACT backup=$dir"
ls -l "$dir"
"""
