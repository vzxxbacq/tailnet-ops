"""Pinned versions and fixed upstream facts."""

HEADSCALE_VERSION = "0.29.6"
HEADSCALE_SHA256 = {
    "amd64": "7477c374949eea6fb7cf3cbff14dbef49e4d118d9a33557d6764a77ece617e53",
    "arm64": "7b3c792ebe10e1a81a0c8d9674aee8eb540e7dbb7ccb80a98b71024da4c72a48",
}
HEADSCALE_URL = (
    "https://github.com/juanfont/headscale/releases/download/"
    "v{version}/headscale_{version}_linux_{arch}"
)
TAILSCALE_VERSION = "1.104.2"
# The static .tgz from pkgs.tailscale.com (checked against its published .sha256) and
# the two binaries inside it.
TAILSCALE_SHA256 = {
    "amd64": "512f613ed7d04fc7282f7dc5bd76aa105aae28168fbb9357eb749ebcbc29f0ae",
    "arm64": "5776aaa901b5ef1916e66be5bb54b9f481cd399c9c28db123a8cab620efa237b",
}
TAILSCALE_BIN_SHA256 = {
    "amd64": {
        "tailscale": "790cf117e5ddb64421faed041490274e65c47ad6c90e9d4ce2cb3968ad06e535",
        "tailscaled": "2b391d03f7cf25c4e0d11d344d577deca94436efad1ae9af002e46269d951ba3",
    },
    "arm64": {
        "tailscale": "f56aaf3f64e2e9843b55dd4760bb097c62df01b255dae79b4d2680b387dae464",
        "tailscaled": "3978859251e2f996d0c8dd44a5966c51876c15221eb6970fd6b4239f2457544b",
    },
}
TAILSCALE_URL = "https://pkgs.tailscale.com/stable/tailscale_{version}_{arch}.tgz"
# The standalone macOS app: the official package, notarized, signed by Tailscale Inc.
TAILSCALE_APP_VERSION = "1.104.2"
TAILSCALE_APP_URL = f"https://pkgs.tailscale.com/stable/Tailscale-{TAILSCALE_APP_VERSION}-macos.pkg"
TAILSCALE_APP_SHA256 = "1724d2e021d3c5f817f427f628260c013531a528f1258a7d477735d198b11f55"
TAILSCALE_APP_SIGNER = "Developer ID Installer: Tailscale Inc. (W5364U7YZB)"
# acme.sh gets a Let's Encrypt certificate for a region with a domain, answering DNS-01 through
# Cloudflare's API. Only these two files are used; each is checked against its sha256.
ACME_SH_VERSION = "3.1.6"
ACME_SH_URL = "https://raw.githubusercontent.com/acmesh-official/acme.sh/{version}/{path}"
ACME_SH_SHA256 = {
    "acme.sh": "c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7",
    "dnsapi/dns_cf.sh": "9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8",
}
# cloudflared runs the tunnel in front of tn-agent; the release's own binaries, checked against the
# sha256 its release notes publish.
CLOUDFLARED_VERSION = "2026.10.1"
CLOUDFLARED_URL = "https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-linux-{arch}"
CLOUDFLARED_SHA256 = {
    "amd64": "3bfc539f45d2620c71debb7a86be0efa737ed5ccbad9eb85c787116900e5c586",
    "arm64": "2c65dfabf616c40efc7545d107d7a57ad5e21377e2964b7e88af19a238074a46",
}
DEFAULT_AGENT_PORT = 18480   # tn-agent's port on the control host's loopback, where cloudflared reaches it
ACME_SERVER = "letsencrypt"
ACME_DNS_SLEEP = 60       # seconds for the TXT record to reach Cloudflare's servers; skips acme.sh's DoH checks
DEFAULT_TAILSCALE_PORT = 41641
PREAUTH_KEY_EXPIRY = "10m"
JOIN_CODE_EXPIRY = "30m"   # a link code made by hand elsewhere and pasted in

OFFICIAL_DERP_MAP = "https://controlplane.tailscale.com/derpmap/default"
IPV6_PREFIX = "fd7a:115c:a1e0::/48"

DEFAULT_PORT = 9443
DEFAULT_STUN_PORT = 3478
DEFAULT_METRICS_PORT = 9090
DEFAULT_GRPC_PORT = 50443

CA_DAYS = 3650
SERVER_CERT_DAYS = 825
CERT_RENEW_DAYS = 30


def headscale_asset(arch):
    return f"headscale_{HEADSCALE_VERSION}_linux_{arch}"


def headscale_url(arch):
    return HEADSCALE_URL.format(version=HEADSCALE_VERSION, arch=arch)


def acme_url(path):
    return ACME_SH_URL.format(version=ACME_SH_VERSION, path=path)


def tailscale_asset(arch):
    return f"tailscale_{TAILSCALE_VERSION}_{arch}.tgz"


def tailscale_url(arch):
    return TAILSCALE_URL.format(version=TAILSCALE_VERSION, arch=arch)


def cloudflared_url(arch):
    return CLOUDFLARED_URL.format(version=CLOUDFLARED_VERSION, arch=arch)
