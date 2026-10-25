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
DEFAULT_TAILSCALE_PORT = 41641
PREAUTH_KEY_EXPIRY = "10m"

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


def tailscale_asset(arch):
    return f"tailscale_{TAILSCALE_VERSION}_{arch}.tgz"


def tailscale_url(arch):
    return TAILSCALE_URL.format(version=TAILSCALE_VERSION, arch=arch)
