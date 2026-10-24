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
