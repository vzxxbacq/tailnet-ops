"""What counts as site data or a secret. Shared by the guard and --redact."""

import ipaddress
import re

CGNAT = ipaddress.IPv4Network("100.64.0.0/10")
DOC_NETS = tuple(
    ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
# tailnet-ops's own default range for alias ranges and line tunnels: the same for every site.
TOOL_NET = ipaddress.IPv4Network("10.255.0.0/16")
# Addresses that may appear in the repository and in shared output.
SHAREABLE_NETS = DOC_NETS + (
    CGNAT,
    TOOL_NET,
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("0.0.0.0/32"),
)

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
SHAREABLE_V6 = tuple(
    ipaddress.IPv6Network(n) for n in ("fd7a:115c:a1e0::/48", "2001:db8::/32", "::1/128", "::/128", "fe80::/10")
)

SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("Headscale key", re.compile(r"\bhskey-(?:auth|api)-[A-Za-z0-9_-]{8,}")),
    ("Tailscale key", re.compile(r"\btskey-[a-z]+-[A-Za-z0-9_-]{8,}")),
    ("tn-agent MCP token", re.compile(r"\btna_[A-Za-z0-9_-]{40,}")),
    ("Tailscale private key", re.compile(r"\b(?:privkey|nlpriv):[0-9a-f]{64}\b")),
    ("legacy Headscale pre-auth key", re.compile(r"(?<![0-9A-Fa-f])[0-9a-f]{48}(?![0-9A-Fa-f])")),
    ("WireGuard private key", re.compile(r"(?i)\bPrivateKey\s*=\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")),
    (
        "token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}"
            r"|xox[abprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}"
            r"|AKIA[0-9A-Z]{16})"
        ),
    ),
    ("bearer token", re.compile(r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}")),
)

PRIVATE_LINK = re.compile(
    r"(?i)\b(?:claude\.ai/(?:code/)?(?:artifact|chat|share|project)s?/"
    r"|docs\.google\.com/|drive\.google\.com/"
    r"|(?:[\w-]+\.)?notion\.(?:so|site)/"
    r"|[\w-]+\.(?:feishu\.cn|larksuite\.com)/(?:docx|docs|wiki|sheets|base)/"
    r"|(?:www\.)?dropbox\.com/(?:s|scl)/)"
)

PUBLIC_NODE_KEY = re.compile(r"\b(nodekey|mkey|discokey|nlpub):[0-9a-f]{64}\b")
PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)


def parse_ipv4(text):
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def is_shareable_ipv4(addr):
    return any(addr in net for net in SHAREABLE_NETS)


def unshareable_ipv4(text):
    """Yield (match, address) for IPv4 literals that must not be shared."""
    for m in IPV4_RE.finditer(text):
        addr = parse_ipv4(m.group())
        if addr is not None and not is_shareable_ipv4(addr):
            yield m, addr


def unshareable_ipv6(text):
    for m in IPV6_RE.finditer(text):
        if m.group().count(":") < 2:
            continue
        try:
            addr = ipaddress.IPv6Address(m.group())
        except ValueError:
            continue
        if not any(addr in net for net in SHAREABLE_V6):
            yield m, addr


def name_pattern(name):
    """Match a host name as a whole token, so `cn-edge` does not match `edge`. A name right after
    ':' is a qualifier, not a host (`mode="w:gz"`, `tag:edge`), and one right after '.' is a suffix
    (`x.tar.gz`), except in a site.toml key (`hosts.edge`, `lines.edge`)."""
    return re.compile(r"(?:(?<=hosts\.)|(?<=lines\.)|(?<![A-Za-z0-9_.:-]))" + re.escape(name) + r"(?![A-Za-z0-9_-])",
                      re.I)
