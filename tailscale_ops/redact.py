"""--redact: replace addresses, host names and keys with stable placeholders."""

import re

from . import privacy


class Redactor:
    """Placeholders come from the site's structure (`<cn-control>`, `<cn-public-ip>`), so
    the same site always redacts the same way. Anything else that looks private is
    numbered by first appearance (`<ip-1>`, `<nodekey-1>`)."""

    def __init__(self, site=None, extra_hosts=None):
        self.names = {}
        self.ips = {}
        self.counters = {}
        self.generic = {}
        if site is not None:
            self._from_site(site)
        for host, placeholder in (extra_hosts or {}).items():
            self.names.setdefault(host, placeholder)

    def _from_site(self, site):
        for r in site.regions.values():
            self.names.setdefault(r.control_host, f"<{r.name}-control>")
            self.names.setdefault(r.check_from, f"<{r.name}-checker>")
            self.ips.setdefault(r.public_ipv4, f"<{r.name}-public-ip>")
            if r.specific_listen:
                self.ips.setdefault(r.listen_ipv4, f"<{r.name}-listen-ip>")
        for i, line in enumerate(site.lines, 1):
            self.names.setdefault(line.initiator, f"<line{i}-initiator>")
            self.names.setdefault(line.responder, f"<line{i}-responder>")
            self.names.setdefault(line.name, f"<line{i}>")
            self.ips.setdefault(line.responder_entry_ipv4, f"<line{i}-entry-ip>")
            self.ips.setdefault(line.initiator_public_ipv4, f"<line{i}-initiator-ip>")
            # Derived names carry the line name joined by '-', which whole-token matching skips.
            self.names.setdefault(line.interface, f"wg-<line{i}>")
            if line.tunnel_ipv4:
                for end, ip in zip(("initiator", "responder"), line.tunnel_addresses):
                    self.ips.setdefault(ip, f"<line{i}-tunnel-{end}>")
        for i, alias in enumerate(site.host_settings, 1):
            self.names.setdefault(alias, f"<host{i}>")
        self.ips = {
            ip: p for ip, p in self.ips.items()
            if (a := privacy.parse_ipv4(ip)) is not None and not (a.is_unspecified or a.is_loopback)
        }

    def _number(self, kind, value):
        key = (kind, value)
        if key not in self.generic:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.generic[key] = f"<{kind}-{self.counters[kind]}>"
        return self.generic[key]

    def __call__(self, text):
        text = privacy.PEM_BLOCK.sub(lambda m: f"<redacted {m.group(1).lower()}>", text)
        for label, pattern in privacy.SECRET_PATTERNS:
            text = pattern.sub(f"<redacted {label}>", text)
        text = privacy.PUBLIC_NODE_KEY.sub(lambda m: self._number(m.group(1), m.group()), text)
        for ip in sorted(self.ips, key=len, reverse=True):
            text = re.sub(r"(?<![\d.])" + re.escape(ip) + r"(?!\.?\d)", self.ips[ip], text)
        text = privacy.IPV4_RE.sub(self._ipv4, text)
        text = privacy.IPV6_RE.sub(self._ipv6, text)
        for name in sorted(self.names, key=len, reverse=True):
            text = privacy.name_pattern(name).sub(self.names[name], text)
        return text

    def _ipv4(self, m):
        addr = privacy.parse_ipv4(m.group())
        if addr is None or privacy.is_shareable_ipv4(addr):
            return m.group()
        return self._number("ip", m.group())

    def _ipv6(self, m):
        for _match, _addr in privacy.unshareable_ipv6(m.group()):
            return self._number("ipv6", m.group())
        return m.group()


def identity(text):
    return text
