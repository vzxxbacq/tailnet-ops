"""STUN binding probe for the embedded Headscale DERP/STUN server.

Self-contained: `tn control verify` sends this file to the checker host and runs it
with `python3 - <address> <port>`. Tailscale's STUN server only answers binding
requests that carry SOFTWARE "tailnode" and a FINGERPRINT, so we send exactly that.
"""

import os
import socket
import struct
import sys
import zlib

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
SOFTWARE = b"tailnode"
FINGERPRINT_XOR = 0x5354554E


def fingerprint(data):
    return (zlib.crc32(data) & 0xFFFFFFFF) ^ FINGERPRINT_XOR


def binding_request(txid):
    if len(txid) != 12:
        raise ValueError("transaction id must be 12 bytes")
    software = struct.pack("!HH", ATTR_SOFTWARE, len(SOFTWARE)) + SOFTWARE
    length = len(software) + 8
    head = struct.pack("!HHI", BINDING_REQUEST, length, MAGIC_COOKIE) + txid
    body = head + software
    return body + struct.pack("!HHI", ATTR_FINGERPRINT, 4, fingerprint(body))


def parse_response(data, txid):
    """Return (ip, port) from a binding success response, or raise ValueError."""
    if len(data) < 20:
        raise ValueError("short STUN message")
    kind, length, cookie = struct.unpack("!HHI", data[:8])
    if cookie != MAGIC_COOKIE or data[8:20] != txid:
        raise ValueError("not a response to our request")
    if kind != BINDING_SUCCESS:
        raise ValueError(f"STUN message type 0x{kind:04x}, expected binding success")
    attrs = data[20 : 20 + length]
    mapped = None
    while len(attrs) >= 4:
        atype, alen = struct.unpack("!HH", attrs[:4])
        value = attrs[4 : 4 + alen]
        attrs = attrs[4 + ((alen + 3) & ~3) :]
        if atype in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS) and len(value) >= 8 and value[1] in (1, 2):
            # Family 1 is IPv4. Family 2 is IPv6; a dual-stack server such as Headscale on
            # *:3478 reports an IPv4 client as an IPv4-mapped IPv6 address.
            size = 4 if value[1] == 1 else 16
            if len(value) < 4 + size:
                continue
            port = struct.unpack("!H", value[2:4])[0]
            addr = value[4:4 + size]
            if atype == ATTR_XOR_MAPPED_ADDRESS:
                port ^= MAGIC_COOKIE >> 16
                key = struct.pack("!I", MAGIC_COOKIE) + txid
                addr = bytes(a ^ b for a, b in zip(addr, key))
            if size == 16 and addr[:12] == b"\0" * 10 + b"\xff\xff":
                addr = addr[12:]
            family = socket.AF_INET if len(addr) == 4 else socket.AF_INET6
            mapped = (socket.inet_ntop(family, addr), port)
            if atype == ATTR_XOR_MAPPED_ADDRESS:
                break
    if mapped is None:
        raise ValueError("no mapped address in the response")
    return mapped


def probe(host, port, attempts=3, timeout=2.0):
    txid = os.urandom(12)
    request = binding_request(txid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for _ in range(attempts):
            s.sendto(request, (host, port))
            try:
                while True:
                    data, _src = s.recvfrom(2048)
                    try:
                        return parse_response(data, txid)
                    except ValueError:
                        continue
            except socket.timeout:
                continue
    raise TimeoutError(f"no STUN answer from {host}:{port} after {attempts} tries")


def main(argv):
    if len(argv) != 3:
        print("usage: stun.py <address> <port>", file=sys.stderr)
        return 2
    try:
        ip, port = probe(argv[1], int(argv[2]))
    except (OSError, ValueError) as e:
        print(f"    STUN failed: {e}", file=sys.stderr)
        return 1
    print(f"    STUN binding ok: this checker is seen as {ip}:{port}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
