import os
import socket
import struct
import subprocess
import sys
import threading
import unittest
import zlib
from pathlib import Path

from tailnet_ops import stun


def tailscale_style_parse(b):
    """What Tailscale's STUN server demands before it answers (net/stun ParseBindingRequest)."""
    if len(b) < 20 or b[:2] != b"\x00\x01" or b[4:8] != struct.pack("!I", stun.MAGIC_COOKIE):
        return None
    txid, attrs, software, last, fp = b[8:20], b[20:], None, None, None
    while len(attrs) >= 4:
        atype, alen = struct.unpack("!HH", attrs[:4])
        value = attrs[4:4 + alen]
        last = atype
        if atype == 0x8022:
            software = value
        if atype == 0x8028:
            fp = struct.unpack("!I", value)[0]
        attrs = attrs[4 + ((alen + 3) & ~3):]
    if software != b"tailnode" or last != 0x8028:
        return None
    if fp != (zlib.crc32(b[:-8]) & 0xFFFFFFFF) ^ 0x5354554E:
        return None
    return txid


def response(txid, ip, port):
    xport = port ^ (stun.MAGIC_COOKIE >> 16)
    xaddr = bytes(a ^ b for a, b in zip(socket.inet_aton(ip), struct.pack("!I", stun.MAGIC_COOKIE)))
    attr = struct.pack("!HHBBH", 0x0020, 8, 0, 1, xport) + xaddr
    return struct.pack("!HHI", 0x0101, len(attr), stun.MAGIC_COOKIE) + txid + attr


class FakeStunServer:
    """A strict, Tailscale-like STUN server on 127.0.0.1."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                return
            txid = tailscale_style_parse(data)
            if txid is not None:
                self.sock.sendto(response(txid, addr[0], addr[1]), addr)

    def close(self):
        self.sock.close()


class StunTest(unittest.TestCase):
    def test_request_satisfies_tailscale(self):
        txid = os.urandom(12)
        req = stun.binding_request(txid)
        self.assertEqual(len(req), 20 + 12 + 8)
        self.assertEqual(tailscale_style_parse(req), txid)

    def test_parse_response(self):
        txid = os.urandom(12)
        self.assertEqual(stun.parse_response(response(txid, "203.0.113.7", 41641), txid), ("203.0.113.7", 41641))
        with self.assertRaises(ValueError):
            stun.parse_response(response(txid, "203.0.113.7", 1), os.urandom(12))

    def test_probe_against_strict_server(self):
        server = FakeStunServer()
        try:
            ip, port = stun.probe("127.0.0.1", server.port, attempts=2, timeout=1)
            self.assertEqual(ip, "127.0.0.1")
            self.assertGreater(port, 0)
            # The same file, run the way the checker runs it.
            p = subprocess.run([sys.executable, "-I", "-", "127.0.0.1", str(server.port)],
                               input=Path(stun.__file__).read_text(), capture_output=True, text=True, timeout=20)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("STUN binding ok", p.stdout)
        finally:
            server.close()

    def test_probe_times_out(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        try:
            with self.assertRaises(TimeoutError):
                stun.probe("127.0.0.1", s.getsockname()[1], attempts=1, timeout=0.2)
        finally:
            s.close()
