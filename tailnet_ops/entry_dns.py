#!/usr/bin/python3
"""DNS for phones on a tailnet-ops entry, installed on the control host by `tn control apply`.

    tn-entry-dns --listen 10.255.254.1 --suffix vlan [--magic 100.100.100.100]

Names under a suffix go to MagicDNS (tailscaled on this host answers 100.100.100.100), so
phones resolve <host>.<region>.<suffix> to addresses this entry reaches. Every other name
goes to this host's own resolvers (/etc/resolv.conf, read for each query). Answers are
passed back unchanged; what cannot be answered gets SERVFAIL. It listens only on the
entry's address, so only phones in the tunnel reach it. Standard library only.
"""

import argparse
import socket
import socketserver
import struct
import threading

TIMEOUT = 3.0


def question(packet):
    """(name, end) of a query's first question: the name in lower case and the offset after its
    type and class. None when the packet is not a query with one readable question."""
    if len(packet) < 12 or packet[2] & 0x80 or struct.unpack("!H", packet[4:6])[0] < 1:
        return None
    i, labels = 12, []
    while i < len(packet):
        n = packet[i]
        if n == 0:
            end = i + 5
            return (".".join(labels).lower(), end) if end <= len(packet) else None
        if n & 0xC0 or i + 1 + n > len(packet):
            return None
        labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None


def servfail(query, end):
    flags = (struct.unpack("!H", query[2:4])[0] & 0x7900) | 0x8080 | 2  # opcode and RD kept; QR, RA, SERVFAIL
    return query[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + query[12:end]


def resolvers(path="/etc/resolv.conf", skip=()):
    out = []
    try:
        with open(path) as f:
            for line in f:
                words = line.split()
                if len(words) >= 2 and words[0] == "nameserver" and words[1] not in skip:
                    out.append(words[1])
    except OSError:
        pass
    return out or ["127.0.0.53"]


def servers_for(name, suffixes, magic, upstream):
    if any(name == s or name.endswith("." + s) for s in suffixes):
        return [magic]
    return upstream


def ask_udp(server, query, port=53):
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.sendto(query, (server, port))
        while True:
            answer, _ = s.recvfrom(65535)
            if answer[:2] == query[:2]:
                return answer


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def ask_tcp(server, query, port=53):
    with socket.create_connection((server, port), timeout=TIMEOUT) as s:
        s.sendall(struct.pack("!H", len(query)) + query)
        head = _recv_exact(s, 2)
        return _recv_exact(s, struct.unpack("!H", head)[0]) if head else None


class Forwarder:
    def __init__(self, listen, suffixes, magic, port=53, resolv_conf="/etc/resolv.conf", upstream_port=53):
        self.listen, self.port = listen, port
        self.suffixes = [s.strip(".").lower() for s in suffixes]
        self.magic, self.resolv_conf, self.upstream_port = magic, resolv_conf, upstream_port

    def answer(self, query, tcp=False):
        q = question(query)
        if q is None:
            return None
        name, end = q
        upstream = resolvers(self.resolv_conf, skip=(self.listen,))
        for server in servers_for(name, self.suffixes, self.magic, upstream):
            try:
                answer = (ask_tcp if tcp else ask_udp)(server, query, self.upstream_port)
                if answer:
                    return answer
            except OSError:
                continue
        return servfail(query, end)

    def servers(self):
        forwarder = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                answer = forwarder.answer(data)
                if answer:
                    sock.sendto(answer, self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(10)
                while True:
                    head = _recv_exact(self.request, 2)
                    query = head and _recv_exact(self.request, struct.unpack("!H", head)[0])
                    answer = query and forwarder.answer(query, tcp=True)
                    if not answer:
                        return
                    self.request.sendall(struct.pack("!H", len(answer)) + answer)

        for cls in (socketserver.ThreadingUDPServer, socketserver.ThreadingTCPServer):
            cls.allow_reuse_address = True
            cls.daemon_threads = True
        return [socketserver.ThreadingUDPServer((self.listen, self.port), UDP),
                socketserver.ThreadingTCPServer((self.listen, self.port), TCP)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", required=True, help="the entry's own address")
    ap.add_argument("--suffix", action="append", required=True, help="a MagicDNS suffix, e.g. vlan")
    ap.add_argument("--magic", default="100.100.100.100", help="MagicDNS")
    ap.add_argument("--port", type=int, default=53)
    args = ap.parse_args(argv)
    servers = Forwarder(args.listen, args.suffix, args.magic, args.port).servers()
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
