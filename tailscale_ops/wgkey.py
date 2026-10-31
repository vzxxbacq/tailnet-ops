"""WireGuard keys made on this machine: X25519 (RFC 7748), standard library only.

Used for phones, which cannot run tn: a phone's key is made here and reaches the phone
inside its configuration file. Not constant-time; it runs once per key, on the
operator's own machine.
"""

import base64
import secrets

P = 2**255 - 19
A24 = 121665


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def x25519(k, u):
    """The X25519 function: scalar k (32 bytes) times the point with u-coordinate u (32 bytes)."""
    n = int.from_bytes(_clamp(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def private_key():
    """A new private key, base64 as `wg genkey` prints it."""
    return base64.b64encode(_clamp(secrets.token_bytes(32))).decode()


def public_key(private):
    """The public key of a base64 private key, as `wg pubkey` prints it."""
    raw = base64.b64decode(private, validate=True)
    if len(raw) != 32:
        raise ValueError("a WireGuard key is 32 bytes")
    return base64.b64encode(x25519(raw, BASE)).decode()
