"""ECDSA P-256 signature checks in pure Python: the standard library has no ECDSA.

Only verification, of public data, so the arithmetic need not be constant-time.
"""

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def on_curve(point):
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def add(p, q):
    """Affine addition; None is the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        m = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (m * m - x1 - x2) % P
    return x3, (m * (x1 - x3) - y1) % P


def mul(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def der_signature(sig):
    """(r, s) from a DER ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s }."""
    def length(i):
        n = sig[i]
        if n < 0x80:
            return n, i + 1
        count = n & 0x7F
        if count not in (1, 2):
            raise ValueError("bad DER length")
        return int.from_bytes(sig[i + 1:i + 1 + count], "big"), i + 1 + count

    def integer(i):
        if sig[i] != 0x02:
            raise ValueError("expected a DER INTEGER")
        n, i = length(i + 1)
        if n == 0 or n > 33:
            raise ValueError("bad DER INTEGER length")
        return int.from_bytes(sig[i:i + n], "big"), i + n

    try:
        if sig[0] != 0x30:
            raise ValueError("expected a DER SEQUENCE")
        total, i = length(1)
        if i + total != len(sig):
            raise ValueError("DER length does not match")
        r, i = integer(i)
        s, i = integer(i)
    except IndexError:
        raise ValueError("truncated DER signature")
    if i != len(sig):
        raise ValueError("trailing bytes after the DER signature")
    return r, s


def verify(public, digest, r, s):
    """True if (r, s) signs the 32-byte digest for the public point (x, y)."""
    if not on_curve(public) or not (1 <= r < N and 1 <= s < N) or len(digest) != 32:
        return False
    z = int.from_bytes(digest, "big")
    w = pow(s, -1, N)
    point = add(mul(z * w % N, G), mul(r * w % N, public))
    return point is not None and point[0] % N == r
