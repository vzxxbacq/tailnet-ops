"""A small CBOR decoder: what WebAuthn's attestation object and COSE keys use (RFC 8949).

Definite lengths only; integers, byte and text strings, arrays, maps, and false/true/null.
"""


class CBORError(ValueError):
    pass


def loads(data):
    value, end = decode(data, 0)
    if end != len(data):
        raise CBORError("trailing bytes after the CBOR item")
    return value


def decode(data, i, depth=0):
    """(value, offset after it) for the item at data[i]."""
    if depth > 16:
        raise CBORError("CBOR nested too deeply")
    if i >= len(data):
        raise CBORError("truncated CBOR")
    major, info = data[i] >> 5, data[i] & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if i + size > len(data):
            raise CBORError("truncated CBOR")
        arg = int.from_bytes(data[i:i + size], "big")
        i += size
    else:
        raise CBORError("indefinite or reserved CBOR lengths are not supported")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(data):
            raise CBORError("truncated CBOR string")
        raw = bytes(data[i:i + arg])
        return (raw if major == 2 else raw.decode("utf-8")), i + arg
    if major == 4:
        items = []
        for _ in range(arg):
            item, i = decode(data, i, depth + 1)
            items.append(item)
        return items, i
    if major == 5:
        out = {}
        for _ in range(arg):
            key, i = decode(data, i, depth + 1)
            if isinstance(key, (list, dict)):
                raise CBORError("CBOR map keys must be simple values")
            out[key], i = decode(data, i, depth + 1)
        return out, i
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise CBORError(f"unsupported CBOR item (major type {major})")
