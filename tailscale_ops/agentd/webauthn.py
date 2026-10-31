"""WebAuthn checks for passkeys: a new credential (enrolment) and a signed assertion (approval).

Only ES256 (ECDSA P-256 with SHA-256), which every platform passkey supports. Attestation is not
checked: Apple gives none, and a credential is trusted because the owner enrolled it with a one-time
code from `tn agent enroll`. Every assertion must carry user verification (Face ID, Touch ID or the
device passcode), not only presence.
"""

import base64
import hashlib
import json

from . import cbor, p256

FLAG_UP = 0x01   # user present
FLAG_UV = 0x04   # user verified
FLAG_AT = 0x40   # attested credential data follows


class WebAuthnError(ValueError):
    pass


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text):
    if not isinstance(text, str):
        raise WebAuthnError("expected base64url text")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise WebAuthnError("bad base64url")


def client_data(raw, kind, challenge, origin):
    """The parsed clientDataJSON, after checking its type, challenge and origin."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("clientDataJSON is not JSON")
    if not isinstance(data, dict):
        raise WebAuthnError("clientDataJSON is not an object")
    if data.get("type") != kind:
        raise WebAuthnError(f"clientDataJSON type is {data.get('type')!r}, not {kind}")
    if data.get("challenge") != b64url(challenge):
        raise WebAuthnError("the challenge does not match")
    if data.get("origin") != origin:
        raise WebAuthnError(f"origin {data.get('origin')!r} is not {origin}")
    if data.get("crossOrigin"):
        raise WebAuthnError("cross-origin requests are refused")
    return data


def authenticator_data(raw, rp_id):
    """{flags, sign_count, rest} after checking the RP ID hash and that the user was verified."""
    if len(raw) < 37:
        raise WebAuthnError("authenticator data is too short")
    if raw[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError(f"the credential is not for {rp_id}")
    flags = raw[32]
    if not flags & FLAG_UP:
        raise WebAuthnError("the user was not present")
    if not flags & FLAG_UV:
        raise WebAuthnError("the user was not verified (Face ID, Touch ID or passcode)")
    return {"flags": flags, "sign_count": int.from_bytes(raw[33:37], "big"), "rest": raw[37:]}


def _cose_es256(key):
    """(x, y) from a COSE_Key map: EC2 (1: 2), ES256 (3: -7), P-256 (-1: 1)."""
    if not isinstance(key, dict) or key.get(1) != 2 or key.get(3) != -7 or key.get(-1) != 1:
        raise WebAuthnError("the credential is not an ES256 (P-256) key")
    x, y = key.get(-2), key.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
        raise WebAuthnError("bad P-256 coordinates")
    point = (int.from_bytes(x, "big"), int.from_bytes(y, "big"))
    if not p256.on_curve(point):
        raise WebAuthnError("the public key is not on P-256")
    return point


def registration(client_data_json, attestation_object, challenge, origin, rp_id):
    """A new credential from navigator.credentials.create(): {id, x, y, sign_count}."""
    client_data(client_data_json, "webauthn.create", challenge, origin)
    try:
        att = cbor.loads(attestation_object)
    except cbor.CBORError as e:
        raise WebAuthnError(f"bad attestation object: {e}")
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise WebAuthnError("the attestation object has no authData")
    auth = authenticator_data(att["authData"], rp_id)
    if not auth["flags"] & FLAG_AT:
        raise WebAuthnError("no attested credential data")
    rest = auth["rest"]
    if len(rest) < 18:
        raise WebAuthnError("attested credential data is too short")
    size = int.from_bytes(rest[16:18], "big")
    cred_id = rest[18:18 + size]
    if len(cred_id) != size or not 16 <= size <= 1023:
        raise WebAuthnError("bad credential id")
    try:
        key, _end = cbor.decode(rest, 18 + size)
    except cbor.CBORError as e:
        raise WebAuthnError(f"bad credential public key: {e}")
    x, y = _cose_es256(key)
    return {"id": b64url(cred_id), "x": f"{x:064x}", "y": f"{y:064x}", "sign_count": auth["sign_count"]}


def assertion(credential, client_data_json, authenticator_data_raw, signature, challenge, origin, rp_id):
    """Check a navigator.credentials.get() result against a stored credential; the new sign count."""
    client_data(client_data_json, "webauthn.get", challenge, origin)
    auth = authenticator_data(authenticator_data_raw, rp_id)
    try:
        r, s = p256.der_signature(signature)
    except ValueError as e:
        raise WebAuthnError(f"bad signature: {e}")
    signed = authenticator_data_raw + hashlib.sha256(client_data_json).digest()
    public = (int(credential["x"], 16), int(credential["y"], 16))
    if not p256.verify(public, hashlib.sha256(signed).digest(), r, s):
        raise WebAuthnError("the signature does not verify")
    old, new = credential.get("sign_count", 0), auth["sign_count"]
    # Synced passkeys (Apple's) always report 0; a counter that moves must move forward.
    if (old or new) and new <= old:
        raise WebAuthnError("the sign count went backwards: a cloned authenticator?")
    return new
