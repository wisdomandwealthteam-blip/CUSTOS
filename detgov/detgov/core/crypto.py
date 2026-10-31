"""Policy verification: canonical JSON + verify-only Ed25519 (RFC 8032, pure Python, standard library only).

Runtime nodes need only the 32-byte public key (hex). Signing is deliberately NOT part of this package: sign the bytes produced by
`canonical_json_bytes(policy)` with any RFC 8032 tool (e.g. `openssl pkeyutl -sign -rawin`), keep the private key offline.

Signed message = canonical_json_bytes(parsed policy): sorted keys, separators (",", ":"), UTF-8, no NaN/Infinity, and no floats
(float text differs across languages; use integers/strings in policies).
"""
import hashlib
import json
import os
import re
from typing import Optional

MAX_POLICY_BYTES = 1024 * 1024
MAX_SIG_FILE_BYTES = 4096

# ---------------------------------------------------------------- canonical JSON

class StrictJSONError(ValueError):
    pass


def _reject_floats(obj):
    stack = [obj]
    n = 0
    while stack:
        v = stack.pop()
        n += 1
        if n > 1_000_000:
            raise ValueError("object too large to canonicalise")
        if isinstance(v, float):
            raise ValueError("floats are not allowed in canonical policy JSON")
        if isinstance(v, dict):
            if not all(isinstance(k, str) for k in v):
                raise ValueError("object keys must be strings")
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)


def canonical_json_bytes(obj) -> bytes:
    """Deterministic bytes for a JSON-compatible object. Raises ValueError/TypeError on NaN/Infinity, floats, non-JSON types, lone surrogates."""
    _reject_floats(obj)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return text.encode("utf-8")


def loads_strict(data: bytes):
    """Parse JSON bytes, rejecting duplicate keys, NaN/Infinity, invalid UTF-8 and excessive nesting."""
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise StrictJSONError(f"duplicate key {k!r}")
            d[k] = v
        return d

    def const(name):
        raise StrictJSONError("NaN/Infinity not allowed")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=const)
    except StrictJSONError:
        raise
    except (ValueError, RecursionError) as e:
        raise StrictJSONError("invalid JSON") from e


# ---------------------------------------------------------------- Ed25519 (verify only)

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_MASK255 = (1 << 255) - 1


def _inv(x):
    return pow(x, _P - 2, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _recover_x(_BY, 0)
_BASE = (_BX, _BY, 1, _BX * _BY % _P)
_IDENT = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    r = _IDENT
    while s:
        if s & 1:
            r = _add(r, p)
        p = _add(p, p)
        s >>= 1
    return r


def _eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _decode_point(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= _MASK255
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 verification (cofactorless equation). Strict: canonical encodings only, S < L, small-order public keys rejected."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a_pt = _decode_point(bytes(public_key))
        r_pt = _decode_point(bytes(signature[:32]))
        if a_pt is None or r_pt is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= _Q:
            return False
        if _eq(_mul(8, a_pt), _IDENT):
            return False                      # small-order key
        h = int.from_bytes(hashlib.sha512(bytes(signature[:32]) + bytes(public_key) + bytes(message)).digest(), "little") % _Q
        return _eq(_mul(s, _BASE), _add(r_pt, _mul(h, a_pt)))
    except Exception:
        return False


_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_HEX128 = re.compile(r"[0-9a-fA-F]{128}")


def parse_public_key_hex(public_key_hex) -> Optional[bytes]:
    if not isinstance(public_key_hex, str) or not _HEX64.fullmatch(public_key_hex):
        return None
    return bytes.fromhex(public_key_hex)


def verify_policy_bytes(policy_bytes: bytes, public_key_hex: str, sig_hex_text: str) -> bool:
    """Verify `sig_hex_text` (128 hex chars, surrounding whitespace ignored) over canonical_json_bytes(parse(policy_bytes)). Never raises."""
    try:
        pk = parse_public_key_hex(public_key_hex)
        sig_text = sig_hex_text.strip() if isinstance(sig_hex_text, str) else ""
        if pk is None or not _HEX128.fullmatch(sig_text):
            return False
        obj = loads_strict(policy_bytes)
        return ed25519_verify(pk, canonical_json_bytes(obj), bytes.fromhex(sig_text))
    except Exception:
        return False


def read_limited(path: str, limit: int) -> bytes:
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file too large")
    return data


def verify_policy_signature(policy_path: str, public_key_hex: str, sig_path: str = None) -> bool:
    """True iff the hex Ed25519 signature in `sig_path` (default: policy_path + '.sig') is valid for the policy's canonical JSON. Never raises."""
    try:
        policy = read_limited(policy_path, MAX_POLICY_BYTES)
        sig = read_limited(sig_path if sig_path is not None else str(policy_path) + ".sig", MAX_SIG_FILE_BYTES)
        return verify_policy_bytes(policy, public_key_hex, sig.decode("ascii"))
    except Exception:
        return False
