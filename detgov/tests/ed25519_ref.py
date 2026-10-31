"""Test-only RFC 8032 signer (private-key operations never ship in the runtime package). Shares point arithmetic with detgov.core.crypto;
correctness of the arithmetic is pinned by the RFC 8032 vectors in test_crypto.py."""
import hashlib
from detgov.core import crypto as C


def _clamp(h):
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")


def _enc(p):
    x, y, z, _ = p
    zi = C._inv(z)
    x, y = x * zi % C._P, y * zi % C._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def public_key(sk: bytes) -> bytes:
    return _enc(C._mul(_clamp(hashlib.sha512(sk).digest()), C._BASE))


def sign(sk: bytes, msg: bytes) -> bytes:
    h = hashlib.sha512(sk).digest()
    a = _clamp(h)
    pk = _enc(C._mul(a, C._BASE))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % C._Q
    big_r = _enc(C._mul(r, C._BASE))
    k = int.from_bytes(hashlib.sha512(big_r + pk + msg).digest(), "little") % C._Q
    return big_r + ((r + k * a) % C._Q).to_bytes(32, "little")
