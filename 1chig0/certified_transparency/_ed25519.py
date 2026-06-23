"""Minimal pure-Python Ed25519 (RFC 8032), stdlib-only.

Interoperates with Go's `crypto/ed25519`: the service signs/verifies raw
Ed25519 over 32-byte SHA3 digests, and the FlagHandler's legitimate
`claim-public` path needs to sign a leaf with a freshly generated key. Rather
than depend on the (unlisted) `cryptography` wheel, this implements the few
primitives we need so the handler stays self-contained on stdlib.

Only `seed -> public key` and `sign(seed, msg)` are exercised here; both follow
RFC 8032 and match Go's output byte-for-byte.
"""
from __future__ import annotations

import hashlib
import os

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q, 1, (_Bx * _By) % _q)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * 2 * _d * t2 % _q
    dd = z1 * 2 * z2 % _q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return (x3 % _q, y3 % _q, z3 % _q, t3 % _q)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodepoint(P) -> bytes:
    x, y, z, _t = P
    zi = _inv(z)
    x = (x * zi) % _q
    y = (y * zi) % _q
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8)
    )


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * _b))


def publickey_from_seed(seed: bytes) -> bytes:
    h = _H(seed)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def sign(seed: bytes, msg: bytes) -> bytes:
    """RFC 8032 Ed25519 signature over `msg` using 32-byte `seed`."""
    h = _H(seed)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    A = _encodepoint(_scalarmult(_B, a))
    r = _Hint(h[_b // 8:_b // 4] + msg)
    R = _scalarmult(_B, r)
    Rs = _encodepoint(R)
    k = _Hint(Rs + A + msg)
    s = (r + k * a) % _L
    return Rs + s.to_bytes(32, "little")


def keypair() -> tuple[bytes, bytes]:
    """Return (seed, public_key_32). The seed is the Go 'private key' first half."""
    seed = os.urandom(32)
    return seed, publickey_from_seed(seed)


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(_b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    P = (x, y, 1, (x * y) % _q)
    return P


def _isoncurve(P) -> bool:
    x, y, z, _t = P
    zi = _inv(z)
    x = (x * zi) % _q
    y = (y * zi) % _q
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def verify(pubkey: bytes, signature: bytes, msg: bytes) -> bool:
    """RFC 8032 Ed25519 verify. Returns False on any malformed input."""
    try:
        if len(signature) != 64 or len(pubkey) != 32:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(pubkey)
        if not _isoncurve(A):
            return False
        s = int.from_bytes(signature[32:], "little")
        h = _Hint(signature[:32] + pubkey + msg)
        x1, y1, z1, _t1 = _scalarmult(_B, s)
        x2, y2, z2, _t2 = _edwards_add(R, _scalarmult(A, h))
        if (x1 * z2 - x2 * z1) % _q != 0:
            return False
        if (y1 * z2 - y2 * z1) % _q != 0:
            return False
        return True
    except Exception:
        return False
