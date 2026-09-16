"""Shared ordinary identity shapes for match and health traffic."""

from __future__ import annotations

import base64
import hashlib
import re
import string


FIRST_NAMES = ("alex", "casey", "jamie", "jordan", "morgan", "riley", "sam", "taylor")
LAST_NAMES = ("baker", "chen", "davis", "garcia", "kim", "lee", "patel", "rivera")
USERNAME_RE = re.compile(r"[a-z]+\.[a-z]+[0-9]{6}")
KEY_INITIAL_ALPHABET = string.ascii_letters
KEY_TAIL_ALPHABET = string.ascii_letters + string.digits + "_.-"
PASSWORD_RE = re.compile(r"[A-Za-z0-9_-]{40}")
VARIABLE_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{7,95}")


def ordinary_username(material: bytes) -> str:
    """Map deterministic or random bytes into the same ordinary login shape."""
    if not isinstance(material, bytes) or len(material) < 6:
        raise ValueError("username material is unavailable")
    given = FIRST_NAMES[material[0] % len(FIRST_NAMES)]
    family = LAST_NAMES[material[1] % len(LAST_NAMES)]
    suffix = int.from_bytes(material[2:6], "big") % 900_000 + 100_000
    return f"{given}.{family}{suffix}"


def valid_ordinary_username(value: object) -> bool:
    return isinstance(value, str) and USERNAME_RE.fullmatch(value) is not None


def ordinary_password(material: bytes) -> str:
    """Map deterministic or random bytes into one ordinary password shape."""
    if not isinstance(material, bytes) or len(material) < 30:
        raise ValueError("password material is unavailable")
    return base64.urlsafe_b64encode(material).decode().rstrip("=")[:40]


def valid_ordinary_password(value: object) -> bool:
    return isinstance(value, str) and PASSWORD_RE.fullmatch(value) is not None


def ordinary_variable_key(material: bytes) -> str:
    """Map deterministic or random bytes across ordinary Variable-key shapes."""
    if not isinstance(material, bytes) or len(material) < 16:
        raise ValueError("Variable key material is unavailable")
    stream = hashlib.shake_256(b"airflow-variable-key-v2\0" + material).digest(97)
    length = 8 + stream[0] % 89
    initial = KEY_INITIAL_ALPHABET[stream[1] % len(KEY_INITIAL_ALPHABET)]
    tail = "".join(
        KEY_TAIL_ALPHABET[value % len(KEY_TAIL_ALPHABET)]
        for value in stream[2 : length + 1]
    )
    return initial + tail


def valid_ordinary_variable_key(value: object) -> bool:
    return isinstance(value, str) and VARIABLE_KEY_RE.fullmatch(value) is not None
