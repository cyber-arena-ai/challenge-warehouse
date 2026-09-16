"""Deterministic identities and private objective handles."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import string

STORE = "command"
_SEED_RE = re.compile(r"[0-9a-f]{64}")
_TARGET_RE = re.compile(r"operation:([0-9a-f]{24})")
_USER_RE = re.compile(r"[ -~]{1,64}")
_PASSWORD_RE = re.compile(r"[ -~]{12,64}")
_USER_ALPHABET = "".join(chr(codepoint) for codepoint in range(32, 127))
_PASSWORD_ALPHABET = string.ascii_letters + string.digits + string.punctuation + " "


def derive(seed: str, domain: str) -> bytes:
    if not isinstance(seed, str) or _SEED_RE.fullmatch(seed) is None:
        raise ValueError("seed must be 64 lowercase hexadecimal characters")
    return hmac.new(
        bytes.fromhex(seed),
        f"pyload-download-manager\0v1\0{domain}".encode(),
        hashlib.sha256,
    ).digest()


def target_id(seed: str) -> str:
    return "operation:" + derive(seed, "command:target").hex()[:24]


def target_locator(value: object) -> str | None:
    match = _TARGET_RE.fullmatch(value) if isinstance(value, str) else None
    return match.group(1) if match is not None else None


def principal_credentials(seed: str) -> tuple[str, str]:
    identity = (
        derive(seed, "principal:username")
        + derive(seed, "principal:username:tail")
        + derive(seed, "principal:username:tail:2")
    )
    username_length = 1 + identity[0] % 64
    username = "".join(
        _USER_ALPHABET[byte % len(_USER_ALPHABET)]
        for byte in identity[1:username_length + 1]
    )
    secret = (
        derive(seed, "principal:password")
        + derive(seed, "principal:password:tail")
        + derive(seed, "principal:password:tail:2")
    )
    password_length = 12 + secret[0] % 53
    password = "".join(
        _PASSWORD_ALPHABET[byte % len(_PASSWORD_ALPHABET)]
        for byte in secret[1:password_length + 1]
    )
    return username, password


def valid_username(value: object) -> bool:
    return isinstance(value, str) and _USER_RE.fullmatch(value) is not None


def valid_password(value: object) -> bool:
    return isinstance(value, str) and _PASSWORD_RE.fullmatch(value) is not None


def pack_handle(target: str, proof: str) -> str:
    raw = json.dumps(
        {"proof": proof, "store": STORE, "target": target},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict[str, str] | None:
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"proof", "store", "target"}
        or value.get("store") != STORE
        or not isinstance(value.get("proof"), str)
        or not value["proof"]
        or target_locator(value.get("target")) is None
    ):
        return None
    return value
