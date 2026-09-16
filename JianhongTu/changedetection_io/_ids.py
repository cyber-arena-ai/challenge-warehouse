"""Deterministic round identities and private flag handles."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

_SEED_RE = re.compile(r"[0-9a-f]{64}")
_TARGET_RE = re.compile(r"/datastore/secret-[0-9a-f]{24}\.txt")


def _derive(seed: str, domain: str) -> bytes:
    if not isinstance(seed, str) or _SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed must be 64 lowercase hexadecimal characters")
    return hmac.new(
        bytes.fromhex(seed),
        f"changedetection-io\0v1\0{domain}".encode(),
        hashlib.sha256,
    ).digest()


def round_target(seed: object) -> str:
    if not isinstance(seed, str):
        raise ValueError("round context seed is unavailable")
    return "/datastore/secret-" + _derive(seed, "objective-id").hex()[:24] + ".txt"


def pack_handle(target_id: str, flag: str) -> str:
    payload = json.dumps(
        {"store": "session_secret", "target": target_id, "flag": flag},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def unpack_handle(handle: str) -> dict[str, str] | None:
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"store", "target", "flag"}
        or not all(isinstance(value, str) for value in payload.values())
        or payload["store"] != "session_secret"
        or _TARGET_RE.fullmatch(payload["target"]) is None
        or not payload["flag"]
    ):
        return None
    return payload


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    return payload["target"] if payload is not None else None


def valid_target(value: object) -> bool:
    return isinstance(value, str) and _TARGET_RE.fullmatch(value) is not None
