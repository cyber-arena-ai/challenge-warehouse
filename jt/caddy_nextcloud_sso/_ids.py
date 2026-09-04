"""Framework-free public-account, target, and handle helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re

# This is deliberately a public, unprivileged SSO account.  The challenge's
# authorization boundary is group membership, not possession of these values.
PUBLIC_USERNAME = "arena-player"
PUBLIC_PASSWORD = "CaddyNextcloudArena2026!"

_READ_TARGET = re.compile(r"Guarded/[0-9a-f]{24}\.txt")


def valid_read_target(value: str) -> bool:
    return isinstance(value, str) and _READ_TARGET.fullmatch(value) is not None


def pack_handle(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        value = json.loads(base64.urlsafe_b64decode(
            (handle + "=" * (-len(handle) % 4)).encode()))
    except (ValueError, binascii.Error):
        return None
    return value if isinstance(value, dict) else None


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    target = payload.get("target")
    if valid_read_target(target):
        return target
    return None
