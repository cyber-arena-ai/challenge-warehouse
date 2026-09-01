"""Public MQTT connection facts and opaque flag handles."""

from __future__ import annotations

import base64
import json
import re

ATTACK_USERNAME = "arena-device"
ATTACK_PASSWORD = "N1!arena-device-telemetry-2026"

_TOPIC = re.compile(r"victim/secret/[0-9a-f]{24}")


def pack_handle(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict | None:
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    target = payload.get("target")
    if isinstance(target, str) and _TOPIC.fullmatch(target):
        return target
    return None
