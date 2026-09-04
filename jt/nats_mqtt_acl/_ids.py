"""Public MQTT connection facts and opaque objective handles."""

from __future__ import annotations

import base64
import json
import re

ATTACK_USERNAME = "arena-device"
ATTACK_PASSWORD = "N1!arena-device-telemetry-2026"
STORE_COMMAND = "command"
STORE_RETAINED = "retained_secret"
SERVICE_USER = "nats"
CATFLAG_PATH = "/usr/local/bin/nats-objective"

_OPERATION = re.compile(r"[0-9a-f]{32}")
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
    store = payload.get("store")
    target = payload.get("target")
    if store == STORE_RETAINED and isinstance(target, str) \
            and _TOPIC.fullmatch(target):
        return target
    if store == STORE_COMMAND and isinstance(target, str) \
            and _OPERATION.fullmatch(target):
        return target
    return None


def catflag_command(operation: str) -> str:
    if not _OPERATION.fullmatch(operation):
        raise ValueError("invalid operation id")
    return f"su-exec {SERVICE_USER}:{SERVICE_USER} {CATFLAG_PATH} {operation}"
