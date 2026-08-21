"""Deterministic principals and opaque objective handles."""

from __future__ import annotations

import base64
import hashlib
import json
import re

STORE_COMMAND = "command"
STORE_RETAINED = "retained_secret"
SERVICE_USER = "nats"
CATFLAG_PATH = "/usr/local/bin/nats-objective"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_OPERATION = re.compile(r"[0-9a-f]{32}")
_TOPIC = re.compile(r"victim/secret/[0-9a-f]{24}")


def derive_principal(seed: str) -> tuple[str, str]:
    if not _HEX64.fullmatch(seed):
        raise ValueError("principal seed must be 64 lowercase hex characters")
    raw = bytes.fromhex(seed)
    username = "u" + hashlib.sha256(b"nats-mqtt-user\0" + raw).hexdigest()[:22]
    password = "N1!" + hashlib.sha256(b"nats-mqtt-password\0" + raw).hexdigest()
    return username, password


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
    if store == STORE_RETAINED and isinstance(target, str) and _TOPIC.fullmatch(target):
        return target
    if store == STORE_COMMAND and isinstance(target, str) and _OPERATION.fullmatch(target):
        return target
    return None


def catflag_command(operation: str) -> str:
    if not _OPERATION.fullmatch(operation):
        raise ValueError("invalid operation id")
    return f"su-exec {SERVICE_USER}:{SERVICE_USER} {CATFLAG_PATH} {operation}"
