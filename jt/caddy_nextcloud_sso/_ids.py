"""Framework-free principal, target, and handle helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex

STORE_GUARDED_FILE = "guarded_file"
STORE_COMMAND = "command"
SERVICE_USER = "service"
OBJECTIVE_HELPER = "/usr/local/bin/caddy-objective"

_READ_TARGET = re.compile(r"Guarded/[0-9a-f]{24}\.txt")
_OPERATION = re.compile(r"[0-9a-f]{32}")


def valid_read_target(value: str) -> bool:
    return isinstance(value, str) and _READ_TARGET.fullmatch(value) is not None


def valid_operation(value: str) -> bool:
    return isinstance(value, str) and _OPERATION.fullmatch(value) is not None


def derive_principal(seed: str) -> tuple[str, str]:
    material = "".join(char for char in seed.lower()
                       if char in "0123456789abcdef")
    if len(material) < 48:
        raise ValueError("seed does not carry enough material")
    return "user" + material[:16], "C1!" + material[16:48]


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
    if payload.get("store") == STORE_GUARDED_FILE and valid_read_target(target):
        return target
    if payload.get("store") == STORE_COMMAND and valid_operation(target):
        return target
    return None


def objective_command(operation: str) -> str:
    if not valid_operation(operation):
        raise ValueError("invalid operation id")
    return (
        f"su-exec {shlex.quote(SERVICE_USER)}:{shlex.quote(SERVICE_USER)} "
        f"{shlex.quote(OBJECTIVE_HELPER)} {shlex.quote(operation)}"
    )
