"""Framework-free principal, target, handle, and helper encodings."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex

STORE_PRIVATE_NOTE = "private_note"
STORE_COMMAND = "command"
SERVICE_USER = "www-data"
OBJECTIVE_HELPER = "/usr/local/bin/suitecrm-objective"

_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_OPERATION = re.compile(r"[0-9a-f]{32}")


def derive_principal(seed: str) -> tuple[str, str, str]:
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 56:
        raise ValueError("seed does not carry enough material")
    return (
        "arena_" + material[:16],
        "S7!" + material[16:48],
        "Arena partition " + material[48:56],
    )


def valid_uuid(value: object) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def valid_operation(value: object) -> bool:
    return isinstance(value, str) and _OPERATION.fullmatch(value) is not None


def pack_handle(payload: dict[str, str]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict[str, str] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        value = json.loads(base64.urlsafe_b64decode(
            (handle + "=" * (-len(handle) % 4)).encode()
        ))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        return None
    return value


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    target = payload.get("target")
    if payload.get("store") == STORE_PRIVATE_NOTE and valid_uuid(target):
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
