"""Framework-free principal, objective, and handle encodings."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex

STORE_PROTECTED_RECEIVER = "protected_receiver"
STORE_COMMAND = "command"
SERVICE_UID = 472
SERVICE_GID = 0
STATE_REGION = "grafana-db"
STATE_PATH = "/var/lib/grafana/grafana.db"
OBJECTIVE_HELPER = "/usr/local/bin/grafana-objective"

_SEED = re.compile(r"[0-9a-fA-F]{64}")
_UID = re.compile(r"arena-cp-[0-9a-f]{24}")
_OPERATION = re.compile(r"[0-9a-f]{32}")


def derive_principal(seed: str) -> tuple[str, str]:
    if not isinstance(seed, str) or _SEED.fullmatch(seed) is None:
        raise ValueError("principal seed must be 64 hexadecimal characters")
    material = seed.lower()
    return "arena_" + material[:20], "Gr!" + material[20:60]


def valid_contact_uid(value: object) -> bool:
    return isinstance(value, str) and _UID.fullmatch(value) is not None


def valid_operation(value: object) -> bool:
    return isinstance(value, str) and _OPERATION.fullmatch(value) is not None


def pack_handle(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: str) -> dict[str, object] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        value = json.loads(base64.urlsafe_b64decode(
            (handle + "=" * (-len(handle) % 4)).encode()
        ))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(value, dict):
        return None
    return value


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    target = payload.get("target")
    if payload.get("store") == STORE_PROTECTED_RECEIVER and valid_contact_uid(target):
        return str(target)
    if payload.get("store") == STORE_COMMAND and valid_operation(target):
        return str(target)
    return None


def objective_command(operation: str) -> str:
    if not valid_operation(operation):
        raise ValueError("invalid operation id")
    return (
        f"setpriv --reuid={SERVICE_UID} --regid={SERVICE_GID} --clear-groups "
        f"{shlex.quote(OBJECTIVE_HELPER)} {shlex.quote(operation)}"
    )
