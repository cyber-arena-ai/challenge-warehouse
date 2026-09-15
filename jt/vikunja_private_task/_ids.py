"""Framework-free principal, target, handle, and helper encodings."""

from __future__ import annotations

import base64
import binascii
import json
import shlex

STORE_PRIVATE_TASK = "private_task"
STORE_COMMAND = "command"
SERVICE_USER = "vikunja"
CATFLAG_PATH = "/usr/local/bin/catflag"


def derive_principal(seed: str) -> tuple[str, str, str]:
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 48:
        raise ValueError("seed does not carry enough material")
    username = "reader" + material[:10]
    password = "V1!" + material[10:42]
    return username, f"{username}@arena.invalid", password


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


def encode_read_target(*, shared_project_id: int, shared_task_id: int,
                       private_task_id: int, private_uid: str) -> str:
    if min(shared_project_id, shared_task_id, private_task_id) <= 0 or not private_uid:
        raise ValueError("read target fields must be nonempty")
    return pack_handle({
        "v": 1,
        "shared_project_id": shared_project_id,
        "shared_task_id": shared_task_id,
        "private_task_id": private_task_id,
        "private_uid": private_uid,
    })


def decode_read_target(value: str) -> dict | None:
    target = unpack_handle(value)
    if target is None or target.get("v") != 1:
        return None
    keys = ("shared_project_id", "shared_task_id", "private_task_id")
    if any(not isinstance(target.get(k), int) or target[k] <= 0 for k in keys):
        return None
    if not isinstance(target.get("private_uid"), str) or not target["private_uid"]:
        return None
    return target


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    if payload.get("store") == STORE_PRIVATE_TASK:
        target = payload.get("target")
        return target if isinstance(target, str) and decode_read_target(target) else None
    if payload.get("store") == STORE_COMMAND:
        operation = payload.get("op")
        return operation if isinstance(operation, str) and operation else None
    return None


def catflag_command(operation_id: str) -> str:
    if not operation_id:
        raise ValueError("operation id must be nonempty")
    return (
        f"su-exec {shlex.quote(SERVICE_USER)} "
        f"{shlex.quote(CATFLAG_PATH)} {shlex.quote(operation_id)}"
    )
