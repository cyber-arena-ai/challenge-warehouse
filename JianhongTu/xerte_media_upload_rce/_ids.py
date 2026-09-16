"""Framework-free principal, target, handle, and helper encodings."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import shlex

STORE_COMMAND = "command"
SERVICE_USER = "www-data"
CATFLAG_PATH = "/usr/local/bin/catflag"
TEMPLATE_NAME = "Nottingham"
USER_FILES = "USER-FILES"
CHECKER_PRINCIPAL_COUNT = 4
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def derive_principal(seed: str) -> tuple[str, str, str]:
    """Username, password, and email for one attacker, from its own seed only.

    The seed is independent cryptographic material per (victim, service,
    attacker); nothing here mixes in a team id, a host, or another assignment.
    """
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 48:
        raise ValueError("seed does not carry enough material")
    username = "author" + material[:10]
    password = "Xa1!" + material[10:42]
    return username, password, f"{username}@arena.invalid"


def checker_principals(team_id: str) -> tuple[tuple[str, str], ...]:
    """Target-specific ordinary accounts shared only by trusted facilities."""
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("facility principal material is unavailable")
    rows = []
    for slot in range(CHECKER_PRINCIPAL_COUNT):
        material = hmac.new(
            token.encode(),
            f"xerte-media-upload-rce:{team_id}:{slot}".encode(),
            hashlib.sha256,
        ).hexdigest()
        rows.append(("author" + material[:10], "Xa1!" + material[10:42]))
    return tuple(rows)


def objective_operation(round_context_seed: str) -> str:
    """Derive the current operation from private round context only."""
    if not isinstance(round_context_seed, str) or not re.fullmatch(
        r"[0-9a-f]{64}", round_context_seed
    ):
        raise ValueError("round context seed is unavailable")
    return hmac.new(
        bytes.fromhex(round_context_seed),
        b"xerte-online-toolkits:command:execute-operation:v1",
        hashlib.sha256,
    ).hexdigest()[:32]


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


def encode_execute_target(*, operation: str) -> str:
    """The public current-round helper operation, never proof material."""
    if not operation:
        raise ValueError("execute target operation must be nonempty")
    return pack_handle({"v": 1, "op": operation})


def decode_execute_target(value: str) -> dict | None:
    target = unpack_handle(value)
    if target is None or target.get("v") != 1:
        return None
    if not isinstance(target.get("op"), str) or not target["op"]:
        return None
    return target


def public_flag_id(handle: str) -> str | None:
    payload = unpack_handle(handle)
    if payload is None or payload.get("store") != STORE_COMMAND:
        return None
    target = payload.get("target")
    return target if isinstance(target, str) and decode_execute_target(target) else None


def project_dir(project_id: int, owner_username: str) -> str:
    """`USER-FILES/<id>-<owner>-<template>` — Xerte's project media layout."""
    return f"{USER_FILES}/{project_id}-{owner_username}-{TEMPLATE_NAME}"


def project_path(project_id: int, owner_username: str) -> str:
    return "/" + project_dir(project_id, owner_username) + "/"


def catflag_command(operation: str) -> str:
    """Run the helper in the service execution context, exactly as an attacker
    who reached execution would — never a direct read of its backing file."""
    if not operation:
        raise ValueError("operation id must be nonempty")
    return (
        f"runuser -u {shlex.quote(SERVICE_USER)} -- "
        f"{shlex.quote(CATFLAG_PATH)} {shlex.quote(operation)}"
    )
