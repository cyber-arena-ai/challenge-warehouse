"""Framework-free principal, objective, and handle encodings."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex

STORE_PROTECTED_FEATURE = "protected_feature"
STORE_COMMAND = "command"
SERVICE_UID = 1000
OBJECTIVE_HELPER = "/usr/local/bin/geoserver-objective"

_FEATURE_TARGET = re.compile(r"sf:roads/(roads\.[0-9]+)")
_OPERATION = re.compile(r"[0-9a-f]{32}")


def derive_principal(seed: str) -> tuple[str, str]:
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 48:
        raise ValueError("seed does not carry enough material")
    return "arena_" + material[:16], "Gs!" + material[16:48]


def valid_operation(value: object) -> bool:
    return isinstance(value, str) and _OPERATION.fullmatch(value) is not None


def feature_id(target: object) -> str | None:
    if not isinstance(target, str):
        return None
    match = _FEATURE_TARGET.fullmatch(target)
    return match.group(1) if match else None


def feature_target(feature: str) -> str:
    if re.fullmatch(r"roads\.[0-9]+", feature) is None:
        raise ValueError("invalid feature id")
    return "sf:roads/" + feature


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
    if payload.get("store") == STORE_PROTECTED_FEATURE and feature_id(target):
        return target
    if payload.get("store") == STORE_COMMAND and valid_operation(target):
        return target
    return None


def objective_command(operation: str) -> str:
    if not valid_operation(operation):
        raise ValueError("invalid operation id")
    return (
        f"setpriv --reuid={SERVICE_UID} --regid={SERVICE_UID} --clear-groups "
        f"{shlex.quote(OBJECTIVE_HELPER)} {shlex.quote(operation)}"
    )
