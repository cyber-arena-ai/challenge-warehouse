"""Framework-free principal, objective, and handle encodings."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import shlex

STORE_PROTECTED_FEATURE = "protected_feature"
STORE_COMMAND = "command"
SERVICE_UID = 1000
OBJECTIVE_HELPER = "/usr/local/bin/geoserver-objective"
CHECKER_PRINCIPALS_PER_ROLE = 4

_FEATURE_TARGET = re.compile(
    r"sf:roads/context/([0-9a-f]{64})/cat/([1-9][0-9]{0,3})"
)
_OPERATION = re.compile(r"[0-9a-f]{32}")
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_ISSUED_USERNAME = re.compile(r"arena_[0-9a-f]{16}")
_ISSUED_PASSWORD = re.compile(r"Gs![0-9a-f]{32}")


def derive_principal(seed: str) -> tuple[str, str]:
    material = "".join(c for c in seed.lower() if c in "0123456789abcdef")
    if len(material) < 48:
        raise ValueError("seed does not carry enough material")
    return "arena_" + material[:16], "Gs!" + material[16:48]


def checker_principals(
    team_id: str, authority: str,
) -> tuple[tuple[str, str], ...]:
    """Match-long SLA accounts derived only by trusted facility processes."""
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token or not team_id:
        raise RuntimeError("checker principal material is unavailable")
    if authority not in ("ordinary", "guarded"):
        raise ValueError("invalid checker authority")
    rows = []
    for slot in range(CHECKER_PRINCIPALS_PER_ROLE):
        material = hmac.new(
            token.encode(),
            f"geoserver-xpath:{team_id}:{authority}:{slot}".encode(),
            hashlib.sha256,
        ).hexdigest()
        rows.append(("arena_" + material[:16], "Gs!" + material[16:48]))
    return tuple(rows)


def road_lifecycle_principals(
    team_id: str,
) -> tuple[tuple[str, str], tuple[str, str]]:
    """Return the stable ordinary/guarded pair used by both road flows."""
    return (
        checker_principals(team_id, "ordinary")[0],
        checker_principals(team_id, "guarded")[0],
    )


def _facility_key() -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("issued principal material is unavailable")
    return token.encode()


def _issued_accounts(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise RuntimeError("issued principal cohort is empty")
    accounts: list[tuple[str, str]] = []
    for row in value:
        if (
            not isinstance(row, (list, tuple))
            or len(row) != 2
            or not isinstance(row[0], str)
            or _ISSUED_USERNAME.fullmatch(row[0]) is None
            or not isinstance(row[1], str)
            or _ISSUED_PASSWORD.fullmatch(row[1]) is None
        ):
            raise RuntimeError("issued principal cohort is malformed")
        accounts.append((row[0], row[1]))
    if (
        len({username for username, _ in accounts}) != len(accounts)
        or len({password for _, password in accounts}) != len(accounts)
    ):
        raise RuntimeError("issued principal cohort has collisions")
    return tuple(sorted(accounts))


def _cohort_signature(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"geoserver-xpath/v1/issued-cohort\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def seal_issued_cohort(accounts: object) -> str:
    """Authenticate the complete arena-issued ordinary principal cohort."""
    rows = _issued_accounts(accounts)
    payload = json.dumps(
        {"accounts": rows, "v": 1}, sort_keys=True, separators=(",", ":")
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_signature(payload)}"


def open_issued_cohort(sealed: object) -> tuple[tuple[str, str], ...]:
    """Verify and decode a sealed arena-issued ordinary principal cohort."""
    if not isinstance(sealed, str) or not sealed or len(sealed) > 32_768:
        raise RuntimeError("issued principal cohort is malformed")
    encoded, separator, signature = sealed.partition(".")
    if not separator or not encoded or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
        raise RuntimeError("issued principal cohort is malformed")
    try:
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise RuntimeError("issued principal cohort is malformed") from error
    if not hmac.compare_digest(signature, _cohort_signature(payload)):
        raise RuntimeError("issued principal cohort is untrusted")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("issued principal cohort is malformed") from error
    if not isinstance(value, dict) or set(value) != {"accounts", "v"} or value["v"] != 1:
        raise RuntimeError("issued principal cohort is malformed")
    return _issued_accounts(value["accounts"])


def valid_operation(value: object) -> bool:
    return isinstance(value, str) and _OPERATION.fullmatch(value) is not None


def feature_category(target: object) -> int | None:
    if not isinstance(target, str):
        return None
    match = _FEATURE_TARGET.fullmatch(target)
    return int(match.group(2)) if match else None


def feature_target(category: int, context: str) -> str:
    if isinstance(category, bool) or not isinstance(category, int):
        raise ValueError("invalid feature category")
    if not 1 <= category <= 9999:
        raise ValueError("invalid feature category")
    if (
        not isinstance(context, str)
        or re.fullmatch(r"[0-9a-f]{64}", context) is None
    ):
        raise ValueError("invalid feature context")
    return f"sf:roads/context/{context}/cat/{category}"


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
    if (
        payload.get("store") == STORE_PROTECTED_FEATURE
        and feature_category(target) is not None
    ):
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
