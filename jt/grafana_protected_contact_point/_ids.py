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

STORE_PROTECTED_RECEIVER = "protected_receiver"
STORE_COMMAND = "command"
SERVICE_UID = 472
SERVICE_GID = 0
STATE_REGION = "grafana-db"
STATE_PATH = "/var/lib/grafana/grafana.db"
OBJECTIVE_HELPER = "/usr/local/bin/grafana-objective"
CHECKER_PRINCIPALS_PER_ROLE = 4
CHECKER_CONTACTS = 4

_SEED = re.compile(r"[0-9a-fA-F]{64}")
_UID = re.compile(r"cp-[0-9a-f]{24}")
_OPERATION = re.compile(r"[0-9a-f]{32}")
_CONTACT_NAME = re.compile(
    r"(Billing|Delivery|Incident|Operations|Platform|Reporting|Support|Usage) "
    r"(alerts|notifications|on-call|webhook) [1-9][0-9]{3}"
)
_CONTACT_URL = re.compile(
    r"http://192\.168\.([0-9]{1,3})\.([0-9]{1,3}):8[0-9]{3}"
    r"/hooks/[0-9a-f]{24}"
)
_CONTACT_TEAMS = (
    "Billing", "Delivery", "Incident", "Operations",
    "Platform", "Reporting", "Support", "Usage",
)
_CONTACT_KINDS = ("alerts", "notifications", "on-call", "webhook")
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def derive_principal(seed: str) -> tuple[str, str]:
    if not isinstance(seed, str) or _SEED.fullmatch(seed) is None:
        raise ValueError("principal seed must be 64 hexadecimal characters")
    material = seed.lower()
    return "arena_" + material[:20], "Gr!" + material[20:60]


def _facility_material(team_id: str, purpose: str, slot: int) -> str:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token or not team_id:
        raise RuntimeError("checker material is unavailable")
    return hmac.new(
        token.encode(),
        f"grafana-protected-contact-point:{team_id}:{purpose}:{slot}".encode(),
        hashlib.sha256,
    ).hexdigest()


def checker_principals(
    team_id: str, authority: str,
) -> tuple[tuple[str, str], ...]:
    """Match-long SLA identities available only to trusted facility roles."""
    if authority not in ("ordinary", "guarded"):
        raise ValueError("invalid checker authority")
    rows = []
    for slot in range(CHECKER_PRINCIPALS_PER_ROLE):
        material = _facility_material(team_id, "principal-" + authority, slot)
        rows.append(("arena_" + material[:20], "Gr!" + material[20:60]))
    return tuple(rows)


def contact_details(material: str) -> tuple[str, str, str]:
    """Map private random material to an ordinary contact-point shape."""
    if not isinstance(material, str) or re.fullmatch(r"[0-9a-f]{64}", material) is None:
        raise ValueError("contact material must be 64 lowercase hex characters")
    team = _CONTACT_TEAMS[int(material[24:26], 16) % len(_CONTACT_TEAMS)]
    kind = _CONTACT_KINDS[int(material[26:28], 16) % len(_CONTACT_KINDS)]
    number = 1000 + int(material[28:32], 16) % 9000
    third = 1 + int(material[32:34], 16) % 254
    fourth = 1 + int(material[34:36], 16) % 254
    port = 8000 + int(material[36:40], 16) % 1000
    return (
        "cp-" + material[:24],
        f"{team} {kind} {number}",
        f"http://192.168.{third}.{fourth}:{port}/hooks/{material[40:64]}",
    )


def checker_contacts(team_id: str) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        contact_details(_facility_material(team_id, "contact", slot))
        for slot in range(CHECKER_CONTACTS)
    )


def valid_contact_uid(value: object) -> bool:
    return isinstance(value, str) and _UID.fullmatch(value) is not None


def valid_contact_name(value: object) -> bool:
    return isinstance(value, str) and _CONTACT_NAME.fullmatch(value) is not None


def valid_contact_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = _CONTACT_URL.fullmatch(value)
    return bool(match and all(1 <= int(octet) <= 254 for octet in match.groups()))


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
