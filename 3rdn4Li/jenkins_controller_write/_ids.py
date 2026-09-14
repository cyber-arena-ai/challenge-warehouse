"""Deterministic identities and opaque handles for the Jenkins challenge."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re


STORE = "protected_job_config"
ANCHOR_REGION = "objective-anchor"
OBJECTIVE_REGION = "protected-job-configs"
POOL_SIZE = 32
CHECKER_POOL_SIZE = 8
POOL_NAMES = tuple(
    "build-" + hashlib.sha256(f"jenkins-pool-v1:{slot}".encode()).hexdigest()[:28]
    for slot in range(POOL_SIZE)
)

_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")
_JOB_RE = re.compile(r"build-[0-9a-f]{28}")
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_ASSIGNMENT_PREFIX = "Managed assignment inventory v1 "


def _round_value(seed: str, purpose: str) -> bytes:
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    return hmac.new(
        bytes.fromhex(seed),
        f"jenkins-controller-write\0{purpose}\0v1".encode(),
        hashlib.sha256,
    ).digest()


def _pool_roles(team_id: str) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("target team identity is unavailable")
    pool_key = os.environ.get(
        _FACILITY_TOKEN_ENV, "jenkins-controller-write-verifier-pool-v1"
    ).encode()
    ranked = sorted(
        range(POOL_SIZE),
        key=lambda slot: hmac.new(
            pool_key,
            f"{team_id}\0pool-role\0{slot}\0v1".encode(),
            hashlib.sha256,
        ).digest(),
    )
    return tuple(ranked[CHECKER_POOL_SIZE:]), tuple(ranked[:CHECKER_POOL_SIZE])


def checker_pool_names(team_id: str) -> tuple[str, ...]:
    _, slots = _pool_roles(team_id)
    return tuple(POOL_NAMES[slot] for slot in slots)


def pool_cover(slot: int) -> str:
    if (
        not isinstance(slot, int)
        or isinstance(slot, bool)
        or not 0 <= slot < POOL_SIZE
    ):
        raise ValueError("Jenkins pool slot is invalid")
    material = hashlib.sha256(f"jenkins-pool-cover-v1:{slot}".encode()).hexdigest()
    return "Protected build configuration " + material[:20]


def round_context(
    seed: str, team_id: str, excluded: set[str] | None = None
) -> dict[str, object]:
    """Derive one target and its non-proof cover from the framework seed."""
    excluded = excluded or set()
    context = _round_value(seed, "generation-context").hex()
    objective_slots, _ = _pool_roles(team_id)
    ranked = sorted(
        objective_slots,
        key=lambda slot: _round_value(seed, f"target-rank\0{slot}"),
    )
    selected = next(
        (slot for slot in ranked if POOL_NAMES[slot] not in excluded), None
    )
    if selected is None:
        raise RuntimeError("no Jenkins objective target is available")
    return {
        "context": context,
        "slot": selected,
        "target": POOL_NAMES[selected],
        "region": OBJECTIVE_REGION,
        "audit": context + ".xml",
        "cover": pool_cover(selected),
        "anchor": _round_value(seed, "integrity-anchor").hex(),
    }


def principal_credentials(seed: str) -> tuple[str, str]:
    if not isinstance(seed, str) or len(seed) < 32:
        raise ValueError("principal seed is unavailable")
    username = hmac.new(
        seed.encode(), b"jenkins-controller-write\0principal-user\0v1", hashlib.sha256
    ).hexdigest()
    username = "ci-user-" + username[:28]
    return username, principal_password(username)


def principal_password(username: str) -> str:
    if re.fullmatch(r"ci-user-[0-9a-f]{28}", username) is None:
        raise ValueError("principal identity is malformed")
    password = hmac.new(
        _facility_key(),
        f"jenkins-controller-write\0participant-password\0{username}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()
    return "Jk!" + password[:32]


def principal_job(seed: str) -> str:
    if not isinstance(seed, str) or len(seed) < 32:
        raise ValueError("principal seed is unavailable")
    material = hmac.new(
        seed.encode(), b"jenkins-controller-write\0principal-job\0v1", hashlib.sha256
    ).hexdigest()
    return "build-" + material[:28]


def _normalize_assignments(
    team_id: str, assignments: list[tuple[str, str, int]]
) -> tuple[tuple[str, str, int], ...]:
    if not isinstance(team_id, str) or not team_id:
        raise ValueError("target team identity is unavailable")
    normalized = tuple(sorted(assignments))
    if not normalized or any(
        re.fullmatch(r"ci-user-[0-9a-f]{28}", username) is None
        or _JOB_RE.fullmatch(job) is None
        or job in POOL_NAMES
        or not isinstance(seed_build, int)
        or isinstance(seed_build, bool)
        or seed_build < 1
        for username, job, seed_build in normalized
    ):
        raise ValueError("participant assignment inventory is malformed")
    if len({username for username, _, _ in normalized}) != len(normalized) or len(
        {job for _, job, _ in normalized}
    ) != len(normalized):
        raise ValueError("participant assignment inventory contains duplicates")
    return normalized


def participant_inventory_job(team_id: str) -> str:
    return checker_pool_names(team_id)[0]


def participant_inventory_description(
    team_id: str, assignments: list[tuple[str, str, int]]
) -> str:
    normalized = _normalize_assignments(team_id, assignments)
    payload = json.dumps(
        {"assignments": normalized, "team_id": team_id, "v": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = hmac.new(
        _facility_key(),
        b"jenkins-controller-write\0assignment-inventory\0v1\0" + payload,
        hashlib.sha256,
    ).hexdigest()
    slot = POOL_NAMES.index(participant_inventory_job(team_id))
    return f"{pool_cover(slot)}\n{_ASSIGNMENT_PREFIX}{encoded}.{signature}"


def participant_assignments(
    team_id: str, description: str
) -> tuple[tuple[str, str, int], ...]:
    if not isinstance(description, str):
        raise RuntimeError("participant assignment inventory is unavailable")
    lines = description.splitlines()
    if len(lines) != 2 or not lines[1].startswith(_ASSIGNMENT_PREFIX):
        raise RuntimeError("participant assignment inventory is unavailable")
    encoded, separator, signature = lines[1][len(_ASSIGNMENT_PREFIX) :].partition(
        "."
    )
    try:
        payload = base64.urlsafe_b64decode(
            (encoded + "=" * (-len(encoded) % 4)).encode()
        )
    except (ValueError, binascii.Error) as error:
        raise RuntimeError("participant assignment inventory is malformed") from error
    expected = hmac.new(
        _facility_key(),
        b"jenkins-controller-write\0assignment-inventory\0v1\0" + payload,
        hashlib.sha256,
    ).hexdigest()
    if separator != "." or not hmac.compare_digest(signature, expected):
        raise RuntimeError("participant assignment inventory is untrusted")
    try:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError
        rows = document["assignments"]
        assignments = [(row[0], row[1], row[2]) for row in rows]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("participant assignment inventory is malformed") from error
    if set(document) != {"assignments", "team_id", "v"} or document.get(
        "team_id"
    ) != team_id or document.get("v") != 1:
        raise RuntimeError("participant assignment inventory is malformed")
    try:
        return _normalize_assignments(team_id, assignments)
    except ValueError as error:
        raise RuntimeError("participant assignment inventory is malformed") from error


def _facility_key() -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("checker principal material is unavailable")
    return token.encode()


def checker_principals(team_id: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("checker principal material is unavailable")
    rows = []
    for slot in range(4):
        purpose = f"{team_id}\0checker-guarded\0{slot}\0v1".encode()
        material = hmac.new(_facility_key(), purpose, hashlib.sha256).digest()
        secret = hmac.new(
            _facility_key(), purpose + b"\0password", hashlib.sha256
        ).hexdigest()
        rows.append(("ci-user-" + material.hex()[:28], "Jk!" + secret[:32]))
    return tuple(rows)


def checker_user_credentials(team_id: str, nonce: bytes) -> tuple[str, str]:
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("checker principal material is unavailable")
    if not isinstance(nonce, bytes) or len(nonce) != 14:
        raise ValueError("checker user nonce must be fourteen bytes")
    prefix = nonce.hex()
    username = "ci-user-" + prefix
    password = hmac.new(
        _facility_key(),
        f"{team_id}\0checker-user-password\0{prefix}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()
    return username, "Jk!" + password[:32]


def checker_job_name(nonce: bytes) -> str:
    if not isinstance(nonce, bytes) or len(nonce) != 14:
        raise ValueError("checker job nonce must be fourteen bytes")
    return "build-" + nonce.hex()


def pack_handle(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: object) -> dict[str, object] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        value = json.loads(
            base64.urlsafe_b64decode((handle + "=" * (-len(handle) % 4)).encode())
        )
    except (ValueError, binascii.Error):
        return None
    if not isinstance(value, dict) or set(value) != {
        "audit",
        "anchor",
        "context",
        "region",
        "slot",
        "store",
        "target",
        "token",
    }:
        return None
    slot = value.get("slot")
    target = value.get("target")
    if (
        value.get("store") != STORE
        or not isinstance(slot, int)
        or isinstance(slot, bool)
        or not 0 <= slot < POOL_SIZE
        or target != POOL_NAMES[slot]
        or value.get("region") != OBJECTIVE_REGION
        or not isinstance(value.get("token"), str)
        or not value["token"]
        or not isinstance(value.get("context"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["context"]) is None
        or not isinstance(value.get("anchor"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["anchor"]) is None
        or value.get("audit") != value.get("context") + ".xml"
    ):
        return None
    return value


def public_locator(handle: object) -> str | None:
    payload = unpack_handle(handle)
    if payload is None:
        return None
    return f"job/{payload['target']}/config.xml"


def parse_public_locator(locator: object) -> str | None:
    if not isinstance(locator, str):
        return None
    match = re.fullmatch(r"job/(build-[0-9a-f]{28})/config\.xml", locator)
    return match.group(1) if match else None
