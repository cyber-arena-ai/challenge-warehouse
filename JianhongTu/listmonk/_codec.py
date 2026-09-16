"""Deterministic identifiers and the credential-bound proof envelope."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from typing import Any

from challenges.interface import VulboxTarget


_GIVEN_NAMES = (
    "avery",
    "cameron",
    "devon",
    "elliot",
    "harper",
    "jordan",
    "morgan",
    "parker",
    "quinn",
    "reese",
    "riley",
    "taylor",
)
_FAMILY_NAMES = (
    "bennett",
    "carter",
    "ellis",
    "foster",
    "hayes",
    "lane",
    "morgan",
    "reed",
    "sawyer",
    "shaw",
    "turner",
    "wells",
)
_MAIL_DOMAINS = ("campaigns.example", "mailing.example", "newsletters.example")
_SERVICE_AREAS = (
    "campaign",
    "delivery",
    "digest",
    "mailing",
    "newsletter",
    "notification",
)
_SERVICE_TASKS = ("dispatch", "preview", "render", "sync", "template", "workflow")
_TEMPLATE_KINDS = ("digest", "notice", "receipt", "reminder", "summary", "update")
_TARGET_USERNAME = re.compile(r"[a-z][a-z0-9.-]{5,63}")
_PROCESS_FACILITY_MATERIAL = secrets.token_bytes(32)


def _seed_bytes(seed: str) -> bytes:
    if (
        not isinstance(seed, str)
        or len(seed) != 64
        or seed != seed.lower()
    ):
        raise ValueError("round context seed is unavailable")
    try:
        return bytes.fromhex(seed)
    except ValueError as error:
        raise ValueError("round context seed is unavailable") from error


def derive(seed: str, label: str) -> bytes:
    return hmac.new(
        _seed_bytes(seed),
        ("cyberarena:listmonk:v1\0" + label).encode(),
        hashlib.sha256,
    ).digest()


def private_seed(target: VulboxTarget, label: str) -> str:
    """Derive facility-private material for one victim coordinate."""
    coordinate = target.meta.get("team_id")
    if not isinstance(coordinate, str) or not coordinate:
        coordinate = f"{target.host}:{target.ports['service']}"
    facility_token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    key = facility_token.encode() if facility_token else _PROCESS_FACILITY_MATERIAL
    return hmac.new(
        key,
        b"cyberarena:listmonk:private:v1\0"
        + label.encode()
        + b"\0"
        + coordinate.encode(),
        hashlib.sha256,
    ).hexdigest()


def private_run_seed(target: VulboxTarget, label: str) -> str:
    """Derive process-fresh material without changing stable facility identities."""
    key = bytes.fromhex(private_seed(target, label))
    return hmac.new(
        key,
        b"cyberarena:listmonk:checker-process:v1\0"
        + _PROCESS_FACILITY_MATERIAL,
        hashlib.sha256,
    ).hexdigest()


def _pick(seed: str, label: str, values: tuple[str, ...]) -> str:
    return values[int.from_bytes(derive(seed, label)[:4], "big") % len(values)]


def principal_profile(seed: str) -> dict[str, str]:
    """Return one ordinary person-shaped restricted analyst identity."""
    given = _pick(seed, "principal:given-name", _GIVEN_NAMES)
    family = _pick(seed, "principal:family-name", _FAMILY_NAMES)
    suffix = derive(seed, "principal:suffix")[:4].hex()
    username = f"{given}.{family}.{suffix}"
    password = base64.urlsafe_b64encode(
        derive(seed, "principal:credential")
    ).decode()
    return {
        "username": username,
        "password": password,
        "name": f"{given.title()} {family.title()}",
        "email": f"{username}@{_pick(seed, 'principal:domain', _MAIL_DOMAINS)}",
    }


def checker_profile(target: VulboxTarget) -> dict[str, str]:
    """Return the hidden match-long checker member of the analyst cohort."""
    return principal_profile(private_seed(target, "checker-principal"))


def round_context(seed: str) -> dict[str, Any]:
    """Derive one rotating, ordinary-shaped API integration and template."""
    area = _pick(seed, "api-token:service-area", _SERVICE_AREAS)
    task = _pick(seed, "api-token:service-task", _SERVICE_TASKS)
    kind = _pick(seed, "api-token:template-kind", _TEMPLATE_KINDS)
    identity = derive(seed, "api-token:target-user")[:5].hex()
    role_suffix = derive(seed, "api-token:role-suffix")[:4].hex()
    template_suffix = derive(seed, "api-token:template-name")[:4].hex()
    return {
        "username": f"{area}.{task}.{identity}",
        "user_name": f"{area.title()} {task.title()} integration",
        "role_name": f"{area.title()} {task.title()} {role_suffix}",
        "template_name": f"{area.title()} {kind.title()} {template_suffix}",
        "template_subject": f"{area.title()} {kind} update",
        "nonce": derive(seed, "api-token:proof-envelope-nonce")[:16],
    }


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode())


def _keystream(token: str, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(
                token.encode(),
                b"cyberarena:listmonk:proof:enc\0"
                + nonce
                + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def seal(token: str, proof: str, nonce: bytes) -> str:
    clear = proof.encode()
    stream = _keystream(token, nonce, len(clear))
    ciphertext = bytes(a ^ b for a, b in zip(clear, stream, strict=True))
    tag = hmac.new(
        token.encode(),
        b"cyberarena:listmonk:proof:tag\0" + nonce + ciphertext,
        hashlib.sha256,
    ).digest()[:16]
    return json.dumps(
        {"v": 1, "nonce": _encode(nonce), "ciphertext": _encode(ciphertext), "tag": _encode(tag)},
        separators=(",", ":"),
    )


def open_envelope(token: str, document: str) -> str | None:
    try:
        envelope = json.loads(document)
        if envelope.get("v") != 1:
            return None
        nonce = _decode(str(envelope["nonce"]))
        ciphertext = _decode(str(envelope["ciphertext"]))
        tag = _decode(str(envelope["tag"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    expected = hmac.new(
        token.encode(),
        b"cyberarena:listmonk:proof:tag\0" + nonce + ciphertext,
        hashlib.sha256,
    ).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        return None
    stream = _keystream(token, nonce, len(ciphertext))
    try:
        return bytes(a ^ b for a, b in zip(ciphertext, stream, strict=True)).decode()
    except UnicodeDecodeError:
        return None


def pack_handle(payload: dict[str, Any]) -> str:
    return _encode(json.dumps(payload, separators=(",", ":")).encode())


def unpack_handle(handle: str) -> dict[str, Any] | None:
    try:
        value = json.loads(_decode(handle))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def public_locator(handle: str) -> str | None:
    value = unpack_handle(handle)
    if value is None:
        return None
    username = value.get("username")
    template_id = value.get("template_id")
    if not isinstance(username, str) or _TARGET_USERNAME.fullmatch(username) is None:
        return None
    if (
        not isinstance(template_id, int)
        or isinstance(template_id, bool)
        or template_id < 1
    ):
        return None
    return json.dumps(
        {"username": username, "template_id": template_id}, separators=(",", ":")
    )
