"""Deterministic private identities for the Airflow challenge."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
from typing import Any

from .image.identity import ordinary_password, ordinary_username, ordinary_variable_key


STORE = "nested_variable_password"
_SEED_RE = re.compile(r"[0-9a-f]{64}")
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_CONTEXT_RE = re.compile(r"[A-Za-z0-9_-]+")
# The standalone verifier runs both probes in one trusted host process and does
# not inject the live game's cross-process facility token.
_PROCESS_FACILITY_MATERIAL = secrets.token_bytes(32)
_FLAG_ALPHABET = string.ascii_uppercase + string.digits


def _seed_bytes(seed: str) -> bytes:
    if not isinstance(seed, str) or _SEED_RE.fullmatch(seed) is None:
        raise ValueError("seed must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(seed)


def _derive(seed: str, domain: str) -> bytes:
    return hmac.new(
        _seed_bytes(seed),
        f"cyberarena:airflow:{domain}:v1".encode(),
        hashlib.sha256,
    ).digest()


def _text(raw: bytes, length: int = 32) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")[:length]


def principal_credentials(seed: str) -> tuple[str, str]:
    """Return one ordinary-shaped, match-long native Airflow login."""
    username = ordinary_username(_derive(seed, "principal:username"))
    password = ordinary_password(_derive(seed, "principal:password"))
    return username, password


def _facility_material(team_id: str, domain: str) -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not isinstance(team_id, str) or not team_id:
        raise ValueError("team id is unavailable")
    key = token.encode() if token else _PROCESS_FACILITY_MATERIAL
    return hmac.new(
        key,
        f"cyberarena:airflow:{team_id}:{domain}:v1".encode(),
        hashlib.sha256,
    ).digest()


def new_ordinary_credentials() -> tuple[str, str]:
    """Return a fresh login with the same public shape as arena principals."""
    return (
        ordinary_username(secrets.token_bytes(32)),
        ordinary_password(secrets.token_bytes(32)),
    )


def objective_shaped_noise_token() -> str:
    """Return non-scoring noise in the same public shape as proof values."""
    return "FLAG{" + "".join(secrets.choice(_FLAG_ALPHABET) for _ in range(32)) + "}"


def facility_admin_credentials(team_id: str) -> tuple[str, str]:
    """Return the facility-held native administrator credential."""
    return (
        ordinary_username(_facility_material(team_id, "administrator:username")),
        ordinary_password(_facility_material(team_id, "administrator:password")),
    )


def principal_context_key(team_id: str) -> str:
    """Return the guarded native record holding sealed principal assignments."""
    return ordinary_variable_key(_facility_material(team_id, "principal-context"))


def _context_key(team_id: str, purpose: str) -> bytes:
    if purpose != "principals":
        raise ValueError("private context purpose is invalid")
    return _facility_material(team_id, f"sealed-context:{purpose}")


def _context_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(
                key,
                b"airflow-context-stream-v1\0"
                + nonce
                + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def seal_context(team_id: str, purpose: str, value: object) -> str:
    """Seal private facility context for opaque persistence in prod."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if not raw or len(raw) > 16_384:
        raise ValueError("private context size is invalid")
    key = _context_key(team_id, purpose)
    nonce = secrets.token_bytes(24)
    stream = _context_stream(key, nonce, len(raw))
    ciphertext = bytes(left ^ right for left, right in zip(raw, stream))
    tag = hmac.new(
        key, b"airflow-context-seal-v1\0" + nonce + ciphertext, hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(nonce + ciphertext + tag).decode().rstrip("=")


def open_context(team_id: str, purpose: str, token: object) -> Any:
    """Authenticate and open facility context kept opaque from prod."""
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 32_768
        or _CONTEXT_RE.fullmatch(token) is None
    ):
        raise ValueError("sealed private context is malformed")
    try:
        envelope = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except ValueError as error:
        raise ValueError("sealed private context is malformed") from error
    if len(envelope) < 57:
        raise ValueError("sealed private context is malformed")
    nonce, body = envelope[:24], envelope[24:]
    ciphertext, supplied_tag = body[:-32], body[-32:]
    key = _context_key(team_id, purpose)
    expected_tag = hmac.new(
        key, b"airflow-context-seal-v1\0" + nonce + ciphertext, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError("sealed private context authentication failed")
    stream = _context_stream(key, nonce, len(ciphertext))
    raw = bytes(left ^ right for left, right in zip(ciphertext, stream))
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("sealed private context is malformed") from error


def objective_sentinel_key(team_id: str) -> str:
    """Return a stable neutral native key for objective-lifecycle integrity."""
    return ordinary_variable_key(_facility_material(team_id, "objective:sentinel"))


def _variable_key(seed: str, purpose: str) -> str:
    return ordinary_variable_key(_derive(seed, f"{purpose}:key"))


def principal_health_variable_key(seed: str) -> str:
    """Return one match-long native Variable key for principal health."""
    return _variable_key(seed, "principal:health-variable")


def round_context(seed: str) -> dict[str, str]:
    """Derive the complete concrete objective context from one round seed."""
    return {
        "context": _derive(seed, f"{STORE}:context").hex(),
        "key": _variable_key(seed, STORE),
        "top_control": "credential-" + _text(
            _derive(seed, f"{STORE}:top-control"), 28
        ),
        "deep_control": "api-" + _text(
            _derive(seed, f"{STORE}:deep-control"), 28
        ),
        "region": "zone-" + _derive(seed, f"{STORE}:region").hex()[:10],
        "description": "Managed integration profile "
        + _derive(seed, f"{STORE}:description").hex()[:12],
    }


def pack_handle(payload: dict[str, str]) -> str:
    document = {"v": 1, **payload}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: object) -> dict[str, Any] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        document = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(document, dict)
        or set(document) != {"v", "store", "context", "key", "token"}
        or document.get("v") != 1
        or document.get("store") != STORE
        or any(
            not isinstance(document.get(key), str) or not document[key]
            for key in ("context", "key", "token")
        )
    ):
        return None
    return document
