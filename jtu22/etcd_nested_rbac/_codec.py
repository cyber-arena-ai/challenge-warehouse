"""Deterministic, domain-separated challenge identity derivation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re


TARGET_KEY_RE = re.compile(
    r"/services/production/[a-f0-9]{24}/credentials/database-password"
)
PRINCIPAL_RE = re.compile(r"config-[a-f0-9]{16}")
ROLE_RE = re.compile(r"workspace-[a-f0-9]{16}")

CHECKER_PRINCIPAL_COUNT = 4
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def derive(seed: str, label: str) -> bytes:
    if re.fullmatch(r"[a-f0-9]{64}", seed or "") is None:
        raise ValueError("round context seed is unavailable")
    return hmac.new(bytes.fromhex(seed), label.encode(), hashlib.sha256).digest()


def target_key(seed: str) -> str:
    identity = derive(seed, "database-password:target-key").hex()[:24]
    return f"/services/production/{identity}/credentials/database-password"


def principal_credentials(seed: str) -> tuple[str, str]:
    username = "config-" + derive(seed, "principal:username").hex()[:16]
    password = base64.urlsafe_b64encode(
        derive(seed, "principal:password")
    ).decode().rstrip("=")
    return username, password


def checker_principals(team_id: str) -> tuple[tuple[str, str], ...]:
    """Stable target-specific ordinary principals prepared before round zero."""
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("facility principal material is unavailable")
    rows = []
    for slot in range(CHECKER_PRINCIPAL_COUNT):
        seed = hmac.new(
            token.encode(),
            f"etcd-configuration-store:{team_id}:{slot}".encode(),
            hashlib.sha256,
        ).hexdigest()
        rows.append(principal_credentials(seed))
    return tuple(rows)


def principal_role(username: str) -> str:
    if PRINCIPAL_RE.fullmatch(username) is None:
        raise ValueError("invalid principal id")
    return "workspace-" + username.removeprefix("config-")


def principal_prefix(username: str) -> str:
    if PRINCIPAL_RE.fullmatch(username) is None:
        raise ValueError("invalid principal id")
    return f"/teams/analyst/{username}/"


def prefix_end(prefix: str) -> str:
    raw = bytearray(prefix.encode())
    for index in range(len(raw) - 1, -1, -1):
        if raw[index] < 255:
            raw[index] += 1
            return bytes(raw[: index + 1]).decode()
    raise ValueError("prefix has no finite range end")


def valid_target_key(value: object) -> bool:
    return isinstance(value, str) and TARGET_KEY_RE.fullmatch(value) is not None
