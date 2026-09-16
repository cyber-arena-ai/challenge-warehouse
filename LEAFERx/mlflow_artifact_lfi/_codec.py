"""Deterministic identities and opaque private handles for MLflow."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


_SEED_RE = re.compile(r"[0-9a-f]{64}")
_WORKFLOW_MANIFEST_DOMAIN = b"mlflow-workflow-principals-v1\0"
USERNAME_DOMAIN = "target"


def _seed_key(seed: str) -> bytes:
    if not isinstance(seed, str) or not _SEED_RE.fullmatch(seed):
        raise ValueError("round_context_seed must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(seed)


def derive(seed: str, domain: str, size: int = 32) -> bytes:
    return hmac.new(_seed_key(seed), domain.encode(), hashlib.sha256).digest()[:size]


def password_from_seed(seed: str, domain: str) -> str:
    return base64.urlsafe_b64encode(derive(seed, domain, 24)).decode().rstrip("=")


def signed_username(secret: str, nonce: bytes, domain: str) -> str:
    if len(nonce) != 8:
        raise ValueError("username nonce must be eight bytes")
    mac = hmac.new(secret.encode(), domain.encode() + b"\0" + nonce, hashlib.sha256).digest()[:8]
    return (nonce + mac).hex()


def username_owned(secret: str, username: object, domain: str) -> bool:
    if not isinstance(username, str) or not re.fullmatch(r"[0-9a-f]{32}", username):
        return False
    raw = bytes.fromhex(username)
    return hmac.compare_digest(username, signed_username(secret, raw[:8], domain))


def principal_identity(seed: str, admin_secret: str) -> tuple[str, str]:
    username = signed_username(
        admin_secret, derive(seed, "principal:username-nonce", 8), USERNAME_DOMAIN
    )
    return username, password_from_seed(seed, "principal:password")


def principal_workflow(seed: str, admin_secret: str) -> dict[str, str]:
    username, password = principal_identity(seed, admin_secret)
    return {
        "username": username,
        "password": password,
        "experiment_name": "Experiment "
        + derive(seed, "principal:workflow-experiment", 16).hex(),
    }


def workflow_manifest(
    accounts: Sequence[Mapping[str, str]], *, facility_secret: str, team_id: str
) -> dict[str, Any]:
    if not facility_secret or not team_id:
        raise ValueError("facility-bound workflow context is required")
    payload: dict[str, Any] = {
        "v": 4,
        "team_id": team_id,
        "accounts": [
            {"username": account["username"], "password": account["password"]}
            for account in accounts
        ],
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    payload["auth"] = hmac.new(
        facility_secret.encode(), _WORKFLOW_MANIFEST_DOMAIN + encoded, hashlib.sha256
    ).hexdigest()
    return payload


def workflow_manifest_accounts(
    value: object, *, facility_secret: str, team_id: str
) -> list[dict[str, str]] | None:
    if (
        not facility_secret
        or not team_id
        or not isinstance(value, dict)
        or value.get("v") != 4
        or value.get("team_id") != team_id
        or not isinstance(value.get("accounts"), list)
        or not isinstance(value.get("auth"), str)
    ):
        return None
    payload = {
        "v": value["v"],
        "team_id": value["team_id"],
        "accounts": value["accounts"],
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    expected = hmac.new(
        facility_secret.encode(), _WORKFLOW_MANIFEST_DOMAIN + encoded, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(value["auth"], expected):
        return None
    accounts: list[dict[str, str]] = []
    for account in value["accounts"]:
        if not isinstance(account, dict):
            return None
        username = account.get("username")
        password = account.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        accounts.append({"username": username, "password": password})
    return accounts


def round_identity(seed: str, admin_secret: str) -> dict[str, str]:
    token = derive(seed, "objective:experiment-name", 16).hex()
    return {
        "context": derive(seed, "objective:generation-context").hex(),
        "owner": signed_username(
            admin_secret, derive(seed, "objective:owner-nonce", 8), USERNAME_DOMAIN
        ),
        "owner_password": password_from_seed(seed, "objective:owner-password"),
        "experiment_name": f"Experiment {token}",
        "trace_id": "tr-" + derive(seed, "objective:trace-id", 16).hex(),
        "read_field": "input." + derive(seed, "objective:read-field", 8).hex(),
        "write_field": "review." + derive(seed, "objective:write-field", 8).hex(),
        "timestamp": str(1_700_000_000_000 + int.from_bytes(
            derive(seed, "objective:timestamp", 4), "big"
        ) % 31_536_000_000),
    }


def pack_handle(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: object) -> dict[str, Any] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) and value.get("v") == 1 else None


def public_locator(handle: str) -> str | None:
    value = unpack_handle(handle)
    if value is None:
        return None
    public = value.get("public")
    if not isinstance(public, dict) or not public:
        return None
    try:
        return json.dumps(public, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return None
