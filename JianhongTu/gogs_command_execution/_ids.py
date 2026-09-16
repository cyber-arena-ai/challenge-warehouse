"""Deterministic round identities and opaque execute-objective handles."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re


STORE = "victim_execution_witness"
_SEED_RE = re.compile(r"[0-9a-f]{64}")
_OPERATION_RE = re.compile(r"[0-9a-f]{32}")


def _derive(seed: str, purpose: str) -> bytes:
    if not isinstance(seed, str) or _SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    return hmac.new(
        bytes.fromhex(seed),
        f"gogs-code-collaboration\0{purpose}\0v1".encode(),
        hashlib.sha256,
    ).digest()


def round_context(seed: str) -> dict[str, str]:
    """Derive one proof operation independently of the proof token."""
    return {
        "context": _derive(seed, "generation-context").hex(),
        "operation": _derive(seed, "proof-operation").hex()[:32],
    }


def pack_handle(payload: dict[str, str]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: object) -> dict[str, str] | None:
    if not isinstance(handle, str) or not handle:
        return None
    try:
        value = json.loads(
            base64.urlsafe_b64decode((handle + "=" * (-len(handle) % 4)).encode())
        )
    except (ValueError, binascii.Error):
        return None
    if not isinstance(value, dict) or set(value) != {
        "context",
        "operation",
        "store",
        "token",
    }:
        return None
    if (
        value.get("store") != STORE
        or not isinstance(value.get("context"), str)
        or _SEED_RE.fullmatch(value["context"]) is None
        or not isinstance(value.get("operation"), str)
        or _OPERATION_RE.fullmatch(value["operation"]) is None
        or not isinstance(value.get("token"), str)
        or not value["token"]
    ):
        return None
    return value


def public_locator(handle: object) -> str | None:
    payload = unpack_handle(handle)
    return None if payload is None else f"gogs-proof:{payload['operation']}"


def parse_public_locator(locator: object) -> str | None:
    if not isinstance(locator, str):
        return None
    match = re.fullmatch(r"gogs-proof:([0-9a-f]{32})", locator)
    return match.group(1) if match else None
