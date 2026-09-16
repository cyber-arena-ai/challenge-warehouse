"""Deterministic objective and principal identities for the Gradio service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re


STORE = "proof_file"
STATE_ROOT = "/var/lib/gradio-arena"
PROOF_ROOT = f"{STATE_ROOT}/public"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TARGET = re.compile(r"report-[0-9a-f]{24}\.txt")
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_FIRST = (
    "amber", "cedar", "coral", "dawn", "ember", "fern", "hazel", "indigo",
    "juniper", "linden", "maple", "olive", "pearl", "river", "sable", "willow",
)
_LAST = (
    "archer", "bennett", "carter", "dalton", "ellis", "foster", "garner", "harper",
    "irwin", "jensen", "kendall", "lawson", "morgan", "nolan", "parker", "sutton",
)


def _seed(value: object) -> bytes:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError("seed must be 32 bytes encoded as lowercase hexadecimal")
    return bytes.fromhex(value)


def derive(seed: object, domain: str) -> bytes:
    return hmac.new(
        _seed(seed), f"gradio-component-read/v1/{domain}".encode(), hashlib.sha256
    ).digest()


def _facility_key() -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("issued principal material is unavailable")
    return token.encode()


def principal_credentials(seed: object) -> tuple[str, str]:
    identity = derive(seed, "principal/identity")
    password_material = derive(seed, "principal/password")[:24]
    username = (
        f"{_FIRST[identity[0] & 15]}.{_LAST[identity[1] & 15]}."
        f"{identity[2:7].hex()}"
    )
    password = base64.urlsafe_b64encode(password_material).decode().rstrip("=")
    return username, password


def _cohort_signature(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"gradio-component-read/v1/issued-cohort\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def issued_cohort(accounts: object) -> str:
    """Seal the issued cohort so health can tell it from defender-authored state."""
    payload = json.dumps(
        {"accounts": sorted(accounts), "v": 1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_signature(payload)}"


def sealed_cohort(sealed: str) -> tuple[tuple[str, str], ...]:
    encoded, _, signature = sealed.partition(".")
    payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if not hmac.compare_digest(signature, _cohort_signature(payload)):
        raise RuntimeError("issued principal cohort is untrusted")
    return tuple(
        (username, password)
        for username, password in json.loads(payload)["accounts"]
    )


def round_context(seed: object) -> dict[str, str]:
    context = derive(seed, "objective/context").hex()
    target_id = f"report-{derive(seed, 'objective/target').hex()[:24]}.txt"
    return {
        "context": context,
        "target_id": target_id,
        "target_path": f"{PROOF_ROOT}/{target_id}",
    }


def _valid(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "context", "store", "target_id", "target_path", "token", "v"
    }:
        return False
    target_id = value.get("target_id")
    return (
        value.get("v") == 1
        and value.get("store") == STORE
        and isinstance(value.get("context"), str)
        and _HEX64.fullmatch(value["context"]) is not None
        and isinstance(target_id, str)
        and _TARGET.fullmatch(target_id) is not None
        and value.get("target_path") == f"{PROOF_ROOT}/{target_id}"
        and isinstance(value.get("token"), str)
        and bool(value["token"])
        and "\n" not in value["token"]
        and len(value["token"]) <= 512
    )


def pack_handle(payload: dict[str, object]) -> str:
    value = {"v": 1, "store": STORE, **payload}
    if not _valid(value):
        raise ValueError("invalid objective handle payload")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unpack_handle(handle: object) -> dict[str, object] | None:
    if not isinstance(handle, str) or not handle or len(handle) > 2048:
        return None
    try:
        raw = base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4))
        value = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    return value if _valid(value) else None


def public_locator(handle: object) -> str | None:
    value = unpack_handle(handle)
    target = value.get("target_path") if value is not None else None
    return target if isinstance(target, str) else None
