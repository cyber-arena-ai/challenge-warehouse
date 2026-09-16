"""Facility-owned Navigate identity and placement derivation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re


COHORT_FILE = "/var/lib/navigate-proof/issued.cohort"
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")


def _facility_key() -> bytes:
    facility_token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not facility_token:
        raise RuntimeError("Navigate facility material unavailable")
    return facility_token.encode()


def _cohort_signature(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"navigate-cms/v1/issued-cohort\0" + payload,
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
    """Recover the issued cohort only when the facility seal verifies."""
    encoded, _, signature = sealed.strip().partition(".")
    payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if not hmac.compare_digest(signature, _cohort_signature(payload)):
        raise RuntimeError("Navigate issued principal cohort is untrusted")
    accounts = tuple(
        (username, password)
        for username, password in json.loads(payload)["accounts"]
    )
    if not accounts:
        raise RuntimeError("Navigate issued principal cohort is empty")
    return accounts


def _round_digest(seed: str, purpose: str) -> str:
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise RuntimeError("Navigate placement material unavailable")
    return hmac.new(
        bytes.fromhex(seed),
        f"navigate-cms\0command_execution\0{purpose}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()


def round_context(seed: str) -> tuple[str, str, str]:
    """Derive retry cache, public target, and record authenticator from STATE-1."""
    key = _round_digest(seed, "placement-cache")
    target_id = _round_digest(seed, "operation-id")[:24]
    mac = hmac.new(
        bytes.fromhex(seed),
        "\0".join(("navigate-placement-record", key, target_id)).encode(),
        hashlib.sha256,
    ).hexdigest()
    return key, target_id, mac
