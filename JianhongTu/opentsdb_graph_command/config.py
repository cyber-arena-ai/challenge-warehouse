"""Package constants, the facility-sealed issued cohort, and round derivation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re


SERVICE_PORT = 4242
COHORT_FILE = "/var/lib/opentsdb-release/issued.cohort"
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")


def _facility_key() -> bytes:
    facility_token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not facility_token:
        raise RuntimeError("facility identity material unavailable")
    return facility_token.encode()


def _cohort_signature(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"opentsdb-graph-command/v1/issued-cohort\0" + payload,
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
    # Compare as bytes: a tampered file reaches us decoded with errors="replace",
    # and compare_digest rejects non-ASCII str with TypeError rather than False.
    if not hmac.compare_digest(
        signature.encode("utf-8", "replace"), _cohort_signature(payload).encode()
    ):
        raise RuntimeError("OpenTSDB issued principal cohort is untrusted")
    accounts = tuple(
        (principal, token) for principal, token in json.loads(payload)["accounts"]
    )
    if not accounts:
        raise RuntimeError("OpenTSDB issued principal cohort is empty")
    return accounts


def _round_digest(seed: str, purpose: str) -> str:
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise RuntimeError("OpenTSDB round context unavailable")
    return hmac.new(
        bytes.fromhex(seed),
        f"opentsdb-metrics\0command\0{purpose}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()


def round_context(seed: str) -> tuple[str, str]:
    """Derive the retry key and execution-operation target from STATE-1."""
    return (
        _round_digest(seed, "placement-cache"),
        _round_digest(seed, "operation-id")[:24],
    )
