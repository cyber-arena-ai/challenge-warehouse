"""Facility-owned identities for the external HorizontCMS checker."""

from __future__ import annotations

import hashlib
import hmac
import os


def checker_identities(team_id: str) -> tuple[tuple[str, str], ...]:
    """Derive two per-victim Editor identities from private facility state."""
    facility_token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not facility_token or not team_id:
        raise RuntimeError("checker facility identity unavailable")

    identities = []
    for index in (1, 2):
        digest = hmac.new(
            facility_token.encode(),
            f"horizont-checker:{team_id}:{index}".encode(),
            hashlib.sha256,
        ).hexdigest()
        identities.append((f"arena_{digest[:16]}", f"Hz9!{digest[16:44]}"))
    return tuple(identities)
