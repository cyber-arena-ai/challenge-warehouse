"""Facility-owned Navigate checker identity derivation."""

from __future__ import annotations

import hashlib
import hmac
import os


def checker_identity(team_id: str) -> tuple[str, str]:
    """Derive one per-victim normal-User identity from private facility state."""
    facility_token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not facility_token or not team_id:
        raise RuntimeError("checker facility identity unavailable")
    digest = hmac.new(
        facility_token.encode(),
        f"navigate-cms-checker:{team_id}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return "nv_" + digest[:20], "Nv!" + digest[20:52]
