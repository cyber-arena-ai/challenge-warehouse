"""Package constants and facility-owned checker identity derivation."""

from __future__ import annotations

import hashlib
import hmac
import os


SERVICE_PORT = 4242


def checker_identity(team_id: str) -> tuple[str, str]:
    """Derive a per-victim baseline identity from private facility state."""
    facility_token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not facility_token or not team_id:
        raise RuntimeError("checker facility identity unavailable")
    digest = hmac.new(
        facility_token.encode(),
        f"opentsdb-checker:{team_id}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"player-{digest[:12]}", f"arena-{digest[12:60]}"
