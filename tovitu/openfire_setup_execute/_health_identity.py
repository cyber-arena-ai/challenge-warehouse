"""Facility-derived administrator identity for the external health checker."""

from __future__ import annotations

import hashlib
import hmac
import os

from challenges.interface import VulboxTarget


def checker_admin_credentials(target: VulboxTarget) -> tuple[str, str]:
    secret = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    team_id = str(target.meta.get("team_id", ""))
    if not secret or not team_id:
        raise RuntimeError("Openfire checker facility identity context is unavailable")
    digest = hmac.new(
        secret.encode(),
        f"openfire-checker:{team_id}:administrator".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"arena-health-{digest[:12]}", f"Of9!{digest[12:52]}"
