"""Facility-derived ordinary identities for the external health checker."""

from __future__ import annotations

import hashlib
import hmac
import os

from challenges.interface import VulboxTarget


def checker_credentials(
    target: VulboxTarget,
) -> tuple[tuple[str, str], tuple[str, str]]:
    secret = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    team_id = str(target.meta.get("team_id", ""))
    if not secret or not team_id:
        raise RuntimeError("ownCloud checker facility identity context is unavailable")

    def derive(role: str) -> tuple[str, str]:
        digest = hmac.new(
            secret.encode(),
            f"owncloud-checker:{team_id}:{role}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"arena_{digest[:16]}", f"Oc-{digest[16:48]}!"

    return derive("primary"), derive("peer")
