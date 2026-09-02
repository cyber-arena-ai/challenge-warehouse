"""Private facility-derived identity for the external Website checker."""

from __future__ import annotations

import hashlib
import hmac
import os

from challenges.interface import VulboxTarget

from ._client import DolibarrError


def checker_credentials(target: VulboxTarget) -> tuple[str, str]:
    """Derive one unguessable, victim-specific editor credential."""

    secret = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    team_id = target.meta.get("team_id")
    if not secret or not isinstance(team_id, str) or not team_id:
        raise DolibarrError("checker identity context unavailable")
    digest = hmac.new(
        secret.encode(),
        f"dolibarr-website-checker\0{team_id}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return "ed" + digest[:14], "Aa1!" + digest[14:46]
