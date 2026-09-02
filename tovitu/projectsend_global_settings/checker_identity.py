"""Facility-derived identities used only by the external ProjectSend checker."""

from __future__ import annotations

import hashlib
import hmac
import os


_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def checker_identities(team_id: str) -> dict[str, tuple[str, str]]:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("facility checker identity is unavailable")

    def derive(role: str) -> tuple[str, str]:
        digest = hmac.new(
            token.encode(),
            f"projectsend-global-settings-checker:{team_id}:{role}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"health{digest[:16]}", f"Ps9!{digest[16:48]}"

    return {
        "administrator": derive("administrator"),
        "client": derive("client"),
    }
