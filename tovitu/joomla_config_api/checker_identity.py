"""Facility-derived Joomla identities for the external workflow checker."""

from __future__ import annotations

import hashlib
import hmac
import os


_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def _identity(token: str, team_id: str, role: str) -> tuple[str, str]:
    digest = hmac.new(
        token.encode(),
        f"joomla-config-api-checker:{team_id}:{role}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return "arena_" + digest[:18], "Jm!" + digest[18:58]


def checker_identities(team_id: str) -> tuple[tuple[str, str], tuple[str, str]]:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("facility checker identity is unavailable")
    return (
        _identity(token, team_id, "registered"),
        _identity(token, team_id, "administrator"),
    )
