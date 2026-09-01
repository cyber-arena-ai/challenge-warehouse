"""Facility-derived identities used only by the external Webmin checker."""

from __future__ import annotations

import hashlib
import hmac
import os


_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"


def checker_identities(team_id: str) -> dict[str, tuple[str, str, tuple[str, ...]]]:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token:
        raise RuntimeError("facility checker identity is unavailable")

    def derive(role: str) -> tuple[str, str]:
        digest = hmac.new(
            token.encode(),
            f"webmin-filemanager-checker:{team_id}:{role}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"health_{digest[:16]}", f"Wm9!{digest[16:48]}"

    first = derive("restricted-1")
    second = derive("restricted-2")
    administrator = derive("file-manager")
    return {
        "restricted-1": (*first, ("change-user",)),
        "restricted-2": (*second, ("change-user",)),
        "file-manager": (*administrator, ("change-user", "filemin")),
    }
