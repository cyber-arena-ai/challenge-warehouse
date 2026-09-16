"""Facility-derived and facility-sealed identities for the external checker."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Iterable

from challenges.interface import VulboxTarget


CHECKER_POOL_SIZE = 4
ISSUED_COHORT_STATE = "/var/lib/openfire-arena/issued-cohort"


def _facility_key() -> bytes:
    secret = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not secret:
        raise RuntimeError("Openfire checker facility identity context is unavailable")
    return secret.encode()


def _credentials(team_id: str, role: str, slot: int) -> tuple[str, str]:
    if not team_id:
        raise RuntimeError("Openfire checker facility identity context is unavailable")
    digest = hmac.new(
        _facility_key(),
        f"openfire-setup-execute:{team_id}:{role}:{slot}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"user{digest[:16]}", f"Of9!{digest[16:44]}"


def checker_principal_pools(
    target: VulboxTarget,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Facility-only identities health still needs beside the issued cohort.

    `administrator` is retained because no issued participant carries
    administrator authority, so there is no issued principal a console-side
    defense could separate these from. One `ordinary` member joins every XMPP
    rotation so a two-party delivery is always exercised, including the ordinary
    two-team case where a single participant is issued.
    """
    team_id = str(target.meta.get("team_id", ""))
    if not team_id:
        raise RuntimeError("Openfire checker facility identity context is unavailable")
    return {
        role: tuple(
            _credentials(team_id, role, slot) for slot in range(CHECKER_POOL_SIZE)
        )
        for role in ("administrator", "ordinary")
    }


def _cohort_tag(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"openfire-server/v1/issued-cohort\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def seal_issued_cohort(accounts: Iterable[tuple[str, str]]) -> str:
    """Seal the complete issued `(username, password)` cohort for health."""
    rows = sorted([username, password] for username, password in accounts)
    payload = json.dumps(rows, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_tag(payload)}"


def open_issued_cohort(sealed: str) -> tuple[tuple[str, str], ...]:
    encoded, _, tag = sealed.partition(".")
    payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    # Compare as bytes: the tag half is defender-authored, and compare_digest
    # rejects a non-ASCII str operand by raising instead of returning False.
    if not hmac.compare_digest(tag.encode(), _cohort_tag(payload).encode()):
        raise RuntimeError("Openfire issued principal cohort is untrusted")
    accounts = tuple(
        (username, password) for username, password in json.loads(payload)
    )
    if not accounts:
        raise RuntimeError("Openfire issued principal cohort is empty")
    return accounts


def issued_principals(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    """Every participant identity this victim issued, read through the executor.

    The record is root-only in-container state a root defender can rewrite, so
    the facility seal — not the file mode — is what makes it trustworthy here.
    Unreadable, empty or untrusted state fails the probe rather than narrowing
    the cohort health exercises.
    """
    rc, output = target.meta["exec_in_container"](
        target.host, f"cat {ISSUED_COHORT_STATE}"
    )
    sealed = (output or "").strip()
    if rc != 0 or not sealed:
        raise RuntimeError("Openfire issued principal cohort is unavailable")
    return open_issued_cohort(sealed)
