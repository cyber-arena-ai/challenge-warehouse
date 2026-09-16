"""Facility-bound ordinary identities for the external health checker."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re

from challenges.interface import VulboxTarget


_POOL_SIZE = 6
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_USERNAME = re.compile(r"cloud_[a-f0-9]{16}")
_PASSWORD = re.compile(r"Oc-[a-f0-9]{32}!")


def _format_identity(digest: str) -> tuple[str, str]:
    return f"cloud_{digest[:16]}", f"Oc-{digest[16:48]}!"


def _facility_key() -> bytes:
    secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not secret:
        raise RuntimeError("ownCloud issued principal material is unavailable")
    return secret.encode()


def _validated_accounts(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("ownCloud issued principal cohort is empty")
    accounts: list[tuple[str, str]] = []
    for row in value:
        if (
            not isinstance(row, list)
            or len(row) != 2
            or not isinstance(row[0], str)
            or _USERNAME.fullmatch(row[0]) is None
            or not isinstance(row[1], str)
            or _PASSWORD.fullmatch(row[1]) is None
        ):
            raise RuntimeError("ownCloud issued principal cohort is malformed")
        accounts.append((row[0], row[1]))
    if (
        len({username for username, _ in accounts}) != len(accounts)
        or len({password for _, password in accounts}) != len(accounts)
    ):
        raise RuntimeError("ownCloud issued principal cohort has collisions")
    return tuple(sorted(accounts))


def _cohort_signature(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"owncloud-signed-url/v1/issued-cohort\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def seal_issued_cohort(accounts: object) -> str:
    """Seal the complete issued cohort for defender-independent verification."""
    rows = _validated_accounts(accounts)
    payload = json.dumps(
        {"accounts": rows, "v": 1}, sort_keys=True, separators=(",", ":")
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_signature(payload)}"


def open_issued_cohort(sealed: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(sealed, str) or not sealed or len(sealed) > 32_768:
        raise RuntimeError("ownCloud issued principal cohort is malformed")
    encoded, separator, signature = sealed.partition(".")
    if not separator or not encoded or not re.fullmatch(r"[a-f0-9]{64}", signature):
        raise RuntimeError("ownCloud issued principal cohort is malformed")
    try:
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise RuntimeError("ownCloud issued principal cohort is malformed") from error
    if not hmac.compare_digest(signature, _cohort_signature(payload)):
        raise RuntimeError("ownCloud issued principal cohort is untrusted")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("ownCloud issued principal cohort is malformed") from error
    if not isinstance(value, dict) or set(value) != {"accounts", "v"} or value["v"] != 1:
        raise RuntimeError("ownCloud issued principal cohort is malformed")
    return _validated_accounts(value["accounts"])


def checker_identity_pool(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    team_id = str(target.meta.get("team_id", ""))
    if not team_id:
        raise RuntimeError("ownCloud checker facility identity context is unavailable")

    def derive(index: int) -> tuple[str, str]:
        digest = hmac.new(
            _facility_key(),
            f"owncloud-signed-url:principal:{team_id}:{index}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return _format_identity(digest)

    return tuple(derive(index) for index in range(_POOL_SIZE))
