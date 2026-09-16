"""Facility-authenticated issued-principal cohort for health checks."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re

from challenges.interface import VulboxTarget


_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_USERNAME = re.compile(r"user[0-9a-f]{16}")
_PASSWORD = re.compile(r"C1![0-9a-f]{32}")
_SIGNATURE = re.compile(r"[0-9a-f]{64}")
_LABEL = b"caddy-nextcloud-sso/v1/issued-cohort\0"
_MAX_SEALED_BYTES = 32_768


def _team_id(target: VulboxTarget) -> str:
    team_id = target.meta.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("issued principal team identity is unavailable")
    return team_id


def _facility_key() -> bytes:
    secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not secret:
        raise RuntimeError("issued principal material is unavailable")
    return secret.encode()


def _validated_accounts(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("issued principal cohort is empty")
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
            raise RuntimeError("issued principal cohort is malformed")
        accounts.append((row[0], row[1]))
    if (
        len({username for username, _password in accounts}) != len(accounts)
        or len({password for _username, password in accounts}) != len(accounts)
    ):
        raise RuntimeError("issued principal cohort has collisions")
    return tuple(sorted(accounts))


def _signature(target: VulboxTarget, payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        _LABEL + _team_id(target).encode() + b"\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def seal_issued_cohort(
    target: VulboxTarget, accounts: object,
) -> str:
    """Seal the complete issued cohort for defender-independent verification."""
    rows = _validated_accounts(accounts)
    payload = json.dumps(
        {"accounts": rows, "v": 1}, separators=(",", ":"), sort_keys=True,
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_signature(target, payload)}"


def open_issued_cohort(
    target: VulboxTarget, sealed: object,
) -> tuple[tuple[str, str], ...]:
    if (
        not isinstance(sealed, str)
        or not sealed
        or len(sealed) > _MAX_SEALED_BYTES
    ):
        raise RuntimeError("issued principal cohort is malformed")
    encoded, separator, signature = sealed.partition(".")
    if (
        not separator
        or not encoded
        or _SIGNATURE.fullmatch(signature) is None
    ):
        raise RuntimeError("issued principal cohort is malformed")
    try:
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as error:
        raise RuntimeError("issued principal cohort is malformed") from error
    if not hmac.compare_digest(signature, _signature(target, payload)):
        raise RuntimeError("issued principal cohort is untrusted")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("issued principal cohort is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"accounts", "v"}
        or value["v"] != 1
    ):
        raise RuntimeError("issued principal cohort is malformed")
    return _validated_accounts(value["accounts"])
