"""Facility-authenticated HorizontCMS baseline-principal cohort."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os


COHORT_PATH = "/var/lib/horizont/issued-cohort"
_DOMAIN = b"horizont-cms-filemanager/v1/issued-cohort\0"


def format_identity(digest: str) -> tuple[str, str]:
    """Render an ordinary Editor identity from seed-derived material."""
    return f"ed{digest[:14]}", f"Hz9!{digest[14:44]}"


def _facility_key() -> bytes:
    token = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    if not token:
        raise RuntimeError("HorizontCMS facility material unavailable")
    return token.encode()


def seal_issued_cohort(accounts: list[tuple[str, str]]) -> str:
    """Authenticate the complete sorted cohort written by provisioning."""
    payload = json.dumps(sorted(accounts), separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    tag = hmac.new(_facility_key(), _DOMAIN + payload, hashlib.sha256).hexdigest()
    return f"{encoded}.{tag}"


def open_issued_cohort(sealed: str) -> tuple[tuple[str, str], ...]:
    """Return only a nonempty cohort authenticated by the facility."""
    try:
        encoded, separator, tag = sealed.strip().partition(".")
        if not separator or len(tag) != 64:
            raise ValueError
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        expected = hmac.new(
            _facility_key(), _DOMAIN + payload, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError
        decoded = json.loads(payload)
        if not isinstance(decoded, list):
            raise ValueError
        accounts = []
        for account in decoded:
            if (
                not isinstance(account, list)
                or len(account) != 2
                or not all(isinstance(value, str) and value for value in account)
            ):
                raise ValueError
            accounts.append((account[0], account[1]))
        if not accounts:
            raise ValueError
    except (binascii.Error, TypeError, ValueError) as exc:
        raise RuntimeError("HorizontCMS issued cohort is untrusted") from exc
    return tuple(accounts)
