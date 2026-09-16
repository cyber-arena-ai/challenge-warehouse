"""Native and checker identities for Vikunja's external probes and placement."""

from __future__ import annotations

from functools import lru_cache
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Iterable

from challenges.interface import VulboxTarget

from ._ids import derive_principal

_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_VERIFIER_TEAM_ID = "check"
_NATIVE_ACCOUNT_LABEL = b"vikunja-private-task/v1/native-account\0"
_ISSUED_COHORT_LABEL = b"vikunja-private-task/v1/issued-cohort\0"
NATIVE_ACCOUNT_PATH = "/arena/state/native_account"
ISSUED_COHORT_PATH = "/arena/state/issued_cohort"
CHECKER_POOL_SIZE = 4
_USERNAME_RE = re.compile(r"reader[0-9a-f]{10}")
_PASSWORD_RE = re.compile(r"V1![0-9a-f]{32}")


def seal_native_account(target: VulboxTarget, username: str, password: str) -> str:
    """Bind the native placement credential so prod root cannot substitute it."""
    secret, _team_id = _private_context(target)
    payload = base64.urlsafe_b64encode(json.dumps(
        {"password": password, "username": username},
        sort_keys=True, separators=(",", ":"),
    ).encode()).decode().rstrip("=")
    return payload + "." + _native_tag(secret, payload)


def open_native_account(target: VulboxTarget, sealed: str) -> tuple[str, str]:
    """Return the sealed native credential, refusing untrusted state loudly."""
    secret, _team_id = _private_context(target)
    payload, _, tag = sealed.partition(".")
    if not payload or not hmac.compare_digest(tag, _native_tag(secret, payload)):
        raise RuntimeError("native account state is untrusted")
    value = json.loads(base64.urlsafe_b64decode(
        payload + "=" * (-len(payload) % 4)))
    return value["username"], value["password"]


def _native_tag(secret: str, payload: str) -> str:
    return hmac.new(
        secret.encode(),
        _NATIVE_ACCOUNT_LABEL + payload.encode(),
        hashlib.sha256,
    ).hexdigest()


@lru_cache(maxsize=1)
def _verifier_secret() -> str:
    """Keep standalone-verifier identities private and stable per process."""
    return secrets.token_hex(32)


def _private_context(target: VulboxTarget) -> tuple[str, str]:
    team_id = target.meta.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("checker identity context unavailable")
    secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not secret:
        if team_id != _VERIFIER_TEAM_ID:
            raise RuntimeError("checker identity context unavailable")
        secret = _verifier_secret()
    return secret, team_id


def checker_writer_identities(
    target: VulboxTarget,
) -> tuple[tuple[str, str, str], ...]:
    """Derive the bounded facility writers still needed to create probe noise."""
    secret, team_id = _private_context(target)

    def identity(index: int) -> tuple[str, str, str]:
        digest = hmac.new(
            secret.encode(),
            f"vikunja-private-task\0{team_id}\0{index}\0writer".encode(),
            hashlib.sha256,
        ).hexdigest()
        return derive_principal(digest)

    return tuple(identity(index) for index in range(CHECKER_POOL_SIZE))


def _issued_cohort_tag(secret: str, payload: str) -> str:
    return hmac.new(
        secret.encode(),
        _ISSUED_COHORT_LABEL + payload.encode(),
        hashlib.sha256,
    ).hexdigest()


def _validate_issued_rows(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("issued principal cohort is empty or malformed")
    rows: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or _USERNAME_RE.fullmatch(item[0]) is None
            or not isinstance(item[1], str)
            or _PASSWORD_RE.fullmatch(item[1]) is None
        ):
            raise RuntimeError("issued principal cohort is malformed")
        rows.append((item[0], item[1]))
    if (
        rows != sorted(rows)
        or len({username for username, _password in rows}) != len(rows)
        or len({password for _username, password in rows}) != len(rows)
    ):
        raise RuntimeError("issued principal cohort is malformed")
    return tuple(rows)


def seal_issued_cohort(
    target: VulboxTarget, accounts: Iterable[tuple[str, str]],
) -> str:
    """Seal the complete sorted issued `(username, password)` cohort."""
    rows = sorted([username, password] for username, password in accounts)
    _validate_issued_rows(rows)
    payload = base64.urlsafe_b64encode(
        json.dumps(rows, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    secret, _team_id = _private_context(target)
    return payload + "." + _issued_cohort_tag(secret, payload)


def open_issued_cohort(
    target: VulboxTarget, sealed: object,
) -> tuple[tuple[str, str], ...]:
    """Open only an authenticated, nonempty, canonical issued cohort."""
    try:
        if not isinstance(sealed, str) or sealed.count(".") != 1:
            raise RuntimeError("issued principal cohort is malformed")
        payload, tag = sealed.split(".", 1)
        secret, _team_id = _private_context(target)
        if (
            not payload
            or re.fullmatch(r"[0-9a-f]{64}", tag) is None
            or not hmac.compare_digest(tag, _issued_cohort_tag(secret, payload))
        ):
            raise RuntimeError("issued principal cohort is untrusted")
        raw = base64.b64decode(
            payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        value = json.loads(raw)
    except RuntimeError:
        raise
    except (UnicodeDecodeError, ValueError, binascii.Error, json.JSONDecodeError) as error:
        raise RuntimeError("issued principal cohort is malformed") from error
    rows = _validate_issued_rows(value)
    canonical = base64.urlsafe_b64encode(
        json.dumps([list(row) for row in rows], separators=(",", ":")).encode()
    ).decode().rstrip("=")
    if not hmac.compare_digest(payload, canonical):
        raise RuntimeError("issued principal cohort is malformed")
    return rows


def issued_principals(
    target: VulboxTarget,
) -> tuple[tuple[str, str], ...]:
    """Read and authenticate the complete issued cohort through the executor."""
    rc, out = target.meta["exec_in_container"](
        target.host, f"cat {ISSUED_COHORT_PATH}")
    sealed = (out or "").strip()
    if rc != 0 or not sealed:
        raise RuntimeError("issued principal cohort is unavailable")
    return open_issued_cohort(target, sealed)
