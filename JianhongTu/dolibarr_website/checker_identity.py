"""Facility-sealed issued editor cohort for the external Website checker."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re

from challenges.interface import VulboxTarget


COHORT_PATH = "/var/lib/cyberarena/dolibarr-proof/issued.cohort"
_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_USERNAME = re.compile(r"ed[0-9a-f]{14}")
_PASSWORD = re.compile(r"Aa1![0-9a-f]{32}")


def _facility_key() -> bytes:
    secret = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not secret:
        raise RuntimeError("Dolibarr issued editor material is unavailable")
    return secret.encode()


def _validated_editors(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("Dolibarr issued editor cohort is empty")
    editors: list[tuple[str, str]] = []
    for row in value:
        if (
            not isinstance(row, list)
            or len(row) != 2
            or not isinstance(row[0], str)
            or _USERNAME.fullmatch(row[0]) is None
            or not isinstance(row[1], str)
            or _PASSWORD.fullmatch(row[1]) is None
        ):
            raise RuntimeError("Dolibarr issued editor cohort is malformed")
        editors.append((row[0], row[1]))
    if (
        len({username for username, _ in editors}) != len(editors)
        or len({password for _, password in editors}) != len(editors)
    ):
        raise RuntimeError("Dolibarr issued editor cohort has collisions")
    return tuple(sorted(editors))


def _cohort_signature(payload: bytes) -> str:
    return hmac.new(
        _facility_key(),
        b"dolibarr-website/v1/issued-cohort\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def seal_issued_cohort(editors: object) -> str:
    """Seal the complete issued cohort for defender-independent verification."""
    rows = _validated_editors(editors)
    payload = json.dumps(
        {"editors": rows, "v": 1}, sort_keys=True, separators=(",", ":")
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{_cohort_signature(payload)}"


def open_issued_cohort(sealed: object) -> tuple[tuple[str, str], ...]:
    """Verify a sealed cohort outside the defender's trust boundary."""
    if not isinstance(sealed, str) or not sealed or len(sealed) > 32_768:
        raise RuntimeError("Dolibarr issued editor cohort is malformed")
    encoded, separator, signature = sealed.partition(".")
    if not separator or not encoded or not re.fullmatch(r"[a-f0-9]{64}", signature):
        raise RuntimeError("Dolibarr issued editor cohort is malformed")
    try:
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise RuntimeError("Dolibarr issued editor cohort is malformed") from error
    if not hmac.compare_digest(signature, _cohort_signature(payload)):
        raise RuntimeError("Dolibarr issued editor cohort is untrusted")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("Dolibarr issued editor cohort is malformed") from error
    if not isinstance(value, dict) or set(value) != {"editors", "v"} or value["v"] != 1:
        raise RuntimeError("Dolibarr issued editor cohort is malformed")
    return _validated_editors(value["editors"])


def issued_editors(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    """Read and verify the cohort the facility issued to this victim."""
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("Dolibarr issued editor bridge is unavailable")
    rc, output = exec_in(target.host, f"cat {COHORT_PATH}")
    if rc != 0:
        raise RuntimeError("Dolibarr issued editor cohort is unavailable")
    return open_issued_cohort((output or "").strip())
