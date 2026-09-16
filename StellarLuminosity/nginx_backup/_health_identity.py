"""Facility-attested ordinary identity for Nginx UI health workflows."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex

from challenges.interface import VulboxTarget


_ADMIN_MANIFEST = "/srv/nginx-ui/private/admin.json"
_ATTESTED_ADMIN = "/run/nginx-ui-native-admin"
_ATTESTATION_LABEL = b"nginx-ui-management/v1/native-admin\0"
_NATIVE_USERNAME_RE = re.compile(r"[0-9a-f]{32}")
_NATIVE_PASSWORD_RE = re.compile(r"[A-Za-z0-9_-]{16}")


def _credentials(material: bytes) -> tuple[str, str]:
    encoded = base64.urlsafe_b64encode(material).decode().rstrip("=")
    username_length = 8 + material[0] % 13
    password_length = 8 + material[1] % 13
    return "n" + encoded[2 : username_length + 1], encoded[-password_length:]


def _facility_key(target: VulboxTarget) -> bytes:
    secret = os.environ.get("CYBERARENA_FACILITY_TOKEN", "")
    team_id = target.meta.get("team_id")
    if not isinstance(team_id, str) or not team_id:
        raise RuntimeError("Nginx UI checker identity context unavailable")
    if not secret and team_id == "check":
        secret = "canonical-verifier-only"
    if not secret:
        raise RuntimeError("Nginx UI checker identity context unavailable")
    return secret.encode()


def _parse_native_admin(raw: str) -> tuple[str, str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("Nginx UI native administrator malformed") from error
    username = value.get("username") if isinstance(value, dict) else None
    password = value.get("password") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"username", "password"}
        or not isinstance(username, str)
        or not _NATIVE_USERNAME_RE.fullmatch(username)
        or not isinstance(password, str)
        or not _NATIVE_PASSWORD_RE.fullmatch(password)
    ):
        raise RuntimeError("Nginx UI native administrator malformed")
    return username, password


def seal_native_admin_credentials(target: VulboxTarget, exec_in) -> None:
    rc, output = exec_in(target.host, f"cat {_ADMIN_MANIFEST}")
    if rc != 0:
        raise RuntimeError("Nginx UI native administrator unavailable")
    username, password = _parse_native_admin(output)
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {"password": password, "username": username},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).decode().rstrip("=")
    tag = hmac.new(
        _facility_key(target),
        _ATTESTATION_LABEL + payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    record = payload + "." + tag
    temporary = _ATTESTED_ADMIN + ".tmp"
    command = " ".join(
        (
            "set -eu; umask 077; printf '%s\\n'",
            shlex.quote(record),
            ">",
            shlex.quote(temporary) + ";",
            "chown root:root",
            shlex.quote(temporary) + ";",
            "chmod 0400",
            shlex.quote(temporary) + ";",
            "mv -f",
            shlex.quote(temporary),
            shlex.quote(_ATTESTED_ADMIN),
        )
    )
    rc, output = exec_in(target.host, command)
    if rc != 0:
        raise RuntimeError(
            "Nginx UI native administrator attestation failed: "
            + (output or f"rc={rc}")[-200:]
        )


def existing_admin_credentials(target: VulboxTarget) -> tuple[str, str]:
    exec_in = target.meta.get("exec_in_container")
    if exec_in is None:
        raise RuntimeError("Nginx UI native administrator bridge unavailable")
    rc, output = exec_in(target.host, f"cat {_ATTESTED_ADMIN}")
    if rc != 0:
        raise RuntimeError("Nginx UI native administrator attestation unavailable")
    payload, separator, tag = output.strip().partition(".")
    expected = hmac.new(
        _facility_key(target),
        _ATTESTATION_LABEL + payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not separator or not hmac.compare_digest(tag, expected):
        raise RuntimeError("Nginx UI native administrator attestation invalid")
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("Nginx UI native administrator attestation invalid") from error
    return _parse_native_admin(raw)


def fresh_admin_credentials(existing_username: str) -> tuple[str, str]:
    while True:
        credentials = _credentials(secrets.token_bytes(32))
        if len(credentials[0]) != len(existing_username):
            return credentials
