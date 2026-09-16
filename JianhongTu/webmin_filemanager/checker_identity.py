"""Authenticated principal context used by the external Webmin checker."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
import re
import secrets


_FACILITY_TOKEN_ENV = "CYBERARENA_FACILITY_TOKEN"
_FILE_MANAGER_POOL_SIZE = 2
_CONTEXT_RE = re.compile(r"[A-Za-z0-9_-]+")
_USERNAME_RE = re.compile(r"arena_[a-f0-9]{16}")
_PASSWORD_RE = re.compile(r"Wm9![a-f0-9]{28}")


@dataclass(frozen=True)
class PrincipalAssignments:
    issued: tuple[tuple[str, str], ...]
    file_managers: tuple[tuple[str, str], ...]


def _facility_key(team_id: str, purpose: str) -> bytes:
    token = os.environ.get(_FACILITY_TOKEN_ENV, "")
    if not token or not team_id:
        raise RuntimeError("facility checker identity is unavailable")
    return hmac.new(
        token.encode(),
        f"webmin-filemanager:{team_id}:{purpose}:v1".encode(),
        hashlib.sha256,
    ).digest()


def assignment_filename() -> str:
    return "system-inventory.conf"


def _stream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(
                key,
                b"webmin-principal-context-stream-v1\0"
                + nonce
                + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def seal_assignments(
    team_id: str,
    issued: list[tuple[str, str]],
    file_managers: list[tuple[str, str]],
) -> str:
    if not issued or not file_managers:
        raise ValueError("principal assignment set is empty")
    raw = json.dumps(
        {
            "file_managers": [list(account) for account in sorted(file_managers)],
            "issued": [list(account) for account in sorted(issued)],
            "v": 2,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    key = _facility_key(team_id, "principal-context")
    nonce = secrets.token_bytes(24)
    ciphertext = bytes(
        left ^ right for left, right in zip(raw, _stream(key, nonce, len(raw)))
    )
    tag = hmac.new(
        key,
        b"webmin-principal-context-seal-v1\0" + nonce + ciphertext,
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(nonce + ciphertext + tag).decode().rstrip("=")


def open_assignments(team_id: str, token: object) -> PrincipalAssignments:
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 16_384
        or _CONTEXT_RE.fullmatch(token) is None
    ):
        raise ValueError("principal assignment record is malformed")
    try:
        envelope = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except ValueError as error:
        raise ValueError("principal assignment record is malformed") from error
    if len(envelope) < 57:
        raise ValueError("principal assignment record is malformed")
    nonce, body = envelope[:24], envelope[24:]
    ciphertext, supplied_tag = body[:-32], body[-32:]
    key = _facility_key(team_id, "principal-context")
    expected_tag = hmac.new(
        key,
        b"webmin-principal-context-seal-v1\0" + nonce + ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError("principal assignment record authentication failed")
    raw = bytes(
        left ^ right
        for left, right in zip(ciphertext, _stream(key, nonce, len(ciphertext)))
    )
    try:
        document = json.loads(raw)
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("principal assignment record is malformed") from error

    def parse_accounts(name: str) -> tuple[tuple[str, str], ...]:
        rows = document[name]
        if not isinstance(rows, list):
            raise ValueError("principal assignment record is malformed")
        accounts = tuple(
            (row[0], row[1])
            for row in rows
            if isinstance(row, list) and len(row) == 2
        )
        if (
            not accounts
            or len(accounts) != len(rows)
            or any(
                not isinstance(username, str)
                or not isinstance(password, str)
                or _USERNAME_RE.fullmatch(username) is None
                or _PASSWORD_RE.fullmatch(password) is None
                for username, password in accounts
            )
            or len({username for username, _ in accounts}) != len(accounts)
            or len({password for _, password in accounts}) != len(accounts)
        ):
            raise ValueError("principal assignment record is malformed")
        return accounts

    if (
        not isinstance(document, dict)
        or set(document) != {"file_managers", "issued", "v"}
        or document.get("v") != 2
    ):
        raise ValueError("principal assignment record is malformed")
    try:
        issued = parse_accounts("issued")
        file_managers = parse_accounts("file_managers")
    except (KeyError, TypeError) as error:
        raise ValueError("principal assignment record is malformed") from error
    combined = issued + file_managers
    if (
        len({username for username, _ in combined}) != len(combined)
        or len({password for _, password in combined}) != len(combined)
    ):
        raise ValueError("principal assignment record is malformed")
    return PrincipalAssignments(issued=issued, file_managers=file_managers)


def new_checker_identities() -> dict[str, tuple[str, str, tuple[str, ...]]]:
    def fresh() -> tuple[str, str]:
        return f"arena_{secrets.token_hex(8)}", f"Wm9!{secrets.token_hex(14)}"

    identities = {}
    for index in range(_FILE_MANAGER_POOL_SIZE):
        role = f"file-manager-{index}"
        identities[role] = (*fresh(), ("change-user", "filemin"))
    return identities
