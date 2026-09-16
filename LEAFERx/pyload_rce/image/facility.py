#!/usr/bin/env python3
"""Rotate and release pyLoad's private administrator credential."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import secrets
import sys
import urllib.parse

HOST = "127.0.0.1"
PORT = 8000
PRIVATE_DIR = Path("/var/lib/pyload-arena")
ADMIN_PATH = PRIVATE_DIR / "admin-password"
ADMIN_PENDING = PRIVATE_DIR / "admin-password.pending"
STATUS_KEYS = {"pause", "active", "queue", "total", "speed", "download"}


def _request(path: str, fields: dict[str, str]) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(HOST, PORT, timeout=15)
    try:
        connection.request(
            "POST",
            path,
            urllib.parse.urlencode(fields).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _rpc(
    method: str, username: str, password: str, **arguments: object
) -> tuple[int, object]:
    fields = {"u": username, "p": password}
    # pyLoad unquotes RPC arguments again after normal form decoding.
    fields.update(
        {key: repr(value).replace("%", "%25") for key, value in arguments.items()}
    )
    status, raw = _request(f"/api/{method}", fields)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"native {method} returned malformed JSON") from error
    return status, value


def _status(username: str, password: str) -> tuple[int, object]:
    return _rpc("status_server", username, password)


def _write_atomic(path: Path, value: bytes) -> None:
    PRIVATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".next")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(PRIVATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_secret(path: Path) -> str:
    value = path.read_text().strip()
    if not value or "\n" in value:
        raise RuntimeError("private administrator state is malformed")
    return value


def _auth_ok(username: str, password: str) -> bool:
    status, value = _status(username, password)
    return status == 200 and isinstance(value, dict) and STATUS_KEYS <= set(value)


def initialize() -> None:
    PRIVATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ADMIN_PATH.exists():
        if ADMIN_PENDING.exists() or not ADMIN_PATH.is_file():
            raise RuntimeError("private administrator state is malformed")
        if not _auth_ok("pyload", _read_secret(ADMIN_PATH)):
            raise RuntimeError("private administrator credential was rejected")
        return

    if ADMIN_PENDING.exists():
        if not ADMIN_PENDING.is_file():
            raise RuntimeError("pending administrator state is malformed")
        candidate = _read_secret(ADMIN_PENDING)
    else:
        candidate = "A9!" + secrets.token_hex(24)
        _write_atomic(ADMIN_PENDING, (candidate + "\n").encode())

    if not _auth_ok("pyload", candidate):
        if not _auth_ok("pyload", "pyload"):
            raise RuntimeError("administrator rotation cannot be reconciled")
        status, value = _rpc(
            "change_password",
            "pyload",
            "pyload",
            user="pyload",
            oldpw="pyload",
            newpw=candidate,
        )
        if status != 200 or value is not True or not _auth_ok("pyload", candidate):
            raise RuntimeError("administrator rotation failed")
    os.replace(ADMIN_PENDING, ADMIN_PATH)
    directory = os.open(PRIVATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _admin() -> tuple[str, str]:
    password = _read_secret(ADMIN_PATH)
    if not _auth_ok("pyload", password):
        raise RuntimeError("private administrator credential was rejected")
    return "pyload", password


def main(argv: list[str]) -> int:
    result = "OK"
    try:
        if argv == [argv[0], "initialize"]:
            initialize()
        elif argv == [argv[0], "health-admin"]:
            result = _admin()[1]
        else:
            return 2
    except Exception as error:
        print(f"facility operation failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
