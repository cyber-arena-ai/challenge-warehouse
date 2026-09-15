#!/usr/bin/env python3
"""Create one opaque native Nginx UI administrator at first boot."""

from __future__ import annotations

import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time


HOST = "127.0.0.1"
PORT = 9000
MANIFEST = Path("/srv/nginx-ui/private/admin.json")


def request(
    method: str,
    path: str,
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict]:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token is not None:
        headers["Authorization"] = token
    connection = http.client.HTTPConnection(HOST, PORT, timeout=20)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise RuntimeError("Nginx UI provisioning returned malformed JSON")
    return response.status, value


def encrypted(values: dict[str, str]) -> dict[str, str]:
    status, document = request(
        "POST",
        "/api/crypto/public_key",
        {"timestamp": int(time.time() * 1000), "fingerprint": secrets.token_hex(16)},
    )
    key = document.get("public_key")
    if status != 200 or not isinstance(key, str):
        raise RuntimeError("Nginx UI public-key provisioning failed")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as key_file:
        key_file.write(key)
        key_file.flush()
        completed = subprocess.run(
            [
                "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", key_file.name,
                "-pkeyopt", "rsa_padding_mode:pkcs1",
            ],
            input=json.dumps(values, separators=(",", ":")).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        raise RuntimeError("Nginx UI credential encryption failed")
    return {"encrypted_params": base64.b64encode(completed.stdout).decode()}


def credentials() -> dict[str, str]:
    if MANIFEST.exists():
        value = json.loads(MANIFEST.read_text())
    else:
        value = {
            "username": secrets.token_hex(16),
            "password": secrets.token_urlsafe(12),
        }
        temporary = MANIFEST.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, MANIFEST)
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise RuntimeError("Nginx UI administrator manifest malformed")
    return value


def login(value: dict[str, str]) -> str:
    status, document = request(
        "POST",
        "/api/login",
        encrypted({"name": value["username"], "password": value["password"]}),
    )
    token = document.get("token")
    if (
        status != 200
        or document.get("code") != 200
        or not isinstance(token, str)
        or not token
    ):
        raise RuntimeError("Nginx UI administrator login failed")
    return token


def main() -> None:
    if len(sys.argv) != 1:
        raise RuntimeError("invalid Nginx UI provisioning arguments")
    value = credentials()
    status, install = request("GET", "/api/install")
    if status != 200:
        raise RuntimeError("Nginx UI install status failed")
    if install.get("lock") is False:
        status, _ = request(
            "POST",
            "/api/install",
            encrypted(
                {
                    "email": value["username"] + "@example.invalid",
                    "username": value["username"],
                    "password": value["password"],
                }
            ),
        )
        if status != 200:
            raise RuntimeError("Nginx UI native installation failed")
    login(value)


if __name__ == "__main__":
    main()
