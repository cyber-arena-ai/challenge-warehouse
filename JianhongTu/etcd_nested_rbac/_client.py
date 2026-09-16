"""Small stdlib client for etcd's native v3 JSON gateway."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from challenges.interface import VulboxTarget


def target_base(target: VulboxTarget) -> str:
    return f"http://{target.host}:{target.ports['service']}"


def b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def unb64(value: str) -> str:
    return base64.b64decode(value, validate=True).decode()


def request(
    base: str,
    path: str,
    payload: dict[str, Any],
    *,
    token: str | None = None,
    timeout: int = 15,
) -> tuple[int, bytes]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = token
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def document(status: int, raw: bytes, operation: str) -> dict[str, Any]:
    try:
        value = json.loads(raw or b"{}")
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{operation} returned malformed JSON") from error
    if status != 200 or not isinstance(value, dict):
        raise RuntimeError(f"{operation} returned HTTP {status}")
    return value


def authenticate(base: str, username: str, password: str) -> str:
    status, raw = request(
        base,
        "/v3/auth/authenticate",
        {"name": username, "password": password},
    )
    response = document(status, raw, "authentication")
    token = response.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("authentication returned no token")
    return token


def range_key(
    base: str,
    token: str,
    key: str,
    *,
    range_end: str | None = None,
) -> tuple[int, bytes]:
    payload = {"key": b64(key)}
    if range_end is not None:
        payload["range_end"] = b64(range_end)
    return request(base, "/v3/kv/range", payload, token=token)


def put_key(base: str, token: str, key: str, value: str) -> tuple[int, bytes]:
    return request(
        base,
        "/v3/kv/put",
        {"key": b64(key), "value": b64(value)},
        token=token,
    )


def delete_key(base: str, token: str, key: str) -> tuple[int, bytes]:
    return request(
        base,
        "/v3/kv/deleterange",
        {"key": b64(key)},
        token=token,
    )


def encoded_values(node: object) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "value" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(encoded_values(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(encoded_values(value))
    return found


def decoded_values(raw: bytes) -> list[str]:
    try:
        node = json.loads(raw)
        return [unb64(value) for value in encoded_values(node)]
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("etcd returned malformed value data") from error
