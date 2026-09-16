"""Small stdlib Gradio HTTP client shared by the checker and PoV."""

from __future__ import annotations

import http.client
import json
import secrets
import urllib.parse


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20,
) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        connection.close()


def login(host: str, port: int, username: str, password: str) -> str:
    body = urllib.parse.urlencode(
        {"username": username, "password": password}
    ).encode()
    status, headers, _ = request(
        host,
        port,
        "POST",
        "/login",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    cookies = [
        value.split(";", 1)[0]
        for key, value in headers
        if key.lower() == "set-cookie"
    ]
    if status != 200 or not cookies:
        raise RuntimeError(f"Gradio login returned HTTP {status}")
    return "; ".join(cookies)


def json_request(
    host: str,
    port: int,
    method: str,
    path: str,
    payload: object,
    cookie: str,
) -> tuple[int, object, bytes]:
    status, _, raw = request(
        host,
        port,
        method,
        path,
        body=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "Cookie": cookie},
    )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        document = None
    return status, document, raw


def config(host: str, port: int, cookie: str) -> dict:
    status, _, raw = request(
        host, port, "GET", "/config", headers={"Cookie": cookie}
    )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Gradio configuration was malformed") from error
    if status != 200 or not isinstance(document, dict):
        raise RuntimeError(f"Gradio configuration returned HTTP {status}")
    return document


def component_id(document: dict, component_type: str) -> int:
    for row in document.get("components", []):
        if (
            isinstance(row, dict)
            and row.get("type") == component_type
            and isinstance(row.get("id"), int)
        ):
            return row["id"]
    raise RuntimeError(f"Gradio omitted its {component_type} component")


def reverse(host: str, port: int, cookie: str, value: str) -> str:
    status, document, _ = json_request(
        host,
        port,
        "POST",
        "/run/predict",
        {"data": [value], "fn_index": 0, "session_hash": secrets.token_hex(8)},
        cookie,
    )
    data = document.get("data") if isinstance(document, dict) else None
    if status != 200 or not isinstance(data, list) or not data:
        raise RuntimeError(f"Gradio reverse workflow returned HTTP {status}")
    result = data[0]
    if not isinstance(result, str):
        raise RuntimeError("Gradio reverse workflow returned malformed output")
    return result


def publish(
    host: str, port: int, cookie: str, name: str, content: str
) -> str:
    status, document, _ = json_request(
        host,
        port,
        "POST",
        "/run/predict",
        {
            "data": [name, content],
            "fn_index": 1,
            "session_hash": secrets.token_hex(8),
        },
        cookie,
    )
    data = document.get("data") if isinstance(document, dict) else None
    if status != 200 or not isinstance(data, list) or not data:
        raise RuntimeError(f"Gradio publish workflow returned HTTP {status}")
    result = data[0]
    if not isinstance(result, str):
        raise RuntimeError("Gradio publish workflow returned malformed output")
    return result


def upload(
    host: str, port: int, cookie: str, filename: str, content: bytes
) -> str:
    boundary = "----arena" + secrets.token_hex(16)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    status, _, raw = request(
        host,
        port,
        "POST",
        "/upload",
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": cookie,
        },
    )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Gradio upload returned malformed JSON") from error
    if (
        status != 200
        or not isinstance(document, list)
        or len(document) != 1
        or not isinstance(document[0], str)
    ):
        raise RuntimeError(f"Gradio upload returned HTTP {status}")
    return document[0]


def file_read(host: str, port: int, cookie: str, path: str) -> tuple[int, bytes]:
    status, _, raw = request(
        host,
        port,
        "GET",
        "/file=" + urllib.parse.quote(path, safe="/"),
        headers={"Cookie": cookie},
    )
    return status, raw
