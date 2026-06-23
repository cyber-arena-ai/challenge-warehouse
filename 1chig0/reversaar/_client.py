"""HTTP client for reversaar (the saarCTF 2024 C CGI reversing service, port 7331).

The service is a plain-CGI binary behind nginx+fcgiwrap. Auth is a `Session`
cookie = base64(HMAC_SHA256(secret_key, username) || username); `/api/login`
(POST JSON {username,password}) registers-or-logs-in and Set-Cookie's it.

A subtlety the handlers MUST respect: the Session token base64 frequently ends
in `==`, and naively re-passing it through a fresh httpx `cookies=` argument can
mangle it. We therefore always send auth as an explicit `Cookie:` header. The
reversing endpoints (`/api/array/new` etc.) store the body REVERSED, and GET
`/api/<type>/<idx>` 302-redirects to a static `/userdata/<uuid>` blob.
"""
from __future__ import annotations

import base64
import logging

import httpx

log = logging.getLogger(__name__)

PORT = 7331
_TIMEOUT = 10.0


class ClientError(Exception):
    """Protocol-level failure (login rejected / unexpected response)."""


def base_url(ip: str) -> str:
    return f"http://{ip}:{PORT}"


def new_client() -> httpx.Client:
    return httpx.Client(timeout=_TIMEOUT)


def ping(ip: str) -> bool:
    """True if the web root answers 200."""
    try:
        with new_client() as c:
            return c.get(base_url(ip) + "/").status_code == 200
    except httpx.HTTPError:
        return False


def login(c: httpx.Client, ip: str, username: str, password: str) -> str:
    """Register-or-login `username`; return the raw Session token. Raises
    ClientError on rejection. Uses the normal credential flow (NOT a forged
    cookie), so it keeps working after a defender rotates the key / drops the
    backdoor."""
    r = c.post(base_url(ip) + "/api/login", json={"username": username, "password": password})
    if r.status_code != 200:
        raise ClientError(f"login {username}: HTTP {r.status_code}")
    token = r.cookies.get("Session")
    if not token:
        raise ClientError(f"login {username}: no Session cookie")
    return token


def _auth(token: str) -> dict:
    return {"Cookie": f"Session={token}"}


def store_array(c: httpx.Client, ip: str, token: str, data: bytes) -> int:
    """POST raw bytes to /api/array/new (base64 transfer-encoded); return the id.
    The service stores the array REVERSED."""
    r = c.post(
        base_url(ip) + "/api/array/new",
        content=base64.b64encode(data),
        headers={
            **_auth(token),
            "Content-Type": "application/octet-stream",
            "Content-Transfer-Encoding": "base64",
        },
    )
    if r.status_code != 200:
        raise ClientError(f"store_array: HTTP {r.status_code}")
    try:
        return int(r.json()["id"])
    except Exception as e:  # noqa: BLE001
        raise ClientError(f"store_array: bad response {r.text[:80]!r}") from e


def get_array(c: httpx.Client, ip: str, token: str, idx: int) -> bytes:
    """GET /api/array/<idx> (follows the 302 to /userdata) and base64-decode the
    stored (reversed) blob back to raw bytes."""
    r = c.get(base_url(ip) + f"/api/array/{idx}", headers=_auth(token), follow_redirects=True)
    if r.status_code != 200:
        raise ClientError(f"get_array {idx}: HTTP {r.status_code}")
    try:
        return base64.b64decode(r.content)
    except Exception as e:  # noqa: BLE001
        raise ClientError(f"get_array {idx}: bad base64 {r.content[:40]!r}") from e


def store_text(c: httpx.Client, ip: str, token: str, data: bytes) -> int:
    r = c.post(base_url(ip) + "/api/text/new", content=data, headers=_auth(token))
    if r.status_code != 200:
        raise ClientError(f"store_text: HTTP {r.status_code}")
    try:
        return int(r.json()["id"])
    except Exception as e:  # noqa: BLE001
        raise ClientError(f"store_text: bad response {r.text[:80]!r}") from e


def get_text(c: httpx.Client, ip: str, token: str, idx: int) -> bytes:
    r = c.get(base_url(ip) + f"/api/text/{idx}", headers=_auth(token), follow_redirects=True)
    if r.status_code != 200:
        raise ClientError(f"get_text {idx}: HTTP {r.status_code}")
    return r.content
