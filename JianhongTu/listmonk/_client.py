"""Small standard-library Listmonk HTTP client shared by facility probes."""

from __future__ import annotations

import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from challenges.interface import VulboxTarget


ANALYST_ROLE = "Subscriber Data Analyst"
ANALYST_PERMISSIONS = ["subscribers:get_all", "subscribers:sql_query"]


def target_base(target: VulboxTarget) -> str:
    return f"http://{target.host}:{target.ports['service']}"


def request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
    username: str | None = None,
    token: str | None = None,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, bytes]:
    query = "?" + urllib.parse.urlencode(params) if params else ""
    headers: dict[str, str] = {}
    data = None
    if username is not None and token is not None:
        headers["Authorization"] = f"token {username}:{token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        base.rstrip("/") + path + query,
        data=data,
        headers=headers,
        method=method,
    )
    open_request = opener.open if opener is not None else urllib.request.urlopen
    try:
        with open_request(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def data_response(status: int, raw: bytes, operation: str) -> Any:
    try:
        document = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{operation} returned malformed JSON") from error
    if status != 200 or not isinstance(document, dict) or "data" not in document:
        raise RuntimeError(f"{operation} returned HTTP {status}")
    return document["data"]


class AdminClient:
    def __init__(self, base: str, token: str) -> None:
        self.base = base
        self.token = token

    def call(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> Any:
        status, raw = request(
            self.base,
            path,
            method=method,
            payload=payload,
            username="arena-admin-api",
            token=self.token,
        )
        return data_response(status, raw, f"{method} {path}")


def target_admin(target: VulboxTarget) -> AdminClient:
    exec_in = target.meta.get("exec_in_container")
    if exec_in is None:
        raise RuntimeError("no facility exec bridge")
    rc, out = exec_in(target.host, "cat /srv/listmonk/private/admin-api-token")
    token = (out or "").strip()
    if rc != 0 or len(token) < 24:
        raise RuntimeError("Listmonk bootstrap credential unavailable")
    return AdminClient(target_base(target), token)


def ensure_role(admin: AdminClient, name: str, permissions: list[str]) -> int:
    roles = admin.call("/api/roles/users")
    if not isinstance(roles, list):
        raise RuntimeError("Listmonk user-role listing was malformed")
    matches = [
        row for row in roles if isinstance(row, dict) and row.get("name") == name
    ]
    if len(matches) > 1:
        raise RuntimeError(f"duplicate Listmonk role {name!r}")
    payload = {
        "name": name,
        "type": "user",
        "permissions": permissions,
        "lists": [],
    }
    if matches:
        role_id = int(matches[0]["id"])
        admin.call(f"/api/roles/users/{role_id}", method="PUT", payload=payload)
        return role_id
    created = admin.call("/api/roles/users", method="POST", payload=payload)
    return int(created["id"])


def create_analyst_user(
    admin: AdminClient, role_id: int, profile: dict[str, str]
) -> int:
    """Create one ordinary restricted analyst through Listmonk administration."""
    created = admin.call(
        "/api/users",
        method="POST",
        payload={
            "username": profile["username"],
            "name": profile["name"],
            "type": "user",
            "status": "enabled",
            "password_login": True,
            "password": profile["password"],
            "user_role_id": role_id,
            "list_role_id": None,
            "email": profile["email"],
        },
    )
    return int(created["id"])


def session_login(base: str, username: str, password: str) -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    payload = urllib.parse.urlencode(
        {"username": username, "password": password, "next": "/admin/"}
    ).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/admin/login",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with opener.open(req, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"login returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"login returned HTTP {error.code}") from error
    if not any(cookie.name == "session" for cookie in jar):
        raise RuntimeError("login did not issue a session cookie")
    return opener
