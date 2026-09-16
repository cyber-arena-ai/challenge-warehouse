"""Small stdlib client for Airflow's public and administration APIs."""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def ordinary_user_agent() -> str:
    """Return a fresh browser-shaped fingerprint shared by all native clients."""
    platform = secrets.choice(
        (
            "X11; Linux x86_64",
            "Macintosh; Intel Mac OS X 10_15_7",
            "Windows NT 10.0; Win64; x64",
        )
    )
    if secrets.randbelow(2) == 0:
        major = secrets.randbelow(12) + 124
        return (
            f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36"
        )
    major = secrets.randbelow(12) + 124
    return f"Mozilla/5.0 ({platform}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"


class AirflowClient:
    def __init__(
        self,
        base: str,
        username: str,
        password: str,
        *,
        user_agent: str | None = None,
    ) -> None:
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.user_agent = user_agent or ordinary_user_agent()
        self._token: str | None = None

    def request(
        self,
        method: str,
        path: str,
        *,
        body: object | None = None,
        timeout: float = 15,
    ) -> tuple[int | None, object]:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            return response.status, _decode(raw)
        except urllib.error.HTTPError as error:
            return error.code, _decode(error.read())
        except OSError as error:
            return None, type(error).__name__

    def login(self, *, timeout: float = 15) -> bool:
        status, document = self.request(
            "POST",
            "/auth/token",
            body={"username": self.username, "password": self.password},
            timeout=timeout,
        )
        if status not in (200, 201) or not isinstance(document, dict):
            return False
        token = document.get("access_token")
        if not isinstance(token, str) or not token:
            return False
        self._token = token
        return True

    def create_user(
        self,
        username: str,
        password: str,
        *,
        role: str = "Op",
    ) -> tuple[int | None, object]:
        return self.request(
            "POST",
            "/auth/fab/v1/users",
            body={
                "username": username,
                "email": f"{username}@users.invalid",
                "first_name": "Service",
                "last_name": "Member",
                "roles": [{"name": role}],
                "password": password,
            },
        )

    def get_user(self, username: str) -> tuple[int | None, object]:
        return self.request(
            "GET", "/auth/fab/v1/users/" + urllib.parse.quote(username)
        )

    def delete_user(self, username: str) -> tuple[int | None, object]:
        return self.request(
            "DELETE", "/auth/fab/v1/users/" + urllib.parse.quote(username)
        )

    def get_variable(self, key: str) -> tuple[int | None, object]:
        return self.request("GET", "/api/v2/variables/" + urllib.parse.quote(key))

    def list_variables(self, pattern: str) -> tuple[int | None, object]:
        query = urllib.parse.urlencode(
            {"variable_key_pattern": pattern, "limit": 20}
        )
        return self.request("GET", "/api/v2/variables?" + query)

    def create_variable(self, document: dict[str, str]) -> tuple[int | None, object]:
        return self.request("POST", "/api/v2/variables", body=document)

    def update_variable(self, key: str, document: dict[str, str]) -> tuple[int | None, object]:
        return self.request(
            "PATCH",
            "/api/v2/variables/" + urllib.parse.quote(key),
            body=document,
        )

    def delete_variable(self, key: str) -> tuple[int | None, object]:
        return self.request("DELETE", "/api/v2/variables/" + urllib.parse.quote(key))


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode(errors="replace")
