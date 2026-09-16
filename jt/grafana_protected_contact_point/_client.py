"""Small stdlib Grafana HTTP client shared by checker and private PoV."""

from __future__ import annotations

import base64
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

_HTTP_PLATFORMS = (
    "X11; Linux x86_64",
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
)
_HTTP_ACCEPTS = (
    "*/*",
    "application/json, text/plain, */*",
    "application/json, */*;q=0.8",
)


def _ordinary_headers() -> dict[str, str]:
    major = 126 + secrets.randbelow(20)
    platform = secrets.choice(_HTTP_PLATFORMS)
    return {
        "Accept": secrets.choice(_HTTP_ACCEPTS),
        "User-Agent": (
            f"Mozilla/5.0 ({platform}; rv:{major}.0) "
            f"Gecko/20100101 Firefox/{major}.0"
        ),
    }


class GrafanaClient:
    def __init__(
        self, base: str, username: str = "", password: str = "", timeout: int = 20,
    ) -> None:
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout

    def request(
        self, method: str, path: str, document: object | None = None,
    ) -> tuple[int, bytes]:
        body = None if document is None else json.dumps(document).encode()
        headers = _ordinary_headers()
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.username:
            raw = f"{self.username}:{self.password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        request = urllib.request.Request(
            self.base + path, data=body, method=method, headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read(2_000_000)
        except urllib.error.HTTPError as error:
            return error.code, error.read(2_000_000)

    def json(
        self, method: str, path: str, document: object | None = None,
    ) -> tuple[int, object]:
        status, raw = self.request(method, path, document)
        try:
            return status, json.loads(raw or b"null")
        except ValueError:
            return status, None

    def health(self) -> bool:
        status, document = self.json("GET", "/api/health")
        return status == 200 and isinstance(document, dict) and document.get("database") == "ok"

    def contact_points(self) -> tuple[int, list[dict]]:
        status, document = self.json("GET", "/api/v1/provisioning/contact-points")
        rows = [row for row in document if isinstance(row, dict)] if isinstance(document, list) else []
        return status, rows

    def contact_point(self, uid: str) -> tuple[int, dict | None]:
        status, rows = self.contact_points()
        matches = [row for row in rows if row.get("uid") == uid]
        return status, matches[0] if len(matches) == 1 else None

    def update_contact_point(self, uid: str, document: dict) -> int:
        path = "/api/v1/provisioning/contact-points/" + urllib.parse.quote(uid, safe="")
        status, _ = self.request("PUT", path, document)
        return status


def update_document(contact: dict, *, name: str, url: str) -> dict:
    """Return the provisioning API's supported webhook update shape."""
    return {
        "uid": str(contact.get("uid") or ""),
        "name": name,
        "type": str(contact.get("type") or "webhook"),
        "disableResolveMessage": bool(contact.get("disableResolveMessage", False)),
        "settings": {"url": url},
    }
