"""Small standard-library client for Openfire's supported admin workflows."""

from __future__ import annotations

import http.client
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass


class OpenfireError(RuntimeError):
    """Raised when Openfire does not complete the requested workflow."""


@dataclass(frozen=True)
class Response:
    status: int
    path: str
    body: bytes


class WebSession:
    def __init__(self, base_url: str):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("Openfire admin URL must use HTTP")
        self.host = parsed.hostname
        self.port = parsed.port or 80
        self.cookies: dict[str, str] = {}

    def csrf(self) -> str:
        try:
            return self.cookies["csrf"]
        except KeyError as exc:
            raise OpenfireError("Openfire did not issue a CSRF cookie") from exc

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        *,
        follow: bool = False,
        timeout: float = 20.0,
    ) -> Response:
        current_method = method
        current_path = path
        current_body = body
        current_headers = dict(headers or {})
        for _ in range(8):
            request_headers = dict(current_headers)
            if self.cookies:
                request_headers["Cookie"] = "; ".join(
                    f"{name}={value}" for name, value in self.cookies.items()
                )
            connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
            try:
                connection.request(
                    current_method,
                    current_path,
                    body=current_body,
                    headers=request_headers,
                )
                response = connection.getresponse()
                payload = response.read()
                for raw in response.headers.get_all("Set-Cookie", []):
                    pair = raw.split(";", 1)[0]
                    if "=" in pair:
                        name, value = pair.split("=", 1)
                        self.cookies[name] = value
                location = response.getheader("Location")
                status = response.status
            finally:
                connection.close()
            if not follow or status not in (301, 302, 303, 307, 308) or not location:
                return Response(status, current_path, payload)
            parsed = urllib.parse.urlsplit(location)
            current_path = parsed.path or "/"
            if parsed.query:
                current_path += "?" + parsed.query
            if status in (301, 302, 303):
                current_method = "GET"
                current_body = None
                current_headers = {}
        raise OpenfireError("too many Openfire redirects")

    def form(
        self, path: str, fields: dict[str, str], *, follow: bool = True
    ) -> Response:
        body = urllib.parse.urlencode(fields).encode()
        return self.request(
            "POST",
            path,
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
            follow=follow,
        )

    def upload(self, path: str, filename: str, payload: bytes) -> Response:
        boundary = "----arena" + secrets.token_hex(16)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="uploadfile"; filename="{filename}"\r\n'
            "Content-Type: application/x-java-archive\r\n\r\n"
        ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
        return self.request(
            "POST",
            path,
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
            follow=True,
        )


def wait_http(base_url: str, path: str = "/login.jsp", timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    last = "not attempted"
    while time.monotonic() < deadline:
        try:
            response = WebSession(base_url).request("GET", path, timeout=5)
            last = f"HTTP {response.status}"
            if response.status == 200:
                return
        except (OSError, OpenfireError) as exc:
            last = type(exc).__name__
        time.sleep(1)
    raise OpenfireError(f"Openfire did not become ready: {last}")


def setup_openfire(base_url: str) -> None:
    session = WebSession(base_url)
    response = session.request("GET", "/setup/index.jsp")
    if response.status != 200:
        raise OpenfireError(f"setup index returned HTTP {response.status}")
    body = response.body.decode("utf-8", "replace")
    match = re.search(r'name="csrf" value="([^"]+)"', body)
    if not match:
        raise OpenfireError("setup index lacked its CSRF field")
    response = session.request(
        "GET",
        "/setup/index.jsp?"
        + urllib.parse.urlencode(
            {"csrf": match.group(1), "localeCode": "en", "save": "Continue"}
        ),
        follow=True,
    )
    if not response.path.endswith("/setup/setup-host-settings.jsp"):
        raise OpenfireError("setup did not reach host settings")

    body = response.body.decode("utf-8", "replace")
    match = re.search(r'name="csrf" value="([^"]+)"', body)
    if not match:
        raise OpenfireError("host settings lacked its CSRF field")
    response = session.form(
        "/setup/setup-host-settings.jsp",
        {
            "csrf": match.group(1),
            "domain": "openfire.test",
            "fqdn": "openfire.test",
            "embeddedPort": "9090",
            "securePort": "9091",
            "encryptionAlgorithm": "Blowfish",
            "encryptionKey": "arena-openfire-key",
            "encryptionKey1": "arena-openfire-key",
            "continue": "Continue",
        },
    )
    if not response.path.endswith("/setup/setup-datasource-settings.jsp"):
        raise OpenfireError("setup did not reach data-source settings")

    response = session.request("GET", "/setup/setup-datasource-settings.jsp")
    body = response.body.decode("utf-8", "replace")
    match = re.search(r'name="csrf" value="([^"]+)"', body)
    if not match:
        raise OpenfireError("data-source settings lacked its CSRF field")
    response = session.request(
        "GET",
        "/setup/setup-datasource-settings.jsp?"
        + urllib.parse.urlencode(
            {
                "csrf": match.group(1),
                "next": "true",
                "mode": "embedded",
                "continue": "Continue",
            }
        ),
        follow=True,
    )
    if not response.path.endswith("/setup/setup-profile-settings.jsp"):
        raise OpenfireError("setup did not reach profile settings")

    response = session.form(
        "/setup/setup-profile-settings.jsp",
        {"mode": "default", "continue": "Continue"},
    )
    if not response.path.endswith("/setup/setup-admin-settings.jsp"):
        raise OpenfireError("setup did not reach administrator settings")
    response = session.form(
        "/setup/setup-admin-settings.jsp",
        {"doSkip": "Skip This Step"},
    )
    if not response.path.endswith("/setup/setup-finished.jsp"):
        raise OpenfireError(f"Openfire setup did not finish: {response.path}")


def login(base_url: str, username: str, password: str) -> WebSession:
    session = WebSession(base_url)
    response = session.request("GET", "/login.jsp")
    if response.status != 200:
        raise OpenfireError(f"login page returned HTTP {response.status}")
    response = session.form(
        "/login.jsp",
        {
            "url": "/index.jsp",
            "login": "true",
            "csrf": session.csrf(),
            "username": username,
            "password": password,
        },
    )
    text = response.body.decode("utf-8", "replace")
    if not response.path.endswith("/index.jsp") or f"<strong>{username}</strong>" not in text:
        raise OpenfireError("Openfire administrator login failed")
    return session


def ensure_user(session: WebSession, username: str, password: str, name: str) -> None:
    summary = session.request("GET", "/user-summary.jsp")
    if summary.status != 200:
        raise OpenfireError("user summary unavailable")
    exists = f"username={urllib.parse.quote(username)}".encode() in summary.body
    if exists:
        page = session.request(
            "GET", "/user-password.jsp?" + urllib.parse.urlencode({"username": username})
        )
        if page.status != 200:
            raise OpenfireError("existing user password page unavailable")
        response = session.form(
            "/user-password.jsp",
            {
                "csrf": session.csrf(),
                "username": username,
                "password": password,
                "passwordConfirm": password,
                "update": "Update Password",
            },
        )
        if "success=true" not in response.path:
            raise OpenfireError("existing user password update failed")
        return
    page = session.request("GET", "/user-create.jsp")
    if page.status != 200:
        raise OpenfireError("user creation page unavailable")
    query = urllib.parse.urlencode(
        {
            "csrf": session.csrf(),
            "username": username,
            "name": name,
            "email": f"{username}@example.test",
            "password": password,
            "passwordConfirm": password,
            "create": "Create User",
        }
    )
    response = session.request("GET", "/user-create.jsp?" + query, follow=True)
    if "success=true" not in response.path or f"username={username}" not in response.path:
        raise OpenfireError(f"creating Openfire user {username} failed")


def delete_user(session: WebSession, username: str) -> None:
    page = session.request(
        "GET", "/user-delete.jsp?" + urllib.parse.urlencode({"username": username})
    )
    if page.status != 200:
        return
    response = session.request(
        "GET",
        "/user-delete.jsp?"
        + urllib.parse.urlencode(
            {
                "csrf": session.csrf(),
                "username": username,
                "delete": "Delete User",
            }
        ),
        follow=True,
    )
    if "deletesuccess=true" not in response.path:
        raise OpenfireError(f"deleting Openfire user {username} failed")


def upload_plugin(session: WebSession, filename: str, payload: bytes) -> None:
    page = session.request("GET", "/plugin-admin.jsp")
    if page.status != 200:
        raise OpenfireError("plugin administration unavailable")
    response = session.upload(
        "/plugin-admin.jsp?uploadplugin&csrf=" + urllib.parse.quote(session.csrf()),
        filename,
        payload,
    )
    if "uploadsuccess=true" not in response.path:
        raise OpenfireError("Openfire plugin upload failed")


def delete_plugin(session: WebSession, canonical_name: str) -> None:
    page = session.request("GET", "/plugin-admin.jsp")
    if page.status != 200:
        raise OpenfireError("plugin administration unavailable")
    response = session.request(
        "GET",
        "/plugin-admin.jsp?"
        + urllib.parse.urlencode(
            {"csrf": session.csrf(), "deleteplugin": canonical_name}
        ),
        follow=True,
    )
    if "deletesuccess=true" not in response.path:
        raise OpenfireError(f"deleting Openfire plugin {canonical_name} failed")
