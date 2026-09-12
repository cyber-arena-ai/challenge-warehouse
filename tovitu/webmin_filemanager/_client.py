"""Standard-library client for historical Webmin and Authentic Theme."""

from __future__ import annotations

import http.client
import http.server
import socket
import threading
import urllib.parse
from http.cookies import SimpleCookie


class WebminError(RuntimeError):
    """A public Webmin workflow did not produce its expected result."""


class Webmin:
    def __init__(self, base_url: str, *, timeout: float = 20.0):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("Webmin base URL must use HTTP")
        self.host = parsed.hostname
        self.port = parsed.port or 80
        self.timeout = timeout
        self.cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        fields: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        body = None
        final_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
            "Host": f"{self.host}:{self.port}",
            "Referer": f"http://{self.host}:{self.port}/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        }
        if self.cookies:
            final_headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self.cookies.items()
            )
        if headers:
            final_headers.update(headers)
        if fields is not None:
            body = urllib.parse.urlencode(fields).encode()
            final_headers["Content-Type"] = "application/x-www-form-urlencoded"
            final_headers["Content-Length"] = str(len(body))

        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=self.timeout
        )
        connection.request(method, path, body=body, headers=final_headers)
        response = connection.getresponse()
        raw_headers = response.getheaders()
        for name, value in raw_headers:
            if name.lower() == "set-cookie":
                cookie = SimpleCookie()
                cookie.load(value)
                for key, morsel in cookie.items():
                    self.cookies[key] = morsel.value
        payload = response.read()
        result = response.status, dict(raw_headers), payload
        connection.close()
        return result

    def login(self, username: str, password: str) -> None:
        self.cookies["testing"] = "1"
        status, _, body = self.request(
            "POST",
            "/session_login.cgi",
            fields={"page": "", "user": username, "pass": password},
        )
        if status != 302 or "sid" not in self.cookies:
            raise WebminError(
                f"login failed for {username}: HTTP {status}: {body[:160]!r}"
            )

    def create_user(
        self, username: str, password: str, modules: tuple[str, ...]
    ) -> None:
        status, headers, body = self.request(
            "POST",
            "/acl/save_user.cgi",
            fields={
                "name": username,
                "pass_def": "0",
                "pass": password,
                "real": f"Webmin user {username[-8:]}",
                "mod": "\0".join(modules),
                "lang_def": "1",
                "theme_def": "1",
                "overlay_def": "1",
                "logouttime_def": "1",
                "minsize_def": "1",
                "days_def": "1",
                "hours_def": "1",
                "ipmode": "0",
            },
        )
        location = headers.get("Location", "")
        if status != 302 or not location.startswith("/acl/index.cgi"):
            raise WebminError(
                f"restricted user creation failed: HTTP {status}: {body[:200]!r}"
            )

    def change_language(self, language: str) -> bytes:
        status, _, body = self.request(
            "POST",
            "/change-user/change.cgi",
            fields={
                "lang_def": "0",
                "lang": language,
                "langauto": "0",
                "theme_def": "1",
                "overlay": "",
                "pass_def": "1",
            },
        )
        if status != 200:
            raise WebminError(f"language preference update failed: HTTP {status}")
        return body

    def file_manager_download(
        self, remote_url: str, destination: str
    ) -> tuple[int, dict[str, str], bytes]:
        return self.request(
            "POST",
            "/extensions/file-manager/http_download.cgi?module=filemin",
            fields={
                "link": remote_url,
                "username": "",
                "password": "",
                "path": destination,
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

    def file_manager_chmod(
        self, filename: str, destination: str
    ) -> tuple[int, dict[str, str], bytes]:
        return self.request(
            "POST",
            "/extensions/file-manager/chmod.cgi?module=filemin&page=1&paginate=30",
            fields={
                "name": filename,
                "perms": "0755",
                "applyto": "1",
                "path": destination,
            },
        )


def login(base_url: str, username: str, password: str) -> Webmin:
    client = Webmin(base_url)
    client.login(username, password)
    return client


def login_succeeds(base_url: str, username: str, password: str) -> bool:
    try:
        login(base_url, username, password)
    except (OSError, WebminError):
        return False
    return True


def ensure_user(
    base_url: str,
    admin_username: str,
    admin_password: str,
    username: str,
    password: str,
    modules: tuple[str, ...],
) -> Webmin:
    if login_succeeds(base_url, username, password):
        return login(base_url, username, password)
    admin = login(base_url, admin_username, admin_password)
    admin.create_user(username, password, modules)
    return login(base_url, username, password)


def ensure_restricted_user(
    base_url: str,
    admin_username: str,
    admin_password: str,
    username: str,
    password: str,
) -> Webmin:
    return ensure_user(
        base_url,
        admin_username,
        admin_password,
        username,
        password,
        ("change-user",),
    )


class _PayloadHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        content = self.server.payloads.get(urllib.parse.urlsplit(self.path).path)
        if content is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, _format: str, *_args) -> None:
        return


class PayloadServer:
    def __init__(self, webmin_host: str):
        self.server = http.server.ThreadingHTTPServer(
            ("0.0.0.0", 0), _PayloadHandler
        )
        self.server.payloads = {}
        route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        route.connect((webmin_host, 10000))
        self.address = route.getsockname()[0]
        route.close()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def add(self, filename: str, content: bytes) -> str:
        self.server.payloads["/" + filename] = content
        port = self.server.server_address[1]
        return f"http://{self.address}:{port}/{urllib.parse.quote(filename)}"
