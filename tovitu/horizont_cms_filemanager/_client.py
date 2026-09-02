"""Standard-library client for HorizontCMS authentication and FileManager."""

from __future__ import annotations

import http.cookiejar
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)


class HorizontError(RuntimeError):
    """A public HorizontCMS workflow did not produce its expected result."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Session:
    def __init__(self, base_url: str, *, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )
        self._no_redirect = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar), _NoRedirect()
        )

    def request(
        self,
        path: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        *,
        redirects: bool = True,
    ) -> tuple[int, str, dict[str, str], bytes]:
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"User-Agent": DEFAULT_USER_AGENT, **(headers or {})},
        )
        opener = self._opener if redirects else self._no_redirect
        try:
            with opener.open(request, timeout=self.timeout) as response:
                return (
                    response.status,
                    response.geturl(),
                    dict(response.headers),
                    response.read(),
                )
        except urllib.error.HTTPError as exc:
            return exc.code, exc.geturl(), dict(exc.headers), exc.read()

    def get(self, path: str) -> tuple[int, str, dict[str, str], bytes]:
        return self.request(path)

    def form(
        self, path: str, values: dict[str, str], *, redirects: bool = True
    ) -> tuple[int, str, dict[str, str], bytes]:
        return self.request(
            path,
            urllib.parse.urlencode(values).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
            redirects=redirects,
        )

    def multipart(
        self,
        path: str,
        fields: dict[str, str],
        filename: str,
        content_type: str,
        content: bytes,
    ) -> tuple[int, str, dict[str, str], bytes]:
        boundary = "----WebKitFormBoundary" + secrets.token_hex(12)
        parts: list[bytes] = []
        for name, value in fields.items():
            parts.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                    value.encode(),
                    b"\r\n",
                ]
            )
        parts.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="up_file[]"; filename="{filename}"\r\n'.encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                content,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            ]
        )
        return self.request(
            path,
            b"".join(parts),
            {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "X-Requested-With": "XMLHttpRequest",
            },
        )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise HorizontError(message)


def csrf(body: bytes) -> str:
    for pattern in (
        rb'<meta name="csrf-token" content="([^"]+)"',
        rb'name="_token" value="([^"]+)"',
    ):
        match = re.search(pattern, body)
        if match:
            return match.group(1).decode()
    raise HorizontError("CSRF token absent")


def login(base_url: str, username: str, password: str) -> Session:
    session = Session(base_url)
    status, _, _, page = session.get("/admin/login")
    _require(status == 200, f"login page HTTP {status}")
    status, final_url, _, _ = session.form(
        "/admin/login",
        {
            "_token": csrf(page),
            "username": username,
            "password": password,
            "submit_login": "login",
        },
    )
    _require(
        status == 200 and final_url.endswith("/admin/dashboard"),
        "login rejected",
    )
    return session


def login_succeeds(base_url: str, username: str, password: str) -> bool:
    try:
        login(base_url, username, password)
    except (HorizontError, OSError, urllib.error.URLError):
        return False
    return True


def ensure_editor(
    base_url: str,
    admin_username: str,
    admin_password: str,
    username: str,
    password: str,
    label: str,
) -> Session:
    if login_succeeds(base_url, username, password):
        return login(base_url, username, password)

    admin = login(base_url, admin_username, admin_password)
    status, _, _, page = admin.get("/admin/user/create")
    _require(status == 200, f"create-user page HTTP {status}")
    status, _, headers, _ = admin.form(
        "/admin/user/create",
        {
            "_token": csrf(page),
            "name": label,
            "username": username,
            "password": password,
            "password2": password,
            "email": f"{username}@arena.invalid",
            "role_id": "4",
        },
        redirects=False,
    )
    location = headers.get("Location", "")
    _require(
        status in {301, 302, 303} and "/admin/user/edit/" in location,
        f"Editor creation failed: HTTP {status}",
    )
    return login(base_url, username, password)


def file_manager(session: Session) -> tuple[str, bytes]:
    status, _, _, page = session.get("/admin/file-manager/index")
    _require(status == 200 and b"filemanager" in page.lower(), "FileManager unavailable")
    return csrf(page), page


def upload(
    session: Session,
    token: str,
    filename: str,
    content_type: str,
    content: bytes,
) -> str:
    status, _, _, body = session.multipart(
        "/admin/file-manager/fileupload",
        {"_token": token, "dir_path": ""},
        filename,
        content_type,
        content,
    )
    try:
        names = json.loads(body).get("uploadedFileNames") or []
    except (json.JSONDecodeError, AttributeError):
        names = []
    _require(status == 200 and len(names) == 1, f"upload failed: HTTP {status}")
    return str(names[0])


def rename(session: Session, token: str, old_name: str, new_name: str) -> None:
    status, _, _, _ = session.form(
        "/admin/file-manager/rename",
        {
            "_token": token,
            "old_file": "/" + old_name.lstrip("/"),
            "new_file": "/" + new_name.lstrip("/"),
        },
    )
    _require(status == 200, f"rename failed: HTTP {status}")


def exercise_filemanager(session: Session, content: bytes, destination: str) -> None:
    token, _ = file_manager(session)
    source = secrets.token_hex(12) + ".txt"
    stored = upload(session, token, source, "text/plain", content)
    rename(session, token, stored, destination)
    status, _, _, received = session.get("/storage/" + destination)
    _require(status == 200 and received == content, "renamed content did not round-trip")
