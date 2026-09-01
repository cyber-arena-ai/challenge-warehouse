"""Standard-library client for ProjectSend's supported workflows."""

from __future__ import annotations

import email.utils
import hashlib
import http.cookiejar
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request


class ProjectSendError(RuntimeError):
    pass


class Session:
    def __init__(self, base_url: str, *, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(
        self,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            urllib.parse.urljoin(self.base_url, path),
            data=data,
            headers=headers or {},
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def form(
        self, path: str, values: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        return self.request(
            path,
            data=urllib.parse.urlencode(values).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProjectSendError(message)


def csrf(session: Session) -> str:
    status, _, body = session.request("index.php")
    match = re.search(rb'name="csrf_token" value="([a-f0-9]+)"', body)
    _require(status == 200 and match is not None, "CSRF token unavailable")
    return match.group(1).decode()


def login(base_url: str, username: str, password: str) -> Session:
    session = Session(base_url)
    status, _, body = session.form(
        "index.php",
        {
            "csrf_token": csrf(session),
            "do": "login",
            "username": username,
            "password": password,
        },
    )
    _require(status == 200 and b'id="login_form"' not in body, "login rejected")
    return session


def public_title(base_url: str) -> str:
    status, _, body = Session(base_url).request("index.php")
    match = re.search(rb"<title>.*?&raquo;\s+(.*?)</title>", body)
    _require(status == 200 and match is not None, "public title unavailable")
    return match.group(1).decode("utf-8", "replace")


def admin_set_title(admin: Session, value: str) -> None:
    status, _, body = admin.request("options.php?section=general")
    match = re.search(
        rb'name="csrf_token" id="csrf_token" value="([a-f0-9]+)"', body
    )
    _require(status == 200 and match is not None, "options form unavailable")
    status, _, _ = admin.form(
        "options.php",
        {
            "csrf_token": match.group(1).decode(),
            "section": "general",
            "this_install_title": value,
        },
    )
    _require(status == 200, "authorized setting update failed")


def anonymous_set_title(base_url: str, value: str) -> int:
    session = Session(base_url)
    status, _, _ = session.form(
        "options.php",
        {
            "csrf_token": csrf(session),
            "section": "general",
            "this_install_title": value,
        },
    )
    return status


def ensure_client(
    admin: Session,
    base_url: str,
    username: str,
    password: str,
    label: str,
) -> None:
    try:
        login(base_url, username, password)
        return
    except ProjectSendError:
        pass
    status, _, body = admin.request("clients-add.php")
    match = re.search(
        rb'name="csrf_token" id="csrf_token" value="([a-f0-9]+)"', body
    )
    _require(status == 200 and match is not None, "client form unavailable")
    status, _, body = admin.form(
        "clients-add.php",
        {
            "csrf_token": match.group(1).decode(),
            "name": label,
            "username": username,
            "password": password,
            "email": f"{username}@example.invalid",
            "max_file_size": "0",
            "active": "1",
        },
    )
    _require(status == 200 and b"Edit client" in body, "client creation failed")
    login(base_url, username, password)


def ensure_system_user(
    admin: Session,
    base_url: str,
    username: str,
    password: str,
    label: str,
) -> None:
    try:
        login(base_url, username, password)
        return
    except ProjectSendError:
        pass
    status, _, body = admin.request("users-add.php")
    match = re.search(
        rb'name="csrf_token" id="csrf_token" value="([a-f0-9]+)"', body
    )
    _require(status == 200 and match is not None, "system-user form unavailable")
    status, _, _ = admin.form(
        "users-add.php",
        {
            "csrf_token": match.group(1).decode(),
            "name": label,
            "username": username,
            "password": password,
            "email": f"{username}@example.invalid",
            "level": "9",
            "max_file_size": "0",
            "active": "1",
        },
    )
    _require(status == 200, "system-user creation failed")
    login(base_url, username, password)


def _multipart(filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----arena-projectsend-" + secrets.token_hex(8)
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="name"\r\n\r\n'
        f"{filename}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def upload(session: Session, filename: str, content: bytes) -> float:
    payload, content_type = _multipart(filename, content)
    status, headers, body = session.request(
        "includes/upload.process.php",
        data=payload,
        headers={"Content-Type": content_type},
    )
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ProjectSendError("upload returned non-JSON") from exc
    _require(status == 200 and parsed.get("OK") == 1, "upload rejected")
    return email.utils.parsedate_to_datetime(headers["Date"]).timestamp()


def locate_upload(
    base_url: str,
    username: str,
    uploaded_at: float,
    filename: str,
    expected: bytes,
) -> str:
    user_hash = hashlib.sha1(username.encode()).hexdigest()
    offsets = [0]
    for hours in range(1, 15):
        offsets.extend((hours * 3600, -hours * 3600))
    for offset in offsets:
        path = f"upload/files/{int(uploaded_at + offset)}-{user_hash}-{filename}"
        status, _, body = Session(base_url).request(path)
        if status == 200 and body == expected:
            return path
    raise ProjectSendError("uploaded file not publicly retrievable")


def file_is_listed(session: Session, filename: str) -> bool:
    status, _, body = session.request("my_files/index.php")
    return status == 200 and filename.encode() in body
