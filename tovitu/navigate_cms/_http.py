"""Small stdlib Navigate HTTP client shared by trusted probes."""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None,
            opener: urllib.request.OpenerDirector | None = None, timeout: float = 15):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    client = opener or urllib.request.build_opener()
    try:
        return client.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return exc


def login(base: str, username: str, password: str):
    no_redirect = urllib.request.build_opener(_NoRedirect())
    form = urllib.parse.urlencode(
        {"login-username": username, "login-password": password}
    ).encode()
    response = request(
        f"{base}/login.php",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        opener=no_redirect,
    )
    response.read()
    cookies: dict[str, str] = {}
    for raw in response.headers.get_all("Set-Cookie", []):
        parsed = SimpleCookie()
        parsed.load(raw)
        cookies.update({name: morsel.value for name, morsel in parsed.items()})
    sessions = [
        (name, value) for name, value in cookies.items() if name.startswith("NVSID_")
    ]
    if response.status != 302 or len(sessions) != 1:
        raise RuntimeError("normal User login failed")
    session_name, session_id = sessions[0]
    # Docker service aliases contain underscores. The historical application
    # puts that alias in Domain=, which modern cookie policy rejects. Send the
    # exact application-issued session explicitly, as a browser on a normal DNS
    # hostname would do.
    opener = urllib.request.build_opener()
    opener.addheaders = [
        ("Cookie", f"{session_name}={session_id}; PHPSESSID={session_id}; navigate-session-id={session_id}")
    ]
    dashboard = request(f"{base}/navigate.php?fid=dashboard", opener=opener)
    dashboard_body = dashboard.read()
    if dashboard.status != 200 or b'id="navigate-content"' not in dashboard_body:
        raise RuntimeError("authenticated dashboard failed")
    return opener, session_id


def multipart(field: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----navigate-" + secrets.token_hex(12)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def ordinary_upload(base: str, session_id: str, filename: str, marker: bytes) -> None:
    body, content_type = multipart("upload", filename, marker)
    query = urllib.parse.urlencode({"session_id": session_id, "engine": "dropzone"})
    response = request(
        f"{base}/navigate_upload.php?{query}",
        data=body,
        headers={"Content-Type": content_type},
    )
    payload = response.read()
    if response.status != 200:
        raise RuntimeError("ordinary media upload failed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("ordinary media upload returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("filename") != filename
        or not str(value.get("temporal", "")).startswith("upload-")
    ):
        raise RuntimeError("ordinary media upload returned the wrong file")


def create_user(opener: urllib.request.OpenerDirector, base: str, username: str,
                password: str) -> None:
    form = urllib.parse.urlencode(
        {
            "form-sent": "true",
            "id": "",
            "user-username": username,
            "user-password": password,
            "user-email": f"{username}@arena.invalid",
            "user-profile": "2",
            "user-language": "en",
            "user-timezone": "UTC",
            "user-decimal_separator": ".",
            "user-thousands_separator": "",
            "user-date_format": "Y-m-d H:i",
            "user-skin": "cupertino",
            "user-blocked": "0",
            "user-all-websites": "1",
            "navigate_permissions_changes": "[]",
        }
    ).encode()
    response = request(
        f"{base}/navigate.php?fid=users&act=2",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        opener=opener,
    )
    response.read()
    if response.status not in {200, 302}:
        raise RuntimeError("supported User creation workflow failed")
