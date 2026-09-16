"""Small stdlib Navigate HTTP client shared by trusted probes."""

from __future__ import annotations

import gzip
import http.client
import json
import secrets
import string
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import CookieJar
from http.cookies import SimpleCookie


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _NoDefaultEncoding(http.client.HTTPConnection):
    """Keep `http.client` from supplying an `Accept-Encoding` of its own.

    It otherwise sends `identity` whenever the caller omits the header, which
    would put a fixed string on the wire for every request meant to carry none.
    A header the caller does supply is still sent, as an ordinary one.
    """

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        super().putrequest(method, url, skip_host=skip_host,
                           skip_accept_encoding=True)


class _PlainHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_NoDefaultEncoding, req)


class _Decoded:
    """A response whose compressed body has already been decoded."""

    def __init__(self, response, body: bytes):
        self._response = response
        self._body = body

    def read(self, *_args):
        body, self._body = self._body, b""
        return body

    def __getattr__(self, name):
        return getattr(self._response, name)


def _response_cookies(response):
    cookies = {}
    for raw in response.headers.get_all("Set-Cookie", []):
        parsed = SimpleCookie()
        parsed.load(raw)
        cookies.update(parsed)
    return cookies


def _is_persistent(cookie) -> bool:
    max_age = cookie["max-age"]
    if max_age:
        try:
            return int(max_age) > 0
        except ValueError:
            return False
    expires = cookie["expires"]
    if not expires:
        return False
    try:
        deadline = parsedate_to_datetime(expires)
    except (TypeError, ValueError):
        return False
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return deadline > datetime.now(timezone.utc)


def _remember_cookie_jar(response, url: str):
    cookies = _response_cookies(response)
    remembered = cookies.get("navigate-user")
    if not remembered or not _is_persistent(remembered):
        raise RuntimeError("remembered User login issued no persistent cookie")

    issued = CookieJar()
    issued.extract_cookies(response, urllib.request.Request(url))
    native = [cookie for cookie in issued if cookie.name == "navigate-user"]
    if len(native) != 1:
        raise RuntimeError("remembered User login issued an inapplicable cookie")

    resumed = CookieJar()
    resumed.set_cookie(native[0])
    probe = urllib.request.Request(url)
    resumed.add_cookie_header(probe)
    if probe.get_header("Cookie") != f"navigate-user={native[0].value}":
        raise RuntimeError("remembered User login issued an inapplicable cookie")
    return resumed


def opener_for(*handlers) -> urllib.request.OpenerDirector:
    """Build an opener that contributes no headers of its own.

    `urllib` otherwise fills in its own `User-Agent`, which would put a fixed
    string on the wire for every request whose caller deliberately left that
    header out.
    """
    opener = urllib.request.build_opener(_PlainHandler(), *handlers)
    opener.addheaders = []
    return opener


def request(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None,
            opener: urllib.request.OpenerDirector | None = None, timeout: float = 15):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    client = opener or opener_for()
    try:
        response = client.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    # `mod_deflate` compresses whenever the drawn Accept-Encoding offers gzip,
    # and every caller here matches on exact bytes.
    if response.headers.get("Content-Encoding", "").lower() != "gzip":
        return response
    return _Decoded(response, gzip.decompress(response.read()))


def login(
    base: str,
    username: str,
    password: str,
    *,
    headers: dict[str, str] | None = None,
    remember: bool = False,
):
    context_headers = dict(headers or {})
    no_redirect = opener_for(_NoRedirect())
    fields = {"login-username": username, "login-password": password}
    if remember:
        fields["login-remember"] = "1"
    form = urllib.parse.urlencode(fields).encode()
    response = request(
        f"{base}/login.php",
        data=form,
        headers={
            **context_headers,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        opener=no_redirect,
    )
    response.read()
    cookies = _response_cookies(response)
    sessions = [
        (name, cookie.value)
        for name, cookie in cookies.items()
        if name.startswith("NVSID_")
    ]
    if response.status != 302 or len(sessions) != 1:
        raise RuntimeError("normal User login failed")
    session_name, session_id = sessions[0]
    if remember:
        remembered = _remember_cookie_jar(response, f"{base}/login.php")
        response = request(
            f"{base}/login.php",
            headers=context_headers,
            opener=opener_for(
                urllib.request.HTTPCookieProcessor(remembered), _NoRedirect()
            ),
        )
        response.read()
        remembered_cookies = _response_cookies(response)
        remembered_sessions = [
            (name, cookie.value)
            for name, cookie in remembered_cookies.items()
            if name.startswith("NVSID_")
        ]
        if response.status != 302 or len(remembered_sessions) != 1:
            raise RuntimeError("persistent User login failed")
        session_name, session_id = remembered_sessions[0]
    # Docker service aliases contain underscores. The historical application
    # puts that alias in Domain=, which modern cookie policy rejects. Send the
    # exact application-issued session explicitly, as a browser on a normal DNS
    # hostname would do. Measured on the image: the application sets all three of
    # these itself (`cfg/session.php` the first two, `login.php` the third), so an
    # ordinary browser sends the same trio back, and the dashboard is reached with
    # the NVSID_ one alone. The triple is no checker fingerprint.
    opener = opener_for()
    opener.addheaders = [
        ("Cookie", f"{session_name}={session_id}; PHPSESSID={session_id}; navigate-session-id={session_id}")
    ]
    dashboard = request(
        f"{base}/navigate.php?fid=dashboard",
        headers=context_headers,
        opener=opener,
    )
    dashboard_body = dashboard.read()
    if dashboard.status == 404:
        dashboard = request(
            f"{base}/navigate.php?fid=dashboard",
            headers=context_headers,
            opener=opener,
        )
        dashboard_body = dashboard.read()
    if (
        dashboard.status != 200
        or b'id="navigate-content"' not in dashboard_body
    ):
        raise RuntimeError("authenticated dashboard failed")
    if remember:
        identity_start = dashboard_body.find(b'<a class="bold" href="?fid=2"')
        identity_end = dashboard_body.find(b"</a>", identity_start)
        identity_link = dashboard_body[identity_start:identity_end]
        if (
            identity_start < 0
            or identity_end < 0
            or not identity_link.endswith(b" /> " + username.encode())
        ):
            raise RuntimeError("persistent User login resumed the wrong identity")
    return opener, session_id


def multipart(field: str, filename: str, content: bytes) -> tuple[bytes, str]:
    # Free-form over the lengths and characters ordinary clients draw their own
    # boundaries from, so the delimiter carries no fixed shape either.
    alphabet = string.ascii_letters + string.digits + "-_"
    boundary = "".join(
        secrets.choice(alphabet) for _ in range(16 + secrets.randbelow(55))
    )
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def ordinary_upload(
    base: str,
    opener: urllib.request.OpenerDirector,
    session_id: str,
    filename: str,
    marker: bytes,
    *,
    headers: dict[str, str] | None = None,
    on_registered: Callable[[int], None] | None = None,
) -> int:
    context_headers = dict(headers or {})
    body, content_type = multipart("file", filename, marker)
    query = urllib.parse.urlencode({"session_id": session_id, "engine": "tinymce"})
    response = request(
        f"{base}/navigate_upload.php?{query}",
        data=body,
        headers={**context_headers, "Content-Type": content_type},
    )
    payload = response.read()
    if response.status != 200:
        raise RuntimeError("ordinary media upload failed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("ordinary media upload returned invalid JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("location"), str):
        raise RuntimeError("ordinary media upload returned no registered file")
    base_parts = urllib.parse.urlsplit(base)
    parts = urllib.parse.urlsplit(
        urllib.parse.urljoin(base.rstrip("/") + "/", value["location"])
    )
    expected_path = base_parts.path.rstrip("/") + "/navigate_download.php"
    download_query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    valid_location = (
        (parts.scheme, parts.netloc) == (base_parts.scheme, base_parts.netloc)
        and parts.path == expected_path
        and not parts.fragment
        and len(download_query) == 1
        and download_query[0][0] == "id"
        and download_query[0][1].isdigit()
        and int(download_query[0][1]) > 0
    )
    if not valid_location:
        raise RuntimeError("ordinary media upload returned an invalid download URL")
    media_id = int(download_query[0][1])
    if on_registered is not None:
        on_registered(media_id)
    # The media id addresses the application's own file record. Nothing in this
    # request carries the name, so a properties page that shows it is evidence
    # the service registered the upload rather than echoing it back.
    properties = request(
        f"{base}/navigate.php?"
        + urllib.parse.urlencode(
            {"fid": "files", "act": "edit", "id": download_query[0][1]}
        ),
        headers=context_headers,
        opener=opener,
    )
    registered = properties.read()
    if properties.status != 200 or filename.encode() not in registered:
        raise RuntimeError("registered media is absent from native file properties")
    download_query.append(("sid", session_id))
    download_url = urllib.parse.urlunsplit(
        (
            base_parts.scheme,
            base_parts.netloc,
            expected_path,
            urllib.parse.urlencode(download_query),
            "",
        )
    )
    download = request(
        download_url,
        headers=context_headers,
        opener=opener_for(_NoRedirect()),
    )
    downloaded = download.read()
    if download.status != 200 or downloaded != marker:
        raise RuntimeError("registered media did not round-trip over HTTP")
    return media_id


def register_upload(
    base: str,
    opener: urllib.request.OpenerDirector,
    session_id: str,
    filename: str,
    content: bytes,
    *,
    headers: dict[str, str] | None = None,
) -> int:
    """Register media through the ordinary Files-section upload workflow.

    The record is created by the application's own `file::register_upload`, so
    its id is drawn from the live media sequence rather than from this client.
    """
    context_headers = dict(headers or {})
    body, content_type = multipart("file", filename, content)
    staged = request(
        f"{base}/navigate_upload.php?"
        + urllib.parse.urlencode({"session_id": session_id, "name": filename}),
        data=body,
        headers={**context_headers, "Content-Type": content_type},
    )
    staged.read()
    if staged.status != 200:
        raise RuntimeError("Files-section media staging failed")
    registered = request(
        f"{base}/navigate.php?"
        + urllib.parse.urlencode(
            {
                "fid": "files", "act": "json", "op": "upload",
                "tmp_name": "{{BASE64}}", "name": filename, "parent": "0",
            }
        ),
        headers=context_headers,
        opener=opener,
    )
    payload = registered.read()
    if registered.status != 200:
        raise RuntimeError("Files-section media registration failed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Files-section registration returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("name") != filename:
        raise RuntimeError("Files-section registration returned no record")
    media_id = value.get("id")
    if not isinstance(media_id, str) or not media_id.isdigit() or int(media_id) <= 0:
        raise RuntimeError("Files-section registration returned no record id")
    return int(media_id)


def delete_media(
    base: str,
    opener: urllib.request.OpenerDirector,
    media_id: int,
    *,
    headers: dict[str, str] | None = None,
) -> None:
    """Remove one checker-created native media record and require confirmation."""
    response = request(
        f"{base}/navigate.php?"
        + urllib.parse.urlencode(
            {"fid": "files", "act": "json", "op": "delete", "id": media_id}
        ),
        headers=dict(headers or {}),
        opener=opener,
    )
    payload = response.read()
    try:
        deleted = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("media cleanup returned invalid JSON") from exc
    if response.status != 200 or deleted != 1:
        raise RuntimeError("media cleanup did not remove its native record")


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
