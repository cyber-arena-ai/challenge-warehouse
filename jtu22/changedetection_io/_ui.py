"""Small stdlib client for changedetection.io's anonymous watch UI."""

from __future__ import annotations

import html
import http.cookiejar
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

_CSRF_RE = re.compile(rb'name="csrf_token" value="([^"]+)"')
_EDIT_RE = re.compile(r"/edit/([0-9a-f-]+)")
_PREVIEW_RE = re.compile(rb'<pre id="difference"[^>]*>(.*?)</pre>', re.DOTALL)
_WATCH_ROW_RE = re.compile(
    rb'<tr[^>]+data-watch-uuid="([0-9a-f-]+)"[^>]*>(.*?)</tr>', re.DOTALL
)


def _participant_user_agent() -> str:
    family = secrets.choice(("browser", "firefox", "curl"))
    if family == "browser":
        major = secrets.randbelow(13) + 134
        build = secrets.randbelow(5000) + 6000
        patch = secrets.randbelow(200)
        return (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} Safari/537.36"
        )
    if family == "firefox":
        major = secrets.randbelow(13) + 134
        return (
            f"Mozilla/5.0 (X11; Linux x86_64; rv:{major}.0) "
            f"Gecko/20100101 Firefox/{major}.0"
        )
    return f"curl/8.{secrets.randbelow(14)}.{secrets.randbelow(5)}"


class WatchWorkflowError(RuntimeError):
    def __init__(
        self,
        message: str,
        watch_uuid: str | None = None,
        *,
        stage: str | None = None,
        status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.watch_uuid = watch_uuid
        self.stage = stage
        self.status = status


def opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    client.addheaders = [("User-Agent", _participant_user_agent())]
    return client


def request(
    client: urllib.request.OpenerDirector,
    base: str,
    path: str,
    *,
    fields: dict[str, str] | None = None,
    timeout: float = 12,
) -> tuple[int, str, bytes]:
    data = None if fields is None else urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        base + path,
        data=data,
        method="GET" if fields is None else "POST",
    )
    try:
        with client.open(req, timeout=timeout) as response:
            return response.status, response.geturl(), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.geturl(), error.read()


def csrf(body: bytes) -> str:
    match = _CSRF_RE.search(body)
    if match is None:
        raise RuntimeError("public page did not contain a CSRF token")
    return html.unescape(match.group(1).decode())


def create_watch(
    client: urllib.request.OpenerDirector,
    base: str,
    source_url: str,
    xpath_filter: str,
) -> tuple[str, bool, bytes]:
    status, _, root = request(client, base, "/")
    if status != 200:
        raise RuntimeError(f"public root returned HTTP {status}")
    status, final_url, _ = request(
        client,
        base,
        "/form/add/quickwatch",
        fields={
            "csrf_token": csrf(root),
            "url": source_url,
            "tags": "",
            "processor": "text_json_diff",
            "edit_and_watch_submit_button": "Edit > Watch",
        },
    )
    if status != 200:
        raise RuntimeError(f"quick-watch form returned HTTP {status}")
    match = _EDIT_RE.search(final_url)
    if match is None:
        raise RuntimeError("quick-watch form did not open an edit page")
    watch_uuid = match.group(1)

    status, _, edit = request(client, base, f"/edit/{watch_uuid}?unpause_on_save=1")
    if status != 200:
        raise WatchWorkflowError(
            f"watch edit page returned HTTP {status}",
            watch_uuid,
            stage="edit",
            status=status,
        )
    status, _, saved = request(
        client,
        base,
        f"/edit/{watch_uuid}?unpause_on_save=1",
        fields={
            "csrf_token": csrf(edit),
            "include_filters": xpath_filter,
            "url": source_url,
            "tags": "",
            "headers": "",
            "fetch_backend": "html_requests",
            "time_between_check_use_default": "y",
        },
    )
    if status != 200:
        raise WatchWorkflowError(
            f"watch save returned HTTP {status}",
            watch_uuid,
            stage="save",
            status=status,
        )
    return watch_uuid, b"Updated watch" in saved, saved


def preview(
    client: urllib.request.OpenerDirector,
    base: str,
    watch_uuid: str,
    *,
    timeout: float = 45,
) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, _, body = request(client, base, f"/preview/{watch_uuid}")
        if status == 200:
            match = _PREVIEW_RE.search(body)
            if match is not None:
                return html.unescape(match.group(1).decode(errors="replace")).strip()
        time.sleep(0.5)
    return None


def delete_watch(
    client: urllib.request.OpenerDirector, base: str, watch_uuid: str
) -> bool:
    try:
        status, _, body = request(
            client, base, "/delete?" + urllib.parse.urlencode({"uuid": watch_uuid})
        )
        return status == 200 and b"Deleted." in body
    except Exception:
        return False


def watches_with_source(body: bytes, source_url: str) -> list[str]:
    """Locate only rows carrying this invocation's exact unguessable URL."""
    matches = []
    for watch_uuid, rendered in watch_rows(body):
        if source_url in rendered:
            matches.append(watch_uuid)
    return matches


def watch_rows(body: bytes) -> list[tuple[str, str]]:
    """Return watch UUIDs and their rendered root-row content."""
    return [
        (
            match.group(1).decode(),
            html.unescape(match.group(2).decode(errors="replace")),
        )
        for match in _WATCH_ROW_RE.finditer(body)
    ]


def watch_matches(
    client: urllib.request.OpenerDirector,
    base: str,
    watch_uuid: str,
    source_url: str,
) -> bool:
    """Confirm an exact unguessable source URL before deleting its watch."""
    status, _, body = request(client, base, f"/edit/{watch_uuid}")
    if status != 200:
        return False
    rendered = html.unescape(body.decode(errors="replace"))
    return source_url in rendered
