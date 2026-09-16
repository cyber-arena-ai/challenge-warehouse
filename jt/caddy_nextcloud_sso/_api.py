"""Small stdlib Nextcloud client shared by handler, checker, and private PoV."""

from __future__ import annotations

import base64
import html
import http.cookiejar
import ipaddress
import re
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 20
_TOKEN = re.compile(rb'data-requesttoken="([^"]+)"')

_PLATFORMS = (
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
    "X11; Linux x86_64",
)


def browser_headers() -> dict[str, str]:
    platform = secrets.choice(_PLATFORMS)
    major = 128 + secrets.randbelow(18)
    build = 6200 + secrets.randbelow(900)
    patch = 40 + secrets.randbelow(180)
    return {
        "User-Agent": (
            f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} Safari/537.36"
        ),
        "Accept": secrets.choice((
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.7",
        )),
        "Accept-Language": secrets.choice((
            "en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.8,fr;q=0.5",
        )),
    }


def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", host],
            capture_output=True, text=True, timeout=5,
        ).stdout.split()
        if out:
            return out[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return host


def webdav_path(username: str, target: str) -> str:
    user = urllib.parse.quote(username, safe="")
    segments = "/".join(urllib.parse.quote(part, safe="")
                        for part in target.split("/"))
    return f"/remote.php/dav/files/{user}/{segments}"


def unauthenticated_status(base: str, path: str = "/status.php") -> int:
    request = urllib.request.Request(
        base.rstrip("/") + path, method="GET", headers=browser_headers())
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


class NextcloudClient:
    def __init__(self, base: str, username: str, password: str,
                 *, headers: dict[str, str] | None = None):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.headers = {**browser_headers(), **(headers or {})}
        self._token = ""
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method: str, path: str, *, data: bytes | None = None,
                headers: dict[str, str] | None = None,
                max_bytes: int | None = None) -> tuple[int, bytes, str]:
        credentials = base64.b64encode(
            f"{self.username}:{self.password}".encode()).decode()
        merged = {"Authorization": "Basic " + credentials, **self.headers}
        if self._token:
            merged["requesttoken"] = self._token
        if headers:
            merged.update(headers)
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=merged)
        try:
            with self._opener.open(request, timeout=TIMEOUT) as response:
                raw = (
                    response.read() if max_bytes is None
                    else response.read(max_bytes + 1)
                )
                if max_bytes is not None and len(raw) > max_bytes:
                    raise ValueError("response body exceeds limit")
                return response.status, raw, response.geturl()
        except urllib.error.HTTPError as error:
            raw = (
                error.read() if max_bytes is None
                else error.read(max_bytes + 1)
            )
            if max_bytes is not None and len(raw) > max_bytes:
                raise ValueError("response body exceeds limit")
            return error.code, raw, error.geturl()

    def login(self, *, max_bytes: int | None = None) -> bool:
        status, raw, final_url = self.request(
            "GET", "/index.php/login", max_bytes=max_bytes)
        match = _TOKEN.search(raw)
        if match:
            self._token = html.unescape(match.group(1).decode())
        return status == 200 and "/apps/dashboard/" in final_url and bool(self._token)

    def webdav(self, method: str, target: str,
               data: bytes | None = None,
               *, max_bytes: int | None = None) -> tuple[int, bytes]:
        status, raw, _ = self.request(
            method, webdav_path(self.username, target), data=data,
            headers={"Content-Type": "application/octet-stream"},
            max_bytes=max_bytes)
        return status, raw
