"""Small stdlib Joomla client shared by trusted probes."""

from __future__ import annotations

import http.cookiejar
import ipaddress
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message


class AuthenticationError(RuntimeError):
    """A trusted Joomla credential was rejected."""


def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                host,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        addresses = result.stdout.split()
        if addresses:
            return addresses[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return host


def request(
    url: str,
    *,
    opener: urllib.request.OpenerDirector | None = None,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15,
) -> tuple[int, bytes, Message]:
    client = opener or urllib.request.build_opener()
    req = urllib.request.Request(
        url, data=body, method=method, headers=headers or {}
    )
    try:
        with client.open(req, timeout=timeout) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def _form_token(html: bytes) -> str:
    match = re.search(rb'name="([a-f0-9]{32})" value="1"', html)
    if match is None:
        raise RuntimeError("Joomla form token missing")
    return match.group(1).decode()


def _cookie_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )


def frontend_login(base: str, username: str, password: str) -> None:
    opener = _cookie_opener()
    status, html, _ = request(
        f"{base}/index.php?option=com_users&view=login", opener=opener
    )
    if status != 200:
        raise RuntimeError("Joomla frontend login form unavailable")
    token = _form_token(html)
    form = urllib.parse.urlencode(
        {
            "username": username,
            "password": password,
            "option": "com_users",
            "task": "user.login",
            "return": "",
            token: "1",
        }
    ).encode()
    status, html, _ = request(
        f"{base}/index.php/component/users/?task=user.login&Itemid=101",
        opener=opener,
        method="POST",
        body=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200 or b"Log out" not in html:
        raise AuthenticationError("Joomla Registered login rejected")


def admin_token(base: str, username: str, password: str, user_id: str) -> str:
    opener = _cookie_opener()
    status, html, _ = request(f"{base}/administrator/index.php", opener=opener)
    if status != 200:
        raise RuntimeError("Joomla administrator login form unavailable")
    token = _form_token(html)
    form = urllib.parse.urlencode(
        {
            "username": username,
            "passwd": password,
            "option": "com_login",
            "task": "login",
            "return": "aW5kZXgucGhw",
            token: "1",
        }
    ).encode()
    request(
        f"{base}/administrator/index.php",
        opener=opener,
        method="POST",
        body=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    status, profile, _ = request(
        f"{base}/administrator/index.php?option=com_users&task=user.edit&id={user_id}",
        opener=opener,
    )
    match = re.search(
        rb'id="jform_joomlatoken_token".*?value="([^"]+)"', profile, re.S
    )
    if status in {401, 403} or match is None:
        raise AuthenticationError("Joomla administrator login rejected")
    if status != 200:
        raise RuntimeError("Joomla administrator profile unavailable")
    return match.group(1).decode()


def api_request(
    base: str,
    token: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> tuple[int, bytes]:
    body = None if payload is None else json.dumps(payload).encode()
    headers = {
        "Accept": "application/vnd.api+json",
        "X-Joomla-Token": token,
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    suffix = "?page%5Boffset%5D=20&page%5Blimit%5D=20" if method == "GET" else ""
    status, raw, _ = request(
        f"{base}/api/index.php/v1/config/application{suffix}",
        method=method,
        body=body,
        headers=headers,
    )
    return status, raw


def config_values(raw: bytes) -> dict[str, object]:
    document = json.loads(raw)
    rows = document.get("data") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("Joomla configuration response has no data")
    values: dict[str, object] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        attributes = row.get("attributes")
        if isinstance(attributes, dict):
            values.update({key: value for key, value in attributes.items() if key != "id"})
    return values
