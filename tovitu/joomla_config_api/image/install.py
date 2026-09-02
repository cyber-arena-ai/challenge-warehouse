#!/usr/bin/env python3
"""Perform Joomla's supported web installation against local MariaDB."""

from __future__ import annotations

import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8080"


def request(
    url: str,
    *,
    opener: urllib.request.OpenerDirector,
    body: bytes | None = None,
) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {},
    )
    try:
        with opener.open(req, timeout=30) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")


installer = json.loads(Path("/run/joomla/installer.json").read_text())
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)
status, html = request(f"{BASE}/installation/index.php", opener=opener)
if status != 200 or "Joomla! 4.2.7" not in html:
    raise SystemExit("Joomla installer did not start")
match = re.search(r'"csrf\.token":"([a-f0-9]+)"', html)
if match is None:
    raise SystemExit("Joomla installer token missing")
token = match.group(1)
form = {
    "jform[language]": "en-GB",
    "jform[site_name]": "Cyber Arena Joomla",
    "jform[admin_user]": "Arena Facility Administrator",
    "jform[admin_username]": installer["username"],
    "jform[admin_password]": installer["password"],
    "admin_password2": installer["password"],
    "jform[admin_email]": "installer@arena.invalid",
    "jform[db_type]": "mysqli",
    "jform[db_host]": "127.0.0.1",
    "jform[db_user]": "joomla",
    "jform[db_pass]": "joomla-db-local",
    "jform[db_name]": "joomla",
    "jform[db_prefix]": "jos_",
    "jform[db_old]": "remove",
    "jform[db_encryption]": "0",
    "jform[db_sslkey]": "",
    "jform[db_sslcert]": "",
    "jform[db_sslverifyservercert]": "0",
    "jform[db_sslca]": "",
    "jform[db_sslcipher]": "",
}
for task in (
    "dbcheck",
    "create",
    "populate1",
    "populate2",
    "populate3",
    "custom1",
    "custom2",
    "config",
):
    posted = dict(form)
    posted[token] = "1"
    status, raw = request(
        f"{BASE}/installation/index.php?task=installation.{task}&format=json",
        opener=opener,
        body=urllib.parse.urlencode(posted).encode(),
    )
    payload = json.loads(raw)
    if status != 200 or payload.get("error") or payload.get("messages"):
        raise SystemExit(f"Joomla installer task failed: {task}")
    token = payload["token"]
