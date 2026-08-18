#!/usr/bin/env python3
"""Create the first Gogs identity while HTTP is bound to loopback only."""

from __future__ import annotations

import http.cookiejar
import re
import secrets
import sys
import urllib.parse
import urllib.request


def main() -> None:
    base = sys.argv[1].rstrip("/")
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    with opener.open(base + "/user/sign_up", timeout=15) as response:
        page = response.read().decode(errors="replace")
    match = re.search(r'name="_csrf" value="([^"]+)"', page)
    if not match:
        raise RuntimeError("bootstrap CSRF token missing")
    username = "bootstrap" + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    body = urllib.parse.urlencode(
        {
            "_csrf": match.group(1),
            "user_name": username,
            "email": f"{username}@example.invalid",
            "password": password,
            "retype": password,
        }
    ).encode()
    with opener.open(
        urllib.request.Request(base + "/user/sign_up", data=body), timeout=30
    ) as response:
        response.read()
    with opener.open(base + "/admin", timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(
                f"bootstrap identity is not an administrator (HTTP {response.status})"
            )


if __name__ == "__main__":
    main()
