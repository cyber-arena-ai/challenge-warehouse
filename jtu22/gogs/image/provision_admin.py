#!/usr/bin/env python3
"""Create and discard the first Gogs identity so public users are non-admin."""

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


if __name__ == "__main__":
    main()
