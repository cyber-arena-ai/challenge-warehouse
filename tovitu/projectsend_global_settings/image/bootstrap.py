#!/usr/bin/env python3
"""Install the pinned ProjectSend instance through its supported HTTP flow."""

from __future__ import annotations

import os
import time
import urllib.parse
import urllib.request


BASE = "http://127.0.0.1/"


def request(path: str, data: dict[str, str] | None = None) -> tuple[int, bytes]:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(urllib.parse.urljoin(BASE, path), data=body)
    with urllib.request.urlopen(req, timeout=20) as response:
        return response.status, response.read()


def main() -> None:
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            status, body = request("index.php")
            if status == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("ProjectSend HTTP service did not start")

    if b'id="login_form"' in body:
        return
    password = os.environ["PROJECTSEND_ADMIN_PASSWORD"]
    status, body = request(
        "install/index.php",
        {
            "install_title": "ProjectSend Arena context 0000000000000000",
            "base_uri": "/",
            "admin_name": "Arena Administrator",
            "admin_email": "admin@example.invalid",
            "admin_username": "arenaadmin",
            "admin_pass": password,
        },
    )
    if status != 200 or b"Everything is up and running." not in body:
        raise RuntimeError(
            f"ProjectSend HTTP installation failed: HTTP {status}: {body[:800]!r}"
        )


if __name__ == "__main__":
    main()
