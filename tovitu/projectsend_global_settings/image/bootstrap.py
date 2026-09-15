#!/usr/bin/env python3
"""Install the pinned ProjectSend instance through its supported HTTP flow."""

from __future__ import annotations

import os
import time
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1/"


def request(
    path: str,
    data: dict[str, str] | None = None,
    *,
    timeout: float = 20,
) -> tuple[int, bytes]:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(urllib.parse.urljoin(BASE, path), data=body)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, response.read()


def _request_timeout(deadline: float) -> float:
    return max(0.1, min(20.0, deadline - time.monotonic()))


def _installed(body: bytes) -> bool:
    return b'id="login_form"' in body


def _probe_install(deadline: float) -> tuple[bool, bytes]:
    try:
        status, body = request(
            "index.php", timeout=_request_timeout(deadline),
        )
    except OSError:
        return False, b""
    return status == 200 and _installed(body), body


def _wait_for_install(deadline: float, seconds: float = 20) -> bool:
    reconcile_deadline = min(deadline, time.monotonic() + seconds)
    while time.monotonic() < reconcile_deadline:
        installed, _ = _probe_install(deadline)
        if installed:
            return True
        time.sleep(min(1.0, max(0.0, reconcile_deadline - time.monotonic())))
    return False


def main() -> None:
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            status, body = request(
                "index.php", timeout=_request_timeout(deadline),
            )
            if status == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("ProjectSend HTTP service did not start")

    if _installed(body):
        return
    password = os.environ["PROJECTSEND_ADMIN_PASSWORD"]
    install_data = {
        "install_title": "ProjectSend Arena context 0000000000000000",
        "base_uri": "/",
        "admin_name": "Arena Administrator",
        "admin_email": "admin@example.invalid",
        "admin_username": "arenaadmin",
        "admin_pass": password,
    }
    last_failure = "installer did not complete"
    while time.monotonic() < deadline:
        installed, body = _probe_install(deadline)
        if installed:
            return
        try:
            status, body = request(
                "install/index.php",
                install_data,
                timeout=_request_timeout(deadline),
            )
            if status == 200 and b"Everything is up and running." in body:
                return
            last_failure = f"HTTP {status}: {body[:800]!r}"
        except OSError as error:
            last_failure = type(error).__name__

        # A timed-out POST may still have committed. Reconcile through the public
        # login page before deciding whether another idempotent install attempt is
        # needed.
        if _wait_for_install(deadline):
            return

    raise RuntimeError(f"ProjectSend HTTP installation failed: {last_failure}")


if __name__ == "__main__":
    main()
