from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_api", Path(__file__).resolve().parents[1] / "_api.py")
api = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(api)


def test_webdav_path_quotes_identity_and_segments():
    assert api.webdav_path("user name", "Guarded/a b.txt") == (
        "/remote.php/dav/files/user%20name/Guarded/a%20b.txt")


def test_browser_headers_are_ordinary_and_unlabelled():
    headers = [api.browser_headers() for _ in range(40)]
    assert all(row["User-Agent"].startswith("Mozilla/5.0 ") for row in headers)
    assert all("Chrome/" in row["User-Agent"] for row in headers)
    assert all("caddy" not in row["User-Agent"].lower()
               and "arena" not in row["User-Agent"].lower()
               and "checker" not in row["User-Agent"].lower()
               for row in headers)
    assert all(row["Accept-Language"].startswith("en-") for row in headers)
