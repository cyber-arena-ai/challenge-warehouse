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
