from __future__ import annotations

import importlib.util
import socket
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("geoserver_client", ROOT / "_client.py")
client = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(client)


def test_underscore_service_alias_resolves_before_http() -> None:
    with patch.object(socket, "gethostbyname", return_value="10.1.2.3") as resolve:
        assert client.resolve_host("team1_prod") == "10.1.2.3"
    resolve.assert_called_once_with("team1_prod")


def test_standard_host_is_left_unchanged() -> None:
    with patch.object(socket, "gethostbyname") as resolve:
        assert client.resolve_host("127.0.0.1") == "127.0.0.1"
    resolve.assert_not_called()
