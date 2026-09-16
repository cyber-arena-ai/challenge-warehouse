from __future__ import annotations

import importlib.util
import socket
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

from challenges.geoserver_xpath import _client as package_client
from challenges.geoserver_xpath.image import road_protocol

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("geoserver_client", ROOT / "_client.py")
client = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(client)

FACILITY_SPEC = importlib.util.spec_from_file_location(
    "geoserver_facility_wire", ROOT / "image" / "facility.py"
)
facility = importlib.util.module_from_spec(FACILITY_SPEC)
assert FACILITY_SPEC.loader is not None
FACILITY_SPEC.loader.exec_module(facility)


def test_underscore_service_alias_resolves_before_http() -> None:
    with patch.object(socket, "gethostbyname", return_value="10.1.2.3") as resolve:
        assert client.resolve_host("team1_prod") == "10.1.2.3"
    resolve.assert_called_once_with("team1_prod")


def test_standard_host_is_left_unchanged() -> None:
    with patch.object(socket, "gethostbyname") as resolve:
        assert client.resolve_host("127.0.0.1") == "127.0.0.1"
    resolve.assert_not_called()


def test_http_headers_have_ordinary_browser_shapes() -> None:
    headers = [client._ordinary_headers() for _ in range(20)]
    assert all(row["User-Agent"].startswith("Mozilla/5.0 (") for row in headers)
    assert all("Firefox/" in row["User-Agent"] for row in headers)
    assert all("checker" not in row["User-Agent"].lower()
               and "arena" not in row["User-Agent"].lower()
               for row in headers)
    assert all(row["Accept"] in client._HTTP_ACCEPTS for row in headers)


def test_checker_and_objective_use_identical_road_wire_requests(
    monkeypatch,
) -> None:
    captured: list[tuple[str, str, str, dict[str, str], bytes | None]] = []
    shared_headers = {
        "Accept": "application/json,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) "
            "Gecko/20100101 Firefox/137.0"
        ),
    }

    class Response:
        status = 200
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def read(_limit: int) -> bytes:
            return b'{"numberMatched":0,"features":[]}'

    def urlopen(request: urllib.request.Request, **_kwargs):
        parsed = urllib.parse.urlsplit(request.full_url)
        captured.append((
            request.get_method(), parsed.path, parsed.query,
            {key.lower(): value for key, value in request.header_items()},
            request.data,
        ))
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(package_client, "_ordinary_headers", lambda: shared_headers)
    monkeypatch.setattr(facility, "ordinary_headers", lambda: shared_headers)
    monkeypatch.setattr(facility, "BASE", "http://service/geoserver")

    external = package_client.GeoServerClient(
        "http://service", "guarded", "secret"
    )
    credentials = ("guarded", "secret")
    label = "FLAG{" + "A" * 32 + "}"
    category = 17
    geometry = ((594000, 4917000), (596000, 4919000))
    cql_filter = road_protocol.road_filter(category, label)

    pairs = [
        (
            lambda: external.feature(
                "sf:roads", cql_filter=cql_filter, count=3
            ),
            lambda: facility.feature_response(category, credentials, label),
        ),
        (
            lambda: external.insert_road(label, category, geometry),
            lambda: facility.insert_feature(
                label, category, [list(point) for point in geometry], credentials
            ),
        ),
        (
            lambda: external.road_property_value("label", category, label),
            lambda: facility.feature_property_value(
                "label", category, label, credentials
            ),
        ),
        (
            lambda: external.map_png(
                road_protocol.WMS_WIDTH,
                road_protocol.WMS_HEIGHT,
                layer="sf:roads",
                srs="EPSG:26713",
                bbox=road_protocol.WMS_BBOX,
                cql_filter=cql_filter,
                transparent=True,
            ),
            lambda: facility.map_feature(category, label, credentials),
        ),
        (
            lambda: external.delete_road(label, category),
            lambda: facility.delete_feature(category, label, credentials),
        ),
    ]
    for checker_call, objective_call in pairs:
        captured.clear()
        checker_call()
        objective_call()
        assert captured[0] == captured[1]
        assert captured[0][1].startswith("/geoserver/")
        assert captured[0][3]["user-agent"].startswith("Mozilla/5.0 (")
        assert captured[0][3]["authorization"].startswith("Basic ")
        assert "Python-urllib" not in captured[0][3]["user-agent"]

    external.feature("sf:roads", cql_filter=cql_filter, count=3)
    assert "resultType" not in captured[-1][2]
    assert "+" not in captured[-1][2]
