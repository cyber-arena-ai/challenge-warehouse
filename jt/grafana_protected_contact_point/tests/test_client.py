from __future__ import annotations

from challenges.grafana_protected_contact_point import _client


def test_http_headers_have_varied_ordinary_browser_shapes() -> None:
    headers = [_client._ordinary_headers() for _ in range(20)]
    assert all(row["User-Agent"].startswith("Mozilla/5.0 (") for row in headers)
    assert all("Firefox/" in row["User-Agent"] for row in headers)
    assert all(row["Accept"] in _client._HTTP_ACCEPTS for row in headers)
    assert all(
        "checker" not in (row["User-Agent"] + row["Accept"]).lower()
        and "arena" not in (row["User-Agent"] + row["Accept"]).lower()
        for row in headers
    )
