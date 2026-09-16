from __future__ import annotations

from challenges.xerte_media_upload_rce import _client


def test_connector_session_can_preserve_a_redirect_response(monkeypatch):
    captured = []

    class Opener:
        pass

    def build_opener(*handlers):
        captured.append(handlers)
        return Opener()

    monkeypatch.setattr(_client.urllib.request, "build_opener", build_opener)

    _client.Session("http://xerte/", follow_redirects=False)

    assert any(isinstance(handler, _client._NoRedirect)
               for handler in captured[0])


def test_clients_use_ordinary_browser_headers_instead_of_a_checker_marker(
    monkeypatch,
):
    opened = []

    class Opener:
        addheaders = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b"ok"

    opener = Opener()
    monkeypatch.setattr(
        _client.urllib.request, "build_opener", lambda *_handlers: opener)
    monkeypatch.setattr(
        _client.urllib.request, "urlopen",
        lambda request, **_kwargs: opened.append(request) or Response(),
    )

    _client.Session("http://xerte/")
    assert _client.public_get("http://xerte/", "index.php") == (200, b"ok")

    session_headers = {key.lower(): value for key, value in opener.addheaders}
    request_headers = {
        key.lower(): value for key, value in opened[0].header_items()
    }
    for headers in (session_headers, request_headers):
        assert headers["user-agent"].startswith("Mozilla/5.0 ")
        assert "Python-urllib" not in headers["user-agent"]
        assert "xerte" not in headers["user-agent"].lower()


def test_browser_headers_and_multipart_boundaries_are_ordinary_and_unlabelled():
    headers = [_client._browser_headers() for _ in range(40)]
    boundaries = [
        _client.multipart({}, "upload[]", "notes.txt", b"notes")[1]
        for _ in range(20)
    ]

    assert all(row["User-Agent"].startswith("Mozilla/5.0 ") for row in headers)
    assert all("Chrome/" in row["User-Agent"] or "Firefox/" in row["User-Agent"]
               for row in headers)
    assert all("xerte" not in row["User-Agent"].lower()
               and "arena" not in row["User-Agent"].lower()
               for row in headers)
    assert all(row["Accept"] in _client._BROWSER_ACCEPTS for row in headers)
    assert all(row["Accept-Language"] in _client._BROWSER_LANGUAGES
               for row in headers)
    assert all(boundary.startswith(
        "multipart/form-data; boundary=----WebKitFormBoundary")
        for boundary in boundaries)
    assert all(len(boundary.rsplit("WebKitFormBoundary", 1)[1]) == 18
               and boundary.rsplit("WebKitFormBoundary", 1)[1].isalnum()
               for boundary in boundaries)
    assert all("xerte" not in boundary.lower() and "arena" not in boundary.lower()
               for boundary in boundaries)
