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
