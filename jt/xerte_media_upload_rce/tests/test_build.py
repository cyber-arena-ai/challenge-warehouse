from __future__ import annotations

from pathlib import Path

from jt.xerte_media_upload_rce import build


def test_build_always_uses_current_package_context(monkeypatch):
    calls = []

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or Completed(),
    )

    assert build.build_image(object()) == (
        build.XerteMediaUploadRceChallenge().vulbox.reference
    )
    assert len(calls) == 1
    assert calls[0][0][-1] == str(Path(build.__file__).resolve().parent / "image")
