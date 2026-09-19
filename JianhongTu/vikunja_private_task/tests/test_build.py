from __future__ import annotations

from pathlib import Path

import docker

from JianhongTu.vikunja_private_task import build


class _Completed:
    returncode = 0
    stdout = ""
    stderr = ""


class _Images:
    def __init__(self, present: bool):
        self.present = present

    def get(self, tag):
        if self.present:
            return object()
        raise docker.errors.ImageNotFound(f"no such image: {tag}")


class _Client:
    def __init__(self, present: bool):
        self.images = _Images(present)


def _capture(monkeypatch):
    calls = []
    monkeypatch.setattr(
        build.subprocess, "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or _Completed(),
    )
    return calls


def test_build_skipped_when_image_present(monkeypatch):
    """The tag already on the box is the image: no docker build, so the game
    neither rebuilds per run nor depends on the layer cache surviving."""
    calls = _capture(monkeypatch)
    tag = build.VikunjaPrivateTaskChallenge().vulbox.reference
    assert build.build_image(_Client(present=True)) == tag
    assert calls == []


def test_build_runs_from_package_context_when_image_absent(monkeypatch):
    calls = _capture(monkeypatch)
    tag = build.VikunjaPrivateTaskChallenge().vulbox.reference
    assert build.build_image(_Client(present=False)) == tag
    assert len(calls) == 1
    cmd = calls[0][0]
    assert cmd[:2] == ["docker", "build"] and "-t" in cmd and tag in cmd
    assert cmd[-1] == str(Path(build.__file__).resolve().parent / "image")
