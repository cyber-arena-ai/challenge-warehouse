from pathlib import Path

from jtu22.changedetection_io import build
from jtu22.changedetection_io.challenge import UPSTREAM_COMMIT


def test_image_pins_source_base_and_dependency_lock():
    package = Path(__file__).parents[1]
    dockerfile = (package / "image" / "Dockerfile").read_text()
    lock = (package / "image" / "requirements.lock").read_text()

    assert UPSTREAM_COMMIT in dockerfile
    assert "python:3.11.15-slim-bookworm@sha256:" in dockerfile
    assert "DEBIAN_SNAPSHOT=20260715T000000Z" in dockerfile
    assert "snapshot.debian.org" in dockerfile
    assert "pip install --no-cache-dir --no-deps" in dockerfile
    assert "elementpath==5.1.1" in lock
    assert "lxml==6.1.1" in lock
    assert "requests==2.34.2" in lock


def test_production_image_does_not_contain_external_checker():
    package = Path(__file__).parents[1]
    dockerfile = (package / "image" / "Dockerfile").read_text()
    assert "checker.py" not in dockerfile
    assert not (package / "image" / "checker.py").exists()


def test_setup_locks_ui_and_restores_operator_api_token():
    configure = (
        Path(__file__).parents[1] / "image" / "configure.py"
    ).read_text()
    assert 'application["api_access_token"] = API_TOKEN' in configure
    assert "secrets.token_bytes(32)" in configure
    assert 'application["password"]' in configure


def test_build_always_rebuilds_the_current_context(monkeypatch):
    calls = []

    class StaleImageClient:
        class Images:
            @staticmethod
            def get(tag):
                raise AssertionError(f"must not reuse mutable image tag {tag}")

        images = Images()

    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)),
    )

    assert build.build_image(StaleImageClient()) == (
        "cyberarena/chal-changedetection-io:v1"
    )
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:4] == ["docker", "build", "--platform=linux/amd64", "-t"]
    assert command[-1] == str(build._CONTEXT_DIR)
    assert kwargs == {"check": True, "capture_output": True, "text": True}
