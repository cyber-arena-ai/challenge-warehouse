from __future__ import annotations

import importlib.util
from pathlib import Path

from challenges.interface import ObservationStatus, VulboxTarget

from jtu22.changedetection_io import flag_handler
from jtu22.changedetection_io.flag_handler import ChangedetectionIoFlagHandler
from jtu22.changedetection_io.restart_handler import ChangedetectionIoRestartHandler


def _target(exec_in):
    return VulboxTarget(
        host="prod",
        ports={"service": 5000},
        meta={"exec_in_container": exec_in},
    )


def test_flag_retrieve_is_structured_read_only_and_exact():
    calls = []

    def exec_in(host, command):
        calls.append((host, command))
        return 0, "FLAG{current}\n"

    handler = ChangedetectionIoFlagHandler()
    handle = (
        "host.file:/var/lib/changedetection/private/reports/"
        "aaaaaaaaaaaaaaaaaaaa-operator-report.txt"
    )
    present = handler.retrieve(_target(exec_in), handle, "FLAG{current}")
    mismatch = handler.retrieve(_target(exec_in), handle, "FLAG{other}")

    assert present.status is ObservationStatus.PRESENT
    assert mismatch.status is ObservationStatus.MISMATCH
    assert calls == [
        (
            "prod",
            "/arena/flag_store.py retrieve "
            "/var/lib/changedetection/private/reports/"
            "aaaaaaaaaaaaaaaaaaaa-operator-report.txt",
        ),
        (
            "prod",
            "/arena/flag_store.py retrieve "
            "/var/lib/changedetection/private/reports/"
            "aaaaaaaaaaaaaaaaaaaa-operator-report.txt",
        ),
    ]


def test_unknown_flag_handle_does_not_exec():
    called = False

    def exec_in(host, command):
        nonlocal called
        called = True
        return 0, "FLAG{x}"

    result = ChangedetectionIoFlagHandler().retrieve(
        _target(exec_in), "host.file:/other", "FLAG{x}"
    )
    assert result.status is ObservationStatus.ERROR
    assert not called


def test_flag_context_and_id_rotate_together(monkeypatch):
    values = iter(("a" * 20, "b" * 20))
    monkeypatch.setattr(flag_handler.secrets, "token_hex", lambda _size: next(values))
    calls = []

    def exec_in(host, command):
        calls.append((host, command))
        return 0, ""

    handler = ChangedetectionIoFlagHandler()
    first = handler.plant_one(_target(exec_in), "FLAG{first}")
    second = handler.plant_one(_target(exec_in), "FLAG{second}")

    assert first != second
    assert handler.flag_id(first) == (
        "/var/lib/changedetection/private/reports/"
        "aaaaaaaaaaaaaaaaaaaa-operator-report.txt"
    )
    assert handler.flag_id(second) == (
        "/var/lib/changedetection/private/reports/"
        "bbbbbbbbbbbbbbbbbbbb-operator-report.txt"
    )
    assert "FLAG{first}" not in calls[0][1]
    assert handler.flag_id("host.file:/other") is None


def test_flag_store_retrieve_does_not_mutate(monkeypatch, tmp_path):
    path = Path(__file__).parents[1] / "image" / "flag_store.py"
    spec = importlib.util.spec_from_file_location("changedetection_flag_store", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report = report_dir / ("a" * 20 + "-operator-report.txt")
    report.write_text(
        "Changedetection Operations Report\n"
        "Archive access token: FLAG{stored}\n"
    )
    monkeypatch.setattr(module, "REPORT_DIR", report_dir)
    before = report.stat().st_mtime_ns
    assert module.retrieve(str(report)) == "FLAG{stored}"
    assert report.stat().st_mtime_ns == before


def test_restart_reports_compile_spawn_readiness():
    output = "\n".join(
        [
            "changedetection-restart: compile ok",
            "changedetection: process started pid=42",
            "changedetection: service ready on :5000",
        ]
    )
    result = ChangedetectionIoRestartHandler().run(
        _target(lambda host, command: (0, output))
    )
    assert result.passed
    assert [child.name for child in result.children] == [
        "compile",
        "spawn",
        "readiness",
    ]


def test_restart_does_not_touch_flag_or_run_checker():
    restart = (Path(__file__).parents[1] / "image" / "restart.sh").read_text()
    start = (Path(__file__).parents[1] / "image" / "start.sh").read_text()
    assert "flag_store" not in restart + start
    assert "operator-report" not in restart + start
    assert "checker.py" not in restart + start
