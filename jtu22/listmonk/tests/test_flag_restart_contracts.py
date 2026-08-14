from __future__ import annotations

import importlib.util
from pathlib import Path

from challenges.interface import Flag, ObservationStatus, VulboxTarget

from jtu22.listmonk import build
from jtu22.listmonk.challenge import ListmonkChallenge
from jtu22.listmonk.flag_handler import (
    CREDENTIAL_HANDLE,
    CREDENTIAL_STORE,
    OBJECT_HANDLE,
    OBJECT_STORE,
    ListmonkFlagHandler,
)
from jtu22.listmonk.restart_handler import ListmonkRestartHandler


def _target(exec_in):
    return VulboxTarget(
        host="prod",
        ports={"service": 9000, "object_store": 9001},
        meta={"exec_in_container": exec_in},
    )


def test_challenge_declares_two_independently_scored_capabilities():
    challenge = ListmonkChallenge()
    assert challenge.flag_stores() == [CREDENTIAL_STORE, OBJECT_STORE]
    assert challenge.vulbox.exposed_ports["object_store"] == 9001


def test_multiflag_plant_returns_one_handle_per_capability():
    calls = []

    def exec_in(host, command):
        calls.append((host, command))
        return 0, ""

    handles = ListmonkFlagHandler().plant(
        _target(exec_in),
        {
            CREDENTIAL_STORE: Flag("FLAG{CREDENTIAL}"),
            OBJECT_STORE: Flag("FLAG{PRIVATEOBJECT}"),
        },
    )
    assert handles == {
        CREDENTIAL_STORE: CREDENTIAL_HANDLE,
        OBJECT_STORE: OBJECT_HANDLE,
    }
    assert "plant-credential" in calls[0][1]
    assert "plant-object" in calls[1][1]


def test_retrieve_is_read_only_structured_and_exact():
    calls = []

    def exec_in(host, command):
        calls.append((host, command))
        return 0, "FLAG{current}\n"

    handler = ListmonkFlagHandler()
    present = handler.retrieve(_target(exec_in), CREDENTIAL_HANDLE, "FLAG{current}")
    mismatch = handler.retrieve(_target(exec_in), OBJECT_HANDLE, "FLAG{other}")

    assert present.status is ObservationStatus.PRESENT
    assert present.value == "FLAG{current}"
    assert mismatch.status is ObservationStatus.MISMATCH
    assert mismatch.value == "FLAG{current}"
    assert calls == [
        ("prod", "/arena/flag_store.py retrieve-credential"),
        ("prod", "/arena/flag_store.py retrieve-object"),
    ]


def test_retrieve_distinguishes_missing_from_database_error():
    missing = ListmonkFlagHandler().retrieve(
        _target(lambda host, command: (0, "")), CREDENTIAL_HANDLE, "FLAG{x}"
    )
    assert missing.status is ObservationStatus.NOT_FOUND

    calls = []

    def failed_read(host, command):
        calls.append(command)
        return (0, "") if command == "true" else (2, "psql failed")

    error = ListmonkFlagHandler().retrieve(
        _target(failed_read), CREDENTIAL_HANDLE, "FLAG{x}"
    )
    assert error.status is ObservationStatus.ERROR
    assert calls == ["/arena/flag_store.py retrieve-credential", "true"]


def test_retrieve_rejects_unknown_handle_without_exec():
    called = False

    def exec_in(host, command):
        nonlocal called
        called = True
        return 0, "FLAG{x}"

    result = ListmonkFlagHandler().retrieve(
        _target(exec_in), "settings:other", "FLAG{x}"
    )
    assert result.status is ObservationStatus.ERROR
    assert not called


def test_flag_store_retrieval_is_read_only(monkeypatch):
    path = Path(__file__).parents[1] / "image" / "flag_store.py"
    spec = importlib.util.spec_from_file_location("listmonk_flag_store", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    seen = []

    def fake_psql(sql, *, capture=False):
        seen.append((sql, capture))
        return "FLAG{db}"

    monkeypatch.setattr(module, "_psql", fake_psql)
    monkeypatch.setattr(module, "_mc", lambda *args, **kwargs: "FLAG{object}")
    assert module.retrieve_credential() == "FLAG{db}"
    assert module.retrieve_object() == "FLAG{object}"
    assert len(seen) == 1
    sql, capture = seen[0]
    assert sql.lstrip().upper().startswith("SELECT ")
    assert "INSERT" not in sql.upper()
    assert "UPDATE" not in sql.upper()
    assert capture is True


def test_restart_reports_build_spawn_and_readiness_without_checker():
    calls = []
    output = "\n".join(
        [
            "listmonk-restart: compile ok",
            "listmonk: process started pid=42",
            "listmonk: service ready on :9000",
        ]
    )

    def exec_in(host, command):
        calls.append(command)
        return 0, output

    result = ListmonkRestartHandler().run(_target(exec_in))
    assert result.passed
    assert [child.name for child in result.children] == [
        "compile",
        "spawn",
        "readiness",
    ]
    assert all(child.passed for child in result.children)
    assert calls == ["/arena/restart.sh"]


def test_restart_preserves_partial_phase_evidence_on_readiness_failure():
    output = "\n".join(
        [
            "listmonk-restart: compile ok",
            "listmonk: process started pid=42",
            "listmonk-restart: launch/readiness failed",
        ]
    )
    result = ListmonkRestartHandler().run(
        _target(lambda host, command: (30, output))
    )
    assert not result.passed
    assert [child.passed for child in result.children] == [True, True, False]


def test_restart_reports_compile_failure_with_diagnostic():
    output = "internal/core/subscribers.go:42: undefined: broken\nlistmonk-restart: compile failed"
    result = ListmonkRestartHandler().run(
        _target(lambda host, command: (10, output))
    )

    assert not result.passed
    assert [child.passed for child in result.children] == [False, False, False]
    assert "undefined: broken" in result.children[0].detail


def test_builder_does_not_reuse_an_existing_mutable_tag(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))

    monkeypatch.setattr(build.subprocess, "run", run)
    tag = build.build_image(client=object())

    assert tag == "cyberarena/chal-listmonk:v1"
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:4] == ["docker", "build", "--platform=linux/amd64", "-t"]
    assert command[4] == tag
    assert kwargs == {"check": True, "capture_output": True, "text": True}


def test_restart_scripts_leave_flag_state_and_checker_out_of_restart_path():
    image = Path(__file__).parents[1] / "image"
    restart = (image / "restart.sh").read_text()
    start = (image / "start.sh").read_text()

    assert "checker" not in restart
    assert "checker" not in start
    assert "flag_store" not in restart
    assert "flag_store" not in start
    assert "settings" not in restart
    assert "settings" not in start
    assert "pg_ctl" not in restart
    assert "pg_ctl" not in start


def test_restart_compiles_before_atomic_install_and_process_replacement():
    restart = (Path(__file__).parents[1] / "image" / "restart.sh").read_text()

    compile_at = restart.index('go build -buildvcs=false -o "$NEXT" ./cmd')
    install_at = restart.index('mv -f "$NEXT" "$LIVE"')
    replace_at = restart.index("/arena/start.sh")
    assert compile_at < install_at < replace_at
    assert "GOPROXY=off" in restart
    assert "GOTOOLCHAIN=local" in restart
    assert "trap cleanup EXIT" in restart
    assert "if [ \"$rc\" -ne 0 ]" in restart
    assert "stop_backend" in restart
    assert "pkill -f '[l]istmonk/bin/listmonk'" in restart
