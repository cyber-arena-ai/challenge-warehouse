from __future__ import annotations

from challenges.grafana_protected_contact_point import restart_handler
from challenges.interface import VulboxTarget


def test_restart_uses_short_exec_calls_while_the_build_runs_in_background(
    monkeypatch,
) -> None:
    commands = []
    polls = iter(["running", "done:0"])

    def execute(_host, command):
        commands.append(command)
        if "nohup setsid" in command:
            return 0, "4321\n"
        if "printf done:" in command:
            return 0, next(polls)
        if "tail -c 500" in command:
            return 0, "reload complete"
        raise AssertionError(command)

    monkeypatch.setattr(restart_handler.secrets, "token_hex", lambda _size: "ab" * 8)
    monkeypatch.setattr(restart_handler.time, "sleep", lambda _seconds: None)
    result = restart_handler.GrafanaRestartHandler().run(VulboxTarget(
        host="team1_prod",
        ports={"service": 3000},
        meta={"exec_in_container": execute},
    ))
    assert result.passed
    assert result.children[0].passed
    assert result.detail == "reload complete"
    assert len(commands) == 4
    assert "nohup setsid bash -c" in commands[0]
    assert "/arena/restart.sh" in commands[0]


def test_restart_rejects_a_worker_that_disappears_without_status(monkeypatch) -> None:
    def execute(_host, command):
        if "nohup setsid" in command:
            return 0, "4321\n"
        if "printf done:" in command:
            return 0, "lost"
        return 0, ""

    monkeypatch.setattr(restart_handler.secrets, "token_hex", lambda _size: "cd" * 8)
    result = restart_handler.GrafanaRestartHandler().run(VulboxTarget(
        host="team1_prod",
        ports={"service": 3000},
        meta={"exec_in_container": execute},
    ))
    assert not result.passed
    assert result.detail == "restart worker exited without status"
