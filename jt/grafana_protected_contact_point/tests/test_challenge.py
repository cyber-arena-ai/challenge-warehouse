from __future__ import annotations

import pytest

from challenges.interface import VulboxTarget
from challenges.grafana_protected_contact_point.challenge import (
    GrafanaProtectedContactPointChallenge,
)


TARGET = VulboxTarget(host="prod", ports={"service": 3000})


def test_initial_start_allows_parallel_cold_cache_hydration() -> None:
    commands: list[str] = []

    def execute(host: str, command: str) -> tuple[int, str]:
        assert host == "prod"
        commands.append(command)
        return 0, ""

    GrafanaProtectedContactPointChallenge().initial_start(TARGET, execute)

    assert len(commands) == 1
    assert "seq 1 3000" in commands[0]
    assert "/run/grafana/arena.ready" in commands[0]


def test_initial_start_rejects_missing_readiness() -> None:
    with pytest.raises(RuntimeError, match="setup did not become ready"):
        GrafanaProtectedContactPointChallenge().initial_start(
            TARGET, lambda *_args: (1, "")
        )
