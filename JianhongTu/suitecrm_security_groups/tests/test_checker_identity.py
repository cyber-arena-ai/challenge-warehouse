from __future__ import annotations

import re

import pytest

from challenges.interface import VulboxTarget
from challenges.suitecrm_security_groups.checker_identity import (
    CHECKER_POOL_SIZE,
    checker_setup,
)


def target(team_id: str) -> VulboxTarget:
    return VulboxTarget(host="prod", ports={"service": 8080}, meta={"team_id": team_id})


def test_checker_identities_are_victim_specific_and_match_attacker_shape(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    first = checker_setup(target("victim-a"))
    repeated = checker_setup(target("victim-a"))
    second = checker_setup(target("victim-b"))

    assert first == repeated
    assert first != second
    assert first["ordinary"] != first["guarded"]
    principals = first["ordinary"] + first["guarded"]
    assert len(first["ordinary"]) == CHECKER_POOL_SIZE
    assert len(first["guarded"]) == CHECKER_POOL_SIZE
    assert len({principal[0] for principal in principals}) == 2 * CHECKER_POOL_SIZE
    for username, password, group in principals:
        assert re.fullmatch(r"arena_[0-9a-f]{16}", username)
        assert re.fullmatch(r"S7![0-9a-f]{32}", password)
        assert re.fullmatch(r"Arena partition [0-9a-f]{8}", group)
    assert re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        first["client_id"],
    )


def test_checker_identities_use_private_process_context_in_standalone_verifier(
    monkeypatch,
) -> None:
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    first = checker_setup(target("check"))
    repeated = checker_setup(target("check"))

    assert first == repeated


def test_checker_identities_require_private_facility_context_in_game(
    monkeypatch,
) -> None:
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        checker_setup(target("victim"))
