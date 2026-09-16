from __future__ import annotations

import pytest

from challenges.caddy_nextcloud_sso.cohort import (
    open_issued_cohort,
    seal_issued_cohort,
)
from challenges.interface import VulboxTarget


def target(team_id: str = "victim-team") -> VulboxTarget:
    return VulboxTarget(
        host="victim", ports={"service": 8080}, meta={"team_id": team_id},
    )


def accounts() -> list[list[str]]:
    return [
        ["user" + "b" * 16, "C1!" + "2" * 32],
        ["user" + "a" * 16, "C1!" + "1" * 32],
    ]


def test_issued_cohort_is_sorted_nonempty_and_team_bound(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    sealed = seal_issued_cohort(target(), accounts())

    assert open_issued_cohort(target(), sealed) == (
        ("user" + "a" * 16, "C1!" + "1" * 32),
        ("user" + "b" * 16, "C1!" + "2" * 32),
    )
    with pytest.raises(RuntimeError, match="untrusted"):
        open_issued_cohort(target("other-team"), sealed)


def test_issued_cohort_rejects_empty_tampered_and_untrusted_material(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    with pytest.raises(RuntimeError, match="empty"):
        seal_issued_cohort(target(), [])

    sealed = seal_issued_cohort(target(), accounts())
    replacement = "0" if sealed[-1] != "0" else "1"
    with pytest.raises(RuntimeError, match="untrusted"):
        open_issued_cohort(target(), sealed[:-1] + replacement)

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "different-token")
    with pytest.raises(RuntimeError, match="untrusted"):
        open_issued_cohort(target(), sealed)
