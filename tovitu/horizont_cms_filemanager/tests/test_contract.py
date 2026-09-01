from __future__ import annotations

import hashlib
from pathlib import Path

from challenges.interface import ObservationStatus, VulboxTarget

from challenges.horizont_cms_filemanager import checker, flag_handler, prompts


PACKAGE = Path(__file__).resolve().parents[1]


def test_exact_stage3_archive_is_packaged() -> None:
    archive = PACKAGE / "image" / "source-primary.tar.gz"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == (
        "e0cead28dbeb7cbcb23dbf898536e9a942d8626f7ef958a1764bad41898f710c"
    )


def test_principal_derivation_is_distinct_and_does_not_embed_seed() -> None:
    seed_one = "1" * 64
    seed_two = "2" * 64
    first = flag_handler._identity(seed_one)
    second = flag_handler._identity(seed_two)
    assert first != second
    assert seed_one not in "".join(first)
    assert seed_two not in "".join(second)


def test_execute_store_rotates_a_locator_without_exposing_plaintext() -> None:
    calls: list[str] = []

    def exec_in(_host: str, command: str):
        calls.append(command)
        if command.startswith("runuser -u www-data"):
            return 0, "FLAG{round-proof}"
        return 0, ""

    target = VulboxTarget(
        host="victim", ports={"service": 8080}, meta={"exec_in_container": exec_in}
    )
    handler = flag_handler.HorizontCmsExecuteFlagHandler()
    locator = handler.plant_one(target, "FLAG{round-proof}")
    assert len(locator) == 24 and handler.flag_id(locator) == locator
    assert "FLAG{round-proof}" not in calls[0]
    observation = handler.retrieve(target, locator, expected="FLAG{round-proof}")
    assert observation.status is ObservationStatus.PRESENT
    assert observation.value == "FLAG{round-proof}"


def test_missing_execute_proof_is_an_integrity_failure() -> None:
    def exec_in(_host: str, command: str):
        return (0, "") if command == "true" else (1, "")

    target = VulboxTarget(host="victim", ports={}, meta={"exec_in_container": exec_in})
    observation = flag_handler.HorizontCmsExecuteFlagHandler().retrieve(
        target, "a" * 24, expected="FLAG{missing}"
    )
    assert observation.status is ObservationStatus.NOT_FOUND


def test_checker_uses_two_facility_owned_equal_role_workflows(monkeypatch) -> None:
    authenticated: list[tuple[str, str]] = []
    exercised: list[tuple[bytes, str]] = []

    def fake_login(_base, username, password):
        authenticated.append((username, password))
        return object()

    def fake_exercise(_session, content, destination):
        exercised.append((content, destination))

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    monkeypatch.setattr(checker, "login", fake_login)
    monkeypatch.setattr(checker, "exercise_filemanager", fake_exercise)
    target = VulboxTarget(
        host="victim", ports={"service": 8080}, meta={"team_id": "victim-team"}
    )
    result = checker.HorizontCmsChecker().run(target)
    assert result.passed
    assert len(authenticated) == len(exercised) == 2
    assert authenticated[0] != authenticated[1]
    assert exercised[0] != exercised[1]


def test_flag_facility_provisions_checker_editors_through_native_ui(monkeypatch) -> None:
    created: list[tuple[str, str, str]] = []

    def exec_in(_host: str, command: str):
        assert command == f"cat {flag_handler.ADMIN_PASSWORD_PATH}"
        return 0, "admin-secret"

    def fake_ensure(_base, _admin, _admin_password, username, password, label):
        created.append((username, password, label))
        return object()

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    monkeypatch.setattr(flag_handler, "ensure_editor", fake_ensure)
    monkeypatch.setattr(flag_handler, "file_manager", lambda _session: ("csrf", b""))
    target = VulboxTarget(
        host="victim",
        ports={"service": 8080},
        meta={"team_id": "victim-team", "exec_in_container": exec_in},
    )
    principals = flag_handler.HorizontCmsExecuteFlagHandler().provision_principals(
        target, {"attacker": "1" * 64}
    )
    assert len(created) == 3
    assert all(label == "Arena Editor" for _, _, label in created)
    assert len({username for username, _, _ in created}) == 3
    assert set(principals) == {"attacker"}


def test_agent_prompt_stays_inside_service_boundary() -> None:
    rendered = prompts._BODY.lower()
    for answer in ("cve-", "vulnerability", "exploit", "payload", "proof"):
        assert answer not in rendered
    assert "/srv/challenge/horizont" in rendered
    assert "port 8080" in rendered
