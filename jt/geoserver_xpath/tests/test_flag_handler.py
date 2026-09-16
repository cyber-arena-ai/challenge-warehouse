from __future__ import annotations

import base64
import json

import pytest

from challenges.interface import Flag, FlagObservation, ObservationStatus, VulboxTarget
from challenges.geoserver_xpath import flag_handler
from challenges.geoserver_xpath._ids import (
    STORE_COMMAND,
    STORE_PROTECTED_FEATURE,
    feature_category,
    feature_target,
    open_issued_cohort,
    pack_handle,
    unpack_handle,
)
from challenges.geoserver_xpath.flag_handler import GeoServerFlagHandler
from challenges.geoserver_xpath.image.road_protocol import valid_geometry


TARGET = VulboxTarget(host="prod", ports={}, meta={})
FLAG = "FLAG{round-proof}"
ROUND_SEED = "11" * 32
CONTEXT = flag_handler._round_context(ROUND_SEED)


def test_round_context_is_stable_separated_and_rotates() -> None:
    same = flag_handler._round_context(ROUND_SEED)
    rotated = flag_handler._round_context("22" * 32)

    assert same == CONTEXT
    assert rotated != CONTEXT
    assert CONTEXT["command_cache"] != CONTEXT["feature_context"]
    assert CONTEXT["command_target"] != str(CONTEXT["command_cache"])[:32]
    categories = CONTEXT["feature_categories"]
    assert isinstance(categories, list) and len(categories) == 64
    assert len(set(categories)) == 64
    assert all(1 <= category <= 9999 for category in categories)
    assert valid_geometry(CONTEXT["feature_geometry"])


def test_feature_target_identity_distinguishes_nonadjacent_rounds() -> None:
    context_a = flag_handler._round_context("11" * 32)
    context_b = flag_handler._round_context("22" * 32)
    category = 17

    targets = [
        feature_target(category, str(context["feature_context"]))
        for context in (context_a, context_b, context_a)
    ]

    assert targets[0] == targets[2]
    assert targets[0] != targets[1]
    assert [feature_category(target) for target in targets] == [17, 17, 17]


def test_round_context_does_not_depend_on_proof_values(monkeypatch) -> None:
    seen: list[tuple[str, object]] = []
    handler = GeoServerFlagHandler()
    monkeypatch.setattr(
        handler, "_plant_command",
        lambda _target, _value, cache, operation: (
            seen.append((cache, operation)) or "command-handle"
        ),
    )
    monkeypatch.setattr(
        handler, "_plant_feature",
        lambda _target, _value, context: (
            seen.append((str(context["feature_context"]), context["feature_geometry"]))
            or "feature-handle"
        ),
    )
    target = VulboxTarget(
        host="prod", ports={}, meta={"round_context_seed": ROUND_SEED}
    )

    for suffix in ("one", "two"):
        handler.plant(target, {
            STORE_COMMAND: Flag(f"FLAG{{command-{suffix}}}"),
            STORE_PROTECTED_FEATURE: Flag(f"FLAG{{feature-{suffix}}}"),
        })

    assert seen[:2] == seen[2:]


def test_round_context_seed_is_required() -> None:
    with pytest.raises(ValueError, match="round context seed"):
        flag_handler._round_context("")


def test_fresh_execute_identity_is_cached_before_backing_write(monkeypatch) -> None:
    handler = GeoServerFlagHandler()
    events: list[str] = []
    monkeypatch.setattr(handler, "_cached", lambda *_args: None)
    monkeypatch.setattr(handler, "_cache", lambda *_args: events.append("cache"))
    monkeypatch.setattr(
        handler, "_write_command_objective",
        lambda *_args: events.append("write"),
    )

    handle = handler._plant_command(
        TARGET, FLAG, str(CONTEXT["command_cache"]),
        str(CONTEXT["command_target"]),
    )

    assert events == ["cache", "write"]
    assert unpack_handle(handle)["flag"] == FLAG


def test_cached_execute_placement_repairs_same_identity(monkeypatch) -> None:
    handler = GeoServerFlagHandler()
    operation = "ab" * 16
    handle = pack_handle({
        "store": STORE_COMMAND,
        "target": operation,
        "flag": FLAG,
    })
    writes: list[tuple[str, str]] = []
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)
    monkeypatch.setattr(
        handler, "_write_command_objective",
        lambda _target, op, value: writes.append((op, value)),
    )
    monkeypatch.setattr(
        handler,
        "retrieve",
        lambda *_args, **_kwargs: FlagObservation(
            ObservationStatus.PRESENT, value=FLAG
        ),
    )

    assert handler._plant_command(
        TARGET, FLAG, str(CONTEXT["command_cache"]), operation
    ) == handle
    assert writes == [(operation, FLAG)]


def test_irreconstructible_cached_execute_identity_fails_closed(
    monkeypatch,
) -> None:
    handler = GeoServerFlagHandler()
    handle = pack_handle({
        "store": STORE_COMMAND,
        "target": "invalid",
        "flag": FLAG,
    })
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)

    with pytest.raises(RuntimeError, match="operation id is invalid"):
        handler._plant_command(
            TARGET, FLAG, str(CONTEXT["command_cache"]), "ab" * 16
        )


def test_combined_principal_batch_is_order_indistinguishable(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    initialized: list[str] = []
    monkeypatch.setattr(
        flag_handler, "initialize_journal",
        lambda _client, _key, team_id: initialized.append(team_id),
    )
    batches: list[list[dict[str, object]]] = []
    sealed_cohorts: list[str] = []

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        if " store-issued-cohort " in command:
            sealed_cohorts.append(command.rsplit(" ", 1)[1])
            return 0, "OK"
        encoded = command.rsplit(" ", 1)[1]
        users = json.loads(base64.b64decode(encoded))
        batches.append(users)
        return 0, json.dumps({"count": len(users)})

    target = VulboxTarget(
        host="prod",
        ports={"service": 8080},
        meta={"team_id": "victim", "exec_in_container": exec_in},
    )
    seeds = {"attacker-b": "02" * 32, "attacker-a": "01" * 32}

    principals = GeoServerFlagHandler().provision_principals(target, seeds)

    assert set(principals) == set(seeds)
    usernames = [str(user["username"]) for user in batches[0]]
    assert usernames == sorted(usernames)
    assert open_issued_cohort(sealed_cohorts[0]) == (
        ("arena_" + "01" * 8, "Gs!" + "01" * 16),
        ("arena_" + "02" * 8, "Gs!" + "02" * 16),
    )
    assert initialized == ["victim", "victim:objective-placement"]


def test_feature_placement_is_bracketed_by_native_journal_trace(
    monkeypatch,
) -> None:
    events: list[str] = []
    trace = flag_handler.JournalEntry(
        "ABCDEFG", 1_800_000_000, flag_handler.PHASE_INTENT
    )

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(
        flag_handler, "road_lifecycle_principals",
        lambda _team_id: (
            ("arena_ordinary", "ordinary-secret"),
            ("arena_guarded", "guarded-secret"),
        ),
    )
    monkeypatch.setattr(flag_handler, "GeoServerClient", lambda *_args: object())
    monkeypatch.setattr(
        flag_handler, "begin_placement_trace",
        lambda *_args, **_kwargs: (events.append("journal-intent") or trace),
    )
    monkeypatch.setattr(
        flag_handler, "finish_placement_trace",
        lambda *args: (events.append("journal-active") or args[3]),
    )
    monkeypatch.setattr(
        flag_handler, "complete_placement_trace",
        lambda *args: (events.append("journal-complete") or args[3]),
    )

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        if "pending-feature" in command:
            events.append("pending")
            return 44, ""
        if "plant-feature" in command:
            assert "arena_guarded arena_ordinary ABCDEFG 1800000000" in command
            request = json.loads(base64.b64decode(command.split()[2]))
            assert request == {
                "context": CONTEXT["feature_context"],
                "value": FLAG,
                "categories": CONTEXT["feature_categories"],
                "geometry": CONTEXT["feature_geometry"],
            }
            events.append("objective")
            return 0, json.dumps({
                "category": 17,
                "retire_nonce": "",
                "retire_born_at": 0,
            })
        if "finalize-feature" in command:
            assert command.endswith(" arena_guarded")
            events.append("finalize")
            return 0, "17\n"
        if "clear-feature" in command:
            assert command.endswith(" ABCDEFG 1800000000")
            events.append("clear")
            return 0, ""
        raise AssertionError(command)

    target = VulboxTarget(
        host="prod",
        ports={"service": 8080},
        meta={"team_id": "victim", "exec_in_container": exec_in},
    )
    handle = GeoServerFlagHandler()._plant_feature(target, FLAG, CONTEXT)

    assert feature_category(unpack_handle(handle)["target"]) == 17
    assert events == [
        "pending", "journal-intent", "objective", "journal-active",
        "finalize", "journal-complete", "clear",
    ]


def test_feature_placement_without_game_material_skips_trace(monkeypatch) -> None:
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    monkeypatch.setattr(
        flag_handler,
        "begin_placement_trace",
        lambda *_args: pytest.fail("build-mode placement must not trace"),
    )

    target = VulboxTarget(
        host="prod",
        ports={"service": 8080},
        meta={
            "team_id": "check",
            "exec_in_container": lambda *_args: (0, json.dumps({
                "category": 17,
                "retire_nonce": "",
                "retire_born_at": 0,
            })),
        },
    )

    handle = GeoServerFlagHandler()._plant_feature(target, FLAG, CONTEXT)

    assert feature_category(unpack_handle(handle)["target"]) == 17


def test_completed_feature_retry_returns_before_new_intent(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(
        flag_handler, "road_lifecycle_principals",
        lambda _team_id: (("ordinary", "one"), ("guarded", "two")),
    )
    monkeypatch.setattr(flag_handler, "GeoServerClient", lambda *_args: object())
    monkeypatch.setattr(
        flag_handler, "begin_placement_trace",
        lambda *_args, **_kwargs: pytest.fail("completed retry must not add intent"),
    )
    commands: list[str] = []

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        commands.append(command)
        assert "pending-feature" in command
        return 0, json.dumps({"complete": True, "category": 17})

    target = VulboxTarget(
        host="prod", ports={"service": 8080},
        meta={"team_id": "victim", "exec_in_container": exec_in},
    )
    handle = GeoServerFlagHandler()._plant_feature(target, FLAG, CONTEXT)

    assert feature_category(unpack_handle(handle)["target"]) == 17
    assert len(commands) == 1


def test_feature_retrieval_uses_the_shared_guarded_lifecycle_identity(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(
        flag_handler, "road_lifecycle_principals",
        lambda _team_id: (
            ("arena_ordinary", "ordinary-secret"),
            ("arena_guarded", "guarded-secret"),
        ),
    )
    commands: list[str] = []

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        commands.append(command)
        return 0, FLAG + "\n"

    target = VulboxTarget(
        host="prod", ports={"service": 8080},
        meta={"team_id": "victim", "exec_in_container": exec_in},
    )
    handle = pack_handle({
        "store": STORE_PROTECTED_FEATURE,
        "target": feature_target(17, str(CONTEXT["feature_context"])),
        "flag": FLAG,
    })

    observed = GeoServerFlagHandler().retrieve(target, handle, expected=FLAG)

    assert observed.status is ObservationStatus.PRESENT
    assert commands == ["/arena/facility.py read-feature 17 arena_guarded"]


def test_pending_feature_retry_finishes_exact_retirement_before_clear(
    monkeypatch,
) -> None:
    events: list[str] = []
    active = flag_handler.JournalEntry(
        "ABCDEFG", 1_800_000_000, "active"
    )
    retired = flag_handler.JournalEntry(
        "HIJKLMN", 1_799_999_900, flag_handler.PHASE_RECHECKED
    )
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(
        flag_handler, "road_lifecycle_principals",
        lambda _team_id: (
            ("arena_ordinary", "ordinary-secret"),
            ("arena_guarded", "guarded-secret"),
        ),
    )
    monkeypatch.setattr(flag_handler, "GeoServerClient", lambda *_args: object())

    def begin(*_args, **kwargs):
        assert kwargs["resume"] == flag_handler.JournalEntry(
            active.nonce, active.born_at, flag_handler.PHASE_INTENT
        )
        events.append("meta-intent-resume")
        return active

    def finish(*args):
        assert args[-1] == retired
        events.append("meta-active-delete")
        return args[3]

    def complete(*args):
        assert args[-1] == retired
        events.append("meta-remove")
        return args[3]

    monkeypatch.setattr(flag_handler, "begin_placement_trace", begin)
    monkeypatch.setattr(flag_handler, "finish_placement_trace", finish)
    monkeypatch.setattr(flag_handler, "complete_placement_trace", complete)

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        if "pending-feature" in command:
            events.append("pending")
            return 0, json.dumps({
                "complete": False,
                "same": True,
                "category": 17,
                "nonce": active.nonce,
                "born_at": active.born_at,
                "retire_nonce": retired.nonce,
                "retire_born_at": retired.born_at,
            })
        if "resume-feature" in command:
            assert command.endswith(" arena_guarded arena_ordinary")
            events.append("native-resume")
            return 0, json.dumps({
                "category": 17,
                "retire_nonce": retired.nonce,
                "retire_born_at": retired.born_at,
            })
        if "finalize-feature" in command:
            events.append("native-delete-absence")
            return 0, "17\n"
        if "clear-feature" in command:
            assert command.endswith(f" {active.nonce} {active.born_at}")
            events.append("pending-clear")
            return 0, ""
        raise AssertionError(command)

    target = VulboxTarget(
        host="prod", ports={"service": 8080},
        meta={"team_id": "victim", "exec_in_container": exec_in},
    )
    handle = GeoServerFlagHandler()._plant_feature(target, FLAG, CONTEXT)

    assert feature_category(unpack_handle(handle)["target"]) == 17
    assert events == [
        "pending", "meta-intent-resume", "native-resume",
        "meta-active-delete", "native-delete-absence", "meta-remove",
        "pending-clear",
    ]


def test_new_proof_drains_prior_pending_generation_before_new_intent(
    monkeypatch,
) -> None:
    events: list[str] = []
    prior = flag_handler.JournalEntry("ABCDEFG", 1_800_000_000, "active")
    fresh = flag_handler.JournalEntry(
        "HIJKLMN", 1_800_000_060, flag_handler.PHASE_INTENT
    )
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(
        flag_handler, "road_lifecycle_principals",
        lambda _team_id: (
            ("arena_ordinary", "ordinary-secret"),
            ("arena_guarded", "guarded-secret"),
        ),
    )
    monkeypatch.setattr(flag_handler, "GeoServerClient", lambda *_args: object())

    def begin(*_args, **kwargs):
        if "resume" in kwargs:
            events.append("meta-prior-intent")
            return prior
        events.append("meta-new-intent")
        return fresh

    def finish(*args):
        events.append(f"meta-{args[3].nonce}-active")
        return args[3]

    def complete(*_args):
        events.append("meta-retirement-complete")
        return _args[3]

    monkeypatch.setattr(flag_handler, "begin_placement_trace", begin)
    monkeypatch.setattr(flag_handler, "finish_placement_trace", finish)
    monkeypatch.setattr(flag_handler, "complete_placement_trace", complete)

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        if "pending-feature" in command:
            events.append("pending-prior")
            return 0, json.dumps({
                "complete": False,
                "same": False,
                "category": 17,
                "nonce": prior.nonce,
                "born_at": prior.born_at,
                "retire_nonce": "",
                "retire_born_at": 0,
            })
        if "resume-feature" in command:
            events.append("native-prior")
            return 0, json.dumps({
                "category": 17, "retire_nonce": "", "retire_born_at": 0,
            })
        if "plant-feature" in command:
            assert f"{fresh.nonce} {fresh.born_at}" in command
            events.append("native-new")
            return 0, json.dumps({
                "category": 22, "retire_nonce": "", "retire_born_at": 0,
            })
        if "finalize-feature" in command:
            events.append("native-retirement")
            return 0, ""
        if "clear-feature" in command:
            events.append("pending-clear")
            return 0, ""
        raise AssertionError(command)

    target = VulboxTarget(
        host="prod", ports={"service": 8080},
        meta={"team_id": "victim", "exec_in_container": exec_in},
    )
    handle = GeoServerFlagHandler()._plant_feature(target, FLAG, CONTEXT)

    assert feature_category(unpack_handle(handle)["target"]) == 22
    assert events == [
        "pending-prior", "meta-prior-intent", "native-prior",
        "meta-ABCDEFG-active", "native-retirement",
        "meta-retirement-complete", "pending-clear", "meta-new-intent",
        "native-new", "meta-HIJKLMN-active", "native-retirement",
        "meta-retirement-complete", "pending-clear",
    ]
