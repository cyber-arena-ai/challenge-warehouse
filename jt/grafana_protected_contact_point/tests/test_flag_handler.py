from __future__ import annotations

import base64
import hashlib
import json

import pytest

from challenges.interface import FlagObservation, ObservationStatus, VulboxTarget
from challenges.grafana_protected_contact_point._ids import (
    STORE_COMMAND,
    STORE_PROTECTED_RECEIVER,
    contact_details,
    pack_handle,
    unpack_handle,
)
from challenges.grafana_protected_contact_point import flag_handler as handler_module
from challenges.grafana_protected_contact_point.flag_handler import GrafanaFlagHandler


ROUND_SEED = "01" * 32
TARGET = VulboxTarget(
    host="prod",
    ports={"service": 3000},
    meta={"round_context_seed": ROUND_SEED},
)
FLAG = "FLAG{round-proof}"
OPERATION = handler_module._round_value(
    TARGET,
    STORE_COMMAND,
    f"operation-id\0{handler_module._group_id(TARGET)}",
    32,
)


def test_round_group_targets_and_caches_are_stable_separated_and_rotate() -> None:
    retry = VulboxTarget(
        host="prod", ports={"service": 3000},
        meta={"round_context_seed": ROUND_SEED},
    )
    rotated = VulboxTarget(
        host="prod", ports={"service": 3000},
        meta={"round_context_seed": "02" * 32},
    )
    def context(target: VulboxTarget) -> list[str]:
        group = handler_module._group_id(target)
        return [
            group,
            handler_module._round_value(
                target, STORE_COMMAND, f"operation-id\0{group}", 32
            ),
            GrafanaFlagHandler._cache_key(target, STORE_COMMAND),
            handler_module._round_value(
                target, STORE_PROTECTED_RECEIVER, f"target-id\0{group}"
            ),
            handler_module._round_value(
                target, STORE_PROTECTED_RECEIVER, f"integrity-anchor\0{group}"
            ),
            GrafanaFlagHandler._cache_key(target, STORE_PROTECTED_RECEIVER),
        ]

    first = context(TARGET)
    assert first == context(retry)
    assert len(set(first)) == len(first)
    assert all(a != b for a, b in zip(first, context(rotated), strict=True))


def test_round_context_seed_is_required() -> None:
    target = VulboxTarget(host="prod", ports={"service": 3000}, meta={})
    with pytest.raises(RuntimeError, match="round context seed unavailable"):
        handler_module._group_id(target)


def command_handle(
    token: str = FLAG, operation: str = OPERATION,
) -> str:
    return pack_handle({
        "store": STORE_COMMAND, "target": operation, "token": token,
    })


def anchor_name(target: VulboxTarget = TARGET, token: str = FLAG) -> str:
    group = handler_module._group_id(target)
    material = handler_module._round_value(
        target, STORE_PROTECTED_RECEIVER, f"integrity-anchor\0{group}"
    )
    return handler_module._anchor_name(token, material)


def test_fresh_execute_identity_is_cached_before_generation_write(monkeypatch) -> None:
    handler = GrafanaFlagHandler()
    events: list[str] = []
    monkeypatch.setattr(handler, "_cached", lambda *_args: None)
    monkeypatch.setattr(handler, "_cache", lambda *_args: events.append("cache"))
    handle = handler._prepare_command(TARGET, FLAG)

    assert events == ["cache"]
    assert unpack_handle(handle)["token"] == FLAG

    monkeypatch.setattr(
        handler, "_write_command_objective", lambda *_args: events.append("write")
    )
    monkeypatch.setattr(
        handler,
        "retrieve",
        lambda *_args, **_kwargs: FlagObservation(
            ObservationStatus.PRESENT, value=FLAG
        ),
    )
    handler._converge_command(TARGET, handle)
    assert events == ["cache", "write"]


def test_cached_execute_placement_repairs_same_identity(monkeypatch) -> None:
    handler = GrafanaFlagHandler()
    handle = command_handle()
    writes: list[tuple[str, str]] = []
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)
    monkeypatch.setattr(
        handler,
        "_write_command_objective",
        lambda _target, op, value: writes.append((op, value)),
    )
    monkeypatch.setattr(
        handler,
        "retrieve",
        lambda *_args, **_kwargs: FlagObservation(
            ObservationStatus.PRESENT, value=FLAG
        ),
    )

    assert handler._prepare_command(TARGET, FLAG) == handle
    handler._converge_command(TARGET, handle)
    assert writes == [(OPERATION, FLAG)]


def test_command_writes_are_isolated_by_operation(monkeypatch) -> None:
    commands: list[str] = []
    handler = GrafanaFlagHandler()
    monkeypatch.setattr(
        handler, "_exec",
        lambda _target, command: commands.append(command) or (0, ""),
    )

    first = "01" * 16
    second = "02" * 16
    handler._write_command_objective(TARGET, first, "first-token")
    handler._write_command_objective(TARGET, second, "second-token")

    assert f"/opt/arena/objective/{first}.new" in commands[0]
    assert f"/opt/arena/objective/{second}.new" in commands[1]
    assert "/opt/arena/objective/current" not in "".join(commands)


def test_irreconstructible_cached_execute_identity_fails_closed(monkeypatch) -> None:
    handler = GrafanaFlagHandler()
    handle = pack_handle({
        "store": STORE_COMMAND, "target": "invalid", "token": FLAG,
    })
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)

    with pytest.raises(RuntimeError, match="operation id is invalid"):
        handler._prepare_command(TARGET, FLAG)


def test_valid_but_non_derived_cached_execute_identity_fails_closed(
    monkeypatch,
) -> None:
    handler = GrafanaFlagHandler()
    handle = command_handle(operation="f" * 32)
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)

    with pytest.raises(RuntimeError, match="operation id is invalid"):
        handler._prepare_command(TARGET, FLAG)


def test_receiver_allocation_is_cached_before_native_placement(monkeypatch) -> None:
    handler = GrafanaFlagHandler()
    events: list[tuple[str, str]] = []
    cached_handles: list[str] = []
    monkeypatch.setattr(handler, "_cached", lambda *_args: None)

    def cache(_target, _store, _value, handle):
        cached_handles.append(handle)
        events.append(("cache", handle))

    def execute(_target, command):
        assert command.startswith("/arena/facility.py stage-receiver ")
        events.append(("facility", command))
        return 0, json.dumps({"org_id": 1, "anchor_id": 17})

    monkeypatch.setattr(handler, "_cache", cache)
    monkeypatch.setattr(handler, "_exec", execute)

    final = handler._plant_receiver(TARGET, FLAG, command_handle())

    assert [event[0] for event in events] == ["cache", "facility", "cache"]
    assert unpack_handle(cached_handles[0])["anchor_id"] is None
    assert unpack_handle(final)["anchor_id"] == 17
    request = json.loads(base64.b64decode(events[1][1].rsplit(" ", 1)[1]))
    assert request["uid"] == unpack_handle(final)["target"]
    assert request["anchor_name"] == anchor_name()
    assert request["uid"] not in request["anchor_name"]
    assert request["command_operation"] == OPERATION
    assert request["command_sha256"] == hashlib.sha256(
        FLAG.encode()
    ).hexdigest()


def test_integrity_anchor_is_target_unlinked_and_returns_exact_token(
    monkeypatch,
) -> None:
    first_uid, first_name, first_url = contact_details("1" * 64)
    second_uid, _, _ = contact_details("2" * 64)
    handle = pack_handle({
        "store": STORE_PROTECTED_RECEIVER,
        "target": first_uid,
        "token": FLAG,
        "name": first_name,
        "url": first_url,
        "org_id": 1,
        "anchor_id": 17,
        "anchor_name": anchor_name(),
    })
    monkeypatch.setattr(
        GrafanaFlagHandler,
        "_snapshot",
        lambda *_args: (b"database", None),
    )
    monkeypatch.setattr(
        handler_module,
        "service_account_name",
        lambda *_args: anchor_name(),
    )

    observation = GrafanaFlagHandler().retrieve(TARGET, handle, expected=FLAG)
    assert observation.status is ObservationStatus.PRESENT
    assert observation.value == FLAG
    assert first_uid not in anchor_name()
    assert second_uid not in anchor_name()
    assert anchor_name() == anchor_name()
    assert anchor_name(token="FLAG{other-round-proof}") != anchor_name()
    rotated = VulboxTarget(
        host="prod", ports={"service": 3000},
        meta={"round_context_seed": "02" * 32},
    )
    assert anchor_name(rotated) != anchor_name()


def test_cached_receiver_reconciles_without_rotating_identity(monkeypatch) -> None:
    handler = GrafanaFlagHandler()
    group = handler_module._group_id(TARGET)
    material = handler_module._round_value(
        TARGET, STORE_PROTECTED_RECEIVER, f"target-id\0{group}"
    )
    uid, name, url = contact_details(material)
    handle = pack_handle({
        "store": STORE_PROTECTED_RECEIVER,
        "target": uid,
        "token": FLAG,
        "name": name,
        "url": url,
        "org_id": 1,
        "anchor_id": 23,
        "anchor_name": anchor_name(),
    })
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)
    monkeypatch.setattr(
        handler,
        "_exec",
        lambda *_args: (0, json.dumps({"org_id": 1, "anchor_id": 23})),
    )
    monkeypatch.setattr(
        handler, "_cache", lambda *_args: (_ for _ in ()).throw(
            AssertionError("stable receiver handle must not be rewritten")
        )
    )

    assert handler._plant_receiver(TARGET, FLAG, command_handle()) == handle


def test_valid_but_non_derived_cached_receiver_identity_fails_closed(
    monkeypatch,
) -> None:
    handler = GrafanaFlagHandler()
    uid, name, url = contact_details("f" * 64)
    handle = pack_handle({
        "store": STORE_PROTECTED_RECEIVER,
        "target": uid,
        "token": FLAG,
        "name": name,
        "url": url,
        "org_id": 1,
        "anchor_id": 23,
        "anchor_name": anchor_name(),
    })
    monkeypatch.setattr(handler, "_cached", lambda *_args: handle)

    with pytest.raises(RuntimeError, match="cached receiver target is invalid"):
        handler._plant_receiver(TARGET, FLAG, command_handle())


def test_group_does_not_commit_receiver_when_command_placement_fails(
    monkeypatch,
) -> None:
    handler = GrafanaFlagHandler()
    events: list[str] = []
    receiver_handle = "receiver-handle"
    flags = {
        STORE_PROTECTED_RECEIVER: type(
            "StubFlag", (), {"value": "receiver-token"}
        )(),
        STORE_COMMAND: type("StubFlag", (), {"value": "command-token"})(),
    }
    monkeypatch.setattr(
        handler, "_prepare_command",
        lambda *_args: events.append("prepare") or command_handle(),
    )
    monkeypatch.setattr(
        handler, "_plant_receiver",
        lambda *_args: events.append("stage") or receiver_handle,
    )
    monkeypatch.setattr(
        handler, "_converge_command",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("command failed")),
    )
    monkeypatch.setattr(
        handler, "_commit_receiver", lambda *_args: events.append("commit")
    )

    with pytest.raises(RuntimeError, match="command failed"):
        handler.plant(TARGET, flags)

    assert events == ["prepare", "stage"]


def test_group_retries_same_staged_receiver_after_lost_commit_response(
    monkeypatch,
) -> None:
    handler = GrafanaFlagHandler()
    receiver_handle = "receiver-handle"
    command = "command-handle"
    events: list[str] = []
    journal = {"current": "published-group", "previous": None}
    flags = {
        STORE_PROTECTED_RECEIVER: type(
            "StubFlag", (), {"value": "receiver-token"}
        )(),
        STORE_COMMAND: type("StubFlag", (), {"value": "command-token"})(),
    }
    monkeypatch.setattr(
        handler, "_prepare_command",
        lambda *_args: events.append("prepare") or command,
    )
    monkeypatch.setattr(
        handler, "_plant_receiver",
        lambda *_args: events.append("stage") or receiver_handle,
    )
    monkeypatch.setattr(
        handler, "_converge_command",
        lambda *_args: events.append("command"),
    )
    commits = 0

    def commit(_target, receiver, command_generation):
        nonlocal commits
        assert receiver == receiver_handle
        assert command_generation == command
        commits += 1
        events.append("commit")
        journal.update(
            current=(receiver, command_generation), previous="published-group"
        )
        if commits == 1:
            raise RuntimeError("response lost")

    monkeypatch.setattr(handler, "_commit_receiver", commit)

    with pytest.raises(RuntimeError, match="response lost"):
        handler.plant(TARGET, flags)
    assert journal["previous"] == "published-group"
    assert handler.plant(TARGET, flags) == {
        STORE_PROTECTED_RECEIVER: receiver_handle,
        STORE_COMMAND: command,
    }
    assert journal["previous"] == "published-group"
    assert events == ["prepare", "stage", "command", "commit"] * 2


def test_lost_command_observation_keeps_published_generation_for_retry(
    monkeypatch,
) -> None:
    handler = GrafanaFlagHandler()
    old_operation = "01" * 16
    new_command = command_handle("command-token", "02" * 16)
    receiver_handle = "receiver-handle"
    generations = {old_operation: "old-command-token"}
    attempts = 0
    commits = 0
    flags = {
        STORE_PROTECTED_RECEIVER: type(
            "StubFlag", (), {"value": "receiver-token"}
        )(),
        STORE_COMMAND: type("StubFlag", (), {"value": "command-token"})(),
    }
    monkeypatch.setattr(handler, "_prepare_command", lambda *_args: new_command)
    monkeypatch.setattr(handler, "_plant_receiver", lambda *_args: receiver_handle)

    def converge(_target, handle):
        nonlocal attempts
        attempts += 1
        payload = unpack_handle(handle)
        generations[str(payload["target"])] = str(payload["token"])
        if attempts == 1:
            raise RuntimeError("observation response lost")

    def commit(*_args):
        nonlocal commits
        commits += 1

    monkeypatch.setattr(handler, "_converge_command", converge)
    monkeypatch.setattr(handler, "_commit_receiver", commit)

    with pytest.raises(RuntimeError, match="observation response lost"):
        handler.plant(TARGET, flags)
    assert generations[old_operation] == "old-command-token"
    assert commits == 0

    placed = handler.plant(TARGET, flags)
    assert placed[STORE_COMMAND] == new_command
    assert generations == {
        old_operation: "old-command-token", "02" * 16: "command-token",
    }
    assert attempts == 2 and commits == 1


def test_malformed_existing_cache_is_not_silently_rotated(monkeypatch) -> None:
    handler = GrafanaFlagHandler()
    monkeypatch.setattr(handler, "_exec", lambda *_args: (0, "not-a-handle"))

    with pytest.raises(RuntimeError, match="cached command plant state is invalid"):
        handler._cached(TARGET, STORE_COMMAND, FLAG)


def test_combined_principal_batch_is_order_indistinguishable(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    batches: list[dict] = []

    def execute(_host: str, command: str):
        document = json.loads(base64.b64decode(command.rsplit(" ", 1)[1]))
        batches.append(document)
        return 0, json.dumps({
            "users": len(document["users"]),
            "contacts": len(document["contacts"]),
        })

    target = VulboxTarget(
        host="prod", ports={},
        meta={"team_id": "victim", "exec_in_container": execute},
    )
    principals = GrafanaFlagHandler().provision_principals(
        target, {"attacker-b": "02" * 32, "attacker-a": "01" * 32}
    )

    assert set(principals) == {"attacker-a", "attacker-b"}
    users = batches[0]["users"]
    assert [row["username"] for row in users] == sorted(
        row["username"] for row in users
    )
    assert {row["role"] for row in users} == {"Editor", "Admin"}
    assert all("checker" not in row["username"] for row in users)
