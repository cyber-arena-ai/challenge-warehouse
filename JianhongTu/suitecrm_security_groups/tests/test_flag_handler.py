from __future__ import annotations

import base64
import json
import re

import pytest

from challenges.interface import Flag, ObservationStatus, VulboxTarget
from challenges.suitecrm_security_groups import flag_handler
from challenges.suitecrm_security_groups._ids import (
    STORE_COMMAND,
    STORE_PRIVATE_NOTE,
    unpack_handle,
)
from challenges.suitecrm_security_groups.flag_handler import (
    CACHE_DIR,
    OBJECTIVE_DIR,
    SuiteCrmFlagHandler,
)

COMMAND_FLAG = "FLAG{current-command-proof}"
NOTE_FLAG = "FLAG{current-note-proof}"
NEXT_COMMAND_FLAG = "FLAG{next-command-proof}"
NEXT_NOTE_FLAG = "FLAG{next-note-proof}"
FINAL_COMMAND_FLAG = "FLAG{final-command-proof}"
FINAL_NOTE_FLAG = "FLAG{final-note-proof}"
ROUND_SEED = "1" * 64
NEXT_ROUND_SEED = "2" * 64
FINAL_ROUND_SEED = "3" * 64
ROUND_CONTEXT = flag_handler._round_context(ROUND_SEED)
NEXT_ROUND_CONTEXT = flag_handler._round_context(NEXT_ROUND_SEED)
FINAL_ROUND_CONTEXT = flag_handler._round_context(FINAL_ROUND_SEED)
NOTE_ID = ROUND_CONTEXT["note"]
NEXT_NOTE_ID = NEXT_ROUND_CONTEXT["note"]
FINAL_NOTE_ID = FINAL_ROUND_CONTEXT["note"]
OPERATION = ROUND_CONTEXT["operation"]
NEXT_OPERATION = NEXT_ROUND_CONTEXT["operation"]
FINAL_OPERATION = FINAL_ROUND_CONTEXT["operation"]
GROUP_FIELDS = (
    "group", "note", "operation", "note_digest", "command_digest",
    "note_cache", "command_cache",
)


def command_path(operation: str) -> str:
    return f"{OBJECTIVE_DIR}/{operation}"


class FakeContainer:
    def __init__(self):
        self.files: dict[str, str] = {}
        self.note_state = {
            "current": None,
            "previous": None,
            "pending": None,
            "retiring": None,
        }
        self.commands: list[str] = []
        self.fail_before_once: set[str] = set()
        self.fail_after_once: set[str] = set()

    def _result(self, operation: str, action) -> tuple[int, str]:
        if operation in self.fail_before_once:
            self.fail_before_once.remove(operation)
            return 1, ""
        action()
        if operation in self.fail_after_once:
            self.fail_after_once.remove(operation)
            return 1, ""
        return 0, "OK\n"

    def __call__(self, _host: str, command: str) -> tuple[int, str]:
        self.commands.append(command)
        if command.startswith(
            "su-exec www-data:www-data /usr/local/bin/suitecrm-objective "
        ):
            operation = command.rsplit(" ", 1)[1]
            value = self.files.get(command_path(operation))
            if value is None:
                return 1, ""
            lines = value.splitlines()
            if len(lines) != 2 or lines[0] != operation:
                return 1, ""
            return 0, lines[1] + "\n"
        if command.startswith("if [ ! -e "):
            path = command.split("if [ ! -e ", 1)[1].split(" ]", 1)[0]
            if path not in self.files:
                return 44, ""
            return (0, self.files[path]) if self.files[path] else (45, "")
        if command.startswith("install -d") and CACHE_DIR in command:
            encoded = re.search(r"printf %s (\S+) \| base64 -d > (\S+)\.new", command)
            assert encoded
            self.files[encoded.group(2)] = base64.b64decode(encoded.group(1)).decode()
            return 0, ""
        if command.startswith("install -d") and OBJECTIVE_DIR in command:
            encoded = re.search(r"printf %s (\S+) \| base64 -d > (\S+)\.new", command)
            assert encoded
            return self._result(
                "publish-command",
                lambda: self.files.__setitem__(
                    encoded.group(2), base64.b64decode(encoded.group(1)).decode()
                ),
            )
        if command == "/arena/facility.py read-group-state":
            return 0, json.dumps(self.note_state) + "\n"
        if command.startswith("/arena/facility.py record-pending "):
            fields = command.split()
            assert len(fields) == 2 + 2 * len(GROUP_FIELDS)
            requested = dict(zip(
                GROUP_FIELDS,
                fields[2:2 + len(GROUP_FIELDS)],
                strict=True,
            ))
            expected = (
                None
                if fields[2 + len(GROUP_FIELDS):] == ["NONE"] * len(GROUP_FIELDS)
                else dict(zip(
                    GROUP_FIELDS,
                    fields[2 + len(GROUP_FIELDS):],
                    strict=True,
                ))
            )

            def record() -> None:
                assert self.note_state["current"] == expected
                assert not self.note_state["retiring"]
                assert self.note_state["pending"] in (None, requested)
                self.note_state["pending"] = requested

            return self._result("record-pending", record)
        if command.startswith("/arena/facility.py promote-pending "):
            fields = command.split()
            assert len(fields) == 2 + len(GROUP_FIELDS)
            requested = dict(zip(GROUP_FIELDS, fields[2:], strict=True))

            def promote() -> None:
                assert self.note_state["pending"] == requested
                old = self.note_state["current"]
                older = self.note_state["previous"]
                self.note_state["current"] = requested
                self.note_state["previous"] = old
                self.note_state["pending"] = None
                self.note_state["retiring"] = older

            return self._result("promote-pending", promote)
        if command.startswith("/arena/facility.py finish-retirement "):
            fields = command.split()
            assert len(fields) == 2 + len(GROUP_FIELDS)
            requested = dict(zip(GROUP_FIELDS, fields[2:], strict=True))
            operation_id = requested["operation"]

            def finish() -> None:
                assert self.note_state["retiring"] == requested
                self.files.pop(command_path(operation_id), None)
                self.files.pop(command_path(operation_id) + ".new", None)
                self.note_state["retiring"] = None

            return self._result("finish-retirement", finish)
        return 0, ""


class FakeApi:
    user_id = "guarded-user"

    def __init__(self):
        self.records: dict[str, dict[str, str]] = {}
        self.fail_create_once = False
        self.fail_delete_after_once = False
        self.deletions: list[str] = []

    def set_entry(self, module: str, fields: dict[str, str]) -> str:
        assert module == "Notes"
        record_id = fields.get("id")
        assert record_id is not None
        if fields.get("deleted") == "1":
            self.records.pop(record_id, None)
            self.deletions.append(record_id)
            if self.fail_delete_after_once:
                self.fail_delete_after_once = False
                raise RuntimeError("simulated lost delete response")
        elif fields.get("new_with_id") == "1" and record_id not in self.records:
            if self.fail_create_once:
                self.fail_create_once = False
                raise RuntimeError("simulated create interruption")
            self.records[record_id] = {"id": record_id, **fields}
        elif record_id in self.records:
            self.records[record_id] = {"id": record_id, **fields}
        return record_id

    def get_entry(self, module: str, record_id: str, _fields) -> list[dict[str, str]]:
        assert module == "Notes"
        return [self.records.get(record_id, {"id": record_id})]


def runtime(
    container: FakeContainer, seed: str = ROUND_SEED,
) -> VulboxTarget:
    return VulboxTarget(
        host="prod",
        ports={"service": 8080},
        meta={
            "exec_in_container": container,
            "team_id": "victim",
            "round_context_seed": seed,
        },
    )


def flags(command: str = COMMAND_FLAG, note: str = NOTE_FLAG) -> dict[str, Flag]:
    return {
        STORE_COMMAND: Flag(value=command),
        STORE_PRIVATE_NOTE: Flag(value=note),
    }


def handler_with_ids(monkeypatch, api: FakeApi) -> SuiteCrmFlagHandler:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    handler = SuiteCrmFlagHandler()
    monkeypatch.setattr(handler, "_guarded_api", lambda _target, **_kwargs: api)
    return handler


def settle_first_group(
    handler: SuiteCrmFlagHandler, container: FakeContainer
) -> dict[str, str]:
    placed = dict(handler.plant(runtime(container), flags()))
    assert container.files[command_path(OPERATION)] == f"{OPERATION}\n{COMMAND_FLAG}\n"
    current = container.note_state["current"]
    assert current is not None
    assert current["group"] == ROUND_CONTEXT["group"]
    assert current["note"] == NOTE_ID
    assert current["operation"] == OPERATION
    assert current["note_cache"] == ROUND_CONTEXT["note_cache"]
    assert current["command_cache"] == ROUND_CONTEXT["command_cache"]
    assert container.note_state["previous"] is None
    assert container.note_state["pending"] is None
    assert container.note_state["retiring"] is None
    return placed


def test_retry_reuses_handles_and_repairs_both_backing_states(monkeypatch) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    first = settle_first_group(handler, container)
    del container.files[command_path(OPERATION)]
    del api.records[NOTE_ID]

    repeated = handler.plant(runtime(container), flags())

    assert repeated == first
    assert container.files[command_path(OPERATION)] == f"{OPERATION}\n{COMMAND_FLAG}\n"
    assert api.records[NOTE_ID]["filename"] == NOTE_FLAG


def test_note_create_failure_preserves_the_published_group(monkeypatch) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    settle_first_group(handler, container)
    old_command = container.files[command_path(OPERATION)]
    api.fail_create_once = True

    with pytest.raises(RuntimeError, match="simulated create interruption"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    assert container.files[command_path(OPERATION)] == old_command
    assert container.note_state["current"]["note"] == NOTE_ID
    assert container.note_state["pending"]["note"] == NEXT_NOTE_ID
    assert NOTE_ID in api.records
    assert NEXT_NOTE_ID not in api.records


def test_pending_is_durable_before_note_mutation(monkeypatch) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    settle_first_group(handler, container)
    container.fail_before_once.add("record-pending")

    with pytest.raises(RuntimeError, match="journal persistence failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    assert container.note_state["pending"] is None
    assert NEXT_NOTE_ID not in api.records
    assert command_path(NEXT_OPERATION) not in container.files


def test_command_failure_preserves_old_group_then_retry_converges(monkeypatch) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    settle_first_group(handler, container)
    old_command = container.files[command_path(OPERATION)]
    container.fail_before_once.add("publish-command")

    with pytest.raises(RuntimeError, match="command objective placement failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    assert container.files[command_path(OPERATION)] == old_command
    assert command_path(NEXT_OPERATION) not in container.files
    assert container.note_state["current"]["note"] == NOTE_ID
    assert container.note_state["pending"]["note"] == NEXT_NOTE_ID
    assert NOTE_ID in api.records and NEXT_NOTE_ID in api.records

    placed = handler.plant(
        runtime(container, NEXT_ROUND_SEED), flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG)
    )
    assert unpack_handle(placed[STORE_COMMAND])["target"] == NEXT_OPERATION
    assert container.files[command_path(NEXT_OPERATION)] == (
        f"{NEXT_OPERATION}\n{NEXT_COMMAND_FLAG}\n"
    )
    assert container.files[command_path(OPERATION)] == old_command
    assert NOTE_ID in api.records
    assert container.note_state["current"]["note"] == NEXT_NOTE_ID
    assert container.note_state["previous"]["note"] == NOTE_ID
    assert container.note_state["retiring"] is None


def test_lost_command_response_resumes_group_and_preserves_predecessor(
    monkeypatch,
) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    first = settle_first_group(handler, container)
    container.fail_after_once.add("publish-command")

    with pytest.raises(RuntimeError, match="command objective placement failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    assert container.files[command_path(NEXT_OPERATION)] == (
        f"{NEXT_OPERATION}\n{NEXT_COMMAND_FLAG}\n"
    )
    assert container.files[command_path(OPERATION)] == f"{OPERATION}\n{COMMAND_FLAG}\n"
    assert container.note_state["pending"]["note"] == NEXT_NOTE_ID
    assert NOTE_ID in api.records and NEXT_NOTE_ID in api.records

    placed = handler.plant(
        runtime(container, NEXT_ROUND_SEED), flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG)
    )
    assert unpack_handle(placed[STORE_PRIVATE_NOTE])["target"] == NEXT_NOTE_ID
    assert NOTE_ID in api.records
    assert container.note_state["current"]["note"] == NEXT_NOTE_ID
    assert container.note_state["previous"]["note"] == NOTE_ID
    assert handler.retrieve(
        runtime(container), first[STORE_COMMAND], expected=COMMAND_FLAG
    ).status is ObservationStatus.PRESENT


@pytest.mark.parametrize("corrupted", ["command", "note"])
def test_resume_requires_exact_pending_command_and_note_pair(
    monkeypatch, corrupted: str,
) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    settle_first_group(handler, container)
    container.fail_after_once.add("publish-command")

    with pytest.raises(RuntimeError, match="command objective placement failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    if corrupted == "command":
        container.files[command_path(NEXT_OPERATION)] = (
            f"{NEXT_OPERATION}\nFLAG{{modified}}\n"
        )
    else:
        api.records[NEXT_NOTE_ID]["filename"] = "FLAG{modified}"

    placed = handler.plant(
        runtime(container, NEXT_ROUND_SEED), flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG)
    )

    assert unpack_handle(placed[STORE_PRIVATE_NOTE])["target"] == NEXT_NOTE_ID
    assert container.files[command_path(NEXT_OPERATION)] == (
        f"{NEXT_OPERATION}\n{NEXT_COMMAND_FLAG}\n"
    )
    assert api.records[NEXT_NOTE_ID]["filename"] == NEXT_NOTE_FLAG
    assert container.note_state["current"]["note"] == NEXT_NOTE_ID
    assert container.note_state["previous"]["note"] == NOTE_ID
    assert NOTE_ID in api.records
    assert api.deletions == []


def test_lost_journal_and_retirement_responses_converge_boundedly(monkeypatch) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    first = settle_first_group(handler, container)
    container.fail_after_once.add("record-pending")

    with pytest.raises(RuntimeError, match="journal persistence failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )
    assert container.files[command_path(OPERATION)] == f"{OPERATION}\n{COMMAND_FLAG}\n"
    assert container.note_state["pending"]["note"] == NEXT_NOTE_ID

    second = handler.plant(
        runtime(container, NEXT_ROUND_SEED), flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG)
    )
    assert container.note_state["current"]["note"] == NEXT_NOTE_ID
    assert container.note_state["previous"]["note"] == NOTE_ID
    assert NOTE_ID in api.records
    assert handler.retrieve(
        runtime(container), first[STORE_COMMAND], expected=COMMAND_FLAG
    ).status is ObservationStatus.PRESENT

    api.fail_delete_after_once = True
    with pytest.raises(RuntimeError, match="simulated lost delete response"):
        handler.plant(
            runtime(container, FINAL_ROUND_SEED), flags(FINAL_COMMAND_FLAG, FINAL_NOTE_FLAG)
        )
    assert container.note_state["current"]["note"] == FINAL_NOTE_ID
    assert container.note_state["previous"]["note"] == NEXT_NOTE_ID
    assert container.note_state["retiring"]["note"] == NOTE_ID
    assert command_path(OPERATION) in container.files
    assert command_path(NEXT_OPERATION) in container.files
    assert command_path(FINAL_OPERATION) in container.files
    assert handler.retrieve(
        runtime(container), second[STORE_COMMAND], expected=NEXT_COMMAND_FLAG
    ).status is ObservationStatus.PRESENT
    assert NEXT_NOTE_ID in api.records

    handler.plant(
        runtime(container, FINAL_ROUND_SEED), flags(FINAL_COMMAND_FLAG, FINAL_NOTE_FLAG)
    )
    assert container.note_state["retiring"] is None
    assert command_path(OPERATION) not in container.files
    assert command_path(NEXT_OPERATION) in container.files
    assert command_path(FINAL_OPERATION) in container.files
    assert len([
        path for path in container.files if path.startswith(OBJECTIVE_DIR + "/")
    ]) == 2
    assert api.deletions == [NOTE_ID]


def test_new_process_recovers_incomplete_pending_from_exact_caches(
    monkeypatch,
) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    settle_first_group(handler, container)
    container.fail_before_once.add("publish-command")

    with pytest.raises(RuntimeError, match="command objective placement failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    assert container.note_state["pending"]["note"] == NEXT_NOTE_ID
    api.records.pop(NEXT_NOTE_ID)
    container.files.pop(command_path(NEXT_OPERATION), None)

    placed = handler.plant(
        runtime(container, FINAL_ROUND_SEED), flags(FINAL_COMMAND_FLAG, FINAL_NOTE_FLAG)
    )

    assert unpack_handle(placed[STORE_PRIVATE_NOTE])["target"] == FINAL_NOTE_ID
    assert api.records[NEXT_NOTE_ID]["filename"] == NEXT_NOTE_FLAG
    assert api.records[FINAL_NOTE_ID]["filename"] == FINAL_NOTE_FLAG
    assert container.files[command_path(NEXT_OPERATION)] == (
        f"{NEXT_OPERATION}\n{NEXT_COMMAND_FLAG}\n"
    )
    assert container.files[command_path(FINAL_OPERATION)] == (
        f"{FINAL_OPERATION}\n{FINAL_COMMAND_FLAG}\n"
    )
    assert container.note_state["current"]["note"] == FINAL_NOTE_ID
    assert container.note_state["previous"]["note"] == NEXT_NOTE_ID
    assert NOTE_ID not in api.records


def test_unrecoverable_pending_fails_before_new_identity_allocation(
    monkeypatch,
) -> None:
    container = FakeContainer()
    api = FakeApi()
    handler = handler_with_ids(monkeypatch, api)
    settle_first_group(handler, container)
    container.fail_before_once.add("publish-command")
    with pytest.raises(RuntimeError, match="command objective placement failed"):
        handler.plant(
            runtime(container, NEXT_ROUND_SEED),
            flags(NEXT_COMMAND_FLAG, NEXT_NOTE_FLAG),
        )

    pending = container.note_state["pending"]
    assert pending is not None
    container.files.pop(f"{CACHE_DIR}/{pending['command_cache']}")
    cache_paths = {
        path for path in container.files if path.startswith(CACHE_DIR + "/")
    }

    with pytest.raises(RuntimeError, match="pending objective group cache"):
        handler.plant(
            runtime(container, FINAL_ROUND_SEED),
            flags(FINAL_COMMAND_FLAG, FINAL_NOTE_FLAG),
        )

    assert {
        path for path in container.files if path.startswith(CACHE_DIR + "/")
    } == cache_paths
    assert FINAL_NOTE_ID not in api.records
    assert command_path(FINAL_OPERATION) not in container.files


@pytest.mark.parametrize("store", [STORE_COMMAND, STORE_PRIVATE_NOTE])
def test_corrupt_cached_identity_fails_closed(store: str) -> None:
    container = FakeContainer()
    value = COMMAND_FLAG if store == STORE_COMMAND else NOTE_FLAG
    key = ROUND_CONTEXT[
        "command_cache" if store == STORE_COMMAND else "note_cache"
    ]
    target_id = ROUND_CONTEXT[
        "operation" if store == STORE_COMMAND else "note"
    ]
    container.files[f"{CACHE_DIR}/{key}"] = "not-a-handle"

    with pytest.raises(RuntimeError, match="cached identity is irreconstructible"):
        SuiteCrmFlagHandler()._cached(
            runtime(container), store, value, target_id, key,
        )


def test_round_context_is_stable_separated_rotating_and_proof_independent() -> None:
    first = flag_handler._round_context(ROUND_SEED)
    assert first == flag_handler._round_context(ROUND_SEED)
    assert first != flag_handler._round_context(NEXT_ROUND_SEED)
    assert len(set(first.values())) == len(first)
    assert first["note"] != first["operation"]
    assert first["note_cache"] != first["command_cache"]
    assert all(ROUND_SEED not in value for value in first.values())


@pytest.mark.parametrize("seed", (None, "", "1" * 63, "g" * 64, "A" * 64))
def test_plant_rejects_missing_or_invalid_round_context(seed) -> None:
    container = FakeContainer()
    target = runtime(container)
    if seed is None:
        target.meta.pop("round_context_seed")
    else:
        target.meta["round_context_seed"] = seed
    with pytest.raises(ValueError, match="round context seed is unavailable"):
        SuiteCrmFlagHandler().plant(target, flags())
