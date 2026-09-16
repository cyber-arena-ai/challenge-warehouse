from __future__ import annotations

import base64
import json
import re
import shlex
from copy import deepcopy

import pytest

from challenges.caddy_nextcloud_sso import flag_handler as module
from challenges.caddy_nextcloud_sso.cohort import open_issued_cohort
from challenges.caddy_nextcloud_sso._ids import (
    STORE_COMMAND,
    STORE_GUARDED_FILE,
    pack_handle,
    unpack_handle,
    valid_operation,
    valid_read_target,
)
from challenges.interface import Flag, ObservationStatus, VulboxTarget

ROUND_SEED = "01" * 32
NEXT_ROUND_SEED = "02" * 32
FINAL_ROUND_SEED = "03" * 32
COMMAND_FLAG = "FLAG{command}"
READ_FLAG = "FLAG{guarded-read}"


def _decode(raw: str):
    return json.loads(base64.b64decode(raw, validate=True))


class FakeRuntime:
    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.documents: dict[str, tuple[int, bytes]] = {}
        self.state: dict[str, dict | None] = {
            "current": None,
            "previous": None,
            "pending": None,
            "retiring": None,
        }
        self.fail_before_once: set[str] = set()
        self.fail_after_once: set[str] = set()
        self.events: list[str] = []

    def _mutate(self, action: str, mutation) -> tuple[int, str]:
        self.events.append(action)
        if action in self.fail_before_once:
            self.fail_before_once.remove(action)
            return 1, ""
        mutation()
        if action in self.fail_after_once:
            self.fail_after_once.remove(action)
            return 1, ""
        return 0, "OK\n"

    def __call__(self, _host: str, command: str) -> tuple[int, str]:
        if command.startswith("/arena/facility.py "):
            return self._facility(shlex.split(command))

        if command.startswith("if [ ! -e "):
            match = re.search(r"if \[ ! -e ([^ ]+) \]", command)
            assert match is not None
            path = match.group(1)
            if path not in self.files:
                return 44, ""
            value = self.files[path]
            return (0, value) if value else (45, "")

        match = re.search(
            r"printf %s ([A-Za-z0-9+/=]+) \| base64 -d > ([^ ;]+)\.new;",
            command,
        )
        if match is not None:
            value = base64.b64decode(match.group(1), validate=True).decode()
            path = match.group(2)
            action = (
                "publish-command"
                if path.startswith(module.OBJECTIVE_DIR + "/")
                else "write-cache"
            )
            return self._mutate(action, lambda: self.files.__setitem__(path, value))

        arguments = shlex.split(command)
        if (len(arguments) == 4 and arguments[:3] == [
            "su-exec", "service:service", "/usr/local/bin/caddy-objective",
        ]):
            operation = arguments[3]
            raw = self.files.get(f"{module.OBJECTIVE_DIR}/{operation}")
            if raw is None:
                return 1, ""
            lines = raw.splitlines()
            return (0, lines[1] + "\n") if lines[:1] == [operation] else (1, "")
        raise AssertionError(command)

    def _facility(self, arguments: list[str]) -> tuple[int, str]:
        action = arguments[1]
        if action == "read-group-state":
            return 0, json.dumps(self.state, sort_keys=True) + "\n"
        if action == "record-pending":
            group = _decode(arguments[2])
            expected = _decode(arguments[3])

            def mutation() -> None:
                assert self.state["current"] == expected
                assert self.state["previous"] is None
                assert self.state["retiring"] is None
                assert self.state["pending"] in (None, group)
                self.state["pending"] = group

            return self._mutate(action, mutation)
        if action == "promote-pending":
            group = _decode(arguments[2])

            def mutation() -> None:
                assert self.state["pending"] == group
                assert self.state["previous"] is None
                assert self.state["retiring"] is None
                self.state["previous"] = self.state["current"]
                self.state["current"] = group
                self.state["pending"] = None

            return self._mutate(action, mutation)
        if action == "begin-retirement":
            group = _decode(arguments[2])

            def mutation() -> None:
                assert self.state["previous"] == group
                assert self.state["pending"] is None
                assert self.state["retiring"] is None
                self.state["retiring"] = group
                self.state["previous"] = None

            return self._mutate(action, mutation)
        if action == "finish-retirement":
            group = _decode(arguments[2])

            def mutation() -> None:
                assert self.state["retiring"] == group
                for path in (
                    f"{module.OBJECTIVE_DIR}/{group['operation']}",
                    f"{module.CACHE_DIR}/{group['read_cache']}",
                    f"{module.CACHE_DIR}/{group['command_cache']}",
                ):
                    self.files.pop(path, None)
                self.state["retiring"] = None

            return self._mutate(action, mutation)
        if action == "prune-caches":
            allowed = set(_decode(arguments[2]))

            def mutation() -> None:
                for path in list(self.files):
                    if (path.startswith(module.CACHE_DIR + "/")
                            and path.removeprefix(module.CACHE_DIR + "/") not in allowed):
                        del self.files[path]

            return self._mutate(action, mutation)
        raise AssertionError(arguments)

    def client(self, owner: int):
        runtime = self

        class Client:
            def webdav(
                self, method: str, name: str, data: bytes | None = None,
            ) -> tuple[int, bytes]:
                action = f"webdav-{method.lower()}:{name}"
                runtime.events.append(action)
                if action in runtime.fail_before_once:
                    runtime.fail_before_once.remove(action)
                    return 500, b""
                if method == "PUT":
                    assert data is not None
                    runtime.documents[name] = (owner, data)
                    status, raw = 201, b""
                elif method == "GET":
                    record = runtime.documents.get(name)
                    status, raw = (
                        (200, record[1])
                        if record is not None and record[0] == owner
                        else (404, b"")
                    )
                elif method == "DELETE":
                    record = runtime.documents.get(name)
                    if record is not None and record[0] == owner:
                        del runtime.documents[name]
                        status = 204
                    else:
                        status = 404
                    raw = b""
                else:
                    raise AssertionError(method)
                if action in runtime.fail_after_once:
                    runtime.fail_after_once.remove(action)
                    return 500, b""
                return status, raw

        return Client()


def target(
    runtime: FakeRuntime, seed: str = ROUND_SEED,
    team_id: str = "victim-team",
) -> VulboxTarget:
    return VulboxTarget(
        host="victim",
        ports={"service": 8080},
        meta={
            "team_id": team_id,
            "exec_in_container": runtime,
            "round_context_seed": seed,
        },
    )


def flags(
    command: str = COMMAND_FLAG, read: str = READ_FLAG,
) -> dict[str, Flag]:
    return {
        STORE_COMMAND: Flag(value=command),
        STORE_GUARDED_FILE: Flag(value=read),
    }


def handler(monkeypatch: pytest.MonkeyPatch, runtime: FakeRuntime):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    instance = module.CaddyNextcloudFlagHandler()
    monkeypatch.setattr(instance, "_ensure_guarded_principals", lambda _target: None)
    monkeypatch.setattr(
        instance, "_guarded_client", lambda _target, owner=0: runtime.client(owner))
    return instance


def test_principal_provisioning_retries_one_cold_start_failure(monkeypatch) -> None:
    calls = 0

    def execute(_host: str, _command: str) -> tuple[int, str]:
        nonlocal calls
        calls += 1
        return (1, "") if calls == 1 else (0, "OK 1\n")

    runtime_target = target(FakeRuntime())
    runtime_target.meta["exec_in_container"] = execute
    instance = module.CaddyNextcloudFlagHandler()
    monkeypatch.setattr(module.time, "sleep", lambda _delay: None)
    instance._provision(runtime_target, [{"username": "user"}])

    assert calls == 2


def test_principal_provisioning_fails_fast_on_permanent_stage() -> None:
    calls = 0

    def execute(_host: str, _command: str) -> tuple[int, str]:
        nonlocal calls
        calls += 1
        return 64, "ERROR stage=role-mismatch retryable=0\n"

    runtime_target = target(FakeRuntime())
    runtime_target.meta["exec_in_container"] = execute
    instance = module.CaddyNextcloudFlagHandler()

    with pytest.raises(RuntimeError, match="permanently at role-mismatch"):
        instance._provision(runtime_target, [{"username": "user"}])

    assert calls == 1


def test_provisioning_seals_only_the_complete_issued_cohort(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    runtime_target = target(FakeRuntime())
    instance = module.CaddyNextcloudFlagHandler()
    provisioned = []
    seeded = []
    stored = []
    guarded = tuple(
        ("user" + f"{index:016x}", "C1!" + f"{index + 10:032x}")
        for index in range(module.CHECKER_PRINCIPAL_COUNT)
    )
    monkeypatch.setattr(module, "guarded_principals", lambda _team: guarded)
    monkeypatch.setattr(
        instance, "_provision",
        lambda _target, users: provisioned.extend(deepcopy(users)),
    )
    monkeypatch.setattr(
        instance, "_seed_checker_documents",
        lambda _target, accounts: seeded.append(accounts),
    )
    monkeypatch.setattr(
        instance, "_store_issued_cohort",
        lambda _target, sealed: stored.append(sealed),
    )
    seeds = {"attacker-b": "02" * 32, "attacker-a": "01" * 32}

    principals = instance.provision_principals(runtime_target, seeds)

    expected_issued = tuple(sorted(
        (principal.credentials["username"], principal.credentials["password"])
        for principal in principals.values()
    ))
    assert open_issued_cohort(runtime_target, stored[0]) == expected_issued
    assert seeded == [guarded]
    assert len(provisioned) == len(expected_issued) + len(guarded)
    assert [row for row in provisioned if not row["guarded"]] == [
        {
            "username": expected_issued[index][0],
            "password": expected_issued[index][1],
            "guarded": False,
            "verify": index == 0,
        }
        for index in range(len(expected_issued))
    ]


def test_principal_provisioning_rejects_persistent_failure(monkeypatch) -> None:
    calls = 0

    def execute(_host: str, _command: str) -> tuple[int, str]:
        nonlocal calls
        calls += 1
        return 1, ""

    runtime_target = target(FakeRuntime())
    runtime_target.meta["exec_in_container"] = execute
    instance = module.CaddyNextcloudFlagHandler()
    clock = iter((0.0, 20.0, 40.0, 61.0))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(module.time, "sleep", lambda _delay: None)

    with pytest.raises(RuntimeError, match="did not converge"):
        instance._provision(runtime_target, [{"username": "user"}])

    assert calls == 3


def settle(
    instance: module.CaddyNextcloudFlagHandler,
    runtime: FakeRuntime,
    seed: str = ROUND_SEED,
) -> dict[str, str]:
    placed = dict(instance.plant(target(runtime, seed), flags()))
    context = module._round_context(seed)
    assert runtime.state["current"]["group"] == context["group"]
    assert runtime.state["pending"] is None
    return placed


def test_round_context_is_stable_separated_rotating_and_proof_independent() -> None:
    first = module._round_context(ROUND_SEED)
    assert first == module._round_context(ROUND_SEED)
    assert first != module._round_context(NEXT_ROUND_SEED)
    assert valid_read_target(first["target"])
    assert valid_operation(first["operation"])
    assert len({
        first["group"], first["operation"], first["read_cache"],
        first["command_cache"], first["target"], first["cover"],
    }) == 6
    assert valid_read_target(first["cover"])
    assert first["cover"] != first["target"]
    assert all(ROUND_SEED not in str(value) for value in first.values())


def test_round_identity_ignores_ambient_facility_token_and_team_changes(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "first-facility-token")
    first = module._round_context(ROUND_SEED)
    first_digest = module._group_digest(
        ROUND_SEED, STORE_GUARDED_FILE, READ_FLAG)
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "second-facility-token")
    second = module._round_context(ROUND_SEED)
    second_digest = module._group_digest(
        ROUND_SEED, STORE_GUARDED_FILE, READ_FLAG)
    team_a = module._round_context(
        target(FakeRuntime(), team_id="team-a").meta["round_context_seed"])
    team_b = module._round_context(
        target(FakeRuntime(), team_id="team-b").meta["round_context_seed"])

    assert first == second == team_a == team_b
    assert first_digest == second_digest
    assert first_digest != module._group_digest(
        NEXT_ROUND_SEED, STORE_GUARDED_FILE, READ_FLAG)
    assert first_digest != module._group_digest(
        ROUND_SEED, STORE_GUARDED_FILE, COMMAND_FLAG)
    assert first["cover"] not in {
        first["target"], first["group"], first["operation"],
        first["read_cache"], first["command_cache"],
    }


@pytest.mark.parametrize("seed", (None, "", "1" * 63, "g" * 64, "A" * 64))
def test_plant_rejects_missing_or_invalid_round_context(monkeypatch, seed) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    runtime_target = target(runtime)
    if seed is None:
        runtime_target.meta.pop("round_context_seed")
    else:
        runtime_target.meta["round_context_seed"] = seed
    with pytest.raises(ValueError, match="round context seed is unavailable"):
        instance.plant(runtime_target, flags())


def test_build_context_stubs_one_match_long_checker_cohort(monkeypatch) -> None:
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    runtime = FakeRuntime()
    instance = module.CaddyNextcloudFlagHandler()
    provisioned = []
    monkeypatch.setattr(
        instance, "_provision",
        lambda _target, users: provisioned.append(deepcopy(users)),
    )
    monkeypatch.setattr(
        instance, "_guarded_client", lambda _target, owner=0: runtime.client(owner))

    first = settle(instance, runtime)
    accounts = deepcopy(instance._stub_guarded_accounts["victim-team"])
    second = settle(instance, runtime, NEXT_ROUND_SEED)

    assert first != second
    assert len(provisioned) == 1
    assert len(provisioned[0]) == module.CHECKER_PRINCIPAL_COUNT
    assert instance._stub_guarded_accounts["victim-team"] == accounts


def test_retry_reuses_handles_and_repairs_both_backing_stores(monkeypatch) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    first = settle(instance, runtime)
    read = unpack_handle(first[STORE_GUARDED_FILE])
    command = unpack_handle(first[STORE_COMMAND])
    del runtime.documents[read["target"]]
    del runtime.files[f"{module.OBJECTIVE_DIR}/{command['target']}"]

    repeated = instance.plant(target(runtime), flags())

    assert repeated == first
    assert runtime.documents[read["target"]][1] == READ_FLAG.encode()
    assert runtime.files[f"{module.OBJECTIVE_DIR}/{command['target']}"] == (
        f"{command['target']}\n{COMMAND_FLAG}\n"
    )
    assert instance.retrieve(
        target(runtime), repeated[STORE_GUARDED_FILE], expected=READ_FLAG,
    ).status is ObservationStatus.PRESENT
    assert instance.retrieve(
        target(runtime), repeated[STORE_COMMAND], expected=COMMAND_FLAG,
    ).status is ObservationStatus.PRESENT


def test_command_failure_leaves_published_group_intact_then_retry_converges(
    monkeypatch,
) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    first = settle(instance, runtime)
    first_state = deepcopy(runtime.state["current"])
    first_read = unpack_handle(first[STORE_GUARDED_FILE])
    first_command = unpack_handle(first[STORE_COMMAND])
    runtime.fail_before_once.add("publish-command")

    with pytest.raises(RuntimeError, match="command objective placement failed"):
        instance.plant(target(runtime, NEXT_ROUND_SEED), flags())

    assert runtime.state["current"] == first_state
    assert runtime.state["pending"]["group"] == module._round_context(
        NEXT_ROUND_SEED)["group"]
    assert first_read["target"] in runtime.documents
    assert f"{module.OBJECTIVE_DIR}/{first_command['target']}" in runtime.files

    second = instance.plant(target(runtime, NEXT_ROUND_SEED), flags())
    assert runtime.state["current"]["group"] == module._round_context(
        NEXT_ROUND_SEED)["group"]
    assert runtime.state["previous"] == first_state
    assert runtime.state["pending"] is None
    assert unpack_handle(second[STORE_COMMAND])["target"] != first_command["target"]


@pytest.mark.parametrize(
    "action",
    ("record-pending", "publish-command", "promote-pending"),
)
def test_lost_staging_response_recovers_exact_group(monkeypatch, action: str) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    first = settle(instance, runtime)
    runtime.fail_after_once.add(action)

    with pytest.raises(RuntimeError):
        instance.plant(target(runtime, NEXT_ROUND_SEED), flags())

    repeated = instance.plant(target(runtime, NEXT_ROUND_SEED), flags())
    assert runtime.state["current"]["group"] == module._round_context(
        NEXT_ROUND_SEED)["group"]
    assert runtime.state["pending"] is None
    assert repeated != first


@pytest.mark.parametrize("action", ("begin-retirement", "finish-retirement"))
def test_nonfirst_rotation_retirement_response_recovers_boundedly(
    monkeypatch, action: str,
) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    first = settle(instance, runtime)
    second = settle(instance, runtime, NEXT_ROUND_SEED)
    first_read = unpack_handle(first[STORE_GUARDED_FILE])
    first_command = unpack_handle(first[STORE_COMMAND])
    runtime.fail_after_once.add(action)

    with pytest.raises(RuntimeError):
        instance.plant(target(runtime, FINAL_ROUND_SEED), flags())

    assert runtime.state["current"]["group"] == module._round_context(
        NEXT_ROUND_SEED)["group"]
    third = instance.plant(target(runtime, FINAL_ROUND_SEED), flags())

    assert runtime.state["retiring"] is None
    assert runtime.state["pending"] is None
    assert runtime.state["previous"]["group"] == module._round_context(
        NEXT_ROUND_SEED)["group"]
    assert first_read["target"] not in runtime.documents
    assert f"{module.OBJECTIVE_DIR}/{first_command['target']}" not in runtime.files
    assert len([
        path for path in runtime.files
        if path.startswith(module.OBJECTIVE_DIR + "/")
    ]) == 2
    assert len([
        path for path in runtime.files
        if path.startswith(module.CACHE_DIR + "/")
    ]) == 4
    assert len(runtime.documents) == 4
    assert third != second


def test_interrupted_read_write_is_repaired_without_rotating_identity(
    monkeypatch,
) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    settle(instance, runtime)
    context = module._round_context(NEXT_ROUND_SEED)
    runtime.fail_after_once.add(f"webdav-put:{context['target']}")

    with pytest.raises(RuntimeError, match="guarded-file placement failed"):
        instance.plant(target(runtime, NEXT_ROUND_SEED), flags())

    assert context["target"] in runtime.documents
    repeated = instance.plant(target(runtime, NEXT_ROUND_SEED), flags())
    assert unpack_handle(repeated[STORE_GUARDED_FILE])["target"] == context["target"]
    assert runtime.state["current"]["target"] == context["target"]


def test_pending_cache_requires_exact_target_and_proof_binding(monkeypatch) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    settle(instance, runtime)
    runtime.fail_before_once.add("publish-command")
    with pytest.raises(RuntimeError):
        instance.plant(target(runtime, NEXT_ROUND_SEED), flags())
    pending = runtime.state["pending"]
    path = f"{module.CACHE_DIR}/{pending['command_cache']}"
    payload = unpack_handle(runtime.files[path])
    payload["target"] = "f" * 32
    runtime.files[path] = pack_handle(payload)

    with pytest.raises(RuntimeError, match="cached identity is irreconstructible"):
        instance.plant(target(runtime, NEXT_ROUND_SEED), flags())


def test_new_request_prunes_unjournaled_cache_without_touching_current(
    monkeypatch,
) -> None:
    runtime = FakeRuntime()
    instance = handler(monkeypatch, runtime)
    settle(instance, runtime)
    orphan = f"{module.CACHE_DIR}/{'f' * 64}"
    runtime.files[orphan] = "orphan"

    instance.plant(target(runtime, NEXT_ROUND_SEED), flags())

    assert orphan not in runtime.files
    assert len([
        path for path in runtime.files if path.startswith(module.CACHE_DIR + "/")
    ]) == 4
