from __future__ import annotations

import base64
import json
import re

from challenges.interface import Flag, ObservationStatus, OracleKind, VulboxTarget

from challenges.opentsdb_graph_command import checker, config
from challenges.opentsdb_graph_command.challenge import OpenTSDBGraphCommandChallenge
from challenges.opentsdb_graph_command.flag_handler import OpenTSDBExecuteFlagHandler


class Recorder:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def __call__(self, _host: str, command: str) -> tuple[int, str]:
        self.commands.append(command)
        return 0, ""


def target(recorder: Recorder) -> VulboxTarget:
    return VulboxTarget(
        host="victim",
        ports={"service": 4242},
        meta={"team_id": "victim-team", "exec_in_container": recorder},
    )


def test_execute_store_contract() -> None:
    spec = OpenTSDBGraphCommandChallenge().flag_store_specs()[0]
    assert spec.name == "command"
    assert spec.kind is OracleKind.EXECUTE
    assert spec.scope == "host.command.execute"


def test_principals_are_distinct_seed_derived_and_equal_role(monkeypatch) -> None:
    recorder = Recorder()
    handler = OpenTSDBExecuteFlagHandler()
    seeds = {"red": "a" * 64, "blue": "b" * 64}
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    principals = handler.provision_principals(target(recorder), seeds)
    assert set(principals) == set(seeds)
    assert len({p.principal_id for p in principals.values()}) == 2
    assert len({tuple(p.credentials.items()) for p in principals.values()}) == 2
    assert all(set(p.credentials) == {"token"} for p in principals.values())
    assert "red" not in recorder.commands[0]
    assert "blue" not in recorder.commands[0]
    assert recorder.commands[0].endswith("&& /arena/start-opentsdb.sh")


def test_checker_is_network_only_and_uses_facility_identity(monkeypatch) -> None:
    constructed: list[tuple[str, int, str | None]] = []

    class FakeClient:
        def __init__(self, host: str, port: int, token: str | None = None):
            constructed.append((host, port, token))

        def put(self, _metric: str, _tag: str, _value: int):
            return 200, '{"success":1}', 1000

        def query(self, _metric: str, _tag: str, _timestamp: int):
            return 200, '[{"dps":{"1000":123456}}]'

        def request(self, _path: str):
            return 200, "OpenTSDB"

        def graph(self, _metric: str, _tag: str, _timestamp: int):
            return 200, '{"plotted":1,"points":1}'

    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-owned-test-secret")
    monkeypatch.setattr(checker, "OpenTSDBClient", FakeClient)
    monkeypatch.setattr(checker.secrets, "randbelow", lambda _bound: 23456)
    result = checker.OpenTSDBChecker().run(
        VulboxTarget(
            host="victim",
            ports={"service": 4242},
            meta={"team_id": "victim-team"},
        )
    )
    _, expected_token = config.checker_identity("victim-team")
    assert result.passed
    assert constructed == [("victim", 4242, expected_token)]


def test_execute_targets_rotate_and_do_not_expose_flags() -> None:
    recorder = Recorder()
    handler = OpenTSDBExecuteFlagHandler()
    first = handler.plant(
        target(recorder), {"command": Flag("FLAG{" + "A" * 32 + "}")}
    )["command"]
    retry = handler.plant(
        target(recorder), {"command": Flag("FLAG{" + "A" * 32 + "}")}
    )["command"]
    second = handler.plant(
        target(recorder), {"command": Flag("FLAG{" + "B" * 32 + "}")}
    )["command"]
    first_id = handler.flag_id(first)
    assert first_id == handler.flag_id(retry)
    assert first_id != handler.flag_id(second)
    assert re.fullmatch(
        r"/usr/local/libexec/opentsdb-release-[0-9a-f]{24}", first_id or ""
    )
    decoded = base64.urlsafe_b64decode(first).decode()
    assert "FLAG{" not in decoded
    assert "chmod 0400" in recorder.commands[0]
    assert "chmod 4750" in recorder.commands[0]


def test_missing_execute_proof_is_an_integrity_failure() -> None:
    class MissingRecorder(Recorder):
        def __call__(self, _host: str, command: str) -> tuple[int, str]:
            return (0, "") if command == "true" else (1, "")

    handle = base64.urlsafe_b64encode(
        json.dumps(
            {"helper": "/usr/local/libexec/opentsdb-release-" + "a" * 24}
        ).encode()
    ).decode()
    observation = OpenTSDBExecuteFlagHandler().retrieve(
        target(MissingRecorder()), handle, expected="FLAG{missing}"
    )
    assert observation.status is ObservationStatus.NOT_FOUND
