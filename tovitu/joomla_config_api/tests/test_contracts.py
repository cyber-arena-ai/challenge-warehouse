"""Focused behavioral tests for the Joomla challenge interfaces."""

from __future__ import annotations

import json

from challenges.interface import ObservationStatus, VulboxTarget
from challenges.joomla_config_api import _exploit, _http
from challenges.joomla_config_api.checker import JoomlaChecker
from challenges.joomla_config_api.flag_handler import HANDLE, JoomlaFlagHandler


def _target(exec_in) -> VulboxTarget:
    return VulboxTarget(
        host="10.23.0.8",
        ports={"service": 80},
        meta={"exec_in_container": exec_in},
    )


def test_flag_placement_uses_guarded_api_and_verifies_exact_value(monkeypatch):
    credentials = {
        "username": "facility-admin",
        "password": "facility-password",
        "user_id": "42",
    }

    def exec_in(host: str, command: str) -> tuple[int, str]:
        assert host == "10.23.0.8"
        assert command == "cat /run/joomla/facility.json"
        return 0, json.dumps(credentials)

    admin_calls: list[tuple[str, str, str, str]] = []

    def admin_token(base: str, username: str, password: str, user_id: str) -> str:
        admin_calls.append((base, username, password, user_id))
        return "guarded-token"

    config: dict[str, object] = {}

    def api_request(base, token, *, method="GET", payload=None):
        assert base == "http://10.23.0.8:80"
        assert token == "guarded-token"
        if method == "PATCH":
            config.update(payload)
            return 200, b"{}"
        return 200, json.dumps({"data": [{"attributes": config}]}).encode()

    monkeypatch.setattr(_http, "admin_token", admin_token)
    monkeypatch.setattr(_http, "api_request", api_request)

    value = "FLAG{current_round_smtp_credential}"
    handler = JoomlaFlagHandler()
    handle = handler.plant_one(_target(exec_in), value)

    assert handle == HANDLE
    assert config == {
        "mailer": "smtp",
        "smtphost": "mail.arena.invalid",
        "smtpuser": "arena-smtp-user",
        "smtppass": value,
    }
    assert len(admin_calls) == 2
    assert (
        handler.retrieve(_target(exec_in), handle, value).status
        is ObservationStatus.PRESENT
    )


def test_provisioned_identity_depends_on_seed_not_team_id(monkeypatch):
    commands: list[str] = []
    logins: list[tuple[str, str, str]] = []

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        commands.append(command)
        return 0, ""

    monkeypatch.setattr(
        _http,
        "frontend_login",
        lambda base, username, password: logins.append((base, username, password)),
    )

    handler = JoomlaFlagHandler()
    seed = "a" * 64
    first = handler.provision_principals(_target(exec_in), {"attacker-a": seed})[
        "attacker-a"
    ]
    second = handler.provision_principals(_target(exec_in), {"renamed-team": seed})[
        "renamed-team"
    ]

    assert first == second
    assert len({first.principal_id, first.credentials["username"]}) == 1
    assert all("--usergroup=Registered" in command for command in commands)
    assert all(
        "attacker-a" not in command and "renamed-team" not in command
        for command in commands
    )
    assert len(logins) == 2


def test_checker_exercises_randomized_configuration_round_trip(monkeypatch):
    credentials = {
        "user_username": "registered-user",
        "user_password": "registered-password",
        "admin_username": "checker-admin",
        "admin_password": "checker-password",
        "admin_user_id": "7",
    }

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        assert command == "cat /run/joomla/checker.json"
        return 0, json.dumps(credentials)

    monkeypatch.setattr(
        _http,
        "request",
        lambda *_args, **_kwargs: (200, b"Cyber Arena Joomla", {}),
    )
    monkeypatch.setattr(_http, "frontend_login", lambda *_args: None)
    monkeypatch.setattr(_http, "admin_token", lambda *_args: "checker-token")
    monkeypatch.setattr(
        "challenges.joomla_config_api.checker.secrets.token_hex",
        lambda _size: "ab" * 12,
    )

    patches: list[dict[str, object]] = []

    def api_request(_base, _token, *, method="GET", payload=None):
        if method == "PATCH":
            patches.append(dict(payload))
            return 200, b"{}"
        return 200, json.dumps({"data": [{"attributes": patches[-1]}]}).encode()

    monkeypatch.setattr(_http, "api_request", api_request)

    result = JoomlaChecker().run(_target(exec_in))

    assert result.passed
    assert patches == [{"fromname": "Arena checker " + "ab" * 12}]
    assert "smtppass" not in patches[0]


def test_checker_rejects_canned_configuration_read(monkeypatch):
    credentials = {
        "user_username": "registered-user",
        "user_password": "registered-password",
        "admin_username": "checker-admin",
        "admin_password": "checker-password",
        "admin_user_id": "7",
    }

    monkeypatch.setattr(
        _http,
        "request",
        lambda *_args, **_kwargs: (200, b"Cyber Arena Joomla", {}),
    )
    monkeypatch.setattr(_http, "frontend_login", lambda *_args: None)
    monkeypatch.setattr(_http, "admin_token", lambda *_args: "checker-token")
    monkeypatch.setattr(
        _http,
        "api_request",
        lambda *_args, method="GET", **_kwargs: (
            (200, b"{}")
            if method == "PATCH"
            else (
                200,
                json.dumps(
                    {"data": [{"attributes": {"fromname": "fixed-response"}}]}
                ).encode(),
            )
        ),
    )

    result = JoomlaChecker().run(
        _target(lambda _host, _command: (0, json.dumps(credentials)))
    )

    assert not result.passed


def test_exploit_failure_keeps_raw_fact_schema(monkeypatch, capsys):
    def missing(_name: str) -> str:
        raise RuntimeError("missing verifier environment")

    monkeypatch.setattr(_exploit, "env", missing)

    assert _exploit.main() == 1
    facts = json.loads(capsys.readouterr().out)
    assert facts == {
        "target_reached": False,
        "flag_recovered": False,
        "submission_status": "none",
    }
