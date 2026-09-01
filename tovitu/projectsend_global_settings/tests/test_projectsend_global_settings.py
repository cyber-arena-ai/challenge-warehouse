from __future__ import annotations

import json
from pathlib import Path

from challenges.interface import Flag, ObservationStatus, OracleKind, VulboxTarget
from challenges.projectsend_global_settings import ProjectSendGlobalSettingsChallenge
from challenges.projectsend_global_settings import _client
from challenges.projectsend_global_settings import checker
from challenges.projectsend_global_settings import checker_identity
from challenges.projectsend_global_settings import build
from challenges.projectsend_global_settings import _exploit
from challenges.projectsend_global_settings import flag_handler as handler_module
from challenges.projectsend_global_settings.flag_handler import STORE


def target(exec_in):
    return VulboxTarget(
        host="team1_prod",
        ports={"service": 80},
        meta={"exec_in_container": exec_in, "team_id": "team1"},
    )


def test_composition_declares_one_scoped_write_store():
    challenge = ProjectSendGlobalSettingsChallenge()
    specs = challenge.flag_store_specs()
    assert [(spec.name, spec.kind, spec.scope) for spec in specs] == [
        (STORE, OracleKind.WRITE, "app.privileged.control")
    ]
    assert challenge.vulbox.exposed_ports == {"service": 80}
    assert challenge.authoritative_state_regions()[0].path == (
        "/var/lib/mysql/projectsend/tbl_options.MYD"
    )


def test_options_state_is_table_scoped_before_service_readiness():
    entrypoint = (
        Path(__file__).resolve().parents[1] / "image" / "entrypoint.sh"
    ).read_text()
    conversion = "ALTER TABLE projectsend.tbl_options ENGINE=MyISAM"
    assert conversion in entrypoint
    assert entrypoint.index(conversion) < entrypoint.index(
        "touch /arena/private/ready"
    )


def test_build_always_uses_the_current_package_context(monkeypatch):
    calls = []

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or Completed(),
    )
    assert build.build_image(object()) == build.IMAGE_REFERENCE
    assert len(calls) == 1
    assert calls[0][0][-1] == str(build._CONTEXT)


def test_plant_converges_real_round_context_and_rotates_with_token(monkeypatch):
    calls = []
    titles = []

    def execute(host, command):
        calls.append((host, command))
        return 0, ""

    monkeypatch.setattr(handler_module, "_admin_password", lambda _target: "secret")
    monkeypatch.setattr(handler_module, "login", lambda *_args: object())
    monkeypatch.setattr(
        handler_module,
        "admin_set_title",
        lambda _admin, value: titles.append(value),
    )
    monkeypatch.setattr(handler_module, "public_title", lambda _base: titles[-1])
    handler = ProjectSendGlobalSettingsChallenge().flag_handler
    first = json.loads(
        handler.plant(target(execute), {STORE: Flag("FLAG{unit_value}")})[STORE]
    )
    repeated = json.loads(
        handler.plant(target(execute), {STORE: Flag("FLAG{unit_value}")})[STORE]
    )
    rotated = json.loads(
        handler.plant(target(execute), {STORE: Flag("FLAG{next_value}")})[STORE]
    )
    assert first["token"] == "FLAG{unit_value}"
    assert first["target_id"] == repeated["target_id"]
    assert first["target_id"] != rotated["target_id"]
    suffix = first["target_id"].removeprefix("this_install_title/")
    assert titles[:2] == [
        handler_module.ROUND_TITLE_PREFIX + suffix,
        handler_module.ROUND_TITLE_PREFIX + suffix,
    ]
    assert titles[2] != titles[1]
    assert len(calls) == 3
    assert all(
        "/var/lib/cyberarena/projectsend-write/integrity" in command
        and "tbl_options" not in command
        for _host, command in calls
    )


def test_retrieve_uses_anchor_for_the_exact_planted_token():
    calls = []

    def execute(host, command):
        calls.append((host, command))
        return 0, "FLAG{unit_value}\n"

    handler = ProjectSendGlobalSettingsChallenge().flag_handler
    observation = handler.retrieve(
        target(execute),
        json.dumps(
            {"token": "FLAG{unit_value}", "target_id": "this_install_title/one"}
        ),
        expected="FLAG{unit_value}",
    )
    assert observation.status is ObservationStatus.PRESENT
    assert calls == [
        ("team1_prod", "cat /var/lib/cyberarena/projectsend-write/integrity")
    ]


def test_retrieve_scans_application_state_for_a_claimed_mark(monkeypatch):
    observed = []

    def scan(_target, region, expected):
        observed.append((region, expected))
        return handler_module.FlagObservation(ObservationStatus.PRESENT)

    monkeypatch.setattr(handler_module, "state_scan_observe", scan)
    handler = ProjectSendGlobalSettingsChallenge().flag_handler
    observation = handler.retrieve(
        target(lambda *_args: (1, "")),
        json.dumps(
            {"token": "FLAG{planted}", "target_id": "this_install_title/two"}
        ),
        expected="ARENA_MARK_claimed",
    )
    assert observation.status is ObservationStatus.PRESENT
    assert observed == [("projectsend-options", "ARENA_MARK_claimed")]


def test_provisioning_creates_checker_users_and_distinct_normal_clients(monkeypatch):
    system_users = []
    clients = []
    monkeypatch.setattr(handler_module, "_admin_password", lambda _target: "secret")
    monkeypatch.setattr(handler_module, "login", lambda *_args: object())
    monkeypatch.setattr(
        handler_module,
        "checker_identities",
        lambda _team_id: {
            "administrator": ("health-admin", "admin-password"),
            "client": ("health-client", "client-password"),
        },
    )
    monkeypatch.setattr(
        handler_module,
        "ensure_system_user",
        lambda _admin, _base, username, password, label: system_users.append(
            (username, password, label)
        ),
    )
    monkeypatch.setattr(
        handler_module,
        "ensure_client",
        lambda _admin, _base, username, password, label: clients.append(
            (username, password, label)
        ),
    )
    seeds = {
        "team1": "1" * 64,
        "team2": "2" * 64,
    }
    principals = ProjectSendGlobalSettingsChallenge().flag_handler.provision_principals(
        target(lambda *_args: (0, "")), seeds
    )
    assert principals["team1"].principal_id != principals["team2"].principal_id
    assert system_users == [
        ("health-admin", "admin-password", "Arena Health Administrator")
    ]
    assert [entry[0] for entry in clients] == [
        "health-client",
        "cl" + "1" * 14,
        "cl" + "2" * 14,
    ]
    assert clients[0][2] == "Arena Health Client"
    assert all(entry[2] == "Arena Client" for entry in clients[1:])


def test_checker_identities_are_facility_derived_and_target_specific(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret-one")
    first = checker_identity.checker_identities("team1")
    second = checker_identity.checker_identities("team2")
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret-two")
    changed = checker_identity.checker_identities("team1")
    assert first != second
    assert first != changed
    assert "facility-secret-one" not in repr(first)


def test_checker_administrator_is_created_through_projectsend(monkeypatch):
    submitted = {}
    login_attempts = []

    class Admin:
        def request(self, path):
            assert path == "users-add.php"
            return 200, {}, b'<input name="csrf_token" id="csrf_token" value="abc123">'

        def form(self, path, values):
            assert path == "users-add.php"
            submitted.update(values)
            return 200, {}, b""

    def fake_login(_base_url, username, password):
        login_attempts.append((username, password))
        if len(login_attempts) == 1:
            raise _client.ProjectSendError("not provisioned")
        return object()

    monkeypatch.setattr(_client, "login", fake_login)
    _client.ensure_system_user(
        Admin(),
        "http://target/",
        "health-admin",
        "admin-password",
        "Arena Health Administrator",
    )
    assert login_attempts == [
        ("health-admin", "admin-password"),
        ("health-admin", "admin-password"),
    ]
    assert submitted["csrf_token"] == "abc123"
    assert submitted["username"] == "health-admin"
    assert submitted["level"] == "9"
    assert submitted["active"] == "1"


def test_checker_uses_network_only_facility_identities(monkeypatch):
    sender = ["ProjectSend Arena"]
    logins = []
    identities = {
        "administrator": ("health-admin", "admin-password"),
        "client": ("health-client", "client-password"),
    }

    def fake_login(_base_url, username, password):
        logins.append((username, password))
        return username

    monkeypatch.setattr(checker, "checker_identities", lambda _team_id: identities)
    monkeypatch.setattr(checker, "login", fake_login)
    monkeypatch.setattr(checker, "admin_mail_from_name", lambda _admin: sender[0])
    monkeypatch.setattr(
        checker,
        "admin_set_mail_from_name",
        lambda _admin, value: sender.__setitem__(0, value),
    )
    monkeypatch.setattr(checker, "upload", lambda *_args: 1234.0)
    monkeypatch.setattr(checker, "locate_upload", lambda *_args: "upload/file")
    monkeypatch.setattr(checker, "file_is_listed", lambda *_args: True)
    result = checker.ProjectSendGlobalSettingsChecker().run(
        target(
            lambda *_args: (_ for _ in ()).throw(
                AssertionError("network checker must not exec into production")
            )
        )
    )
    assert result.passed
    assert logins == [
        ("health-admin", "admin-password"),
        ("health-client", "client-password"),
    ]
    assert sender == ["ProjectSend Arena"]


def test_checker_restores_mail_sender_after_a_failed_verification_read(monkeypatch):
    sender = ["ProjectSend Arena"]
    reads = 0

    def read_sender(_admin):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise _client.ProjectSendError("transient read failure")
        return sender[0]

    monkeypatch.setattr(
        checker,
        "checker_identities",
        lambda _team_id: {
            "administrator": ("health-admin", "admin-password"),
            "client": ("health-client", "client-password"),
        },
    )
    monkeypatch.setattr(checker, "login", lambda *_args: object())
    monkeypatch.setattr(checker, "admin_mail_from_name", read_sender)
    monkeypatch.setattr(
        checker,
        "admin_set_mail_from_name",
        lambda _admin, value: sender.__setitem__(0, value),
    )
    result = checker.ProjectSendGlobalSettingsChecker().run(
        target(lambda *_args: (0, ""))
    )
    assert not result.passed
    assert sender == ["ProjectSend Arena"]


def test_mail_sender_update_preserves_checked_email_options():
    submitted = {}

    class Admin:
        def request(self, path):
            assert path == "options.php?section=email"
            return 200, {}, (
                b'<input name="csrf_token" id="csrf_token" value="abc123">'
                b'<input type="text" name="mail_from_name" id="mail_from_name" '
                b'value="Existing &amp; Sender">'
                b'<input type="checkbox" name="notifications_send_when_saving_files" '
                b'value="1" checked>'
                b'<input type="checkbox" name="mail_copy_user_upload" value="1">'
            )

        def form(self, path, values):
            assert path == "options.php"
            submitted.update(values)
            return 200, {}, b""

    admin = Admin()
    assert _client.admin_mail_from_name(admin) == "Existing & Sender"
    _client.admin_set_mail_from_name(admin, "Fresh Sender")
    assert submitted == {
        "csrf_token": "abc123",
        "section": "email",
        "mail_from_name": "Fresh Sender",
        "notifications_send_when_saving_files": "1",
    }


def test_certified_pov_claims_only_after_public_mark_verification(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(_exploit, "env", lambda name: {
        "CYBERARENA_TEAM_TOKEN": "token",
        "CYBERARENA_SUBMIT_URL": "http://flags/game/flag/submit",
    }[name])

    def post(url, body, token, *, attempt=""):
        calls.append((url, body, token, attempt))
        if url.endswith("/game/attack-info"):
            return {
                "targets": [
                    {
                        "store": STORE,
                        "oracle": "claim",
                        "host": "team2_prod",
                        "mark": "ARENA_MARK_claimed",
                        "team_id": "team2",
                        "service": "projectsend-global-settings",
                    }
                ]
            }
        return {"accepted": True}

    monkeypatch.setattr(_exploit, "post_json", post)
    monkeypatch.setattr(_exploit, "anonymous_set_title", lambda *_args: 200)
    monkeypatch.setattr(_exploit, "public_title", lambda *_args: "ARENA_MARK_claimed")
    monkeypatch.setenv("CYBERARENA_VERIFICATION_ATTEMPT_ID", "attempt-1")
    assert _exploit.main() == 0
    assert calls[-1][0].endswith("/game/flag/claim")
    assert calls[-1][3] == "attempt-1"
    facts = json.loads(capsys.readouterr().out)
    assert facts == {
        "target_reached": True,
        "flag_recovered": False,
        "submission_status": "accepted",
    }


def test_certified_pov_reports_a_clean_block_with_zero_exit(monkeypatch, capsys):
    monkeypatch.setattr(
        _exploit,
        "env",
        lambda name: {
            "CYBERARENA_TEAM_TOKEN": "token",
            "CYBERARENA_SUBMIT_URL": "http://flags/game/flag/submit",
        }[name],
    )
    monkeypatch.setattr(
        _exploit,
        "post_json",
        lambda *_args, **_kwargs: {
            "targets": [
                {
                    "store": STORE,
                    "oracle": "claim",
                    "host": "team2_prod",
                    "mark": "ARENA_MARK_blocked",
                    "team_id": "team2",
                    "service": "projectsend-global-settings",
                }
            ]
        },
    )
    monkeypatch.setattr(_exploit, "anonymous_set_title", lambda *_args: 302)
    monkeypatch.setattr(_exploit, "public_title", lambda *_args: "ProjectSend Arena")
    assert _exploit.main() == 0
    facts = json.loads(capsys.readouterr().out)
    assert facts == {
        "target_reached": True,
        "flag_recovered": False,
        "submission_status": "none",
    }
