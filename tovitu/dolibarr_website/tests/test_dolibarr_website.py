from __future__ import annotations

import json

from challenges.interface import Flag, ObservationStatus, OracleKind, VulboxTarget
from challenges.dolibarr_website import DolibarrWebsiteChallenge
from challenges.dolibarr_website import _exploit
from challenges.dolibarr_website import checker as checker_module
from challenges.dolibarr_website import flag_handler as flag_handler_module
from challenges.dolibarr_website.checker import DolibarrWebsiteChecker
from challenges.dolibarr_website.checker_identity import checker_credentials
from challenges.dolibarr_website.flag_handler import STORE


def target(exec_in, *, team_id="team1"):
    return VulboxTarget(
        host="team1_prod",
        ports={"service": 80},
        meta={"team_id": team_id, "exec_in_container": exec_in},
    )


def test_composition_declares_one_scoped_execute_store():
    challenge = DolibarrWebsiteChallenge()
    specs = challenge.flag_store_specs()
    assert [(spec.name, spec.kind, spec.scope) for spec in specs] == [
        (STORE, OracleKind.EXECUTE, "host.command.execute")
    ]
    assert challenge.vulbox.exposed_ports == {"service": 80}


def test_plant_exposes_only_service_operation_parent(monkeypatch):
    operation_id = "a" * 32
    calls = []

    def execute(host, command):
        calls.append((host, command))
        return 0, operation_id

    handler = DolibarrWebsiteChallenge().flag_handler
    handle = handler.plant(target(execute), {STORE: Flag("FLAG{unit_test_value}")})[STORE]
    assert handler.flag_id(handle).endswith("/" + operation_id)
    assert "-m 711 /var/lib/cyberarena/dolibarr-proof" in calls[0][1]
    assert "-m 700 /var/lib/cyberarena/dolibarr-proof/tokens" in calls[0][1]


def test_retrieve_runs_operation_as_www_data():
    operation_id = "b" * 32
    flag = "FLAG{unit_test_value}"
    handle = json.dumps(
        {
            "flag_id": "/var/lib/cyberarena/dolibarr-proof/operations/" + operation_id,
            "flag": flag,
        }
    )
    calls = []

    def execute(host, command):
        calls.append((host, command))
        return 0, flag + "\n"

    observation = DolibarrWebsiteChallenge().flag_handler.retrieve(
        target(execute), handle, expected=flag
    )
    assert observation.status is ObservationStatus.PRESENT
    assert calls == [
        (
            "team1_prod",
            "su -s /bin/sh www-data -c "
            + "/var/lib/cyberarena/dolibarr-proof/operations/"
            + operation_id,
        )
    ]


def test_liveness_returns_red_when_http_is_down():
    result = DolibarrWebsiteChallenge().functionality_test.run(
        target(lambda _host, _command: (7, ""))
    )
    assert result.passed is False


def test_checker_is_network_only(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    expected_user, expected_password = checker_credentials(target(None))
    calls = []

    def login(base_url, username, password):
        calls.append((base_url, username, password))
        return object(), "token"

    monkeypatch.setattr(checker_module, "login", login)
    monkeypatch.setattr(checker_module, "create_site_and_page", lambda *_args: 17)
    monkeypatch.setattr(checker_module, "update_page", lambda *_args: "")
    monkeypatch.setattr(
        checker_module,
        "render_public",
        lambda *_args: "ARENA-DOLIBARR-" + "a" * 24 + " Website publication is available.",
    )
    monkeypatch.setattr(
        checker_module.secrets,
        "token_hex",
        lambda size: "a" * (size * 2),
    )
    result = DolibarrWebsiteChecker().run(
        target(lambda *_args: (_ for _ in ()).throw(AssertionError("exec used")))
    )
    assert result.passed is True
    assert calls == [("http://team1_prod:80", expected_user, expected_password)]


def test_principal_provisioning_creates_equal_role_checker(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    created = []
    monkeypatch.setattr(flag_handler_module, "_admin_password", lambda _target: "admin")
    monkeypatch.setattr(
        flag_handler_module,
        "login",
        lambda *_args: (object(), "token"),
    )
    monkeypatch.setattr(flag_handler_module, "configure_website", lambda *_args: None)
    monkeypatch.setattr(
        flag_handler_module,
        "ensure_editor",
        lambda _admin, _token, username, password, label: created.append(
            (username, password, label)
        ),
    )
    runtime_target = target(lambda *_args: (0, ""))
    principals = DolibarrWebsiteChallenge().flag_handler.provision_principals(
        runtime_target,
        {"team-a": "a" * 64, "team-b": "b" * 64},
    )
    checker_user, checker_password = checker_credentials(runtime_target)
    assert set(principals) == {"team-a", "team-b"}
    assert created[-1] == (checker_user, checker_password, "WebsiteEditor")
    assert checker_user not in {
        principal.principal_id for principal in principals.values()
    }


def test_certified_pov_uses_editor_workflow_and_proof_target(monkeypatch):
    published = {}
    monkeypatch.setattr(_exploit, "login", lambda *_args: (object(), "token"))
    monkeypatch.setattr(_exploit, "create_site_and_page", lambda *_args: 17)

    def update(_editor, _token, site, page_id, content):
        published.update(site=site, page_id=page_id, content=content)

    monkeypatch.setattr(_exploit, "update_page", update)
    monkeypatch.setattr(
        _exploit,
        "render_public",
        lambda *_args: "rendered FLAG{proof_from_service}",
    )
    recovered = _exploit.steal(
        "victim_prod",
        {"username": "editor", "password": "password"},
        "/proof/operation",
    )
    assert recovered == "FLAG{proof_from_service}"
    assert published["page_id"] == 17
    assert "<?PHP" in published["content"]
    assert 'shell_exec("/proof/operation")' in published["content"]


def test_certified_pov_reports_clean_block_as_success(monkeypatch, capsys):
    values = {
        "CYBERARENA_TEAM_TOKEN": "team-token",
        "CYBERARENA_SUBMIT_URL": "http://flag_service:8080/game/flag/submit",
    }
    monkeypatch.setattr(_exploit, "env", values.__getitem__)
    monkeypatch.setattr(
        _exploit,
        "post_json",
        lambda *_args, **_kwargs: {
            "targets": [
                {
                    "host": "victim_prod",
                    "service": "dolibarr-website",
                    "store": "service_command",
                    "flag_id": "/proof/operation",
                }
            ],
            "principals": [
                {
                    "host": "victim_prod",
                    "service": "dolibarr-website",
                    "credentials": {
                        "username": "editor",
                        "password": "password",
                    },
                }
            ],
        },
    )
    monkeypatch.setattr(_exploit, "steal", lambda *_args: None)

    assert _exploit.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "target_reached": True,
        "flag_recovered": False,
        "submission_status": "none",
    }
