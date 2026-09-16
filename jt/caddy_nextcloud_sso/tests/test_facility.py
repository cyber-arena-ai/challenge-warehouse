from __future__ import annotations

import importlib.util
import base64
import json
from pathlib import Path
import subprocess

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_facility",
    Path(__file__).resolve().parents[1] / "image" / "facility.py")
facility = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(facility)


def state() -> dict:
    return {
        "accounts": [
            {"username": "user" + "a" * 16, "hash": "$2a$14$guarded",
             "guarded": True},
            {"username": "user" + "b" * 16, "hash": "$2a$14$ordinary",
             "guarded": False},
            {"username": "user" + "c" * 16, "hash": "$2a$14$principal",
             "guarded": False},
        ],
    }


def test_rendered_caddyfile_has_only_loopback_internal_listeners():
    rendered = facility.render_caddyfile(state())
    assert "admin 127.0.0.1:2019" in rendered
    assert "\n:9080 {\n\tbind 127.0.0.1" in rendered
    assert "http://127.0.0.1:9080" not in rendered
    assert "php_fastcgi 127.0.0.1:9000" in rendered
    assert "\n:8080 {" in rendered
    assert "Remote-User {http.auth.user.id}" in rendered
    assert "Remote-Groups guarded" in rendered
    assert "useraaaaaaaaaaaaaaaa" in rendered
    assert "userbbbbbbbbbbbbbbbb" in rendered
    assert "usercccccccccccccccc" in rendered
    assert "@guarded expression `{http.auth.user.id} == \"useraaaaaaaaaaaaaaaa\"`" in rendered


def test_principal_normalization_is_stable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)
    raw = [{"username": "user" + "b" * 16, "password": "C1!" + "2" * 32,
            "guarded": False}]
    first, transient = facility.normalize_principals(raw, [])
    second, _ = facility.normalize_principals(raw, first)
    assert first == second
    assert first[0]["hash"].startswith("hash:")
    assert "password" not in first[0]
    assert transient[0]["password"] == raw[0]["password"]


def test_principal_normalization_rejects_duplicates(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)
    row = {"username": "user" + "c" * 16, "password": "C1!" + "3" * 32,
           "guarded": False}
    with pytest.raises(ValueError):
        facility.normalize_principals([row, row], [])


def test_malformed_principal_batch_fails_before_application_mutation(monkeypatch):
    monkeypatch.setattr(facility, "load_state", state)
    monkeypatch.setattr(
        facility, "install_config",
        lambda _pending: pytest.fail("malformed batch reached application config"),
    )
    malformed = base64.b64encode(json.dumps([
        {"username": "not-a-user", "password": "C1!" + "3" * 32,
         "guarded": False},
    ]).encode()).decode()

    with pytest.raises(facility.PrincipalProvisioningError) as failure:
        facility.principals(malformed)

    assert failure.value.stage == "input"
    assert failure.value.retryable is False


def test_main_emits_only_secret_safe_principal_stage(monkeypatch, capsys):
    monkeypatch.setattr(
        facility, "principals",
        lambda _encoded: (_ for _ in ()).throw(
            facility.PrincipalProvisioningError(
                "role-mismatch", retryable=False)),
    )
    monkeypatch.setattr(
        facility.sys, "argv", ["facility.py", "principals", "secret-material"],
    )

    assert facility.main() == 64
    assert capsys.readouterr().out == (
        "ERROR stage=role-mismatch retryable=0\n")


def test_principal_role_cannot_change(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)
    username = "user" + "d" * 16
    old = [{"username": username, "hash": "hash:old", "guarded": True}]
    raw = [{"username": username, "password": "C1!" + "4" * 32,
            "guarded": False}]
    with pytest.raises(ValueError, match="role changed"):
        facility.normalize_principals(raw, old)


def test_principal_provisioning_persists_hashes_not_plaintext(
    monkeypatch: pytest.MonkeyPatch, capsys,
):
    existing = state()
    saved = []
    installed = []
    password = "C1!" + "5" * 32
    users = [
        {"username": "user" + "d" * 16, "password": password,
         "guarded": False, "verify": True},
        {"username": "user" + "e" * 16, "password": "C1!" + "6" * 32,
         "guarded": True},
        {"username": "user" + "f" * 16, "password": "C1!" + "7" * 32,
         "guarded": False},
    ]
    encoded = base64.b64encode(json.dumps(users).encode()).decode()

    monkeypatch.setattr(facility, "load_state", lambda: existing)
    monkeypatch.setattr(
        facility, "hash_password", lambda value: "bcrypt-placeholder-" + value[-1])
    monkeypatch.setattr(facility, "install_config", installed.append)
    verified = []

    def user_info(account, **_kwargs):
        verified.append(account["username"])
        return {
            "groups": ["SAML_guarded"] if account["guarded"] else [],
        }

    monkeypatch.setattr(facility, "user_info", user_info)
    monkeypatch.setattr(facility, "save_state", saved.append)

    facility.principals(encoded)

    assert installed == saved
    assert capsys.readouterr().out == "OK 3\n"
    assert verified == ["user" + "d" * 16, "user" + "e" * 16]
    serialized = json.dumps(saved[0])
    assert password not in serialized
    assert '"password"' not in serialized
    assert '"verify"' not in serialized
    assert all("hash" in account for account in saved[0]["accounts"])


def test_principal_role_mismatch_is_permanent_and_state_is_not_published(
    monkeypatch: pytest.MonkeyPatch,
):
    existing = state()
    saved = []
    raw = [
        {"username": "user" + "d" * 16, "password": "C1!" + "4" * 32,
         "guarded": False, "verify": True},
        {"username": "user" + "e" * 16, "password": "C1!" + "5" * 32,
         "guarded": True},
    ]
    monkeypatch.setattr(facility, "load_state", lambda: existing)
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)
    monkeypatch.setattr(facility, "install_config", lambda _pending: None)
    monkeypatch.setattr(
        facility, "user_info", lambda account, **_kwargs: {
            "groups": ["SAML_guarded"] if not account["guarded"] else [],
        },
    )
    monkeypatch.setattr(facility, "save_state", saved.append)

    with pytest.raises(facility.PrincipalProvisioningError) as failure:
        facility.principals(base64.b64encode(json.dumps(raw).encode()).decode())

    assert failure.value.stage == "role-mismatch"
    assert failure.value.retryable is False
    assert saved == []


def test_setup_reconciles_guarded_team_folder_delete_permission(
    monkeypatch: pytest.MonkeyPatch,
):
    existing = {**state(), "folder": "7"}
    calls = []
    saved = []
    monkeypatch.setattr(facility, "load_state", lambda: existing)
    monkeypatch.setattr(facility, "bootstrap_credentials", lambda: {})
    monkeypatch.setattr(
        facility, "user_info", lambda _account: {"groups": ["SAML_guarded"]})
    monkeypatch.setattr(
        facility, "occ", lambda *arguments: calls.append(arguments) or "")
    monkeypatch.setattr(facility, "save_state", saved.append)

    facility.setup()

    assert calls == [
        ("groupfolders:group", "7", "SAML_guarded", "read", "write", "delete")
    ]
    assert saved == [existing]


def test_configure_uses_only_exact_native_hosts(
    monkeypatch: pytest.MonkeyPatch,
):
    calls = []
    monkeypatch.setattr(facility, "load_state", lambda: {"provider": "1"})
    monkeypatch.setattr(
        facility, "occ", lambda *arguments: calls.append(arguments) or "")
    monkeypatch.setattr(
        facility,
        "trusted_domains",
        lambda: ("team1_prod", "team1_ingress", "10.176.1.2", "127.0.0.1"),
    )
    monkeypatch.setattr(facility, "save_state", lambda _state: None)

    facility.configure_apps()

    assert ("app:enable", "user_saml") in calls
    assert ("app:enable", "groupfolders") in calls
    assert ("config:system:set", "skeletondirectory", "--value=") in calls
    domain_calls = [call for call in calls if "trusted_domains" in call]
    assert domain_calls == [
        ("config:system:delete", "trusted_domains"),
        ("config:system:set", "trusted_domains", "0", "--value=team1_prod"),
        ("config:system:set", "trusted_domains", "1", "--value=team1_ingress"),
        ("config:system:set", "trusted_domains", "2", "--value=10.176.1.2"),
        ("config:system:set", "trusted_domains", "3", "--value=127.0.0.1"),
    ]
    assert "*" not in " ".join(part for call in domain_calls for part in call)
    assert not [call for call in calls if call[0] == "app:disable"]
    assert calls.index(
        ("config:system:set", "skeletondirectory", "--value=")
    ) < calls.index(
        ("config:app:set", "user_saml", "type", "--value=environment-variable")
    )


def test_trusted_domains_derive_exact_prod_ingress_and_local_hosts(monkeypatch):
    monkeypatch.setattr(facility.socket, "gethostname", lambda: "team7_prod")
    monkeypatch.setattr(
        facility.socket, "gethostbyname", lambda host: "10.176.7.2")

    assert facility.trusted_domains() == (
        "team7_prod", "team7_ingress", "10.176.7.2", "127.0.0.1",
    )


def test_occ_json_ignores_leading_php_warning(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        facility, "occ",
        lambda *args, **_kwargs: 'PHP warning\n{"installed":true}',
    )
    assert facility.occ_json("status", "--output=json") == {"installed": True}


def test_user_info_confirms_native_state_after_first_login_timeout(
    monkeypatch: pytest.MonkeyPatch,
):
    account = {"username": "user" + "a" * 16, "password": "C1!" + "1" * 32}
    login_calls = 0

    class SlowFirstLogin:
        def __init__(self, actual, *, timeout):
            assert actual == account
            assert timeout == facility.PRINCIPAL_REQUEST_TIMEOUT_SECONDS

        def login(self):
            nonlocal login_calls
            login_calls += 1
            if login_calls == 1:
                raise TimeoutError("first-login jobs still running")

    calls = []
    sleeps = []
    monkeypatch.setattr(facility, "PublicClient", SlowFirstLogin)
    monkeypatch.setattr(facility.time, "sleep", sleeps.append)

    def delayed_user_info(*args, **_kwargs):
        calls.append(args)
        if len(calls) < 3:
            raise RuntimeError("database is locked")
        return {"groups": []}

    monkeypatch.setattr(facility, "occ_json", delayed_user_info)

    assert facility.user_info(account) == {"groups": []}
    assert calls == [
        ("user:info", account["username"], "--output=json"),
        ("user:info", account["username"], "--output=json"),
        ("user:info", account["username"], "--output=json"),
    ]
    assert login_calls == 2
    assert sleeps == [0.25, 0.25, 0.5]


def test_user_info_fails_closed_when_occ_remains_unavailable(
    monkeypatch: pytest.MonkeyPatch,
):
    account = {"username": "user" + "b" * 16, "password": "C1!" + "2" * 32}

    class SlowFirstLogin:
        def __init__(self, actual, *, timeout):
            assert actual == account
            assert timeout == facility.PRINCIPAL_REQUEST_TIMEOUT_SECONDS

        def login(self):
            raise TimeoutError("first-login jobs still running")

    monkeypatch.setattr(facility, "PublicClient", SlowFirstLogin)
    monkeypatch.setattr(facility.time, "sleep", lambda _delay: None)
    clock = iter((0.0, facility.PRINCIPAL_CONVERGENCE_SECONDS + 1))
    monkeypatch.setattr(facility.time, "monotonic", lambda: next(clock))

    with pytest.raises(RuntimeError, match="principal login did not converge"):
        facility.user_info(account)


def test_user_info_does_not_start_login_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
):
    account = {"username": "user" + "c" * 16, "password": "C1!" + "3" * 32}
    monkeypatch.setattr(facility.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(
        facility,
        "PublicClient",
        lambda *_args, **_kwargs: pytest.fail("expired login was started"),
    )

    with pytest.raises(RuntimeError, match="principal login did not converge"):
        facility.user_info(account, deadline=10.0)


def test_user_info_does_not_start_occ_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
):
    account = {"username": "user" + "d" * 16, "password": "C1!" + "4" * 32}
    clock = iter((0.0, 10.0))
    monkeypatch.setattr(facility.time, "monotonic", lambda: next(clock))

    class SuccessfulLogin:
        def __init__(self, actual, *, timeout):
            assert actual == account
            assert timeout == 10.0

        def login(self):
            return None

    monkeypatch.setattr(facility, "PublicClient", SuccessfulLogin)
    monkeypatch.setattr(
        facility,
        "occ_json",
        lambda *_args, **_kwargs: pytest.fail("expired OCC command was started"),
    )

    with pytest.raises(
        RuntimeError, match="principal user information did not converge",
    ):
        facility.user_info(account, deadline=10.0)


def test_user_info_clamps_login_and_occ_to_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
):
    account = {"username": "user" + "e" * 16, "password": "C1!" + "5" * 32}
    clock = iter((6.0, 7.0))
    monkeypatch.setattr(facility.time, "monotonic", lambda: next(clock))
    observed = {}

    class SuccessfulLogin:
        def __init__(self, actual, *, timeout):
            assert actual == account
            observed["login_timeout"] = timeout

        def login(self):
            return None

    def user_info(*_args, timeout):
        observed["occ_timeout"] = timeout
        return {"groups": []}

    monkeypatch.setattr(facility, "PublicClient", SuccessfulLogin)
    monkeypatch.setattr(facility, "occ_json", user_info)

    assert facility.user_info(account, deadline=10.0) == {"groups": []}
    assert observed == {"login_timeout": 4.0, "occ_timeout": 3.0}


def test_user_info_translates_occ_timeout_after_budget_expires(
    monkeypatch: pytest.MonkeyPatch,
):
    account = {"username": "user" + "f" * 16, "password": "C1!" + "6" * 32}
    clock = iter((0.0, 1.0, 10.0))
    monkeypatch.setattr(facility.time, "monotonic", lambda: next(clock))

    class SuccessfulLogin:
        def __init__(self, actual, *, timeout):
            assert actual == account
            assert timeout == 10.0

        def login(self):
            return None

    def timed_out(*_args, timeout):
        assert timeout == 9.0
        raise subprocess.TimeoutExpired(["occ"], timeout)

    monkeypatch.setattr(facility, "PublicClient", SuccessfulLogin)
    monkeypatch.setattr(facility, "occ_json", timed_out)

    with pytest.raises(
        RuntimeError, match="principal user information did not converge",
    ):
        facility.user_info(account, deadline=10.0)


def test_issued_cohort_storage_is_atomic_root_only(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(facility, "ISSUED_COHORT", tmp_path / "cohort")
    ownership = []
    monkeypatch.setattr(
        facility.os, "fchown",
        lambda _descriptor, uid, gid: ownership.append((uid, gid)),
    )
    sealed = "payload." + "a" * 64

    facility.store_issued_cohort(sealed)

    assert capsys.readouterr().out == "OK\n"
    assert facility.ISSUED_COHORT.read_text() == sealed
    assert facility.ISSUED_COHORT.stat().st_mode & 0o777 == 0o400
    assert ownership == [(0, 0)]
    assert list(tmp_path.glob(".cohort.*.tmp")) == []


def group(offset: int) -> dict:
    values = "abcdef0123456789"
    return {
        "group": values[offset] * 64,
        "target": "Guarded/autumn-" + values[offset + 1] * 32 + ".txt",
        "cover": "Guarded/bridge-" + values[offset + 2] * 32 + ".txt",
        "owner": offset % 4,
        "cover_after": bool(offset % 2),
        "operation": values[offset + 3] * 32,
        "read_digest": values[offset + 4] * 64,
        "command_digest": values[offset + 5] * 64,
        "read_cache": values[offset + 6] * 64,
        "command_cache": values[offset + 7] * 64,
    }


def encoded(value: object) -> str:
    return base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode()


def test_group_journal_promotes_and_retires_bounded_generations(
    monkeypatch, tmp_path, capsys,
):
    persisted = {
        **state(),
        "objective_groups": {slot: None for slot in facility.GROUP_SLOTS},
    }

    def save(value):
        copied = json.loads(json.dumps(value))
        persisted.clear()
        persisted.update(copied)

    monkeypatch.setattr(facility, "load_state", lambda: persisted)
    monkeypatch.setattr(facility, "save_state", save)
    monkeypatch.setattr(facility, "OBJECTIVE_DIR", tmp_path / "objective")
    monkeypatch.setattr(facility, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(
        facility, "OBJECTIVE_GROUPS_ISSUED", tmp_path / "groups.issued")
    facility.OBJECTIVE_DIR.mkdir()
    facility.CACHE_DIR.mkdir()
    first = group(0)
    second = group(8)

    facility.record_pending(encoded(first), encoded(None))
    facility.promote_pending(encoded(first))
    facility.record_pending(encoded(second), encoded(first))
    facility.promote_pending(encoded(second))
    assert persisted["objective_groups"]["current"] == second
    assert persisted["objective_groups"]["previous"] == first

    for path in (
        facility.OBJECTIVE_DIR / first["operation"],
        facility.CACHE_DIR / first["read_cache"],
        facility.CACHE_DIR / first["command_cache"],
    ):
        path.write_text("old")
    facility.begin_retirement(encoded(first))
    assert persisted["objective_groups"]["previous"] is None
    assert persisted["objective_groups"]["retiring"] == first
    facility.finish_retirement(encoded(first))

    assert persisted["objective_groups"]["retiring"] is None
    assert not list(facility.OBJECTIVE_DIR.iterdir())
    assert not list(facility.CACHE_DIR.iterdir())
    assert capsys.readouterr().out.count("OK\n") == 6


def test_initial_boot_is_distinct_from_issued_journal_loss(monkeypatch, tmp_path):
    monkeypatch.setattr(facility, "STATE", tmp_path / "facility.json")
    monkeypatch.setattr(
        facility, "OBJECTIVE_GROUPS_ISSUED", tmp_path / "groups.issued")
    monkeypatch.setattr(
        facility,
        "bootstrap_credentials",
        lambda: {"username": "user" + "a" * 16, "password": "C1!" + "1" * 32},
    )
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)

    initial = facility.load_state()

    assert facility.objective_groups(initial) == {
        slot: None for slot in facility.GROUP_SLOTS
    }
    assert not facility.OBJECTIVE_GROUPS_ISSUED.exists()


def test_a_b_journal_loss_fails_closed_before_c(monkeypatch, tmp_path):
    monkeypatch.setattr(facility, "STATE", tmp_path / "facility.json")
    monkeypatch.setattr(
        facility, "OBJECTIVE_GROUPS_ISSUED", tmp_path / "groups.issued")
    facility.save_state({
        **state(),
        "provider": "1",
        "folder": "7",
        "objective_groups": {slot: None for slot in facility.GROUP_SLOTS},
    })
    first = group(0)
    second = group(8)
    third = group(4)

    facility.record_pending(encoded(first), encoded(None))
    facility.promote_pending(encoded(first))
    facility.record_pending(encoded(second), encoded(first))
    facility.promote_pending(encoded(second))
    facility.STATE.unlink()

    with pytest.raises(RuntimeError, match="missing after objective issuance"):
        facility.load_state()
    with pytest.raises(RuntimeError, match="missing after objective issuance"):
        facility.record_pending(encoded(third), encoded(second))
    assert facility.OBJECTIVE_GROUPS_ISSUED.read_text() == (
        facility.OBJECTIVE_GROUPS_ISSUED_VALUE
    )


def test_group_journal_rejects_stale_expected_current(monkeypatch, tmp_path):
    first = group(0)
    persisted = {
        **state(),
        "objective_groups": {
            "current": first, "previous": None,
            "pending": None, "retiring": None,
        },
    }
    monkeypatch.setattr(facility, "load_state", lambda: persisted)
    marker = tmp_path / "groups.issued"
    marker.write_text(facility.OBJECTIVE_GROUPS_ISSUED_VALUE)
    monkeypatch.setattr(facility, "OBJECTIVE_GROUPS_ISSUED", marker)

    with pytest.raises(RuntimeError, match="changed before staging"):
        facility.record_pending(encoded(group(8)), encoded(None))


@pytest.mark.parametrize("field", ("owner", "target", "read_cache"))
def test_group_state_rejects_malformed_records(monkeypatch, field):
    malformed = group(0)
    malformed[field] = True
    monkeypatch.setattr(
        facility,
        "load_state",
        lambda: {
            "objective_groups": {
                "current": malformed, "previous": None,
                "pending": None, "retiring": None,
            },
        },
    )

    with pytest.raises(RuntimeError, match="state malformed"):
        facility.read_group_state()


def test_cache_pruning_keeps_only_valid_allowlist(monkeypatch, tmp_path):
    monkeypatch.setattr(facility, "CACHE_DIR", tmp_path)
    keep = "a" * 64
    remove = "b" * 64
    (tmp_path / keep).write_text("keep")
    (tmp_path / remove).write_text("remove")

    facility.prune_caches(encoded([keep]))

    assert (tmp_path / keep).read_text() == "keep"
    assert not (tmp_path / remove).exists()
