from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "suitecrm_facility", ROOT / "image" / "facility.py"
)
facility = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(facility)


def account(value: str) -> dict[str, str]:
    return {
        "username": "arena_" + value * 16,
        "password": "S7!" + value * 32,
        "group": "Arena partition " + value * 8,
    }


def test_principal_batch_is_sorted_and_rejects_duplicates() -> None:
    normalized = facility.normalize_principal_batch([account("b"), account("a")])
    assert [item["username"] for item in normalized] == sorted(
        item["username"] for item in normalized
    )
    try:
        facility.normalize_principal_batch([account("a"), account("a")])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate principal accepted")


def test_sql_string_escapes_quotes() -> None:
    assert facility.sql_string("alpha'beta") == "'alpha''beta'"


def test_uuid_validation_is_strict() -> None:
    assert facility.valid_uuid("12345678-1234-1234-1234-123456789abc")
    assert not facility.valid_uuid("12345678-1234-1234-1234-123456789ABC")
    assert not facility.valid_uuid("../12345678-1234-1234-1234-123456789abc")
    assert facility.valid_note_uuid("12345678-1234-4abc-8abc-123456789abc")
    assert not facility.valid_note_uuid("12345678-1234-babc-aabc-123456789abc")


def test_principal_setup_does_not_persist_checker_credentials(
    monkeypatch, capsys,
) -> None:
    accounts = [account("a"), account("b"), account("c"), account("d")]
    client_id = "12345678-1234-1234-1234-123456789abc"
    raw = {
        "accounts": accounts,
        "checker": {
            "ordinary": [accounts[0]["username"], accounts[1]["username"]],
            "guarded": [accounts[2]["username"], accounts[3]["username"]],
        },
        "client": {"id": client_id, "secret": "S7!" + "c" * 40},
    }
    state: dict[str, object] = {"role_id": "role", "current_group": None}
    saved: list[dict[str, object]] = []
    monkeypatch.setattr(facility, "initialize", lambda: state)
    monkeypatch.setattr(facility, "admin_api", lambda: object())
    monkeypatch.setattr(
        facility, "ensure_client",
        lambda _api, value, checked_id, _secret: value.update(client_id=checked_id),
    )
    monkeypatch.setattr(facility, "ensure_account", lambda *_args: "user-id")
    monkeypatch.setattr(facility, "save_state", lambda value: saved.append(dict(value)))

    facility.provision(base64.b64encode(json.dumps(raw).encode()).decode())

    assert json.loads(capsys.readouterr().out) == {
        "client_id": client_id,
        "count": 4,
    }
    serialized = json.dumps(saved[-1])
    assert "password" not in serialized
    assert raw["client"]["secret"] not in serialized
    assert "ordinary" not in saved[-1] and "guarded" not in saved[-1]


def test_note_group_journal_transitions_are_atomic_and_contain_no_proof(
    monkeypatch, tmp_path, capsys,
) -> None:
    monkeypatch.setattr(facility, "STATE", tmp_path / "facility.json")
    monkeypatch.setattr(facility, "OBJECTIVE_DIR", tmp_path / "objectives")
    facility.OBJECTIVE_DIR.mkdir()
    note_id = "12345678-1234-4abc-8abc-123456789abc"
    next_note = "87654321-4321-4cba-8cba-cba987654321"
    final_note = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    operation = "1" * 32
    next_operation = "2" * 32
    final_operation = "3" * 32
    note_digest = "4" * 64
    command_digest = "5" * 64
    note_cache = "a" * 64
    command_cache = "b" * 64
    group = "0" * 64
    next_group = "1" * 64
    final_group = "2" * 64

    facility.record_pending(
        group, note_id, operation, note_digest, command_digest, note_cache, command_cache,
        "NONE", "NONE", "NONE", "NONE", "NONE", "NONE", "NONE",
    )
    assert capsys.readouterr().out.strip() == "OK"
    facility.promote_pending(
        group, note_id, operation, note_digest, command_digest, note_cache, command_cache,
    )
    assert capsys.readouterr().out.strip() == "OK"
    facility.record_pending(
        next_group, next_note, next_operation,
        "6" * 64, "7" * 64, "c" * 64, "d" * 64,
        group, note_id, operation,
        note_digest, command_digest, note_cache, command_cache,
    )
    assert capsys.readouterr().out.strip() == "OK"
    facility.promote_pending(
        next_group, next_note, next_operation,
        "6" * 64, "7" * 64, "c" * 64, "d" * 64,
    )
    assert capsys.readouterr().out.strip() == "OK"
    assert facility.group_state() == {
        "current": {
            "group": next_group,
            "note": next_note,
            "operation": next_operation,
            "note_digest": "6" * 64,
            "command_digest": "7" * 64,
            "note_cache": "c" * 64,
            "command_cache": "d" * 64,
        },
        "previous": {
            "group": group,
            "note": note_id,
            "operation": operation,
            "note_digest": note_digest,
            "command_digest": command_digest,
            "note_cache": note_cache,
            "command_cache": command_cache,
        },
        "pending": None,
        "retiring": None,
    }
    facility.record_pending(
        final_group, final_note, final_operation,
        "8" * 64, "9" * 64, "e" * 64, "f" * 64,
        next_group, next_note, next_operation,
        "6" * 64, "7" * 64, "c" * 64, "d" * 64,
    )
    assert capsys.readouterr().out.strip() == "OK"
    facility.promote_pending(
        final_group, final_note, final_operation,
        "8" * 64, "9" * 64, "e" * 64, "f" * 64,
    )
    assert capsys.readouterr().out.strip() == "OK"
    assert facility.group_state()["retiring"]["note"] == note_id
    (facility.OBJECTIVE_DIR / operation).write_text("old command")
    facility.finish_retirement(
        group, note_id, operation,
        note_digest, command_digest, note_cache, command_cache,
    )
    assert capsys.readouterr().out.strip() == "OK"
    assert not (facility.OBJECTIVE_DIR / operation).exists()
    assert json.loads(facility.STATE.read_text()) == {
        "client_id": "",
        "current_group": {
            "group": final_group,
            "note": final_note,
            "operation": final_operation,
            "note_digest": "8" * 64,
            "command_digest": "9" * 64,
            "note_cache": "e" * 64,
            "command_cache": "f" * 64,
        },
        "previous_group": {
            "group": next_group,
            "note": next_note,
            "operation": next_operation,
            "note_digest": "6" * 64,
            "command_digest": "7" * 64,
            "note_cache": "c" * 64,
            "command_cache": "d" * 64,
        },
        "pending_group": None,
        "retiring_group": None,
        "role_id": "",
    }
