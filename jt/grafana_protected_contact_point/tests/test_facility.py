from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMAND_OPERATION = "1a" * 16
COMMAND_TOKEN = "FLAG{command-proof}"
SPEC = importlib.util.spec_from_file_location(
    "grafana_facility", ROOT / "image" / "facility.py"
)
facility = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(facility)


def encoded_request(**updates) -> str:
    document = {
        "uid": "cp-" + "a" * 24,
        "name": "Operations alerts 1234",
        "url": "http://192.168.21.22:8123/hooks/" + "c" * 24,
        "anchor_name": "FLAG{round-proof}",
        "anchor_id": 17,
        "command_operation": COMMAND_OPERATION,
        "command_sha256": facility.hashlib.sha256(
            COMMAND_TOKEN.encode()
        ).hexdigest(),
    }
    document.update(updates)
    return base64.b64encode(json.dumps(document).encode()).decode()


def journal(*, current=None, previous=None, pending=None) -> dict:
    return {"current": current, "previous": previous, "pending": pending}


def receiver(
    *, uid: str = "cp-" + "a" * 24, anchor_id: int = 17,
    anchor_name: str = "FLAG{round-proof}",
    name: str = "Operations alerts 1234",
    url: str = "http://192.168.21.22:8123/hooks/" + "c" * 24,
    command_operation: str = COMMAND_OPERATION,
    command_token: str = COMMAND_TOKEN,
) -> dict:
    return {
        "uid": uid,
        "anchor_id": anchor_id,
        "anchor_sha256": facility.hashlib.sha256(anchor_name.encode()).hexdigest(),
        "name": name,
        "url": url,
        "command_operation": command_operation,
        "command_sha256": facility.hashlib.sha256(
            command_token.encode()
        ).hexdigest(),
    }


def test_corrupt_receiver_state_fails_before_application_mutation(
    tmp_path: Path, monkeypatch,
) -> None:
    current = tmp_path / "current.json"
    current.write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", current)
    monkeypatch.setattr(
        facility, "get_contact", lambda *_args: (_ for _ in ()).throw(
            AssertionError("corrupt state must fail before application access")
        )
    )

    with pytest.raises(RuntimeError, match="invalid receiver state"):
        facility.stage_receiver(encoded_request())


def test_missing_contact_is_restored_with_same_uid_and_anchor(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    current = tmp_path / "current.json"
    current.write_text(json.dumps(journal(current=receiver())), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", current)
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "get_contact", lambda *_args: None)
    created: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        facility, "create_contact", lambda *args: created.append(args)
    )

    facility.stage_receiver(encoded_request())

    assert created == [(
        "cp-" + "a" * 24,
        "Operations alerts 1234",
        "http://192.168.21.22:8123/hooks/" + "c" * 24,
    )]
    assert json.loads(capsys.readouterr().out)["anchor_id"] == 17


def test_tampered_existing_contact_is_restored_exactly(
    tmp_path: Path, monkeypatch,
) -> None:
    current = tmp_path / "current.json"
    current.write_text(json.dumps(journal(current=receiver())), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", current)
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "get_contact", lambda *_args: {
        "type": "webhook", "name": "tampered", "settings": {"url": "http://wrong"},
    })
    updates: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        facility, "update_contact", lambda *args: updates.append(args)
    )

    facility.stage_receiver(encoded_request())

    assert updates == [(
        "cp-" + "a" * 24,
        "Operations alerts 1234",
        "http://192.168.21.22:8123/hooks/" + "c" * 24,
    )]


def test_missing_cached_anchor_is_irreconstructible_without_mutation(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(facility, "CURRENT", tmp_path / "missing.json")
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: False)
    monkeypatch.setattr(
        facility, "create_contact", lambda *_args: (_ for _ in ()).throw(
            AssertionError("missing anchor must fail before contact creation")
        )
    )

    with pytest.raises(RuntimeError, match="anchor identity is irreconstructible"):
        facility.stage_receiver(encoded_request())


def test_fresh_state_write_failure_compensates_application_objects(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(facility, "CURRENT", tmp_path / "missing.json")
    events: list[tuple[str, object]] = []
    monkeypatch.setattr(facility, "find_service_account", lambda _name: None)
    monkeypatch.setattr(facility, "get_contact", lambda _uid: None)
    monkeypatch.setattr(
        facility, "create_contact", lambda uid, _name, _url: events.append(("create", uid))
    )
    monkeypatch.setattr(facility, "create_service_account", lambda _name: 29)
    monkeypatch.setattr(
        facility, "write_private", lambda *_args: (_ for _ in ()).throw(OSError())
    )
    monkeypatch.setattr(
        facility, "delete_contact", lambda uid: events.append(("delete-contact", uid))
    )
    monkeypatch.setattr(
        facility,
        "delete_service_account",
        lambda account_id: events.append(("delete-anchor", account_id)),
    )

    with pytest.raises(OSError):
        facility.stage_receiver(encoded_request(anchor_id=None))

    assert [event[0] for event in events] == [
        "create", "delete-contact", "delete-anchor",
    ]


def test_provisional_retry_recovers_existing_anchor_without_duplicate(
    tmp_path: Path, monkeypatch,
) -> None:
    current = tmp_path / "missing.json"
    monkeypatch.setattr(facility, "CURRENT", current)
    monkeypatch.setattr(
        facility, "find_service_account", lambda _name: {
            "id": 31, "name": "FLAG{round-proof}", "isDisabled": False,
        }
    )
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(
        facility, "create_service_account", lambda _name: (_ for _ in ()).throw(
            AssertionError("recovered anchor must not be duplicated")
        )
    )
    monkeypatch.setattr(facility, "get_contact", lambda _uid: None)
    created: list[tuple[str, str, str]] = []
    monkeypatch.setattr(facility, "create_contact", lambda *args: created.append(args))

    facility.stage_receiver(encoded_request(anchor_id=None))

    state = json.loads(current.read_text(encoding="utf-8"))
    assert state["pending"]["anchor_id"] == 31
    assert created == [(
        "cp-" + "a" * 24,
        "Operations alerts 1234",
        "http://192.168.21.22:8123/hooks/" + "c" * 24,
    )]


def test_staging_new_receiver_preserves_published_current(
    tmp_path: Path, monkeypatch,
) -> None:
    state_path = tmp_path / "current.json"
    old = receiver()
    state_path.write_text(json.dumps(journal(current=old)), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", state_path)
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "get_contact", lambda _uid: None)
    monkeypatch.setattr(facility, "create_contact", lambda *_args: None)
    monkeypatch.setattr(
        facility, "delete_contact",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("published receiver must not be retired while staging")
        ),
    )

    facility.stage_receiver(encoded_request(
        uid="cp-" + "b" * 24,
        name="Platform webhook 5678",
        url="http://192.168.31.32:8456/hooks/" + "d" * 24,
        anchor_name="FLAG{next-round}",
        anchor_id=29,
        command_operation="2b" * 16,
        command_sha256=facility.hashlib.sha256(b"next-command").hexdigest(),
    ))

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["current"] == old
    assert state["previous"] is None
    assert state["pending"]["uid"] == "cp-" + "b" * 24
    assert state["pending"]["anchor_id"] == 29


def test_repeated_stage_reuses_pending_identity_without_new_objects(
    tmp_path: Path, monkeypatch,
) -> None:
    state_path = tmp_path / "current.json"
    pending = receiver()
    expected = journal(pending=pending)
    state_path.write_text(json.dumps(expected), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", state_path)
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "get_contact", lambda _uid: {
        "type": "webhook",
        "name": "Operations alerts 1234",
        "settings": {"url": "http://192.168.21.22:8123/hooks/" + "c" * 24},
    })
    monkeypatch.setattr(
        facility, "create_service_account",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must reuse pending")),
    )
    monkeypatch.setattr(
        facility, "create_contact",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must reuse pending")),
    )

    facility.stage_receiver(encoded_request())
    facility.stage_receiver(encoded_request())

    assert json.loads(state_path.read_text(encoding="utf-8")) == expected


def test_commit_retires_only_older_predecessor_and_is_retry_idempotent(
    tmp_path: Path, monkeypatch,
) -> None:
    state_path = tmp_path / "current.json"
    older = receiver(
        uid="cp-" + "9" * 24, anchor_id=9, anchor_name="FLAG{older}",
        name="Delivery alerts 2345",
        url="http://192.168.11.12:8234/hooks/" + "9" * 24,
        command_operation="09" * 16, command_token="older-command",
    )
    old = receiver(command_operation="0a" * 16, command_token="old-command")
    pending = receiver(
        uid="cp-" + "b" * 24, anchor_id=29, anchor_name="FLAG{next-round}",
        name="Platform webhook 5678",
        url="http://192.168.31.32:8456/hooks/" + "d" * 24,
        command_operation="0b" * 16, command_token="next-command",
    )
    state_path.write_text(json.dumps(journal(
        current=old, previous=older, pending=pending,
    )), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", state_path)
    objective_dir = tmp_path / "objectives"
    objective_dir.mkdir()
    monkeypatch.setattr(facility, "OBJECTIVE_DIR", objective_dir)
    for group, token in (
        (older, "older-command"), (old, "old-command"), (pending, "next-command"),
    ):
        (objective_dir / group["command_operation"]).write_text(
            f'{group["command_operation"]}\n{token}\n', encoding="utf-8"
        )
    (objective_dir / f'{older["command_operation"]}.new').write_text(
        "interrupted-write", encoding="utf-8"
    )
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "get_contact", lambda _uid: {
        "type": "webhook",
        "name": "Platform webhook 5678",
        "settings": {"url": "http://192.168.31.32:8456/hooks/" + "d" * 24},
    })
    deleted: list[tuple[str, object]] = []
    monkeypatch.setattr(
        facility, "delete_contact", lambda uid: deleted.append(("contact", uid))
    )
    monkeypatch.setattr(
        facility, "delete_service_account",
        lambda account_id: deleted.append(("anchor", account_id)),
    )
    request = encoded_request(
        uid="cp-" + "b" * 24,
        name="Platform webhook 5678",
        url="http://192.168.31.32:8456/hooks/" + "d" * 24,
        anchor_name="FLAG{next-round}",
        anchor_id=29,
        command_operation="0b" * 16,
        command_sha256=facility.hashlib.sha256(b"next-command").hexdigest(),
    )

    facility.commit_receiver(request)
    facility.commit_receiver(request)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state == journal(current=pending, previous=old)
    assert not (objective_dir / older["command_operation"]).exists()
    assert not (objective_dir / f'{older["command_operation"]}.new').exists()
    assert (objective_dir / old["command_operation"]).exists()
    assert (objective_dir / pending["command_operation"]).exists()
    assert deleted == [
        ("contact", "cp-" + "9" * 24),
        ("anchor", 9),
    ]


def test_interrupted_commit_keeps_current_and_pending_for_retry(
    tmp_path: Path, monkeypatch,
) -> None:
    state_path = tmp_path / "current.json"
    older = receiver(
        uid="cp-" + "9" * 24, anchor_id=9, anchor_name="FLAG{older}",
        name="Delivery alerts 2345",
        url="http://192.168.11.12:8234/hooks/" + "9" * 24,
        command_operation="09" * 16, command_token="older-command",
    )
    old = receiver(command_operation="0a" * 16, command_token="old-command")
    pending = receiver(
        uid="cp-" + "b" * 24, anchor_id=29, anchor_name="FLAG{next-round}",
        name="Platform webhook 5678",
        url="http://192.168.31.32:8456/hooks/" + "d" * 24,
        command_operation="0b" * 16, command_token="next-command",
    )
    original = journal(current=old, previous=older, pending=pending)
    state_path.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT", state_path)
    monkeypatch.setattr(facility, "OBJECTIVE_DIR", tmp_path / "objectives")
    monkeypatch.setattr(facility, "command_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "get_contact", lambda _uid: {
        "type": "webhook",
        "name": "Platform webhook 5678",
        "settings": {"url": "http://192.168.31.32:8456/hooks/" + "d" * 24},
    })
    monkeypatch.setattr(facility, "delete_contact", lambda _uid: None)
    monkeypatch.setattr(facility, "delete_service_account", lambda _account_id: None)
    monkeypatch.setattr(
        facility, "write_private",
        lambda *_args: (_ for _ in ()).throw(OSError("interrupted")),
    )

    with pytest.raises(OSError, match="interrupted"):
        facility.commit_receiver(encoded_request(
            uid="cp-" + "b" * 24,
            name="Platform webhook 5678",
            url="http://192.168.31.32:8456/hooks/" + "d" * 24,
            anchor_name="FLAG{next-round}",
            anchor_id=29,
            command_operation="0b" * 16,
            command_sha256=facility.hashlib.sha256(b"next-command").hexdigest(),
        ))

    assert json.loads(state_path.read_text(encoding="utf-8")) == original


def test_command_mismatch_cannot_promote_receiver_group(
    tmp_path: Path, monkeypatch,
) -> None:
    state_path = tmp_path / "current.json"
    old = receiver(command_operation="0a" * 16, command_token="old-command")
    pending = receiver(
        uid="cp-" + "b" * 24, anchor_id=29, anchor_name="FLAG{next-round}",
        name="Platform webhook 5678",
        url="http://192.168.31.32:8456/hooks/" + "d" * 24,
        command_operation="0b" * 16, command_token="next-command",
    )
    original = journal(current=old, pending=pending)
    state_path.write_text(json.dumps(original), encoding="utf-8")
    objective_dir = tmp_path / "objectives"
    objective_dir.mkdir()
    (objective_dir / pending["command_operation"]).write_text(
        f'{pending["command_operation"]}\nwrong-command\n', encoding="utf-8"
    )
    monkeypatch.setattr(facility, "CURRENT", state_path)
    monkeypatch.setattr(facility, "OBJECTIVE_DIR", objective_dir)
    monkeypatch.setattr(facility, "service_account_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "ensure_contact", lambda *_args: None)

    with pytest.raises(RuntimeError, match="command generation does not match"):
        facility.commit_receiver(encoded_request(
            uid="cp-" + "b" * 24,
            name="Platform webhook 5678",
            url="http://192.168.31.32:8456/hooks/" + "d" * 24,
            anchor_name="FLAG{next-round}",
            anchor_id=29,
            command_operation="0b" * 16,
            command_sha256=facility.hashlib.sha256(b"next-command").hexdigest(),
        ))

    assert json.loads(state_path.read_text(encoding="utf-8")) == original


@pytest.mark.parametrize(
    ("status", "value", "message"),
    [
        (503, None, "could not read contact points"),
        (200, {}, "response malformed"),
        (200, [{"uid": "cp-" + "a" * 24}, {"uid": "cp-" + "a" * 24}],
         "identity is ambiguous"),
    ],
)
def test_contact_read_errors_fail_closed(
    monkeypatch, status: int, value: object, message: str,
) -> None:
    monkeypatch.setattr(
        facility, "json_request", lambda *_args, **_kwargs: (status, value)
    )
    monkeypatch.setattr(facility, "credentials", lambda _name: ("u", "p"))

    with pytest.raises(RuntimeError, match=message):
        facility.get_contact("cp-" + "a" * 24)


def test_anchor_search_ambiguity_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(facility, "credentials", lambda _name: ("u", "p"))
    monkeypatch.setattr(
        facility,
        "json_request",
        lambda *_args, **_kwargs: (200, {"serviceAccounts": [
            {"id": 1, "name": "FLAG{x}"},
            {"id": 2, "name": "FLAG{x}"},
        ]}),
    )

    with pytest.raises(RuntimeError, match="identity is ambiguous"):
        facility.find_service_account("FLAG{x}")
