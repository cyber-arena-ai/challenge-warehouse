from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("grafana_ids", ROOT / "_ids.py")
ids = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ids)


def test_principal_derivation_is_distinct_deterministic_and_seed_only() -> None:
    seed_a = "01" * 32
    seed_b = "02" * 32
    assert ids.derive_principal(seed_a) == ids.derive_principal(seed_a)
    assert ids.derive_principal(seed_a) != ids.derive_principal(seed_b)
    username, password = ids.derive_principal(seed_a)
    assert username == "arena_" + "01" * 10
    assert password.startswith("Gr!") and len(password) == 43


def test_public_ids_expose_only_rotating_targets() -> None:
    uid = "cp-" + "ab" * 12
    operation = "cd" * 16
    receiver = ids.pack_handle({
        "store": ids.STORE_PROTECTED_RECEIVER,
        "target": uid,
        "token": "FLAG{integrity}",
        "anchor_id": 4,
        "org_id": 1,
    })
    command = ids.pack_handle({
        "store": ids.STORE_COMMAND,
        "target": operation,
        "token": "FLAG{command}",
    })
    assert ids.public_flag_id(receiver) == uid
    assert ids.public_flag_id(command) == operation
    assert "FLAG" not in ids.public_flag_id(receiver)
    assert ids.public_flag_id("not-a-handle") is None


def test_service_operation_is_strictly_uid_472() -> None:
    operation = "ef" * 16
    assert ids.objective_command(operation) == (
        "setpriv --reuid=472 --regid=0 --clear-groups "
        "/usr/local/bin/grafana-objective " + operation
    )
    try:
        ids.objective_command("../bad")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid operation accepted")


def test_checker_material_is_private_deterministic_and_same_shape(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    ordinary = ids.checker_principals("victim", "ordinary")
    guarded = ids.checker_principals("victim", "guarded")
    assert ordinary == ids.checker_principals("victim", "ordinary")
    assert ordinary != guarded
    assert len(ordinary) == ids.CHECKER_PRINCIPALS_PER_ROLE
    for username, password in ordinary + guarded:
        assert re.fullmatch(r"arena_[0-9a-f]{20}", username)
        assert re.fullmatch(r"Gr![0-9a-f]{40}", password)


def test_checker_contacts_match_objective_record_shapes(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    contacts = ids.checker_contacts("victim")
    assert contacts == ids.checker_contacts("victim")
    assert len(set(contacts)) == ids.CHECKER_CONTACTS
    for uid, name, url in contacts:
        assert ids.valid_contact_uid(uid)
        assert ids.valid_contact_name(name)
        assert ids.valid_contact_url(url)
        assert "checker" not in name.lower() + url.lower()
        assert "arena" not in uid.lower() + name.lower() + url.lower()
        assert "example.invalid" not in url


def test_checker_material_requires_facility_secret(monkeypatch) -> None:
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    try:
        ids.checker_contacts("victim")
    except RuntimeError:
        pass
    else:
        raise AssertionError("checker material derived without facility secret")
