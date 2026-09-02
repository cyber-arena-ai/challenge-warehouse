from __future__ import annotations

import importlib.util
import secrets
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "xerte_media_upload_rce_ids", Path(__file__).resolve().parents[1] / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def seed() -> str:
    return secrets.token_hex(32)


def test_principal_derivation_is_deterministic_and_distinct():
    first = seed()
    assert ids.derive_principal(first) == ids.derive_principal(first)
    values = [ids.derive_principal(seed()) for _ in range(30)]
    assert len({row[0] for row in values}) == 30
    assert len({row[1] for row in values}) == 30


def test_checker_principals_are_target_specific_facility_material(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-one")
    first = ids.checker_principals("victim-a")
    second = ids.checker_principals("victim-b")
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-two")
    changed = ids.checker_principals("victim-a")

    assert len(first) == ids.CHECKER_PRINCIPAL_COUNT
    assert first != second != changed
    assert len(set(first)) == len(first)
    assert all(user.startswith("author") and password.startswith("Xa1!")
               for user, password in first)


def test_checker_principals_require_facility_material(monkeypatch):
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        ids.checker_principals("victim")


def test_objective_operation_is_stable_but_target_and_round_specific(monkeypatch):
    first = ids.objective_operation(
        "objective-key", "victim-a", "FLAG{round-one}")

    assert first == ids.objective_operation(
        "objective-key", "victim-a", "FLAG{round-one}")
    assert first != ids.objective_operation(
        "objective-key", "victim-b", "FLAG{round-one}")
    assert first != ids.objective_operation(
        "objective-key", "victim-a", "FLAG{round-two}")
    assert first != ids.objective_operation(
        "other-key", "victim-a", "FLAG{round-one}")
    assert len(first) == 32


def test_short_seed_is_rejected():
    with pytest.raises(ValueError):
        ids.derive_principal("abcd")


def test_execute_target_round_trip_and_validation():
    encoded = ids.encode_execute_target(operation="a" * 32)
    assert ids.decode_execute_target(encoded) == {"v": 1, "op": "a" * 32}
    assert ids.decode_execute_target("garbage") is None
    assert ids.decode_execute_target(
        ids.pack_handle({"v": 1, "op": ""})) is None


def test_public_target_carries_the_locator_and_no_proof_material():
    flag = "FLAG{never-public}"
    password = "Xa1!deadbeef"
    target = ids.encode_execute_target(operation="b" * 32)
    handle = ids.pack_handle({"store": ids.STORE_COMMAND, "op": "b" * 32,
                              "target": target, "flag": flag,
                              "password": password})
    published = ids.public_flag_id(handle)
    assert published == target
    assert flag not in published
    assert password not in published
    decoded = ids.decode_execute_target(published)
    assert set(decoded) == {"v", "op"}


def test_execute_flag_id_rotates_with_the_operation():
    def handle(operation: str) -> str:
        return ids.pack_handle({
            "store": ids.STORE_COMMAND, "op": operation,
            "target": ids.encode_execute_target(operation=operation)})

    first, second = ids.public_flag_id(handle("1" * 32)), ids.public_flag_id(handle("2" * 32))
    assert first and second and first != second


def test_public_flag_id_is_total_and_store_scoped():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.public_flag_id(bad) is None
    assert ids.public_flag_id(ids.pack_handle({"store": "other", "target": "x"})) is None
    assert ids.public_flag_id(
        ids.pack_handle({"store": ids.STORE_COMMAND, "target": "not-a-target"})) is None


def test_helper_runs_only_in_the_service_execution_context():
    command = ids.catflag_command("deadbeef" * 4)
    assert command.split() == [
        "runuser", "-u", ids.SERVICE_USER, "--", ids.CATFLAG_PATH, "deadbeef" * 4]
    with pytest.raises(ValueError):
        ids.catflag_command("")


def test_project_layout_matches_the_application():
    assert ids.project_dir(4, "curator01") == "USER-FILES/4-curator01-Nottingham"
    assert ids.project_path(4, "curator01") == "/USER-FILES/4-curator01-Nottingham/"


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
