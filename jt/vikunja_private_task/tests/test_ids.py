from __future__ import annotations

import importlib.util
import secrets
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "vikunja_private_task_ids", Path(__file__).resolve().parents[1] / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def seed() -> str:
    return secrets.token_hex(32)


def test_principal_derivation_is_deterministic_and_distinct():
    first = seed()
    assert ids.derive_principal(first) == ids.derive_principal(first)
    values = [ids.derive_principal(seed()) for _ in range(30)]
    assert len({row[0] for row in values}) == 30
    assert len({row[2] for row in values}) == 30


def test_short_seed_is_rejected():
    with pytest.raises(ValueError):
        ids.derive_principal("abcd")


def test_read_target_round_trip_and_validation():
    encoded = ids.encode_read_target(
        shared_project_id=1, shared_task_id=2, private_task_id=3,
        private_uid="6c9365aa-70d4-4d34-b05c-743bfa0a9c7b")
    decoded = ids.decode_read_target(encoded)
    assert decoded == {
        "v": 1,
        "shared_project_id": 1,
        "shared_task_id": 2,
        "private_task_id": 3,
        "private_uid": "6c9365aa-70d4-4d34-b05c-743bfa0a9c7b",
    }
    assert ids.decode_read_target("garbage") is None


def test_public_ids_never_publish_the_flag():
    flag = "FLAG{never-public}"
    target = ids.encode_read_target(
        shared_project_id=4, shared_task_id=5, private_task_id=6,
        private_uid="uid")
    read = ids.pack_handle({"store": ids.STORE_PRIVATE_TASK,
                            "target": target, "flag": flag})
    execute = ids.pack_handle({"store": ids.STORE_COMMAND,
                               "op": "a" * 32, "flag": flag})
    assert ids.public_flag_id(read) == target
    assert ids.public_flag_id(execute) == "a" * 32
    assert flag not in ids.public_flag_id(read)
    assert flag not in ids.public_flag_id(execute)


def test_execute_target_rotates_and_helper_is_service_scoped():
    first = ids.pack_handle({"store": ids.STORE_COMMAND, "op": "1" * 32})
    second = ids.pack_handle({"store": ids.STORE_COMMAND, "op": "2" * 32})
    assert ids.public_flag_id(first) != ids.public_flag_id(second)
    command = ids.catflag_command("deadbeef" * 4)
    assert command.split() == [
        "su-exec", ids.SERVICE_USER, ids.CATFLAG_PATH, "deadbeef" * 4]


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
