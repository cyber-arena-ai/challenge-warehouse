from __future__ import annotations

import importlib.util
import secrets
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_ids", Path(__file__).resolve().parents[1] / "_ids.py")
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


def test_short_seed_is_rejected():
    with pytest.raises(ValueError):
        ids.derive_principal("abcd")


def test_public_targets_are_validated_and_do_not_publish_proofs():
    proof = "FLAG{never-public}"
    path = "Guarded/" + "a" * 24 + ".txt"
    operation = "b" * 32
    read = ids.pack_handle({
        "store": ids.STORE_GUARDED_FILE, "target": path, "flag": proof,
    })
    execute = ids.pack_handle({
        "store": ids.STORE_COMMAND, "target": operation, "flag": proof,
    })
    assert ids.public_flag_id(read) == path
    assert ids.public_flag_id(execute) == operation
    assert ids.valid_read_target("Guarded/../../secret.txt") is False
    assert ids.valid_operation("not-an-operation") is False


def test_execute_command_uses_service_context():
    assert ids.objective_command("d" * 32).split() == [
        "su-exec", "service:service", ids.OBJECTIVE_HELPER, "d" * 32,
    ]


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
