from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_ids", Path(__file__).resolve().parents[1] / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def test_public_target_is_validated_and_does_not_publish_proof():
    proof = "FLAG{never-public}"
    path = "Guarded/" + "a" * 24 + ".txt"
    read = ids.pack_handle({
        "store": ids.STORE_GUARDED_FILE,
        "target": path,
        "flag": proof,
    })
    assert ids.public_flag_id(read) == path
    assert ids.valid_read_target("Guarded/../../secret.txt") is False
    assert proof not in ids.public_flag_id(read)

    operation = "b" * 32
    execute = ids.pack_handle({
        "store": ids.STORE_COMMAND,
        "target": operation,
        "flag": proof,
    })
    assert ids.public_flag_id(execute) == operation
    assert proof not in ids.public_flag_id(execute)


def test_execute_helper_is_uid_scoped_and_target_validated():
    operation = "deadbeef" * 4
    assert ids.objective_command(operation).split() == [
        "su-exec", "service:service", "/usr/local/bin/caddy-objective", operation,
    ]
    with pytest.raises(ValueError):
        ids.objective_command("not-an-operation")


def test_principal_derivation_is_deterministic_and_distinct():
    seed_a = "01" * 32
    seed_b = "02" * 32
    assert ids.derive_principal(seed_a) == ids.derive_principal(seed_a)
    assert ids.derive_principal(seed_a) != ids.derive_principal(seed_b)
    username, password = ids.derive_principal(seed_a)
    assert username == "user" + "01" * 8
    assert password.startswith("C1!") and len(password) == 35


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
