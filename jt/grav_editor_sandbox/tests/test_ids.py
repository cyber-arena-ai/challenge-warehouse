"""Narrow unit tests for the three contracts that are easy to get silently wrong:
baseline-principal seed derivation, the flag-handle codec (and what `flag_id`
may publish), and the command objective's helper invocation.

`_ids.py` is framework-free on purpose, so these run against the file directly —
no orchestration checkout, no docker, no network.
"""

from __future__ import annotations

import importlib.util
import secrets
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "grav_editor_sandbox_ids", Path(__file__).resolve().parents[1] / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def _seed() -> str:
    return secrets.token_hex(32)


# ── seed derivation ─────────────────────────────────────────────────────────

def test_derivation_is_deterministic_in_the_seed_alone():
    seed = _seed()
    assert ids.derive_principal(seed) == ids.derive_principal(seed)


def test_distinct_seeds_give_distinct_identities_and_secrets():
    pairs = [ids.derive_principal(_seed()) for _ in range(50)]
    assert len({username for username, _ in pairs}) == 50
    assert len({password for _, password in pairs}) == 50


def test_derived_credentials_satisfy_the_account_policy():
    username, password = ids.derive_principal(_seed())
    assert username.isalnum() and username.islower() and len(username) == 16
    assert len(password) >= 8
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)


def test_a_seed_without_enough_material_is_rejected():
    with pytest.raises(ValueError):
        ids.derive_principal("abc123")


# ── handles and what flag_id may publish ────────────────────────────────────

def test_handle_round_trips():
    payload = {"store": ids.STORE_COMMAND, "op": "a" * 32, "flag": "FLAG{x}"}
    assert ids.unpack_handle(ids.pack_handle(payload)) == payload


def test_unpack_guards_garbage_instead_of_raising():
    for bad in ("", "not-base64!!", "null", "eyJhIjog"):
        assert ids.unpack_handle(bad) is None


def test_flag_id_publishes_the_target_half_and_never_the_flag():
    flag = "FLAG{never-published}"
    read_handle = ids.pack_handle(
        {"store": ids.STORE_JWT, "target": ids.JWT_TARGET, "flag": flag})
    exec_handle = ids.pack_handle(
        {"store": ids.STORE_COMMAND, "op": "b" * 32, "flag": flag})

    assert ids.public_flag_id(read_handle) == ids.JWT_TARGET
    assert ids.public_flag_id(exec_handle) == "b" * 32
    for handle in (read_handle, exec_handle):
        assert flag not in (ids.public_flag_id(handle) or "")


def test_flag_id_is_none_for_an_unknown_or_broken_handle():
    assert ids.public_flag_id("garbage") is None
    assert ids.public_flag_id(ids.pack_handle({"store": "other"})) is None
    assert ids.public_flag_id(ids.pack_handle({"store": ids.STORE_COMMAND})) is None


def test_execute_handles_rotate_their_public_id():
    first = ids.pack_handle({"store": ids.STORE_COMMAND, "op": "1" * 32})
    second = ids.pack_handle({"store": ids.STORE_COMMAND, "op": "2" * 32})
    assert ids.public_flag_id(first) != ids.public_flag_id(second)


# ── the helper invocation contract ──────────────────────────────────────────

def test_helper_runs_as_the_service_account_with_the_operation_id():
    command = ids.catflag_command("deadbeef" * 4)
    assert command.split() == [
        "runuser", "-u", ids.SERVICE_USER, "--", ids.CATFLAG_PATH, "deadbeef" * 4]


def test_helper_argument_is_shell_quoted():
    assert ids.catflag_command("x; rm -rf /").endswith("'x; rm -rf /'")


def test_helper_refuses_an_empty_operation_id():
    with pytest.raises(ValueError):
        ids.catflag_command("")
