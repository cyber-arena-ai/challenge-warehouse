from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("suitecrm_ids", ROOT / "_ids.py")
ids = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ids)


def test_principal_derivation_is_distinct_and_deterministic() -> None:
    seed_a = "01" * 32
    seed_b = "02" * 32
    assert ids.derive_principal(seed_a) == ids.derive_principal(seed_a)
    assert ids.derive_principal(seed_a) != ids.derive_principal(seed_b)
    username, password, group = ids.derive_principal(seed_a)
    assert username == "arena_" + "01" * 8
    assert password.startswith("S7!") and len(password) == 35
    assert group.startswith("Arena partition ")


def test_public_ids_expose_only_valid_targets() -> None:
    note = "12345678-1234-1234-1234-123456789abc"
    operation = "ab" * 16
    read = ids.pack_handle({
        "store": ids.STORE_PRIVATE_NOTE,
        "target": note,
        "flag": "FLAG{private}",
    })
    command = ids.pack_handle({
        "store": ids.STORE_COMMAND,
        "target": operation,
        "flag": "FLAG{command}",
    })
    assert ids.public_flag_id(read) == note
    assert ids.public_flag_id(command) == operation
    assert "FLAG" not in ids.public_flag_id(read)
    assert ids.public_flag_id("not-a-handle") is None


def test_objective_command_is_fixed_to_service_context() -> None:
    operation = "cd" * 16
    assert ids.objective_command(operation) == (
        "su-exec www-data:www-data /usr/local/bin/suitecrm-objective " + operation
    )
    try:
        ids.objective_command("../bad")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid operation accepted")
