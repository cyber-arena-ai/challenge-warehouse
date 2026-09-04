from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("geoserver_ids", ROOT / "_ids.py")
ids = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ids)


def test_principal_derivation_is_distinct_and_deterministic() -> None:
    seed_a = "01" * 32
    seed_b = "02" * 32
    assert ids.derive_principal(seed_a) == ids.derive_principal(seed_a)
    assert ids.derive_principal(seed_a) != ids.derive_principal(seed_b)
    username, password = ids.derive_principal(seed_a)
    assert username == "arena_" + "01" * 8
    assert password.startswith("Gs!") and len(password) == 35


def test_public_ids_expose_only_valid_targets() -> None:
    target = "sf:roads/roads.826"
    operation = "ab" * 16
    read = ids.pack_handle({
        "store": ids.STORE_PROTECTED_FEATURE,
        "target": target,
        "flag": "FLAG{private}",
    })
    command = ids.pack_handle({
        "store": ids.STORE_COMMAND,
        "target": operation,
        "flag": "FLAG{command}",
    })
    assert ids.public_flag_id(read) == target
    assert ids.public_flag_id(command) == operation
    assert "FLAG" not in ids.public_flag_id(read)
    assert ids.public_flag_id("not-a-handle") is None


def test_feature_target_and_service_command_are_strict() -> None:
    assert ids.feature_id("sf:roads/roads.826") == "roads.826"
    assert ids.feature_id("roads.826") is None
    assert ids.feature_target("roads.826") == "sf:roads/roads.826"
    operation = "cd" * 16
    assert ids.objective_command(operation) == (
        "setpriv --reuid=1000 --regid=1000 --clear-groups "
        "/usr/local/bin/geoserver-objective " + operation
    )
    try:
        ids.objective_command("../bad")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid operation accepted")
