from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("suitecrm_ids", ROOT / "_ids.py")
ids = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ids)


def test_public_ids_expose_only_valid_targets() -> None:
    note = "12345678-1234-1234-1234-123456789abc"
    read = ids.pack_handle({
        "store": ids.STORE_PRIVATE_NOTE,
        "target": note,
        "flag": "FLAG{private}",
    })
    assert ids.public_flag_id(read) == note
    assert "FLAG" not in ids.public_flag_id(read)
    assert ids.public_flag_id("not-a-handle") is None

    operation = "b" * 32
    execute = ids.pack_handle({
        "store": ids.STORE_COMMAND,
        "target": operation,
        "flag": "FLAG{private}",
    })
    assert ids.public_flag_id(execute) == operation


def test_execute_helper_is_uid_scoped_and_target_validated() -> None:
    operation = "deadbeef" * 4
    assert ids.objective_command(operation).split() == [
        "su-exec", "www-data:www-data",
        "/usr/local/bin/suitecrm-objective", operation,
    ]
    with pytest.raises(ValueError):
        ids.objective_command("not-an-operation")
