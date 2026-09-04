from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "suitecrm_facility", ROOT / "image" / "facility.py"
)
facility = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(facility)

def account(value: str) -> dict[str, str]:
    return {
        "username": "arena_" + value * 16,
        "password": "S7!" + value * 32,
        "group": "Arena partition " + value * 8,
    }


def test_principal_batch_is_sorted_and_rejects_duplicates() -> None:
    normalized = facility.normalize_principal_batch([account("b"), account("a")])
    assert [item["username"] for item in normalized] == sorted(
        item["username"] for item in normalized
    )
    try:
        facility.normalize_principal_batch([account("a"), account("a")])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate principal accepted")


def test_sql_string_escapes_quotes() -> None:
    assert facility.sql_string("alpha'beta") == "'alpha''beta'"


def test_uuid_validation_is_strict() -> None:
    assert facility.valid_uuid("12345678-1234-1234-1234-123456789abc")
    assert not facility.valid_uuid("12345678-1234-1234-1234-123456789ABC")
    assert not facility.valid_uuid("../12345678-1234-1234-1234-123456789abc")
