from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

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


def test_checker_principals_are_match_long_same_shape_and_role_distinct(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    ordinary = ids.checker_principals("victim", "ordinary")
    guarded = ids.checker_principals("victim", "guarded")
    assert ordinary == ids.checker_principals("victim", "ordinary")
    assert ordinary != guarded
    assert len(ordinary) == ids.CHECKER_PRINCIPALS_PER_ROLE
    assert all(re.fullmatch(r"arena_[0-9a-f]{16}", username)
               for username, _password in (*ordinary, *guarded))
    assert all(re.fullmatch(r"Gs![0-9a-f]{32}", password)
               for _username, password in (*ordinary, *guarded))
    assert ids.road_lifecycle_principals("victim") == (
        ordinary[0], guarded[0]
    )


def test_checker_principals_require_facility_material(monkeypatch) -> None:
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        ids.checker_principals("victim", "ordinary")


def test_issued_cohort_is_sorted_authenticated_and_nonempty(monkeypatch) -> None:
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    accounts = [
        ("arena_" + "b" * 16, "Gs!" + "2" * 32),
        ("arena_" + "a" * 16, "Gs!" + "1" * 32),
    ]

    sealed = ids.seal_issued_cohort(accounts)

    assert ids.open_issued_cohort(sealed) == tuple(sorted(accounts))
    with pytest.raises(RuntimeError, match="untrusted"):
        ids.open_issued_cohort(
            sealed[:-1] + ("0" if sealed[-1] != "0" else "1")
        )
    with pytest.raises(RuntimeError, match="empty"):
        ids.seal_issued_cohort([])
    with pytest.raises(RuntimeError, match="malformed"):
        ids.open_issued_cohort("not-a-seal")


def test_issued_cohort_rejects_another_facility_token(monkeypatch) -> None:
    accounts = [("arena_" + "a" * 16, "Gs!" + "1" * 32)]
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret-one")
    sealed = ids.seal_issued_cohort(accounts)
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret-two")

    with pytest.raises(RuntimeError, match="untrusted"):
        ids.open_issued_cohort(sealed)


def test_public_ids_expose_only_valid_targets() -> None:
    target = f"sf:roads/context/{'12' * 32}/cat/826"
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
    context = "12" * 32
    target = f"sf:roads/context/{context}/cat/826"
    assert ids.feature_category(target) == 826
    assert ids.feature_category("sf:roads/cat/826") is None
    assert ids.feature_category("sf:roads/roads.826") is None
    assert ids.feature_target(826, context) == target
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
