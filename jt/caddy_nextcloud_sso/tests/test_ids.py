from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_ids", Path(__file__).resolve().parents[1] / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def seed(value: int) -> str:
    return f"{value:016x}" * 4


def test_principal_derivation_is_deterministic_and_distinct():
    first = seed(1)
    assert ids.derive_principal(first) == ids.derive_principal(first)
    values = [ids.derive_principal(seed(value)) for value in range(1, 31)]
    assert len({row[0] for row in values}) == 30
    assert len({row[1] for row in values}) == 30


def test_short_seed_is_rejected():
    with pytest.raises(ValueError):
        ids.derive_principal("abcd")


def test_guarded_principals_are_target_specific_and_match_attacker_shape(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    first = ids.guarded_principals("team-a")
    assert first == ids.guarded_principals("team-a")
    assert first != ids.guarded_principals("team-b")
    accounts = list(first)
    assert len(accounts) == ids.CHECKER_PRINCIPAL_COUNT
    assert len(set(accounts)) == len(accounts)
    assert all(re.fullmatch(r"user[0-9a-f]{16}", username)
               for username, _password in accounts)
    assert all(re.fullmatch(r"C1![0-9a-f]{32}", password)
               for _username, password in accounts)


def test_guarded_principals_require_trusted_facility_material(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("CYBERARENA_FACILITY_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="guarded principal material"):
        ids.guarded_principals("team-a")


def test_checker_document_name_uses_rejection_sampling(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    material = bytes((0, 255, 1, 255, 1, *range(8)))

    target, body = ids._checker_document_from_material(
        "team-a", 0, "control", material)

    assert target.startswith("Guarded/bridge_0001020304050607")
    assert ids.checker_document_owner("team-a", target) == 0
    assert ids.checker_document_identity("team-a", target) == (0, "control")
    assert body == ids.checker_document_body("team-a", 0, target)
    shadow = ids.checker_document_seed("team-a", 0, "shadow")[0]
    assert ids.checker_document_identity("team-a", shadow) == (0, "shadow")


def test_global_checker_pairs_have_authenticated_owners_and_order(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    team_id = "victim-team"
    pairs = [ids.checker_pair_seed(team_id)]
    for _ in range(ids.CHECKER_CHAIN_LIMIT - 1):
        pairs.append(ids.checker_pair_successor(team_id, pairs[-1][1][0]))
    targets = [
        target for _owner, control, shadow in pairs
        for target in (control[0], shadow[0])
    ]

    assert ids.checker_pair_chain(team_id, list(reversed(targets))) == tuple(
        (owner, control[0], shadow[0]) for owner, control, shadow in pairs)
    assert all(
        ids.checker_document_identity(team_id, record[0]) == (owner, kind)
        for owner, control, shadow in pairs
        for kind, record in (("control", control), ("shadow", shadow))
    )
    assert {pairs[index][0] == pairs[index + 1][0]
            for index in range(len(pairs) - 1)} == {False, True}


def test_pair_owner_and_control_word_count_use_independent_material(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-test-token")
    combinations = set()
    pairs = []
    for value in range(256):
        pair = ids._checker_pair_from_material(
            "victim-team", value.to_bytes(2, "big") * 16)
        owner, control, _shadow = pair
        stem = control[0].removeprefix("Guarded/").removesuffix(".txt")[:-32]
        separator = stem[-1]
        word_count = len(stem[:-1].split(separator))
        combinations.add((owner, word_count))
        pairs.append(pair)

    assert combinations == {
        (owner, word_count)
        for owner in range(ids.CHECKER_PRINCIPAL_COUNT)
        for word_count in range(1, 5)
    }
    assert pairs == [
        ids._checker_pair_from_material(
            "victim-team", value.to_bytes(2, "big") * 16)
        for value in range(256)
    ]


def test_objective_cover_body_is_deterministic_and_non_scoring():
    cover = "Guarded/autumn-" + "a" * 32 + ".txt"

    body = ids.objective_cover_body(cover)

    assert body == ids.objective_cover_body(cover)
    assert re.fullmatch(rb"FLAG\{[A-Z0-9]{32}\}", body)
    with pytest.raises(ValueError, match="cover target"):
        ids.objective_cover_body("Guarded/not-valid.txt")


def test_public_targets_are_validated_and_do_not_publish_proofs():
    proof = "FLAG{never-public}"
    path = "Guarded/autumn-" + "a" * 32 + ".txt"
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
