from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("nats_mqtt_acl_ids", _ROOT / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def test_public_targets_round_trip_without_flag_material():
    flag = "FLAG{never-public}"
    topic = "victim/secret/" + "a" * 24
    operation = "b" * 32
    read = ids.pack_handle({
        "store": ids.STORE_RETAINED, "target": topic, "flag": flag,
    })
    execute = ids.pack_handle({
        "store": ids.STORE_COMMAND, "target": operation, "flag": flag,
    })
    assert ids.public_flag_id(read) == topic
    assert ids.public_flag_id(execute) == operation
    assert flag not in ids.public_flag_id(read)
    assert flag not in ids.public_flag_id(execute)


def test_public_target_rejects_non_topic_handles():
    assert ids.public_flag_id(ids.pack_handle({
        "store": ids.STORE_RETAINED,
        "target": "victim/public/" + "a" * 24,
        "flag": "FLAG{private}",
    })) is None


def test_execute_helper_is_uid_scoped_and_target_validated():
    operation = "deadbeef" * 4
    assert ids.catflag_command(operation).split() == [
        "su-exec", "nats:nats", "/usr/local/bin/nats-objective", operation,
    ]
    with pytest.raises(ValueError):
        ids.catflag_command("not-an-operation")


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
