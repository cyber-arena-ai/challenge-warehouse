from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("nats_mqtt_acl_ids", _ROOT / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def test_public_targets_round_trip_without_flag_material():
    flag = "FLAG{never-public}"
    topic = "victim/secret/" + "a" * 24
    read = ids.pack_handle({"target": topic, "flag": flag})
    assert ids.public_flag_id(read) == topic
    assert flag not in ids.public_flag_id(read)


def test_public_target_rejects_non_topic_handles():
    assert ids.public_flag_id(ids.pack_handle({
        "target": "victim/public/" + "a" * 24,
        "flag": "FLAG{private}",
    })) is None


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
