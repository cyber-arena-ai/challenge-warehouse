from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("nats_mqtt_acl_mqtt", _ROOT / "_mqtt.py")
mqtt = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mqtt)


def test_remaining_length_encoding():
    assert mqtt._remaining_length(0) == b"\x00"
    assert mqtt._remaining_length(127) == b"\x7f"
    assert mqtt._remaining_length(128) == b"\x80\x01"
    assert mqtt._remaining_length(16384) == b"\x80\x80\x01"


def test_utf8_encoding():
    assert mqtt._utf8("MQTT") == b"\x00\x04MQTT"
