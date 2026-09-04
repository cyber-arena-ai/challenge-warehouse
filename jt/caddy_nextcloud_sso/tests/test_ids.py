from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_ids", Path(__file__).resolve().parents[1] / "_ids.py")
ids = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ids)


def test_public_target_is_validated_and_does_not_publish_proof():
    proof = "FLAG{never-public}"
    path = "Guarded/" + "a" * 24 + ".txt"
    read = ids.pack_handle({"target": path, "flag": proof})
    assert ids.public_flag_id(read) == path
    assert ids.valid_read_target("Guarded/../../secret.txt") is False
    assert proof not in ids.public_flag_id(read)


def test_public_account_is_explicitly_unprivileged_connection_data():
    assert ids.PUBLIC_USERNAME == "arena-player"
    assert len(ids.PUBLIC_PASSWORD) >= 20


def test_handle_decoder_is_total():
    for bad in ("", "not-base64!", "bnVsbA", "e30"):
        assert ids.unpack_handle(bad) in (None, {})
