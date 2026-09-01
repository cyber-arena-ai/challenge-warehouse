from __future__ import annotations

import base64
import json
import shlex

import pytest

from challenges.interface import VulboxTarget

from jtu22.etcd_nested_rbac import checker


@pytest.mark.parametrize("protected_result", ["vulnerable", "fixed"])
def test_checker_preserves_legitimate_nested_workflow_and_boundary(
    monkeypatch, protected_result: str
):
    store: dict[str, str] = {}
    transaction_ranges: list[str] = []
    deleted_keys: list[str] = []
    hex_values = {10: "a" * 20, 20: "d" * 40}
    values_16 = iter(("b" * 32, "c" * 32, "e" * 32))

    def token_hex(size: int) -> str:
        return next(values_16) if size == 16 else hex_values[size]

    def execute(_host: str, command: str) -> tuple[int, str]:
        parts = shlex.split(command)
        if parts[1] == "plant":
            store[parts[2]] = base64.urlsafe_b64decode(parts[3]).decode()
        elif parts[1] == "delete":
            store.pop(parts[2], None)
        return 0, ""

    def b64decode(value: str) -> str:
        return base64.b64decode(value).decode()

    def response(value: str) -> bytes:
        encoded = base64.b64encode(value.encode()).decode()
        return json.dumps({"responses": [{"response_txn": {"responses": [{"response_range": {"kvs": [{"value": encoded}]}}]}}]}).encode()

    def request(_base, path, payload, *, token=None):
        assert token == "token"
        if path == "/v3/kv/put":
            store[b64decode(payload["key"])] = b64decode(payload["value"])
            return 200, b"{}"
        if path == "/v3/kv/deleterange":
            key = b64decode(payload["key"])
            deleted_keys.append(key)
            store.pop(key, None)
            return 200, b"{}"
        if path == "/v3/kv/range":
            key = b64decode(payload["key"])
            if key.startswith("/services/"):
                return 403, b"{}"
            return (
                (200, response(store[key]))
                if key in store
                else (200, b'{"kvs":[]}')
            )
        if path == "/v3/kv/txn":
            ops = payload["success"][0]["request_txn"]["success"]
            range_key = b64decode(ops[0]["request_range"]["key"])
            transaction_ranges.append(range_key)
            if range_key.startswith("/services/"):
                if protected_result == "fixed":
                    return 403, b"{}"
                return 200, response(store[range_key])
            put = ops[1]["request_put"]
            store[b64decode(put["key"])] = b64decode(put["value"])
            delete = ops[2]["request_delete_range"]
            delete_key = b64decode(delete["key"])
            deleted_keys.append(delete_key)
            store.pop(delete_key, None)
            return 200, response(store[range_key])
        raise AssertionError(path)

    monkeypatch.setattr(checker.secrets, "token_hex", token_hex)
    monkeypatch.setattr(checker, "resolve_host", lambda _target: "127.0.0.1")
    monkeypatch.setattr(checker, "_authenticate", lambda _base: "token")
    monkeypatch.setattr(checker, "_request", request)
    target = VulboxTarget("prod", {"service": 2379}, {"exec_in_container": execute})

    checker._exercise(target)

    assert any(key.startswith("/teams/analyst/config/") for key in transaction_ranges)
    assert any(
        key.startswith("/services/production/") for key in transaction_ranges
    )
    assert not any("/checker/" in key for key in transaction_ranges)
    assert not any(key.startswith("/teams/analyst/config/") for key in store)
    assert not any(key.startswith("/services/") for key in store)
    assert len([key for key in deleted_keys if key.startswith("/teams/analyst/")]) >= 2
    assert any(key.endswith("/retired") for key in deleted_keys)
