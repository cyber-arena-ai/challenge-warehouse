from __future__ import annotations

import urllib.parse
from pathlib import Path

import pytest

from jtu22.listmonk import checker


def _facts():
    return {
        "list_id": "7",
        "fixtures": [
            {
                "present": "health-a-hidden",
                "absent": "health-b-hidden",
                "values": {
                    "selector_key": "profile_a1b2",
                    "selector_value": "selector-a",
                    "settings": "settings-a",
                    "users": "users-a",
                    "key": "key-a",
                },
            },
            {
                "present": "health-b-hidden",
                "absent": "health-a-hidden",
                "values": {
                    "selector_key": "profile_c3d4",
                    "selector_value": "selector-b",
                    "settings": "settings-b",
                    "users": "users-b",
                    "key": "key-b",
                },
            },
        ],
    }


def test_every_run_covers_direct_nested_and_keyword_decoys():
    values = _facts()["fixtures"][0]["values"]
    for _ in range(50):
        direct = checker._direct_expression(values)
        nested = checker._nested_expression(values)
        for expression in (direct, nested):
            assert "settings" in expression
            assert "users" in expression
            assert "upload.s3.aws_secret_access_key" in expression
        assert "EXISTS (SELECT 1 FROM subscribers AS" in nested


def test_compound_witness_checks_both_query_and_export(monkeypatch):
    calls = []

    def request(base, path, *, raw=False):
        calls.append((path, raw))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["query"][0]
        fixture = _facts()["fixtures"][0 if "selector-a" in query else 1]
        if raw:
            return f"email,name\nexample,{fixture['present']}\n"
        return {"data": {"results": [{"name": fixture["present"]}]}}

    monkeypatch.setattr(checker, "_request", request)
    checker._exercise("http://service:9000", _facts())

    assert len(calls) == 4
    assert sum(path.startswith("/api/subscribers?") for path, _ in calls) == 2
    assert sum(path.startswith("/api/subscribers/export?") for path, _ in calls) == 2
    assert all("health-a-hidden" not in path for path, _ in calls)
    assert all("health-b-hidden" not in path for path, _ in calls)
    assert sum("list_id=" in path for path, _ in calls) == 2


def test_retired_health_group_shortcut_cannot_satisfy_checker(monkeypatch):
    seen = []

    def checker_aware_stub(base, path, *, raw=False):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["query"][0]
        seen.append(query)
        if "health_group" in query:
            return "email,name\nexample,health-a-hidden\n" if raw else {
                "data": {"results": [{"name": "health-a-hidden"}]}
            }
        return "email,name\n" if raw else {"data": {"results": []}}

    monkeypatch.setattr(checker, "_request", checker_aware_stub)
    with pytest.raises(RuntimeError, match="wrong fixture set"):
        checker._exercise("http://service:9000", _facts())

    assert seen
    assert all("health_group" not in query for query in seen)
    assert any("profile_a1b2" in query for query in seen)


def test_retired_local_checker_is_not_auto_detected():
    package = Path(__file__).parents[1]
    assert not (package / "image" / "checker.sh").exists()
    assert (package / "_maintainer" / "stale" / "image_checker.sh").is_file()
