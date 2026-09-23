from __future__ import annotations

import json

from challenges.grafana_protected_contact_point import checker
from challenges.interface import VulboxTarget


def target(execute):
    return VulboxTarget(
        host="team1_prod",
        ports={"service": 3000},
        meta={"exec_in_container": execute},
    )


def contact(uid: str, name: str, url: str) -> dict:
    return {
        "uid": uid,
        "name": name,
        "type": "webhook",
        "disableResolveMessage": False,
        "settings": {"url": url},
    }


def test_checker_rejects_successful_put_when_update_was_not_persisted(monkeypatch):
    nonce = "ab" * 12
    uid = "arena-check-" + nonce
    original_name = "checker-original-" + nonce
    url = "http://checker.invalid/hook/" + nonce

    monkeypatch.setattr(checker.secrets, "token_hex", lambda _length: nonce)

    def execute(_host, command):
        if "checker-arm" in command:
            return 0, json.dumps({
                "username": "checker",
                "password": "password",
                "uid": uid,
            })
        return 0, ""

    class FakeClient:
        def __init__(self, *_args):
            pass

        def contact_points(self):
            return 200, [contact(uid, original_name, url)]

        def contact_point(self, _uid):
            return 200, contact(uid, original_name, url)

        def update_contact_point(self, _uid, _document):
            return 202

    monkeypatch.setattr(checker, "GrafanaClient", FakeClient)
    result = checker.GrafanaChecker().run(target(execute))
    assert not result.passed
    assert any(
        child.name == "persisted_update" and not child.passed
        for child in result.children
    )


def test_checker_verifies_the_updated_network_document(monkeypatch):
    nonces = iter(["ab" * 12, "cd" * 8])
    monkeypatch.setattr(checker.secrets, "token_hex", lambda _length: next(nonces))
    uid = "arena-check-" + "ab" * 12
    url = "http://checker.invalid/hook/" + "ab" * 12
    state = contact(uid, "checker-original-" + "ab" * 12, url)

    def execute(_host, command):
        if "checker-arm" in command:
            return 0, json.dumps({
                "username": "checker",
                "password": "password",
                "uid": uid,
            })
        return 0, ""

    class FakeClient:
        def __init__(self, *_args):
            pass

        def contact_points(self):
            return 200, [dict(state)]

        def contact_point(self, _uid):
            return 200, dict(state)

        def update_contact_point(self, _uid, document):
            state.update(document)
            return 202

    monkeypatch.setattr(checker, "GrafanaClient", FakeClient)
    result = checker.GrafanaChecker().run(target(execute))
    assert result.passed
    assert [child.name for child in result.children][-1] == "persisted_update"
