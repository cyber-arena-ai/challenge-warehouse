from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "caddy_nextcloud_sso_facility",
    Path(__file__).resolve().parents[1] / "image" / "facility.py")
facility = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(facility)


def state() -> dict:
    return {
        "guarded": {"username": "guard0000000000000000", "password": "secret1",
                    "hash": "$2a$14$guarded"},
        "ordinary": {"username": "check0000000000000000", "password": "secret2",
                     "hash": "$2a$14$ordinary"},
        "principals": [{"username": "user" + "a" * 16, "password": "secret3",
                        "hash": "$2a$14$principal"}],
    }


def test_rendered_caddyfile_has_only_loopback_internal_listeners():
    rendered = facility.render_caddyfile(state())
    assert "admin 127.0.0.1:2019" in rendered
    assert "\n:9080 {\n\tbind 127.0.0.1" in rendered
    assert "http://127.0.0.1:9080" not in rendered
    assert "php_fastcgi 127.0.0.1:9000" in rendered
    assert "\n:8080 {" in rendered
    assert "Remote-User {http.auth.user.id}" in rendered
    assert "Remote-Groups guarded" in rendered
    assert all(secret not in rendered for secret in ("secret1", "secret2", "secret3"))


def test_principal_normalization_is_stable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)
    raw = [{"username": "user" + "b" * 16, "password": "C1!" + "2" * 32}]
    first = facility.normalize_principals(raw, [])
    second = facility.normalize_principals(raw, first)
    assert first == second
    assert first[0]["hash"].startswith("hash:")


def test_principal_normalization_rejects_duplicates(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(facility, "hash_password", lambda value: "hash:" + value)
    row = {"username": "user" + "c" * 16, "password": "C1!" + "3" * 32}
    with pytest.raises(ValueError):
        facility.normalize_principals([row, row], [])


def test_occ_json_ignores_leading_php_warning(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        facility, "occ", lambda *args: 'PHP warning\n{"installed":true}')
    assert facility.occ_json("status", "--output=json") == {"installed": True}


def test_checker_uses_separate_internal_accounts(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr(facility, "load_state", state)
    facility.checker_bundle()
    bundle = json.loads(capsys.readouterr().out)
    assert bundle["ordinary"] == {
        "username": "check0000000000000000", "password": "secret2",
    }
