from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "geoserver_facility", ROOT / "image" / "facility.py"
)
facility = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(facility)


def test_user_and_role_response_shapes_are_normalized() -> None:
    assert facility.list_names(
        {"users": [{"enabled": True, "userName": "alice"}]},
        "users", "user",
    ) == {"alice"}
    assert facility.list_names(
        {"roles": {"role": ["ADMIN", "ARENA_GUARDED"]}},
        "roles", "role",
    ) == {"ADMIN", "ARENA_GUARDED"}


def test_application_acl_is_native_and_minimal() -> None:
    source = (ROOT / "image" / "facility.py").read_text(encoding="utf-8")
    assert '"topp.states.r": "ROLE_AUTHENTICATED"' in source
    assert '"sf.roads.r": GUARDED_ROLE' in source
    assert '"sf.roads.w": GUARDED_ROLE' in source
    assert "/rest/security/acl/layers" not in source
    assert '"/security/acl/layers.json"' in source


def test_user_create_uses_geoserver_json_wrapper(monkeypatch) -> None:
    documents: list[object] = []

    def fake_rest(method, path, *, credentials, document=None):
        if method == "GET":
            return 200, b'{"users":[]}'
        documents.append(document)
        return 201, b""

    monkeypatch.setattr(facility, "rest", fake_rest)
    facility.upsert_user(("admin", "rotated"), "alice", "secret")

    assert documents == [{
        "user": {"userName": "alice", "password": "secret", "enabled": True}
    }]


def test_execute_helper_rejects_non_service_real_uid() -> None:
    helper = (ROOT / "image" / "geoserver-objective.c").read_text(
        encoding="utf-8"
    )
    dockerfile = (ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    assert "getuid() != SERVICE_UID" in helper
    assert '#define SERVICE_UID 1000' in helper
    assert 'chmod 4750 /usr/local/bin/geoserver-objective' in dockerfile
    assert 'chmod 0700 /arena/secrets /arena/state /opt/arena/objective' in dockerfile


def test_principal_batch_validates_login_and_guarded_denial(
    monkeypatch, capsys,
) -> None:
    users = [{"username": "alice", "password": "secret"}]
    encoded = base64.b64encode(json.dumps(users).encode()).decode()
    reconciled: list[tuple[str, str]] = []
    requests: list[str] = []

    monkeypatch.setattr(facility, "admin", lambda: ("admin", "rotated"))
    monkeypatch.setattr(
        facility,
        "upsert_user",
        lambda credentials, username, password: reconciled.append(
            (username, password)
        ),
    )

    def fake_request(method, path, **kwargs):
        requests.append(path)
        if "GetPropertyValue" in path:
            return 200, b"Illinois"
        return 400, b"guarded"

    monkeypatch.setattr(facility, "request", fake_request)
    facility.principals(encoded)

    assert reconciled == [("alice", "secret")]
    assert ["GetPropertyValue" in path for path in requests] == [True, False]
    assert json.loads(capsys.readouterr().out) == {"count": 1}


def test_second_bootstrap_reuses_rotated_admin(monkeypatch, tmp_path: Path) -> None:
    secrets_path = tmp_path / "accounts.json"
    secrets_path.write_text(json.dumps({
        "admin": {"username": "admin", "password": "rotated"},
        "ordinary": {"username": facility.ORDINARY_USER, "password": "one"},
        "guarded": {"username": facility.GUARDED_USER, "password": "two"},
    }), encoding="utf-8")
    monkeypatch.setattr(facility, "SECRETS", secrets_path)

    rest_calls: list[tuple[str, str, tuple[str, str]]] = []
    reconciled: list[tuple[str, str]] = []

    def fake_rest(method, path, *, credentials, document=None):
        rest_calls.append((method, path, credentials))
        return 200, b"{}"

    monkeypatch.setattr(facility, "rest", fake_rest)
    monkeypatch.setattr(facility, "ensure_role", lambda credentials, role: None)
    monkeypatch.setattr(
        facility, "upsert_user",
        lambda credentials, username, password: reconciled.append(
            (username, password)
        ),
    )
    monkeypatch.setattr(
        facility, "assign_role", lambda credentials, role, username: None
    )
    monkeypatch.setattr(facility, "ensure_acl", lambda credentials: None)

    facility.bootstrap()

    assert rest_calls == [
        ("GET", "/security/roles.json", ("admin", "rotated"))
    ]
    assert reconciled == [
        (facility.ORDINARY_USER, "one"),
        (facility.GUARDED_USER, "two"),
    ]
