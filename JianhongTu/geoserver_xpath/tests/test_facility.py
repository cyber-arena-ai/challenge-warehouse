from __future__ import annotations

import base64
import importlib.util
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "geoserver_facility", ROOT / "image" / "facility.py"
)
facility = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(facility)

CONTEXT = "11" * 32
NEXT_CONTEXT = "22" * 32


def feature_request(
    value: str,
    *,
    context: str = CONTEXT,
    categories: tuple[int, ...] = (22,),
    geometry: list[list[int]] | None = None,
) -> str:
    document = {
        "context": context,
        "value": value,
        "categories": list(categories),
        "geometry": geometry or [[594000, 4917000], [596000, 4919000]],
    }
    return base64.b64encode(json.dumps(document).encode()).decode()


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


def test_resource_acl_is_specific_and_idempotent(monkeypatch, tmp_path: Path) -> None:
    rest_acl = tmp_path / "rest.properties"
    rest_acl.write_text(
        "/**;GET=ADMIN\n/**;POST,DELETE,PUT=ADMIN\n", encoding="utf-8"
    )
    monkeypatch.setattr(facility, "REST_ACL", rest_acl)

    facility.ensure_resource_acl()
    facility.ensure_resource_acl()

    lines = rest_acl.read_text(encoding="utf-8").splitlines()
    assert lines[0] == facility.RESOURCE_RULE
    assert lines.count(facility.RESOURCE_RULE) == 1
    assert lines[1:] == ["/**;GET=ADMIN", "/**;POST,DELETE,PUT=ADMIN"]


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
    written: list[tuple[Path, object]] = []
    monkeypatch.setattr(
        facility, "write_secret", lambda path, value: written.append((path, value))
    )
    facility.principals(encoded)

    assert reconciled == [("alice", "secret")]
    assert ["GetPropertyValue" in path for path in requests] == [True, False]
    assert written == [(
        facility.FEATURE_OBSERVERS,
        [{"username": "alice", "password": "secret"}],
    )]
    assert json.loads(capsys.readouterr().out) == {"count": 1}


def test_guarded_checker_principal_gets_native_role(monkeypatch, capsys) -> None:
    username = "arena_" + "a" * 16
    password = "Gs!" + "b" * 32
    users = [{"username": username, "password": password, "guarded": True}]
    encoded = base64.b64encode(json.dumps(users).encode()).decode()
    assignments: list[tuple[str, str]] = []
    secrets_written: list[tuple[Path, object]] = []

    monkeypatch.setattr(facility, "admin", lambda: ("admin", "rotated"))
    monkeypatch.setattr(facility, "upsert_user", lambda *_args: None)
    monkeypatch.setattr(
        facility,
        "assign_role",
        lambda _credentials, role, username: assignments.append((role, username)),
    )
    monkeypatch.setattr(
        facility,
        "request",
        lambda _method, path, **_kwargs: (
            (200, b"Illinois") if "GetPropertyValue" in path else (200, b"roads")
        ),
    )
    monkeypatch.setattr(
        facility,
        "write_secret",
        lambda path, value: secrets_written.append((path, value)),
    )

    facility.principals(encoded)

    assert assignments == [(facility.GUARDED_ROLE, username)]
    assert secrets_written == [(
        facility.FEATURE_CREATORS,
        [{"username": username, "password": password}],
    )]
    assert json.loads(capsys.readouterr().out) == {"count": 1}


def test_issued_cohort_storage_is_atomic_and_root_only(
    monkeypatch, tmp_path: Path, capsys,
) -> None:
    destination = tmp_path / "issued-cohort"
    owner_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(facility, "ISSUED_COHORT", destination)
    monkeypatch.setattr(
        facility.os,
        "fchown",
        lambda _descriptor, uid, gid: owner_calls.append((uid, gid)),
    )
    sealed = "payload_1." + "a" * 64

    facility.store_issued_cohort(sealed)

    assert destination.read_text(encoding="utf-8") == sealed
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400
    assert owner_calls == [(0, 0)]
    assert list(tmp_path.glob(".issued-cohort.*.tmp")) == []
    assert capsys.readouterr().out == "OK\n"


def test_issued_cohort_read_rejects_unsafe_state(monkeypatch, capsys) -> None:
    sealed = "payload_1." + "a" * 64

    class CohortState:
        def __init__(self, mode: int, uid: int = 0, gid: int = 0):
            self.metadata = SimpleNamespace(
                st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid
            )

        def lstat(self):
            return self.metadata

        def read_text(self, **_kwargs):
            return sealed

    monkeypatch.setattr(facility, "ISSUED_COHORT", CohortState(0o400))
    facility.read_issued_cohort()
    assert capsys.readouterr().out == sealed + "\n"

    monkeypatch.setattr(facility, "ISSUED_COHORT", CohortState(0o600))
    with pytest.raises(RuntimeError, match="unsafe"):
        facility.read_issued_cohort()


def test_feature_state_write_failure_preserves_prior_and_journaled_insert(
    monkeypatch, tmp_path: Path,
) -> None:
    value = "FLAG{new}"
    prior = "FLAG{prior}"
    creator = "arena_" + "a" * 16
    geometry = [[594000, 4917000], [596000, 4919000]]
    current = tmp_path / "current.json"
    pending = tmp_path / "pending.json"
    current.write_text(json.dumps({
        "context": CONTEXT,
        "value": prior,
        "category": 11,
        "geometry": geometry,
        "creator": creator,
        "previous_category": 0,
        "previous_value": "",
        "trace_nonce": "",
        "trace_born_at": 0,
        "previous_trace_nonce": "",
        "previous_trace_born_at": 0,
    }), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT_FEATURE", current)
    monkeypatch.setattr(facility, "PENDING_FEATURE", pending)
    monkeypatch.setattr(
        facility, "feature_creator",
        lambda _username="": (creator, "Gs!" + "b" * 32),
    )
    monkeypatch.setattr(
        facility, "feature_observer",
        lambda _username="": ("arena_" + "c" * 16, "Gs!" + "d" * 32),
    )
    roads = {11: ("roads.7", prior, geometry)}

    def fake_find(category, _credentials, wanted=""):
        row = roads.get(category)
        if row is not None and wanted and row[1] != wanted:
            row = None
        return ([{
            "id": row[0], "properties": {"cat": category, "label": row[1]},
            "geometry": {
                "type": "MultiLineString", "coordinates": [row[2]],
            },
        }] if row else [])

    def fake_insert(inserted_value, category, inserted_geometry, _credentials):
        roads[category] = ("roads.99", inserted_value, inserted_geometry)
        return 200, b"SUCCESS"

    real_write = facility.write_secret

    def fake_write(path, value):
        if path == current:
            raise OSError("state unavailable")
        real_write(path, value)

    monkeypatch.setattr(facility, "find_features", fake_find)
    monkeypatch.setattr(facility, "insert_feature", fake_insert)
    monkeypatch.setattr(facility, "unused_category", lambda *_args: 22)
    monkeypatch.setattr(facility, "validate_feature", lambda *_args: None)
    monkeypatch.setattr(facility, "write_secret", fake_write)

    encoded = feature_request(
        value, context=NEXT_CONTEXT, categories=(22,), geometry=geometry
    )
    with pytest.raises(OSError, match="state unavailable"):
        facility.plant_feature(encoded)
    assert set(roads) == {11, 22}
    assert json.loads(current.read_text(encoding="utf-8"))["category"] == 11
    assert pending.exists()


def test_feature_insert_before_state_retry_reuses_native_feature(
    monkeypatch, tmp_path: Path,
) -> None:
    value = "FLAG{proof}"
    creator = "arena_" + "a" * 16
    geometry = [[594000, 4917000], [596000, 4919000]]
    current = tmp_path / "current.json"
    pending = tmp_path / "pending.json"
    pending.write_text(json.dumps({
        "context": CONTEXT,
        "value": value,
        "category": 17,
        "geometry": geometry,
        "creator": creator,
        "previous_category": 0,
        "previous_value": "",
        "retire_category": 0,
        "retire_value": "",
        "trace_nonce": "",
        "trace_born_at": 0,
        "retire_trace_nonce": "",
        "retire_trace_born_at": 0,
    }), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT_FEATURE", current)
    monkeypatch.setattr(facility, "PENDING_FEATURE", pending)
    monkeypatch.setattr(
        facility, "feature_creator",
        lambda username="": (creator, "Gs!" + "b" * 32),
    )
    monkeypatch.setattr(
        facility, "feature_observer",
        lambda username="": ("arena_" + "c" * 16, "Gs!" + "d" * 32),
    )
    monkeypatch.setattr(
        facility, "find_features", lambda *_args: [{
            "id": "roads.17",
            "properties": {"cat": 17, "label": value},
            "geometry": {
                "type": "MultiLineString", "coordinates": [geometry],
            },
        }]
    )
    monkeypatch.setattr(
        facility, "insert_feature",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("retry must reuse the proof-bearing native feature")
        ),
    )
    monkeypatch.setattr(facility, "validate_feature", lambda *_args: None)

    encoded = feature_request(
        value, context=CONTEXT, categories=(17,), geometry=geometry
    )
    facility.plant_feature(encoded)

    assert json.loads(current.read_text(encoding="utf-8")) == {
        "context": CONTEXT,
        "value": value,
        "category": 17,
        "geometry": geometry,
        "creator": creator,
        "previous_category": 0,
        "previous_value": "",
        "trace_nonce": "",
        "trace_born_at": 0,
        "previous_trace_nonce": "",
        "previous_trace_born_at": 0,
    }
    assert pending.exists()
    facility.finalize_feature()
    assert pending.exists()
    facility.clear_feature_pending()
    assert not pending.exists()


def test_pending_trace_is_proof_neutral_and_complete_retry_is_idempotent(
    monkeypatch, tmp_path: Path, capsys,
) -> None:
    old_value = "FLAG{prior-proof-must-not-leak}"
    current = tmp_path / "current.json"
    pending = tmp_path / "pending.json"
    current.write_text(json.dumps({
        "context": CONTEXT,
        "value": old_value,
        "category": 17,
        "geometry": [[594000, 4917000], [596000, 4919000]],
        "creator": "arena_" + "a" * 16,
        "previous_category": 0,
        "previous_value": "",
        "trace_nonce": "ABCDEFG",
        "trace_born_at": 1_800_000_000,
        "previous_trace_nonce": "",
        "previous_trace_born_at": 0,
    }), encoding="utf-8")
    pending.write_text(json.dumps({
        "context": CONTEXT,
        "value": old_value,
        "category": 17,
        "geometry": [[594000, 4917000], [596000, 4919000]],
        "creator": "arena_" + "a" * 16,
        "previous_category": 0,
        "previous_value": "",
        "retire_category": 0,
        "retire_value": "",
        "trace_nonce": "ABCDEFG",
        "trace_born_at": 1_800_000_000,
        "retire_trace_nonce": "",
        "retire_trace_born_at": 0,
    }), encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT_FEATURE", current)
    monkeypatch.setattr(facility, "PENDING_FEATURE", pending)

    assert facility.pending_feature_trace(NEXT_CONTEXT) == 0
    interrupted = capsys.readouterr().out
    assert old_value not in interrupted
    assert json.loads(interrupted) == {
        "complete": False,
        "same": False,
        "category": 17,
        "nonce": "ABCDEFG",
        "born_at": 1_800_000_000,
        "retire_nonce": "",
        "retire_born_at": 0,
    }

    pending.unlink()
    assert facility.pending_feature_trace(CONTEXT) == 0
    assert json.loads(capsys.readouterr().out) == {
        "complete": True,
        "category": 17,
    }


def test_rotation_retires_only_grandparent_after_new_state_is_durable(
    monkeypatch, tmp_path: Path,
) -> None:
    creator = "arena_" + "a" * 16
    geometry = [[594000, 4917000], [596000, 4919000]]
    previous_geometry = [[602000, 4924000], [604000, 4926000]]
    current = tmp_path / "current.json"
    pending = tmp_path / "pending.json"
    current.write_text(json.dumps({
        "context": CONTEXT,
        "value": "FLAG{current}",
        "category": 11,
        "geometry": geometry,
        "creator": creator,
        "previous_category": 7,
        "previous_value": "FLAG{previous}",
        "trace_nonce": "HIJKLMN",
        "trace_born_at": 1_800_000_000,
        "previous_trace_nonce": "ABCDEFG",
        "previous_trace_born_at": 1_799_999_900,
    }), encoding="utf-8")
    roads = {
        7: ("roads.1", "FLAG{previous}", previous_geometry),
        11: ("roads.2", "FLAG{current}", geometry),
    }
    events: list[tuple[str, int]] = []
    monkeypatch.setattr(facility, "CURRENT_FEATURE", current)
    monkeypatch.setattr(facility, "PENDING_FEATURE", pending)
    monkeypatch.setattr(
        facility, "feature_creator",
        lambda _username="": (creator, "Gs!" + "b" * 32),
    )
    monkeypatch.setattr(
        facility, "feature_observer",
        lambda _username="": ("arena_" + "c" * 16, "Gs!" + "d" * 32),
    )
    monkeypatch.setattr(facility, "unused_category", lambda *_args: 22)

    def fake_find(category, _credentials, wanted=""):
        row = roads.get(category)
        if row is not None and wanted and row[1] != wanted:
            row = None
        return ([{
            "id": row[0], "properties": {"cat": category, "label": row[1]},
            "geometry": {
                "type": "MultiLineString", "coordinates": [row[2]],
            },
        }] if row else [])

    def fake_insert(value, category, inserted_geometry, _credentials):
        roads[category] = ("roads.3", value, inserted_geometry)
        events.append(("insert", category))
        return 200, b"SUCCESS"

    def fake_delete(category, value, _credentials):
        assert roads[category][1] == value
        assert json.loads(current.read_text(encoding="utf-8"))["category"] == 22
        roads.pop(category)
        events.append(("delete", category))
        return 200, b"SUCCESS"

    monkeypatch.setattr(facility, "find_features", fake_find)
    monkeypatch.setattr(facility, "insert_feature", fake_insert)
    monkeypatch.setattr(facility, "delete_feature", fake_delete)
    monkeypatch.setattr(
        facility, "validate_feature",
        lambda category, *_args: events.append(("validate", category)),
    )

    encoded = feature_request(
        "FLAG{new}", context=NEXT_CONTEXT, categories=(22,), geometry=geometry
    )
    facility.plant_feature(encoded, "", "", "OPQRSTU", "1800000060")

    assert events == [
        ("validate", 11), ("insert", 22),
        ("validate", 22),
    ]
    assert set(roads) == {7, 11, 22}
    assert json.loads(pending.read_text(encoding="utf-8"))[
        "retire_trace_nonce"
    ] == "ABCDEFG"
    facility.finalize_feature()
    assert events[-1] == ("delete", 7)
    assert set(roads) == {11, 22}
    assert json.loads(current.read_text(encoding="utf-8")) == {
        "context": NEXT_CONTEXT,
        "value": "FLAG{new}",
        "category": 22,
        "geometry": json.loads(current.read_text(encoding="utf-8"))["geometry"],
        "creator": creator,
        "previous_category": 11,
        "previous_value": "FLAG{current}",
        "trace_nonce": "OPQRSTU",
        "trace_born_at": 1_800_000_060,
        "previous_trace_nonce": "HIJKLMN",
        "previous_trace_born_at": 1_800_000_000,
    }
    facility.clear_feature_pending("OPQRSTU", "1800000060")
    assert not pending.exists()


def test_read_uses_one_stable_category_query_without_fid_follow_up(
    monkeypatch, capsys,
) -> None:
    monkeypatch.setattr(facility, "account", lambda _name: ("guarded", "secret"))
    categories: list[int] = []

    def fake_find(category, _credentials):
        categories.append(category)
        return [{
            "id": "roads.91",
            "properties": {"cat": category, "label": "FLAG{proof}"},
        }]

    monkeypatch.setattr(
        facility, "find_features", fake_find,
    )

    assert facility.read_feature(17) == 0
    assert categories == [17]
    assert capsys.readouterr().out == "FLAG{proof}\n"


def test_read_resolves_the_selected_guarded_creator(monkeypatch, capsys) -> None:
    selected: list[str] = []
    monkeypatch.setattr(
        facility, "feature_creator",
        lambda username: (
            selected.append(username) or (username, "guarded-secret")
        ),
    )
    monkeypatch.setattr(
        facility, "find_features",
        lambda *_args: [{
            "properties": {"cat": 17, "label": "FLAG{proof}"},
        }],
    )

    assert facility.read_feature(17, "arena_" + "a" * 16) == 0
    assert selected == ["arena_" + "a" * 16]
    assert capsys.readouterr().out == "FLAG{proof}\n"


def test_objective_placement_uses_the_checker_control_request_history(
    monkeypatch,
) -> None:
    guarded = ("guarded", "secret")
    ordinary = ("ordinary", "secret")
    value = "FLAG{" + "A" * 32 + "}"
    geometry = [[594000, 4917000], [596000, 4919000]]
    trace: list[str] = []
    row: dict[str, object] | None = None

    def fake_find(category, credentials, wanted=""):
        nonlocal row
        trace.append("lookup" if row is not None else "availability")
        if row is None or (wanted and row["properties"]["label"] != wanted):
            return []
        return [row]

    def fake_insert(inserted, category, inserted_geometry, _credentials):
        nonlocal row
        trace.append("insert")
        row = {
            "properties": {"cat": category, "label": inserted},
            "geometry": {
                "type": "MultiLineString", "coordinates": [inserted_geometry],
            },
        }
        return 200, b"SUCCESS"

    monkeypatch.setattr(facility, "find_features", fake_find)
    monkeypatch.setattr(facility, "insert_feature", fake_insert)
    monkeypatch.setattr(
        facility, "feature_response",
        lambda *_args: (trace.append("ordinary") or (403, b"")),
    )
    monkeypatch.setattr(
        facility, "feature_property_value",
        lambda *_args: (trace.append("property") or (200, b"property")),
    )
    images = iter((b"selected", b"absent"))

    def fake_map(*_args):
        image = next(images)
        trace.append("wms_selected" if image == b"selected" else "wms_absent")
        return 200, image

    monkeypatch.setattr(facility, "map_feature", fake_map)
    monkeypatch.setattr(facility, "property_matches", lambda *_args: True)
    monkeypatch.setattr(facility, "render_matches", lambda *_args: True)

    category = facility.unused_category(guarded, set(), [17])
    facility.ensure_feature(value, category, geometry, guarded)
    facility.validate_feature(category, value, geometry, guarded, ordinary)

    assert trace == [
        "availability", "availability", "insert", "lookup", "property",
        "wms_selected", "wms_absent", "ordinary",
    ]


def test_feature_locator_uses_seed_order_and_skips_reserved_categories(
    monkeypatch,
) -> None:
    checked: list[int] = []

    def fake_find(category, _credentials):
        checked.append(category)
        return [{"occupied": True}] if category in {17, 22} else []

    monkeypatch.setattr(facility, "find_features", fake_find)

    assert facility.unused_category(
        ("guarded", "secret"), {31}, [17, 31, 22, 45]
    ) == 45
    assert checked == [17, 22, 45]


def test_corrupt_feature_placement_state_fails_without_rotation(
    monkeypatch, tmp_path: Path,
) -> None:
    current = tmp_path / "current.json"
    current.write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(facility, "CURRENT_FEATURE", current)
    monkeypatch.setattr(facility, "PENDING_FEATURE", tmp_path / "pending.json")
    monkeypatch.setattr(
        facility,
        "feature_creator",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("corrupt identity must not create a replacement")
        ),
    )

    encoded = feature_request("FLAG{proof}")
    with pytest.raises(RuntimeError, match="invalid protected feature"):
        facility.plant_feature(encoded)


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
    monkeypatch.setattr(facility, "ensure_resource_acl", lambda: None)

    facility.bootstrap()

    assert rest_calls == [
        ("GET", "/security/roles.json", ("admin", "rotated"))
    ]
    assert reconciled == [
        (facility.ORDINARY_USER, "one"),
        (facility.GUARDED_USER, "two"),
    ]
