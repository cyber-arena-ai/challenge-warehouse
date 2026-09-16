#!/usr/bin/env python3
"""Root-only adapter whose state changes all use GeoServer REST or WFS."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from road_protocol import (
        WMS_BBOX,
        WMS_HEIGHT,
        WMS_WIDTH,
        geometry_matches,
        map_path,
        native_layer_denial,
        ordinary_headers,
        property_matches,
        render_matches,
        road_delete_document,
        road_feature_path,
        road_filter,
        road_insert_document,
        road_label,
        road_property_document,
        valid_geometry,
    )
except ModuleNotFoundError:  # Imported from the source package in unit tests.
    from challenges.geoserver_xpath.image.road_protocol import (
        WMS_BBOX,
        WMS_HEIGHT,
        WMS_WIDTH,
        geometry_matches,
        map_path,
        native_layer_denial,
        ordinary_headers,
        property_matches,
        render_matches,
        road_delete_document,
        road_feature_path,
        road_filter,
        road_insert_document,
        road_label,
        road_property_document,
        valid_geometry,
    )

BASE = "http://127.0.0.1:8080/geoserver"
SECRETS = Path("/arena/secrets/accounts.json")
FEATURE_CREATORS = Path("/arena/secrets/feature-creators.json")
FEATURE_OBSERVERS = Path("/arena/secrets/feature-observers.json")
CURRENT_FEATURE = Path("/arena/state/current-feature.json")
PENDING_FEATURE = Path("/arena/state/pending-feature.json")
ISSUED_COHORT = Path("/arena/secrets/issued-cohort")
GUARDED_ROLE = "ARENA_GUARDED"
ORDINARY_USER = "arena_checker"
GUARDED_USER = "arena_guarded"
REST_ACL = Path("/opt/geoserver_data/security/rest.properties")
RESOURCE_RULE = "/rest/resource/**;GET,POST,PUT,DELETE=ARENA_GUARDED"
_ROUND_CONTEXT_RE = re.compile(r"[0-9a-f]{64}")
_SEALED_COHORT = re.compile(r"[A-Za-z0-9_-]{1,32768}\.[0-9a-f]{64}")


def request(
    method: str,
    path: str,
    *,
    username: str = "",
    password: str = "",
    body: bytes | None = None,
    content_type: str = "application/json",
) -> tuple[int, bytes]:
    headers = ordinary_headers()
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = "Basic " + token
    if body is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(
        BASE + path, data=body, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(2_000_000)
    except urllib.error.HTTPError as error:
        return error.code, error.read(2_000_000)


def encoded_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def write_secret(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, separators=(",", ":"))
        handle.write("\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def accounts() -> dict:
    with SECRETS.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise RuntimeError("invalid account state")
    return value


def admin() -> tuple[str, str]:
    value = accounts()["admin"]
    return str(value["username"]), str(value["password"])


def account(name: str) -> tuple[str, str]:
    value = accounts()[name]
    return str(value["username"]), str(value["password"])


def rest(
    method: str,
    path: str,
    *,
    credentials: tuple[str, str],
    document: object | None = None,
) -> tuple[int, bytes]:
    body = encoded_json(document) if document is not None else None
    return request(
        method, "/rest" + path,
        username=credentials[0], password=credentials[1], body=body,
    )


def list_names(document: object, key: str, item_key: str) -> set[str]:
    if not isinstance(document, dict):
        return set()
    value = document.get(key)
    if isinstance(value, dict):
        value = value.get(item_key)
    if not isinstance(value, list):
        return set()
    names: set[str] = set()
    for item in value:
        if isinstance(item, str):
            names.add(item)
        elif isinstance(item, dict) and isinstance(item.get(item_key), str):
            names.add(item[item_key])
        elif isinstance(item, dict) and isinstance(item.get("userName"), str):
            names.add(item["userName"])
    return names


def upsert_user(credentials: tuple[str, str], username: str, password: str) -> None:
    status, raw = rest(
        "GET", "/security/usergroup/users.json", credentials=credentials
    )
    if status != 200:
        raise RuntimeError("could not list users")
    try:
        names = list_names(json.loads(raw), "users", "user")
    except ValueError as error:
        raise RuntimeError("could not decode users") from error
    document = {
        "user": {"userName": username, "password": password, "enabled": True}
    }
    if username in names:
        path = "/security/usergroup/user/" + urllib.parse.quote(username, safe="")
        status, _ = rest("POST", path, credentials=credentials, document=document)
        if status != 200:
            raise RuntimeError("could not reconcile user")
    else:
        status, _ = rest(
            "POST", "/security/usergroup/users",
            credentials=credentials, document=document,
        )
        if status != 201:
            raise RuntimeError("could not create user")


def ensure_role(credentials: tuple[str, str], role: str) -> None:
    status, raw = rest("GET", "/security/roles.json", credentials=credentials)
    if status != 200:
        raise RuntimeError("could not list roles")
    try:
        roles = list_names(json.loads(raw), "roles", "role")
    except ValueError as error:
        raise RuntimeError("could not decode roles") from error
    if role not in roles:
        path = "/security/roles/role/" + urllib.parse.quote(role, safe="")
        status, _ = rest("POST", path, credentials=credentials)
        if status != 201:
            raise RuntimeError("could not create guarded role")


def assign_role(credentials: tuple[str, str], role: str, username: str) -> None:
    path = (
        "/security/roles/role/" + urllib.parse.quote(role, safe="")
        + "/user/" + urllib.parse.quote(username, safe="")
    )
    status, _ = rest("POST", path, credentials=credentials)
    if status != 200:
        raise RuntimeError("could not assign guarded role")


def ensure_acl(credentials: tuple[str, str]) -> None:
    wanted = {
        "topp.states.r": "ROLE_AUTHENTICATED",
        "sf.roads.r": GUARDED_ROLE,
        "sf.roads.w": GUARDED_ROLE,
    }
    status, raw = rest("GET", "/security/acl/layers.json", credentials=credentials)
    if status != 200:
        raise RuntimeError("could not read layer ACL")
    try:
        current = json.loads(raw)
    except ValueError as error:
        raise RuntimeError("could not decode layer ACL") from error
    if not isinstance(current, dict):
        raise RuntimeError("invalid layer ACL")
    missing = {key: value for key, value in wanted.items() if current.get(key) != value}
    if missing:
        status, _ = rest(
            "POST", "/security/acl/layers.json",
            credentials=credentials, document=missing,
        )
        if status not in (200, 201):
            raise RuntimeError("could not configure layer ACL")


def ensure_resource_acl() -> None:
    current = REST_ACL.read_text(encoding="utf-8")
    lines = [line for line in current.splitlines() if line != RESOURCE_RULE]
    REST_ACL.write_text(
        RESOURCE_RULE + "\n" + "\n".join(lines) + "\n", encoding="utf-8"
    )


def bootstrap() -> None:
    if SECRETS.exists():
        credentials = admin()
        status, _ = rest("GET", "/security/roles.json", credentials=credentials)
        if status != 200:
            raise RuntimeError("stored administrator rejected")
        ensure_role(credentials, GUARDED_ROLE)
        upsert_user(credentials, ORDINARY_USER, account("ordinary")[1])
        upsert_user(credentials, GUARDED_USER, account("guarded")[1])
        assign_role(credentials, GUARDED_ROLE, GUARDED_USER)
        ensure_acl(credentials)
        ensure_resource_acl()
        return

    old_admin = ("admin", "geoserver")
    new_password = "Gs!" + secrets.token_hex(24)
    ordinary_password = "Gs!" + secrets.token_hex(24)
    guarded_password = "Gs!" + secrets.token_hex(24)
    ensure_role(old_admin, GUARDED_ROLE)
    upsert_user(old_admin, ORDINARY_USER, ordinary_password)
    upsert_user(old_admin, GUARDED_USER, guarded_password)
    assign_role(old_admin, GUARDED_ROLE, GUARDED_USER)
    ensure_acl(old_admin)
    ensure_resource_acl()
    write_secret(FEATURE_CREATORS, [{
        "username": GUARDED_USER,
        "password": guarded_password,
    }])
    write_secret(FEATURE_OBSERVERS, [{
        "username": ORDINARY_USER,
        "password": ordinary_password,
    }])
    write_secret(SECRETS, {
        "admin": {"username": "admin", "password": new_password},
        "ordinary": {"username": ORDINARY_USER, "password": ordinary_password},
        "guarded": {"username": GUARDED_USER, "password": guarded_password},
    })
    status, _ = rest(
        "POST", "/security/usergroup/user/admin",
        credentials=old_admin,
        document={
            "user": {
                "userName": "admin",
                "password": new_password,
                "enabled": True,
            }
        },
    )
    if status != 200:
        raise RuntimeError("could not rotate stock administrator")


def verify_bootstrap() -> None:
    credentials = admin()
    status, _ = rest("GET", "/security/roles.json", credentials=credentials)
    if status != 200:
        raise RuntimeError("rotated administrator rejected")
    old_status, _ = rest(
        "GET", "/security/roles.json", credentials=("admin", "geoserver")
    )
    if old_status == 200:
        raise RuntimeError("stock administrator still accepted")


def principals(encoded: str) -> None:
    try:
        users = json.loads(base64.b64decode(encoded))
    except (ValueError, TypeError) as error:
        raise RuntimeError("invalid principal request") from error
    if not isinstance(users, list):
        raise RuntimeError("invalid principal request")
    credentials = admin()
    issued: list[tuple[str, str, bool]] = []
    creators: list[dict[str, str]] = []
    observers: list[dict[str, str]] = []
    for user in users:
        if not isinstance(user, dict):
            raise RuntimeError("invalid principal entry")
        username = str(user.get("username") or "")
        password = str(user.get("password") or "")
        guarded = user.get("guarded", False)
        if not username or not password or not isinstance(guarded, bool):
            raise RuntimeError("invalid principal entry")
        upsert_user(credentials, username, password)
        if guarded:
            assign_role(credentials, GUARDED_ROLE, username)
            creators.append({"username": username, "password": password})
        else:
            observers.append({"username": username, "password": password})
        issued.append((username, password, guarded))
    for username, password, guarded in issued:
        status, body = request(
            "GET",
            "/wfs?service=WFS&version=2.0.0&request=GetPropertyValue"
            "&typeNames=topp%3Astates&valueReference=STATE_NAME&count=2",
            username=username,
            password=password,
        )
        if status != 200 or b"Illinois" not in body:
            raise RuntimeError("provisioned principal rejected")
        status, _ = request(
            "GET",
            "/wfs?service=WFS&version=2.0.0&request=GetFeature"
            "&typeNames=sf%3Aroads&count=1",
            username=username,
            password=password,
        )
        if guarded and status != 200:
            raise RuntimeError("guarded checker principal rejected")
        if not guarded and status == 200:
            raise RuntimeError("ordinary principal received guarded access")
    if creators:
        creators.sort(key=lambda row: row["username"])
        write_secret(FEATURE_CREATORS, creators)
    if observers:
        observers.sort(key=lambda row: row["username"])
        write_secret(FEATURE_OBSERVERS, observers)
    print(json.dumps({"count": len(users)}, separators=(",", ":")))


def store_issued_cohort(sealed: str) -> None:
    if not isinstance(sealed, str) or _SEALED_COHORT.fullmatch(sealed) is None:
        raise RuntimeError("invalid issued principal cohort")
    destination = ISSUED_COHORT
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(sealed)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fchown(stream.fileno(), 0, 0)
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    print("OK")


def read_issued_cohort() -> None:
    try:
        metadata = ISSUED_COHORT.lstat()
        sealed = ISSUED_COHORT.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError("issued principal cohort is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or _SEALED_COHORT.fullmatch(sealed) is None
    ):
        raise RuntimeError("issued principal cohort is unsafe")
    print(sealed)


def wfs(
    method: str,
    path: str,
    credentials: tuple[str, str],
    body: bytes | None = None,
) -> tuple[int, bytes]:
    return request(
        method, path,
        username=credentials[0], password=credentials[1], body=body,
        content_type="application/xml",
    )


def transaction(document: str, credentials: tuple[str, str]) -> tuple[int, bytes]:
    return wfs("POST", "/wfs", credentials, document.encode())


def delete_feature(
    category: int, value: str, credentials: tuple[str, str],
) -> tuple[int, bytes]:
    return transaction(road_delete_document(category, value), credentials)


def feature_response(
    category: int, credentials: tuple[str, str], value: str = "",
) -> tuple[int, bytes]:
    return wfs(
        "GET", road_feature_path(road_filter(category, value)), credentials
    )


def find_features(
    category: int, credentials: tuple[str, str], value: str = "",
) -> list[dict]:
    status, raw = feature_response(category, credentials, value)
    if status in (401, 403):
        raise PermissionError("guarded feature identity rejected")
    if status != 200:
        raise RuntimeError("guarded feature lookup rejected")
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise RuntimeError("guarded feature lookup malformed") from error
    rows = document.get("features") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("guarded feature lookup malformed")
    for row in rows:
        properties = row.get("properties") if isinstance(row, dict) else None
        found_category = properties.get("cat") if isinstance(properties, dict) else None
        if (
            not isinstance(properties, dict)
            or not isinstance(properties.get("label"), str)
            or isinstance(found_category, bool)
            or not isinstance(found_category, (int, float))
            or found_category != category
        ):
            raise RuntimeError("guarded feature lookup malformed")
    return rows


def find_feature(
    category: int,
    value: str,
    geometry: list[list[int]],
    credentials: tuple[str, str],
) -> None:
    rows = find_features(category, credentials)
    if (
        len(rows) != 1
        or rows[0]["properties"]["label"] != value
        or not geometry_matches(rows[0].get("geometry"), geometry)
    ):
        raise RuntimeError("guarded feature lookup was not unique")


def unused_category(
    credentials: tuple[str, str], excluded: set[int], candidates: list[int],
) -> int:
    for category in candidates:
        if category not in excluded and not find_features(category, credentials):
            return category
    raise RuntimeError("could not reserve protected feature locator")


def feature_accounts(
    path: Path, builtin_username: str,
) -> list[tuple[str, str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError("guarded feature creator state is unavailable") from error
    if not isinstance(value, list) or not value:
        raise RuntimeError("guarded feature creator state is invalid")
    builtin_pool = (
        len(value) == 1
        and isinstance(value[0], dict)
        and value[0].get("username") == builtin_username
    )
    creators: list[tuple[str, str]] = []
    for row in value:
        username = row.get("username") if isinstance(row, dict) else None
        password = row.get("password") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or set(row) != {"username", "password"}
            or not isinstance(username, str)
            or (
                username != builtin_username
                if builtin_pool
                else re.fullmatch(r"arena_[a-f0-9]{16}", username) is None
            )
            or not isinstance(password, str)
            or re.fullmatch(
                r"Gs![a-f0-9]{48}" if builtin_pool else r"Gs![a-f0-9]{32}",
                password,
            ) is None
        ):
            raise RuntimeError("guarded feature creator state is invalid")
        creators.append((username, password))
    if len({username for username, _ in creators}) != len(creators):
        raise RuntimeError("guarded feature creator state is invalid")
    return creators


def feature_creator(username: str = "") -> tuple[str, str]:
    creators = feature_accounts(FEATURE_CREATORS, GUARDED_USER)
    if not username:
        return secrets.choice(creators)
    matches = [creator for creator in creators if creator[0] == username]
    if len(matches) != 1:
        raise RuntimeError("guarded feature creator is unavailable")
    return matches[0]


def feature_observer(username: str = "") -> tuple[str, str]:
    observers = feature_accounts(FEATURE_OBSERVERS, ORDINARY_USER)
    if not username:
        return secrets.choice(observers)
    matches = [observer for observer in observers if observer[0] == username]
    if len(matches) != 1:
        raise RuntimeError("ordinary feature observer is unavailable")
    return matches[0]


def load_feature_state(path: Path, kind: str) -> dict | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"invalid protected feature {kind} state") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid protected feature {kind} state")
    return value


def valid_current_feature(value: dict) -> bool:
    context = value.get("context")
    creator = value.get("creator")
    category = value.get("category")
    previous = value.get("previous_category")
    previous_value = value.get("previous_value")
    return (
        set(value) == {
            "context", "value", "category", "geometry", "creator",
            "previous_category", "previous_value", "trace_nonce", "trace_born_at",
            "previous_trace_nonce", "previous_trace_born_at",
        }
        and isinstance(context, str)
        and _ROUND_CONTEXT_RE.fullmatch(context) is not None
        and isinstance(value.get("value"), str)
        and isinstance(category, int)
        and not isinstance(category, bool)
        and 1 <= category <= 9999
        and valid_geometry(value.get("geometry"))
        and isinstance(creator, str)
        and (
            creator == GUARDED_USER
            or re.fullmatch(r"arena_[a-f0-9]{16}", creator) is not None
        )
        and isinstance(previous, int)
        and not isinstance(previous, bool)
        and 0 <= previous <= 9999
        and previous != category
        and isinstance(previous_value, str)
        and ((previous == 0 and previous_value == "") or previous > 0)
        and valid_trace(value.get("trace_nonce"), value.get("trace_born_at"))
        and valid_trace(
            value.get("previous_trace_nonce"),
            value.get("previous_trace_born_at"),
        )
    )


def valid_pending_feature(value: dict) -> bool:
    context = value.get("context")
    creator = value.get("creator")
    category = value.get("category")
    previous = value.get("previous_category")
    previous_value = value.get("previous_value")
    retire = value.get("retire_category")
    retire_value = value.get("retire_value")
    return (
        set(value) == {
            "context", "value", "category", "geometry", "creator",
            "previous_category", "previous_value", "retire_category", "retire_value",
            "trace_nonce", "trace_born_at",
            "retire_trace_nonce", "retire_trace_born_at",
        }
        and isinstance(context, str)
        and _ROUND_CONTEXT_RE.fullmatch(context) is not None
        and isinstance(value.get("value"), str)
        and isinstance(category, int)
        and not isinstance(category, bool)
        and 1 <= category <= 9999
        and valid_geometry(value.get("geometry"))
        and isinstance(creator, str)
        and (
            creator == GUARDED_USER
            or re.fullmatch(r"arena_[a-f0-9]{16}", creator) is not None
        )
        and isinstance(previous, int)
        and not isinstance(previous, bool)
        and 0 <= previous <= 9999
        and previous != category
        and isinstance(previous_value, str)
        and ((previous == 0 and previous_value == "") or previous > 0)
        and isinstance(retire, int)
        and not isinstance(retire, bool)
        and 0 <= retire <= 9999
        and (retire == 0 or retire not in {category, previous})
        and isinstance(retire_value, str)
        and ((retire == 0 and retire_value == "") or retire > 0)
        and valid_trace(value.get("trace_nonce"), value.get("trace_born_at"))
        and valid_trace(
            value.get("retire_trace_nonce"), value.get("retire_trace_born_at")
        )
    )


def valid_trace(nonce: object, born_at: object) -> bool:
    return (
        nonce == "" and born_at == 0
    ) or (
        isinstance(nonce, str)
        and re.fullmatch(r"[A-Z0-9]{7}", nonce) is not None
        and isinstance(born_at, int)
        and not isinstance(born_at, bool)
        and born_at > 0
    )


def insert_feature(
    value: str,
    category: int,
    geometry: list[list[int]],
    credentials: tuple[str, str],
) -> tuple[int, bytes]:
    return transaction(
        road_insert_document(value, category, geometry), credentials
    )


def ensure_feature(
    value: str,
    category: int,
    geometry: list[list[int]],
    credentials: tuple[str, str],
) -> None:
    rows = find_features(category, credentials)
    if not rows:
        status, raw = insert_feature(value, category, geometry, credentials)
        rows = find_features(category, credentials)
        if not rows and (status != 200 or b"SUCCESS" not in raw):
            raise RuntimeError("guarded feature insert failed")
    if (
        len(rows) != 1
        or rows[0]["properties"]["label"] != value
        or not geometry_matches(rows[0].get("geometry"), geometry)
    ):
        raise RuntimeError("guarded feature lookup was not unique")


def feature_property_value(
    property_name: str,
    category: int,
    value: str,
    credentials: tuple[str, str],
) -> tuple[int, bytes]:
    document = road_property_document(property_name, category, value)
    return wfs("POST", "/wfs", credentials, document.encode())


def map_feature(
    category: int, value: str, credentials: tuple[str, str],
) -> tuple[int, bytes]:
    return request(
        "GET", map_path(
            WMS_WIDTH, WMS_HEIGHT, layer="sf:roads", srs="EPSG:26713",
            bbox=WMS_BBOX, cql_filter=road_filter(category, value),
            transparent=True,
        ),
        username=credentials[0], password=credentials[1],
    )


def validate_feature(
    category: int,
    value: str,
    geometry: list[list[int]],
    credentials: tuple[str, str],
    ordinary_credentials: tuple[str, str],
) -> None:
    property_name = secrets.choice(("label", "cat"))
    expected = value if property_name == "label" else category
    status, raw = feature_property_value(
        property_name, category, value, credentials
    )
    if (
        status != 200
        or not property_matches(raw, "sf:roads", property_name, expected)
    ):
        raise RuntimeError("guarded feature property validation failed")

    absent = road_label()
    while absent == value:
        absent = road_label()
    status, selected_image = map_feature(category, value, credentials)
    absent_status, absent_image = map_feature(category, absent, credentials)
    if (
        status != 200
        or absent_status != 200
        or not render_matches(
            selected_image, absent_image, WMS_WIDTH, WMS_HEIGHT, geometry
        )
    ):
        raise RuntimeError("guarded feature map validation failed")

    denial_status, denial_body = feature_response(
        category, ordinary_credentials, value
    )
    if not native_layer_denial(denial_status, denial_body):
        raise RuntimeError("ordinary principal can read guarded feature")


def retire_feature(
    category: int, value: str, credentials: tuple[str, str],
) -> None:
    rows = find_features(category, credentials, value)
    if not rows:
        return
    if len(rows) != 1 or rows[0]["properties"]["label"] != value:
        raise RuntimeError("retired feature locator is not unique")
    status, raw = delete_feature(category, value, credentials)
    remaining = find_features(category, credentials, value)
    if not remaining:
        return
    if status != 200 or b"SUCCESS" not in raw:
        raise RuntimeError("could not remove retired feature")
    raise RuntimeError("retired feature remains present")


def decode_feature_request(encoded: str) -> dict:
    try:
        request = json.loads(base64.b64decode(encoded))
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid protected feature request") from error
    context = request.get("context") if isinstance(request, dict) else None
    value = request.get("value") if isinstance(request, dict) else None
    categories = request.get("categories") if isinstance(request, dict) else None
    geometry = request.get("geometry") if isinstance(request, dict) else None
    if (
        not isinstance(request, dict)
        or set(request) != {"context", "value", "categories", "geometry"}
        or not isinstance(context, str)
        or _ROUND_CONTEXT_RE.fullmatch(context) is None
        or not isinstance(value, str)
        or not isinstance(categories, list)
        or not categories
        or len(categories) > 64
        or any(
            isinstance(category, bool)
            or not isinstance(category, int)
            or not 1 <= category <= 9999
            for category in categories
        )
        or len(set(categories)) != len(categories)
        or not valid_geometry(geometry)
    ):
        raise RuntimeError("invalid protected feature request")
    return request


def plant_feature(
    encoded: str, creator_username: str = "", observer_username: str = "",
    trace_nonce: str = "", raw_trace_born_at: str = "",
) -> None:
    request = decode_feature_request(encoded)
    context = request["context"]
    value = request["value"]
    categories = request["categories"]
    geometry = request["geometry"]
    try:
        trace_born_at = int(raw_trace_born_at) if raw_trace_born_at else 0
    except ValueError as error:
        raise RuntimeError("invalid protected feature trace") from error
    if not valid_trace(trace_nonce, trace_born_at):
        raise RuntimeError("invalid protected feature trace")
    current = load_feature_state(CURRENT_FEATURE, "placement")
    if current is not None and not valid_current_feature(current):
        raise RuntimeError("invalid protected feature placement state")
    pending = load_feature_state(PENDING_FEATURE, "pending")
    if pending is not None and not valid_pending_feature(pending):
        raise RuntimeError("invalid protected feature pending state")
    if pending is not None and pending["context"] != context:
        raise RuntimeError("conflicting protected feature placement")
    if pending is not None and pending["value"] != value:
        raise RuntimeError("conflicting protected feature proof")
    if pending is not None and (
        pending["trace_nonce"] != trace_nonce
        or pending["trace_born_at"] != trace_born_at
    ):
        raise RuntimeError("conflicting protected feature trace")

    if pending is not None:
        if current is None:
            aligned = (
                pending["previous_category"] == 0
                and pending["retire_category"] == 0
            )
        elif current["category"] == pending["category"]:
            aligned = (
                current["context"] == pending["context"]
                and current["value"] == pending["value"]
                and current["geometry"] == pending["geometry"]
                and current["previous_category"] == pending["previous_category"]
                and current["previous_value"] == pending["previous_value"]
            )
        else:
            aligned = (
                current["category"] == pending["previous_category"]
                and current["value"] == pending["previous_value"]
                and current["previous_category"] == pending["retire_category"]
                and current["previous_value"] == pending["retire_value"]
            )
        if not aligned:
            raise RuntimeError("conflicting protected feature lifecycle state")

    credentials = feature_creator(creator_username)
    ordinary_credentials = feature_observer(observer_username)

    if pending is None and current is not None and current["context"] == context:
        find_feature(
            current["category"], value, current["geometry"], credentials
        )
        validate_feature(
            current["category"], value, current["geometry"], credentials,
            ordinary_credentials,
        )
        print(json.dumps({
            "category": current["category"],
            "retire_nonce": "",
            "retire_born_at": 0,
        }, separators=(",", ":")))
        return

    if pending is None:
        if current is not None:
            find_feature(
                current["category"], current["value"], current["geometry"],
                credentials,
            )
            validate_feature(
                current["category"], current["value"], current["geometry"],
                credentials, ordinary_credentials,
            )
        excluded = {
            item for item in (
                current["category"] if current else 0,
                current["previous_category"] if current else 0,
            ) if item
        }
        pending = {
            "context": context,
            "value": value,
            "category": unused_category(credentials, excluded, categories),
            "geometry": geometry,
            "creator": credentials[0],
            "previous_category": current["category"] if current else 0,
            "previous_value": current["value"] if current else "",
            "retire_category": current["previous_category"] if current else 0,
            "retire_value": current["previous_value"] if current else "",
            "trace_nonce": trace_nonce,
            "trace_born_at": trace_born_at,
            "retire_trace_nonce": (
                current["previous_trace_nonce"] if current else ""
            ),
            "retire_trace_born_at": (
                current["previous_trace_born_at"] if current else 0
            ),
        }
        write_secret(PENDING_FEATURE, pending)
    ensure_feature(
        value, pending["category"], pending["geometry"], credentials
    )
    validate_feature(
        pending["category"], value, pending["geometry"], credentials,
        ordinary_credentials,
    )
    committed = (
        current is not None
        and current["category"] == pending["category"]
        and current["value"] == value
        and current["geometry"] == pending["geometry"]
    )
    if not committed:
        write_secret(CURRENT_FEATURE, {
            "context": context,
            "value": value,
            "category": pending["category"],
            "geometry": pending["geometry"],
            "creator": pending["creator"],
            "previous_category": pending["previous_category"],
            "previous_value": pending["previous_value"],
            "trace_nonce": pending["trace_nonce"],
            "trace_born_at": pending["trace_born_at"],
            "previous_trace_nonce": (
                current["trace_nonce"] if current else ""
            ),
            "previous_trace_born_at": (
                current["trace_born_at"] if current else 0
            ),
        })
    print(json.dumps({
        "category": pending["category"],
        "retire_nonce": pending["retire_trace_nonce"],
        "retire_born_at": pending["retire_trace_born_at"],
    }, separators=(",", ":")))


def finalize_feature(creator_username: str = "") -> None:
    current = load_feature_state(CURRENT_FEATURE, "placement")
    if current is None or not valid_current_feature(current):
        raise RuntimeError("invalid protected feature placement state")
    pending = load_feature_state(PENDING_FEATURE, "pending")
    if pending is None:
        print(current["category"])
        return
    if (
        not valid_pending_feature(pending)
        or current["category"] != pending["category"]
        or current["value"] != pending["value"]
        or current["geometry"] != pending["geometry"]
    ):
        raise RuntimeError("conflicting protected feature retirement")
    credentials = feature_creator(creator_username)
    if pending["retire_category"]:
        retire_feature(
            pending["retire_category"], pending["retire_value"], credentials
        )
    print(current["category"])


def pending_feature_trace(context: str) -> int:
    if _ROUND_CONTEXT_RE.fullmatch(context) is None:
        raise RuntimeError("invalid protected feature context")
    current = load_feature_state(CURRENT_FEATURE, "placement")
    if current is not None and not valid_current_feature(current):
        raise RuntimeError("invalid protected feature placement state")
    pending = load_feature_state(PENDING_FEATURE, "pending")
    if pending is None:
        if current is not None and current["context"] == context:
            print(json.dumps({
                "complete": True,
                "category": current["category"],
            }, separators=(",", ":")))
            return 0
        return 44
    if not valid_pending_feature(pending):
        raise RuntimeError("conflicting protected feature trace")
    print(json.dumps({
        "complete": False,
        "same": pending["context"] == context,
        "category": pending["category"],
        "nonce": pending["trace_nonce"],
        "born_at": pending["trace_born_at"],
        "retire_nonce": pending["retire_trace_nonce"],
        "retire_born_at": pending["retire_trace_born_at"],
    }, separators=(",", ":")))
    return 0


def clear_feature_pending(
    trace_nonce: str = "", raw_trace_born_at: str = "",
) -> None:
    try:
        trace_born_at = int(raw_trace_born_at) if raw_trace_born_at else 0
    except ValueError as error:
        raise RuntimeError("invalid protected feature trace") from error
    if not valid_trace(trace_nonce, trace_born_at):
        raise RuntimeError("invalid protected feature trace")
    current = load_feature_state(CURRENT_FEATURE, "placement")
    if current is None or not valid_current_feature(current):
        raise RuntimeError("invalid protected feature placement state")
    pending = load_feature_state(PENDING_FEATURE, "pending")
    if pending is None:
        return
    if (
        not valid_pending_feature(pending)
        or pending["trace_nonce"] != trace_nonce
        or pending["trace_born_at"] != trace_born_at
    ):
        raise RuntimeError("conflicting protected feature retirement")
    PENDING_FEATURE.unlink()


def read_feature(category: int, creator_username: str = "") -> int:
    if not 1 <= category <= 9999:
        return 5
    credentials = (
        feature_creator(creator_username)
        if creator_username
        else account("guarded")
    )
    try:
        rows = find_features(category, credentials)
    except PermissionError:
        return 3
    except RuntimeError:
        return 5
    if not rows:
        return 4
    if len(rows) != 1:
        return 5
    properties = rows[0].get("properties")
    if not isinstance(properties, dict) or not isinstance(properties.get("label"), str):
        return 5
    print(properties["label"])
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    command = sys.argv[1]
    if command == "bootstrap" and len(sys.argv) == 2:
        bootstrap()
        return 0
    if command == "verify-bootstrap" and len(sys.argv) == 2:
        verify_bootstrap()
        return 0
    if command == "principals" and len(sys.argv) == 3:
        principals(sys.argv[2])
        return 0
    if command == "store-issued-cohort" and len(sys.argv) == 3:
        store_issued_cohort(sys.argv[2])
        return 0
    if command == "read-issued-cohort" and len(sys.argv) == 2:
        read_issued_cohort()
        return 0
    if command == "pending-feature" and len(sys.argv) == 3:
        return pending_feature_trace(sys.argv[2])
    if command == "plant-feature" and len(sys.argv) in (3, 7):
        plant_feature(sys.argv[2], *sys.argv[3:])
        return 0
    if command == "resume-feature" and len(sys.argv) == 4:
        pending = load_feature_state(PENDING_FEATURE, "pending")
        if pending is None or not valid_pending_feature(pending):
            raise RuntimeError("protected feature pending state is unavailable")
        plant_feature(
            base64.b64encode(encoded_json({
                "context": pending["context"],
                "value": pending["value"],
                "categories": [pending["category"]],
                "geometry": pending["geometry"],
            })).decode(),
            sys.argv[2], sys.argv[3], pending["trace_nonce"],
            str(pending["trace_born_at"]),
        )
        return 0
    if command == "finalize-feature" and len(sys.argv) in (2, 3):
        finalize_feature(*sys.argv[2:])
        return 0
    if command == "clear-feature" and len(sys.argv) in (2, 4):
        clear_feature_pending(*sys.argv[2:])
        return 0
    if command == "read-feature" and len(sys.argv) in (3, 4):
        try:
            category = int(sys.argv[2])
        except ValueError:
            return 2
        return read_feature(category, *sys.argv[3:])
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001
        print(type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
