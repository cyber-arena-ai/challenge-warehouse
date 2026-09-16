#!/usr/bin/env python3
"""Root-only SuiteCRM principal provisioning and placement metadata."""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8080"
STATE = Path("/arena/secrets/facility.json")
ADMIN_ENV = Path("/arena/secrets/admin.env")
OBJECTIVE_DIR = Path("/opt/arena/objective")
PLANT_CACHE_DIR = Path("/arena/state/plants")
USERNAME = re.compile(r"arena_[0-9a-f]{16}")
GROUP = re.compile(r"Arena partition [0-9a-f]{8}")
UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
NOTE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
ROLE_NAME = "Arena equivalent Security Group role"
CLIENT_NAME = "Arena SuiteCRM V8 password client"
TIMEOUT = 30


def _nv(fields: dict[str, object]) -> list[dict[str, str]]:
    return [{"name": name, "value": str(value)} for name, value in fields.items()]


def _rows(document: object) -> list[dict[str, str]]:
    if not isinstance(document, dict):
        return []
    output: list[dict[str, str]] = []
    for entry in document.get("entry_list") or []:
        if not isinstance(entry, dict):
            continue
        row = {"id": str(entry.get("id") or "")}
        for key, pair in (entry.get("name_value_list") or {}).items():
            if isinstance(pair, dict):
                row[str(key)] = str(pair.get("value") or "")
        output.append(row)
    return output


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class Api:
    def __init__(self):
        self.session = ""
        self.user_id = ""
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def open(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(
            BASE + path, data=data, method=method, headers=headers or {}
        )
        try:
            with self.opener.open(request, timeout=TIMEOUT) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def rest(
        self,
        method: str,
        params: dict[str, object],
        *,
        top_level: dict[str, str] | None = None,
        allowed_errors: tuple[str, ...] = (),
    ) -> object:
        form = {
            "method": method,
            "input_type": "JSON",
            "response_type": "JSON",
            "rest_data": json.dumps(params, separators=(",", ":")),
        }
        if top_level:
            form.update(top_level)
        status, raw = self.open(
            "POST", "/service/v4_1/rest.php",
            data=urllib.parse.urlencode(form).encode(),
        )
        if status != 200:
            raise RuntimeError("SuiteCRM REST unavailable")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError("SuiteCRM REST malformed") from error
        if (
            isinstance(result, dict)
            and result.get("name") in {
                "Invalid Session ID", "Access Denied", "Invalid Login"
            }
            and result.get("name") not in allowed_errors
        ):
            raise RuntimeError("SuiteCRM operation rejected")
        return result

    def login(self, username: str, password: str) -> bool:
        result = self.rest("login", {
            "user_auth": {
                "user_name": username,
                "password": hashlib.md5(password.encode()).hexdigest(),
                "version": "1",
            },
            "application_name": "cyber-arena-facility",
            "name_value_list": [],
        }, allowed_errors=("Invalid Login",))
        if not isinstance(result, dict) or not result.get("id"):
            return False
        values = result.get("name_value_list") or {}
        user = values.get("user_id") if isinstance(values, dict) else None
        if not isinstance(user, dict) or not user.get("value"):
            return False
        self.session = str(result["id"])
        self.user_id = str(user["value"])
        return True

    def set_entry(
        self,
        module: str,
        fields: dict[str, object],
        *,
        top_level: dict[str, str] | None = None,
    ) -> str:
        result = self.rest("set_entry", {
            "session": self.session,
            "module_name": module,
            "name_value_list": _nv(fields),
            "track_view": False,
        }, top_level=top_level)
        if not isinstance(result, dict) or not result.get("id") or result["id"] == "-1":
            raise RuntimeError("SuiteCRM record save failed")
        return str(result["id"])

    def get_entry(
        self, module: str, record_id: str, fields: list[str]
    ) -> list[dict[str, str]]:
        result = self.rest("get_entry", {
            "session": self.session,
            "module_name": module,
            "id": record_id,
            "select_fields": fields,
            "link_name_to_fields_array": [],
            "track_view": False,
        }, allowed_errors=("Access Denied",))
        return _rows(result)

    def list(
        self, module: str, query: str, fields: list[str], limit: int = 200
    ) -> list[dict[str, str]]:
        result = self.rest("get_entry_list", {
            "session": self.session,
            "module_name": module,
            "query": query,
            "order_by": "",
            "offset": 0,
            "select_fields": fields,
            "link_name_to_fields_array": [],
            "max_results": limit,
            "deleted": 0,
            "favorites": False,
        })
        return _rows(result)

    def relate(
        self, module: str, record_id: str, link: str, related_ids: list[str]
    ) -> None:
        result = self.rest("set_relationship", {
            "session": self.session,
            "module_name": module,
            "module_id": record_id,
            "link_field_name": link,
            "related_ids": related_ids,
            "name_value_list": [],
            "delete": False,
        })
        if isinstance(result, dict) and result.get("failed"):
            raise RuntimeError("SuiteCRM relationship failed")

    def set_role_actions(self, role_id: str, actions: list[tuple[str, int]]) -> None:
        pairs = [
            ("module", "ACLRoles"),
            ("action", "Save"),
            ("record", role_id),
        ]
        pairs.extend(("act_guid" + action, str(access))
                     for action, access in actions)
        status, _ = self.open(
            "POST", "/index.php",
            data=urllib.parse.urlencode(pairs).encode(),
            headers={
                "Cookie": "PHPSESSID=" + self.session,
                "Referer": BASE + "/index.php?module=ACLRoles&action=EditView",
            },
        )
        if status != 200:
            raise RuntimeError("SuiteCRM role form rejected")


def load_admin() -> tuple[str, str]:
    values: dict[str, str] = {}
    for raw in ADMIN_ENV.read_text().splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key] = value
    username = values.get("ADMIN_USER", "")
    password = values.get("ADMIN_PASS", "")
    if not username or not password:
        raise RuntimeError("admin credential unavailable")
    return username, password


def save_state(state: dict[str, object]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix(".new")
    temporary.write_text(json.dumps(state, separators=(",", ":"), sort_keys=True))
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE)


def load_state() -> dict[str, object]:
    if not STATE.exists():
        state: dict[str, object] = {
            "client_id": "",
            "role_id": "",
            "current_group": None,
            "previous_group": None,
            "pending_group": None,
            "retiring_group": None,
        }
        save_state(state)
    value = json.loads(STATE.read_text())
    if not isinstance(value, dict):
        raise RuntimeError("facility state malformed")
    return value


def admin_api() -> Api:
    username, password = load_admin()
    api = Api()
    if not api.login(username, password):
        raise RuntimeError("admin login rejected")
    return api


def find_one(
    api: Api, module: str, table: str, field: str, value: str
) -> dict[str, str] | None:
    rows = api.list(
        module, f"{table}.{field}={sql_string(value)}", ["id", field], limit=2
    )
    matches = [row for row in rows if row.get(field) == value]
    if len(matches) > 1:
        raise RuntimeError("duplicate application identity")
    return matches[0] if matches else None


def ensure_role(api: Api, state: dict[str, object]) -> str:
    row = find_one(api, "ACLRoles", "acl_roles", "name", ROLE_NAME)
    role_id = row["id"] if row else api.set_entry("ACLRoles", {
        "name": ROLE_NAME,
        "description": "Equivalent normal role with group-scoped Notes and Cases",
    })
    actions = api.list(
        "ACLActions",
        "acl_actions.category IN ('Notes','Cases','AOR_Reports','AOR_Fields')",
        ["id", "name", "category"],
        limit=200,
    )
    group_actions = {"list", "view", "edit", "delete", "export", "massupdate"}
    overrides: list[tuple[str, int]] = []
    for action in actions:
        if action.get("category") in {"Notes", "Cases"}:
            access = 80 if action.get("name") in group_actions else 89
        else:
            access = 89 if action.get("name") == "access" else 90
        overrides.append((action["id"], access))
    if not overrides:
        raise RuntimeError("ACL actions unavailable")
    api.set_role_actions(role_id, overrides)
    state["role_id"] = role_id
    return role_id


def ensure_client(
    api: Api, state: dict[str, object], client_id: str, secret: str
) -> None:
    row = find_one(api, "OAuth2Clients", "oauth2clients", "name", CLIENT_NAME)
    if row and row["id"] != client_id:
        raise RuntimeError("OAuth client identity changed")
    fields: dict[str, object] = {
        "id": client_id,
        "name": CLIENT_NAME,
        "secret": hashlib.sha256(secret.encode()).hexdigest(),
        "redirect_url": BASE,
        "is_confidential": "1",
        "allowed_grant_type": "password",
        "duration_value": "3600",
        "duration_amount": "1",
        "duration_unit": "hour",
    }
    if not row:
        fields["new_with_id"] = "1"
    if api.set_entry("OAuth2Clients", fields) != client_id:
        raise RuntimeError("OAuth client provisioning failed")
    state["client_id"] = client_id


def normalize_principal_batch(raw: object) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ValueError("principal batch must be a list")
    output: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("principal must be an object")
        username = item.get("username")
        password = item.get("password")
        group = item.get("group")
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("invalid username")
        if not isinstance(password, str) or len(password) < 32:
            raise ValueError("invalid password")
        if not isinstance(group, str) or not GROUP.fullmatch(group):
            raise ValueError("invalid group")
        output.append({"username": username, "password": password, "group": group})
    if len({item["username"] for item in output}) != len(output):
        raise ValueError("duplicate principal")
    if len({item["group"] for item in output}) != len(output):
        raise ValueError("duplicate group")
    return sorted(output, key=lambda item: item["username"])


def normalize_client(raw: object) -> tuple[str, str]:
    if not isinstance(raw, dict):
        raise ValueError("OAuth client must be an object")
    client_id = raw.get("id")
    secret = raw.get("secret")
    if not valid_uuid(client_id):
        raise ValueError("invalid OAuth client id")
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("invalid OAuth client secret")
    return client_id, secret


def normalize_checker(
    raw: object, accounts: list[dict[str, str]]
) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        raise ValueError("checker identities must be an object")
    checker: dict[str, list[str]] = {}
    for key in ("ordinary", "guarded"):
        values = raw.get(key)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("checker identity pool invalid")
        checker[key] = values
    if set(checker["ordinary"]) & set(checker["guarded"]):
        raise ValueError("checker identity pools must be distinct")
    usernames = {account["username"] for account in accounts}
    if any(value not in usernames for values in checker.values() for value in values):
        raise ValueError("checker identity not provisioned")
    return checker


def ensure_group(api: Api, name: str, role_id: str) -> str:
    row = find_one(api, "SecurityGroups", "securitygroups", "name", name)
    group_id = row["id"] if row else api.set_entry("SecurityGroups", {
        "name": name,
        "description": "Arena record partition",
    })
    api.relate("ACLRoles", role_id, "SecurityGroups", [group_id])
    return group_id


def ensure_user(api: Api, account: dict[str, str], group_id: str) -> str:
    username = account["username"]
    row = find_one(api, "Users", "users", "user_name", username)
    fields: dict[str, object] = {
        "user_name": username,
        "first_name": "Arena",
        "last_name": "User",
        "status": "Active",
        "employee_status": "Active",
        "is_admin": "0",
        "UserType": "RegularUser",
        "receive_notifications": "0",
        "system_generated_password": "0",
    }
    if row:
        fields["id"] = row["id"]
    user_id = api.set_entry(
        "Users", fields,
        top_level={
            "old_password": "",
            "new_password": account["password"],
            "password_change": "true",
        },
    )
    api.relate("Users", user_id, "SecurityGroups", [group_id])
    return user_id


def ensure_account(api: Api, account: dict[str, str], role_id: str) -> str:
    group_id = ensure_group(api, account["group"], role_id)
    return ensure_user(api, account, group_id)


def initialize() -> dict[str, object]:
    state = load_state()
    api = admin_api()
    ensure_role(api, state)
    save_state(state)
    return state


def provision(encoded: str) -> None:
    raw = json.loads(base64.b64decode(encoded, validate=True))
    if not isinstance(raw, dict):
        raise ValueError("provisioning payload must be an object")
    accounts = normalize_principal_batch(raw.get("accounts"))
    normalize_checker(raw.get("checker"), accounts)
    client_id, client_secret = normalize_client(raw.get("client"))
    state = initialize()
    api = admin_api()
    role_id = str(state["role_id"])
    ensure_client(api, state, client_id, client_secret)
    for account in accounts:
        ensure_account(api, account, role_id)
    save_state(state)
    print(json.dumps({
        "count": len(accounts),
        "client_id": client_id,
    }, separators=(",", ":"), sort_keys=True))


GROUP_FIELDS = (
    "group", "note", "operation", "note_digest", "command_digest",
    "note_cache", "command_cache",
)
GROUP_KEYS = set(GROUP_FIELDS)


def valid_group(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == GROUP_KEYS
        and isinstance(value.get("group"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["group"])
        and valid_note_uuid(value.get("note"))
        and isinstance(value.get("operation"), str)
        and re.fullmatch(r"[0-9a-f]{32}", value["operation"])
        and isinstance(value.get("note_digest"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["note_digest"])
        and isinstance(value.get("command_digest"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["command_digest"])
        and isinstance(value.get("note_cache"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["note_cache"])
        and isinstance(value.get("command_cache"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["command_cache"])
    )


def objective_group(
    group: str,
    note: str,
    operation: str,
    note_digest: str,
    command_digest: str,
    note_cache: str,
    command_cache: str,
    *,
    allow_none: bool = False,
) -> dict[str, str] | None:
    raw = (
        group, note, operation, note_digest, command_digest, note_cache, command_cache,
    )
    if allow_none and raw == ("NONE",) * len(GROUP_FIELDS):
        return None
    value = dict(zip(GROUP_FIELDS, raw, strict=True))
    if not valid_group(value):
        raise ValueError("invalid objective group")
    return value


def group_state(
    state: dict[str, object] | None = None,
) -> dict[str, dict[str, str] | None]:
    state = load_state() if state is None else state
    storage_keys = {
        "current_group", "previous_group", "pending_group", "retiring_group"
    }
    if not storage_keys.issubset(state):
        raise RuntimeError("objective group state incomplete")
    values: dict[str, dict[str, str] | None] = {}
    for name in ("current", "previous", "pending", "retiring"):
        value = state.get(f"{name}_group")
        if value is not None and not valid_group(value):
            raise RuntimeError(f"{name} objective group state malformed")
        values[name] = dict(value) if isinstance(value, dict) else None
    concrete = [group for group in values.values() if group is not None]
    if (
        len({group["group"] for group in concrete}) != len(concrete)
        or len({group["note"] for group in concrete}) != len(concrete)
        or len({group["operation"] for group in concrete}) != len(concrete)
    ):
        raise RuntimeError("objective group state identities overlap")
    if values["retiring"] is not None and (
        values["current"] is None
        or values["previous"] is None
        or values["pending"] is not None
    ):
        raise RuntimeError("objective group retirement state inconsistent")
    return values


def read_group_state() -> None:
    print(json.dumps(group_state(), separators=(",", ":"), sort_keys=True))


def record_pending(
    group: str,
    note_id: str,
    operation: str,
    note_digest: str,
    command_digest: str,
    note_cache: str,
    command_cache: str,
    expected_group: str,
    expected_note: str,
    expected_operation: str,
    expected_note_digest: str,
    expected_command_digest: str,
    expected_note_cache: str,
    expected_command_cache: str,
) -> None:
    pending = objective_group(
        group, note_id, operation, note_digest, command_digest, note_cache, command_cache,
    )
    expected = objective_group(
        expected_group, expected_note,
        expected_operation,
        expected_note_digest,
        expected_command_digest,
        expected_note_cache,
        expected_command_cache,
        allow_none=True,
    )
    assert pending is not None
    state = load_state()
    values = group_state(state)
    if values["retiring"]:
        raise RuntimeError("prior objective group retirement incomplete")
    if values["current"] != expected:
        raise RuntimeError("current objective group changed during placement")
    if any(
        group is not None
        and (
            group["group"] == pending["group"]
            or group["note"] == pending["note"]
            or group["operation"] == pending["operation"]
        )
        for group in (values["current"], values["previous"])
    ):
        raise RuntimeError("pending objective group identity is already retained")
    if values["pending"] is not None and values["pending"] != pending:
        raise RuntimeError("another objective group is pending")
    state["pending_group"] = pending
    save_state(state)
    print("OK")


def promote_pending(
    group: str,
    note_id: str,
    operation: str,
    note_digest: str,
    command_digest: str,
    note_cache: str,
    command_cache: str,
) -> None:
    pending = objective_group(
        group, note_id, operation, note_digest, command_digest, note_cache, command_cache,
    )
    assert pending is not None
    state = load_state()
    values = group_state(state)
    if values["pending"] != pending:
        raise RuntimeError("pending objective group changed")
    if values["retiring"]:
        raise RuntimeError("prior objective group retirement incomplete")
    state["current_group"] = pending
    state["previous_group"] = values["current"]
    state["pending_group"] = None
    state["retiring_group"] = values["previous"]
    save_state(state)
    print("OK")


def finish_retirement(
    group: str,
    note_id: str,
    operation: str,
    note_digest: str,
    command_digest: str,
    note_cache: str,
    command_cache: str,
) -> None:
    retiring = objective_group(
        group, note_id, operation, note_digest, command_digest, note_cache, command_cache,
    )
    assert retiring is not None
    state = load_state()
    values = group_state(state)
    if values["retiring"] != retiring:
        raise RuntimeError("retiring objective group changed")
    (OBJECTIVE_DIR / operation).unlink(missing_ok=True)
    (OBJECTIVE_DIR / f"{operation}.new").unlink(missing_ok=True)
    (PLANT_CACHE_DIR / note_cache).unlink(missing_ok=True)
    (PLANT_CACHE_DIR / f"{note_cache}.new").unlink(missing_ok=True)
    (PLANT_CACHE_DIR / command_cache).unlink(missing_ok=True)
    (PLANT_CACHE_DIR / f"{command_cache}.new").unlink(missing_ok=True)
    state["retiring_group"] = None
    save_state(state)
    print("OK")


def valid_uuid(value: object) -> bool:
    return isinstance(value, str) and UUID.fullmatch(value) is not None


def valid_note_uuid(value: object) -> bool:
    return isinstance(value, str) and NOTE_UUID.fullmatch(value) is not None


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("facility operations require root")
    if len(sys.argv) == 2 and sys.argv[1] == "initialize":
        initialize()
        print("OK")
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "principals":
        provision(sys.argv[2])
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "read-group-state":
        read_group_state()
        return 0
    if len(sys.argv) == 16 and sys.argv[1] == "record-pending":
        record_pending(*sys.argv[2:])
        return 0
    if len(sys.argv) == 9 and sys.argv[1] == "promote-pending":
        promote_pending(*sys.argv[2:])
        return 0
    if len(sys.argv) == 9 and sys.argv[1] == "finish-retirement":
        finish_retirement(*sys.argv[2:])
        return 0
    raise SystemExit("invalid facility operation")


if __name__ == "__main__":
    raise SystemExit(main())
