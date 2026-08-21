"""Small stdlib SuiteCRM client shared by handler, checker, and private PoV."""

from __future__ import annotations

import hashlib
import http.cookiejar
import ipaddress
import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence

TIMEOUT = 30
_AUTH_ERRORS = {"Invalid Session ID", "Access Denied", "Invalid Login"}


def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        output = subprocess.run(
            [
                "docker", "inspect", "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                host,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.split()
        if output:
            return output[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return host


def _name_values(fields: Mapping[str, object]) -> list[dict[str, str]]:
    return [{"name": name, "value": str(value)} for name, value in fields.items()]


def record_values(document: object) -> list[dict[str, str]]:
    if not isinstance(document, dict):
        return []
    output: list[dict[str, str]] = []
    for entry in document.get("entry_list") or []:
        if not isinstance(entry, dict):
            continue
        row = {"id": str(entry.get("id") or "")}
        values = entry.get("name_value_list") or {}
        if isinstance(values, dict):
            for key, pair in values.items():
                if isinstance(pair, dict):
                    row[str(key)] = str(pair.get("value") or "")
        output.append(row)
    return output


class SuiteCrmClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.session = ""
        self.user_id = ""
        self.oauth = ""
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def _open(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, bytes, str]:
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers=dict(headers or {}),
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT) as response:
                return response.status, response.read(), response.geturl()
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.geturl()

    def rest(
        self,
        method: str,
        params: Mapping[str, object],
        *,
        allowed_errors: Iterable[str] = (),
    ) -> object:
        form = {
            "method": method,
            "input_type": "JSON",
            "response_type": "JSON",
            "rest_data": json.dumps(params, separators=(",", ":")),
        }
        status, raw, _ = self._open(
            "POST", "/service/v4_1/rest.php",
            data=urllib.parse.urlencode(form).encode(),
        )
        if status != 200:
            raise RuntimeError(f"legacy REST returned HTTP {status}")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError("legacy REST returned malformed JSON") from error
        allowed = set(allowed_errors)
        if (
            isinstance(result, dict)
            and result.get("name") in _AUTH_ERRORS
            and result.get("name") not in allowed
        ):
            raise RuntimeError(f"legacy REST rejected {method}")
        return result

    def login(self, username: str, password: str) -> bool:
        result = self.rest("login", {
            "user_auth": {
                "user_name": username,
                "password": hashlib.md5(password.encode()).hexdigest(),
                "version": "1",
            },
            "application_name": "cyber-arena",
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
        fields: Mapping[str, object],
    ) -> str:
        result = self.rest("set_entry", {
            "session": self.session,
            "module_name": module,
            "name_value_list": _name_values(fields),
            "track_view": False,
        })
        if not isinstance(result, dict) or not result.get("id") or result["id"] == "-1":
            raise RuntimeError(f"could not save {module} record")
        return str(result["id"])

    def get_entry(
        self,
        module: str,
        record_id: str,
        fields: Sequence[str],
    ) -> list[dict[str, str]]:
        result = self.rest("get_entry", {
            "session": self.session,
            "module_name": module,
            "id": record_id,
            "select_fields": list(fields),
            "link_name_to_fields_array": [],
            "track_view": False,
        }, allowed_errors=("Access Denied",))
        return record_values(result)

    def post_form(
        self,
        pairs: Sequence[tuple[str, str]],
        *,
        referer_path: str,
    ) -> tuple[int, str, str]:
        return_status, raw, final_url = self._open(
            "POST", "/index.php",
            data=urllib.parse.urlencode(pairs).encode(),
            headers={
                "Cookie": "PHPSESSID=" + self.session,
                "Referer": self.base + referer_path,
            },
        )
        return return_status, raw.decode("utf-8", "replace"), final_url

    def html(self, path: str) -> tuple[int, str]:
        status, raw, _ = self._open(
            "GET", path, headers={"Cookie": "PHPSESSID=" + self.session}
        )
        return status, raw.decode("utf-8", "replace")

    def save_report_field(
        self,
        report_id: str,
        name: str,
        label: str,
        *,
        report_module: str = "Notes",
        field: str = "name",
        function: str = "",
    ) -> None:
        pairs = [
            ("module", "AOR_Reports"),
            ("action", "Save"),
            ("record", report_id),
            ("return_module", "AOR_Reports"),
            ("return_action", "DetailView"),
            ("return_id", report_id),
            ("name", name),
            ("report_module", report_module),
            ("assigned_user_id", self.user_id),
            ("graphs_per_row", "2"),
            ("aor_fields_group_display[0]", "-1"),
            ("aor_fields_deleted[0]", "0"),
            ("aor_fields_field_order[0]", "0"),
            ("aor_fields_module_path[0]", report_module),
            ("aor_fields_field[0]", field),
            ("aor_fields_display[0]", "1"),
            ("aor_fields_label[0]", label),
            ("aor_fields_field_function[0]", function),
            ("aor_fields_sort_by[0]", ""),
            ("aor_fields_group_by[0]", "0"),
            ("aor_fields_group_order[0]", "0"),
            ("aor_fields_group_display[1]", "-1"),
        ]
        status, _, _ = self.post_form(
            pairs,
            referer_path="/index.php?module=AOR_Reports&action=EditView",
        )
        if status != 200:
            raise RuntimeError("could not save report field")

    def oauth_login(
        self,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
    ) -> bool:
        body = urllib.parse.urlencode({
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": "",
            "client_id": client_id,
            "client_secret": client_secret,
        }).encode()
        status, raw, _ = self._open("POST", "/Api/access_token", data=body)
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            return False
        token = document.get("access_token") if isinstance(document, dict) else None
        if status != 200 or not isinstance(token, str) or not token:
            return False
        self.oauth = token
        return True

    def v8(
        self,
        method: str,
        path: str,
        payload: object | None = None,
    ) -> tuple[int, object]:
        data = None if payload is None else json.dumps(payload).encode()
        status, raw, _ = self._open(
            method,
            "/Api/V8" + path,
            data=data,
            headers={
                "Authorization": "Bearer " + self.oauth,
                "Accept": "application/vnd.api+json",
                "Content-Type": "application/vnd.api+json",
            },
        )
        try:
            return status, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return status, {"raw": raw.decode("utf-8", "replace")[:500]}


def relationship_record(document: object, record_id: str) -> dict[str, object] | None:
    if not isinstance(document, dict):
        return None
    data = document.get("data") or []
    if isinstance(data, dict):
        data = [data]
    for item in data:
        if isinstance(item, dict) and item.get("id") == record_id:
            return item
    return None
