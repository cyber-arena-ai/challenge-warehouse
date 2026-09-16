"""Small stdlib client shared by the checker, handler, and private PoV."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 15


def response_detail(status: int, raw: bytes) -> str:
    """Return a bounded HTTP diagnostic."""
    try:
        value = json.loads(raw or b"{}")
        message = value.get("message") if isinstance(value, dict) else None
    except (TypeError, json.JSONDecodeError):
        message = None
    if not isinstance(message, str) or not message.strip():
        message = (raw or b"").decode(errors="replace").strip()
    message = " ".join(message.split())[:240]
    return f"HTTP {status}" + (f": {message}" if message else "")


def safe_response_detail(status: int, raw: bytes, *sensitive: str) -> str:
    detail = response_detail(status, raw)
    values = sorted(
        (value for value in sensitive if value), key=len, reverse=True)
    for value in values:
        detail = detail.replace(value, "<redacted>")
    return detail


class VikunjaApi:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def request(self, method: str, path: str, *, token: str | None = None,
                basic: tuple[str, str] | None = None, body: dict | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        data = None if body is None else json.dumps(body).encode()
        request_headers = {"Accept": "application/json"}
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        if token:
            request_headers["Authorization"] = "Bearer " + token
        if basic:
            encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
            request_headers["Authorization"] = "Basic " + encoded
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    @staticmethod
    def _json(raw: bytes) -> dict:
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise ValueError("expected JSON object")
        return value

    def register(self, username: str, email: str, password: str) -> int:
        status, _ = self.register_result(username, email, password)
        return status

    def register_result(
        self, username: str, email: str, password: str,
    ) -> tuple[int, str]:
        status, raw = self.request("POST", "/api/v1/register", body={
            "username": username, "email": email, "password": password,
        })
        if 200 <= status < 300:
            return status, f"HTTP {status}"
        return status, safe_response_detail(
            status, raw, username, email, password)

    def login(self, username: str, password: str) -> str | None:
        _, token, _ = self.login_result(username, password)
        return token

    def login_result(
        self, username: str, password: str,
    ) -> tuple[int, str | None, str]:
        status, raw = self.request("POST", "/api/v1/login", body={
            "username": username, "password": password,
        })
        if status != 200:
            return status, None, safe_response_detail(
                status, raw, username, password)
        try:
            token = self._json(raw).get("token")
        except (TypeError, ValueError, json.JSONDecodeError):
            return status, None, "HTTP 200: malformed login response"
        if not isinstance(token, str) or not token:
            return status, None, "HTTP 200: login response omitted token"
        return status, token, "HTTP 200"

    def registration_available(self) -> tuple[bool, str]:
        status, raw = self.request("GET", "/api/v1/info")
        if status != 200:
            return False, response_detail(status, raw)
        try:
            value = self._json(raw)
            available = value["auth"]["local"]["registration_enabled"] is True
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return False, "HTTP 200: malformed registration capability"
        return available, "HTTP 200: registration enabled" if available else (
            "HTTP 200: registration disabled"
        )

    def default_project_id(self, token: str) -> int | None:
        status, raw = self.request("GET", "/api/v1/user", token=token)
        if status != 200:
            raise RuntimeError(f"current user read -> {status}")
        settings = self._json(raw).get("settings")
        if not isinstance(settings, dict):
            raise ValueError("current user response omitted settings")
        project_id = settings.get("default_project_id")
        if project_id == 0:
            return None
        if not isinstance(project_id, int) or project_id < 0:
            raise ValueError("current user response has invalid default project")
        return project_id

    def create_project(self, token: str, title: str, *,
                       description: str = "", identifier: str = "") -> dict:
        status, raw = self.request("PUT", "/api/v1/projects", token=token,
                                   body={
                                       "title": title,
                                       "description": description,
                                       "identifier": identifier,
                                   })
        if status not in (200, 201):
            raise RuntimeError(f"project create -> {status}")
        return self._json(raw)

    def all_projects(self, token: str) -> list[dict]:
        projects: list[dict] = []
        for page in range(1, 101):
            query = urllib.parse.urlencode({"page": page, "per_page": 50})
            status, raw = self.request(
                "GET", f"/api/v1/projects?{query}", token=token)
            if status != 200:
                raise RuntimeError(f"project enumeration -> {status}")
            value = json.loads(raw or b"[]")
            if not isinstance(value, list):
                raise ValueError("expected project list")
            projects.extend(item for item in value if isinstance(item, dict))
            if len(value) < 50:
                return projects
        raise RuntimeError("project enumeration exceeded safe pagination bound")

    def create_task(self, token: str, project_id: int, title: str,
                    description: str) -> dict:
        status, raw = self.request(
            "PUT", f"/api/v1/projects/{project_id}/tasks", token=token,
            body={"title": title, "description": description})
        if status not in (200, 201):
            raise RuntimeError(f"task create -> {status}")
        return self._json(raw)

    def find_tasks(self, token: str, project_id: int, title: str) -> list[dict]:
        tasks: list[dict] = []
        for page in range(1, 101):
            query = urllib.parse.urlencode(
                {"s": title, "page": page, "per_page": 50})
            status, raw = self.request(
                "GET", f"/api/v1/projects/{project_id}/tasks?{query}", token=token)
            if status != 200:
                raise RuntimeError(f"task search -> {status}")
            value = json.loads(raw or b"[]")
            if not isinstance(value, list):
                raise ValueError("expected task list")
            tasks.extend(item for item in value if isinstance(item, dict))
            if len(value) < 50:
                return tasks
        raise RuntimeError("task search exceeded safe pagination bound")

    def share_project(self, token: str, project_id: int, username: str) -> int:
        status, _ = self.request(
            "PUT", f"/api/v1/projects/{project_id}/users", token=token,
            body={"username": username, "permission": 0})
        return status

    def get_project(self, token: str, project_id: int) -> int:
        status, _ = self.request("GET", f"/api/v1/projects/{project_id}", token=token)
        return status

    def project_permissions(self, token: str, project_id: int) -> dict[str, int]:
        status, raw = self.request(
            "GET", f"/api/v1/projects/{project_id}/users", token=token)
        if status != 200:
            raise RuntimeError(f"project users read -> {status}")
        value = json.loads(raw or b"[]")
        if not isinstance(value, list):
            raise ValueError("expected project user list")
        return {
            row["username"]: row["permission"] for row in value
            if (
                isinstance(row, dict)
                and isinstance(row.get("username"), str)
                and isinstance(row.get("permission"), int)
            )
        }

    def set_project_permission(self, token: str, project_id: int,
                               username: str, permission: int) -> int:
        status, _ = self.request(
            "POST", f"/api/v1/projects/{project_id}/users/{username}", token=token,
            body={"permission": permission})
        return status

    def unshare_project(self, token: str, project_id: int,
                        username: str) -> int:
        status, _ = self.request(
            "DELETE", f"/api/v1/projects/{project_id}/users/{username}", token=token)
        return status

    def relate(self, token: str, task_id: int, other_task_id: int) -> int:
        status, _ = self.request(
            "PUT", f"/api/v1/tasks/{task_id}/relations", token=token,
            body={"other_task_id": other_task_id, "relation_kind": "related"})
        return status

    def get_task(self, token: str, task_id: int) -> tuple[int, dict | None, bytes]:
        status, raw = self.request("GET", f"/api/v1/tasks/{task_id}", token=token)
        if status != 200:
            return status, None, raw
        return status, self._json(raw), raw

    def update_task(self, token: str, task: dict, *, title: str,
                    description: str) -> dict:
        task_id = task.get("id")
        if not isinstance(task_id, int) or task_id <= 0:
            raise ValueError("task id is required for update")
        body = dict(task)
        body.update({"title": title, "description": description})
        status, raw = self.request(
            "POST", f"/api/v1/tasks/{task_id}", token=token, body=body)
        if status != 200:
            raise RuntimeError(f"task update -> {status}")
        return self._json(raw)

    def delete_task(self, token: str, task_id: int) -> int:
        status, _ = self.request(
            "DELETE", f"/api/v1/tasks/{task_id}", token=token)
        return status

    def delete_project(self, token: str, project_id: int) -> int:
        status, _ = self.request(
            "DELETE", f"/api/v1/projects/{project_id}", token=token)
        return status

    def caldav_hrefs(self, username: str, password: str,
                     project_id: int) -> tuple[int, list[str]]:
        status, raw = self.request(
            "PROPFIND", f"/dav/projects/{project_id}/",
            basic=(username, password),
            headers={"Depth": "1", "Content-Type": "application/xml"})
        if status != 207:
            return status, []
        root = ET.fromstring(raw)
        hrefs = [node.text for node in root.findall(".//{DAV:}href")
                 if node.text and node.text.endswith(".ics")]
        return status, hrefs

    def caldav_get(self, username: str, password: str, path: str) -> tuple[int, bytes]:
        parsed = urllib.parse.urlparse(path)
        return self.request("GET", parsed.path, basic=(username, password),
                            headers={"Accept": "text/calendar"})
