"""Small stdlib client shared by the checker, handler, and private PoV."""

from __future__ import annotations

import base64
import ipaddress
import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 15


def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", host],
            capture_output=True, text=True, timeout=5,
        ).stdout.split()
        if out:
            return out[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return host


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
        status, _ = self.request("POST", "/api/v1/register", body={
            "username": username, "email": email, "password": password,
        })
        return status

    def login(self, username: str, password: str) -> str | None:
        status, raw = self.request("POST", "/api/v1/login", body={
            "username": username, "password": password,
        })
        if status != 200:
            return None
        token = self._json(raw).get("token")
        return token if isinstance(token, str) and token else None

    def create_project(self, token: str, title: str) -> dict:
        status, raw = self.request("PUT", "/api/v1/projects", token=token,
                                   body={"title": title})
        if status not in (200, 201):
            raise RuntimeError(f"project create -> {status}")
        return self._json(raw)

    def create_task(self, token: str, project_id: int, title: str,
                    description: str) -> dict:
        status, raw = self.request(
            "PUT", f"/api/v1/projects/{project_id}/tasks", token=token,
            body={"title": title, "description": description})
        if status not in (200, 201):
            raise RuntimeError(f"task create -> {status}")
        return self._json(raw)

    def share_project(self, token: str, project_id: int, username: str) -> int:
        status, _ = self.request(
            "PUT", f"/api/v1/projects/{project_id}/users", token=token,
            body={"username": username, "permission": 0})
        return status

    def get_project(self, token: str, project_id: int) -> int:
        status, _ = self.request("GET", f"/api/v1/projects/{project_id}", token=token)
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

    def delete_task(self, token: str, task_id: int) -> None:
        self.request("DELETE", f"/api/v1/tasks/{task_id}", token=token)

    def delete_project(self, token: str, project_id: int) -> None:
        self.request("DELETE", f"/api/v1/projects/{project_id}", token=token)

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
