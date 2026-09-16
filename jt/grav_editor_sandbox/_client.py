"""A small stdlib Grav API client, shared by the network CHECKER and the private
exploit. No framework imports — the exploit runs as a bare script in the attacker
container, where only same-directory ``_*.py`` siblings exist.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import urllib.error
import urllib.request

TIMEOUT = 15


def resolve_host(host: str) -> str:
    """A routable address for the vulbox. The framework passes the prod container
    NAME; a plain IP comes back as-is, otherwise `docker inspect` turns the name
    into a bridge IP (the poller runs on the host and can do that; an attacker
    container reaches the name directly, where inspect simply fails and the name
    is returned unchanged)."""
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
    except Exception:  # noqa: BLE001 — resolution is best-effort
        pass
    return host


class GravApi:
    """Bearer-token client for the bundled API plugin under ``/api/v1``."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.token: str | None = None

    # ── transport ───────────────────────────────────────────────────────
    def request(self, method: str, path: str, body: dict | None = None,
                *, token: str | None = None) -> tuple[int, object]:
        """`(status, parsed_body)`. HTTP errors come back as a status, not an
        exception; only transport failures raise."""
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        bearer = token if token is not None else self.token
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, (json.loads(raw) if raw else None)
            except json.JSONDecodeError:
                return error.code, raw.decode(errors="replace")

    def get_text(self, path: str) -> tuple[int, str]:
        """Fetch a rendered page (the public site, not the API)."""
        req = urllib.request.Request(self.base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                return response.status, response.read().decode(errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors="replace")

    # ── operations ──────────────────────────────────────────────────────
    def login(self, username: str, password: str) -> bool:
        """Exchange a baseline credential for an access token."""
        status, result = self.request(
            "POST", "/api/v1/auth/token",
            {"username": username, "password": password})
        token = None
        if status == 200 and isinstance(result, dict):
            token = (result.get("data") or {}).get("access_token")
        self.token = token
        return bool(token)

    def create_page(self, route: str, title: str, content: str) -> tuple[int, object]:
        """The ordinary editor workflow: publish a page whose body is processed
        by Twig, exactly as the site's own content does."""
        return self.request("POST", "/api/v1/pages", {
            "route": route,
            "title": title,
            "content": content,
            "header": {"published": True, "visible": True,
                       "process": {"twig": True}},
        })

    def delete_page(self, route: str) -> tuple[int, object]:
        return self.request("DELETE", "/api/v1/pages" + route)

    def read_plugin_config(self, plugin: str) -> tuple[int, object]:
        """A privileged read — a content editor is expected to be denied."""
        return self.request("GET", f"/api/v1/config/plugins/{plugin}")
