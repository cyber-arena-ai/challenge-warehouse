#!/usr/bin/env python3
"""Private facility helper for supported Openfire administrator provisioning."""

from __future__ import annotations

import http.client
import sys
import urllib.parse
from pathlib import Path


PORT = 9090
ADMIN_PASSWORD = Path("/var/lib/openfire-arena/admin-password")


class Session:
    def __init__(self):
        self.cookies: dict[str, str] = {}

    def csrf(self) -> str:
        try:
            return self.cookies["csrf"]
        except KeyError as error:
            raise RuntimeError("Openfire did not issue a CSRF cookie") from error

    def request(self, method, path, body=None, headers=None, *, follow=False):
        current_method = method
        current_path = path
        current_body = body
        current_headers = dict(headers or {})
        for _ in range(8):
            request_headers = dict(current_headers)
            if self.cookies:
                request_headers["Cookie"] = "; ".join(
                    f"{name}={value}" for name, value in self.cookies.items()
                )
            connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
            try:
                connection.request(
                    current_method,
                    current_path,
                    body=current_body,
                    headers=request_headers,
                )
                response = connection.getresponse()
                payload = response.read()
                for raw in response.headers.get_all("Set-Cookie", []):
                    pair = raw.split(";", 1)[0]
                    if "=" in pair:
                        name, value = pair.split("=", 1)
                        self.cookies[name] = value
                location = response.getheader("Location")
                status = response.status
            finally:
                connection.close()
            if not follow or status not in {301, 302, 303, 307, 308} or not location:
                return status, current_path, payload
            parsed = urllib.parse.urlsplit(location)
            current_path = parsed.path or "/"
            if parsed.query:
                current_path += "?" + parsed.query
            if status in {301, 302, 303}:
                current_method = "GET"
                current_body = None
                current_headers = {}
        raise RuntimeError("too many Openfire redirects")

    def form(self, path, fields):
        return self.request(
            "POST",
            path,
            urllib.parse.urlencode(fields).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
            follow=True,
        )


def login(username, password):
    session = Session()
    status, _, _ = session.request("GET", "/login.jsp")
    if status != 200:
        raise RuntimeError("Openfire administrator login page unavailable")
    _, path, body = session.form(
        "/login.jsp",
        {
            "url": "/index.jsp",
            "login": "true",
            "csrf": session.csrf(),
            "username": username,
            "password": password,
        },
    )
    if not path.endswith("/index.jsp") or f"<strong>{username}</strong>".encode() not in body:
        raise RuntimeError("Openfire administrator login failed")
    return session


def delete_user(session, username):
    status, _, _ = session.request(
        "GET", "/user-delete.jsp?" + urllib.parse.urlencode({"username": username})
    )
    if status != 200:
        return
    _, path, _ = session.request(
        "GET",
        "/user-delete.jsp?"
        + urllib.parse.urlencode(
            {"csrf": session.csrf(), "username": username, "delete": "Delete User"}
        ),
        follow=True,
    )
    if "deletesuccess=true" not in path:
        raise RuntimeError("Openfire checker administrator replacement failed")


def create_admin(session, username, password):
    status, _, _ = session.request("GET", "/user-create.jsp")
    if status != 200:
        raise RuntimeError("Openfire user creation page unavailable")
    query = urllib.parse.urlencode(
        {
            "csrf": session.csrf(),
            "username": username,
            "name": "Arena Health Administrator",
            "email": f"{username}@example.test",
            "password": password,
            "passwordConfirm": password,
            "isadmin": "true",
            "create": "Create User",
        }
    )
    _, path, _ = session.request("GET", "/user-create.jsp?" + query, follow=True)
    if "success=true" not in path or f"username={username}" not in path:
        raise RuntimeError("Openfire checker administrator creation failed")


def ensure_checker_admin(username, password):
    try:
        login(username, password)
        return
    except RuntimeError:
        pass
    bootstrap = login("admin", ADMIN_PASSWORD.read_text().strip())
    summary_status, _, summary = bootstrap.request("GET", "/user-summary.jsp")
    if summary_status != 200:
        raise RuntimeError("Openfire user summary unavailable")
    if f"username={urllib.parse.quote(username)}".encode() in summary:
        delete_user(bootstrap, username)
    create_admin(bootstrap, username, password)
    login(username, password)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "ensure-checker-admin":
        ensure_checker_admin(sys.argv[2], sys.argv[3])
        return
    raise SystemExit("invalid facility command")


if __name__ == "__main__":
    main()
