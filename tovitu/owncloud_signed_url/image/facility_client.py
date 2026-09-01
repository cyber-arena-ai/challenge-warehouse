#!/usr/bin/env python3
"""Private facility helper using supported OCS and WebDAV surfaces only."""

from __future__ import annotations

import base64
import http.client
import json
import sys
import time
import urllib.parse
from pathlib import Path


PORT = 8080
CREDENTIALS = Path("/run/owncloud-arena/credentials.json")


def request(method, path, body=None, *, username=None, password=None, headers=None):
    payload = body.encode() if isinstance(body, str) else body
    final_headers = {"Host": "localhost:8080", "Connection": "close"}
    if username is not None:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        final_headers["Authorization"] = f"Basic {token}"
    final_headers.update(headers or {})
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    try:
        connection.request(method, path, body=payload, headers=final_headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def creds():
    return json.loads(CREDENTIALS.read_text())


def wait_ready(timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body = request("GET", "/status.php")
            if status == 200 and json.loads(body).get("installed") is True:
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError("ownCloud did not finish supported bootstrap")


def ocs(method, path, fields=None):
    data = creds()
    body = urllib.parse.urlencode(fields or {})
    status, response = request(
        method,
        path + ("&" if "?" in path else "?") + "format=json",
        body,
        username=data["admin_username"],
        password=data["admin_password"],
        headers={
            "OCS-APIRequest": "true",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    parsed = json.loads(response)
    code = parsed.get("ocs", {}).get("meta", {}).get("statuscode")
    return status, code


def ensure_user(username, password):
    wait_ready()
    status, code = ocs(
        "POST", "/ocs/v1.php/cloud/users", {"userid": username, "password": password}
    )
    if status == 200 and code == 100:
        return
    dav = f"/remote.php/dav/files/{urllib.parse.quote(username, safe='')}/"
    auth_status, _ = request(
        "PROPFIND",
        dav,
        username=username,
        password=password,
        headers={"Depth": "0"},
    )
    if auth_status not in {200, 207}:
        raise RuntimeError(f"supported user setup failed: HTTP {status}, OCS {code}")


def objective_credentials():
    data = creds()
    ensure_user(data["objective_username"], data["objective_password"])
    return data["objective_username"], data["objective_password"]


def objective_path(filename):
    username, _ = objective_credentials()
    return "/remote.php/dav/files/{}/{}".format(
        urllib.parse.quote(username, safe=""),
        urllib.parse.quote(filename, safe=""),
    )


def put_objective(filename, content_b64):
    username, password = objective_credentials()
    status, _ = request(
        "PUT",
        objective_path(filename),
        base64.b64decode(content_b64),
        username=username,
        password=password,
    )
    if status not in {201, 204}:
        raise RuntimeError(f"objective WebDAV PUT failed: HTTP {status}")


def get_objective(filename):
    username, password = objective_credentials()
    status, body = request(
        "GET", objective_path(filename), username=username, password=password
    )
    print(json.dumps({"status": status, "content_b64": base64.b64encode(body).decode()}))


def repair_objective():
    data = creds()
    status, code = ocs(
        "PUT",
        "/ocs/v1.php/cloud/users/" + urllib.parse.quote(data["objective_username"], safe=""),
        {"key": "password", "value": data["objective_password"]},
    )
    if status != 200 or code != 100:
        raise RuntimeError(f"objective password repair failed: HTTP {status}, OCS {code}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("facility command required")
    command = sys.argv[1]
    if command == "ensure-user" and len(sys.argv) == 4:
        ensure_user(sys.argv[2], sys.argv[3])
    elif command == "put-objective" and len(sys.argv) == 4:
        put_objective(sys.argv[2], sys.argv[3])
    elif command == "get-objective" and len(sys.argv) == 3:
        get_objective(sys.argv[2])
    elif command == "repair-objective" and len(sys.argv) == 2:
        repair_objective()
    else:
        raise SystemExit("invalid facility command")


if __name__ == "__main__":
    main()
