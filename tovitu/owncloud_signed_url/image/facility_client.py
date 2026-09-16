#!/usr/bin/env python3
"""Private facility helper using supported OCS and WebDAV surfaces only."""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import secrets
import stat
import sys
import time
import urllib.parse
from pathlib import Path


PORT = 8080
CREDENTIALS = Path("/run/owncloud-arena/credentials.json")
PLACEMENT_ROOT = Path("/var/lib/owncloud-arena/placements")
ISSUED_COHORT = Path("/var/lib/owncloud-arena/issued-cohort")
OBJECTIVE_NAME = re.compile(r"document-[a-f0-9]{20}\.txt")
OBJECTIVE_USER = re.compile(r"cloud_[a-f0-9]{16}")
SEALED_COHORT = re.compile(r"[A-Za-z0-9_-]{1,32600}\.[a-f0-9]{64}")


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


def objective_path(username, filename):
    return "/remote.php/dav/files/{}/{}".format(
        urllib.parse.quote(username, safe=""),
        urllib.parse.quote(filename, safe=""),
    )


def put_objective(placement_key, filename, content_b64):
    context = load_context(placement_key)
    username, password = context["username"], context["password"]
    ensure_user(username, password)
    status, _ = request(
        "PUT",
        objective_path(username, filename),
        base64.b64decode(content_b64),
        username=username,
        password=password,
    )
    if status not in {201, 204}:
        raise RuntimeError(f"objective WebDAV PUT failed: HTTP {status}")


def get_objective(placement_key, filename):
    context = load_context(placement_key)
    username, password = context["username"], context["password"]
    ensure_user(username, password)
    status, body = request(
        "GET",
        objective_path(username, filename),
        username=username,
        password=password,
    )
    print(json.dumps({"status": status, "content_b64": base64.b64encode(body).decode()}))


def repair_objective(placement_key):
    context = load_context(placement_key)
    username, password = context["username"], context["password"]
    status, code = ocs(
        "PUT",
        "/ocs/v1.php/cloud/users/" + urllib.parse.quote(username, safe=""),
        {"key": "password", "value": password},
    )
    if status != 200 or code != 100:
        raise RuntimeError(f"objective password repair failed: HTTP {status}, OCS {code}")


def store_issued_cohort(sealed):
    if not isinstance(sealed, str) or SEALED_COHORT.fullmatch(sealed) is None:
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


def read_issued_cohort():
    try:
        metadata = ISSUED_COHORT.lstat()
        sealed = ISSUED_COHORT.read_text()
    except OSError as error:
        raise RuntimeError("issued principal cohort is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or SEALED_COHORT.fullmatch(sealed) is None
    ):
        raise RuntimeError("issued principal cohort is unsafe")
    print(sealed)


def _lexists(path):
    return os.path.lexists(path)


def _ensure_private_marker(path):
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        os.fsync(descriptor)
        os.close(descriptor)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise RuntimeError("unsafe objective context marker")


def _validate_public_context(context):
    return (
        isinstance(context, dict)
        and set(context) == {"username", "read"}
        and isinstance(context.get("username"), str)
        and OBJECTIVE_USER.fullmatch(context["username"])
        and isinstance(context.get("read"), str)
        and OBJECTIVE_NAME.fullmatch(context["read"])
    )


def _validate_stored_context(context):
    if not isinstance(context, dict) or set(context) != {
        "username",
        "password",
        "read",
    }:
        return False
    public = {key: value for key, value in context.items() if key != "password"}
    return (
        _validate_public_context(public)
        and isinstance(context["password"], str)
        and len(context["password"]) >= 32
    )


def _context_path(placement_key):
    if not re.fullmatch(r"[a-f0-9]{64}", placement_key):
        raise RuntimeError("invalid placement key")
    return PLACEMENT_ROOT / "contexts" / placement_key


def load_context(placement_key):
    destination = _context_path(placement_key)
    try:
        metadata = destination.lstat()
        stored = json.loads(destination.read_text())
    except Exception as error:
        raise RuntimeError("stored objective context is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
        or not _validate_stored_context(stored)
    ):
        raise RuntimeError("stored objective context is invalid")
    return stored


def preallocate_context(placement_key, candidate_b64):
    if not re.fullmatch(r"[a-f0-9]{64}", placement_key):
        raise RuntimeError("invalid placement key")
    try:
        candidate = json.loads(base64.urlsafe_b64decode(candidate_b64).decode())
    except Exception as error:
        raise RuntimeError("invalid candidate context") from error
    if (
        not _validate_public_context(candidate)
    ):
        raise RuntimeError("invalid candidate context")

    initialized = PLACEMENT_ROOT.parent / "placements.initialized"
    was_initialized = _lexists(initialized)
    if was_initialized and not _lexists(PLACEMENT_ROOT):
        raise RuntimeError("ownCloud objective context state was lost")
    PLACEMENT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    PLACEMENT_ROOT.chmod(0o700)
    root_metadata = PLACEMENT_ROOT.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_mode & 0o077:
        raise RuntimeError("unsafe objective context directory")

    contexts = PLACEMENT_ROOT / "contexts"
    issued = PLACEMENT_ROOT / "issued"
    for directory in (contexts, issued):
        if was_initialized and not _lexists(directory):
            raise RuntimeError("ownCloud objective context state was lost")
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError("unsafe objective context directory")
    _ensure_private_marker(initialized)

    destination = contexts / placement_key
    history = issued / placement_key
    if not _lexists(destination) and _lexists(history):
        raise RuntimeError("ownCloud objective context state was lost")

    temporary = contexts / f".{placement_key}.{secrets.token_hex(8)}.tmp"
    stored_candidate = {
        **candidate,
        "password": "Oc-Objective-" + secrets.token_urlsafe(32),
    }
    payload = json.dumps(stored_candidate, separators=(",", ":"), sort_keys=True)
    if not _lexists(destination):
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    metadata = destination.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise RuntimeError("unsafe stored objective context")
    try:
        stored = load_context(placement_key)
    except Exception as error:
        raise RuntimeError("stored objective context is unavailable") from error
    if (
        not _validate_stored_context(stored)
    ):
        raise RuntimeError("stored objective context is invalid")
    _ensure_private_marker(history)
    public = {key: value for key, value in stored.items() if key != "password"}
    print(json.dumps(public, separators=(",", ":"), sort_keys=True))


def main():
    if len(sys.argv) < 2:
        raise SystemExit("facility command required")
    command = sys.argv[1]
    if command == "ensure-user" and len(sys.argv) == 4:
        ensure_user(sys.argv[2], sys.argv[3])
    elif command == "put-objective" and len(sys.argv) == 5:
        put_objective(sys.argv[2], sys.argv[3], sys.argv[4])
    elif command == "get-objective" and len(sys.argv) == 4:
        get_objective(sys.argv[2], sys.argv[3])
    elif command == "repair-objective" and len(sys.argv) == 3:
        repair_objective(sys.argv[2])
    elif command == "preallocate-context" and len(sys.argv) == 4:
        preallocate_context(sys.argv[2], sys.argv[3])
    elif command == "store-issued-cohort" and len(sys.argv) == 3:
        store_issued_cohort(sys.argv[2])
    elif command == "read-issued-cohort" and len(sys.argv) == 2:
        read_issued_cohort()
    else:
        raise SystemExit("invalid facility command")


if __name__ == "__main__":
    main()
