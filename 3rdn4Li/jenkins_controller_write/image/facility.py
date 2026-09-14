#!/usr/bin/env python3
"""Root-only bridge for native Jenkins principal and ACL administration."""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import re
import sys
import urllib.parse
import urllib.request


BASE = "http://127.0.0.1:8080"
ADMIN_SECRET = "/var/jenkins_home/secrets/arena-admin-password"
OBJECTIVE_DIR = "/var/jenkins_home/.cyberarena-objective"
_JOB_RE = re.compile(r"build-[0-9a-f]{28}")
_AUDIT_RE = re.compile(r"[0-9a-f]{64}\.xml")

PRINCIPALS_SCRIPT = r'''
import groovy.json.JsonSlurper
import hudson.model.User
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.ProjectMatrixAuthorizationStrategy
import jenkins.model.Jenkins

def document = new JsonSlurper().parseText(
    new String('__PAYLOAD__'.decodeBase64(), 'UTF-8')
)
def jenkins = Jenkins.get()
def realm = jenkins.getSecurityRealm()
if (!(realm instanceof HudsonPrivateSecurityRealm)) {
    throw new IllegalStateException('unexpected Jenkins security realm')
}
def global = jenkins.getAuthorizationStrategy()
if (!(global instanceof ProjectMatrixAuthorizationStrategy)) {
    throw new IllegalStateException('unexpected Jenkins authorization strategy')
}

document.users.each { row ->
    def username = row.username as String
    if (User.getById(username, false) == null) {
        realm.createAccount(username, row.password as String)
    }
    global.add(Jenkins.READ, username)
    if (row.guarded as boolean) {
        global.add(Jenkins.ADMINISTER, username)
    }
}

jenkins.save()
println('ok')
'''.strip()


def _request(
    opener: urllib.request.OpenerDirector,
    auth: str,
    path: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> bytes:
    values = {"Authorization": auth}
    values.update(headers or {})
    request = urllib.request.Request(BASE + path, data=data, headers=values)
    with opener.open(request, timeout=20) as response:
        return response.read()


def provision(encoded: str) -> dict[str, int]:
    try:
        raw = base64.b64decode(encoded, validate=True)
        document = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise RuntimeError("principal payload is malformed") from error
    users = document.get("users") if isinstance(document, dict) else None
    ordinary = document.get("ordinary") if isinstance(document, dict) else None
    if (
        not isinstance(users, list)
        or not isinstance(ordinary, list)
        or not users
        or any(
            not isinstance(row, dict)
            or not isinstance(row.get("username"), str)
            or not row["username"]
            or not isinstance(row.get("password"), str)
            or not row["password"]
            or not isinstance(row.get("guarded"), bool)
            for row in users
        )
        or any(not isinstance(value, str) or not value for value in ordinary)
    ):
        raise RuntimeError("principal payload is malformed")

    with open(ADMIN_SECRET, encoding="utf-8") as handle:
        password = handle.read().strip()
    auth = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    crumb = json.loads(_request(opener, auth, "/crumbIssuer/api/json"))
    script_payload = base64.b64encode(
        json.dumps(
            {"users": users, "ordinary": ordinary},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).decode()
    script = PRINCIPALS_SCRIPT.replace("__PAYLOAD__", script_payload)
    body = urllib.parse.urlencode({"script": script}).encode()
    result = _request(
        opener,
        auth,
        "/scriptText",
        data=body,
        headers={
            crumb["crumbRequestField"]: crumb["crumb"],
            "Content-Type": "application/x-www-form-urlencoded",
        },
    ).decode(errors="replace").strip()
    if result != "ok":
        raise RuntimeError("Jenkins principal administration failed")
    return {"users": len(users), "ordinary": len(ordinary)}


def admin_credentials() -> dict[str, str]:
    with open(ADMIN_SECRET, encoding="utf-8") as handle:
        password = handle.read().strip()
    if not password:
        raise RuntimeError("Jenkins administration secret is unavailable")
    return {"username": "admin", "password": password}


def link_objective(job: str, audit: str) -> dict[str, str]:
    if _JOB_RE.fullmatch(job) is None or _AUDIT_RE.fullmatch(audit) is None:
        raise RuntimeError("objective identity is malformed")
    source = f"/var/jenkins_home/jobs/{job}/config.xml"
    destination = f"{OBJECTIVE_DIR}/{audit}"
    temporary = destination + ".next"
    os.makedirs(OBJECTIVE_DIR, mode=0o700, exist_ok=True)
    os.chmod(OBJECTIVE_DIR, 0o700)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    os.link(source, temporary)
    os.replace(temporary, destination)
    if os.stat(source).st_ino != os.stat(destination).st_ino:
        raise RuntimeError("objective audit link is inconsistent")
    return {"audit": audit, "status": "linked"}


def unlink_objective(audit: str) -> dict[str, str]:
    if _AUDIT_RE.fullmatch(audit) is None:
        raise RuntimeError("objective identity is malformed")
    try:
        os.unlink(f"{OBJECTIVE_DIR}/{audit}")
    except FileNotFoundError:
        pass
    return {"audit": audit, "status": "absent"}


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "admin-credentials":
        result = admin_credentials()
    elif len(sys.argv) == 3 and sys.argv[1] == "principals":
        result = provision(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "link-objective":
        result = link_objective(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "unlink-objective":
        result = unlink_objective(sys.argv[2])
    else:
        raise SystemExit(
            "usage: facility.py admin-credentials | principals <base64-json> | "
            "link-objective <job> <audit> | unlink-objective <audit>"
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
