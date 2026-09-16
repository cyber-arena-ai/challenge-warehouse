#!/usr/bin/env python3
"""Root-only adapter; every Grafana state mutation uses a supported HTTP API."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:3000"
ACCOUNTS = Path("/arena/secrets/accounts.json")
CURRENT = Path("/arena/state/current-receiver.json")
OBJECTIVE_DIR = Path("/opt/arena/objective")
CONTACT_UID = re.compile(r"cp-[0-9a-f]{24}")
COMMAND_OPERATION = re.compile(r"[0-9a-f]{32}")
CONTACT_NAME = re.compile(
    r"(Billing|Delivery|Incident|Operations|Platform|Reporting|Support|Usage) "
    r"(alerts|notifications|on-call|webhook) [1-9][0-9]{3}"
)
CONTACT_URL = re.compile(
    r"http://192\.168\.([0-9]{1,3})\.([0-9]{1,3}):8[0-9]{3}"
    r"/hooks/[0-9a-f]{24}"
)


def valid_contact_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = CONTACT_URL.fullmatch(value)
    return bool(match and all(1 <= int(octet) <= 254 for octet in match.groups()))


def write_private(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, separators=(",", ":"))
        handle.write("\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def init_secrets() -> None:
    if ACCOUNTS.exists():
        return
    write_private(ACCOUNTS, {
        "admin": {
            "username": "arena_admin_" + secrets.token_hex(8),
            "password": "Ga!" + secrets.token_hex(24),
        },
    })


def accounts() -> dict:
    with ACCOUNTS.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise RuntimeError("invalid account state")
    return value


def credentials(name: str) -> tuple[str, str]:
    value = accounts()[name]
    return str(value["username"]), str(value["password"])


def request(
    method: str,
    path: str,
    auth: tuple[str, str],
    document: object | None = None,
) -> tuple[int, bytes]:
    body = None if document is None else json.dumps(document).encode()
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    headers = {"Authorization": "Basic " + token, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BASE + path, data=body, method=method, headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(2_000_000)
    except urllib.error.HTTPError as error:
        return error.code, error.read(2_000_000)


def json_request(
    method: str,
    path: str,
    auth: tuple[str, str],
    document: object | None = None,
) -> tuple[int, object]:
    status, raw = request(method, path, auth, document)
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        return status, None


def lookup_user(admin: tuple[str, str], username: str) -> tuple[int, int | None]:
    path = "/api/users/lookup?loginOrEmail=" + urllib.parse.quote(username, safe="")
    status, value = json_request("GET", path, admin)
    user_id = value.get("id") if isinstance(value, dict) else None
    return status, user_id if isinstance(user_id, int) else None


def ensure_org_user(username: str, password: str, role: str) -> int:
    admin = credentials("admin")
    status, user_id = lookup_user(admin, username)
    if status == 404:
        status, value = json_request("POST", "/api/admin/users", admin, {
            "name": username,
            "email": username + "@arena.invalid",
            "login": username,
            "password": password,
            "OrgId": 1,
        })
        user_id = value.get("id") if isinstance(value, dict) else None
        if status not in (200, 201) or not isinstance(user_id, int):
            raise RuntimeError("could not create Grafana user")
    elif status == 200 and isinstance(user_id, int):
        reset_status, _ = request(
            "PUT", f"/api/admin/users/{user_id}/password", admin,
            {"password": password},
        )
        if reset_status not in (200, 204):
            raise RuntimeError("could not reconcile Grafana credential")
    else:
        raise RuntimeError("could not look up Grafana user")

    role_status, _ = request(
        "PATCH", f"/api/org/users/{user_id}", admin, {"role": role}
    )
    if role_status not in (200, 204):
        raise RuntimeError("could not assign Grafana role")
    login_status, memberships = json_request(
        "GET", "/api/user/orgs", (username, password)
    )
    if (
        login_status != 200
        or not isinstance(memberships, list)
        or not any(
            isinstance(membership, dict)
            and membership.get("orgId") == 1
            and membership.get("role") == role
            for membership in memberships
        )
    ):
        raise RuntimeError("Grafana role validation failed")
    return user_id


def bootstrap() -> None:
    status, _ = request("GET", "/api/org", credentials("admin"))
    if status != 200:
        raise RuntimeError("administrator validation failed")


def provision_principals(encoded: str) -> None:
    try:
        document = json.loads(base64.b64decode(encoded))
    except (TypeError, ValueError) as error:
        raise RuntimeError("invalid principal request") from error
    if not isinstance(document, dict):
        raise RuntimeError("invalid principal request")
    users = document.get("users")
    contacts = document.get("contacts")
    if not isinstance(users, list) or not isinstance(contacts, list):
        raise RuntimeError("invalid principal request")
    prepared_users: list[tuple[str, str, str]] = []
    for user in users:
        if not isinstance(user, dict):
            raise RuntimeError("invalid principal request")
        username = user.get("username")
        password = user.get("password")
        role = user.get("role")
        if (
            not isinstance(username, str)
            or re.fullmatch(r"arena_[0-9a-f]{20}", username) is None
            or not isinstance(password, str)
            or re.fullmatch(r"Gr![0-9a-f]{40}", password) is None
            or role not in ("Editor", "Admin")
        ):
            raise RuntimeError("invalid principal request")
        prepared_users.append((username, password, role))
    if (
        len({row[0] for row in prepared_users}) != len(prepared_users)
        or [row[0] for row in prepared_users] != sorted(row[0] for row in prepared_users)
    ):
        raise RuntimeError("invalid principal request")

    prepared_contacts: list[tuple[str, str, str]] = []
    for contact in contacts:
        if not isinstance(contact, dict):
            raise RuntimeError("invalid principal request")
        uid = contact.get("uid")
        name = contact.get("name")
        url = contact.get("url")
        if (
            not isinstance(uid, str)
            or CONTACT_UID.fullmatch(uid) is None
            or not isinstance(name, str)
            or CONTACT_NAME.fullmatch(name) is None
            or not valid_contact_url(url)
        ):
            raise RuntimeError("invalid principal request")
        prepared_contacts.append((uid, name, url))
    if (
        len({row[0] for row in prepared_contacts}) != len(prepared_contacts)
        or [row[0] for row in prepared_contacts] != sorted(
            row[0] for row in prepared_contacts
        )
    ):
        raise RuntimeError("invalid principal request")

    for username, password, role in prepared_users:
        ensure_org_user(username, password, role)
    for uid, name, url in prepared_contacts:
        ensure_contact(uid, name, url)
    print(json.dumps({
        "users": len(prepared_users), "contacts": len(prepared_contacts),
    }, separators=(",", ":")))


def contact_path(uid: str) -> str:
    return "/api/v1/provisioning/contact-points/" + urllib.parse.quote(uid, safe="")


def create_contact(uid: str, name: str, url: str) -> None:
    status, _ = request(
        "POST", "/api/v1/provisioning/contact-points", credentials("admin"),
        {
            "uid": uid,
            "name": name,
            "type": "webhook",
            "disableResolveMessage": False,
            "settings": {"url": url},
        },
    )
    if status not in (200, 201, 202):
        raise RuntimeError("could not create contact point")


def update_contact(uid: str, name: str, url: str) -> None:
    status, _ = request(
        "PUT", contact_path(uid), credentials("admin"),
        {
            "uid": uid,
            "name": name,
            "type": "webhook",
            "disableResolveMessage": False,
            "settings": {"url": url},
        },
    )
    if status not in (200, 202):
        raise RuntimeError("could not update contact point")


def get_contact(uid: str) -> dict | None:
    status, value = json_request(
        "GET", "/api/v1/provisioning/contact-points", credentials("admin")
    )
    if status != 200:
        raise RuntimeError("could not read contact points")
    if not isinstance(value, list):
        raise RuntimeError("contact-point response malformed")
    matches = [row for row in value if isinstance(row, dict) and row.get("uid") == uid]
    if len(matches) > 1:
        raise RuntimeError("contact-point identity is ambiguous")
    return matches[0] if matches else None


def contact_matches(value: dict, name: str, url: str) -> bool:
    settings = value.get("settings")
    return (
        value.get("type") == "webhook"
        and value.get("name") == name
        and isinstance(settings, dict)
        and settings.get("url") == url
    )


def ensure_contact(uid: str, name: str, url: str) -> None:
    current = get_contact(uid)
    if current is None:
        create_contact(uid, name, url)
    elif not contact_matches(current, name, url):
        update_contact(uid, name, url)


def delete_contact(uid: str) -> None:
    status, _ = request("DELETE", contact_path(uid), credentials("admin"))
    if status not in (200, 202, 204, 404):
        raise RuntimeError("could not delete contact point")


def create_service_account(name: str) -> int:
    status, value = json_request(
        "POST", "/api/serviceaccounts", credentials("admin"),
        {"name": name, "role": "Viewer", "isDisabled": False},
    )
    account_id = value.get("id") if isinstance(value, dict) else None
    if status not in (200, 201) or not isinstance(account_id, int):
        raise RuntimeError("could not create integrity anchor")
    return account_id


def delete_service_account(account_id: int) -> None:
    status, _ = request(
        "DELETE", f"/api/serviceaccounts/{account_id}", credentials("admin")
    )
    if status not in (200, 202, 204, 404):
        raise RuntimeError("could not delete integrity anchor")


def get_service_account(account_id: int) -> dict | None:
    status, value = json_request(
        "GET", f"/api/serviceaccounts/{account_id}", credentials("admin")
    )
    if status == 404:
        return None
    if status != 200 or not isinstance(value, dict):
        raise RuntimeError("could not read integrity anchor")
    return value


def find_service_account(name: str) -> dict | None:
    query = urllib.parse.urlencode({"query": name, "page": 1, "perpage": 1000})
    status, value = json_request(
        "GET", "/api/serviceaccounts/search?" + query, credentials("admin")
    )
    if status != 200 or not isinstance(value, dict):
        raise RuntimeError("could not search integrity anchors")
    rows = value.get("serviceAccounts")
    if not isinstance(rows, list):
        raise RuntimeError("integrity-anchor search malformed")
    matches = [
        row for row in rows
        if isinstance(row, dict) and row.get("name") == name
    ]
    if len(matches) > 1:
        raise RuntimeError("integrity-anchor identity is ambiguous")
    return matches[0] if matches else None


def service_account_matches(account_id: int, name: str) -> bool:
    value = get_service_account(account_id)
    return bool(
        value is not None
        and value.get("id") == account_id
        and value.get("name") == name
        and value.get("isDisabled") is False
    )


def _valid_receiver(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and CONTACT_UID.fullmatch(str(value.get("uid") or "")) is not None
        and isinstance(value.get("anchor_id"), int)
        and not isinstance(value.get("anchor_id"), bool)
        and re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("anchor_sha256") or "")
        ) is not None
        and COMMAND_OPERATION.fullmatch(
            str(value.get("command_operation") or "")
        ) is not None
        and re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("command_sha256") or "")
        ) is not None
        and CONTACT_NAME.fullmatch(str(value.get("name") or "")) is not None
        and valid_contact_url(value.get("url"))
    )


def receiver_journal() -> dict[str, dict | None]:
    if not CURRENT.exists():
        return {"current": None, "previous": None, "pending": None}
    try:
        with CURRENT.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as error:
        raise RuntimeError("invalid receiver state") from error
    if not isinstance(value, dict) or set(value) != {"current", "previous", "pending"}:
        raise RuntimeError("invalid receiver state")
    receivers = [value[slot] for slot in ("current", "previous", "pending")]
    if any(receiver is not None and not _valid_receiver(receiver) for receiver in receivers):
        raise RuntimeError("invalid receiver state")
    concrete = [receiver for receiver in receivers if receiver is not None]
    if (
        len({receiver["uid"] for receiver in concrete}) != len(concrete)
        or len({receiver["anchor_id"] for receiver in concrete}) != len(concrete)
        or len({receiver["command_operation"] for receiver in concrete})
        != len(concrete)
    ):
        raise RuntimeError("invalid receiver state")
    return value


def retire_receiver(value: dict) -> None:
    uid = value.get("uid")
    account_id = value.get("anchor_id")
    if not isinstance(uid, str) or not isinstance(account_id, int):
        raise RuntimeError("invalid receiver state")
    delete_contact(uid)
    delete_service_account(account_id)
    operation = value.get("command_operation")
    if (
        not isinstance(operation, str)
        or COMMAND_OPERATION.fullmatch(operation) is None
    ):
        raise RuntimeError("invalid receiver state")
    (OBJECTIVE_DIR / operation).unlink(missing_ok=True)
    (OBJECTIVE_DIR / f"{operation}.new").unlink(missing_ok=True)


def command_matches(operation: str, digest: str) -> bool:
    try:
        lines = (OBJECTIVE_DIR / operation).read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    return bool(
        len(lines) == 2
        and lines[0] == operation
        and hashlib.sha256(lines[1].encode()).hexdigest() == digest
    )


def receiver_matches(
    value: dict | None, uid: str, name: str, url: str, digest: str,
    command_operation: str, command_digest: str,
) -> bool:
    return bool(
        value is not None
        and value.get("uid") == uid
        and value.get("anchor_sha256") == digest
        and value.get("name") == name
        and value.get("url") == url
        and value.get("command_operation") == command_operation
        and value.get("command_sha256") == command_digest
    )


def receiver_request(
    encoded: str,
) -> tuple[str, str, str, str, int | None, str, str]:
    try:
        value = json.loads(base64.b64decode(encoded))
        uid = value["uid"]
        name = value["name"]
        url = value["url"]
        anchor_name = value["anchor_name"]
        expected_anchor_id = value.get("anchor_id")
        command_operation = value["command_operation"]
        command_digest = value["command_sha256"]
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("invalid receiver request") from error
    if (
        not isinstance(uid, str)
        or CONTACT_UID.fullmatch(uid) is None
        or not isinstance(name, str)
        or CONTACT_NAME.fullmatch(name) is None
        or not valid_contact_url(url)
        or not isinstance(anchor_name, str)
        or not isinstance(command_operation, str)
        or COMMAND_OPERATION.fullmatch(command_operation) is None
        or not isinstance(command_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", command_digest) is None
        or (
            expected_anchor_id is not None
            and (
                not isinstance(expected_anchor_id, int)
                or isinstance(expected_anchor_id, bool)
            )
        )
    ):
        raise RuntimeError("invalid receiver request")
    return (
        uid, name, url, anchor_name, expected_anchor_id,
        command_operation, command_digest,
    )


def print_receiver(anchor_id: int) -> None:
    print(json.dumps({"org_id": 1, "anchor_id": anchor_id}, separators=(",", ":")))


def stage_receiver(encoded: str) -> None:
    (
        uid, name, url, anchor_name, expected_anchor_id,
        command_operation, command_digest,
    ) = receiver_request(encoded)
    journal = receiver_journal()
    digest = hashlib.sha256(anchor_name.encode()).hexdigest()
    for slot in ("current", "pending"):
        receiver = journal[slot]
        if not receiver_matches(
            receiver, uid, name, url, digest, command_operation, command_digest
        ):
            continue
        anchor_id = receiver["anchor_id"]
        if expected_anchor_id is not None and expected_anchor_id != anchor_id:
            raise RuntimeError("receiver anchor identity conflict")
        if not service_account_matches(anchor_id, anchor_name):
            raise RuntimeError("receiver anchor identity is irreconstructible")
        ensure_contact(uid, name, url)
        print_receiver(anchor_id)
        return

    pending = journal["pending"]
    if pending is not None:
        retire_receiver(pending)
        journal["pending"] = None
        write_private(CURRENT, journal)

    if expected_anchor_id is not None:
        if not service_account_matches(expected_anchor_id, anchor_name):
            raise RuntimeError("receiver anchor identity is irreconstructible")
        contact = get_contact(uid)
        created_contact = contact is None
        ensure_contact(uid, name, url)
        try:
            journal["pending"] = {
                "uid": uid,
                "anchor_id": expected_anchor_id,
                "anchor_sha256": digest,
                "name": name,
                "url": url,
                "command_operation": command_operation,
                "command_sha256": command_digest,
            }
            write_private(CURRENT, journal)
        except Exception:
            if created_contact:
                delete_contact(uid)
            raise
        print_receiver(expected_anchor_id)
        return

    recovered = find_service_account(anchor_name)
    if recovered is not None:
        anchor_id = recovered.get("id")
        if (
            not isinstance(anchor_id, int)
            or isinstance(anchor_id, bool)
            or not service_account_matches(anchor_id, anchor_name)
        ):
            raise RuntimeError("receiver anchor identity is irreconstructible")
        created_anchor = False
    else:
        anchor_id = create_service_account(anchor_name)
        created_anchor = True
    contact = get_contact(uid)
    created_contact = contact is None
    try:
        ensure_contact(uid, name, url)
    except Exception:
        if created_anchor:
            delete_service_account(anchor_id)
        raise
    try:
        journal["pending"] = {
            "uid": uid,
            "anchor_id": anchor_id,
            "anchor_sha256": digest,
            "name": name,
            "url": url,
            "command_operation": command_operation,
            "command_sha256": command_digest,
        }
        write_private(CURRENT, journal)
    except Exception:
        if created_contact:
            delete_contact(uid)
        if created_anchor:
            delete_service_account(anchor_id)
        raise
    print_receiver(anchor_id)


def commit_receiver(encoded: str) -> None:
    (
        uid, name, url, anchor_name, expected_anchor_id,
        command_operation, command_digest,
    ) = receiver_request(encoded)
    if expected_anchor_id is None:
        raise RuntimeError("receiver commit requires an anchor identity")
    journal = receiver_journal()
    digest = hashlib.sha256(anchor_name.encode()).hexdigest()
    current = journal["current"]
    if receiver_matches(
        current, uid, name, url, digest, command_operation, command_digest
    ):
        if current["anchor_id"] != expected_anchor_id:
            raise RuntimeError("receiver anchor identity conflict")
        if not service_account_matches(expected_anchor_id, anchor_name):
            raise RuntimeError("receiver anchor identity is irreconstructible")
        ensure_contact(uid, name, url)
        if not command_matches(command_operation, command_digest):
            raise RuntimeError("command generation does not match objective group")
        print_receiver(expected_anchor_id)
        return

    pending = journal["pending"]
    if (
        not receiver_matches(
            pending, uid, name, url, digest, command_operation, command_digest
        )
        or pending["anchor_id"] != expected_anchor_id
    ):
        raise RuntimeError("receiver commit does not match pending state")
    if not service_account_matches(expected_anchor_id, anchor_name):
        raise RuntimeError("receiver anchor identity is irreconstructible")
    ensure_contact(uid, name, url)
    if not command_matches(command_operation, command_digest):
        raise RuntimeError("command generation does not match objective group")
    previous = journal["previous"]
    if previous is not None:
        retire_receiver(previous)
    write_private(CURRENT, {
        "current": pending,
        "previous": current,
        "pending": None,
    })
    print_receiver(expected_anchor_id)


def main() -> None:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action == "init-secrets" and len(sys.argv) == 2:
        init_secrets()
    elif action == "bootstrap" and len(sys.argv) == 2:
        bootstrap()
    elif action == "principals" and len(sys.argv) == 3:
        provision_principals(sys.argv[2])
    elif action == "stage-receiver" and len(sys.argv) == 3:
        stage_receiver(sys.argv[2])
    elif action == "commit-receiver" and len(sys.argv) == 3:
        commit_receiver(sys.argv[2])
    else:
        raise RuntimeError("invalid facility operation")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 — keep credentials/request data out
        print(f"facility operation failed: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1)
