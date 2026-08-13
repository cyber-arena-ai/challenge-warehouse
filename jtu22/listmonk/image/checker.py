#!/usr/bin/env python3
"""Provision fresh health fixtures in the active Listmonk database.

This helper is intentionally not a checker. It performs the small privileged
setup that cannot be done by the limited API identity, then returns hidden facts
to the external health checker. All decisive assertions are made off-box over
Listmonk's public HTTP interface.
"""
from __future__ import annotations

import json
import secrets
import subprocess
import sys

USER = "ops-analyst"
TOKEN = "ops-analyst-token-a7f3e9c15b4d"
LIST_NAME = "Health Query Samples"
EMAIL_PREFIX = "healthcheck-"
EMAIL_SUFFIX = "@fieldmail.example"

PROVISION_SQL = """
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('cyberarena-listmonk-health'));

UPDATE users SET password = :'token', password_login = FALSE
    WHERE username = :'user';

DELETE FROM subscribers
    WHERE email LIKE :'prefix' || '%' || :'suffix'
      AND created_at < NOW() - INTERVAL '5 minutes';

INSERT INTO lists (uuid, name, type, optin, description)
    SELECT gen_random_uuid(), :'list', 'private', 'single',
           'Ephemeral subscriber-query health samples.'
    WHERE NOT EXISTS (SELECT 1 FROM lists WHERE name = :'list');

INSERT INTO subscribers (uuid, email, name, attribs, status) VALUES
    (gen_random_uuid(), :'email_a', :'name_a',
        jsonb_build_object(
            :'selector_key_a', :'selector_value_a',
            'settings', :'settings_a',
            'users', :'users_a',
            'upload.s3.aws_secret_access_key', :'key_a'),
        'enabled'),
    (gen_random_uuid(), :'email_b', :'name_b',
        jsonb_build_object(
            :'selector_key_b', :'selector_value_b',
            'settings', :'settings_b',
            'users', :'users_b',
            'upload.s3.aws_secret_access_key', :'key_b'),
        'enabled')
    ON CONFLICT (email) DO UPDATE
        SET name = EXCLUDED.name, attribs = EXCLUDED.attribs,
            status = EXCLUDED.status, updated_at = NOW();

INSERT INTO subscriber_lists (subscriber_id, list_id, status)
    SELECT s.id, l.id, 'confirmed'
        FROM subscribers s, lists l
        WHERE s.email IN (:'email_a', :'email_b') AND l.name = :'list'
    ON CONFLICT (subscriber_id, list_id) DO UPDATE SET status = 'confirmed';

COMMIT;
"""


def _shellquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _psql(
    sql: str,
    params: dict[str, str] | None = None,
    *,
    capture: bool = False,
) -> str:
    command = ["psql", "-d", "listmonk", "-v", "ON_ERROR_STOP=1", "-q"]
    for key, value in (params or {}).items():
        command += ["-v", f"{key}={value}"]
    if capture:
        command.append("-tA")
    result = subprocess.run(
        ["su", "postgres", "-c", " ".join(_shellquote(arg) for arg in command)],
        input=sql,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()[-300:]}")
    return result.stdout.strip()


def provision() -> dict[str, object]:
    marker = secrets.token_hex(5)
    names = [f"health-a-{marker}", f"health-b-{marker}"]
    values = [
        {
            "selector_key": f"profile_{secrets.token_hex(5)}",
            "selector_value": secrets.token_hex(8),
            "settings": secrets.token_hex(7),
            "users": secrets.token_hex(7),
            "key": secrets.token_hex(7),
        }
        for _ in range(2)
    ]
    params = {
        "user": USER,
        "token": TOKEN,
        "list": LIST_NAME,
        "prefix": EMAIL_PREFIX,
        "suffix": EMAIL_SUFFIX,
        "email_a": f"{EMAIL_PREFIX}a-{marker}{EMAIL_SUFFIX}",
        "email_b": f"{EMAIL_PREFIX}b-{marker}{EMAIL_SUFFIX}",
        "name_a": names[0],
        "name_b": names[1],
        "selector_key_a": values[0]["selector_key"],
        "selector_key_b": values[1]["selector_key"],
        "selector_value_a": values[0]["selector_value"],
        "selector_value_b": values[1]["selector_value"],
        "settings_a": values[0]["settings"],
        "settings_b": values[1]["settings"],
        "users_a": values[0]["users"],
        "users_b": values[1]["users"],
        "key_a": values[0]["key"],
        "key_b": values[1]["key"],
    }
    _psql(PROVISION_SQL, params)

    list_id = _psql(
        "SELECT id FROM lists WHERE name = :'list' ORDER BY id LIMIT 1;",
        {"list": LIST_NAME},
        capture=True,
    )
    user_count = _psql(
        "SELECT count(*) FROM users WHERE username = :'user';",
        {"user": USER},
        capture=True,
    )
    if not list_id.isdigit() or user_count != "1":
        raise RuntimeError("fixture list or limited API identity is missing")

    return {
        "list_id": list_id,
        "fixtures": [
            {"present": names[0], "absent": names[1], "values": values[0]},
            {"present": names[1], "absent": names[0], "values": values[1]},
        ],
    }


def main() -> None:
    if sys.argv[1:] != ["--provision"]:
        raise RuntimeError("this helper only supports --provision")
    print(json.dumps(provision()))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - emit a bounded facility diagnostic
        print(f"fixture provisioning failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
