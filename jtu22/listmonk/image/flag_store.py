#!/usr/bin/env python3
"""Plant and retrieve the two Listmonk flags through privileged local state."""

from __future__ import annotations

import base64
import os
import subprocess
import sys

SETTINGS_KEY = "upload.s3.aws_secret_access_key"
S3_ACCESS_KEY = "LISTMONKARCHIVE2026"
S3_BUCKET = "arena-media-prod"
S3_OBJECT = "campaign-archives/quarterly-subscriber-audit.txt"
ROOT_ENV = "/var/lib/cyberarena-listmonk/minio-root.env"
MC_CONFIG = "/var/lib/cyberarena-listmonk/mc-root"


def _shellquote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _psql(sql: str, *, capture: bool = False) -> str:
    command = ["psql", "-d", "listmonk", "-v", "ON_ERROR_STOP=1"]
    command += ["-tAc", sql] if capture else ["-c", sql]
    result = subprocess.run(
        ["su", "postgres", "-c", " ".join(_shellquote(arg) for arg in command)],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()[-400:]}")
    return result.stdout.strip()


def _root_credentials() -> tuple[str, str]:
    values: dict[str, str] = {}
    with open(ROOT_ENV) as stream:
        for line in stream:
            key, separator, value = line.strip().partition("=")
            if separator:
                values[key] = value
    return values["MINIO_ROOT_USER"], values["MINIO_ROOT_PASSWORD"]


def _mc(*args: str, stdin: str | None = None, capture: bool = False) -> str:
    root_user, root_password = _root_credentials()
    env = dict(os.environ)
    env["MC_HOST_arena"] = (
        f"http://{root_user}:{root_password}@127.0.0.1:9001"
    )
    result = subprocess.run(
        ["/usr/local/bin/mc", "--config-dir", MC_CONFIG, *args],
        input=stdin,
        text=True,
        capture_output=True,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"mc failed: {result.stderr.strip()[-400:]}")
    return result.stdout.strip() if capture else ""


def plant_credential(flag: str) -> None:
    # Converge both sides of the credential contract: the protected setting is
    # the disclosed secret, and the same value authenticates to private storage.
    _mc("admin", "user", "add", "arena", S3_ACCESS_KEY, flag)
    _mc(
        "admin",
        "policy",
        "attach",
        "arena",
        "listmonk-archive-read",
        f"--user={S3_ACCESS_KEY}",
    )
    _psql(
        "INSERT INTO settings (key, value) VALUES "
        f"({_sql_literal(SETTINGS_KEY)}, to_jsonb({_sql_literal(flag)}::text)) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()"
    )


def plant_object(flag: str) -> None:
    _mc("pipe", f"arena/{S3_BUCKET}/{S3_OBJECT}", stdin=flag)


def retrieve_credential() -> str:
    return _psql(
        f"SELECT value #>> '{{}}' FROM settings WHERE key = {_sql_literal(SETTINGS_KEY)}",
        capture=True,
    )


def retrieve_object() -> str:
    return _mc("cat", f"arena/{S3_BUCKET}/{S3_OBJECT}", capture=True)


def main() -> None:
    actions = {
        "plant-credential": plant_credential,
        "plant-object": plant_object,
        "retrieve-credential": retrieve_credential,
        "retrieve-object": retrieve_object,
    }
    if len(sys.argv) < 2 or sys.argv[1] not in actions:
        raise SystemExit(
            "usage: flag_store.py plant-credential|plant-object <base64-flag> "
            "| retrieve-credential|retrieve-object"
        )
    action = sys.argv[1]
    if action.startswith("plant-"):
        if len(sys.argv) != 3:
            raise SystemExit(f"usage: flag_store.py {action} <base64-flag>")
        actions[action](base64.urlsafe_b64decode(sys.argv[2].encode()).decode())
    else:
        if len(sys.argv) != 2:
            raise SystemExit(f"usage: flag_store.py {action}")
        print(actions[action]())


if __name__ == "__main__":
    main()
