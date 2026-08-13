#!/usr/bin/env python3
"""Plant and retrieve the challenge flag as a protected listmonk setting.

The flag is a rotated administrator-only credential stored in the `settings`
table under `upload.s3.aws_secret_access_key` (an ordinary listmonk S3 secret).
Only an administrator (settings:get) may read it through the app; the operator
`ops-analyst` cannot, and the subscriber query endpoint blocks it via the table
allowlist. Recovering it therefore proves the export table-validation bypass.

Runs inside the container over `psql` (local postgres). Retrieval is one SELECT
and never repairs or rewrites state. Usage:
    flag_store.py plant <base64-flag>
    flag_store.py retrieve
"""
from __future__ import annotations

import base64
import subprocess
import sys

SETTINGS_KEY = "upload.s3.aws_secret_access_key"


def _psql(sql: str, *, capture: bool = False) -> str:
    cmd = ["psql", "-d", "listmonk", "-v", "ON_ERROR_STOP=1"]
    if capture:
        cmd += ["-tAc", sql]
    else:
        cmd += ["-c", sql]
    result = subprocess.run(
        ["su", "postgres", "-c", " ".join(_shellquote(c) for c in cmd)],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()[-400:]}")
    return result.stdout.strip()


def _shellquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _sql_literal(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def plant(flag: str) -> None:
    # Idempotent overwrite: ensure the row exists, then set the current flag.
    _psql(
        "INSERT INTO settings (key, value) VALUES "
        f"({_sql_literal(SETTINGS_KEY)}, to_jsonb({_sql_literal(flag)}::text)) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()"
    )


def retrieve() -> str:
    """Read the exact scalar setting value without changing database state."""
    return _psql(
        f"SELECT value #>> '{{}}' FROM settings WHERE key = {_sql_literal(SETTINGS_KEY)}",
        capture=True,
    )


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in {"plant", "retrieve"}:
        raise SystemExit("usage: flag_store.py plant <base64-flag> | retrieve")
    if sys.argv[1] == "plant":
        if len(sys.argv) != 3:
            raise SystemExit("usage: flag_store.py plant <base64-flag>")
        flag = base64.urlsafe_b64decode(sys.argv[2].encode()).decode()
        plant(flag)
    else:
        print(retrieve())


if __name__ == "__main__":
    main()
