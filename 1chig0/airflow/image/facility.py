#!/usr/bin/env python3
"""Root-only trusted accessors for Airflow facility operations."""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile

try:
    from identity import (
        valid_ordinary_password,
        valid_ordinary_username,
        valid_ordinary_variable_key,
    )
except ModuleNotFoundError:  # Loaded directly by package tests.
    from challenges.airflow.image.identity import (
        valid_ordinary_password,
        valid_ordinary_username,
        valid_ordinary_variable_key,
    )


PRIVATE = pathlib.Path("/var/lib/cyberarena-private/airflow")
AIRFLOW_HOME = pathlib.Path("/var/lib/airflow")
SOURCE = pathlib.Path("/opt/airflow-source")
BOOTSTRAP = PRIVATE / "bootstrap-admin.json"
BOOTSTRAP_RETIRED = AIRFLOW_HOME / ".arena-bootstrap-retired"
BOOTSTRAP_RETIRED_VALUE = "retired\n"
JWT_SECRET = AIRFLOW_HOME / ".arena-jwt-secret"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _atomic(path: pathlib.Path, raw: str, mode: int = 0o600) -> None:
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _bootstrap_credentials() -> dict[str, str] | None:
    if not BOOTSTRAP.exists():
        return None
    try:
        value = json.loads(BOOTSTRAP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("bootstrap administrator state is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"password", "username"}
        or not valid_ordinary_username(value.get("username"))
        or not valid_ordinary_password(value.get("password"))
    ):
        raise RuntimeError("bootstrap administrator state is malformed")
    return value


def _retire_bootstrap() -> None:
    credentials = _bootstrap_credentials()
    if credentials is not None:
        environment = [
            f"AIRFLOW_HOME={AIRFLOW_HOME}",
            "AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager",
            "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=sqlite:////var/lib/airflow/airflow.db",
            f"AIRFLOW__CORE__FERNET_KEY={_read(AIRFLOW_HOME / '.arena-fernet-key')}",
            "PYTHONPATH="
            + ":".join(
                str(path)
                for path in (
                    SOURCE / "airflow-core" / "src",
                    SOURCE / "task-sdk" / "src",
                    SOURCE / "providers" / "fab" / "src",
                )
            ),
        ]
        deleted = subprocess.run(
            [
                "runuser",
                "-u",
                "airflow",
                "--",
                "env",
                *environment,
                "python",
                "-m",
                "airflow",
                "users",
                "delete",
                "--username",
                credentials["username"],
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = deleted.stdout + deleted.stderr
        if deleted.returncode != 0 and " does not exist" not in output:
            raise RuntimeError("Airflow bootstrap administrator deletion failed")
    _atomic(JWT_SECRET, secrets.token_urlsafe(48) + "\n", 0o640)
    # Delete (10s) plus this cap (95s) stays below the facility's 120s SSH budget.
    completed = subprocess.run(
        [
            "timeout",
            "--signal=TERM",
            "--kill-after=10",
            "80",
            "/arena/restart.sh",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=95,
    )
    if completed.returncode != 0:
        raise RuntimeError("Airflow bootstrap retirement restart failed")
    BOOTSTRAP.unlink(missing_ok=True)
    _atomic(BOOTSTRAP_RETIRED, BOOTSTRAP_RETIRED_VALUE)


def _raw_variable(key: str) -> None:
    if not valid_ordinary_variable_key(key):
        raise SystemExit("invalid Variable key")
    code = """
import json
import sys
from airflow.models.variable import Variable

value = Variable.get(sys.argv[1], default_var=None)
print(json.dumps({"found": value is not None, "value": value}))
"""
    environment = [
        f"AIRFLOW_HOME={AIRFLOW_HOME}",
        "AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager",
        "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=sqlite:////var/lib/airflow/airflow.db",
        f"AIRFLOW__CORE__FERNET_KEY={_read(AIRFLOW_HOME / '.arena-fernet-key')}",
        "PYTHONPATH="
        + ":".join(
            str(path)
            for path in (
                SOURCE / "airflow-core" / "src",
                SOURCE / "task-sdk" / "src",
                SOURCE / "providers" / "fab" / "src",
            )
        ),
    ]
    completed = subprocess.run(
        [
            "runuser",
            "-u",
            "airflow",
            "--",
            "env",
            *environment,
            "python",
            "-c",
            code,
            key,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    print(completed.stdout.strip())


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "bootstrap-credentials":
        print(json.dumps(_bootstrap_credentials(), sort_keys=True))
        return
    if len(sys.argv) == 2 and sys.argv[1] == "retire-bootstrap":
        _retire_bootstrap()
        print("OK")
        return
    if len(sys.argv) == 3 and sys.argv[1] == "raw-variable":
        _raw_variable(sys.argv[2])
        return
    raise SystemExit(
        "usage: facility.py bootstrap-credentials | retire-bootstrap | "
        "raw-variable KEY"
    )


if __name__ == "__main__":
    main()
