#!/usr/bin/env python3
"""Create the trusted facility administrator through Joomla's supported CLI."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

FACILITY = Path("/run/joomla/facility.json")


def run(*arguments: str) -> str:
    result = subprocess.run(
        list(arguments), capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise SystemExit("Joomla user administration failed")
    return result.stdout


def users() -> str:
    return run("php", "cli/joomla.php", "user:list", "--no-ansi")


def user_id(table: str, username: str) -> str | None:
    match = re.search(r"^\s*(\d+)\s+" + re.escape(username) + r"\s", table, re.M)
    return match.group(1) if match else None


def ensure(username: str, password: str, email: str, group: str) -> str:
    table = users()
    current = user_id(table, username)
    if current:
        return current
    run(
        "php",
        "cli/joomla.php",
        "user:add",
        f"--username={username}",
        f"--name={username}",
        f"--password={password}",
        f"--email={email}",
        f"--usergroup={group}",
        "--no-interaction",
        "--no-ansi",
    )
    current = user_id(users(), username)
    if not current:
        raise SystemExit("Joomla user id unavailable")
    return current


facility = json.loads(FACILITY.read_text())
ensure(
    facility["username"],
    facility["password"],
    "facility@arena.invalid",
    "Super Users",
)
os.chmod(FACILITY, 0o600)
