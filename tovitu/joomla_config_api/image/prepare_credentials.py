#!/usr/bin/env python3
"""Create match-local Joomla facility and checker credentials."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

root = Path("/run/joomla")
root.mkdir(parents=True, exist_ok=True)


def create(path: Path, value: dict[str, str]) -> None:
    if path.exists() and path.stat().st_size:
        return
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)


create(
    root / "facility.json",
    {
        "username": "arena_fac_" + secrets.token_hex(8),
        "password": "Jm!" + secrets.token_hex(20),
    },
)
create(
    root / "installer.json",
    {
        "username": "arena_inst_" + secrets.token_hex(8),
        "password": "Ji!" + secrets.token_hex(20),
    },
)
create(
    root / "checker.json",
    {
        "admin_username": "arena_adm_" + secrets.token_hex(8),
        "admin_password": "Ja!" + secrets.token_hex(20),
        "user_username": "arena_usr_" + secrets.token_hex(8),
        "user_password": "Ju!" + secrets.token_hex(20),
    },
)
