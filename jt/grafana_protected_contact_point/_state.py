"""Structured reads of Grafana's authoritative SQLite state."""

from __future__ import annotations

import json
import sqlite3


def _database(raw: bytes) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.deserialize(raw)
    return connection


def protected_url(raw: bytes, org_id: int, contact_uid: str) -> str | None:
    with _database(raw) as database:
        row = database.execute(
            "SELECT alertmanager_configuration FROM alert_configuration "
            "WHERE org_id = ? ORDER BY id DESC LIMIT 1",
            (org_id,),
        ).fetchone()
    if row is None or not isinstance(row[0], str):
        return None
    document = json.loads(row[0])
    config = document.get("alertmanager_config") if isinstance(document, dict) else None
    receivers = config.get("receivers") if isinstance(config, dict) else None
    if not isinstance(receivers, list):
        return None
    matches: list[str] = []
    for receiver in receivers:
        configs = (
            receiver.get("grafana_managed_receiver_configs")
            if isinstance(receiver, dict) else None
        )
        if not isinstance(configs, list):
            continue
        for candidate in configs:
            if not isinstance(candidate, dict) or candidate.get("uid") != contact_uid:
                continue
            settings = candidate.get("settings")
            url = settings.get("url") if isinstance(settings, dict) else None
            if isinstance(url, str):
                matches.append(url)
    if len(matches) > 1:
        raise ValueError("contact point UID is not unique")
    return matches[0] if matches else None


def service_account_name(
    raw: bytes, org_id: int, account_id: int,
) -> str | None:
    with _database(raw) as database:
        row = database.execute(
            "SELECT name FROM user WHERE id = ? AND org_id = ? "
            "AND is_service_account = 1 AND is_disabled = 0",
            (account_id, org_id),
        ).fetchone()
    return row[0] if row is not None and isinstance(row[0], str) else None
