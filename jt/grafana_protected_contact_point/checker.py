"""External checker for Grafana's Editor and guarded contact-point workflows."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GrafanaClient, update_document
from ._ids import (
    checker_contacts,
    checker_principals,
    contact_details,
    valid_contact_url,
)


def _contact_matches(contact: dict | None, uid: str, url: str, name: str = "") -> bool:
    if contact is None or contact.get("uid") != uid:
        return False
    settings = contact.get("settings")
    if not isinstance(settings, dict) or settings.get("url") != url:
        return False
    return not name or contact.get("name") == name


def _ordinary_name(excluded: str = "") -> str:
    while True:
        candidate = contact_details(secrets.token_hex(32))[1]
        if candidate != excluded:
            return candidate


def _ordinary_url(excluded: str = "") -> str:
    while True:
        candidate = contact_details(secrets.token_hex(32))[2]
        if candidate != excluded:
            return candidate


def _protected_url(contact: dict | None, uid: str) -> str | None:
    if contact is None or contact.get("uid") != uid:
        return None
    settings = contact.get("settings")
    value = settings.get("url") if isinstance(settings, dict) else None
    return str(value) if valid_contact_url(value) else None


class GrafanaChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "grafana-protected-contact-point-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            team_id = str(target.meta["team_id"])
            ordinary_username, ordinary_password = secrets.choice(
                checker_principals(team_id, "ordinary")
            )
            guarded_username, guarded_password = secrets.choice(
                checker_principals(team_id, "guarded")
            )
            uid, _, _ = secrets.choice(checker_contacts(team_id))
        except (KeyError, TypeError, ValueError, RuntimeError):
            return CheckResult("checker", False, "checker accounts unavailable")

        base = f"http://{target.host}:{target.ports['service']}"
        ordinary = GrafanaClient(base, ordinary_username, ordinary_password)
        guarded = GrafanaClient(base, guarded_username, guarded_password)
        children: list[CheckResult] = []
        try:
            status, protected = guarded.contact_point(uid)
            current_url = _protected_url(protected, uid) if status == 200 else None
            guarded_ready = current_url is not None
            children.append(CheckResult(
                "guarded_read", guarded_ready, f"status={status}"
            ))

            if guarded_ready:
                protected_url = _ordinary_url(current_url)
                protected_name = str(protected.get("name") or "")
                update = update_document(
                    protected, name=protected_name, url=protected_url
                )
                protected_status = guarded.update_contact_point(uid, update)
            else:
                protected_url = ""
                protected_status = 0
            status, protected = guarded.contact_point(uid)
            protected_updated = (
                protected_status in (200, 202)
                and status == 200
                and _contact_matches(protected, uid, protected_url)
            )
            children.append(CheckResult(
                "protected_url_update", protected_updated,
                f"status={protected_status}",
            ))

            status, rows = ordinary.contact_points()
            listed = status == 200 and any(row.get("uid") == uid for row in rows)
            children.append(CheckResult("list", listed, f"status={status}"))

            status, contact = ordinary.contact_point(uid)
            readable = (
                status == 200
                and _contact_matches(contact, uid, protected_url)
            )
            children.append(CheckResult("read", readable, f"status={status}"))
            if readable and protected_updated:
                new_name = _ordinary_name(str(contact.get("name") or ""))
                update = update_document(contact, name=new_name, url=protected_url)
                update_status = ordinary.update_contact_point(uid, update)
            else:
                new_name = ""
                update_status = 0
            children.append(CheckResult(
                "name_update", update_status in (200, 202),
                f"status={update_status}",
            ))

            status, observed = guarded.contact_point(uid)
            protected_ok = status == 200 and _contact_matches(
                observed, uid, protected_url, new_name
            )
            children.append(CheckResult(
                "guarded_observation", protected_ok, f"status={status}"
            ))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("workflow_exception", False, str(error)))
        return CheckResult(
            "checker", bool(children) and all(child.passed for child in children),
            children=children,
        )
