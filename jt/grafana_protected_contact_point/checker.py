"""External checker for Grafana's ordinary Editor contact-point workflow."""

from __future__ import annotations

import base64
import json
import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GrafanaClient, update_document


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _contact_matches(
    contact: dict | None, *, uid: str, name: str, url: str,
) -> bool:
    if not isinstance(contact, dict):
        return False
    settings = contact.get("settings")
    return (
        contact.get("uid") == uid
        and contact.get("name") == name
        and contact.get("type") == "webhook"
        and contact.get("disableResolveMessage") is False
        and isinstance(settings, dict)
        and settings.get("url") == url
    )


class GrafanaChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "grafana-protected-contact-point-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("checker", False, "no exec bridge")
        nonce = secrets.token_hex(12)
        expected_name = "checker-original-" + nonce
        expected_url = "http://checker.invalid/hook/" + nonce
        rc, out = exec_in(
            target.host,
            f"/arena/facility.py checker-arm {nonce} {_b64(expected_url)}",
        )
        try:
            bundle = json.loads((out or "").strip()) if rc == 0 else {}
            username = str(bundle["username"])
            password = str(bundle["password"])
            uid = str(bundle["uid"])
            if uid != "arena-check-" + nonce or not all((username, password)):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return CheckResult("checker", False, "checker setup failed")

        client = GrafanaClient(
            f"http://{target.host}:{target.ports['service']}", username, password
        )
        new_name = "checker-updated-" + secrets.token_hex(8)
        children: list[CheckResult] = []
        try:
            status, rows = client.contact_points()
            listed = status == 200 and any(row.get("uid") == uid for row in rows)
            children.append(CheckResult("list", listed, f"status={status}"))

            status, contact = client.contact_point(uid)
            initial_ok = status == 200 and _contact_matches(
                contact, uid=uid, name=expected_name, url=expected_url,
            )
            children.append(CheckResult("read", initial_ok, f"status={status}"))
            if initial_ok and contact is not None:
                update = update_document(contact, name=new_name, url=expected_url)
                update_status = client.update_contact_point(uid, update)
            else:
                update_status = 0
            children.append(CheckResult(
                "name_update", update_status in (200, 202),
                f"status={update_status}",
            ))

            status, updated = client.contact_point(uid)
            persisted = status == 200 and _contact_matches(
                updated, uid=uid, name=new_name, url=expected_url,
            )
            children.append(CheckResult(
                "persisted_update", persisted, f"status={status}",
            ))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("workflow_exception", False, str(error)))
        finally:
            try:
                exec_in(target.host, f"/arena/facility.py delete-contact {uid}")
            except Exception:  # noqa: BLE001, S110
                pass
        return CheckResult(
            "checker", bool(children) and all(child.passed for child in children),
            children=children,
        )
