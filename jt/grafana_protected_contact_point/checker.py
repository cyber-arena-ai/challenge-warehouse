"""External checker for Grafana's ordinary Editor contact-point workflow."""

from __future__ import annotations

import base64
import json
import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GrafanaClient, update_document


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


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
        rc, out = exec_in(target.host, f"/arena/facility.py checker-arm {nonce}")
        try:
            bundle = json.loads((out or "").strip()) if rc == 0 else {}
            username = str(bundle["username"])
            password = str(bundle["password"])
            uid = str(bundle["uid"])
            url = str(bundle["url"])
            if not all((username, password, uid, url)):
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
            readable = status == 200 and contact is not None
            children.append(CheckResult("read", readable, f"status={status}"))
            if readable:
                update = update_document(contact, name=new_name, url=url)
                update_status = client.update_contact_point(uid, update)
            else:
                update_status = 0
            children.append(CheckResult(
                "name_update", update_status in (200, 202),
                f"status={update_status}",
            ))

            rc, _ = exec_in(
                target.host,
                f"/arena/facility.py checker-finish {uid} {_b64(new_name)} {_b64(url)}",
            )
            children.append(CheckResult("guarded_observation", rc == 0, f"rc={rc}"))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("workflow_exception", False, str(error)))
            try:
                exec_in(target.host, f"/arena/facility.py delete-contact {uid}")
            except Exception:  # noqa: BLE001
                pass
        return CheckResult(
            "checker", bool(children) and all(child.passed for child in children),
            children=children,
        )
