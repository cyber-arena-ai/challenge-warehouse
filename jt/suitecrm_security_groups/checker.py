"""External checker for SuiteCRM's normal record, report, and ACL workflows."""

from __future__ import annotations

import json
import re
import secrets
import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import SuiteCrmClient, relationship_record, resolve_host


def _credentials(account: object) -> dict[str, str]:
    if not isinstance(account, dict):
        raise ValueError("account missing")
    required = ("username", "password", "client_id", "client_secret")
    result = {key: str(account.get(key) or "") for key in required}
    if any(not value for value in result.values()):
        raise ValueError("account incomplete")
    return result


def _login(base: str, account: dict[str, str]) -> SuiteCrmClient:
    client = SuiteCrmClient(base)
    if not client.login(account["username"], account["password"]):
        raise RuntimeError("legacy login rejected")
    if not client.oauth_login(
        account["client_id"], account["client_secret"],
        account["username"], account["password"],
    ):
        raise RuntimeError("OAuth login rejected")
    return client


class SuiteCrmChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "suitecrm-security-groups-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("checker", False, "no exec bridge")
        try:
            rc, out = exec_in(target.host, "/arena/facility.py checker-bundle")
        except Exception as error:  # noqa: BLE001
            return CheckResult("checker", False, f"account exec failed: {error}")
        try:
            bundle = json.loads((out or "").strip()) if rc == 0 else {}
            ordinary = _credentials(bundle["ordinary"])
            guarded = _credentials(bundle["guarded"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return CheckResult("checker", False, "checker accounts unavailable")

        base = f"http://{resolve_host(target.host)}:{target.ports['service']}"
        note_name = secrets.token_hex(16)
        note_value = secrets.token_hex(16) + ".txt"
        case_name = secrets.token_hex(16)
        report_name = secrets.token_hex(16)
        report_label = secrets.token_hex(12)
        guarded_name = secrets.token_hex(16)
        guarded_value = secrets.token_hex(16) + ".txt"
        try:
            with socket.create_connection((resolve_host(target.host), 9000), timeout=2):
                listener_ok = False
        except OSError:
            listener_ok = True
        children: list[CheckResult] = [CheckResult(
            "fastcgi_boundary",
            listener_ok,
            "PHP-FPM unreachable off-box" if listener_ok else "port 9000 exposed",
        )]
        ordinary_api: SuiteCrmClient | None = None
        guarded_api: SuiteCrmClient | None = None
        note_id = case_id = report_id = guarded_id = ""
        try:
            ordinary_api = _login(base, ordinary)
            guarded_api = _login(base, guarded)
            children.append(CheckResult("login", True, "legacy and OAuth accepted"))

            note_id = ordinary_api.set_entry("Notes", {
                "name": note_name,
                "description": secrets.token_hex(24),
                "filename": note_value,
                "file_mime_type": "text/plain",
                "assigned_user_id": ordinary_api.user_id,
            })
            case_id = ordinary_api.set_entry("Cases", {
                "name": case_name,
                "status": "New",
                "priority": "P2",
                "assigned_user_id": ordinary_api.user_id,
            })
            note_rows = ordinary_api.get_entry(
                "Notes", note_id, ["id", "name", "filename", "assigned_user_id"]
            )
            case_rows = ordinary_api.get_entry(
                "Cases", case_id, ["id", "name", "assigned_user_id"]
            )
            own_ok = (
                any(row.get("id") == note_id and row.get("filename") == note_value
                    for row in note_rows)
                and any(row.get("id") == case_id and row.get("name") == case_name
                        for row in case_rows)
            )
            children.append(CheckResult("own_note_case", own_ok, "fresh CRUD"))

            relationship_path = f"/module/Cases/{case_id}/relationships/notes"
            payload = {"data": {"type": "Notes", "id": note_id}}
            create_status, _ = ordinary_api.v8("POST", relationship_path, payload)
            read_status, document = ordinary_api.v8("GET", relationship_path)
            linked = relationship_record(document, note_id)
            delete_status, _ = ordinary_api.v8(
                "DELETE", f"{relationship_path}/{note_id}"
            )
            after_status, after = ordinary_api.v8("GET", relationship_path)
            relationship_ok = (
                create_status in (200, 201)
                and read_status == 200
                and linked is not None
                and (linked.get("attributes") or {}).get("filename") == note_value
                and delete_status in (200, 204)
                and after_status == 200
                and relationship_record(after, note_id) is None
            )
            children.append(CheckResult(
                "v8_relationship", relationship_ok,
                f"create={create_status}, read={read_status}, delete={delete_status}",
            ))

            report_id = ordinary_api.set_entry("AOR_Reports", {
                "name": report_name,
                "report_module": "Notes",
                "assigned_user_id": ordinary_api.user_id,
                "graphs_per_row": "2",
            })
            ordinary_api.save_report_field(
                report_id,
                report_name,
                report_label,
                report_module="Notes",
                field="name",
                function="COUNT",
            )
            report_status, report_body = ordinary_api.html(
                f"/index.php?module=AOR_Reports&action=DetailView&record={report_id}"
            )
            label_at = report_body.find(report_label)
            aggregate_cell = bool(re.search(
                r"<td[^>]*>\s*[1-9][0-9]*\s*</td>",
                report_body[label_at:label_at + 5000] if label_at >= 0 else "",
                re.IGNORECASE,
            ))
            report_ok = (
                report_status == 200
                and report_label in report_body
                and note_name not in report_body
                and aggregate_cell
            )
            children.append(CheckResult(
                "aggregate_report", report_ok, f"status={report_status}"
            ))

            guarded_id = guarded_api.set_entry("Notes", {
                "name": guarded_name,
                "description": secrets.token_hex(24),
                "filename": guarded_value,
                "file_mime_type": "text/plain",
                "assigned_user_id": guarded_api.user_id,
            })
            denied_rows = ordinary_api.get_entry(
                "Notes", guarded_id, ["id", "name", "filename"]
            )
            owner_rows = guarded_api.get_entry(
                "Notes", guarded_id, ["id", "name", "filename"]
            )
            boundary_ok = (
                not any(row.get("id") == guarded_id for row in denied_rows)
                and any(
                    row.get("id") == guarded_id
                    and row.get("filename") == guarded_value
                    for row in owner_rows
                )
            )
            children.append(CheckResult(
                "security_group_boundary", boundary_ok,
                "ordinary denied; owner authorized",
            ))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("workflow_exception", False, str(error)))
        finally:
            for client, module, record_id in (
                (ordinary_api, "AOR_Reports", report_id),
                (ordinary_api, "Cases", case_id),
                (ordinary_api, "Notes", note_id),
                (guarded_api, "Notes", guarded_id),
            ):
                if client is None or not record_id:
                    continue
                try:
                    client.set_entry(module, {"id": record_id, "deleted": "1"})
                except Exception:  # noqa: BLE001
                    pass
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
