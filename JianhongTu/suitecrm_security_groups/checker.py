"""External checker for SuiteCRM's normal record, report, and ACL workflows."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import SuiteCrmClient, relationship_record
from .checker_identity import COHORT_PATH, checker_setup, sealed_cohort


_WORK_ITEMS = (
    ("Contract review", "contract-review", "application/pdf"),
    ("Meeting notes", "meeting-notes", "text/plain"),
    ("Renewal schedule", "renewal-schedule", "text/csv"),
    ("Service summary", "service-summary", "application/vnd.oasis.opendocument.text"),
)
_CASE_TOPICS = (
    "Address confirmation",
    "Invoice question",
    "Renewal follow-up",
    "Service request",
)
_APPLICATION_NAMES = (
    "Account Services",
    "Customer Portal",
    "Sales Workspace",
    "Service Desk",
)


def _client_profile() -> tuple[str, str]:
    major = 124 + secrets.randbelow(16)
    build = 6100 + secrets.randbelow(900)
    patch = 40 + secrets.randbelow(160)
    agents = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} "
        "Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} "
        "Safari/537.36",
        f"Mozilla/5.0 (X11; Linux x86_64; rv:{major}.0) "
        f"Gecko/20100101 Firefox/{major}.0",
    )
    return secrets.choice(_APPLICATION_NAMES), secrets.choice(agents)


def _record_material() -> dict[str, str]:
    title, stem, mime = secrets.choice(_WORK_ITEMS)
    suffix = secrets.token_urlsafe(secrets.choice((6, 8, 10))).rstrip("=")
    extension = {
        "application/pdf": "pdf",
        "text/plain": "txt",
        "text/csv": "csv",
        "application/vnd.oasis.opendocument.text": "odt",
    }[mime]
    return {
        "note_name": f"{title} {suffix}",
        "note_value": f"{stem}-{suffix}.{extension}",
        "note_mime": mime,
        "case_name": f"{secrets.choice(_CASE_TOPICS)} {suffix}",
        "report_name": f"{title} overview {suffix}",
    }


def _account(setup: dict[str, object], key: str) -> dict[str, str]:
    pool = setup.get(key)
    client_id = setup.get("client_id")
    client_secret = setup.get("client_secret")
    if (
        not isinstance(pool, tuple)
        or not pool
        or any(
            not isinstance(principal, tuple)
            or len(principal) != 3
            or any(not isinstance(item, str) or not item for item in principal)
            for principal in pool
        )
        or not isinstance(client_id, str)
        or not client_id
        or not isinstance(client_secret, str)
        or not client_secret
    ):
        raise ValueError("account incomplete")
    username, password, _ = secrets.choice(pool)
    return {
        "username": username,
        "password": password,
        "client_id": client_id,
        "client_secret": client_secret,
    }


def _issued_cohort(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    """Read the facility-sealed issued cohort out of root-only victim state."""
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("issued principal cohort is unavailable")
    rc, out = exec_in(target.host, f"cat {COHORT_PATH}")
    if rc != 0:
        raise RuntimeError("issued principal cohort is unavailable")
    return sealed_cohort(target, out or "")


def _login(
    base: str,
    account: dict[str, str],
    *,
    default_client: bool = False,
) -> SuiteCrmClient:
    if default_client:
        client = SuiteCrmClient(base)
    else:
        application_name, user_agent = _client_profile()
        client = SuiteCrmClient(
            base, application_name=application_name, user_agent=user_agent
        )
    if not client.login(account["username"], account["password"]):
        raise RuntimeError("legacy login rejected")
    if not client.oauth_login(
        account["client_id"], account["client_secret"],
        account["username"], account["password"],
    ):
        raise RuntimeError("OAuth login rejected")
    return client


def _relationship_roundtrip(
    api: SuiteCrmClient,
    case_id: str,
    note_id: str,
    note_value: str,
) -> tuple[bool, str]:
    """Create, read, and delete one native V8 Case-to-Note relationship."""
    path = f"/module/Cases/{case_id}/relationships/notes"
    create_status, _ = api.v8(
        "POST", path, {"data": {"type": "Notes", "id": note_id}}
    )
    read_status, document = api.v8("GET", path)
    linked = relationship_record(document, note_id)
    delete_status, _ = api.v8("DELETE", f"{path}/{note_id}")
    after_status, after = api.v8("GET", path)
    passed = (
        create_status in (200, 201)
        and read_status == 200
        and linked is not None
        and (linked.get("attributes") or {}).get("filename") == note_value
        and delete_status in (200, 204)
        and after_status == 200
        and relationship_record(after, note_id) is None
    )
    return passed, (
        f"create={create_status}, read={read_status}, delete={delete_status}"
    )


class SuiteCrmChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "suitecrm-security-groups-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _issued_principals(
        base: str,
        setup: dict[str, object],
        cohort: tuple[tuple[str, str], ...],
        cleanup: list[tuple[SuiteCrmClient, str, str]],
    ) -> CheckResult:
        """Exercise both REST generations as every issued participant."""
        for username, password in cohort:
            record = _record_material()
            try:
                api = _login(base, {
                    "username": username,
                    "password": password,
                    "client_id": str(setup["client_id"]),
                    "client_secret": str(setup["client_secret"]),
                }, default_client=True)
            except RuntimeError as error:
                return CheckResult("issued_principals", False, str(error))
            note_id = api.set_entry("Notes", {
                "name": record["note_name"],
                "description": "Customer correspondence attachment",
                "filename": record["note_value"],
                "file_mime_type": record["note_mime"],
                "assigned_user_id": api.user_id,
            })
            cleanup.append((api, "Notes", note_id))
            case_id = api.set_entry("Cases", {
                "name": record["case_name"],
                "status": "New",
                "priority": "P2",
                "assigned_user_id": api.user_id,
            })
            cleanup.append((api, "Cases", case_id))
            rows = api.get_entry("Notes", note_id, ["id", "filename"])
            if not any(
                row.get("id") == note_id
                and row.get("filename") == record["note_value"]
                for row in rows
            ):
                return CheckResult(
                    "issued_principals", False, "own Note round-trip failed"
                )
            relationship_ok, detail = _relationship_roundtrip(
                api, case_id, note_id, record["note_value"]
            )
            if not relationship_ok:
                return CheckResult(
                    "issued_principals", False,
                    f"default-client V8 relationship failed: {detail}",
                )
        return CheckResult(
            "issued_principals", True, f"{len(cohort)} issued identities"
        )

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            setup = checker_setup(target)
            # The two pools stay checker-only alongside the issued cohort: the
            # guarded identity owns the scored Note and must never be a
            # participant's, and the deep workflow below spans far more records
            # and calls than the issued leaf, so running it as a participant
            # would widen the window that participant can race.
            ordinary = _account(setup, "ordinary")
            guarded = _account(setup, "guarded")
        except (RuntimeError, ValueError) as error:
            return CheckResult("checker", False, str(error))

        base = f"http://{target.host}:{target.ports['service']}"
        ordinary_record = _record_material()
        guarded_record = _record_material()
        note_name = ordinary_record["note_name"]
        note_value = ordinary_record["note_value"]
        case_name = ordinary_record["case_name"]
        report_name = ordinary_record["report_name"]
        guarded_name = guarded_record["note_name"]
        guarded_value = guarded_record["note_value"]
        children: list[CheckResult] = []
        issued_cleanup: list[tuple[SuiteCrmClient, str, str]] = []
        ordinary_api: SuiteCrmClient | None = None
        guarded_api: SuiteCrmClient | None = None
        note_id = case_id = report_id = guarded_id = ""
        try:
            try:
                children.append(self._issued_principals(
                    base, setup, _issued_cohort(target), issued_cleanup
                ))
            except Exception as error:  # noqa: BLE001
                # Keep a seal-transport failure from suppressing the leaves below.
                children.append(CheckResult("issued_principals", False, str(error)))

            ordinary_api = _login(base, ordinary)
            guarded_api = _login(base, guarded)
            children.append(CheckResult("login", True, "legacy and OAuth accepted"))

            note_id = ordinary_api.set_entry("Notes", {
                "name": note_name,
                "description": "Customer correspondence attachment",
                "filename": note_value,
                "file_mime_type": ordinary_record["note_mime"],
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

            relationship_ok, relationship_detail = _relationship_roundtrip(
                ordinary_api, case_id, note_id, note_value
            )
            children.append(CheckResult(
                "v8_relationship", relationship_ok,
                relationship_detail,
            ))

            report_id = ordinary_api.set_entry("AOR_Reports", {
                "name": report_name,
                "report_module": "Notes",
                "assigned_user_id": ordinary_api.user_id,
                "graphs_per_row": "2",
            })
            ordinary_api.save_report_field(
                report_id, report_name, "NoteName", report_module="Notes", field="name"
            )
            report_status, report_body = ordinary_api.html(
                f"/index.php?module=AOR_Reports&action=DetailView&record={report_id}"
            )
            report_ok = report_status == 200 and note_name in report_body
            children.append(CheckResult(
                "benign_report", report_ok, f"status={report_status}"
            ))

            guarded_id = guarded_api.set_entry("Notes", {
                "name": guarded_name,
                "description": "Customer correspondence attachment",
                "filename": guarded_value,
                "file_mime_type": guarded_record["note_mime"],
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
                *issued_cleanup,
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
