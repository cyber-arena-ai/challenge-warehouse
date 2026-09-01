"""External semantic checker for ProjectSend settings and Client file sharing."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    ProjectSendError,
    admin_mail_from_name,
    admin_set_mail_from_name,
    file_is_listed,
    locate_upload,
    login,
    upload,
)
from .checker_identity import checker_identities


class ProjectSendGlobalSettingsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "projectsend-global-settings-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        nonce = secrets.token_hex(6)
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            identities = checker_identities(str(target.meta["team_id"]))
            admin = login(base_url, *identities["administrator"])
            previous_sender = admin_mail_from_name(admin)
            checker_sender = "Arena check " + nonce
            try:
                admin_set_mail_from_name(admin, checker_sender)
                if admin_mail_from_name(admin) != checker_sender:
                    raise ProjectSendError("authorized mail sender update absent")
            finally:
                admin_set_mail_from_name(admin, previous_sender)
            if admin_mail_from_name(admin) != previous_sender:
                raise ProjectSendError("mail sender restore absent")

            username, password = identities["client"]
            client = login(base_url, username, password)
            filename = f"check-{nonce}.txt"
            content = ("PROJECTSEND-CHECK-" + secrets.token_hex(16)).encode()
            uploaded_at = upload(client, filename, content)
            locate_upload(base_url, username, uploaded_at, filename, content)
            if not file_is_listed(client, filename):
                raise ProjectSendError("uploaded file absent from Client list")
            passed = True
            detail = "authorized mail setting and randomized Client upload passed"
        except (ProjectSendError, OSError, KeyError, RuntimeError) as exc:
            passed = False
            detail = f"workflow failed: {type(exc).__name__}"
        return CheckResult(name="checker", passed=passed, detail=detail)
