"""External legitimate-workflow checker for Webmin module boundaries."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import PayloadServer, WebminError, login
from .checker_identity import checker_identities


class WebminChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "webmin-filemanager-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        nonce = secrets.token_hex(10)
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            identities = checker_identities(str(target.meta["team_id"]))
            users = []
            for role in ("restricted-1", "restricted-2"):
                username, password, _ = identities[role]
                client = login(base_url, username, password)
                status, _, page = client.request("GET", "/change-user/")
                preference_markers = (
                    b"Change Language and Theme",
                    b"Modification de la langue et du th",
                )
                if status != 200 or not any(
                    marker in page for marker in preference_markers
                ):
                    raise WebminError("preference module unavailable")
                client.change_language("fr")
                status, _, page = client.request("GET", "/change-user/")
                if status != 200 or b"Modification de la langue et du th" not in page:
                    raise WebminError("language preference did not persist")
                for path in ("/filemin/", "/shell/"):
                    status, _, denied = client.request("GET", path)
                    denial_markers = (
                        b'data-title-initial="Error',
                        b'data-title-initial="Erreur',
                    )
                    if status != 200 or not any(
                        marker in denied for marker in denial_markers
                    ):
                        raise WebminError("restricted module boundary changed")
                users.append(username)

            admin_username, admin_password, _ = identities["file-manager"]
            admin = login(base_url, admin_username, admin_password)
            filename = f"arena-health-{nonce}.txt"
            content = f"webmin-health-{nonce}-{secrets.token_hex(8)}".encode()
            with PayloadServer(target.host) as payloads:
                remote_url = payloads.add(filename, content)
                status, _, _ = admin.file_manager_download(
                    remote_url, "/srv/challenge/webmin"
                )
            read_status, _, received = admin.request("GET", "/" + filename)
            if status != 302 or read_status != 200 or received != content:
                raise WebminError("administrator File Manager round-trip failed")
        except Exception as exc:
            detail = str(exc) if isinstance(exc, WebminError) else type(exc).__name__
            return CheckResult(name="checker", passed=False, detail=detail)

        return CheckResult(
            name="checker",
            passed=len(users) == 2 and users[0] != users[1],
            detail="two restricted preference workflows and admin File Manager passed",
        )
