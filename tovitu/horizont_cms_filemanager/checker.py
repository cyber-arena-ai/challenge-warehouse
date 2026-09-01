"""External two-Editor legitimate-workflow checker for HorizontCMS."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._checker_identity import checker_identities
from ._client import HorizontError, exercise_filemanager, login


class HorizontCmsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "horizont-cms-filemanager-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        nonce = secrets.token_hex(12)
        base_url = f"http://{target.host}:{target.ports['service']}"
        try:
            observations = []
            identities = checker_identities(str(target.meta.get("team_id", "")))
            for index, (username, password) in enumerate(identities, start=1):
                content = f"horizont-health-{nonce}-{index}-{secrets.token_hex(8)}".encode()
                destination = f"health-{nonce}-{index}-{secrets.token_hex(4)}.txt"
                session = login(base_url, username, password)
                exercise_filemanager(session, content, destination)
                observations.append(destination)
        except Exception as exc:
            detail = "workflow rejected" if isinstance(exc, HorizontError) else type(exc).__name__
            return CheckResult(name="checker", passed=False, detail=detail)

        return CheckResult(
            name="checker",
            passed=len(observations) == 2 and observations[0] != observations[1],
            detail="two distinct Editor upload/rename/read workflows passed",
        )
