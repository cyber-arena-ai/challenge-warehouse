"""Replace the running service from the defender-edited HorizontCMS tree."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class HorizontCmsRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "horizont-cms-filemanager-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, output = target.meta["exec_in_container"](
            target.host, "/arena/restart.sh"
        )
        detail = (output or f"rc={rc}")[-300:]
        children = [
            CheckResult(name="validate", passed=rc == 0, detail=detail),
            CheckResult(
                name="replace",
                passed=rc == 0,
                detail="PHP service replaced" if rc == 0 else "replacement failed",
            ),
        ]
        return CheckResult(
            name="horizont-cms-filemanager-restart",
            passed=rc == 0,
            children=children,
        )
