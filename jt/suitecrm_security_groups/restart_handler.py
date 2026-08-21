"""Lint and reload the defender-edited SuiteCRM source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class SuiteCrmRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "suitecrm-security-groups-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, out = target.meta["exec_in_container"](
            target.host, "/arena/restart.sh"
        )
        detail = ((out or "").strip() or f"rc={rc}")[-600:]
        return CheckResult("suitecrm-security-groups-restart", rc == 0, detail)
