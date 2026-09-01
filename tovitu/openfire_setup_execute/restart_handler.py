"""Offline rebuild and replacement of defender-edited Openfire source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class OpenfireRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "openfire-setup-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "xmpp")

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, output = target.meta["exec_in_container"](
            target.host, "/arena/restart.sh"
        )
        detail = (output or f"rc={rc}")[-400:]
        children = [
            CheckResult(name="compile", passed=rc == 0, detail=detail),
            CheckResult(
                name="replace",
                passed=rc == 0,
                detail="Openfire distribution replaced" if rc == 0 else "replacement failed",
            ),
        ]
        return CheckResult(
            name="openfire-setup-restart",
            passed=rc == 0,
            children=children,
        )
