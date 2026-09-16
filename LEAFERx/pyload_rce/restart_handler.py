"""Validate edited source and restart pyLoad."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class PyloadRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "pyload-download-manager-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, output = target.meta["exec_in_container"](
            target.host, "/arena/restart.sh"
        )
        detail = ((output or "").strip() or f"rc={rc}")[-600:]
        return CheckResult("pyload-restart", rc == 0, detail)
