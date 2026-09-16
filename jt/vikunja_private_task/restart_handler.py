"""Full offline frontend/backend rebuild and service replacement."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class VikunjaRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "vikunja-private-task-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, "/arena/restart.sh")
        detail = ((out or "").strip() or f"rc={rc}")[-600:]
        rebuild = CheckResult("rebuild_reload", rc == 0, detail)
        return CheckResult("vikunja-private-task-restart",
                           rebuild.passed,
                           children=[rebuild])
