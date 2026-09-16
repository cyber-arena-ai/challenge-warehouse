"""Rebuild and replace the defender-edited Gogs server."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class GogsRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "gogs-code-collaboration-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("gogs-restart", False, "no exec bridge")
        rc, output = exec_in(target.host, "/arena/restart.sh")
        output = output or ""
        children = [
            CheckResult(
                "compile",
                "GOGS_RESTART_COMPILE_OK" in output,
                "compile completed" if "GOGS_RESTART_COMPILE_OK" in output else output[-300:],
            ),
            CheckResult(
                "spawn",
                "GOGS_RESTART_SPAWN_OK" in output,
                "process started" if "GOGS_RESTART_SPAWN_OK" in output else output[-300:],
            ),
            CheckResult(
                "readiness",
                rc == 0 and "GOGS_RESTART_READY_OK" in output,
                "public health ready" if rc == 0 else output[-300:],
            ),
        ]
        return CheckResult(
            "gogs-restart", all(child.passed for child in children), children=children
        )
