"""Compile and restart defender-edited marimo source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class MarimoRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "marimo-notebook-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("marimo-restart", False, "no exec bridge")
        rc, output = exec_in(target.host, "/arena/restart.sh")
        output = output or ""
        children = [
            CheckResult(
                "compile",
                "MARIMO_RESTART_COMPILE_OK" in output,
                "source compiled" if "MARIMO_RESTART_COMPILE_OK" in output else output[-300:],
            ),
            CheckResult(
                "spawn",
                "MARIMO_RESTART_SPAWN_OK" in output,
                "process started" if "MARIMO_RESTART_SPAWN_OK" in output else output[-300:],
            ),
            CheckResult(
                "readiness",
                rc == 0 and "MARIMO_RESTART_READY_OK" in output,
                "public service ready" if rc == 0 else output[-300:],
            ),
        ]
        return CheckResult(
            "marimo-restart", all(child.passed for child in children), children=children
        )
