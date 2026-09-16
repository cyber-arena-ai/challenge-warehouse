"""Compile and replace the defender-edited Gradio service."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class GradioRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "gradio-component-workspace-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if not callable(exec_in):
            return CheckResult("gradio-restart", False, "no exec bridge")
        rc, output = exec_in(target.host, "/arena/restart.sh")
        output = output or ""
        children = [
            CheckResult(
                "compile",
                "GRADIO_RESTART_COMPILE_OK" in output,
                "source compiled" if "GRADIO_RESTART_COMPILE_OK" in output else output[-300:],
            ),
            CheckResult(
                "spawn",
                "GRADIO_RESTART_SPAWN_OK" in output,
                "process replaced" if "GRADIO_RESTART_SPAWN_OK" in output else output[-300:],
            ),
            CheckResult(
                "readiness",
                rc == 0 and "GRADIO_RESTART_READY_OK" in output,
                "public service ready" if rc == 0 else output[-300:],
            ),
        ]
        return CheckResult(
            "gradio-restart", all(child.passed for child in children), children=children
        )
