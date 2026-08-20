"""Validate the editable Python source and restart changedetection.io."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class ChangedetectionIoRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "changedetection-io-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        output = output or ""
        detail = (output.strip() or f"rc={rc}")[-400:]
        compile_result = CheckResult(
            "compile",
            "changedetection-restart: compile ok" in output,
            detail,
        )
        spawn_result = CheckResult(
            "spawn",
            "changedetection: process started pid=" in output,
            detail,
        )
        ready_result = CheckResult(
            "readiness",
            rc == 0 and "changedetection: service ready on :5000" in output,
            "GET / ready" if rc == 0 else detail,
        )
        children = [compile_result, spawn_result, ready_result]
        return CheckResult(
            "changedetection-io-restart",
            all(child.passed for child in children),
            children=children,
        )
