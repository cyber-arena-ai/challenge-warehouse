"""Restart handler for the empty sandbox HTTP service."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

from .functionality_test import EmptySandboxFunctionalityTest


class EmptySandboxRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "empty-sandbox-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, "/arena/restart.sh")
        restart = CheckResult(
            "restart",
            rc == 0,
            out.strip()[-200:] if out else f"rc={rc}",
        )
        if rc != 0:
            return CheckResult("empty-sandbox-restart", False, children=[restart])
        health = EmptySandboxFunctionalityTest().run(target)
        return CheckResult(
            "empty-sandbox-restart",
            restart.passed and health.passed,
            children=[restart, health],
        )
